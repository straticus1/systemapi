/**
 * Command Approval Workflow
 * Requires peer approval for sensitive/destructive commands before execution
 */

const crypto = require('crypto');

class CommandApprovalWorkflow {
    constructor(db, alertManager) {
        this.db = db;
        this.alertManager = alertManager;
        this.pendingApprovals = new Map();

        // Commands that require approval
        this.sensitivePatterns = [
            // Destructive commands
            { pattern: /rm\s+-rf/, severity: 'critical', description: 'Recursive force delete', require_approvals: 2 },
            { pattern: /dd\s+if=/, severity: 'critical', description: 'Direct disk write', require_approvals: 2 },
            { pattern: /mkfs/, severity: 'critical', description: 'Format filesystem', require_approvals: 2 },
            { pattern: /fdisk|parted/, severity: 'high', description: 'Partition modification', require_approvals: 2 },

            // Production modifications
            { pattern: /(systemctl|service).*(stop|restart|disable)/, severity: 'high', description: 'Service modification', require_approvals: 1 },
            { pattern: /DROP\s+(DATABASE|TABLE)/i, severity: 'critical', description: 'Database drop operation', require_approvals: 2 },
            { pattern: /TRUNCATE/i, severity: 'high', description: 'Table truncation', require_approvals: 1 },

            // Security changes
            { pattern: /(chmod|chown)\s+(-R\s+)?[0-7]{3,4}/, severity: 'medium', description: 'Permission change', require_approvals: 1 },
            { pattern: /iptables|firewall-cmd/, severity: 'high', description: 'Firewall modification', require_approvals: 1 },
            { pattern: /useradd|userdel|passwd/, severity: 'medium', description: 'User management', require_approvals: 1 },

            // Cron and scheduled tasks
            { pattern: /crontab\s+-e/, severity: 'medium', description: 'Cron modification', require_approvals: 1 },

            // File modifications in critical paths
            { pattern: /\/etc\/(passwd|shadow|sudoers|hosts|fstab)/, severity: 'high', description: 'Critical system file', require_approvals: 1 },
            { pattern: /\/boot\//, severity: 'high', description: 'Boot directory modification', require_approvals: 1 },

            // Network operations
            { pattern: /nc\s+-[el]/, severity: 'medium', description: 'Network listener', require_approvals: 1 },
            { pattern: /wget|curl.*\|\s*bash/, severity: 'high', description: 'Remote script execution', require_approvals: 1 },

            // Package management
            { pattern: /apt-get\s+remove|yum\s+remove|dnf\s+remove/, severity: 'medium', description: 'Package removal', require_approvals: 1 },

            // Docker operations
            { pattern: /docker\s+(stop|rm|kill)/, severity: 'medium', description: 'Container destruction', require_approvals: 1 },
            { pattern: /docker\s+system\s+prune/, severity: 'high', description: 'Docker cleanup', require_approvals: 1 }
        ];
    }

    /**
     * Check if command requires approval
     */
    requiresApproval(command, context = {}) {
        const matches = [];

        for (const rule of this.sensitivePatterns) {
            if (rule.pattern.test(command)) {
                matches.push({
                    pattern: rule.pattern.toString(),
                    severity: rule.severity,
                    description: rule.description,
                    require_approvals: rule.require_approvals
                });
            }
        }

        if (matches.length === 0) {
            return {
                requires_approval: false,
                can_execute: true
            };
        }

        // Find highest severity match
        const highestSeverity = matches.reduce((max, m) =>
            this.getSeverityScore(m.severity) > this.getSeverityScore(max.severity) ? m : max
        );

        return {
            requires_approval: true,
            can_execute: false,
            severity: highestSeverity.severity,
            description: highestSeverity.description,
            require_approvals: highestSeverity.require_approvals,
            matches: matches
        };
    }

    /**
     * Request approval for a command
     */
    async requestApproval(userId, command, context = {}) {
        const approvalCheck = this.requiresApproval(command, context);

        if (!approvalCheck.requires_approval) {
            return {
                approved: true,
                message: 'Command does not require approval'
            };
        }

        const requestId = `req_${crypto.randomUUID()}`;

        const request = {
            request_id: requestId,
            user_id: userId,
            command: command,
            host_id: context.host_id,
            severity: approvalCheck.severity,
            description: approvalCheck.description,
            require_approvals: approvalCheck.require_approvals,
            requested_at: new Date(),
            expires_at: new Date(Date.now() + (context.timeout || 3600000)), // 1 hour default
            status: 'pending',
            approvals: [],
            denials: [],
            execution_token: null
        };

        // Store in database
        await this.db.query(`
            INSERT INTO command_approval_requests (
                request_id, user_id, command, host_id,
                severity, description, require_approvals,
                requested_at, expires_at, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        `, [
            requestId, userId, command, context.host_id,
            request.severity, request.description, request.require_approvals,
            request.requested_at, request.expires_at, 'pending'
        ]);

        this.pendingApprovals.set(requestId, request);

        // Notify approvers
        await this.notifyApprovers(request, context);

        console.log(`⏳ Approval requested: ${requestId} - ${command}`);

        return {
            request_id: requestId,
            status: 'pending',
            severity: request.severity,
            description: request.description,
            require_approvals: request.require_approvals,
            expires_at: request.expires_at,
            message: `⚠️  This command requires ${request.require_approvals} approval(s). Request ID: ${requestId}`,
            approval_url: `/api/v1/approvals/${requestId}`
        };
    }

    /**
     * Approve a command request
     */
    async approve(requestId, approverId, comment = '') {
        let request = this.pendingApprovals.get(requestId);
        if (!request) {
            request = await this.loadRequest(requestId);
        }

        if (!request) {
            return { success: false, error: 'Request not found' };
        }

        if (request.status !== 'pending') {
            return { success: false, error: `Request is ${request.status}` };
        }

        if (new Date() > new Date(request.expires_at)) {
            await this.expireRequest(requestId);
            return { success: false, error: 'Request has expired' };
        }

        // Can't approve your own request
        if (approverId === request.user_id) {
            return { success: false, error: 'Cannot approve your own request' };
        }

        // Check if already approved by this user
        if (request.approvals.some(a => a.user_id === approverId)) {
            return { success: false, error: 'You have already approved this request' };
        }

        const approval = {
            user_id: approverId,
            approved_at: new Date(),
            comment: comment
        };

        request.approvals.push(approval);

        // Save approval
        await this.db.query(`
            INSERT INTO command_approvals (
                request_id, user_id, action, comment, timestamp
            ) VALUES ($1, $2, 'approve', $3, $4)
        `, [requestId, approverId, comment, approval.approved_at]);

        // Check if we have enough approvals
        if (request.approvals.length >= request.require_approvals) {
            await this.finalizeApproval(requestId, request);
        } else {
            await this.db.query(`
                UPDATE command_approval_requests
                SET updated_at = CURRENT_TIMESTAMP
                WHERE request_id = $1
            `, [requestId]);
        }

        console.log(`✅ Approval granted: ${requestId} by ${approverId} (${request.approvals.length}/${request.require_approvals})`);

        return {
            success: true,
            request_id: requestId,
            approvals_count: request.approvals.length,
            require_approvals: request.require_approvals,
            status: request.approvals.length >= request.require_approvals ? 'approved' : 'pending',
            execution_token: request.execution_token
        };
    }

    /**
     * Deny a command request
     */
    async deny(requestId, denierId, reason = '') {
        let request = this.pendingApprovals.get(requestId);
        if (!request) {
            request = await this.loadRequest(requestId);
        }

        if (!request) {
            return { success: false, error: 'Request not found' };
        }

        if (request.status !== 'pending') {
            return { success: false, error: `Request is ${request.status}` };
        }

        const denial = {
            user_id: denierId,
            denied_at: new Date(),
            reason: reason
        };

        request.denials.push(denial);
        request.status = 'denied';

        // Save denial
        await this.db.query(`
            INSERT INTO command_approvals (
                request_id, user_id, action, comment, timestamp
            ) VALUES ($1, $2, 'deny', $3, $4)
        `, [requestId, denierId, reason, denial.denied_at]);

        await this.db.query(`
            UPDATE command_approval_requests
            SET status = 'denied'
            WHERE request_id = $1
        `, [requestId]);

        this.pendingApprovals.delete(requestId);

        // Notify requester
        await this.notifyDenial(request, denial);

        console.log(`❌ Request denied: ${requestId} by ${denierId}`);

        return {
            success: true,
            request_id: requestId,
            status: 'denied',
            denied_by: denierId,
            reason: reason
        };
    }

    /**
     * Finalize approval and generate execution token
     */
    async finalizeApproval(requestId, request) {
        const executionToken = crypto.randomBytes(32).toString('hex');

        request.status = 'approved';
        request.execution_token = executionToken;

        await this.db.query(`
            UPDATE command_approval_requests
            SET status = 'approved',
                execution_token = $2
            WHERE request_id = $1
        `, [requestId, executionToken]);

        // Notify requester
        await this.notifyApproved(request);

        return executionToken;
    }

    /**
     * Validate execution token
     */
    async validateExecutionToken(requestId, token) {
        const request = this.pendingApprovals.get(requestId) || await this.loadRequest(requestId);

        if (!request) {
            return { valid: false, error: 'Request not found' };
        }

        if (request.status !== 'approved') {
            return { valid: false, error: 'Request not approved' };
        }

        if (request.execution_token !== token) {
            return { valid: false, error: 'Invalid execution token' };
        }

        if (new Date() > new Date(request.expires_at)) {
            return { valid: false, error: 'Token expired' };
        }

        // Mark as executed
        await this.db.query(`
            UPDATE command_approval_requests
            SET status = 'executed',
                executed_at = CURRENT_TIMESTAMP
            WHERE request_id = $1
        `, [requestId]);

        request.status = 'executed';
        this.pendingApprovals.delete(requestId);

        return {
            valid: true,
            request_id: requestId,
            command: request.command,
            host_id: request.host_id,
            user_id: request.user_id
        };
    }

    /**
     * Notify approvers of new request
     */
    async notifyApprovers(request, context) {
        const message = {
            title: `⚠️  Command Approval Required`,
            message: `
**Command Approval Request**

User **${request.user_id}** is requesting approval to execute a ${request.severity} severity command:

\`\`\`
${request.command}
\`\`\`

**Details:**
- Host: ${request.host_id || 'N/A'}
- Severity: ${request.severity}
- Description: ${request.description}
- Required Approvals: ${request.require_approvals}
- Expires: ${request.expires_at}

**Actions:**
- Approve: /api/v1/approvals/${request.request_id}/approve
- Deny: /api/v1/approvals/${request.request_id}/deny
            `.trim()
        };

        // Send to configured channels
        if (this.alertManager) {
            await this.alertManager.sendSlack(context.approval_channels || [], message);
            await this.alertManager.sendEmail(context.approval_emails || [], message);
        }
    }

    /**
     * Notify requester of approval
     */
    async notifyApproved(request) {
        const message = {
            title: '✅ Command Approved',
            message: `Your command has been approved and can now be executed.

Request ID: ${request.request_id}
Command: ${request.command}
Execution Token: ${request.execution_token}

This approval expires at: ${request.expires_at}`
        };

        if (this.alertManager) {
            await this.alertManager.sendNotification(request.user_id, message);
        }
    }

    /**
     * Notify requester of denial
     */
    async notifyDenial(request, denial) {
        const message = {
            title: '❌ Command Denied',
            message: `Your command request has been denied.

Request ID: ${request.request_id}
Command: ${request.command}
Denied by: ${denial.user_id}
Reason: ${denial.reason || 'No reason provided'}`
        };

        if (this.alertManager) {
            await this.alertManager.sendNotification(request.user_id, message);
        }
    }

    /**
     * Get severity score for sorting
     */
    getSeverityScore(severity) {
        const scores = { critical: 4, high: 3, medium: 2, low: 1 };
        return scores[severity] || 0;
    }

    /**
     * Load request from database
     */
    async loadRequest(requestId) {
        const result = await this.db.query(`
            SELECT * FROM command_approval_requests
            WHERE request_id = $1
        `, [requestId]);

        if (result.rows.length === 0) {
            return null;
        }

        const row = result.rows[0];

        // Load approvals
        const approvalsResult = await this.db.query(`
            SELECT user_id, action, comment, timestamp
            FROM command_approvals
            WHERE request_id = $1
            ORDER BY timestamp ASC
        `, [requestId]);

        const approvals = approvalsResult.rows
            .filter(a => a.action === 'approve')
            .map(a => ({ user_id: a.user_id, approved_at: a.timestamp, comment: a.comment }));

        const denials = approvalsResult.rows
            .filter(a => a.action === 'deny')
            .map(a => ({ user_id: a.user_id, denied_at: a.timestamp, reason: a.comment }));

        const request = {
            request_id: row.request_id,
            user_id: row.user_id,
            command: row.command,
            host_id: row.host_id,
            severity: row.severity,
            description: row.description,
            require_approvals: row.require_approvals,
            requested_at: row.requested_at,
            expires_at: row.expires_at,
            status: row.status,
            execution_token: row.execution_token,
            approvals: approvals,
            denials: denials
        };

        this.pendingApprovals.set(requestId, request);
        return request;
    }

    /**
     * Expire old pending requests
     */
    async expireRequest(requestId) {
        await this.db.query(`
            UPDATE command_approval_requests
            SET status = 'expired'
            WHERE request_id = $1
        `, [requestId]);

        this.pendingApprovals.delete(requestId);
    }

    /**
     * List pending approvals
     */
    async listPendingApprovals(userId = null) {
        let query = `
            SELECT request_id, user_id, command, host_id, severity,
                   description, require_approvals, requested_at, expires_at,
                   (SELECT COUNT(*) FROM command_approvals
                    WHERE request_id = command_approval_requests.request_id
                    AND action = 'approve') as approval_count
            FROM command_approval_requests
            WHERE status = 'pending'
              AND expires_at > NOW()
        `;

        const params = [];
        if (userId) {
            query += ' AND user_id = $1';
            params.push(userId);
        }

        query += ' ORDER BY requested_at DESC';

        const result = await this.db.query(query, params);
        return result.rows;
    }

    /**
     * Get approval statistics
     */
    async getStats() {
        const result = await this.db.query(`
            SELECT
                status,
                COUNT(*) as count,
                AVG(EXTRACT(EPOCH FROM (executed_at - requested_at))) as avg_approval_time_seconds
            FROM command_approval_requests
            GROUP BY status
        `);

        return result.rows;
    }
}

module.exports = CommandApprovalWorkflow;
