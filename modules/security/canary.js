/**
 * Canary Tokens & Honeypot System
 * Creates fake "high-value" servers that trigger alerts when accessed
 */

const crypto = require('crypto');

class CanarySystem {
    constructor(db, alertManager) {
        this.db = db;
        this.alertManager = alertManager;
        this.honeypots = new Map(); // canaryId -> config
        this.accessAttempts = new Map(); // canaryId -> attempts[]
    }

    /**
     * Create a honeypot host
     */
    async createHoneypot(userId, config) {
        const canaryId = crypto.randomUUID();
        const canaryToken = crypto.randomBytes(32).toString('hex');

        const honeypot = {
            id: canaryId,
            token: canaryToken,
            name: config.name || 'prod-database-master-DO-NOT-TOUCH',
            description: config.description || 'Production database master (decoy)',
            alert_channel: config.alert_channel || 'email',
            alert_targets: config.alert_targets || [],
            track_attacker: config.track_attacker !== false,
            auto_ban: config.auto_ban || false,
            created_by: userId,
            created_at: new Date(),
            access_count: 0,
            last_accessed: null,
            metadata: {
                fake_hostname: config.fake_hostname || `prod-db-master-${Math.floor(Math.random() * 100)}`,
                fake_os: config.fake_os || 'Ubuntu 22.04 LTS',
                fake_ip: config.fake_ip || `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
                fake_location: config.fake_location || 'us-east-1',
                decoy_data: config.decoy_data || {
                    'database': 'users_production',
                    'tables': ['users', 'passwords', 'credit_cards'],
                    'record_count': '15,234,891'
                }
            }
        };

        // Store in database
        await this.db.query(`
            INSERT INTO security_honeypots (
                honeypot_id, canary_token, name, description,
                alert_channel, alert_targets, track_attacker, auto_ban,
                created_by, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        `, [
            canaryId, canaryToken, honeypot.name, honeypot.description,
            honeypot.alert_channel, JSON.stringify(honeypot.alert_targets),
            honeypot.track_attacker, honeypot.auto_ban, userId,
            JSON.stringify(honeypot.metadata)
        ]);

        this.honeypots.set(canaryId, honeypot);

        console.log(`🍯 Honeypot created: ${honeypot.name} (ID: ${canaryId})`);

        return {
            id: canaryId,
            token: canaryToken,
            name: honeypot.name,
            message: '⚠️  This is a decoy. Any access will trigger alerts.',
            access_url: `/api/v1/hosts/${canaryId}`,
            token_url: `/canary/${canaryToken}`
        };
    }

    /**
     * Record honeypot access attempt
     */
    async recordAccess(canaryId, accessInfo) {
        const honeypot = this.honeypots.get(canaryId) || await this.loadHoneypot(canaryId);

        if (!honeypot) {
            return null;
        }

        const attempt = {
            timestamp: new Date(),
            user_id: accessInfo.user_id,
            user_email: accessInfo.user_email,
            ip_address: accessInfo.ip_address,
            user_agent: accessInfo.user_agent,
            endpoint: accessInfo.endpoint,
            method: accessInfo.method,
            session_id: accessInfo.session_id,
            api_key: accessInfo.api_key,
            geolocation: await this.getGeolocation(accessInfo.ip_address),
            fingerprint: this.generateFingerprint(accessInfo)
        };

        // Store attempt
        if (!this.accessAttempts.has(canaryId)) {
            this.accessAttempts.set(canaryId, []);
        }
        this.accessAttempts.get(canaryId).push(attempt);

        // Save to database
        await this.db.query(`
            INSERT INTO honeypot_access_attempts (
                honeypot_id, user_id, user_email, ip_address,
                user_agent, endpoint, method, session_id,
                geolocation, fingerprint, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        `, [
            canaryId, attempt.user_id, attempt.user_email, attempt.ip_address,
            attempt.user_agent, attempt.endpoint, attempt.method, attempt.session_id,
            JSON.stringify(attempt.geolocation), attempt.fingerprint,
            JSON.stringify(accessInfo)
        ]);

        // Trigger alerts
        await this.triggerAlert(honeypot, attempt);

        // Auto-ban if configured
        if (honeypot.auto_ban) {
            await this.banUser(attempt.user_id, attempt.ip_address, canaryId);
        }

        console.log(`🚨 HONEYPOT ACCESSED: ${honeypot.name} by ${attempt.user_email || attempt.ip_address}`);

        return attempt;
    }

    /**
     * Trigger alert for honeypot access
     */
    async triggerAlert(honeypot, attempt) {
        const alert = {
            severity: 'CRITICAL',
            title: `🚨 Honeypot Accessed: ${honeypot.name}`,
            message: `
**SECURITY ALERT: Honeypot Triggered**

A decoy system was accessed, indicating potential malicious activity.

**Honeypot Details:**
- Name: ${honeypot.name}
- Description: ${honeypot.description}
- ID: ${honeypot.id}

**Access Details:**
- User: ${attempt.user_email || 'Unknown'}
- User ID: ${attempt.user_id || 'N/A'}
- IP Address: ${attempt.ip_address}
- Location: ${attempt.geolocation?.city || 'Unknown'}, ${attempt.geolocation?.country || 'Unknown'}
- Timestamp: ${attempt.timestamp}
- Endpoint: ${attempt.endpoint}
- User Agent: ${attempt.user_agent}

**Recommended Actions:**
1. Investigate user account immediately
2. Review access logs for this user
3. Check for other suspicious activity
4. Consider revoking access credentials

This is an automated alert from SystemAPI.io Honeypot System.
            `.trim(),
            honeypot_id: honeypot.id,
            attempt_details: attempt,
            timestamp: new Date()
        };

        // Send alerts based on channel
        const channels = Array.isArray(honeypot.alert_channel)
            ? honeypot.alert_channel
            : [honeypot.alert_channel];

        for (const channel of channels) {
            switch (channel) {
                case 'email':
                    await this.alertManager.sendEmail(honeypot.alert_targets, alert);
                    break;
                case 'slack':
                    await this.alertManager.sendSlack(honeypot.alert_targets, alert);
                    break;
                case 'pagerduty':
                    await this.alertManager.sendPagerDuty(honeypot.alert_targets, alert);
                    break;
                case 'sms':
                    await this.alertManager.sendSMS(honeypot.alert_targets, alert);
                    break;
                case 'webhook':
                    await this.alertManager.sendWebhook(honeypot.alert_targets, alert);
                    break;
                default:
                    console.log('Alert:', alert);
            }
        }

        return alert;
    }

    /**
     * Ban user after honeypot access
     */
    async banUser(userId, ipAddress, reason) {
        await this.db.query(`
            INSERT INTO security_bans (
                user_id, ip_address, reason, banned_at, expires_at
            ) VALUES ($1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '30 days')
        `, [userId, ipAddress, `Honeypot access: ${reason}`]);

        console.log(`🔒 User banned: ${userId} (IP: ${ipAddress})`);
    }

    /**
     * Generate unique fingerprint for attacker tracking
     */
    generateFingerprint(accessInfo) {
        const data = `${accessInfo.ip_address}|${accessInfo.user_agent}|${accessInfo.session_id}`;
        return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
    }

    /**
     * Get geolocation from IP (mock implementation)
     */
    async getGeolocation(ipAddress) {
        // In production, use a real geolocation service
        return {
            ip: ipAddress,
            city: 'Unknown',
            country: 'Unknown',
            latitude: null,
            longitude: null
        };
    }

    /**
     * Load honeypot from database
     */
    async loadHoneypot(canaryId) {
        const result = await this.db.query(`
            SELECT * FROM security_honeypots WHERE honeypot_id = $1
        `, [canaryId]);

        if (result.rows.length === 0) {
            return null;
        }

        const row = result.rows[0];
        const honeypot = {
            id: row.honeypot_id,
            token: row.canary_token,
            name: row.name,
            description: row.description,
            alert_channel: row.alert_channel,
            alert_targets: JSON.parse(row.alert_targets || '[]'),
            track_attacker: row.track_attacker,
            auto_ban: row.auto_ban,
            created_by: row.created_by,
            created_at: row.created_at,
            metadata: JSON.parse(row.metadata || '{}')
        };

        this.honeypots.set(canaryId, honeypot);
        return honeypot;
    }

    /**
     * List all honeypots
     */
    async listHoneypots(userId) {
        const result = await this.db.query(`
            SELECT
                honeypot_id, name, description, alert_channel,
                track_attacker, auto_ban, created_at,
                (SELECT COUNT(*) FROM honeypot_access_attempts
                 WHERE honeypot_id = security_honeypots.honeypot_id) as access_count,
                (SELECT MAX(timestamp) FROM honeypot_access_attempts
                 WHERE honeypot_id = security_honeypots.honeypot_id) as last_accessed
            FROM security_honeypots
            WHERE created_by = $1
            ORDER BY created_at DESC
        `, [userId]);

        return result.rows;
    }

    /**
     * Get honeypot access history
     */
    async getAccessHistory(canaryId, limit = 100) {
        const result = await this.db.query(`
            SELECT * FROM honeypot_access_attempts
            WHERE honeypot_id = $1
            ORDER BY timestamp DESC
            LIMIT $2
        `, [canaryId, limit]);

        return result.rows;
    }

    /**
     * Check if request is accessing a honeypot
     */
    isHoneypot(hostId) {
        return this.honeypots.has(hostId);
    }
}

module.exports = CanarySystem;
