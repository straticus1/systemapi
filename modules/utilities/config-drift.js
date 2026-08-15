/**
 * Configuration Drift Detection
 * Detects when host configurations diverge from baseline or each other
 */

const crypto = require('crypto');

class ConfigDriftDetector {
    constructor(db, fleetManager) {
        this.db = db;
        this.fleetManager = fleetManager;
        this.baselines = new Map(); // baseline_id -> config

        // Configuration files to monitor
        this.monitoredConfigs = [
            '/etc/ssh/sshd_config',
            '/etc/nginx/nginx.conf',
            '/etc/apache2/apache2.conf',
            '/etc/mysql/my.cnf',
            '/etc/postgresql/*/main/postgresql.conf',
            '/etc/redis/redis.conf',
            '/etc/docker/daemon.json',
            '/etc/systemd/system/*.service',
            '/etc/hosts',
            '/etc/resolv.conf',
            '/etc/fstab',
            '/etc/crontab',
            '/etc/security/limits.conf'
        ];
    }

    /**
     * Create baseline from a reference host
     */
    async createBaseline(name, referenceHostId, options = {}) {
        const baselineId = `baseline_${crypto.randomUUID()}`;

        console.log(`📸 Creating baseline: ${name} from ${referenceHostId}`);

        // Collect configuration from reference host
        const config = await this.collectHostConfig(referenceHostId, options);

        const baseline = {
            baseline_id: baselineId,
            name: name,
            description: options.description || `Baseline from ${referenceHostId}`,
            reference_host_id: referenceHostId,
            created_at: new Date(),
            config_snapshot: config,
            monitored_paths: options.custom_paths || this.monitoredConfigs,
            metadata: {
                os: config.os,
                os_version: config.os_version,
                total_files: config.files?.length || 0
            }
        };

        this.baselines.set(baselineId, baseline);

        // Store in database
        await this.db.query(`
            INSERT INTO config_baselines (
                baseline_id, name, description, reference_host_id,
                created_at, config_snapshot, monitored_paths
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [
            baselineId, name, baseline.description, referenceHostId,
            baseline.created_at, JSON.stringify(config),
            JSON.stringify(baseline.monitored_paths)
        ]);

        console.log(`✅ Baseline created: ${baselineId}`);

        return {
            baseline_id: baselineId,
            name: name,
            files_captured: config.files?.length || 0,
            created_at: baseline.created_at
        };
    }

    /**
     * Collect configuration from a host
     */
    async collectHostConfig(hostId, options = {}) {
        const paths = options.custom_paths || this.monitoredConfigs;
        const files = [];

        // Get OS info
        const osInfo = await this.fleetManager.executeCommand(hostId, 'uname -a && cat /etc/os-release 2>/dev/null || echo ""');

        // Collect each config file
        for (const path of paths) {
            try {
                // Use find to handle wildcards
                const findCmd = `find ${path} -type f 2>/dev/null | head -50`;
                const findResult = await this.fleetManager.executeCommand(hostId, findCmd);

                const filePaths = findResult.stdout.split('\n').filter(p => p.trim());

                for (const filePath of filePaths) {
                    // Get file content and metadata
                    const catResult = await this.fleetManager.executeCommand(
                        hostId,
                        `cat "${filePath}" 2>/dev/null && stat -c "%Y %s %a" "${filePath}" 2>/dev/null || stat -f "%m %z %Lp" "${filePath}" 2>/dev/null`
                    );

                    if (catResult.exit_code === 0) {
                        const lines = catResult.stdout.split('\n');
                        const statLine = lines[lines.length - 1];
                        const content = lines.slice(0, -1).join('\n');

                        const [mtime, size, permissions] = statLine.split(' ');

                        files.push({
                            path: filePath,
                            content: content,
                            hash: this.hashContent(content),
                            size: parseInt(size) || 0,
                            mtime: parseInt(mtime) || 0,
                            permissions: permissions || '0644',
                            collected_at: new Date()
                        });
                    }
                }
            } catch (error) {
                console.warn(`Failed to collect ${path} from ${hostId}:`, error.message);
            }
        }

        return {
            host_id: hostId,
            os: this.parseOS(osInfo.stdout),
            os_version: this.parseOSVersion(osInfo.stdout),
            collected_at: new Date(),
            files: files
        };
    }

    /**
     * Detect drift from baseline
     */
    async detectDrift(hostId, baselineId, options = {}) {
        const baseline = this.baselines.get(baselineId) || await this.loadBaseline(baselineId);

        if (!baseline) {
            throw new Error(`Baseline ${baselineId} not found`);
        }

        console.log(`🔍 Checking drift for ${hostId} against baseline ${baseline.name}`);

        // Collect current config from host
        const currentConfig = await this.collectHostConfig(hostId, {
            custom_paths: baseline.monitored_paths
        });

        // Compare configurations
        const driftReport = this.compareConfigs(baseline.config_snapshot, currentConfig, options);

        // Store drift report
        await this.storeDriftReport(hostId, baselineId, driftReport);

        console.log(`${driftReport.has_drift ? '⚠️  Drift detected' : '✅ No drift'}: ${hostId}`);

        return {
            host_id: hostId,
            baseline_id: baselineId,
            baseline_name: baseline.name,
            has_drift: driftReport.has_drift,
            drift_score: driftReport.drift_score,
            total_changes: driftReport.total_changes,
            changes: driftReport.changes,
            checked_at: new Date()
        };
    }

    /**
     * Compare two configurations
     */
    compareConfigs(baseline, current, options = {}) {
        const changes = [];
        let driftScore = 0;

        // Create maps for easy lookup
        const baselineFiles = new Map(baseline.files.map(f => [f.path, f]));
        const currentFiles = new Map(current.files.map(f => [f.path, f]));

        // Check for modified and missing files
        for (const [path, baselineFile] of baselineFiles) {
            const currentFile = currentFiles.get(path);

            if (!currentFile) {
                changes.push({
                    type: 'missing',
                    path: path,
                    severity: this.getDriftSeverity(path, 'missing'),
                    description: 'File removed or not readable',
                    baseline_hash: baselineFile.hash
                });
                driftScore += 10;
            } else if (baselineFile.hash !== currentFile.hash) {
                // Content changed
                const diff = this.generateDiff(baselineFile.content, currentFile.content);

                changes.push({
                    type: 'modified',
                    path: path,
                    severity: this.getDriftSeverity(path, 'modified'),
                    description: `Configuration changed (${diff.additions} additions, ${diff.deletions} deletions)`,
                    baseline_hash: baselineFile.hash,
                    current_hash: currentFile.hash,
                    diff: diff,
                    lines_changed: diff.additions + diff.deletions
                });
                driftScore += diff.additions + diff.deletions;
            } else if (baselineFile.permissions !== currentFile.permissions) {
                // Permissions changed
                changes.push({
                    type: 'permissions',
                    path: path,
                    severity: 'medium',
                    description: `Permissions changed: ${baselineFile.permissions} -> ${currentFile.permissions}`,
                    baseline_permissions: baselineFile.permissions,
                    current_permissions: currentFile.permissions
                });
                driftScore += 5;
            }
        }

        // Check for new files
        for (const [path, currentFile] of currentFiles) {
            if (!baselineFiles.has(path)) {
                changes.push({
                    type: 'added',
                    path: path,
                    severity: this.getDriftSeverity(path, 'added'),
                    description: 'New file detected',
                    current_hash: currentFile.hash,
                    size: currentFile.size
                });
                driftScore += 5;
            }
        }

        // Sort by severity
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        changes.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

        return {
            has_drift: changes.length > 0,
            total_changes: changes.length,
            drift_score: Math.min(driftScore, 100),
            changes: changes,
            summary: this.generateDriftSummary(changes)
        };
    }

    /**
     * Generate diff between two file contents
     */
    generateDiff(baseline, current) {
        const baselineLines = baseline.split('\n');
        const currentLines = current.split('\n');

        let additions = 0;
        let deletions = 0;
        const diffLines = [];

        // Simple line-by-line diff (could use a proper diff library)
        const maxLength = Math.max(baselineLines.length, currentLines.length);

        for (let i = 0; i < maxLength; i++) {
            const baselineLine = baselineLines[i];
            const currentLine = currentLines[i];

            if (baselineLine !== currentLine) {
                if (!currentLine) {
                    deletions++;
                    diffLines.push({ type: '-', line: baselineLine, number: i + 1 });
                } else if (!baselineLine) {
                    additions++;
                    diffLines.push({ type: '+', line: currentLine, number: i + 1 });
                } else {
                    deletions++;
                    additions++;
                    diffLines.push({ type: '-', line: baselineLine, number: i + 1 });
                    diffLines.push({ type: '+', line: currentLine, number: i + 1 });
                }
            }
        }

        return {
            additions: additions,
            deletions: deletions,
            total_changes: additions + deletions,
            diff_lines: diffLines.slice(0, 50) // Limit to first 50 changes
        };
    }

    /**
     * Determine drift severity based on file path and change type
     */
    getDriftSeverity(path, changeType) {
        const criticalPaths = [
            '/etc/ssh/sshd_config',
            '/etc/shadow',
            '/etc/passwd',
            '/etc/sudoers',
            '/etc/security/',
            '/etc/pam.d/'
        ];

        const highPaths = [
            '/etc/nginx/',
            '/etc/apache2/',
            '/etc/systemd/',
            '/etc/docker/',
            '/boot/'
        ];

        // Check if path is critical
        if (criticalPaths.some(cp => path.includes(cp))) {
            return 'critical';
        }

        if (highPaths.some(hp => path.includes(hp))) {
            return 'high';
        }

        if (changeType === 'missing') {
            return 'high';
        }

        return 'medium';
    }

    /**
     * Generate drift summary
     */
    generateDriftSummary(changes) {
        const summary = {
            by_type: {},
            by_severity: {},
            critical_files: []
        };

        for (const change of changes) {
            // Count by type
            summary.by_type[change.type] = (summary.by_type[change.type] || 0) + 1;

            // Count by severity
            summary.by_severity[change.severity] = (summary.by_severity[change.severity] || 0) + 1;

            // Track critical changes
            if (change.severity === 'critical' || change.severity === 'high') {
                summary.critical_files.push(change.path);
            }
        }

        return summary;
    }

    /**
     * Scan entire fleet for drift
     */
    async scanFleet(baselineId, options = {}) {
        const baseline = this.baselines.get(baselineId) || await this.loadBaseline(baselineId);

        if (!baseline) {
            throw new Error(`Baseline ${baselineId} not found`);
        }

        const hosts = await this.fleetManager.getHosts({ status: 'online' });
        const driftReports = [];

        console.log(`🔍 Scanning ${hosts.length} hosts for configuration drift`);

        for (const host of hosts) {
            try {
                const report = await this.detectDrift(host.host_id, baselineId, options);
                driftReports.push(report);
            } catch (error) {
                console.error(`Error scanning ${host.host_id}:`, error.message);
                driftReports.push({
                    host_id: host.host_id,
                    error: error.message,
                    has_drift: null
                });
            }
        }

        const driftedHosts = driftReports.filter(r => r.has_drift);

        return {
            baseline_id: baselineId,
            baseline_name: baseline.name,
            total_hosts_scanned: hosts.length,
            hosts_with_drift: driftedHosts.length,
            drift_percentage: (driftedHosts.length / hosts.length * 100).toFixed(1),
            reports: driftReports,
            scanned_at: new Date()
        };
    }

    /**
     * Auto-remediate drift
     */
    async remediate(hostId, baselineId, options = {}) {
        const driftReport = await this.detectDrift(hostId, baselineId);

        if (!driftReport.has_drift) {
            return {
                remediated: false,
                message: 'No drift detected, nothing to remediate'
            };
        }

        const baseline = this.baselines.get(baselineId);
        const remediationActions = [];

        for (const change of driftReport.changes) {
            if (options.dry_run) {
                remediationActions.push({
                    path: change.path,
                    action: this.getRemediationAction(change),
                    dry_run: true
                });
            } else {
                // Execute remediation
                try {
                    await this.executeRemediation(hostId, change, baseline);
                    remediationActions.push({
                        path: change.path,
                        action: this.getRemediationAction(change),
                        status: 'success'
                    });
                } catch (error) {
                    remediationActions.push({
                        path: change.path,
                        action: this.getRemediationAction(change),
                        status: 'failed',
                        error: error.message
                    });
                }
            }
        }

        return {
            remediated: !options.dry_run,
            host_id: hostId,
            baseline_id: baselineId,
            actions: remediationActions,
            total_actions: remediationActions.length,
            successful: remediationActions.filter(a => a.status === 'success').length
        };
    }

    /**
     * Get remediation action for a change
     */
    getRemediationAction(change) {
        switch (change.type) {
            case 'modified':
                return `Restore file content from baseline`;
            case 'missing':
                return `Recreate file from baseline`;
            case 'added':
                return `Remove unexpected file`;
            case 'permissions':
                return `Restore permissions: ${change.baseline_permissions}`;
            default:
                return 'Unknown action';
        }
    }

    /**
     * Execute remediation
     */
    async executeRemediation(hostId, change, baseline) {
        const baselineFile = baseline.config_snapshot.files.find(f => f.path === change.path);

        switch (change.type) {
            case 'modified':
            case 'missing':
                if (baselineFile) {
                    // Write baseline content to host
                    const content = baselineFile.content.replace(/'/g, "'\\''");
                    await this.fleetManager.executeCommand(
                        hostId,
                        `cat > ${change.path} <<'EOF'\n${content}\nEOF`
                    );

                    // Restore permissions
                    await this.fleetManager.executeCommand(
                        hostId,
                        `chmod ${baselineFile.permissions} ${change.path}`
                    );
                }
                break;

            case 'permissions':
                if (baselineFile) {
                    await this.fleetManager.executeCommand(
                        hostId,
                        `chmod ${baselineFile.permissions} ${change.path}`
                    );
                }
                break;

            case 'added':
                // Optionally remove file (be careful!)
                if (change.severity === 'low') {
                    await this.fleetManager.executeCommand(
                        hostId,
                        `rm -f ${change.path}`
                    );
                }
                break;
        }
    }

    /**
     * Helper functions
     */
    hashContent(content) {
        return crypto.createHash('sha256').update(content).digest('hex').substring(0, 16);
    }

    parseOS(osInfo) {
        if (osInfo.includes('Ubuntu')) return 'Ubuntu';
        if (osInfo.includes('Debian')) return 'Debian';
        if (osInfo.includes('CentOS')) return 'CentOS';
        if (osInfo.includes('Red Hat')) return 'RHEL';
        if (osInfo.includes('Amazon Linux')) return 'Amazon Linux';
        return 'Unknown';
    }

    parseOSVersion(osInfo) {
        const match = osInfo.match(/VERSION="([^"]+)"/);
        return match ? match[1] : 'Unknown';
    }

    async loadBaseline(baselineId) {
        const result = await this.db.query(`
            SELECT * FROM config_baselines WHERE baseline_id = $1
        `, [baselineId]);

        if (result.rows.length === 0) {
            return null;
        }

        const row = result.rows[0];
        const baseline = {
            baseline_id: row.baseline_id,
            name: row.name,
            description: row.description,
            reference_host_id: row.reference_host_id,
            created_at: row.created_at,
            config_snapshot: JSON.parse(row.config_snapshot),
            monitored_paths: JSON.parse(row.monitored_paths)
        };

        this.baselines.set(baselineId, baseline);
        return baseline;
    }

    async storeDriftReport(hostId, baselineId, driftReport) {
        await this.db.query(`
            INSERT INTO config_drift_reports (
                host_id, baseline_id, checked_at, has_drift,
                drift_score, total_changes, report_data
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [
            hostId, baselineId, new Date(), driftReport.has_drift,
            driftReport.drift_score, driftReport.total_changes,
            JSON.stringify(driftReport)
        ]);
    }

    /**
     * Get drift history for a host
     */
    async getDriftHistory(hostId, limit = 30) {
        const result = await this.db.query(`
            SELECT * FROM config_drift_reports
            WHERE host_id = $1
            ORDER BY checked_at DESC
            LIMIT $2
        `, [hostId, limit]);

        return result.rows;
    }
}

module.exports = ConfigDriftDetector;
