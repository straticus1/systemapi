/**
 * Time Travel Debugger
 * Captures system state snapshots for historical analysis and replay
 * "Go back in time" to see exactly what your system looked like at any point
 */

const crypto = require('crypto');
const zlib = require('zlib');

class TimeTravelDebugger {
    constructor(db, fleetManager) {
        this.db = db;
        this.fleetManager = fleetManager;
        this.snapshots = new Map();

        // What to capture in snapshots
        this.captureSpecs = {
            processes: true,
            network: true,
            files: true,
            environment: true,
            services: true,
            logs: true,
            metrics: true
        };
    }

    /**
     * Create a snapshot of current system state
     */
    async createSnapshot(hostId, options = {}) {
        const snapshotId = `snap_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

        console.log(`📸 Creating snapshot: ${snapshotId} for ${hostId}`);

        const snapshot = {
            snapshot_id: snapshotId,
            host_id: hostId,
            created_at: new Date(),
            label: options.label || 'Manual snapshot',
            trigger: options.trigger || 'manual',

            // System state
            state: {}
        };

        // Capture different aspects of system state
        if (options.capture_processes !== false) {
            snapshot.state.processes = await this.captureProcesses(hostId);
        }

        if (options.capture_network !== false) {
            snapshot.state.network = await this.captureNetwork(hostId);
        }

        if (options.capture_files !== false && options.file_paths) {
            snapshot.state.files = await this.captureFiles(hostId, options.file_paths);
        }

        if (options.capture_environment !== false) {
            snapshot.state.environment = await this.captureEnvironment(hostId);
        }

        if (options.capture_services !== false) {
            snapshot.state.services = await this.captureServices(hostId);
        }

        if (options.capture_logs !== false) {
            snapshot.state.logs = await this.captureLogs(hostId, options.log_paths || ['/var/log/syslog']);
        }

        if (options.capture_metrics !== false) {
            snapshot.state.metrics = await this.captureMetrics(hostId);
        }

        // Calculate snapshot size
        const stateJson = JSON.stringify(snapshot.state);
        snapshot.size_bytes = Buffer.byteLength(stateJson);

        // Compress if large
        let storedData = stateJson;
        let compressed = false;
        if (snapshot.size_bytes > 10000) {
            storedData = zlib.gzipSync(stateJson);
            compressed = true;
            snapshot.compressed_size = storedData.length;
        }

        // Store in database
        await this.db.query(`
            INSERT INTO time_travel_snapshots (
                snapshot_id, host_id, created_at, label, trigger,
                size_bytes, is_compressed, state_data
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `, [
            snapshotId, hostId, snapshot.created_at, snapshot.label,
            snapshot.trigger, snapshot.size_bytes, compressed, storedData
        ]);

        this.snapshots.set(snapshotId, snapshot);

        console.log(`✅ Snapshot created: ${snapshotId} (${this.formatBytes(snapshot.size_bytes)})`);

        return {
            snapshot_id: snapshotId,
            created_at: snapshot.created_at,
            size_bytes: snapshot.size_bytes,
            label: snapshot.label
        };
    }

    /**
     * Capture running processes
     */
    async captureProcesses(hostId) {
        const cmd = `ps aux --sort=-%cpu | head -100`;
        const result = await this.fleetManager.executeCommand(hostId, cmd);

        const processes = [];
        const lines = result.stdout.split('\n').slice(1); // Skip header

        for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length >= 11) {
                processes.push({
                    user: parts[0],
                    pid: parseInt(parts[1]),
                    cpu: parseFloat(parts[2]),
                    mem: parseFloat(parts[3]),
                    vsz: parseInt(parts[4]),
                    rss: parseInt(parts[5]),
                    tty: parts[6],
                    stat: parts[7],
                    start: parts[8],
                    time: parts[9],
                    command: parts.slice(10).join(' ')
                });
            }
        }

        return {
            total_processes: processes.length,
            processes: processes,
            captured_at: new Date()
        };
    }

    /**
     * Capture network state
     */
    async captureNetwork(hostId) {
        const commands = {
            connections: `netstat -tunap 2>/dev/null | grep ESTABLISHED || ss -tunap | grep ESTAB`,
            interfaces: `ip addr show 2>/dev/null || ifconfig`,
            routes: `ip route show 2>/dev/null || route -n`,
            listening: `netstat -tuln 2>/dev/null | grep LISTEN || ss -tuln | grep LISTEN`
        };

        const network = {};

        for (const [key, cmd] of Object.entries(commands)) {
            try {
                const result = await this.fleetManager.executeCommand(hostId, cmd);
                network[key] = result.stdout;
            } catch (error) {
                network[key] = `Error: ${error.message}`;
            }
        }

        return {
            ...network,
            captured_at: new Date()
        };
    }

    /**
     * Capture specific files
     */
    async captureFiles(hostId, filePaths) {
        const files = [];

        for (const path of filePaths) {
            try {
                const result = await this.fleetManager.executeCommand(
                    hostId,
                    `if [ -f "${path}" ]; then cat "${path}" && stat -c "%Y %s" "${path}" 2>/dev/null || stat -f "%m %z" "${path}" 2>/dev/null; fi`
                );

                if (result.exit_code === 0 && result.stdout) {
                    const lines = result.stdout.split('\n');
                    const statLine = lines[lines.length - 1];
                    const content = lines.slice(0, -1).join('\n');
                    const [mtime, size] = statLine.split(' ');

                    files.push({
                        path: path,
                        content: content,
                        size: parseInt(size) || 0,
                        mtime: parseInt(mtime) || 0,
                        hash: crypto.createHash('md5').update(content).digest('hex')
                    });
                }
            } catch (error) {
                files.push({
                    path: path,
                    error: error.message
                });
            }
        }

        return {
            total_files: files.length,
            files: files,
            captured_at: new Date()
        };
    }

    /**
     * Capture environment variables
     */
    async captureEnvironment(hostId) {
        const result = await this.fleetManager.executeCommand(hostId, 'env | sort');

        const envVars = {};
        const lines = result.stdout.split('\n');

        for (const line of lines) {
            const [key, ...valueParts] = line.split('=');
            if (key) {
                envVars[key] = valueParts.join('=');
            }
        }

        // Also get system info
        const unameResult = await this.fleetManager.executeCommand(hostId, 'uname -a');
        const hostnameResult = await this.fleetManager.executeCommand(hostId, 'hostname -f 2>/dev/null || hostname');

        return {
            env_vars: envVars,
            uname: unameResult.stdout.trim(),
            hostname: hostnameResult.stdout.trim(),
            captured_at: new Date()
        };
    }

    /**
     * Capture systemd services
     */
    async captureServices(hostId) {
        const result = await this.fleetManager.executeCommand(
            hostId,
            'systemctl list-units --type=service --all --no-pager 2>/dev/null || service --status-all 2>&1'
        );

        return {
            services_output: result.stdout,
            captured_at: new Date()
        };
    }

    /**
     * Capture recent logs
     */
    async captureLogs(hostId, logPaths) {
        const logs = {};

        for (const path of logPaths) {
            try {
                const result = await this.fleetManager.executeCommand(
                    hostId,
                    `tail -n 100 ${path} 2>/dev/null`
                );

                logs[path] = {
                    lines: result.stdout.split('\n'),
                    line_count: result.stdout.split('\n').length
                };
            } catch (error) {
                logs[path] = { error: error.message };
            }
        }

        return {
            logs: logs,
            captured_at: new Date()
        };
    }

    /**
     * Capture current metrics
     */
    async captureMetrics(hostId) {
        // Get latest telemetry
        const telemetry = await this.fleetManager.getLatestTelemetry(hostId);

        return {
            cpu: telemetry?.cpu || null,
            memory: telemetry?.memory || null,
            disk: telemetry?.disk || null,
            network: telemetry?.network || null,
            load_average: telemetry?.load_average || null,
            uptime: telemetry?.uptime || null,
            captured_at: new Date()
        };
    }

    /**
     * Get snapshot by ID
     */
    async getSnapshot(snapshotId) {
        let snapshot = this.snapshots.get(snapshotId);

        if (!snapshot) {
            // Load from database
            snapshot = await this.loadSnapshot(snapshotId);
        }

        return snapshot;
    }

    /**
     * Compare two snapshots
     */
    async compareSnapshots(snapshotId1, snapshotId2) {
        const snap1 = await this.getSnapshot(snapshotId1);
        const snap2 = await this.getSnapshot(snapshotId2);

        if (!snap1 || !snap2) {
            throw new Error('One or both snapshots not found');
        }

        const comparison = {
            snapshot1: {
                id: snap1.snapshot_id,
                created_at: snap1.created_at,
                label: snap1.label
            },
            snapshot2: {
                id: snap2.snapshot_id,
                created_at: snap2.created_at,
                label: snap2.label
            },
            time_difference_ms: new Date(snap2.created_at) - new Date(snap1.created_at),
            differences: {}
        };

        // Compare processes
        if (snap1.state.processes && snap2.state.processes) {
            comparison.differences.processes = this.compareProcesses(
                snap1.state.processes,
                snap2.state.processes
            );
        }

        // Compare files
        if (snap1.state.files && snap2.state.files) {
            comparison.differences.files = this.compareFiles(
                snap1.state.files,
                snap2.state.files
            );
        }

        // Compare metrics
        if (snap1.state.metrics && snap2.state.metrics) {
            comparison.differences.metrics = this.compareMetrics(
                snap1.state.metrics,
                snap2.state.metrics
            );
        }

        // Compare network
        if (snap1.state.network && snap2.state.network) {
            comparison.differences.network = {
                connections_changed: snap1.state.network.connections !== snap2.state.network.connections,
                interfaces_changed: snap1.state.network.interfaces !== snap2.state.network.interfaces
            };
        }

        return comparison;
    }

    /**
     * Compare process lists
     */
    compareProcesses(processes1, processes2) {
        const pids1 = new Set(processes1.processes.map(p => p.pid));
        const pids2 = new Set(processes2.processes.map(p => p.pid));

        const added = processes2.processes.filter(p => !pids1.has(p.pid));
        const removed = processes1.processes.filter(p => !pids2.has(p.pid));

        const common = processes2.processes.filter(p => pids1.has(p.pid));
        const changed = [];

        for (const proc2 of common) {
            const proc1 = processes1.processes.find(p => p.pid === proc2.pid);
            if (proc1 && (proc1.cpu !== proc2.cpu || proc1.mem !== proc2.mem)) {
                changed.push({
                    pid: proc2.pid,
                    command: proc2.command,
                    cpu_change: proc2.cpu - proc1.cpu,
                    mem_change: proc2.mem - proc1.mem
                });
            }
        }

        return {
            added_count: added.length,
            removed_count: removed.length,
            changed_count: changed.length,
            added: added.slice(0, 10),
            removed: removed.slice(0, 10),
            changed: changed.slice(0, 10)
        };
    }

    /**
     * Compare file states
     */
    compareFiles(files1, files2) {
        const fileMap1 = new Map(files1.files.map(f => [f.path, f]));
        const fileMap2 = new Map(files2.files.map(f => [f.path, f]));

        const changes = [];

        for (const [path, file2] of fileMap2) {
            const file1 = fileMap1.get(path);

            if (!file1) {
                changes.push({ path, type: 'added' });
            } else if (file1.hash !== file2.hash) {
                changes.push({
                    path,
                    type: 'modified',
                    size_change: file2.size - file1.size
                });
            }
        }

        for (const [path] of fileMap1) {
            if (!fileMap2.has(path)) {
                changes.push({ path, type: 'removed' });
            }
        }

        return {
            total_changes: changes.length,
            changes: changes
        };
    }

    /**
     * Compare metrics
     */
    compareMetrics(metrics1, metrics2) {
        return {
            cpu_change: (metrics2.cpu?.usage_percent || 0) - (metrics1.cpu?.usage_percent || 0),
            memory_change: (metrics2.memory?.used_percent || 0) - (metrics1.memory?.used_percent || 0),
            disk_change: (metrics2.disk?.[0]?.used_percent || 0) - (metrics1.disk?.[0]?.used_percent || 0)
        };
    }

    /**
     * Create automatic snapshots on a schedule
     */
    async enableAutoSnapshots(hostId, intervalMinutes = 60, options = {}) {
        // In production, this would use a scheduler like node-cron
        console.log(`🕐 Auto-snapshots enabled for ${hostId}: every ${intervalMinutes} minutes`);

        // Store schedule in database
        await this.db.query(`
            INSERT INTO auto_snapshot_schedules (
                host_id, interval_minutes, options, enabled, created_at
            ) VALUES ($1, $2, $3, true, $4)
        `, [hostId, intervalMinutes, JSON.stringify(options), new Date()]);

        return {
            host_id: hostId,
            interval_minutes: intervalMinutes,
            enabled: true
        };
    }

    /**
     * Replay system state to a specific snapshot
     */
    async replayToSnapshot(hostId, snapshotId, options = {}) {
        const snapshot = await this.getSnapshot(snapshotId);

        if (!snapshot) {
            throw new Error(`Snapshot ${snapshotId} not found`);
        }

        console.log(`⏪ Replaying ${hostId} to snapshot ${snapshotId}`);

        const actions = [];

        // Restore files
        if (options.restore_files && snapshot.state.files) {
            for (const file of snapshot.state.files.files) {
                if (!file.error && file.content) {
                    actions.push({
                        type: 'restore_file',
                        path: file.path,
                        status: options.dry_run ? 'dry_run' : 'pending'
                    });

                    if (!options.dry_run) {
                        try {
                            const content = file.content.replace(/'/g, "'\\''");
                            await this.fleetManager.executeCommand(
                                hostId,
                                `cat > ${file.path} <<'EOF'\n${content}\nEOF`
                            );
                            actions[actions.length - 1].status = 'success';
                        } catch (error) {
                            actions[actions.length - 1].status = 'failed';
                            actions[actions.length - 1].error = error.message;
                        }
                    }
                }
            }
        }

        return {
            host_id: hostId,
            snapshot_id: snapshotId,
            replayed_to: snapshot.created_at,
            dry_run: options.dry_run || false,
            actions: actions,
            total_actions: actions.length,
            successful: actions.filter(a => a.status === 'success').length
        };
    }

    /**
     * Get snapshot timeline for a host
     */
    async getTimeline(hostId, options = {}) {
        const limit = options.limit || 100;
        const result = await this.db.query(`
            SELECT snapshot_id, created_at, label, trigger, size_bytes
            FROM time_travel_snapshots
            WHERE host_id = $1
            ORDER BY created_at DESC
            LIMIT $2
        `, [hostId, limit]);

        return result.rows;
    }

    /**
     * Find snapshot closest to a specific time
     */
    async findSnapshotAtTime(hostId, targetTime) {
        const result = await this.db.query(`
            SELECT snapshot_id, created_at, ABS(EXTRACT(EPOCH FROM (created_at - $2))) as time_diff
            FROM time_travel_snapshots
            WHERE host_id = $1
            ORDER BY time_diff ASC
            LIMIT 1
        `, [hostId, targetTime]);

        if (result.rows.length === 0) {
            return null;
        }

        return await this.loadSnapshot(result.rows[0].snapshot_id);
    }

    /**
     * Load snapshot from database
     */
    async loadSnapshot(snapshotId) {
        const result = await this.db.query(`
            SELECT * FROM time_travel_snapshots
            WHERE snapshot_id = $1
        `, [snapshotId]);

        if (result.rows.length === 0) {
            return null;
        }

        const row = result.rows[0];

        // Decompress if needed
        let stateData = row.state_data;
        if (row.is_compressed) {
            stateData = zlib.gunzipSync(stateData);
        }

        const snapshot = {
            snapshot_id: row.snapshot_id,
            host_id: row.host_id,
            created_at: row.created_at,
            label: row.label,
            trigger: row.trigger,
            size_bytes: row.size_bytes,
            state: JSON.parse(stateData.toString())
        };

        this.snapshots.set(snapshotId, snapshot);
        return snapshot;
    }

    /**
     * Delete old snapshots
     */
    async cleanupOldSnapshots(hostId, daysToKeep = 30) {
        const result = await this.db.query(`
            DELETE FROM time_travel_snapshots
            WHERE host_id = $1
              AND created_at < NOW() - INTERVAL '${daysToKeep} days'
            RETURNING snapshot_id
        `, [hostId]);

        console.log(`🧹 Cleaned up ${result.rowCount} old snapshots for ${hostId}`);

        return {
            deleted_count: result.rowCount,
            deleted_snapshots: result.rows.map(r => r.snapshot_id)
        };
    }

    /**
     * Helper: format bytes
     */
    formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    }
}

module.exports = TimeTravelDebugger;
