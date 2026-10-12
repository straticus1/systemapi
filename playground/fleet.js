/**
 * SystemAPI.io fleet gateway.
 * Agents dial out. The control plane never opens an inbound SSH port.
 * Threats: query-string API keys, unsigned exec, and a demo key in production.
 * A missing lease is a refusal. This file does not store the API key.
 */

const WebSocket = require('ws');
const axios = require('axios');
const crypto = require('node:crypto');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { demoKeyAllowed, agentAuthFromRequest, ticketFromRequest } = require('../controlplane/httpauth');
const { validateTenant, validateHostId, validateHostname, validateSSHPublicKey } = require('../controlplane/sshkey');
const { consumeTicket } = require('../controlplane/tickets');
const { issueLease } = require('../controlplane/lease');
const { fingerprint, randomToken } = require('../controlplane/token');
const { zscore } = require('../controlplane/stats');
const { readPlaybook } = require('../controlplane/playbooks');
const { deliverWebhooks, COOLDOWN_MS } = require('../controlplane/router');

class FleetManager {
    constructor(server, db, apiSite = 'systemapi', prometheusMetrics = null) {
        this.wss = new WebSocket.Server({ noServer: true });
        this.db = db;
        this.apiSite = apiSite;
        this.metrics = prometheusMetrics;
        this.connectedAgents = new Map();
        this.terminalSubscribers = new Map();
        this.hostTenants = new Map();
        this.alertCooldown = new Map();
        this.pendingExecutions = new Map();
        this.signer = null;
        this.tickets = null;
        this.registry = null;
        this.env = process.env;

        const accessKey = process.env.DARKSTORAGE_ACCESS_KEY;
        const secretKey = process.env.DARKSTORAGE_SECRET_KEY;
        if (accessKey && secretKey) {
            this.darkStorage = new S3Client({
                region: 'us-east-1',
                endpoint: process.env.DARKSTORAGE_URL || 'http://127.0.0.1:9000',
                credentials: { accessKeyId: accessKey, secretAccessKey: secretKey },
                forcePathStyle: true
            });
        } else {
            this.darkStorage = null;
        }

        server.on('upgrade', (request, socket, head) => {
            this.handleUpgrade(request, socket, head).catch((err) => {
                console.error('[Fleet] upgrade failed:', err.message);
                if (!socket.destroyed) {
                    socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
                    socket.destroy();
                }
            });
        });

        this.wss.on('connection', this.handleConnection.bind(this));
    }

    rejectUpgrade(socket, status, reason) {
        socket.write(`HTTP/1.1 ${status} ${reason}\r\n\r\n`);
        socket.destroy();
    }

    async handleUpgrade(request, socket, head) {
        const parsed = new URL(request.url, 'http://127.0.0.1');
        if (parsed.pathname === '/api/v1/systems/stream') {
            await this.upgradeAgent(request, socket, head, parsed);
            return;
        }
        if (parsed.pathname.startsWith('/api/v1/systems/terminal/')) {
            await this.upgradeTerminal(request, socket, head, parsed);
            return;
        }
        this.rejectUpgrade(socket, 404, 'Not Found');
    }

    async upgradeAgent(request, socket, head, parsed) {
        const auth = agentAuthFromRequest(parsed, request.headers);
        if (!auth.ok) {
            this.rejectUpgrade(socket, auth.status, 'Unauthorized');
            return;
        }
        if (!this.registry) {
            this.rejectUpgrade(socket, 503, 'Unavailable');
            return;
        }
        const keyData = await this.verifyApiKey(auth.token);
        if (!keyData) {
            await this.noteSecurity('auth_fail', fingerprint(auth.token), { where: 'agent_upgrade' });
            this.rejectUpgrade(socket, 403, 'Forbidden');
            return;
        }
        let enroll;
        try {
            enroll = {
                tenant: validateTenant(request.headers['x-systemapi-tenant']),
                hostId: validateHostId(request.headers['x-systemapi-host-id']),
                hostname: validateHostname(request.headers['x-systemapi-hostname']),
                sshPubkey: validateSSHPublicKey(request.headers['x-systemapi-ssh-pubkey'])
            };
        } catch (err) {
            this.rejectUpgrade(socket, 401, 'Unauthorized');
            return;
        }
        request.systemapiEnroll = enroll;
        request.systemapiKey = keyData;
        this.wss.handleUpgrade(request, socket, head, (ws) => {
            this.wss.emit('connection', ws, request, keyData);
        });
    }

    async upgradeTerminal(request, socket, head, parsed) {
        const hostId = decodeURIComponent(parsed.pathname.split('/').pop() || '');
        const ticketRes = ticketFromRequest(parsed);
        if (!ticketRes.ok) {
            this.rejectUpgrade(socket, ticketRes.status, 'Unauthorized');
            return;
        }
        if (!this.tickets || !this.signer) {
            this.rejectUpgrade(socket, 503, 'Unavailable');
            return;
        }
        const purpose = parsed.searchParams.get('purpose') || 'terminal:open';
        if (purpose !== 'terminal:open' && purpose !== 'breakglass:open') {
            this.rejectUpgrade(socket, 401, 'Unauthorized');
            return;
        }
        const row = consumeTicket(this.tickets, ticketRes.ticket, hostId, purpose);
        if (!row) {
            this.rejectUpgrade(socket, 401, 'Unauthorized');
            return;
        }
        const action = purpose === 'breakglass:open' ? 'breakglass' : 'pty';
        let lease;
        try {
            lease = issueLease(this.signer, { hostId, action, payload: action, ttl: 60 });
        } catch (err) {
            this.rejectUpgrade(socket, err.status || 503, 'Unavailable');
            return;
        }
        const dashboardWss = new WebSocket.Server({ noServer: true });
        dashboardWss.handleUpgrade(request, socket, head, (ws) => {
            this.attachTerminalClient(hostId, ws, lease, action);
        });
    }

    async verifyApiKey(secretProvided) {
        if (typeof secretProvided !== 'string' || secretProvided.length === 0 || secretProvided.length > 512) {
            return null;
        }
        if (secretProvided === 'ak_live_1234.demo') {
            if (!demoKeyAllowed(this.env || process.env)) return null;
            return { key_id: 'ak_live_1234', user_id: 'demo_user' };
        }
        if (!this.db) return null;
        try {
            const parts = secretProvided.split('.');
            if (parts.length !== 2) return null;
            const keyId = parts[0];
            const res = await this.db.query(
                `SELECT key_id, user_id, key_hash FROM playground_api_keys
                 WHERE key_id = $1 AND api_site = $2 AND is_active = true AND is_locked = false`,
                [keyId, this.apiSite]
            );
            if (res.rows.length === 0) return null;
            const bcrypt = require('bcryptjs');
            const isValid = await bcrypt.compare(secretProvided, res.rows[0].key_hash);
            if (!isValid) return null;
            await this.db.query('UPDATE playground_api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_id = $1', [keyId]);
            return { key_id: res.rows[0].key_id, user_id: res.rows[0].user_id };
        } catch (err) {
            console.error('[Fleet] API key verification failed:', err.message);
            return null;
        }
    }

    async noteSecurity(kind, actorFingerprint, detail) {
        if (!this.registry) return;
        try {
            await this.registry.recordSecurity({ kind, actor_fingerprint: actorFingerprint, detail });
        } catch (err) {
            console.error('[Fleet] security event failed:', err.message);
        }
    }

    async handleConnection(ws, request, keyData) {
        const enroll = request.systemapiEnroll;
        const userId = keyData.user_id;
        const keyId = keyData.key_id;
        let hostId = null;
        console.log(`[Fleet] Agent connected key fingerprint sha256:${fingerprint(keyId)}`);

        ws.on('message', async (messageBuffer, isBinary) => {
            try {
                if (isBinary) {
                    if (hostId && this.terminalSubscribers.has(hostId)) {
                        const dashboardWs = this.terminalSubscribers.get(hostId);
                        if (dashboardWs.readyState === WebSocket.OPEN) dashboardWs.send(messageBuffer);
                    }
                    return;
                }
                const msg = JSON.parse(messageBuffer.toString());
                if (msg.type === 'telemetry') {
                    hostId = await this.handleTelemetry(keyId, userId, ws, msg.payload, hostId);
                } else if (msg.type === 'command_result') {
                    if (this.pendingExecutions && msg.request_id && this.pendingExecutions.has(msg.request_id)) {
                        const executionContext = this.pendingExecutions.get(msg.request_id);
                        this.logExecutionToDarkStorage(hostId, executionContext.script, msg.payload).catch((err) => {
                            console.error('[DarkStorage] audit write failed:', err.message);
                        });
                        executionContext.resolve(msg.payload);
                        this.pendingExecutions.delete(msg.request_id);
                    }
                } else if (msg.type === 'pty_status') {
                    if (hostId && this.terminalSubscribers.has(hostId)) {
                        const dashboardWs = this.terminalSubscribers.get(hostId);
                        if (dashboardWs.readyState === WebSocket.OPEN) dashboardWs.send(JSON.stringify(msg));
                    }
                }
            } catch (err) {
                console.error('[Fleet] message error:', err.message);
            }
        });

        ws.on('close', async () => {
            if (!hostId) return;
            this.connectedAgents.delete(hostId);
            if (this.terminalSubscribers.has(hostId)) {
                const dashboardWs = this.terminalSubscribers.get(hostId);
                if (dashboardWs.readyState === WebSocket.OPEN) {
                    dashboardWs.send(JSON.stringify({ type: 'pty_status', payload: { status: 'disconnected' } }));
                }
            }
            if (this.registry) {
                try { await this.registry.setHostStatus(hostId, 'offline'); } catch (err) {
                    console.error('[Fleet] status update failed:', err.message);
                }
            }
            if (this.db) {
                try {
                    await this.db.query(`UPDATE playground_hosts SET status = 'offline' WHERE host_id = $1`, [hostId]);
                } catch (err) {
                    console.error('[Fleet] legacy status update failed:', err.message);
                }
            }
        });

        const interval = setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) ws.ping();
            else clearInterval(interval);
        }, 30000);

        if (!this.signer) {
            ws.send(JSON.stringify({ type: 'enroll_error', error: 'signer_unavailable' }));
            ws.close();
            return;
        }
        if (!enroll || !this.registry) {
            ws.send(JSON.stringify({ type: 'enroll_error', error: 'enroll_required' }));
            ws.close();
            return;
        }
        try {
            const host = await this.registry.enroll({
                tenantId: enroll.tenant,
                userId,
                keyId,
                hostId: enroll.hostId,
                hostname: enroll.hostname,
                os: '',
                platform: '',
                sshPubkey: enroll.sshPubkey
            });
            hostId = host.host_id;
            this.hostTenants.set(hostId, host.tenant_id);
            this.connectedAgents.set(hostId, ws);
            ws.send(JSON.stringify({
                type: 'enrolled',
                host_id: hostId,
                control_pubkey: this.signer.publicKeyB64
            }));
        } catch (err) {
            await this.noteSecurity('enroll_rejected', fingerprint(keyId), { error: err.code || 'enroll_failed' });
            ws.send(JSON.stringify({ type: 'enroll_error', error: err.code || 'enroll_failed' }));
            ws.close();
        }
    }

    async handleTelemetry(keyId, userId, ws, payload, hostId) {
        if (!hostId || !this.registry) return hostId;
        const hostInfo = (payload && payload.host) || {};
        try {
            await this.registry.touchHost(hostId, {
                hostname: hostInfo.hostname,
                os: hostInfo.os,
                platform: hostInfo.platform
            });
        } catch (err) {
            console.error('[Fleet] touch failed:', err.message);
        }
        this.exportTelemetryToPrometheus(hostId, payload);
        await this.recordTelemetry(hostId, payload);
        await this.analyzeForAnomalies(hostId, payload);
        await this.evaluateRules(userId, hostId, payload);
        if (payload && Array.isArray(payload.software) && payload.software.length > 0) {
            this.processSoftwareInventory(hostId, payload.software).catch((err) => {
                console.error('[Software Inventory]', err.message);
            });
        }
        if (this.redis) {
            this.redis.publish('systemapi:telemetry', JSON.stringify({ host_id: hostId })).catch((err) => {
                console.error('[control] redis publish failed:', err.message);
            });
        }
        return hostId;
    }

    async recordTelemetry(hostId, telemetry) {
        if (!this.registry || !telemetry) return;
        if (telemetry.cpu && typeof telemetry.cpu.usage_percent === 'number') {
            await this.registry.recordMetric(hostId, 'cpu.usage_percent', telemetry.cpu.usage_percent);
        }
        if (telemetry.memory && typeof telemetry.memory.used_percent === 'number') {
            await this.registry.recordMetric(hostId, 'memory.used_percent', telemetry.memory.used_percent);
        }
        if (Array.isArray(telemetry.disk)) {
            for (const disk of telemetry.disk) {
                if (typeof disk.used_percent === 'number') {
                    await this.registry.recordMetric(hostId, 'disk.used_percent', disk.used_percent, { path: String(disk.path || '') });
                }
            }
        }
    }

    exportTelemetryToPrometheus(hostId, telemetry) {
        if (!this.metrics || !telemetry) return;
        const hostname = telemetry.host && telemetry.host.hostname ? telemetry.host.hostname : 'unknown';
        try {
            if (telemetry.cpu && typeof telemetry.cpu.usage_percent === 'number') {
                this.metrics.cpuUsageGauge.labels(hostId, hostname).set(telemetry.cpu.usage_percent);
            }
            if (telemetry.memory && typeof telemetry.memory.used_percent === 'number') {
                this.metrics.memoryUsageGauge.labels(hostId, hostname).set(telemetry.memory.used_percent);
            }
            if (Array.isArray(telemetry.disk)) {
                telemetry.disk.forEach((disk) => {
                    if (typeof disk.used_percent === 'number') {
                        this.metrics.diskUsageGauge.labels(hostId, hostname, disk.path || '/').set(disk.used_percent);
                    }
                });
            }
        } catch (err) {
            console.error('[Prometheus]', err.message);
        }
    }

    cooled(hostId, rule) {
        const key = `${rule}:${hostId}`;
        const prev = this.alertCooldown.get(key) || 0;
        if (Date.now() - prev < COOLDOWN_MS) return true;
        this.alertCooldown.set(key, Date.now());
        return false;
    }

    async analyzeForAnomalies(hostId, telemetry) {
        if (!this.registry || !telemetry) return;
        const checks = [
            ['cpu.usage_percent', telemetry.cpu && telemetry.cpu.usage_percent],
            ['memory.used_percent', telemetry.memory && telemetry.memory.used_percent]
        ];
        for (const [metric, value] of checks) {
            if (typeof value !== 'number') continue;
            const series = await this.registry.metricSeries(hostId, metric, 60);
            const score = zscore(series.map((point) => point.value));
            if (!score.anomalous) continue;
            const rule = `zscore:${metric}`;
            if (this.cooled(hostId, rule)) continue;
            if (await this.registry.recentAlert(hostId, rule, COOLDOWN_MS)) continue;
            const tenantId = this.hostTenants.get(hostId);
            if (!tenantId) continue;
            const alert = await this.registry.openAlert({
                tenant_id: tenantId,
                host_id: hostId,
                rule_name: rule,
                metric,
                value
            });
            await deliverWebhooks(this, tenantId, { type: 'anomaly', alert_id: alert.id, host_id: hostId, metric, value });
        }
    }

    async evaluateRules(userId, hostId, telemetry) {
        if (!this.db || !telemetry) return;
        try {
            const res = await this.db.query(
                `SELECT alert_id, metric, operator, threshold_value, action_type, action_target, name
                 FROM playground_alerts
                 WHERE user_id = $1 AND api_site = $2 AND is_active = true`,
                [userId, this.apiSite]
            );
            for (const rule of res.rows) this.checkRule(userId, hostId, telemetry, rule);
        } catch (err) {
            console.error('[Fleet] rule lookup failed:', err.message);
        }
    }

    checkRule(userId, hostId, telemetry, rule) {
        let valueToTest = null;
        if (rule.metric === 'cpu.usage_percent') valueToTest = telemetry.cpu && telemetry.cpu.usage_percent;
        if (rule.metric === 'memory.used_percent') valueToTest = telemetry.memory && telemetry.memory.used_percent;
        if (typeof valueToTest !== 'number') return;
        const threshold = parseFloat(rule.threshold_value);
        let triggered = false;
        if (rule.operator === '>') triggered = valueToTest > threshold;
        if (rule.operator === '<') triggered = valueToTest < threshold;
        if (rule.operator === '=') triggered = valueToTest === threshold;
        if (triggered) {
            const hostname = telemetry.host && telemetry.host.hostname;
            this.triggerIncident(rule, valueToTest, hostId, hostname);
        }
    }

    async triggerIncident(rule, actualValue, hostId, hostname) {
        const ruleName = rule.name || rule.metric;
        if (this.cooled(hostId, `rule:${ruleName}`)) return;
        const message = `[SystemAPI.io Incident] Alert '${ruleName}' triggered on ${hostname || hostId}. Metric was ${Number(actualValue).toFixed(2)}.`;
        console.log(`[ALERT] ${ruleName} on ${hostId}`);
        if (rule.action_type === 'sms') await this.sendAdstelcoSMS(rule.action_target, message);
        else if (rule.action_type === 'voice') await this.sendAdstelcoVoice(rule.action_target, message);
        else if (rule.action_type === 'playbook') await this.dispatchPlaybook(rule.action_target, hostId);
    }

    async dispatchPlaybook(playbookId, hostId) {
        let script;
        try {
            script = readPlaybook(playbookId);
        } catch (err) {
            console.error('[PLAYBOOK] refused:', err.message);
            return;
        }
        if (!this.signer) {
            console.error('[PLAYBOOK] signer unavailable');
            return;
        }
        const lease = issueLease(this.signer, { hostId, action: 'sysscript', payload: script, ttl: 60 });
        await this.pushSysscript(hostId, script, {
            allow_exec: true,
            allow_fs_write: false,
            allow_fs_read: false,
            allow_net_outbound: false,
            allow_config_write: false,
            allow_service_reload: false,
            allow_containers: false,
            allow_k3s: false
        }, randomToken(16), lease);
    }

    async sendAdstelcoSMS(toPhone, body) {
        if (!process.env.ADSTELCO_KEY) return;
        try {
            await axios.post(
                'http://127.0.0.1:3000/api/v1/sms/send',
                { to: toPhone, body },
                { headers: { Authorization: `Bearer ${process.env.ADSTELCO_KEY}` }, timeout: 5000, maxRedirects: 0 }
            );
        } catch (err) {
            console.error('[adstelco] SMS send failed:', err.message);
        }
    }

    async sendAdstelcoVoice(toPhone, message) {
        if (!process.env.ADSTELCO_KEY) return;
        try {
            await axios.post(
                'http://127.0.0.1:3000/api/v1/voice/call',
                { to: toPhone, tts_message: message },
                { headers: { Authorization: `Bearer ${process.env.ADSTELCO_KEY}` }, timeout: 5000, maxRedirects: 0 }
            );
        } catch (err) {
            console.error('[adstelco] voice call failed:', err.message);
        }
    }

    async logExecutionToDarkStorage(hostId, script, resultPayload) {
        const hash = crypto.createHash('sha256').update(String(script)).digest('hex');
        if (this.registry && hostId) {
            await this.registry.appendAudit({
                tenant_id: this.hostTenants.get(hostId) || null,
                host_id: hostId,
                actor: 'agent',
                action: 'command_result',
                payload: { script_sha256: hash }
            });
        }
        if (!this.darkStorage || !hostId) return;
        const timestamp = new Date().toISOString();
        const command = new PutObjectCommand({
            Bucket: 'systemapi-audits',
            Key: `sysscript-audits/${hostId}/${timestamp}-${hash.substring(0, 8)}.json`,
            Body: JSON.stringify({ host_id: hostId, timestamp, script_sha256: hash }),
            ContentType: 'application/json'
        });
        await this.darkStorage.send(command);
    }

    async processSoftwareInventory(hostId, softwareList) {
        if (!this.registry) return;
        for (const sw of softwareList) {
            if (!sw || typeof sw !== 'object') continue;
            const saved = await this.registry.upsertSoftware(hostId, sw);
            if (saved.inserted) await this.checkDarkAPIForCVEs(hostId, sw.name || 'unknown', sw.version || 'unknown');
        }
    }

    async checkDarkAPIForCVEs(hostId, name, version) {
        if (!process.env.DARKAPI_KEY) return;
        const darkUrl = process.env.DARKAPI_URL || 'https://api.darkapi.io';
        try {
            const response = await axios.get(
                `${darkUrl}/v1/cve/software/${encodeURIComponent(name)}/${encodeURIComponent(version)}`,
                { headers: { 'X-API-Key': process.env.DARKAPI_KEY }, timeout: 5000, maxRedirects: 0 }
            );
            const vulnerabilities = (response.data && response.data.cves) || [];
            for (const vuln of vulnerabilities) {
                if (!vuln || typeof vuln.id !== 'string') continue;
                await this.registry.saveCVE({
                    host_id: hostId,
                    software_name: name,
                    software_version: version,
                    cve_id: vuln.id,
                    severity: vuln.severity,
                    description: vuln.description
                });
            }
        } catch (err) {
            console.error('[DarkAPI] CVE lookup failed:', err.message);
        }
    }

    pushSysscript(hostId, script, entitlements, requestId, lease) {
        return new Promise((resolve, reject) => {
            if (!lease || typeof lease.signature !== 'string') {
                reject(Object.assign(new Error('lease_required'), { status: 503, code: 'lease_required' }));
                return;
            }
            const ws = this.connectedAgents.get(hostId);
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                reject(Object.assign(new Error('agent_offline'), { status: 409, code: 'agent_offline' }));
                return;
            }
            this.pendingExecutions.set(requestId, { resolve, reject, script });
            setTimeout(() => {
                if (this.pendingExecutions.has(requestId)) {
                    this.pendingExecutions.get(requestId).reject(Object.assign(new Error('agent_timeout'), { status: 504, code: 'agent_timeout' }));
                    this.pendingExecutions.delete(requestId);
                }
            }, 30000);
            ws.send(JSON.stringify({
                type: 'sysscript',
                script,
                entitlements: entitlements || {},
                request_id: requestId,
                lease
            }));
        });
    }

    attachTerminalClient(hostId, dashboardWs, lease, action) {
        if (!lease || typeof lease.signature !== 'string') {
            dashboardWs.send(JSON.stringify({ type: 'pty_status', payload: { error: 'lease_required' } }));
            dashboardWs.close();
            return;
        }
        this.terminalSubscribers.set(hostId, dashboardWs);
        const agentWs = this.connectedAgents.get(hostId);
        if (agentWs && agentWs.readyState === WebSocket.OPEN) {
            agentWs.send(JSON.stringify({
                type: 'pty_start',
                request_id: randomToken(16),
                action: action || 'pty',
                lease
            }));
        } else {
            dashboardWs.send(JSON.stringify({ type: 'pty_status', payload: { error: 'Agent offline' } }));
        }
        dashboardWs.on('close', () => {
            this.terminalSubscribers.delete(hostId);
            if (agentWs && agentWs.readyState === WebSocket.OPEN) {
                agentWs.send(JSON.stringify({ type: 'pty_stop' }));
            }
        });
        dashboardWs.on('message', (msgBuffer, isBinary) => {
            if (!agentWs || agentWs.readyState !== WebSocket.OPEN || isBinary) return;
            try {
                const cmd = JSON.parse(msgBuffer.toString());
                if (cmd && (cmd.type === 'pty_input' || cmd.type === 'pty_resize')) {
                    agentWs.send(JSON.stringify(cmd));
                }
            } catch {
                agentWs.send(JSON.stringify({ type: 'pty_input', data: msgBuffer.toString() }));
            }
        });
    }
}

module.exports = FleetManager;
