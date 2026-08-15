/**
 * ChatOps AI Assistant
 * Natural language interface for fleet management via Slack, Discord, Teams, etc.
 */

const crypto = require('crypto');

class ChatOpsAssistant {
    constructor(db, fleetManager, config = {}) {
        this.db = db;
        this.fleetManager = fleetManager;
        this.conversationHistory = new Map(); // sessionId -> messages[]

        this.capabilities = {
            fleet_status: true,
            execute_commands: config.allow_execution !== false,
            host_diagnostics: true,
            incident_management: true,
            monitoring: true,
            report_generation: true
        };

        // Intent patterns
        this.intents = this.initializeIntents();
    }

    /**
     * Initialize intent recognition patterns
     */
    initializeIntents() {
        return {
            // Fleet status queries
            'fleet_status': {
                patterns: [
                    /how (many|much) (hosts?|servers?|machines?)/i,
                    /fleet (status|health|overview)/i,
                    /show (me )?(all )?hosts?/i,
                    /list (all )?hosts?/i
                ],
                handler: 'getFleetStatus'
            },

            // Host specific queries
            'host_info': {
                patterns: [
                    /info (about|on|for) (.+)/i,
                    /status of (.+)/i,
                    /show me (.+)/i,
                    /what('s| is) (.+)/i
                ],
                handler: 'getHostInfo',
                extractEntity: true
            },

            // Health checks
            'health_check': {
                patterns: [
                    /(check|test) health of (.+)/i,
                    /is (.+) (healthy|ok|working|up)/i,
                    /ping (.+)/i
                ],
                handler: 'checkHealth',
                extractEntity: true
            },

            // Resource usage
            'resource_usage': {
                patterns: [
                    /cpu usage (on|of|for) (.+)/i,
                    /memory (on|of|for) (.+)/i,
                    /disk (space|usage) (on|of|for) (.+)/i,
                    /show (me )?resources? (on|of|for) (.+)/i
                ],
                handler: 'getResourceUsage',
                extractEntity: true
            },

            // Command execution
            'execute_command': {
                patterns: [
                    /run (.+) on (.+)/i,
                    /execute (.+) on (.+)/i,
                    /(restart|stop|start) (.+) on (.+)/i
                ],
                handler: 'executeCommand',
                extractEntity: true,
                requiresApproval: true
            },

            // Incident management
            'list_incidents': {
                patterns: [
                    /(show|list|get) (active )?incidents?/i,
                    /what('s| is) (wrong|broken|failing)/i,
                    /any (issues|problems|alerts)/i
                ],
                handler: 'listIncidents'
            },

            // Logs
            'view_logs': {
                patterns: [
                    /(show|get|tail|view) logs? (from|of|for) (.+)/i,
                    /logs? (from|of|for) (.+)/i
                ],
                handler: 'viewLogs',
                extractEntity: true
            },

            // Reports
            'generate_report': {
                patterns: [
                    /generate (a )?report/i,
                    /create (a )?report/i,
                    /(weekly|daily|monthly) report/i
                ],
                handler: 'generateReport'
            },

            // Predictions
            'predictions': {
                patterns: [
                    /predict (failures?|issues?)/i,
                    /(when|what) will fail/i,
                    /maintenance (predictions?|forecast)/i
                ],
                handler: 'getPredictions'
            },

            // Help
            'help': {
                patterns: [
                    /help/i,
                    /what can you do/i,
                    /commands?/i
                ],
                handler: 'showHelp'
            },

            // Greeting
            'greeting': {
                patterns: [
                    /(hi|hello|hey|howdy)/i
                ],
                handler: 'greet'
            }
        };
    }

    /**
     * Process incoming message from chat platform
     */
    async processMessage(message, context = {}) {
        const sessionId = context.session_id || crypto.randomUUID();

        // Store message in conversation history
        this.addToHistory(sessionId, 'user', message);

        // Recognize intent
        const intent = this.recognizeIntent(message);

        if (!intent) {
            const response = "I'm not sure I understand. Try asking me about fleet status, host information, or type 'help' to see what I can do.";
            this.addToHistory(sessionId, 'assistant', response);
            return { response, intent: null };
        }

        console.log(`💬 ChatOps intent: ${intent.name} from ${context.user_id || 'unknown'}`);

        // Check if command requires approval
        if (intent.requiresApproval && !context.approved) {
            return await this.requestApproval(message, intent, context);
        }

        // Execute intent handler
        try {
            const response = await this[intent.handler](message, intent.entities, context);
            this.addToHistory(sessionId, 'assistant', response);

            return {
                response: response,
                intent: intent.name,
                session_id: sessionId
            };
        } catch (error) {
            console.error('ChatOps error:', error);
            const errorResponse = `Sorry, I encountered an error: ${error.message}`;
            this.addToHistory(sessionId, 'assistant', errorResponse);

            return {
                response: errorResponse,
                error: error.message,
                intent: intent.name
            };
        }
    }

    /**
     * Recognize intent from message
     */
    recognizeIntent(message) {
        for (const [intentName, intent] of Object.entries(this.intents)) {
            for (const pattern of intent.patterns) {
                const match = message.match(pattern);
                if (match) {
                    return {
                        name: intentName,
                        handler: intent.handler,
                        requiresApproval: intent.requiresApproval || false,
                        entities: intent.extractEntity ? this.extractEntities(match) : null
                    };
                }
            }
        }
        return null;
    }

    /**
     * Extract entities from regex match
     */
    extractEntities(match) {
        // Extract captured groups as entities
        return {
            full_match: match[0],
            groups: match.slice(1).filter(Boolean)
        };
    }

    /**
     * Intent Handlers
     */

    async getFleetStatus(message, entities, context) {
        const status = await this.fleetManager.getFleetSummary();

        return `
📊 **Fleet Status**

Total Hosts: ${status.total_hosts}
Online: ${status.online_hosts} ✅
Offline: ${status.offline_hosts} ❌

**Aggregate Resources:**
- CPU: ${status.avg_cpu?.toFixed(1)}% average
- Memory: ${status.avg_memory?.toFixed(1)}% average
- Disk: ${status.avg_disk?.toFixed(1)}% average

Need more details? Ask me about specific hosts or resources!
        `.trim();
    }

    async getHostInfo(message, entities, context) {
        const hostname = entities.groups[entities.groups.length - 1];
        const host = await this.fleetManager.findHost(hostname);

        if (!host) {
            return `❌ I couldn't find a host named "${hostname}". Try "list hosts" to see all available hosts.`;
        }

        return `
🖥️  **${host.hostname}**

Status: ${host.status === 'online' ? '✅ Online' : '❌ Offline'}
IP: ${host.ip_address || 'N/A'}
OS: ${host.os || 'Unknown'}
Last Seen: ${this.formatTime(host.last_seen)}

**Resources:**
- CPU: ${host.cpu_usage || 0}%
- Memory: ${host.memory_usage || 0}%
- Disk: ${host.disk_usage || 0}%

**Uptime:** ${this.formatUptime(host.uptime)}
        `.trim();
    }

    async checkHealth(message, entities, context) {
        const hostname = entities.groups[entities.groups.length - 1];
        const health = await this.fleetManager.healthCheck(hostname);

        if (!health) {
            return `❌ Unable to reach ${hostname}. Host may be offline or unreachable.`;
        }

        const healthStatus = health.status === 'healthy' ? '✅ Healthy' : '⚠️  Issues Detected';

        return `
${healthStatus} - **${hostname}**

Ping: ${health.ping_ms}ms
Services: ${health.services_ok}/${health.services_total} OK
Last Check: ${this.formatTime(health.checked_at)}

${health.issues?.length > 0 ? `\n**Issues:**\n${health.issues.map(i => `- ${i}`).join('\n')}` : ''}
        `.trim();
    }

    async getResourceUsage(message, entities, context) {
        const hostname = entities.groups[entities.groups.length - 1];
        const resources = await this.fleetManager.getResources(hostname);

        if (!resources) {
            return `❌ Couldn't get resource data for ${hostname}`;
        }

        return `
📈 **Resource Usage - ${hostname}**

**CPU:** ${resources.cpu_percent}% ${this.getUsageBar(resources.cpu_percent)}
Cores: ${resources.cpu_cores} | Load: ${resources.load_average?.join(', ')}

**Memory:** ${resources.memory_percent}% ${this.getUsageBar(resources.memory_percent)}
Used: ${this.formatBytes(resources.memory_used)} / ${this.formatBytes(resources.memory_total)}

**Disk:** ${resources.disk_percent}% ${this.getUsageBar(resources.disk_percent)}
Used: ${this.formatBytes(resources.disk_used)} / ${this.formatBytes(resources.disk_total)}

**Network:**
⬇️  In: ${this.formatBytes(resources.network_in)}/s
⬆️  Out: ${this.formatBytes(resources.network_out)}/s
        `.trim();
    }

    async executeCommand(message, entities, context) {
        if (!this.capabilities.execute_commands) {
            return `❌ Command execution is disabled. Contact your administrator.`;
        }

        const command = entities.groups[0];
        const hostname = entities.groups[1];

        // Safety check
        const isDangerous = /rm\s+-rf|dd\s+if=|mkfs|DROP/i.test(command);
        if (isDangerous && !context.force_approved) {
            return `⚠️  **DANGEROUS COMMAND DETECTED**

This command could be destructive: \`${command}\`

Please use the command approval workflow to execute this safely.`;
        }

        const result = await this.fleetManager.executeCommand(hostname, command);

        return `
✅ **Command Executed**

Host: ${hostname}
Command: \`${command}\`

**Output:**
\`\`\`
${result.stdout || '(no output)'}
${result.stderr ? `\nErrors:\n${result.stderr}` : ''}
\`\`\`

Exit Code: ${result.exit_code}
        `.trim();
    }

    async listIncidents(message, entities, context) {
        const incidents = await this.fleetManager.getActiveIncidents();

        if (incidents.length === 0) {
            return `✅ No active incidents! Everything looks good.`;
        }

        let response = `🚨 **Active Incidents (${incidents.length})**\n\n`;

        for (const incident of incidents.slice(0, 5)) {
            const severity = {
                critical: '🔴',
                high: '🟠',
                medium: '🟡',
                low: '🟢'
            }[incident.severity] || '⚪';

            response += `${severity} **${incident.name}**\n`;
            response += `   ${incident.description}\n`;
            response += `   Affected: ${incident.affected_hosts?.length || 0} hosts\n`;
            response += `   Impact: ${incident.impact_score}/100\n\n`;
        }

        if (incidents.length > 5) {
            response += `\n... and ${incidents.length - 5} more incidents`;
        }

        return response.trim();
    }

    async viewLogs(message, entities, context) {
        const hostname = entities.groups[entities.groups.length - 1];
        const logs = await this.fleetManager.getLogs(hostname, { lines: 20 });

        if (!logs || logs.length === 0) {
            return `❌ No recent logs found for ${hostname}`;
        }

        return `
📜 **Recent Logs - ${hostname}**

\`\`\`
${logs.join('\n')}
\`\`\`

Showing last 20 lines. Need more? Ask me to "get full logs for ${hostname}"
        `.trim();
    }

    async generateReport(message, entities, context) {
        const report = await this.fleetManager.generateReport();

        return `
📊 **Fleet Health Report**
Generated: ${new Date().toISOString()}

**Summary:**
- Total Hosts: ${report.total_hosts}
- Health Score: ${report.avg_health_score}/100
- Incidents (24h): ${report.incidents_24h}
- Uptime: ${report.avg_uptime}%

**Top Issues:**
${report.top_issues?.map((issue, i) => `${i + 1}. ${issue}`).join('\n') || 'None'}

**Recommendations:**
${report.recommendations?.map((rec, i) => `${i + 1}. ${rec}`).join('\n') || 'No recommendations at this time'}

📧 Full report sent to your email!
        `.trim();
    }

    async getPredictions(message, entities, context) {
        const predictions = await this.fleetManager.getPredictiveMaintenanceForecast();

        if (predictions.length === 0) {
            return `✅ No failures predicted in the next 7 days. Fleet looks healthy!`;
        }

        let response = `🔮 **Predictive Maintenance Forecast**\n\n`;

        for (const pred of predictions.slice(0, 5)) {
            response += `⚠️  **${pred.host_id}** - ${pred.issue}\n`;
            response += `   Probability: ${(pred.probability * 100).toFixed(0)}%\n`;
            response += `   ETA: ${pred.estimated_time}\n`;
            response += `   Action: ${pred.suggested_actions[0]?.title || 'Monitor'}\n\n`;
        }

        return response.trim();
    }

    async showHelp(message, entities, context) {
        return `
🤖 **SystemAPI ChatOps Assistant**

I can help you manage your fleet! Here's what I can do:

**Fleet Management:**
- "Show fleet status" - Overview of all hosts
- "List hosts" - Show all hosts
- "Info about [hostname]" - Detailed host information
- "Check health of [hostname]" - Run health checks

**Monitoring:**
- "CPU usage on [hostname]" - Show resource usage
- "Show logs from [hostname]" - View recent logs
- "List incidents" - Show active problems

**Predictions:**
- "Predict failures" - ML-powered maintenance forecasts
- "Generate report" - Create health report

**Execution:** ${this.capabilities.execute_commands ? '✅ Enabled' : '❌ Disabled'}
${this.capabilities.execute_commands ? '- "Run [command] on [hostname]" - Execute commands' : ''}

Need something else? Just ask in plain English!
        `.trim();
    }

    async greet(message, entities, context) {
        const greetings = [
            "Hello! I'm your fleet management assistant. How can I help you today?",
            "Hey there! Ready to manage some servers?",
            "Hi! What would you like to know about your fleet?",
            "Howdy! Need help with your infrastructure?"
        ];

        return greetings[Math.floor(Math.random() * greetings.length)];
    }

    /**
     * Request approval for sensitive operations
     */
    async requestApproval(message, intent, context) {
        return `
⚠️  **Approval Required**

This operation requires approval from a team lead or admin.

Please use the command approval workflow:
\`/approve request create "${message}"\`

Or contact your administrator to enable auto-approval for your role.
        `.trim();
    }

    /**
     * Add message to conversation history
     */
    addToHistory(sessionId, role, content) {
        if (!this.conversationHistory.has(sessionId)) {
            this.conversationHistory.set(sessionId, []);
        }

        const history = this.conversationHistory.get(sessionId);
        history.push({
            role: role,
            content: content,
            timestamp: new Date()
        });

        // Keep last 50 messages
        if (history.length > 50) {
            history.shift();
        }
    }

    /**
     * Helper formatters
     */
    formatTime(date) {
        if (!date) return 'Unknown';
        const d = new Date(date);
        const now = new Date();
        const diff = now - d;

        if (diff < 60000) return 'Just now';
        if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
        if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
        return `${Math.floor(diff / 86400000)}d ago`;
    }

    formatUptime(seconds) {
        if (!seconds) return 'Unknown';
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        return `${days}d ${hours}h`;
    }

    formatBytes(bytes) {
        if (!bytes) return '0 B';
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
    }

    getUsageBar(percent) {
        const filled = Math.floor(percent / 10);
        const empty = 10 - filled;
        const bar = '▓'.repeat(filled) + '░'.repeat(empty);

        if (percent >= 90) return `${bar} 🔴`;
        if (percent >= 70) return `${bar} 🟡`;
        return `${bar} 🟢`;
    }
}

module.exports = ChatOpsAssistant;
