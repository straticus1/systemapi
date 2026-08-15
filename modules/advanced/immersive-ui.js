/**
 * Immersive UI System
 * AR/VR fleet visualization and voice control
 */

const crypto = require('crypto');

class ImmersiveUI {
    constructor(db, fleetManager) {
        this.db = db;
        this.fleetManager = fleetManager;
        this.vrSessions = new Map();
        this.voiceSessions = new Map();
    }

    /**
     * AR/VR FLEET VISUALIZATION
     * 3D representation of infrastructure in VR/AR
     */
    async generateVRScene(options = {}) {
        const sceneId = `vr_scene_${crypto.randomUUID()}`;

        console.log(`🥽 Generating VR scene: ${sceneId}`);

        // Get fleet data
        const hosts = await this.fleetManager.getHosts({ status: 'online' });
        const connections = await this.fleetManager.getNetworkTopology();

        // Generate 3D scene data (Three.js/A-Frame compatible)
        const scene = {
            scene_id: sceneId,
            generated_at: new Date(),
            format: 'a-frame', // or 'three.js', 'unity'
            scene_data: {
                assets: this.generateVRAssets(),
                entities: this.generateHostEntities(hosts),
                connections: this.generateConnectionLines(connections),
                environment: this.generateEnvironment(options),
                camera: {
                    position: '0 1.6 3',
                    rotation: '0 0 0'
                },
                lighting: {
                    ambient: '#445',
                    directional: {
                        color: '#fff',
                        intensity: 0.6,
                        position: '-0.5 1 1'
                    }
                }
            },
            metadata: {
                host_count: hosts.length,
                connection_count: connections?.length || 0
            }
        };

        return scene;
    }

    generateVRAssets() {
        return {
            models: [
                {
                    id: 'server-model',
                    src: '/assets/models/server.gltf',
                    type: 'gltf'
                },
                {
                    id: 'router-model',
                    src: '/assets/models/router.gltf',
                    type: 'gltf'
                }
            ],
            materials: [
                {
                    id: 'healthy-mat',
                    color: '#00ff00',
                    emissive: '#00ff00',
                    emissiveIntensity: 0.3
                },
                {
                    id: 'warning-mat',
                    color: '#ffaa00',
                    emissive: '#ffaa00',
                    emissiveIntensity: 0.5
                },
                {
                    id: 'critical-mat',
                    color: '#ff0000',
                    emissive: '#ff0000',
                    emissiveIntensity: 0.7
                }
            ]
        };
    }

    generateHostEntities(hosts) {
        const entities = [];

        // Layout hosts in a grid or force-directed graph
        const gridSize = Math.ceil(Math.sqrt(hosts.length));

        hosts.forEach((host, index) => {
            const x = (index % gridSize) * 2 - gridSize;
            const z = Math.floor(index / gridSize) * 2 - gridSize;
            const y = 0;

            // Determine color based on health
            const material = this.getHostMaterial(host);

            entities.push({
                type: 'server',
                id: host.host_id,
                hostname: host.hostname,
                position: `${x} ${y} ${z}`,
                model: '#server-model',
                material: material,
                scale: '0.5 0.5 0.5',
                interactive: true,
                metadata: {
                    cpu: host.cpu_usage,
                    memory: host.memory_usage,
                    disk: host.disk_usage,
                    status: host.status
                },
                // Info panel that appears on hover
                infoPanel: {
                    visible: false,
                    content: this.generateHostInfoPanel(host)
                },
                // Particle effects for errors
                particles: host.error_count > 0 ? {
                    enabled: true,
                    color: '#ff0000',
                    count: Math.min(host.error_count, 50)
                } : null
            });
        });

        return entities;
    }

    getHostMaterial(host) {
        if (host.status !== 'online') return '#critical-mat';
        if (host.cpu_usage > 80 || host.memory_usage > 80) return '#warning-mat';
        return '#healthy-mat';
    }

    generateConnectionLines(connections) {
        if (!connections) return [];

        return connections.map(conn => ({
            type: 'connection',
            from: conn.source_host,
            to: conn.target_host,
            color: conn.status === 'active' ? '#00ff00' : '#666',
            opacity: 0.5,
            animated: conn.status === 'active',
            bandwidth: conn.bandwidth_mbps,
            latency_ms: conn.latency_ms
        }));
    }

    generateEnvironment(options) {
        const theme = options.theme || 'datacenter';

        const themes = {
            datacenter: {
                skybox: 'gradient',
                skyColor: '#222',
                groundColor: '#111',
                fog: {
                    type: 'exponential',
                    density: 0.05,
                    color: '#222'
                },
                grid: {
                    visible: true,
                    color: '#00ff00',
                    opacity: 0.2
                }
            },
            space: {
                skybox: 'stars',
                stars: {
                    count: 5000,
                    radius: 300
                },
                fog: null,
                grid: null
            },
            ocean: {
                skybox: 'gradient',
                skyColor: '#87CEEB',
                water: {
                    enabled: true,
                    color: '#006994'
                }
            }
        };

        return themes[theme] || themes.datacenter;
    }

    generateHostInfoPanel(host) {
        return `
<div class="vr-info-panel">
    <h3>${host.hostname}</h3>
    <div class="stats">
        <div>CPU: ${host.cpu_usage}%</div>
        <div>Memory: ${host.memory_usage}%</div>
        <div>Disk: ${host.disk_usage}%</div>
        <div>Status: ${host.status}</div>
    </div>
    <div class="actions">
        <button onclick="connectToHost('${host.host_id}')">Connect</button>
        <button onclick="viewLogs('${host.host_id}')">Logs</button>
        <button onclick="restart('${host.host_id}')">Restart</button>
    </div>
</div>
        `.trim();
    }

    /**
     * VOICE CONTROL SYSTEM
     * Control fleet with voice commands
     */
    async startVoiceSession(userId, config = {}) {
        const sessionId = `voice_${crypto.randomUUID()}`;

        const session = {
            session_id: sessionId,
            user_id: userId,
            started_at: new Date(),
            language: config.language || 'en-US',
            wake_word: config.wake_word || 'computer',
            commands_processed: 0,
            active: true
        };

        this.voiceSessions.set(sessionId, session);

        console.log(`🎤 Voice session started: ${sessionId}`);

        return {
            session_id: sessionId,
            wake_word: session.wake_word,
            supported_commands: this.getSupportedVoiceCommands(),
            message: `Say "${session.wake_word}" to activate voice control`
        };
    }

    getSupportedVoiceCommands() {
        return [
            {
                pattern: 'show fleet status',
                description: 'Display overview of all hosts',
                example: 'Computer, show fleet status'
            },
            {
                pattern: 'restart [hostname]',
                description: 'Restart a specific host',
                example: 'Computer, restart web-server-01'
            },
            {
                pattern: 'run [script] on [hostname]',
                description: 'Execute a script on a host',
                example: 'Computer, run update-packages on all hosts'
            },
            {
                pattern: 'check health of [hostname]',
                description: 'Get health status of a host',
                example: 'Computer, check health of database-master'
            },
            {
                pattern: 'show me errors',
                description: 'Display recent error logs',
                example: 'Computer, show me errors'
            },
            {
                pattern: 'create snapshot',
                description: 'Create system state snapshot',
                example: 'Computer, create snapshot'
            },
            {
                pattern: 'start chaos experiment [type]',
                description: 'Launch chaos engineering test',
                example: 'Computer, start chaos experiment CPU stress'
            },
            {
                pattern: 'summarize fleet',
                description: 'Give verbal summary of fleet health',
                example: 'Computer, summarize fleet'
            }
        ];
    }

    async processVoiceCommand(sessionId, audioData) {
        const session = this.voiceSessions.get(sessionId);

        if (!session || !session.active) {
            return { error: 'Invalid or inactive session' };
        }

        // In production, use speech-to-text API (Google Cloud Speech, Azure, etc.)
        const transcript = await this.speechToText(audioData, session.language);

        console.log(`🎤 Voice command: "${transcript}"`);

        // Check for wake word
        const lowerTranscript = transcript.toLowerCase();
        if (!lowerTranscript.includes(session.wake_word.toLowerCase())) {
            return {
                recognized: false,
                message: `Wake word "${session.wake_word}" not detected`
            };
        }

        // Remove wake word and parse command
        const command = lowerTranscript.replace(session.wake_word.toLowerCase(), '').trim();

        const result = await this.executeVoiceCommand(command, session);

        session.commands_processed++;

        // Generate voice response
        const voiceResponse = await this.textToSpeech(result.response_text, session.language);

        return {
            recognized: true,
            transcript: transcript,
            command: command,
            result: result,
            audio_response: voiceResponse
        };
    }

    async speechToText(audioData, language) {
        // Mock implementation - in production, use real API
        const mockCommands = [
            'computer show fleet status',
            'computer restart web-server-01',
            'computer check health of database',
            'computer show me errors',
            'computer summarize fleet'
        ];

        return mockCommands[Math.floor(Math.random() * mockCommands.length)];
    }

    async executeVoiceCommand(command, session) {
        // Parse and execute command
        if (command.includes('show fleet status') || command.includes('fleet status')) {
            return await this.voiceFleetStatus();
        }

        if (command.includes('restart')) {
            const hostname = this.extractHostname(command);
            return await this.voiceRestart(hostname);
        }

        if (command.includes('check health')) {
            const hostname = this.extractHostname(command);
            return await this.voiceHealthCheck(hostname);
        }

        if (command.includes('show') && command.includes('error')) {
            return await this.voiceShowErrors();
        }

        if (command.includes('summarize fleet')) {
            return await this.voiceSummarizeFleet();
        }

        return {
            success: false,
            response_text: `I didn't understand that command. Try saying "show fleet status" or "check health of hostname"`
        };
    }

    async voiceFleetStatus() {
        const summary = await this.fleetManager.getFleetSummary();

        const responseText = `Fleet status: ${summary.online_hosts} hosts online, ${summary.offline_hosts} offline. Average CPU usage is ${summary.avg_cpu?.toFixed(0)} percent.`;

        return {
            success: true,
            response_text: responseText,
            data: summary
        };
    }

    async voiceRestart(hostname) {
        if (!hostname) {
            return {
                success: false,
                response_text: 'I need a hostname to restart. Please specify which host.'
            };
        }

        await this.fleetManager.restartHost(hostname);

        return {
            success: true,
            response_text: `Restarting ${hostname}`
        };
    }

    async voiceHealthCheck(hostname) {
        if (!hostname) {
            return {
                success: false,
                response_text: 'Please specify a hostname to check'
            };
        }

        const health = await this.fleetManager.healthCheck(hostname);

        const status = health.status === 'healthy' ? 'healthy' : 'experiencing issues';

        return {
            success: true,
            response_text: `${hostname} is ${status}. CPU at ${health.cpu}%, memory at ${health.memory}%.`,
            data: health
        };
    }

    async voiceShowErrors() {
        const errors = await this.fleetManager.getRecentErrors({ limit: 5 });

        const responseText = errors.length > 0
            ? `Found ${errors.length} recent errors. The most recent is: ${errors[0].message}`
            : 'No recent errors detected. All systems nominal.';

        return {
            success: true,
            response_text: responseText,
            data: errors
        };
    }

    async voiceSummarizeFleet() {
        const summary = await this.fleetManager.getFleetSummary();
        const incidents = await this.fleetManager.getActiveIncidents();

        const incidentText = incidents.length > 0
            ? `There are ${incidents.length} active incidents requiring attention.`
            : 'No active incidents.';

        const healthScore = summary.avg_health_score || 85;
        const healthText = healthScore > 90 ? 'excellent' : healthScore > 75 ? 'good' : 'needs attention';

        const responseText = `Fleet health is ${healthText} with a score of ${healthScore}. ${summary.online_hosts} out of ${summary.total_hosts} hosts are online. ${incidentText}`;

        return {
            success: true,
            response_text: responseText,
            data: { summary, incidents }
        };
    }

    extractHostname(command) {
        // Simple hostname extraction - in production, use NLP
        const words = command.split(' ');
        const afterOf = words.indexOf('of') !== -1 ? words[words.indexOf('of') + 1] : null;
        const lastWord = words[words.length - 1];

        return afterOf || (lastWord !== 'of' ? lastWord : null);
    }

    async textToSpeech(text, language) {
        // In production, use TTS API (Google Cloud TTS, Amazon Polly, etc.)
        console.log(`🔊 TTS: "${text}"`);

        return {
            audio_data: Buffer.from('mock-audio-data'),
            format: 'mp3',
            text: text
        };
    }

    /**
     * AR OVERLAY
     * Generate AR markers for physical servers
     */
    async generateARMarkers(serverLocations) {
        const markers = [];

        for (const server of serverLocations) {
            markers.push({
                marker_id: crypto.randomUUID(),
                type: 'ar_marker',
                server_id: server.server_id,
                location: server.physical_location,
                marker_data: {
                    pattern: this.generateARPattern(server),
                    size: 0.1, // 10cm
                    overlay: {
                        hostname: server.hostname,
                        status_indicator: server.status,
                        metrics: {
                            cpu: server.cpu_usage,
                            memory: server.memory_usage,
                            temp: server.temperature
                        }
                    }
                }
            });
        }

        return markers;
    }

    generateARPattern(server) {
        // Generate unique QR-like pattern for AR marker
        return {
            type: 'qr_code',
            data: JSON.stringify({
                server_id: server.server_id,
                hostname: server.hostname
            }),
            error_correction: 'H'
        };
    }

    /**
     * Stop voice session
     */
    async stopVoiceSession(sessionId) {
        const session = this.voiceSessions.get(sessionId);

        if (session) {
            session.active = false;
            session.ended_at = new Date();

            console.log(`🎤 Voice session ended: ${sessionId} (${session.commands_processed} commands)`);

            this.voiceSessions.delete(sessionId);

            return {
                session_id: sessionId,
                commands_processed: session.commands_processed,
                duration_ms: session.ended_at - session.started_at
            };
        }

        return { error: 'Session not found' };
    }
}

module.exports = ImmersiveUI;
