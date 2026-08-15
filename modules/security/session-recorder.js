/**
 * Session Recording & Playback
 * Records terminal sessions with timing data for forensic analysis and playback
 */

const crypto = require('crypto');
const zlib = require('zlib');

class SessionRecorder {
    constructor(db) {
        this.db = db;
        this.activeSessions = new Map(); // sessionId -> recording buffer
        this.recordingOptions = {
            captureInput: true,
            captureOutput: true,
            captureTimings: true,
            compressOnSave: true,
            maxSessionSize: 50 * 1024 * 1024 // 50MB max
        };
    }

    /**
     * Start recording a session
     */
    async startRecording(userId, hostId, metadata = {}) {
        const sessionId = `sess_${crypto.randomUUID()}`;

        const session = {
            session_id: sessionId,
            user_id: userId,
            host_id: hostId,
            started_at: new Date(),
            ended_at: null,
            duration_ms: 0,

            // Recording buffers
            events: [],
            input_buffer: [],
            output_buffer: [],

            // Metadata
            command: metadata.command || 'interactive',
            terminal_type: metadata.terminal_type || 'xterm-256color',
            window_size: metadata.window_size || { rows: 24, cols: 80 },
            environment: {
                user: metadata.user,
                pwd: metadata.pwd,
                shell: metadata.shell || '/bin/bash'
            },

            // Stats
            bytes_input: 0,
            bytes_output: 0,
            event_count: 0,
            is_active: true
        };

        this.activeSessions.set(sessionId, session);

        // Store in database
        await this.db.query(`
            INSERT INTO session_recordings (
                session_id, user_id, host_id, started_at,
                command, terminal_type, window_size, environment
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        `, [
            sessionId, userId, hostId, session.started_at,
            session.command, session.terminal_type,
            JSON.stringify(session.window_size),
            JSON.stringify(session.environment)
        ]);

        console.log(`🎬 Session recording started: ${sessionId}`);

        return {
            session_id: sessionId,
            started_at: session.started_at,
            message: 'Recording started. All terminal activity will be captured.'
        };
    }

    /**
     * Record an event (input, output, or system event)
     */
    recordEvent(sessionId, event) {
        const session = this.activeSessions.get(sessionId);
        if (!session || !session.is_active) {
            return false;
        }

        const timestamp = Date.now();
        const timeSinceStart = timestamp - session.started_at.getTime();

        const recordedEvent = {
            type: event.type, // 'input', 'output', 'resize', 'signal'
            timestamp: timeSinceStart,
            data: event.data,
            size: event.data ? event.data.length : 0
        };

        session.events.push(recordedEvent);
        session.event_count++;

        // Update buffers
        if (event.type === 'input') {
            session.input_buffer.push({ time: timeSinceStart, data: event.data });
            session.bytes_input += recordedEvent.size;
        } else if (event.type === 'output') {
            session.output_buffer.push({ time: timeSinceStart, data: event.data });
            session.bytes_output += recordedEvent.size;
        }

        // Check size limit
        const totalSize = session.bytes_input + session.bytes_output;
        if (totalSize > this.recordingOptions.maxSessionSize) {
            console.warn(`⚠️  Session ${sessionId} exceeded size limit, stopping recording`);
            this.stopRecording(sessionId);
        }

        return true;
    }

    /**
     * Stop recording and save to database
     */
    async stopRecording(sessionId) {
        const session = this.activeSessions.get(sessionId);
        if (!session) {
            return null;
        }

        session.ended_at = new Date();
        session.duration_ms = session.ended_at.getTime() - session.started_at.getTime();
        session.is_active = false;

        // Generate asciicast format (asciinema compatible)
        const asciicast = this.generateAsciicast(session);

        // Compress if enabled
        let recordingData = JSON.stringify(asciicast);
        let compressed = false;
        if (this.recordingOptions.compressOnSave) {
            recordingData = zlib.gzipSync(recordingData);
            compressed = true;
        }

        // Save to database
        await this.db.query(`
            UPDATE session_recordings
            SET ended_at = $2,
                duration_ms = $3,
                bytes_input = $4,
                bytes_output = $5,
                event_count = $6,
                recording_data = $7,
                is_compressed = $8
            WHERE session_id = $1
        `, [
            sessionId,
            session.ended_at,
            session.duration_ms,
            session.bytes_input,
            session.bytes_output,
            session.event_count,
            recordingData,
            compressed
        ]);

        // Clean up active session
        this.activeSessions.delete(sessionId);

        console.log(`🎬 Session recording stopped: ${sessionId} (${session.duration_ms}ms, ${session.event_count} events)`);

        return {
            session_id: sessionId,
            duration_ms: session.duration_ms,
            bytes_total: session.bytes_input + session.bytes_output,
            event_count: session.event_count,
            playback_url: `/api/v1/sessions/${sessionId}/playback`
        };
    }

    /**
     * Generate asciicast v2 format for playback
     */
    generateAsciicast(session) {
        return {
            version: 2,
            width: session.window_size.cols,
            height: session.window_size.rows,
            timestamp: Math.floor(session.started_at.getTime() / 1000),
            duration: session.duration_ms / 1000,
            command: session.command,
            title: `Session ${session.session_id}`,
            env: {
                SHELL: session.environment.shell,
                TERM: session.terminal_type
            },
            // Events in format: [time, event_type, data]
            events: session.events.map(e => [
                e.timestamp / 1000, // Convert to seconds
                e.type === 'output' ? 'o' : 'i',
                e.data
            ])
        };
    }

    /**
     * Get recording for playback
     */
    async getRecording(sessionId) {
        const result = await this.db.query(`
            SELECT * FROM session_recordings
            WHERE session_id = $1
        `, [sessionId]);

        if (result.rows.length === 0) {
            return null;
        }

        const row = result.rows[0];

        // Decompress if needed
        let recordingData = row.recording_data;
        if (row.is_compressed) {
            recordingData = zlib.gunzipSync(recordingData);
        }

        const asciicast = JSON.parse(recordingData.toString());

        return {
            session_id: row.session_id,
            user_id: row.user_id,
            host_id: row.host_id,
            started_at: row.started_at,
            ended_at: row.ended_at,
            duration_ms: row.duration_ms,
            command: row.command,
            bytes_input: row.bytes_input,
            bytes_output: row.bytes_output,
            event_count: row.event_count,
            recording: asciicast
        };
    }

    /**
     * Search recordings by criteria
     */
    async searchRecordings(filters = {}) {
        let query = 'SELECT session_id, user_id, host_id, started_at, ended_at, duration_ms, command, event_count FROM session_recordings WHERE 1=1';
        const params = [];
        let paramCount = 1;

        if (filters.user_id) {
            query += ` AND user_id = $${paramCount++}`;
            params.push(filters.user_id);
        }

        if (filters.host_id) {
            query += ` AND host_id = $${paramCount++}`;
            params.push(filters.host_id);
        }

        if (filters.command) {
            query += ` AND command ILIKE $${paramCount++}`;
            params.push(`%${filters.command}%`);
        }

        if (filters.start_date) {
            query += ` AND started_at >= $${paramCount++}`;
            params.push(filters.start_date);
        }

        if (filters.end_date) {
            query += ` AND started_at <= $${paramCount++}`;
            params.push(filters.end_date);
        }

        query += ' ORDER BY started_at DESC LIMIT 100';

        const result = await this.db.query(query, params);
        return result.rows;
    }

    /**
     * Export recording in various formats
     */
    async exportRecording(sessionId, format = 'asciicast') {
        const recording = await this.getRecording(sessionId);
        if (!recording) {
            return null;
        }

        switch (format) {
            case 'asciicast':
                return {
                    format: 'asciicast',
                    mime_type: 'application/json',
                    data: recording.recording
                };

            case 'text':
                // Plain text transcript
                const transcript = this.generateTextTranscript(recording.recording);
                return {
                    format: 'text',
                    mime_type: 'text/plain',
                    data: transcript
                };

            case 'html':
                // HTML with embedded player
                const html = this.generateHTMLPlayer(recording);
                return {
                    format: 'html',
                    mime_type: 'text/html',
                    data: html
                };

            case 'json':
                // Full session data
                return {
                    format: 'json',
                    mime_type: 'application/json',
                    data: recording
                };

            default:
                return null;
        }
    }

    /**
     * Generate text transcript from recording
     */
    generateTextTranscript(asciicast) {
        let transcript = `Session: ${asciicast.title}\n`;
        transcript += `Duration: ${asciicast.duration.toFixed(2)}s\n`;
        transcript += `Command: ${asciicast.command}\n`;
        transcript += `${'='.repeat(60)}\n\n`;

        for (const [time, type, data] of asciicast.events) {
            if (type === 'o') { // Output only
                transcript += data;
            }
        }

        return transcript;
    }

    /**
     * Generate HTML player
     */
    generateHTMLPlayer(recording) {
        return `<!DOCTYPE html>
<html>
<head>
    <title>Session ${recording.session_id}</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/asciinema-player@3.0.1/dist/bundle/asciinema-player.css" />
</head>
<body>
    <div id="session-info">
        <h2>Session Recording: ${recording.session_id}</h2>
        <p>Host: ${recording.host_id} | Duration: ${(recording.duration_ms / 1000).toFixed(2)}s | Events: ${recording.event_count}</p>
    </div>
    <div id="player"></div>
    <script src="https://cdn.jsdelivr.net/npm/asciinema-player@3.0.1/dist/bundle/asciinema-player.min.js"></script>
    <script>
        AsciinemaPlayer.create(${JSON.stringify(recording.recording)}, document.getElementById('player'), {
            autoPlay: false,
            loop: false,
            speed: 1
        });
    </script>
</body>
</html>`;
    }

    /**
     * Analyze session for suspicious activity
     */
    async analyzeSession(sessionId) {
        const recording = await this.getRecording(sessionId);
        if (!recording) {
            return null;
        }

        const suspiciousPatterns = [
            { pattern: /rm\s+-rf\s+\//, severity: 'critical', description: 'Recursive root deletion attempt' },
            { pattern: /chmod\s+777/, severity: 'high', description: 'Unsafe permission change' },
            { pattern: /curl.*\|\s*bash/, severity: 'high', description: 'Pipe to bash from URL' },
            { pattern: /nc\s+-[el]/, severity: 'medium', description: 'Netcat listener' },
            { pattern: /\/etc\/shadow/, severity: 'high', description: 'Shadow file access' },
            { pattern: /\/etc\/passwd/, severity: 'medium', description: 'Password file access' },
            { pattern: /sudo\s+su\s+-/, severity: 'medium', description: 'Root shell escalation' },
            { pattern: /base64.*decode/, severity: 'low', description: 'Base64 decoding (possible obfuscation)' },
            { pattern: /eval.*\$\(/, severity: 'medium', description: 'Command substitution with eval' }
        ];

        const findings = [];
        const transcript = this.generateTextTranscript(recording.recording);

        for (const { pattern, severity, description } of suspiciousPatterns) {
            const matches = transcript.match(pattern);
            if (matches) {
                findings.push({
                    severity: severity,
                    description: description,
                    matched: matches[0],
                    pattern: pattern.toString()
                });
            }
        }

        return {
            session_id: sessionId,
            analyzed_at: new Date(),
            total_findings: findings.length,
            risk_level: this.calculateRiskLevel(findings),
            findings: findings,
            recommendation: findings.length > 0
                ? 'Review this session - suspicious commands detected'
                : 'No suspicious activity detected'
        };
    }

    /**
     * Calculate overall risk level
     */
    calculateRiskLevel(findings) {
        if (findings.length === 0) return 'safe';

        const hasCritical = findings.some(f => f.severity === 'critical');
        const highCount = findings.filter(f => f.severity === 'high').length;

        if (hasCritical) return 'critical';
        if (highCount >= 3) return 'high';
        if (highCount >= 1) return 'medium';
        return 'low';
    }

    /**
     * Get active recordings
     */
    getActiveRecordings() {
        return Array.from(this.activeSessions.values()).map(session => ({
            session_id: session.session_id,
            user_id: session.user_id,
            host_id: session.host_id,
            started_at: session.started_at,
            duration_ms: Date.now() - session.started_at.getTime(),
            event_count: session.event_count,
            bytes_total: session.bytes_input + session.bytes_output
        }));
    }

    /**
     * Clean up old recordings
     */
    async cleanupOldRecordings(daysToKeep = 90) {
        const result = await this.db.query(`
            DELETE FROM session_recordings
            WHERE started_at < NOW() - INTERVAL '${daysToKeep} days'
            RETURNING session_id
        `);

        console.log(`🧹 Cleaned up ${result.rowCount} old session recordings`);

        return {
            deleted_count: result.rowCount,
            deleted_sessions: result.rows.map(r => r.session_id)
        };
    }
}

module.exports = SessionRecorder;
