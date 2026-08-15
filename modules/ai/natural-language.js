/**
 * Natural Language Command Interface
 * Converts plain English to shell commands using AI
 */

class NaturalLanguageProcessor {
    constructor(config = {}) {
        this.openaiKey = config.openai_key || process.env.OPENAI_API_KEY;
        this.model = config.model || 'gpt-4';
        this.commandHistory = [];
    }

    /**
     * Convert natural language query to shell command
     */
    async queryToCommand(query, context = {}) {
        const prompt = this.buildPrompt(query, context);

        try {
            const response = await this.callOpenAI(prompt);
            const result = this.parseResponse(response);

            // Store in history
            this.commandHistory.push({
                query: query,
                command: result.command,
                explanation: result.explanation,
                timestamp: new Date()
            });

            return result;
        } catch (error) {
            console.error('NLP Error:', error);
            return {
                success: false,
                error: error.message,
                fallback: this.getFallbackCommand(query)
            };
        }
    }

    /**
     * Build prompt for OpenAI
     */
    buildPrompt(query, context) {
        const systemPrompt = `You are a Linux/Unix command line expert. Convert natural language queries into safe, correct shell commands.

Rules:
1. Generate SAFE commands only - no destructive operations without explicit confirmation
2. Prefer common, portable commands (avoid rare utilities)
3. Include safety flags where appropriate (e.g., -i for interactive)
4. Explain what the command does
5. Warn about potential dangers
6. Suggest alternatives if query is ambiguous

Output format (JSON):
{
  "command": "the shell command",
  "explanation": "what it does",
  "safety": "safe|caution|dangerous",
  "warnings": ["list", "of", "warnings"],
  "alternatives": ["alternative", "commands"]
}`;

        const contextInfo = context.os ? `\nOS: ${context.os}` : '';
        const hostInfo = context.hostname ? `\nHost: ${context.hostname}` : '';

        return {
            system: systemPrompt,
            user: `Convert to command: "${query}"${contextInfo}${hostInfo}`
        };
    }

    /**
     * Call OpenAI API (mock implementation for now)
     */
    async callOpenAI(prompt) {
        // In production, this would call actual OpenAI API
        // For now, return pattern-matched responses
        return this.patternMatch(prompt.user);
    }

    /**
     * Pattern matching for common queries (fallback)
     */
    patternMatch(query) {
        const patterns = {
            'show.*cpu.*usage': {
                command: 'top -bn1 | grep "Cpu(s)"',
                explanation: 'Shows current CPU usage',
                safety: 'safe',
                warnings: [],
                alternatives: ['mpstat', 'htop']
            },
            'restart.*nginx': {
                command: 'sudo systemctl restart nginx',
                explanation: 'Restarts the nginx web server',
                safety: 'caution',
                warnings: ['Will cause brief service interruption'],
                alternatives: ['sudo nginx -s reload  # Graceful reload']
            },
            'list.*running.*process': {
                command: 'ps aux | head -20',
                explanation: 'Lists running processes',
                safety: 'safe',
                warnings: [],
                alternatives: ['htop', 'top']
            },
            'check.*disk.*space': {
                command: 'df -h',
                explanation: 'Shows disk space usage for all mounted filesystems',
                safety: 'safe',
                warnings: [],
                alternatives: ['du -sh /*']
            },
            'find.*large.*files': {
                command: 'find / -type f -size +100M 2>/dev/null | head -20',
                explanation: 'Finds files larger than 100MB',
                safety: 'safe',
                warnings: ['May take a while on large filesystems'],
                alternatives: ['du -ah / | sort -rh | head -20']
            },
            'show.*memory.*usage': {
                command: 'free -h',
                explanation: 'Displays memory usage in human-readable format',
                safety: 'safe',
                warnings: [],
                alternatives: ['vmstat', 'cat /proc/meminfo']
            },
            'tail.*logs': {
                command: 'tail -f /var/log/syslog',
                explanation: 'Follow system log in real-time',
                safety: 'safe',
                warnings: [],
                alternatives: ['journalctl -f']
            }
        };

        for (const [pattern, response] of Object.entries(patterns)) {
            if (new RegExp(pattern, 'i').test(query)) {
                return response;
            }
        }

        // Default response
        return {
            command: `echo "I'm not sure how to: ${query}"`,
            explanation: 'Query not recognized',
            safety: 'safe',
            warnings: ['Try rephrasing your query'],
            alternatives: []
        };
    }

    /**
     * Parse OpenAI response
     */
    parseResponse(response) {
        return {
            success: true,
            command: response.command,
            explanation: response.explanation,
            safety: response.safety,
            warnings: response.warnings || [],
            alternatives: response.alternatives || [],
            requires_confirmation: response.safety === 'dangerous'
        };
    }

    /**
     * Get fallback command for failed queries
     */
    getFallbackCommand(query) {
        return {
            command: `man -k "${query.split(' ').join(', ')}"`,
            explanation: 'Search manual pages for related commands',
            safety: 'safe'
        };
    }

    /**
     * Batch process multiple queries
     */
    async batchProcess(queries, context = {}) {
        const results = [];

        for (const query of queries) {
            const result = await this.queryToCommand(query, context);
            results.push({
                query: query,
                ...result
            });
        }

        return results;
    }

    /**
     * Get command history
     */
    getHistory(limit = 10) {
        return this.commandHistory.slice(-limit);
    }

    /**
     * Learn from user corrections
     */
    learnFromCorrection(query, suggestedCommand, userCommand) {
        // In production, this would fine-tune the model
        console.log(`Learning: "${query}" -> ${userCommand} (was: ${suggestedCommand})`);

        this.commandHistory.push({
            query: query,
            suggested: suggestedCommand,
            actual: userCommand,
            correction: true,
            timestamp: new Date()
        });
    }
}

module.exports = NaturalLanguageProcessor;
