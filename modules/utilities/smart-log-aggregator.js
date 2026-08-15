/**
 * Smart Log Aggregator
 * AI-powered log collection, parsing, and analysis across fleet
 * Auto-detects patterns, anomalies, and correlates errors
 */

class SmartLogAggregator {
    constructor(db, fleetManager) {
        this.db = db;
        this.fleetManager = fleetManager;

        // Common log patterns
        this.logPatterns = {
            error: /\b(error|err|exception|fatal|critical|panic|failed)\b/i,
            warning: /\b(warn|warning|caution)\b/i,
            info: /\b(info|information)\b/i,
            debug: /\b(debug|trace)\b/i,
            timestamp: /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/,
            ip_address: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
            email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
            uuid: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/i,
            status_code: /\bHTTP\/\d\.\d\s+(\d{3})\b/,
            duration: /\b(\d+\.?\d*)(ms|s|sec|seconds?|minutes?|hours?)\b/i
        };

        // Error classifiers
        this.errorClassifiers = [
            { pattern: /connection (refused|reset|timeout)/i, category: 'network', severity: 'high' },
            { pattern: /out of memory|oom|memory exhausted/i, category: 'memory', severity: 'critical' },
            { pattern: /disk (full|quota|space)/i, category: 'disk', severity: 'high' },
            { pattern: /permission denied|access denied/i, category: 'permissions', severity: 'medium' },
            { pattern: /database.*error|sql.*error/i, category: 'database', severity: 'high' },
            { pattern: /authentication.*failed|invalid.*credentials/i, category: 'auth', severity: 'high' },
            { pattern: /timeout|timed out/i, category: 'timeout', severity: 'medium' },
            { pattern: /segmentation fault|core dumped/i, category: 'crash', severity: 'critical' },
            { pattern: /ssl|tls|certificate/i, category: 'crypto', severity: 'high' }
        ];
    }

    /**
     * Aggregate logs from entire fleet
     */
    async aggregateLogs(options = {}) {
        const {
            since = new Date(Date.now() - 3600000), // Last hour
            log_paths = ['/var/log/syslog', '/var/log/messages', '/var/log/nginx/error.log'],
            filter_pattern = null,
            severity_filter = null
        } = options;

        console.log(`📊 Aggregating logs from fleet since ${since}`);

        const hosts = await this.fleetManager.getHosts({ status: 'online' });
        const aggregatedLogs = [];

        for (const host of hosts) {
            try {
                const logs = await this.collectHostLogs(host.host_id, {
                    since,
                    log_paths,
                    filter_pattern
                });

                aggregatedLogs.push(...logs);
            } catch (error) {
                console.error(`Error collecting logs from ${host.host_id}:`, error.message);
            }
        }

        // Parse and enrich logs
        const parsedLogs = this.parseLogs(aggregatedLogs);

        // Filter by severity if requested
        let filteredLogs = parsedLogs;
        if (severity_filter) {
            filteredLogs = parsedLogs.filter(log => log.severity === severity_filter);
        }

        // Sort by timestamp (most recent first)
        filteredLogs.sort((a, b) => b.timestamp - a.timestamp);

        // Analyze for patterns
        const analysis = this.analyzeLogs(filteredLogs);

        return {
            total_logs: filteredLogs.length,
            total_hosts: hosts.length,
            time_range: {
                from: since,
                to: new Date()
            },
            logs: filteredLogs.slice(0, 1000), // Limit to 1000 for UI
            analysis: analysis,
            has_more: filteredLogs.length > 1000
        };
    }

    /**
     * Collect logs from a single host
     */
    async collectHostLogs(hostId, options) {
        const logs = [];

        for (const logPath of options.log_paths) {
            try {
                // Use journalctl if available, otherwise tail
                let cmd;
                if (logPath === 'journal') {
                    const sinceStr = options.since.toISOString();
                    cmd = `journalctl --since "${sinceStr}" --no-pager -n 1000`;
                } else {
                    // Get logs modified since timestamp
                    const sinceTimestamp = Math.floor(options.since.getTime() / 1000);
                    cmd = `find ${logPath} -type f -newermt "@${sinceTimestamp}" -exec tail -n 100 {} \\; 2>/dev/null || tail -n 100 ${logPath} 2>/dev/null`;
                }

                if (options.filter_pattern) {
                    cmd += ` | grep -i "${options.filter_pattern}"`;
                }

                const result = await this.fleetManager.executeCommand(hostId, cmd);

                if (result.stdout) {
                    const lines = result.stdout.split('\n').filter(l => l.trim());

                    for (const line of lines) {
                        logs.push({
                            host_id: hostId,
                            log_path: logPath,
                            raw_line: line,
                            collected_at: new Date()
                        });
                    }
                }
            } catch (error) {
                console.warn(`Failed to collect ${logPath} from ${hostId}:`, error.message);
            }
        }

        return logs;
    }

    /**
     * Parse raw log lines into structured format
     */
    parseLogs(rawLogs) {
        return rawLogs.map(log => {
            const parsed = {
                ...log,
                timestamp: this.extractTimestamp(log.raw_line) || log.collected_at,
                severity: this.detectSeverity(log.raw_line),
                category: null,
                extracted_data: {}
            };

            // Extract structured data
            const ipMatch = log.raw_line.match(this.logPatterns.ip_address);
            if (ipMatch) parsed.extracted_data.ip_address = ipMatch[0];

            const statusMatch = log.raw_line.match(this.logPatterns.status_code);
            if (statusMatch) parsed.extracted_data.status_code = parseInt(statusMatch[1]);

            const durationMatch = log.raw_line.match(this.logPatterns.duration);
            if (durationMatch) parsed.extracted_data.duration = durationMatch[0];

            const uuidMatch = log.raw_line.match(this.logPatterns.uuid);
            if (uuidMatch) parsed.extracted_data.uuid = uuidMatch[0];

            // Classify errors
            if (parsed.severity === 'error' || parsed.severity === 'critical') {
                for (const classifier of this.errorClassifiers) {
                    if (classifier.pattern.test(log.raw_line)) {
                        parsed.category = classifier.category;
                        parsed.severity = classifier.severity;
                        break;
                    }
                }
            }

            return parsed;
        });
    }

    /**
     * Extract timestamp from log line
     */
    extractTimestamp(line) {
        const match = line.match(this.logPatterns.timestamp);
        if (match) {
            try {
                return new Date(match[0]);
            } catch {
                return null;
            }
        }
        return null;
    }

    /**
     * Detect log severity
     */
    detectSeverity(line) {
        if (this.logPatterns.error.test(line)) return 'error';
        if (this.logPatterns.warning.test(line)) return 'warning';
        if (this.logPatterns.debug.test(line)) return 'debug';
        return 'info';
    }

    /**
     * Analyze logs for patterns and anomalies
     */
    analyzeLogs(logs) {
        const analysis = {
            by_severity: {},
            by_category: {},
            by_host: {},
            top_errors: [],
            error_clusters: [],
            anomalies: [],
            trends: {}
        };

        // Count by severity
        for (const log of logs) {
            analysis.by_severity[log.severity] = (analysis.by_severity[log.severity] || 0) + 1;

            if (log.category) {
                analysis.by_category[log.category] = (analysis.by_category[log.category] || 0) + 1;
            }

            analysis.by_host[log.host_id] = (analysis.by_host[log.host_id] || 0) + 1;
        }

        // Find most common errors
        const errorMessages = logs
            .filter(l => l.severity === 'error' || l.severity === 'critical')
            .map(l => this.normalizeError(l.raw_line));

        const errorCounts = {};
        for (const msg of errorMessages) {
            errorCounts[msg] = (errorCounts[msg] || 0) + 1;
        }

        analysis.top_errors = Object.entries(errorCounts)
            .map(([message, count]) => ({ message, count }))
            .sort((a, b) => b.count - a.count)
            .slice(0, 10);

        // Detect error clusters (similar errors happening together)
        analysis.error_clusters = this.detectErrorClusters(logs);

        // Detect anomalies
        analysis.anomalies = this.detectAnomalies(logs);

        // Trend analysis
        analysis.trends = this.analyzeTrends(logs);

        return analysis;
    }

    /**
     * Normalize error message for grouping
     */
    normalizeError(errorLine) {
        // Remove timestamps, IPs, UUIDs, numbers
        let normalized = errorLine;
        normalized = normalized.replace(this.logPatterns.timestamp, '[TIME]');
        normalized = normalized.replace(this.logPatterns.ip_address, '[IP]');
        normalized = normalized.replace(this.logPatterns.uuid, '[UUID]');
        normalized = normalized.replace(/\b\d+\b/g, '[NUM]');
        normalized = normalized.replace(/pid=\d+/g, 'pid=[NUM]');

        return normalized.substring(0, 200); // Truncate long messages
    }

    /**
     * Detect error clusters
     */
    detectErrorClusters(logs) {
        const clusters = [];
        const errorLogs = logs.filter(l => l.severity === 'error' || l.severity === 'critical');

        // Group by category and time proximity
        const timeWindow = 60000; // 1 minute

        for (let i = 0; i < errorLogs.length; i++) {
            const log = errorLogs[i];
            const clusterLogs = [log];

            // Find related errors within time window
            for (let j = i + 1; j < errorLogs.length; j++) {
                const other = errorLogs[j];

                if (Math.abs(other.timestamp - log.timestamp) < timeWindow) {
                    if (log.category && log.category === other.category) {
                        clusterLogs.push(other);
                    }
                }
            }

            if (clusterLogs.length >= 3) {
                clusters.push({
                    category: log.category || 'unknown',
                    count: clusterLogs.length,
                    hosts: [...new Set(clusterLogs.map(l => l.host_id))],
                    time_span_ms: clusterLogs[clusterLogs.length - 1].timestamp - clusterLogs[0].timestamp,
                    sample_error: log.raw_line
                });

                i += clusterLogs.length - 1; // Skip clustered logs
            }
        }

        return clusters;
    }

    /**
     * Detect anomalies in log patterns
     */
    detectAnomalies(logs) {
        const anomalies = [];

        // Anomaly 1: Sudden error spike
        const errorRate = this.calculateRateOverTime(
            logs.filter(l => l.severity === 'error'),
            5 // 5 minute windows
        );

        const avgErrorRate = errorRate.reduce((sum, r) => sum + r.count, 0) / errorRate.length;

        for (const window of errorRate) {
            if (window.count > avgErrorRate * 3) {
                anomalies.push({
                    type: 'error_spike',
                    description: `Error rate ${window.count}/min is 3x normal (${avgErrorRate.toFixed(1)}/min)`,
                    severity: 'high',
                    time_window: window.time
                });
            }
        }

        // Anomaly 2: New error types
        const recentErrors = logs
            .filter(l => l.timestamp > Date.now() - 600000) // Last 10 minutes
            .filter(l => l.severity === 'error')
            .map(l => this.normalizeError(l.raw_line));

        const historicalErrors = logs
            .filter(l => l.timestamp <= Date.now() - 600000)
            .filter(l => l.severity === 'error')
            .map(l => this.normalizeError(l.raw_line));

        const historicalSet = new Set(historicalErrors);
        const newErrors = recentErrors.filter(e => !historicalSet.has(e));

        if (newErrors.length > 0) {
            anomalies.push({
                type: 'new_error_pattern',
                description: `${newErrors.length} new error pattern(s) detected`,
                severity: 'medium',
                sample: newErrors[0]
            });
        }

        return anomalies;
    }

    /**
     * Analyze trends over time
     */
    analyzeTrends(logs) {
        const errorLogs = logs.filter(l => l.severity === 'error');
        const warningLogs = logs.filter(l => l.severity === 'warning');

        const errorRate = this.calculateRateOverTime(errorLogs, 15); // 15 min windows
        const warningRate = this.calculateRateOverTime(warningLogs, 15);

        return {
            error_trend: this.calculateTrend(errorRate),
            warning_trend: this.calculateTrend(warningRate),
            error_rate_per_15min: errorRate,
            warning_rate_per_15min: warningRate
        };
    }

    /**
     * Calculate rate over time windows
     */
    calculateRateOverTime(logs, windowMinutes) {
        if (logs.length === 0) return [];

        const windows = [];
        const oldestLog = Math.min(...logs.map(l => l.timestamp.getTime()));
        const newestLog = Math.max(...logs.map(l => l.timestamp.getTime()));
        const windowMs = windowMinutes * 60 * 1000;

        for (let time = oldestLog; time <= newestLog; time += windowMs) {
            const windowLogs = logs.filter(l => {
                const t = l.timestamp.getTime();
                return t >= time && t < time + windowMs;
            });

            windows.push({
                time: new Date(time),
                count: windowLogs.length,
                rate_per_min: windowLogs.length / windowMinutes
            });
        }

        return windows;
    }

    /**
     * Calculate trend direction
     */
    calculateTrend(rateData) {
        if (rateData.length < 2) return 'stable';

        const recent = rateData.slice(-3).reduce((sum, r) => sum + r.count, 0) / 3;
        const older = rateData.slice(0, 3).reduce((sum, r) => sum + r.count, 0) / 3;

        if (recent > older * 1.5) return 'increasing';
        if (recent < older * 0.5) return 'decreasing';
        return 'stable';
    }

    /**
     * Search logs with natural language query
     */
    async searchLogs(query, options = {}) {
        console.log(`🔍 Searching logs: "${query}"`);

        // Convert natural language to search parameters
        const searchParams = this.parseNaturalLanguageQuery(query);

        // Aggregate logs with parsed parameters
        const results = await this.aggregateLogs({
            ...options,
            filter_pattern: searchParams.filter_pattern,
            severity_filter: searchParams.severity
        });

        return {
            query: query,
            interpreted_as: searchParams,
            ...results
        };
    }

    /**
     * Parse natural language query
     */
    parseNaturalLanguageQuery(query) {
        const params = {
            filter_pattern: null,
            severity: null
        };

        const lowerQuery = query.toLowerCase();

        // Detect severity
        if (lowerQuery.includes('error') || lowerQuery.includes('failed')) {
            params.severity = 'error';
        } else if (lowerQuery.includes('warning') || lowerQuery.includes('warn')) {
            params.severity = 'warning';
        }

        // Extract search terms (remove common words)
        const stopWords = ['show', 'me', 'find', 'search', 'for', 'the', 'all', 'any'];
        const terms = query.split(' ')
            .filter(word => !stopWords.includes(word.toLowerCase()) && word.length > 2);

        if (terms.length > 0) {
            params.filter_pattern = terms.join('|'); // Regex OR
        }

        return params;
    }

    /**
     * Generate log report
     */
    async generateReport(timeRange = '24h') {
        const since = this.parseTimeRange(timeRange);

        const { logs, analysis } = await this.aggregateLogs({ since });

        return {
            report_id: `report_${Date.now()}`,
            generated_at: new Date(),
            time_range: timeRange,
            summary: {
                total_logs: logs.length,
                errors: analysis.by_severity.error || 0,
                warnings: analysis.by_severity.warning || 0,
                critical: analysis.by_severity.critical || 0
            },
            top_issues: analysis.top_errors.slice(0, 5),
            affected_hosts: Object.keys(analysis.by_host).length,
            error_categories: analysis.by_category,
            anomalies: analysis.anomalies,
            trends: analysis.trends,
            recommendations: this.generateRecommendations(analysis)
        };
    }

    /**
     * Generate recommendations based on analysis
     */
    generateRecommendations(analysis) {
        const recommendations = [];

        // High error rate
        const totalErrors = (analysis.by_severity.error || 0) + (analysis.by_severity.critical || 0);
        if (totalErrors > 100) {
            recommendations.push({
                priority: 'high',
                issue: 'High error rate detected',
                recommendation: 'Investigate top error patterns and implement fixes'
            });
        }

        // Memory issues
        if (analysis.by_category.memory > 0) {
            recommendations.push({
                priority: 'critical',
                issue: 'Memory-related errors detected',
                recommendation: 'Check for memory leaks and scale resources if needed'
            });
        }

        // Network issues
        if (analysis.by_category.network > 10) {
            recommendations.push({
                priority: 'high',
                issue: 'Frequent network errors',
                recommendation: 'Review network configuration and connectivity'
            });
        }

        // Database issues
        if (analysis.by_category.database > 5) {
            recommendations.push({
                priority: 'medium',
                issue: 'Database errors present',
                recommendation: 'Review database queries and connection pooling'
            });
        }

        return recommendations;
    }

    /**
     * Parse time range string
     */
    parseTimeRange(timeRange) {
        const now = Date.now();
        const units = {
            h: 3600000,
            d: 86400000,
            m: 60000
        };

        const match = timeRange.match(/^(\d+)([hmd])$/);
        if (match) {
            const [, amount, unit] = match;
            return new Date(now - parseInt(amount) * units[unit]);
        }

        return new Date(now - 3600000); // Default 1 hour
    }
}

module.exports = SmartLogAggregator;
