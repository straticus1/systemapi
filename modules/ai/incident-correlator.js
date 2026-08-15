/**
 * Incident Correlation Engine
 * AI-powered incident detection and correlation across fleet
 * Identifies patterns, cascading failures, and root causes
 */

class IncidentCorrelator {
    constructor(db) {
        this.db = db;
        this.activeIncidents = new Map();
        this.eventWindow = 300000; // 5 minutes correlation window
        this.correlationRules = this.initializeRules();
    }

    /**
     * Initialize correlation rules
     */
    initializeRules() {
        return [
            {
                id: 'cascading_failure',
                name: 'Cascading Service Failure',
                description: 'Multiple services failing in sequence',
                pattern: (events) => {
                    const serviceFailures = events.filter(e => e.type === 'service_down');
                    return serviceFailures.length >= 3 &&
                           this.hasTemporalSequence(serviceFailures, 60000); // 1 minute
                },
                severity: 'critical',
                suggested_action: 'Check for upstream dependency failures or network issues'
            },
            {
                id: 'memory_exhaustion_cluster',
                name: 'Cluster-wide Memory Exhaustion',
                description: 'Multiple hosts experiencing OOM simultaneously',
                pattern: (events) => {
                    const memEvents = events.filter(e =>
                        e.type === 'high_memory' && e.data?.memory_percent > 90
                    );
                    const uniqueHosts = new Set(memEvents.map(e => e.host_id));
                    return uniqueHosts.size >= 3 &&
                           this.hasTimeProximity(memEvents, 120000); // 2 minutes
                },
                severity: 'critical',
                suggested_action: 'Possible memory leak or sudden traffic spike. Scale resources or investigate application'
            },
            {
                id: 'disk_fill_pattern',
                name: 'Coordinated Disk Fill Pattern',
                description: 'Suspicious rapid disk growth across hosts',
                pattern: (events) => {
                    const diskEvents = events.filter(e =>
                        e.type === 'disk_usage' &&
                        e.data?.growth_rate > 5 // >5% per hour
                    );
                    return diskEvents.length >= 2 &&
                           this.hasCommonCause(diskEvents);
                },
                severity: 'high',
                suggested_action: 'Possible log bomb, DOS attack, or runaway process. Check recent deployments'
            },
            {
                id: 'authentication_spike',
                name: 'Authentication Failure Spike',
                description: 'Unusual authentication failure rate',
                pattern: (events) => {
                    const authFails = events.filter(e => e.type === 'auth_failure');
                    const normalRate = this.getHistoricalRate('auth_failure');
                    const currentRate = authFails.length / (this.eventWindow / 60000); // per minute

                    return currentRate > normalRate * 5; // 5x normal
                },
                severity: 'high',
                suggested_action: 'Possible brute force attack or credential stuffing. Enable rate limiting'
            },
            {
                id: 'network_partition',
                name: 'Network Partition Detected',
                description: 'Multiple hosts losing connectivity simultaneously',
                pattern: (events) => {
                    const connectivityLoss = events.filter(e =>
                        e.type === 'connectivity_lost' || e.type === 'ping_timeout'
                    );
                    const affectedHosts = new Set(connectivityLoss.map(e => e.host_id));

                    // Check if hosts share network segment
                    return affectedHosts.size >= 3 &&
                           this.shareNetworkSegment(Array.from(affectedHosts));
                },
                severity: 'critical',
                suggested_action: 'Check network infrastructure, routers, or cloud provider status'
            },
            {
                id: 'deployment_rollout_issue',
                name: 'Problematic Deployment Rollout',
                description: 'Errors correlate with recent deployment',
                pattern: (events) => {
                    const errors = events.filter(e => e.type === 'error' || e.type === 'exception');
                    const deployments = events.filter(e => e.type === 'deployment');

                    if (deployments.length === 0) return false;

                    const recentDeploy = deployments[deployments.length - 1];
                    const errorsAfterDeploy = errors.filter(e =>
                        e.timestamp > recentDeploy.timestamp
                    );

                    return errorsAfterDeploy.length >= 5; // 5+ errors after deployment
                },
                severity: 'high',
                suggested_action: 'Consider rollback. Review deployment changes and error logs'
            },
            {
                id: 'resource_exhaustion_ddos',
                name: 'Potential DDoS Attack',
                description: 'High CPU/network with connection spike',
                pattern: (events) => {
                    const highCPU = events.filter(e =>
                        e.type === 'high_cpu' && e.data?.cpu_percent > 80
                    );
                    const connectionSpike = events.filter(e =>
                        e.type === 'connection_spike' && e.data?.connections > 1000
                    );

                    return highCPU.length >= 2 && connectionSpike.length >= 1;
                },
                severity: 'critical',
                suggested_action: 'Activate DDoS mitigation. Check firewall rules and rate limiting'
            },
            {
                id: 'database_deadlock_cascade',
                name: 'Database Deadlock Cascade',
                description: 'Multiple database deadlocks in short period',
                pattern: (events) => {
                    const deadlocks = events.filter(e =>
                        e.type === 'database_error' &&
                        e.data?.error?.includes('deadlock')
                    );
                    return deadlocks.length >= 3;
                },
                severity: 'high',
                suggested_action: 'Review transaction isolation levels and query patterns'
            },
            {
                id: 'time_drift_cluster',
                name: 'Clock Drift Across Cluster',
                description: 'System time discrepancies detected',
                pattern: (events) => {
                    const timeDrift = events.filter(e =>
                        e.type === 'time_drift' && Math.abs(e.data?.drift_seconds) > 5
                    );
                    return timeDrift.length >= 2;
                },
                severity: 'medium',
                suggested_action: 'Sync NTP servers. Time drift can cause distributed system issues'
            },
            {
                id: 'ssl_cert_expiration_wave',
                name: 'Multiple Certificate Expirations',
                description: 'SSL/TLS certificates expiring soon',
                pattern: (events) => {
                    const certWarnings = events.filter(e =>
                        e.type === 'cert_expiring' && e.data?.days_until_expiry < 7
                    );
                    return certWarnings.length >= 2;
                },
                severity: 'medium',
                suggested_action: 'Renew certificates immediately. Setup auto-renewal if possible'
            }
        ];
    }

    /**
     * Analyze incoming event and correlate with recent events
     */
    async analyzeEvent(event) {
        // Store event
        await this.storeEvent(event);

        // Get recent events in correlation window
        const recentEvents = await this.getRecentEvents(this.eventWindow);

        // Add current event
        recentEvents.push(event);

        // Run correlation rules
        const incidents = [];
        for (const rule of this.correlationRules) {
            try {
                if (rule.pattern(recentEvents)) {
                    const incident = await this.createIncident(rule, recentEvents, event);
                    incidents.push(incident);
                }
            } catch (error) {
                console.error(`Error in rule ${rule.id}:`, error);
            }
        }

        // Check for new incident patterns using ML
        const mlIncidents = await this.detectAnomalousPatterns(recentEvents);
        incidents.push(...mlIncidents);

        return {
            event_processed: true,
            incidents_detected: incidents.length,
            incidents: incidents
        };
    }

    /**
     * Create incident from matched rule
     */
    async createIncident(rule, events, triggerEvent) {
        const incidentId = `inc_${Date.now()}_${rule.id}`;

        // Check if similar incident already exists
        const existing = Array.from(this.activeIncidents.values()).find(inc =>
            inc.rule_id === rule.id &&
            (Date.now() - inc.created_at.getTime()) < 600000 // 10 minutes
        );

        if (existing) {
            // Update existing incident
            existing.event_count++;
            existing.last_updated = new Date();
            existing.related_events.push(triggerEvent.event_id);
            return existing;
        }

        const incident = {
            incident_id: incidentId,
            rule_id: rule.id,
            name: rule.name,
            description: rule.description,
            severity: rule.severity,
            status: 'open',
            created_at: new Date(),
            last_updated: new Date(),
            event_count: events.length,
            affected_hosts: [...new Set(events.map(e => e.host_id).filter(Boolean))],
            related_events: events.map(e => e.event_id),
            trigger_event: triggerEvent.event_id,
            suggested_action: rule.suggested_action,
            impact_score: this.calculateImpactScore(events, rule.severity),
            root_cause_analysis: await this.performRootCauseAnalysis(events),
            timeline: this.generateTimeline(events)
        };

        this.activeIncidents.set(incidentId, incident);

        // Store in database
        await this.db.query(`
            INSERT INTO incidents (
                incident_id, rule_id, name, description, severity,
                status, created_at, event_count, affected_hosts,
                suggested_action, impact_score, root_cause_analysis
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        `, [
            incidentId, rule.id, incident.name, incident.description, incident.severity,
            'open', incident.created_at, incident.event_count,
            JSON.stringify(incident.affected_hosts),
            incident.suggested_action, incident.impact_score,
            JSON.stringify(incident.root_cause_analysis)
        ]);

        console.log(`🚨 INCIDENT CREATED: ${incidentId} - ${rule.name}`);

        return incident;
    }

    /**
     * Perform root cause analysis
     */
    async performRootCauseAnalysis(events) {
        // Sort events chronologically
        const sorted = events.sort((a, b) => a.timestamp - b.timestamp);

        // Find first event (potential root cause)
        const firstEvent = sorted[0];

        // Look for causal relationships
        const causalChain = [];
        for (let i = 0; i < sorted.length - 1; i++) {
            const current = sorted[i];
            const next = sorted[i + 1];

            // Check if events are causally related
            if (this.areCausallyRelated(current, next)) {
                causalChain.push({
                    cause: current.event_id,
                    effect: next.event_id,
                    time_delta_ms: next.timestamp - current.timestamp
                });
            }
        }

        return {
            probable_root_cause: firstEvent.event_id,
            root_cause_type: firstEvent.type,
            root_cause_host: firstEvent.host_id,
            causal_chain: causalChain,
            confidence: causalChain.length > 0 ? 0.8 : 0.5
        };
    }

    /**
     * Check if two events are causally related
     */
    areCausallyRelated(event1, event2) {
        // Same host events are more likely related
        if (event1.host_id === event2.host_id) {
            return true;
        }

        // Known causal relationships
        const causalPairs = [
            { cause: 'service_down', effect: 'connection_refused' },
            { cause: 'high_memory', effect: 'oom_kill' },
            { cause: 'high_cpu', effect: 'slow_response' },
            { cause: 'disk_full', effect: 'write_error' },
            { cause: 'network_partition', effect: 'connectivity_lost' }
        ];

        return causalPairs.some(pair =>
            event1.type === pair.cause && event2.type === pair.effect
        );
    }

    /**
     * Calculate impact score (0-100)
     */
    calculateImpactScore(events, severity) {
        let score = 0;

        // Severity base score
        const severityScores = { critical: 50, high: 35, medium: 20, low: 10 };
        score += severityScores[severity] || 10;

        // Number of affected hosts
        const hostCount = new Set(events.map(e => e.host_id).filter(Boolean)).size;
        score += Math.min(hostCount * 5, 30);

        // Event frequency
        const frequency = events.length;
        score += Math.min(frequency * 2, 20);

        return Math.min(score, 100);
    }

    /**
     * Generate incident timeline
     */
    generateTimeline(events) {
        return events
            .sort((a, b) => a.timestamp - b.timestamp)
            .map(e => ({
                timestamp: new Date(e.timestamp),
                event_type: e.type,
                host_id: e.host_id,
                message: e.message || e.type
            }));
    }

    /**
     * Detect anomalous patterns using simple ML
     */
    async detectAnomalousPatterns(events) {
        const incidents = [];

        // Group events by type
        const eventsByType = {};
        for (const event of events) {
            if (!eventsByType[event.type]) {
                eventsByType[event.type] = [];
            }
            eventsByType[event.type].push(event);
        }

        // Check for anomalous frequencies
        for (const [type, typeEvents] of Object.entries(eventsByType)) {
            const currentRate = typeEvents.length / (this.eventWindow / 60000);
            const historicalRate = await this.getHistoricalRate(type);

            // Anomaly if current rate > 3x historical average
            if (historicalRate > 0 && currentRate > historicalRate * 3) {
                incidents.push({
                    incident_id: `inc_${Date.now()}_anomaly_${type}`,
                    rule_id: 'ml_anomaly_detection',
                    name: `Anomalous ${type} Event Rate`,
                    description: `Detected ${currentRate.toFixed(1)}/min (normal: ${historicalRate.toFixed(1)}/min)`,
                    severity: 'medium',
                    status: 'open',
                    created_at: new Date(),
                    event_count: typeEvents.length,
                    suggested_action: `Investigate spike in ${type} events`
                });
            }
        }

        return incidents;
    }

    /**
     * Helper functions for pattern matching
     */
    hasTemporalSequence(events, maxGapMs) {
        if (events.length < 2) return false;

        const sorted = events.sort((a, b) => a.timestamp - b.timestamp);
        for (let i = 0; i < sorted.length - 1; i++) {
            const gap = sorted[i + 1].timestamp - sorted[i].timestamp;
            if (gap > maxGapMs) return false;
        }
        return true;
    }

    hasTimeProximity(events, windowMs) {
        if (events.length < 2) return false;

        const timestamps = events.map(e => e.timestamp);
        const min = Math.min(...timestamps);
        const max = Math.max(...timestamps);

        return (max - min) <= windowMs;
    }

    hasCommonCause(events) {
        // Check if events share common attributes
        // (simplified - would use more sophisticated analysis)
        const paths = events.map(e => e.data?.path || '');
        const uniquePaths = new Set(paths);
        return uniquePaths.size < events.length * 0.5; // 50% share same path
    }

    shareNetworkSegment(hostIds) {
        // Simplified - would check actual network topology
        // Assume hosts with similar IDs are in same segment
        return true;
    }

    /**
     * Store event in database
     */
    async storeEvent(event) {
        await this.db.query(`
            INSERT INTO correlation_events (
                event_id, type, host_id, timestamp, data, message
            ) VALUES ($1, $2, $3, $4, $5, $6)
        `, [
            event.event_id,
            event.type,
            event.host_id,
            new Date(event.timestamp),
            JSON.stringify(event.data || {}),
            event.message
        ]);
    }

    /**
     * Get recent events from database
     */
    async getRecentEvents(windowMs) {
        const since = new Date(Date.now() - windowMs);

        const result = await this.db.query(`
            SELECT event_id, type, host_id, timestamp, data, message
            FROM correlation_events
            WHERE timestamp > $1
            ORDER BY timestamp DESC
        `, [since]);

        return result.rows.map(row => ({
            event_id: row.event_id,
            type: row.type,
            host_id: row.host_id,
            timestamp: row.timestamp.getTime(),
            data: JSON.parse(row.data || '{}'),
            message: row.message
        }));
    }

    /**
     * Get historical event rate for anomaly detection
     */
    async getHistoricalRate(eventType) {
        // Get average rate from past 7 days
        const result = await this.db.query(`
            SELECT COUNT(*) as count
            FROM correlation_events
            WHERE type = $1
              AND timestamp > NOW() - INTERVAL '7 days'
        `, [eventType]);

        const count = parseInt(result.rows[0]?.count || 0);
        const minutes = 7 * 24 * 60; // 7 days in minutes
        return count / minutes; // Events per minute
    }

    /**
     * Resolve incident
     */
    async resolveIncident(incidentId, resolution) {
        const incident = this.activeIncidents.get(incidentId);
        if (incident) {
            incident.status = 'resolved';
            incident.resolved_at = new Date();
            incident.resolution = resolution;

            await this.db.query(`
                UPDATE incidents
                SET status = 'resolved',
                    resolved_at = $2,
                    resolution = $3
                WHERE incident_id = $1
            `, [incidentId, incident.resolved_at, resolution]);

            this.activeIncidents.delete(incidentId);
        }
    }

    /**
     * Get active incidents
     */
    getActiveIncidents() {
        return Array.from(this.activeIncidents.values());
    }

    /**
     * Get incident statistics
     */
    async getStats() {
        const result = await this.db.query(`
            SELECT
                severity,
                status,
                COUNT(*) as count,
                AVG(impact_score) as avg_impact
            FROM incidents
            GROUP BY severity, status
        `);

        return result.rows;
    }
}

module.exports = IncidentCorrelator;
