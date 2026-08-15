/**
 * Predictive Maintenance AI
 * Predicts when servers will fail using telemetry data
 */

class PredictiveMaintenanceEngine {
    constructor(db) {
        this.db = db;
        this.predictions = new Map();
        this.models = new Map();
        this.thresholds = {
            disk_full: { days: 7, confidence: 0.75 },
            memory_leak: { hours: 24, confidence: 0.80 },
            cpu_degradation: { hours: 48, confidence: 0.70 },
            network_saturation: { hours: 12, confidence: 0.75 }
        };
    }

    /**
     * Analyze host and predict failures
     */
    async analyzeHost(hostId) {
        // Get historical telemetry
        const history = await this.getTelemetryHistory(hostId, 30); // 30 days

        if (history.length < 100) {
            return {
                host_id: hostId,
                status: 'insufficient_data',
                message: 'Need at least 100 data points for predictions'
            };
        }

        const predictions = [];

        // Predict disk full
        const diskPrediction = this.predictDiskFull(history);
        if (diskPrediction.probability > this.thresholds.disk_full.confidence) {
            predictions.push(diskPrediction);
        }

        // Predict memory leak
        const memoryPrediction = this.predictMemoryLeak(history);
        if (memoryPrediction.probability > this.thresholds.memory_leak.confidence) {
            predictions.push(memoryPrediction);
        }

        // Predict CPU degradation
        const cpuPrediction = this.predictCPUDegradation(history);
        if (cpuPrediction.probability > this.thresholds.cpu_degradation.confidence) {
            predictions.push(cpuPrediction);
        }

        // Store predictions
        this.predictions.set(hostId, {
            timestamp: new Date(),
            predictions: predictions
        });

        return {
            host_id: hostId,
            analyzed_at: new Date(),
            data_points: history.length,
            predictions: predictions,
            overall_health_score: this.calculateHealthScore(predictions)
        };
    }

    /**
     * Predict when disk will be full
     */
    predictDiskFull(history) {
        // Extract disk usage over time
        const diskData = history
            .filter(h => h.disk && h.disk.length > 0)
            .map(h => ({
                timestamp: new Date(h.timestamp),
                usage: h.disk[0].used_percent
            }))
            .sort((a, b) => a.timestamp - b.timestamp);

        if (diskData.length < 10) {
            return { issue: 'disk_full', probability: 0, message: 'Insufficient disk data' };
        }

        // Simple linear regression
        const regression = this.linearRegression(diskData.map((d, i) => [i, d.usage]));

        // Predict when disk will hit 100%
        const currentUsage = diskData[diskData.length - 1].usage;
        const growthRate = regression.slope;

        if (growthRate <= 0) {
            return {
                issue: 'disk_full',
                probability: 0,
                message: 'Disk usage is stable or decreasing'
            };
        }

        const spaceLeft = 100 - currentUsage;
        const hoursToFull = (spaceLeft / growthRate) * (diskData.length > 1 ? 24 : 1);
        const daysToFull = hoursToFull / 24;

        const probability = this.calculateProbability(daysToFull, currentUsage, growthRate);

        return {
            issue: 'disk_full',
            probability: probability,
            estimated_time: `${Math.max(0, daysToFull).toFixed(1)} days`,
            estimated_hours: Math.max(0, hoursToFull),
            current_usage: currentUsage.toFixed(1) + '%',
            growth_rate: (growthRate * 24).toFixed(2) + '% per day',
            suggested_actions: this.getDiskFullActions(daysToFull, currentUsage),
            details: {
                regression: regression,
                confidence: probability
            }
        };
    }

    /**
     * Predict memory leak
     */
    predictMemoryLeak(history) {
        const memData = history
            .filter(h => h.memory)
            .map(h => ({
                timestamp: new Date(h.timestamp),
                usage: h.memory.used_percent
            }))
            .slice(-168); // Last 7 days of hourly data

        if (memData.length < 24) {
            return { issue: 'memory_leak', probability: 0, message: 'Insufficient memory data' };
        }

        // Check for consistent upward trend
        const trend = this.detectTrend(memData.map(d => d.usage));
        const regression = this.linearRegression(memData.map((d, i) => [i, d.usage]));

        // Memory leak indicators:
        // 1. Consistent positive slope
        // 2. No periodic dips (restarts would show this)
        // 3. Correlation > 0.8

        const hasPositiveSlope = regression.slope > 0.1;
        const hasHighCorrelation = regression.r2 > 0.8;
        const noPer idicDips = !this.detectPeriodicPattern(memData.map(d => d.usage));

        if (!hasPositiveSlope || !hasHighCorrelation) {
            return {
                issue: 'memory_leak',
                probability: 0,
                message: 'No memory leak pattern detected'
            };
        }

        const currentUsage = memData[memData.length - 1].usage;
        const hoursTo100 = (100 - currentUsage) / regression.slope;

        const probability = (hasPositiveSlope && hasHighCorrelation && noPeriodicDips) ? 0.85 : 0.5;

        return {
            issue: 'memory_leak',
            probability: probability,
            estimated_time: `${Math.max(0, hoursTo100).toFixed(1)} hours`,
            current_usage: currentUsage.toFixed(1) + '%',
            leak_rate: regression.slope.toFixed(3) + '% per hour',
            suggested_actions: this.getMemoryLeakActions(),
            details: {
                trend: trend,
                regression: regression,
                indicators: { hasPositiveSlope, hasHighCorrelation, noPeriodicDips }
            }
        };
    }

    /**
     * Predict CPU degradation
     */
    predictCPUDegradation(history) {
        const cpuData = history
            .filter(h => h.cpu)
            .map(h => ({
                timestamp: new Date(h.timestamp),
                usage: h.cpu.usage_percent
            }));

        if (cpuData.length < 24) {
            return { issue: 'cpu_degradation', probability: 0, message: 'Insufficient CPU data' };
        }

        // Calculate rolling average
        const rollingAvg = this.rollingAverage(cpuData.map(d => d.usage), 12);

        // Check for increasing baseline
        const baselineTrend = this.detectTrend(rollingAvg);

        if (baselineTrend.direction !== 'increasing') {
            return {
                issue: 'cpu_degradation',
                probability: 0,
                message: 'CPU usage is stable or decreasing'
            };
        }

        const probability = baselineTrend.strength;
        const currentAvg = rollingAvg[rollingAvg.length - 1];

        return {
            issue: 'cpu_degradation',
            probability: probability,
            current_baseline: currentAvg.toFixed(1) + '%',
            trend: baselineTrend.direction,
            trend_strength: baselineTrend.strength,
            suggested_actions: this.getCPUDegradationActions(currentAvg),
            details: {
                rolling_average: rollingAvg.slice(-24)
            }
        };
    }

    /**
     * Simple linear regression
     */
    linearRegression(points) {
        const n = points.length;
        let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;

        for (const [x, y] of points) {
            sumX += x;
            sumY += y;
            sumXY += x * y;
            sumX2 += x * x;
        }

        const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
        const intercept = (sumY - slope * sumX) / n;

        // Calculate R²
        const yMean = sumY / n;
        let ssTotal = 0, ssResidual = 0;
        for (const [x, y] of points) {
            const predicted = slope * x + intercept;
            ssTotal += (y - yMean) ** 2;
            ssResidual += (y - predicted) ** 2;
        }
        const r2 = 1 - (ssResidual / ssTotal);

        return { slope, intercept, r2 };
    }

    /**
     * Detect trend in data
     */
    detectTrend(data) {
        const regression = this.linearRegression(data.map((y, x) => [x, y]));

        return {
            direction: regression.slope > 0.1 ? 'increasing' : regression.slope < -0.1 ? 'decreasing' : 'stable',
            strength: Math.abs(regression.slope) * regression.r2,
            slope: regression.slope
        };
    }

    /**
     * Calculate rolling average
     */
    rollingAverage(data, window) {
        const result = [];
        for (let i = 0; i < data.length; i++) {
            const start = Math.max(0, i - window + 1);
            const slice = data.slice(start, i + 1);
            const avg = slice.reduce((a, b) => a + b, 0) / slice.length;
            result.push(avg);
        }
        return result;
    }

    /**
     * Detect periodic patterns
     */
    detectPeriodicPattern(data) {
        // Simplified: check for regular dips
        const dips = [];
        for (let i = 1; i < data.length - 1; i++) {
            if (data[i] < data[i - 1] && data[i] < data[i + 1]) {
                dips.push(i);
            }
        }

        if (dips.length < 2) return false;

        // Check if dips are regularly spaced
        const intervals = [];
        for (let i = 1; i < dips.length; i++) {
            intervals.push(dips[i] - dips[i - 1]);
        }

        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((sum, val) => sum + (val - avgInterval) ** 2, 0) / intervals.length;

        return variance < avgInterval * 0.2; // Regular if variance is low
    }

    /**
     * Calculate probability based on various factors
     */
    calculateProbability(daysToFull, currentUsage, growthRate) {
        let probability = 0;

        // Factor 1: Time to failure
        if (daysToFull < 1) probability += 0.5;
        else if (daysToFull < 3) probability += 0.4;
        else if (daysToFull < 7) probability += 0.3;
        else if (daysToFull < 14) probability += 0.2;

        // Factor 2: Current usage
        if (currentUsage > 90) probability += 0.3;
        else if (currentUsage > 80) probability += 0.2;
        else if (currentUsage > 70) probability += 0.1;

        // Factor 3: Growth rate
        if (growthRate > 5) probability += 0.2;
        else if (growthRate > 2) probability += 0.1;

        return Math.min(probability, 0.99);
    }

    /**
     * Get suggested actions for disk full
     */
    getDiskFullActions(daysToFull, currentUsage) {
        const actions = [];

        if (daysToFull < 1) {
            actions.push({
                priority: 'critical',
                action: 'cleanup_logs',
                title: 'Clean up old log files',
                script: 'cleanup_old_logs.star'
            });
            actions.push({
                priority: 'critical',
                action: 'expand_disk',
                title: 'Expand disk volume immediately',
                script: null
            });
        } else if (daysToFull < 7) {
            actions.push({
                priority: 'high',
                action: 'schedule_cleanup',
                title: 'Schedule log rotation and cleanup',
                script: 'schedule_cleanup.star'
            });
            actions.push({
                priority: 'medium',
                action: 'analyze_usage',
                title: 'Analyze disk usage and identify large files',
                script: 'disk_usage_analysis.star'
            });
        } else {
            actions.push({
                priority: 'medium',
                action: 'monitor',
                title: 'Continue monitoring disk usage',
                script: null
            });
        }

        return actions;
    }

    /**
     * Get suggested actions for memory leak
     */
    getMemoryLeakActions() {
        return [
            {
                priority: 'high',
                action: 'identify_process',
                title: 'Identify process with memory leak',
                script: 'find_memory_leak.star'
            },
            {
                priority: 'high',
                action: 'schedule_restart',
                title: 'Schedule service restart during maintenance window',
                script: null
            },
            {
                priority: 'medium',
                action: 'enable_monitoring',
                title: 'Enable detailed memory profiling',
                script: null
            }
        ];
    }

    /**
     * Get suggested actions for CPU degradation
     */
    getCPUDegradationActions(currentAvg) {
        const actions = [];

        if (currentAvg > 80) {
            actions.push({
                priority: 'critical',
                action: 'scale_resources',
                title: 'Scale up resources or add more hosts',
                script: null
            });
        }

        actions.push({
            priority: 'high',
            action: 'identify_cpu_hogs',
            title: 'Identify CPU-intensive processes',
            script: 'find_cpu_hogs.star'
        });

        actions.push({
            priority: 'medium',
            action: 'optimize_queries',
            title: 'Review and optimize database queries',
            script: null
        });

        return actions;
    }

    /**
     * Calculate overall health score
     */
    calculateHealthScore(predictions) {
        if (predictions.length === 0) {
            return 100;
        }

        let score = 100;

        for (const prediction of predictions) {
            const impact = prediction.probability * 100;

            if (prediction.issue === 'disk_full') {
                score -= impact * 0.3;
            } else if (prediction.issue === 'memory_leak') {
                score -= impact * 0.4;
            } else if (prediction.issue === 'cpu_degradation') {
                score -= impact * 0.3;
            }
        }

        return Math.max(0, Math.round(score));
    }

    /**
     * Get telemetry history from database
     */
    async getTelemetryHistory(hostId, days) {
        // Mock implementation - would query actual database
        return [];
    }

    /**
     * Analyze entire fleet
     */
    async analyzeFleet() {
        const hosts = await this.getAllHosts();
        const results = [];

        for (const host of hosts) {
            const analysis = await this.analyzeHost(host.host_id);
            results.push(analysis);
        }

        return {
            total_hosts: hosts.length,
            analyzed_at: new Date(),
            hosts_at_risk: results.filter(r => r.predictions && r.predictions.length > 0).length,
            results: results
        };
    }

    /**
     * Get all hosts (mock)
     */
    async getAllHosts() {
        // Would query database
        return [];
    }
}

module.exports = PredictiveMaintenanceEngine;
