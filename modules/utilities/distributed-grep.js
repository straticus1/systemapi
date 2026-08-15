/**
 * Distributed Grep
 * Search files across entire fleet in parallel with aggregated results
 */

const crypto = require('crypto');

class DistributedGrep {
    constructor(fleetManager) {
        this.fleetManager = fleetManager;
        this.activeSearches = new Map(); // searchId -> search state
        this.maxConcurrency = 50; // Max parallel searches
    }

    /**
     * Search across fleet
     */
    async search(pattern, options = {}) {
        const searchId = `search_${crypto.randomUUID()}`;

        const search = {
            search_id: searchId,
            pattern: pattern,
            options: options,
            started_at: new Date(),
            status: 'running',
            total_hosts: 0,
            completed_hosts: 0,
            results: [],
            errors: [],
            stats: {
                total_files_searched: 0,
                total_matches: 0,
                total_bytes_scanned: 0,
                fastest_host_ms: Infinity,
                slowest_host_ms: 0
            }
        };

        this.activeSearches.set(searchId, search);

        // Get target hosts
        const hosts = await this.getTargetHosts(options);
        search.total_hosts = hosts.length;

        console.log(`🔍 Starting distributed search: ${searchId} across ${hosts.length} hosts`);

        // Execute search in parallel with concurrency limit
        const results = await this.executeParallelSearch(search, hosts, pattern, options);

        // Aggregate results
        search.status = 'completed';
        search.completed_at = new Date();
        search.duration_ms = search.completed_at - search.started_at;
        search.results = this.aggregateResults(results);

        console.log(`✅ Search completed: ${searchId} - ${search.stats.total_matches} matches in ${search.duration_ms}ms`);

        return {
            search_id: searchId,
            pattern: pattern,
            total_hosts: search.total_hosts,
            total_matches: search.stats.total_matches,
            total_files_searched: search.stats.total_files_searched,
            duration_ms: search.duration_ms,
            results: search.results.slice(0, options.limit || 1000),
            has_more: search.results.length > (options.limit || 1000)
        };
    }

    /**
     * Execute parallel search across hosts
     */
    async executeParallelSearch(search, hosts, pattern, options) {
        const results = [];
        const batches = this.chunkArray(hosts, this.maxConcurrency);

        for (const batch of batches) {
            const batchPromises = batch.map(host =>
                this.searchHost(host, pattern, options)
                    .then(result => {
                        search.completed_hosts++;
                        search.stats.total_files_searched += result.files_searched || 0;
                        search.stats.total_matches += result.matches?.length || 0;
                        search.stats.total_bytes_scanned += result.bytes_scanned || 0;
                        search.stats.fastest_host_ms = Math.min(search.stats.fastest_host_ms, result.duration_ms || 0);
                        search.stats.slowest_host_ms = Math.max(search.stats.slowest_host_ms, result.duration_ms || 0);
                        return result;
                    })
                    .catch(error => {
                        search.errors.push({
                            host_id: host.host_id,
                            error: error.message
                        });
                        return { host_id: host.host_id, matches: [], error: error.message };
                    })
            );

            const batchResults = await Promise.all(batchPromises);
            results.push(...batchResults);
        }

        return results;
    }

    /**
     * Search a single host
     */
    async searchHost(host, pattern, options) {
        const startTime = Date.now();

        // Build grep command
        const grepCommand = this.buildGrepCommand(pattern, options);

        // Execute on host
        const result = await this.fleetManager.executeCommand(host.host_id, grepCommand);

        const matches = this.parseGrepOutput(result.stdout, host);

        return {
            host_id: host.host_id,
            hostname: host.hostname,
            matches: matches,
            files_searched: matches.length > 0 ? new Set(matches.map(m => m.file)).size : 0,
            bytes_scanned: result.bytes_scanned || 0,
            duration_ms: Date.now() - startTime,
            exit_code: result.exit_code
        };
    }

    /**
     * Build grep command with options
     */
    buildGrepCommand(pattern, options) {
        let command = 'grep';

        // Options
        if (options.recursive) command += ' -r';
        if (options.case_insensitive) command += ' -i';
        if (options.line_number) command += ' -n';
        if (options.count_only) command += ' -c';
        if (options.files_only) command += ' -l';
        if (options.inverted) command += ' -v';
        if (options.extended_regex) command += ' -E';
        if (options.perl_regex) command += ' -P';
        if (options.context_before) command += ` -B ${options.context_before}`;
        if (options.context_after) command += ` -A ${options.context_after}`;
        if (options.context) command += ` -C ${options.context}`;

        // Add color for better parsing (if supported)
        command += ' --color=never';

        // Pattern (escape single quotes)
        const escapedPattern = pattern.replace(/'/g, "'\\''");
        command += ` '${escapedPattern}'`;

        // Paths
        const path = options.path || '/var/log';
        command += ` ${path}`;

        // File type filters
        if (options.include_pattern) {
            command += ` --include='${options.include_pattern}'`;
        }

        if (options.exclude_pattern) {
            command += ` --exclude='${options.exclude_pattern}'`;
        }

        // Limit results
        if (options.max_count) {
            command += ` | head -${options.max_count}`;
        }

        // Suppress errors for inaccessible files
        command += ' 2>/dev/null';

        return command;
    }

    /**
     * Parse grep output into structured results
     */
    parseGrepOutput(output, host) {
        if (!output || output.trim() === '') {
            return [];
        }

        const matches = [];
        const lines = output.split('\n').filter(line => line.trim());

        for (const line of lines) {
            // Parse format: filename:line_number:content
            const match = line.match(/^([^:]+):(\d+):(.+)$/);

            if (match) {
                matches.push({
                    host_id: host.host_id,
                    hostname: host.hostname,
                    file: match[1],
                    line_number: parseInt(match[2]),
                    content: match[3].trim(),
                    timestamp: new Date()
                });
            } else {
                // Files-only mode or count mode
                matches.push({
                    host_id: host.host_id,
                    hostname: host.hostname,
                    file: line.split(':')[0],
                    content: line,
                    timestamp: new Date()
                });
            }
        }

        return matches;
    }

    /**
     * Aggregate and deduplicate results
     */
    aggregateResults(hostResults) {
        const allMatches = [];

        for (const hostResult of hostResults) {
            if (hostResult.matches && hostResult.matches.length > 0) {
                allMatches.push(...hostResult.matches);
            }
        }

        // Sort by relevance (can be enhanced with scoring)
        allMatches.sort((a, b) => {
            // Prioritize by hostname, then by file, then by line number
            if (a.hostname !== b.hostname) {
                return a.hostname.localeCompare(b.hostname);
            }
            if (a.file !== b.file) {
                return a.file.localeCompare(b.file);
            }
            return (a.line_number || 0) - (b.line_number || 0);
        });

        return allMatches;
    }

    /**
     * Search with smart filtering and ranking
     */
    async smartSearch(pattern, options = {}) {
        // First, do a basic search
        const basicResults = await this.search(pattern, options);

        // Apply ML-based ranking (simplified)
        const rankedResults = this.rankResults(basicResults.results, pattern);

        // Cluster similar results
        const clustered = this.clusterResults(rankedResults);

        return {
            ...basicResults,
            results: rankedResults,
            clusters: clustered
        };
    }

    /**
     * Rank results by relevance
     */
    rankResults(results, pattern) {
        return results.map(result => {
            let score = 0;

            // Exact match bonus
            if (result.content.includes(pattern)) {
                score += 10;
            }

            // Shorter lines are often more relevant
            if (result.content.length < 200) {
                score += 5;
            }

            // Recent files bonus (if timestamp available)
            const hoursSinceMatch = (Date.now() - new Date(result.timestamp)) / 3600000;
            if (hoursSinceMatch < 24) {
                score += 3;
            }

            // Configuration files are often important
            if (result.file.includes('/etc/') || result.file.endsWith('.conf')) {
                score += 2;
            }

            return {
                ...result,
                relevance_score: score
            };
        }).sort((a, b) => b.relevance_score - a.relevance_score);
    }

    /**
     * Cluster similar results
     */
    clusterResults(results) {
        const clusters = new Map();

        for (const result of results) {
            // Cluster by file path
            const clusterKey = result.file;

            if (!clusters.has(clusterKey)) {
                clusters.set(clusterKey, {
                    file: result.file,
                    hosts: new Set(),
                    match_count: 0,
                    sample_matches: []
                });
            }

            const cluster = clusters.get(clusterKey);
            cluster.hosts.add(result.hostname);
            cluster.match_count++;

            if (cluster.sample_matches.length < 3) {
                cluster.sample_matches.push(result);
            }
        }

        return Array.from(clusters.values()).map(c => ({
            ...c,
            hosts: Array.from(c.hosts)
        }));
    }

    /**
     * Get target hosts based on options
     */
    async getTargetHosts(options) {
        let hosts = await this.fleetManager.getHosts({ status: 'online' });

        // Filter by tags
        if (options.tags) {
            hosts = hosts.filter(h =>
                options.tags.every(tag => h.tags?.includes(tag))
            );
        }

        // Filter by hostname pattern
        if (options.hostname_pattern) {
            const regex = new RegExp(options.hostname_pattern);
            hosts = hosts.filter(h => regex.test(h.hostname));
        }

        // Filter by OS
        if (options.os_filter) {
            hosts = hosts.filter(h =>
                h.os?.toLowerCase().includes(options.os_filter.toLowerCase())
            );
        }

        // Limit hosts
        if (options.max_hosts) {
            hosts = hosts.slice(0, options.max_hosts);
        }

        return hosts;
    }

    /**
     * Stream results as they come in (for real-time display)
     */
    async *searchStream(pattern, options = {}) {
        const searchId = `search_${crypto.randomUUID()}`;
        const hosts = await this.getTargetHosts(options);

        yield {
            type: 'started',
            search_id: searchId,
            total_hosts: hosts.length,
            pattern: pattern
        };

        // Search hosts one by one and yield results immediately
        for (const host of hosts) {
            try {
                const result = await this.searchHost(host, pattern, options);

                if (result.matches.length > 0) {
                    yield {
                        type: 'results',
                        host_id: host.host_id,
                        hostname: host.hostname,
                        matches: result.matches
                    };
                }

                yield {
                    type: 'progress',
                    completed: hosts.indexOf(host) + 1,
                    total: hosts.length
                };
            } catch (error) {
                yield {
                    type: 'error',
                    host_id: host.host_id,
                    error: error.message
                };
            }
        }

        yield {
            type: 'completed',
            search_id: searchId
        };
    }

    /**
     * Get search history
     */
    getSearchHistory(limit = 10) {
        const history = Array.from(this.activeSearches.values())
            .filter(s => s.status === 'completed')
            .sort((a, b) => b.started_at - a.started_at)
            .slice(0, limit);

        return history.map(s => ({
            search_id: s.search_id,
            pattern: s.pattern,
            total_hosts: s.total_hosts,
            total_matches: s.stats.total_matches,
            duration_ms: s.duration_ms,
            started_at: s.started_at
        }));
    }

    /**
     * Helper: chunk array into batches
     */
    chunkArray(array, size) {
        const chunks = [];
        for (let i = 0; i < array.length; i += size) {
            chunks.push(array.slice(i, i + size));
        }
        return chunks;
    }

    /**
     * Cancel active search
     */
    cancelSearch(searchId) {
        const search = this.activeSearches.get(searchId);
        if (search) {
            search.status = 'cancelled';
            return true;
        }
        return false;
    }

    /**
     * Get search statistics
     */
    getStats() {
        const completed = Array.from(this.activeSearches.values())
            .filter(s => s.status === 'completed');

        if (completed.length === 0) {
            return { total_searches: 0 };
        }

        const totalDuration = completed.reduce((sum, s) => sum + s.duration_ms, 0);
        const totalMatches = completed.reduce((sum, s) => sum + s.stats.total_matches, 0);

        return {
            total_searches: completed.length,
            avg_duration_ms: totalDuration / completed.length,
            avg_matches_per_search: totalMatches / completed.length,
            total_hosts_searched: completed.reduce((sum, s) => sum + s.total_hosts, 0),
            fastest_search_ms: Math.min(...completed.map(s => s.duration_ms)),
            slowest_search_ms: Math.max(...completed.map(s => s.duration_ms))
        };
    }
}

module.exports = DistributedGrep;
