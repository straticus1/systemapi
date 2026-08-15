/**
 * Time-Based API Keys (Cinderella Keys)
 * API keys that expire, work only during certain hours, have geographic restrictions, etc.
 */

const crypto = require('crypto');

class CinderellaKeyManager {
    constructor(db) {
        this.db = db;
    }

    /**
     * Create a time-based API key with restrictions
     */
    async createCinderellaKey(userId, config) {
        const keyId = `ak_temp_${crypto.randomBytes(8).toString('base64url')}`;
        const keySecret = `${keyId}.${crypto.randomBytes(24).toString('base64url')}`;

        // Calculate expiration
        let expiresAt = null;
        if (config.expires_in) {
            expiresAt = new Date();
            const duration = this.parseDuration(config.expires_in);
            expiresAt = new Date(expiresAt.getTime() + duration);
        }

        const cinderellaKey = {
            key_id: keyId,
            key_secret_hash: await this.hashKey(keySecret),
            user_id: userId,
            name: config.name || 'Temporary Key',

            // Time restrictions
            expires_at: expiresAt,
            valid_hours: config.valid_hours || null, // "09:00-17:00 PST"
            valid_days: config.valid_days || null,   // ["monday", "tuesday", ...]
            timezone: config.timezone || 'UTC',

            // Geographic restrictions
            allowed_countries: config.allowed_countries || null,
            allowed_ips: config.allowed_ips || null,
            allowed_cidr: config.allowed_cidr || null,

            // Usage limits
            max_uses: config.max_uses || null,
            max_uses_per_hour: config.max_uses_per_hour || null,
            max_uses_per_day: config.max_uses_per_day || null,

            // Scope restrictions
            allowed_endpoints: config.allowed_endpoints || null,
            allowed_methods: config.allowed_methods || null,
            allowed_hosts: config.allowed_hosts || null,

            // Tracking
            uses_count: 0,
            created_at: new Date(),
            last_used_at: null,
            is_active: true
        };

        // Store in database
        await this.db.query(`
            INSERT INTO cinderella_api_keys (
                key_id, key_secret_hash, user_id, name,
                expires_at, valid_hours, valid_days, timezone,
                allowed_countries, allowed_ips, allowed_cidr,
                max_uses, max_uses_per_hour, max_uses_per_day,
                allowed_endpoints, allowed_methods, allowed_hosts,
                created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
        `, [
            keyId, cinderellaKey.key_secret_hash, userId, cinderellaKey.name,
            expiresAt, cinderellaKey.valid_hours, cinderellaKey.valid_days, cinderellaKey.timezone,
            cinderellaKey.allowed_countries, cinderellaKey.allowed_ips, cinderellaKey.allowed_cidr,
            cinderellaKey.max_uses, cinderellaKey.max_uses_per_hour, cinderellaKey.max_uses_per_day,
            cinderellaKey.allowed_endpoints, cinderellaKey.allowed_methods, cinderellaKey.allowed_hosts,
            cinderellaKey.created_at
        ]);

        console.log(`🕐 Cinderella Key created: ${keyId} (expires: ${expiresAt || 'never'})`);

        return {
            key_id: keyId,
            key_secret: keySecret,
            name: cinderellaKey.name,
            expires_at: expiresAt,
            restrictions: {
                valid_hours: cinderellaKey.valid_hours,
                valid_days: cinderellaKey.valid_days,
                allowed_countries: cinderellaKey.allowed_countries,
                max_uses: cinderellaKey.max_uses
            },
            warning: '⚠️  This key will be displayed only once. Store it securely!'
        };
    }

    /**
     * Validate Cinderella Key with all restrictions
     */
    async validate(keySecret, context = {}) {
        // Parse key
        const [keyId] = keySecret.split('.');
        if (!keyId || !keyId.startsWith('ak_temp_')) {
            return { valid: false, reason: 'Invalid key format' };
        }

        // Load key from database
        const result = await this.db.query(`
            SELECT * FROM cinderella_api_keys WHERE key_id = $1 AND is_active = true
        `, [keyId]);

        if (result.rows.length === 0) {
            return { valid: false, reason: 'Key not found or inactive' };
        }

        const key = result.rows[0];

        // Verify hash
        const bcrypt = require('bcryptjs');
        const isValidHash = await bcrypt.compare(keySecret, key.key_secret_hash);
        if (!isValidHash) {
            return { valid: false, reason: 'Invalid key secret' };
        }

        // Check expiration
        if (key.expires_at && new Date() > new Date(key.expires_at)) {
            await this.deactivateKey(keyId, 'expired');
            return { valid: false, reason: 'Key expired', expired_at: key.expires_at };
        }

        // Check time restrictions
        if (key.valid_hours) {
            const isValidTime = this.isWithinValidHours(key.valid_hours, key.timezone);
            if (!isValidTime) {
                return { valid: false, reason: `Key only valid during: ${key.valid_hours} ${key.timezone}` };
            }
        }

        // Check day restrictions
        if (key.valid_days && key.valid_days.length > 0) {
            const today = new Date().toLocaleDateString('en-US', { weekday: 'lowercase', timeZone: key.timezone });
            if (!key.valid_days.includes(today)) {
                return { valid: false, reason: `Key only valid on: ${key.valid_days.join(', ')}` };
            }
        }

        // Check geographic restrictions
        if (key.allowed_countries && context.country) {
            if (!key.allowed_countries.includes(context.country)) {
                return { valid: false, reason: `Key not allowed in country: ${context.country}` };
            }
        }

        // Check IP restrictions
        if (key.allowed_ips && context.ip_address) {
            if (!key.allowed_ips.includes(context.ip_address)) {
                return { valid: false, reason: `IP address not whitelisted: ${context.ip_address}` };
            }
        }

        // Check CIDR restrictions
        if (key.allowed_cidr && context.ip_address) {
            const isInCIDR = this.checkCIDR(context.ip_address, key.allowed_cidr);
            if (!isInCIDR) {
                return { valid: false, reason: `IP not in allowed CIDR range` };
            }
        }

        // Check max uses
        if (key.max_uses && key.uses_count >= key.max_uses) {
            await this.deactivateKey(keyId, 'max_uses_reached');
            return { valid: false, reason: `Max uses reached (${key.max_uses})` };
        }

        // Check hourly rate limit
        if (key.max_uses_per_hour) {
            const hourlyUses = await this.getHourlyUses(keyId);
            if (hourlyUses >= key.max_uses_per_hour) {
                return { valid: false, reason: `Hourly limit reached (${key.max_uses_per_hour}/hour)` };
            }
        }

        // Check daily rate limit
        if (key.max_uses_per_day) {
            const dailyUses = await this.getDailyUses(keyId);
            if (dailyUses >= key.max_uses_per_day) {
                return { valid: false, reason: `Daily limit reached (${key.max_uses_per_day}/day)` };
            }
        }

        // Check endpoint restrictions
        if (key.allowed_endpoints && context.endpoint) {
            const isAllowed = key.allowed_endpoints.some(pattern =>
                this.matchPattern(context.endpoint, pattern)
            );
            if (!isAllowed) {
                return { valid: false, reason: `Endpoint not allowed: ${context.endpoint}` };
            }
        }

        // Check method restrictions
        if (key.allowed_methods && context.method) {
            if (!key.allowed_methods.includes(context.method.toUpperCase())) {
                return { valid: false, reason: `HTTP method not allowed: ${context.method}` };
            }
        }

        // Check host restrictions
        if (key.allowed_hosts && context.host_id) {
            const isAllowed = key.allowed_hosts.some(pattern =>
                this.matchPattern(context.host_id, pattern)
            );
            if (!isAllowed) {
                return { valid: false, reason: `Host not allowed: ${context.host_id}` };
            }
        }

        // Record usage
        await this.recordUsage(keyId, context);

        return {
            valid: true,
            key_id: keyId,
            user_id: key.user_id,
            remaining_uses: key.max_uses ? (key.max_uses - key.uses_count - 1) : null,
            expires_at: key.expires_at
        };
    }

    /**
     * Check if current time is within valid hours
     */
    isWithinValidHours(validHours, timezone) {
        // Parse "09:00-17:00" format
        const [startTime, endTime] = validHours.split('-');
        const now = new Date().toLocaleString('en-US', { timeZone: timezone });
        const currentTime = new Date(now).toLocaleTimeString('en-US', { hour12: false, timeZone: timezone });

        return currentTime >= startTime && currentTime <= endTime;
    }

    /**
     * Check if IP is in CIDR range
     */
    checkCIDR(ip, cidrRanges) {
        // Simplified CIDR check (would use ip-range library in production)
        return cidrRanges.some(range => {
            if (range.includes('/')) {
                // Basic CIDR matching
                const [network] = range.split('/');
                return ip.startsWith(network.split('.').slice(0, 3).join('.'));
            }
            return ip === range;
        });
    }

    /**
     * Match endpoint/host pattern (supports wildcards)
     */
    matchPattern(value, pattern) {
        if (pattern === '*') return true;
        if (pattern.includes('*')) {
            const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
            return regex.test(value);
        }
        return value === pattern;
    }

    /**
     * Parse duration string (e.g., "2h", "30m", "7d")
     */
    parseDuration(duration) {
        const match = duration.match(/^(\d+)([mhd])$/);
        if (!match) throw new Error('Invalid duration format');

        const [, amount, unit] = match;
        const multipliers = { m: 60000, h: 3600000, d: 86400000 };
        return parseInt(amount) * multipliers[unit];
    }

    /**
     * Hash API key secret
     */
    async hashKey(keySecret) {
        const bcrypt = require('bcryptjs');
        return bcrypt.hash(keySecret, 10);
    }

    /**
     * Record key usage
     */
    async recordUsage(keyId, context) {
        await this.db.query(`
            UPDATE cinderella_api_keys
            SET uses_count = uses_count + 1,
                last_used_at = CURRENT_TIMESTAMP
            WHERE key_id = $1
        `, [keyId]);

        // Log usage for rate limiting
        await this.db.query(`
            INSERT INTO cinderella_key_usage (
                key_id, timestamp, ip_address, endpoint, method, host_id
            ) VALUES ($1, CURRENT_TIMESTAMP, $2, $3, $4, $5)
        `, [keyId, context.ip_address, context.endpoint, context.method, context.host_id]);
    }

    /**
     * Get hourly usage count
     */
    async getHourlyUses(keyId) {
        const result = await this.db.query(`
            SELECT COUNT(*) FROM cinderella_key_usage
            WHERE key_id = $1 AND timestamp > NOW() - INTERVAL '1 hour'
        `, [keyId]);
        return parseInt(result.rows[0].count);
    }

    /**
     * Get daily usage count
     */
    async getDailyUses(keyId) {
        const result = await this.db.query(`
            SELECT COUNT(*) FROM cinderella_key_usage
            WHERE key_id = $1 AND timestamp > NOW() - INTERVAL '1 day'
        `, [keyId]);
        return parseInt(result.rows[0].count);
    }

    /**
     * Deactivate key
     */
    async deactivateKey(keyId, reason) {
        await this.db.query(`
            UPDATE cinderella_api_keys
            SET is_active = false,
                deactivated_at = CURRENT_TIMESTAMP,
                deactivation_reason = $2
            WHERE key_id = $1
        `, [keyId, reason]);

        console.log(`🕐 Cinderella Key deactivated: ${keyId} (${reason})`);
    }

    /**
     * List user's Cinderella keys
     */
    async listKeys(userId) {
        const result = await this.db.query(`
            SELECT
                key_id, name, expires_at, valid_hours, valid_days,
                max_uses, uses_count, created_at, last_used_at, is_active
            FROM cinderella_api_keys
            WHERE user_id = $1
            ORDER BY created_at DESC
        `, [userId]);

        return result.rows.map(row => ({
            ...row,
            remaining_uses: row.max_uses ? (row.max_uses - row.uses_count) : null,
            status: this.getKeyStatus(row)
        }));
    }

    /**
     * Get key status
     */
    getKeyStatus(key) {
        if (!key.is_active) return 'inactive';
        if (key.expires_at && new Date() > new Date(key.expires_at)) return 'expired';
        if (key.max_uses && key.uses_count >= key.max_uses) return 'depleted';
        return 'active';
    }
}

module.exports = CinderellaKeyManager;
