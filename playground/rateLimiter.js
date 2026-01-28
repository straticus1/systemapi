/**
 * Rate limiter for API Playground (Express.js)
 * Uses Redis for fast checks and PostgreSQL for persistent tracking
 */

class PlaygroundRateLimiter {
  constructor(redisClient, apiSite, dbPool) {
    this.redis = redisClient;
    this.apiSite = apiSite;
    this.db = dbPool;

    // Default limits
    this.ANONYMOUS_DAILY_LIMIT = 50;
    this.FREE_DAILY_LIMIT = 100;
  }

  /**
   * Generate Redis key for rate limiting
   */
  getRedisKey(identifier, date) {
    return `playground:ratelimit:${this.apiSite}:${identifier}:${date}`;
  }

  /**
   * Get today's date in ISO format
   */
  getTodayDate() {
    return new Date().toISOString().split('T')[0];
  }

  /**
   * Get reset time (midnight UTC tomorrow)
   */
  getResetTime() {
    const tomorrow = new Date();
    tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
    tomorrow.setUTCHours(0, 0, 0, 0);
    return tomorrow;
  }

  /**
   * Check if request is within rate limits
   * @param {string|null} userId - User ID (if authenticated)
   * @param {string|null} ipAddress - IP address (for anonymous users)
   * @returns {Promise<Object>} { allowed, currentCount, limit, resetTime }
   */
  async checkRateLimit(userId = null, ipAddress = null) {
    const today = this.getTodayDate();
    const resetTime = this.getResetTime();

    if (userId) {
      return this.checkUserRateLimit(userId, today, resetTime);
    } else if (ipAddress) {
      return this.checkAnonymousRateLimit(ipAddress, today, resetTime);
    } else {
      return { allowed: false, currentCount: 0, limit: 0, resetTime };
    }
  }

  /**
   * Check rate limit for authenticated user
   */
  async checkUserRateLimit(userId, date, resetTime) {
    const redisKey = this.getRedisKey(userId, date);

    try {
      // Try Redis first (fast path)
      const count = await this.redis.get(redisKey);
      if (count !== null) {
        const currentCount = parseInt(count);
        const limit = await this.getUserDailyLimit(userId);

        if (currentCount >= limit) {
          return { allowed: false, currentCount, limit, resetTime };
        }

        // Increment in Redis
        await this.redis.incr(redisKey);
        await this.redis.expireAt(redisKey, Math.floor(resetTime.getTime() / 1000));

        return { allowed: true, currentCount: currentCount + 1, limit, resetTime };
      } else {
        // Initialize Redis counter from PostgreSQL
        const pgResult = await this.checkUserRateLimitPG(userId, resetTime);

        // Set Redis counter to match PostgreSQL
        await this.redis.set(redisKey, pgResult.currentCount);
        await this.redis.expireAt(redisKey, Math.floor(resetTime.getTime() / 1000));

        return pgResult;
      }
    } catch (error) {
      console.warn('Redis error in rate limiting:', error.message, '- falling back to PostgreSQL');
      // Fallback to PostgreSQL
      return this.checkUserRateLimitPG(userId, resetTime);
    }
  }

  /**
   * Check rate limit for anonymous user by IP
   */
  async checkAnonymousRateLimit(ipAddress, date, resetTime) {
    const redisKey = this.getRedisKey(`anon:${ipAddress}`, date);

    try {
      // Try Redis first
      const count = await this.redis.get(redisKey);
      if (count !== null) {
        const currentCount = parseInt(count);

        if (currentCount >= this.ANONYMOUS_DAILY_LIMIT) {
          return {
            allowed: false,
            currentCount,
            limit: this.ANONYMOUS_DAILY_LIMIT,
            resetTime
          };
        }

        await this.redis.incr(redisKey);
        await this.redis.expireAt(redisKey, Math.floor(resetTime.getTime() / 1000));

        return {
          allowed: true,
          currentCount: currentCount + 1,
          limit: this.ANONYMOUS_DAILY_LIMIT,
          resetTime
        };
      } else {
        // Initialize from PostgreSQL
        const pgResult = await this.checkAnonymousRateLimitPG(ipAddress, resetTime);

        await this.redis.set(redisKey, pgResult.currentCount);
        await this.redis.expireAt(redisKey, Math.floor(resetTime.getTime() / 1000));

        return pgResult;
      }
    } catch (error) {
      console.warn('Redis error in rate limiting:', error.message, '- falling back to PostgreSQL');
      return this.checkAnonymousRateLimitPG(ipAddress, resetTime);
    }
  }

  /**
   * Get daily limit for user from database
   */
  async getUserDailyLimit(userId) {
    const client = await this.db.connect();
    try {
      const result = await client.query(`
        SELECT daily_limit FROM playground_credits
        WHERE user_id = $1 AND api_site = $2
      `, [userId, this.apiSite]);

      if (result.rows.length > 0) {
        return result.rows[0].daily_limit;
      }

      // Default to free tier if not found
      return this.FREE_DAILY_LIMIT;
    } finally {
      client.release();
    }
  }

  /**
   * Check and increment rate limit using PostgreSQL
   */
  async checkUserRateLimitPG(userId, resetTime) {
    const client = await this.db.connect();
    try {
      // Get or create credit record
      await client.query(`
        INSERT INTO playground_credits (user_id, api_site, tier, daily_limit, daily_used)
        VALUES ($1, $2, 'free', $3, 0)
        ON CONFLICT (user_id, api_site) DO NOTHING
      `, [userId, this.apiSite, this.FREE_DAILY_LIMIT]);

      // Check and reset if needed
      await client.query(`
        UPDATE playground_credits
        SET daily_used = 0, last_daily_reset = CURRENT_TIMESTAMP
        WHERE user_id = $1 AND api_site = $2
          AND last_daily_reset < CURRENT_TIMESTAMP - INTERVAL '1 day'
      `, [userId, this.apiSite]);

      // Get current usage and limit
      const result = await client.query(`
        SELECT daily_used, daily_limit
        FROM playground_credits
        WHERE user_id = $1 AND api_site = $2
      `, [userId, this.apiSite]);

      if (result.rows.length === 0) {
        return { allowed: false, currentCount: 0, limit: 0, resetTime };
      }

      const { daily_used, daily_limit } = result.rows[0];

      if (daily_used >= daily_limit) {
        return { allowed: false, currentCount: daily_used, limit: daily_limit, resetTime };
      }

      // Increment usage
      await client.query(`
        UPDATE playground_credits
        SET daily_used = daily_used + 1
        WHERE user_id = $1 AND api_site = $2
      `, [userId, this.apiSite]);

      return { allowed: true, currentCount: daily_used + 1, limit: daily_limit, resetTime };
    } finally {
      client.release();
    }
  }

  /**
   * Check and increment rate limit for anonymous users using PostgreSQL
   */
  async checkAnonymousRateLimitPG(ipAddress, resetTime) {
    const client = await this.db.connect();
    try {
      // Get or create anonymous rate limit record
      await client.query(`
        INSERT INTO anonymous_rate_limits (ip_address, api_site, daily_requests)
        VALUES ($1, $2, 0)
        ON CONFLICT (ip_address, api_site) DO NOTHING
      `, [ipAddress, this.apiSite]);

      // Reset if needed
      await client.query(`
        UPDATE anonymous_rate_limits
        SET daily_requests = 0, last_daily_reset = CURRENT_TIMESTAMP
        WHERE ip_address = $1 AND api_site = $2
          AND last_daily_reset < CURRENT_TIMESTAMP - INTERVAL '1 day'
      `, [ipAddress, this.apiSite]);

      // Get current usage
      const result = await client.query(`
        SELECT daily_requests
        FROM anonymous_rate_limits
        WHERE ip_address = $1 AND api_site = $2
      `, [ipAddress, this.apiSite]);

      if (result.rows.length === 0) {
        return { allowed: false, currentCount: 0, limit: this.ANONYMOUS_DAILY_LIMIT, resetTime };
      }

      const dailyRequests = result.rows[0].daily_requests;

      if (dailyRequests >= this.ANONYMOUS_DAILY_LIMIT) {
        return { allowed: false, currentCount: dailyRequests, limit: this.ANONYMOUS_DAILY_LIMIT, resetTime };
      }

      // Increment usage
      await client.query(`
        UPDATE anonymous_rate_limits
        SET daily_requests = daily_requests + 1, last_seen = CURRENT_TIMESTAMP
        WHERE ip_address = $1 AND api_site = $2
      `, [ipAddress, this.apiSite]);

      return { allowed: true, currentCount: dailyRequests + 1, limit: this.ANONYMOUS_DAILY_LIMIT, resetTime };
    } finally {
      client.release();
    }
  }

  /**
   * Record usage in database
   */
  async recordUsage(userId, ipAddress, endpoint, method, statusCode, responseTimeMs, success = true, errorMessage = null) {
    const client = await this.db.connect();
    try {
      await client.query(`
        INSERT INTO playground_usage (
          user_id, api_site, endpoint, http_method, status_code,
          response_time_ms, ip_address, success, error_message
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      `, [
        userId, this.apiSite, endpoint, method, statusCode,
        responseTimeMs, ipAddress, success, errorMessage
      ]);
    } catch (error) {
      console.error('Failed to record usage:', error);
      // Don't throw - usage recording failure shouldn't break the request
    } finally {
      client.release();
    }
  }

  /**
   * Express middleware for rate limiting
   */
  rateLimitMiddleware() {
    return async (req, res, next) => {
      const userId = req.userId || null;
      const ipAddress = req.ip;

      const { allowed, currentCount, limit, resetTime } = await this.checkRateLimit(userId, ipAddress);

      // Set rate limit headers
      res.setHeader('X-RateLimit-Limit', limit);
      res.setHeader('X-RateLimit-Remaining', Math.max(0, limit - currentCount));
      res.setHeader('X-RateLimit-Reset', resetTime.toISOString());

      if (!allowed) {
        return res.status(429).json({
          error: 'Rate Limit Exceeded',
          message: `You have exceeded your daily limit of ${limit} requests. Limit resets at ${resetTime.toISOString()}.`,
          current: currentCount,
          limit: limit,
          reset: resetTime.toISOString()
        });
      }

      next();
    };
  }
}

module.exports = PlaygroundRateLimiter;
