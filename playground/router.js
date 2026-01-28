/**
 * Express Router for API Playground
 * Provides endpoints for testing APIs, managing API keys, and exploring endpoints
 */

const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const CodeSnippetGenerator = require('./codeGenerator');

// Use native crypto.randomUUID() instead of uuid package
const uuidv4 = () => crypto.randomUUID();

function createPlaygroundRouter(config) {
  const {
    db,
    redis,
    keycloakURL,
    keycloakRealm,
    keycloakClientID,
    apiSite,
    baseURL
  } = config;

  const AuthManager = require('./auth');
  const PlaygroundRateLimiter = require('./rateLimiter');

  // Initialize services
  const authManager = new AuthManager(keycloakURL, keycloakRealm, keycloakClientID, apiSite, db);
  const rateLimiter = new PlaygroundRateLimiter(redis, apiSite, db);
  const codeGenerator = new CodeSnippetGenerator(baseURL, apiSite);

  const router = express.Router();

  // Apply auth middleware to all routes
  router.use(authManager.authMiddleware());

  // =========================================================================
  // Playground Execution Endpoint
  // =========================================================================

  router.post('/execute', rateLimiter.rateLimitMiddleware(), async (req, res) => {
    const requestId = uuidv4();
    const startTime = Date.now();
    const userId = req.userId || null;
    const ipAddress = req.ip;

    try {
      const {
        endpoint,
        method = 'GET',
        headers = {},
        query_params = {},
        body = null
      } = req.body;

      if (!endpoint) {
        return res.status(400).json({
          success: false,
          error: 'Missing required field: endpoint'
        });
      }

      // Build full URL
      const url = `${baseURL}${endpoint}`;

      // Make the API request
      let response;
      try {
        response = await axios({
          method: method.toLowerCase(),
          url: url,
          headers: headers || {},
          params: query_params || {},
          data: body,
          timeout: 30000,
          validateStatus: () => true // Accept all status codes
        });
      } catch (error) {
        if (error.code === 'ECONNABORTED') {
          // Timeout
          const responseTimeMs = Date.now() - startTime;
          await rateLimiter.recordUsage(
            userId, ipAddress, endpoint, method, 504,
            responseTimeMs, false, 'Request timeout'
          );

          return res.status(504).json({
            success: false,
            status_code: 504,
            error_message: 'Request timeout after 30 seconds',
            response_time_ms: responseTimeMs,
            request_id: requestId
          });
        }
        throw error;
      }

      // Calculate response time
      const responseTimeMs = Date.now() - startTime;

      // Generate code snippets
      const codeSnippets = codeGenerator.generateAll(
        endpoint,
        method,
        headers,
        query_params,
        body
      );

      // Record usage
      await rateLimiter.recordUsage(
        userId, ipAddress, endpoint, method,
        response.status, responseTimeMs, response.status < 400
      );

      // Get rate limit info from headers
      const currentUsed = parseInt(res.getHeader('X-RateLimit-Limit')) -
                         parseInt(res.getHeader('X-RateLimit-Remaining'));
      const limit = parseInt(res.getHeader('X-RateLimit-Limit'));

      return res.status(200).json({
        success: response.status < 400,
        status_code: response.status,
        response_data: response.data,
        response_time_ms: responseTimeMs,
        request_id: requestId,
        code_snippets: codeSnippets,
        usage: {
          daily_used: currentUsed,
          daily_limit: limit,
          remaining: Math.max(0, limit - currentUsed)
        }
      });

    } catch (error) {
      console.error('Error executing playground request:', error);
      const responseTimeMs = Date.now() - startTime;

      await rateLimiter.recordUsage(
        userId, ipAddress, req.body.endpoint || '/unknown',
        req.body.method || 'GET', 500, responseTimeMs,
        false, error.message
      );

      return res.status(500).json({
        success: false,
        status_code: 500,
        error_message: error.message,
        response_time_ms: responseTimeMs,
        request_id: requestId
      });
    }
  });

  // =========================================================================
  // API Key Management Endpoints
  // =========================================================================

  router.post('/api-keys', async (req, res) => {
    if (!req.isAuthenticated) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required to create API keys'
      });
    }

    try {
      const { name, description, expires_in_days, ip_whitelist, allowed_endpoints } = req.body;

      if (!name) {
        return res.status(400).json({ error: 'Missing required field: name' });
      }

      const { keyId, keySecret } = await authManager.createAPIKey(
        req.userId,
        name,
        { description, expiresInDays: expires_in_days, ipWhitelist: ip_whitelist, allowedEndpoints: allowed_endpoints }
      );

      // Fetch created key details
      const client = await db.connect();
      try {
        const result = await client.query(`
          SELECT key_id, name, description, api_site, created_at, expires_at,
                 last_used_at, is_locked, is_active
          FROM playground_api_keys
          WHERE key_id = $1
        `, [keyId]);

        if (result.rows.length === 0) {
          return res.status(404).json({ error: 'API key not found' });
        }

        const row = result.rows[0];

        return res.status(201).json({
          key_id: row.key_id,
          key_secret: keySecret, // Only returned on creation!
          name: row.name,
          description: row.description,
          api_site: row.api_site,
          created_at: row.created_at,
          expires_at: row.expires_at,
          last_used_at: row.last_used_at,
          is_locked: row.is_locked,
          is_active: row.is_active,
          warning: 'Store this API key securely. It will not be shown again.'
        });
      } finally {
        client.release();
      }
    } catch (error) {
      console.error('Error creating API key:', error);
      return res.status(500).json({ error: 'Failed to create API key', message: error.message });
    }
  });

  router.get('/api-keys', async (req, res) => {
    if (!req.isAuthenticated) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    try {
      const client = await db.connect();
      try {
        const result = await client.query(`
          SELECT key_id, name, description, api_site, created_at, expires_at,
                 last_used_at, is_locked, is_active
          FROM playground_api_keys
          WHERE user_id = $1 AND api_site = $2
          ORDER BY created_at DESC
        `, [req.userId, apiSite]);

        return res.json({
          api_keys: result.rows.map(row => ({
            key_id: row.key_id,
            name: row.name,
            description: row.description,
            api_site: row.api_site,
            created_at: row.created_at,
            expires_at: row.expires_at,
            last_used_at: row.last_used_at,
            is_locked: row.is_locked,
            is_active: row.is_active
          }))
        });
      } finally {
        client.release();
      }
    } catch (error) {
      console.error('Error fetching API keys:', error);
      return res.status(500).json({ error: 'Failed to fetch API keys', message: error.message });
    }
  });

  router.delete('/api-keys/:keyId', async (req, res) => {
    if (!req.isAuthenticated) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    try {
      const { keyId } = req.params;
      const client = await db.connect();

      try {
        // Verify ownership
        const checkResult = await client.query(`
          SELECT user_id FROM playground_api_keys
          WHERE key_id = $1 AND api_site = $2
        `, [keyId, apiSite]);

        if (checkResult.rows.length === 0) {
          return res.status(404).json({ error: 'API key not found' });
        }

        if (checkResult.rows[0].user_id !== req.userId) {
          return res.status(403).json({ error: 'Forbidden', message: 'You do not own this API key' });
        }

        // Soft delete (set is_active = false)
        await client.query(`
          UPDATE playground_api_keys
          SET is_active = false
          WHERE key_id = $1
        `, [keyId]);

        return res.json({ success: true, message: 'API key deleted successfully' });
      } finally {
        client.release();
      }
    } catch (error) {
      console.error('Error deleting API key:', error);
      return res.status(500).json({ error: 'Failed to delete API key', message: error.message });
    }
  });

  router.patch('/api-keys/:keyId/lock', async (req, res) => {
    if (!req.isAuthenticated) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    try {
      const { keyId } = req.params;
      const { locked } = req.body;

      if (typeof locked !== 'boolean') {
        return res.status(400).json({ error: 'Missing or invalid field: locked (must be boolean)' });
      }

      const client = await db.connect();
      try {
        // Verify ownership
        const checkResult = await client.query(`
          SELECT user_id FROM playground_api_keys
          WHERE key_id = $1 AND api_site = $2
        `, [keyId, apiSite]);

        if (checkResult.rows.length === 0) {
          return res.status(404).json({ error: 'API key not found' });
        }

        if (checkResult.rows[0].user_id !== req.userId) {
          return res.status(403).json({ error: 'Forbidden', message: 'You do not own this API key' });
        }

        // Update lock status
        await client.query(`
          UPDATE playground_api_keys
          SET is_locked = $1
          WHERE key_id = $2
        `, [locked, keyId]);

        return res.json({
          success: true,
          message: `API key ${locked ? 'locked' : 'unlocked'} successfully`,
          key_id: keyId,
          is_locked: locked
        });
      } finally {
        client.release();
      }
    } catch (error) {
      console.error('Error updating API key lock status:', error);
      return res.status(500).json({ error: 'Failed to update API key', message: error.message });
    }
  });

  // =========================================================================
  // Credits & Usage Endpoints
  // =========================================================================

  router.get('/credits', async (req, res) => {
    if (!req.isAuthenticated) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    try {
      const client = await db.connect();
      try {
        const result = await client.query(`
          SELECT tier, daily_limit, daily_used, monthly_limit, monthly_used,
                 last_daily_reset, last_monthly_reset
          FROM playground_credits
          WHERE user_id = $1 AND api_site = $2
        `, [req.userId, apiSite]);

        if (result.rows.length === 0) {
          // Create default free tier record
          await client.query(`
            INSERT INTO playground_credits (user_id, api_site, tier, daily_limit)
            VALUES ($1, $2, 'free', 100)
          `, [req.userId, apiSite]);

          return res.json({
            tier: 'free',
            daily_limit: 100,
            daily_used: 0,
            daily_remaining: 100,
            monthly_limit: 3000,
            monthly_used: 0,
            monthly_remaining: 3000
          });
        }

        const row = result.rows[0];
        return res.json({
          tier: row.tier,
          daily_limit: row.daily_limit,
          daily_used: row.daily_used,
          daily_remaining: Math.max(0, row.daily_limit - row.daily_used),
          monthly_limit: row.monthly_limit,
          monthly_used: row.monthly_used || 0,
          monthly_remaining: row.monthly_limit ? Math.max(0, row.monthly_limit - row.monthly_used) : null,
          last_daily_reset: row.last_daily_reset,
          last_monthly_reset: row.last_monthly_reset
        });
      } finally {
        client.release();
      }
    } catch (error) {
      console.error('Error fetching credits:', error);
      return res.status(500).json({ error: 'Failed to fetch credits', message: error.message });
    }
  });

  router.get('/rate-limit', async (req, res) => {
    const userId = req.userId || null;
    const ipAddress = req.ip;

    try {
      const { allowed, currentCount, limit, resetTime } = await rateLimiter.checkRateLimit(userId, ipAddress);

      return res.json({
        allowed,
        current: currentCount,
        limit,
        remaining: Math.max(0, limit - currentCount),
        reset: resetTime.toISOString(),
        user_type: userId ? 'authenticated' : 'anonymous'
      });
    } catch (error) {
      console.error('Error fetching rate limit:', error);
      return res.status(500).json({ error: 'Failed to fetch rate limit', message: error.message });
    }
  });

  // =========================================================================
  // Saved Requests (Premium Feature)
  // =========================================================================

  router.post('/saved-requests', async (req, res) => {
    if (!req.isAuthenticated) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    try {
      const {
        name,
        description,
        endpoint,
        method = 'GET',
        headers,
        query_params,
        body,
        folder,
        tags,
        is_public = false
      } = req.body;

      if (!name || !endpoint) {
        return res.status(400).json({ error: 'Missing required fields: name, endpoint' });
      }

      const client = await db.connect();
      try {
        const result = await client.query(`
          INSERT INTO saved_requests (
            user_id, api_site, name, description, endpoint, http_method,
            headers, query_params, body, folder, tags, is_public
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
          RETURNING id, created_at
        `, [
          req.userId, apiSite, name, description, endpoint, method,
          JSON.stringify(headers), JSON.stringify(query_params), JSON.stringify(body),
          folder, tags, is_public
        ]);

        return res.status(201).json({
          success: true,
          id: result.rows[0].id,
          message: 'Request saved successfully',
          created_at: result.rows[0].created_at
        });
      } finally {
        client.release();
      }
    } catch (error) {
      console.error('Error saving request:', error);
      return res.status(500).json({ error: 'Failed to save request', message: error.message });
    }
  });

  router.get('/saved-requests', async (req, res) => {
    if (!req.isAuthenticated) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    }

    try {
      const { folder, tag } = req.query;
      const client = await db.connect();

      try {
        let query = `
          SELECT id, name, description, endpoint, http_method, headers,
                 query_params, body, folder, tags, is_public, created_at,
                 updated_at, last_executed_at
          FROM saved_requests
          WHERE user_id = $1 AND api_site = $2
        `;
        const params = [req.userId, apiSite];

        if (folder) {
          query += ` AND folder = $3`;
          params.push(folder);
        }

        if (tag) {
          query += ` AND $${params.length + 1} = ANY(tags)`;
          params.push(tag);
        }

        query += ` ORDER BY updated_at DESC`;

        const result = await client.query(query, params);

        return res.json({
          saved_requests: result.rows.map(row => ({
            id: row.id,
            name: row.name,
            description: row.description,
            endpoint: row.endpoint,
            method: row.http_method,
            headers: row.headers,
            query_params: row.query_params,
            body: row.body,
            folder: row.folder,
            tags: row.tags,
            is_public: row.is_public,
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_executed_at: row.last_executed_at
          }))
        });
      } finally {
        client.release();
      }
    } catch (error) {
      console.error('Error fetching saved requests:', error);
      return res.status(500).json({ error: 'Failed to fetch saved requests', message: error.message });
    }
  });

  return router;
}

module.exports = createPlaygroundRouter;
