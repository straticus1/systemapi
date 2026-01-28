/**
 * Authentication for API Playground (Express.js)
 * Supports both Keycloak/JWT tokens and API keys
 */

const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

class AuthManager {
  constructor(keycloakURL, keycloakRealm, keycloakClientID, apiSite, dbPool) {
    this.keycloakURL = keycloakURL;
    this.keycloakRealm = keycloakRealm;
    this.keycloakClientID = keycloakClientID;
    this.apiSite = apiSite;
    this.db = dbPool;
    this.jwksURI = `${keycloakURL}/realms/${keycloakRealm}/protocol/openid-connect/certs`;
  }

  /**
   * Generate a new API key pair
   * @returns {Object} { keyId, keySecret }
   */
  generateAPIKey() {
    // Generate random 32-character secret (base64url safe)
    const secret = crypto.randomBytes(32).toString('base64url').substring(0, 32);

    // Create key_id with format: ak_live_{first_16_chars}.{full_secret}
    const keyId = `ak_live_${secret.substring(0, 16)}`;

    return { keyId, keySecret: `${keyId}.${secret}` };
  }

  /**
   * Hash API key secret using bcrypt
   * @param {string} keySecret - The API key secret to hash
   * @returns {Promise<string>} Hashed key
   */
  async hashAPIKey(keySecret) {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(keySecret, salt);
  }

  /**
   * Verify API key secret against stored hash
   * @param {string} keySecret - The key secret to verify
   * @param {string} keyHash - The stored hash
   * @returns {Promise<boolean>}
   */
  async verifyAPIKeyHash(keySecret, keyHash) {
    try {
      return await bcrypt.compare(keySecret, keyHash);
    } catch (error) {
      console.error('Error verifying API key:', error);
      return false;
    }
  }

  /**
   * Create a new API key for a user
   * @returns {Promise<Object>} { keyId, keySecret } - secret is only returned once!
   */
  async createAPIKey(userId, name, options = {}) {
    const {
      description = null,
      expiresInDays = null,
      ipWhitelist = null,
      allowedEndpoints = null
    } = options;

    const { keyId, keySecret } = this.generateAPIKey();
    const keyHash = await this.hashAPIKey(keySecret);

    let expiresAt = null;
    if (expiresInDays) {
      expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + expiresInDays);
    }

    const client = await this.db.connect();
    try {
      await client.query(`
        INSERT INTO playground_api_keys (
          key_id, key_hash, user_id, name, api_site,
          description, expires_at, ip_whitelist, allowed_endpoints
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      `, [
        keyId, keyHash, userId, name, this.apiSite,
        description, expiresAt, ipWhitelist, allowedEndpoints
      ]);

      return { keyId, keySecret };
    } catch (error) {
      console.error('Failed to create API key:', error);
      throw new Error('Failed to create API key');
    } finally {
      client.release();
    }
  }

  /**
   * Verify API key and return user_id if valid
   * @returns {Promise<string|null>} user_id or null
   */
  async verifyAPIKey(keyId, keySecret, ipAddress = null, endpoint = null) {
    const client = await this.db.connect();
    try {
      const result = await client.query(`
        SELECT user_id, key_hash, is_locked, is_active, expires_at,
               ip_whitelist, allowed_endpoints
        FROM playground_api_keys
        WHERE key_id = $1 AND api_site = $2
      `, [keyId, this.apiSite]);

      if (result.rows.length === 0) {
        return null;
      }

      const row = result.rows[0];
      const { user_id, key_hash, is_locked, is_active, expires_at, ip_whitelist, allowed_endpoints } = row;

      // Check if key is active
      if (!is_active || is_locked) {
        return null;
      }

      // Check expiration
      if (expires_at && new Date() > new Date(expires_at)) {
        return null;
      }

      // Verify hash
      const isValid = await this.verifyAPIKeyHash(keySecret, key_hash);
      if (!isValid) {
        return null;
      }

      // Check IP whitelist
      if (ip_whitelist && ipAddress) {
        if (!ip_whitelist.includes(ipAddress)) {
          return null;
        }
      }

      // Check endpoint whitelist
      if (allowed_endpoints && endpoint) {
        if (!allowed_endpoints.includes(endpoint)) {
          return null;
        }
      }

      // Update last_used_at
      await client.query(`
        UPDATE playground_api_keys
        SET last_used_at = CURRENT_TIMESTAMP
        WHERE key_id = $1
      `, [keyId]);

      return user_id;
    } finally {
      client.release();
    }
  }

  /**
   * Verify Keycloak JWT token
   * @param {string} token - JWT token
   * @returns {Object|null} Decoded payload or null
   */
  verifyKeycloakToken(token) {
    try {
      // In production, you should fetch JWKS from Keycloak and verify signature
      // For now, we'll decode without verification (NOT SECURE FOR PRODUCTION!)
      const decoded = jwt.decode(token, { complete: true });

      if (!decoded) {
        return null;
      }

      const payload = decoded.payload;

      // Check expiration
      if (payload.exp && Date.now() / 1000 > payload.exp) {
        return null;
      }

      // Check realm and issuer
      const expectedIssuer = `${this.keycloakURL}/realms/${this.keycloakRealm}`;
      if (payload.iss !== expectedIssuer) {
        return null;
      }

      return payload;
    } catch (error) {
      console.warn('JWT verification failed:', error.message);
      return null;
    }
  }

  /**
   * Get user ID from JWT token
   * @param {string} token - JWT token
   * @returns {string|null} user_id or null
   */
  getUserFromToken(token) {
    const payload = this.verifyKeycloakToken(token);
    if (!payload) {
      return null;
    }

    // Keycloak uses 'sub' as user ID
    return payload.sub || payload.user_id || null;
  }

  /**
   * Middleware to extract and verify authentication
   * Sets req.userId if authenticated
   */
  authMiddleware() {
    return async (req, res, next) => {
      let userId = null;

      // Try API key first (X-API-Key header)
      const apiKeyHeader = req.headers['x-api-key'];
      if (apiKeyHeader) {
        // API key format: ak_live_xxxxx.yyyyy
        const [keyId, keySecret] = apiKeyHeader.split('.').length === 2
          ? [apiKeyHeader.split('.')[0], apiKeyHeader]
          : [null, null];

        if (keyId && keySecret) {
          userId = await this.verifyAPIKey(
            keyId,
            keySecret,
            req.ip,
            req.path
          );
        }
      }

      // Try JWT token if no API key
      if (!userId) {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
          const token = authHeader.substring(7);
          userId = this.getUserFromToken(token);
        }
      }

      // Attach user_id to request
      req.userId = userId;
      req.isAuthenticated = !!userId;

      next();
    };
  }

  /**
   * Middleware to require authentication
   */
  requireAuth() {
    return (req, res, next) => {
      if (!req.isAuthenticated) {
        return res.status(401).json({
          error: 'Unauthorized',
          message: 'Authentication required. Provide a valid API key or JWT token.'
        });
      }
      next();
    };
  }
}

module.exports = AuthManager;
