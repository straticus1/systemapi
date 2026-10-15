/**
 * Authentication for API Playground (Express.js)
 * Supports both Authentik/JWT tokens and API keys
 *
 * Threats (JWT path): a token signed by another issuer or for another
 * audience, an expired or not-yet-valid token, a tampered signature,
 * alg=none or an HS* token "signed" with the public key, a header-chosen
 * algorithm outside the allowlist (RS256, ES256, EdDSA), an unknown kid, and
 * a token accepted while discovery or the JWKS is unreachable. Issuer
 * metadata comes from openid-client 6 discovery (AUTHENTIK_ISSUER, else the
 * Keycloak realm URL; the discovered issuer must equal it) and the signature
 * from jose against the issuer's jwks_uri. Every failure returns null (no
 * user). Audience is OIDC_AUDIENCE, else the configured client id; with
 * neither every token is refused. The jwks_uri must be https and on the
 * issuer's origin. Does NOT mint tokens, decide what a user
 * may do, or log tokens (only error codes).
 */

const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const JWT_ALGORITHMS = ['RS256', 'ES256', 'EdDSA'];
const JWT_MAX_LENGTH = 8192;
const DISCOVERY_TIMEOUT_S = 5;
const JWKS_TIMEOUT_MS = 5000;
// After a failed discovery, tokens are refused without a new attempt for
// this long, so a flood of bearer tokens cannot become a flood of fetches.
const DISCOVERY_RETRY_MS = 30000;

class AuthManager {
  /**
   * options.env replaces process.env for the issuer and audience;
   * options.customFetch lets tests serve discovery and the JWKS locally.
   */
  constructor(keycloakURL, keycloakRealm, keycloakClientID, apiSite, dbPool, options = {}) {
    this.keycloakURL = keycloakURL;
    this.keycloakRealm = keycloakRealm;
    this.keycloakClientID = keycloakClientID;
    this.apiSite = apiSite;
    this.db = dbPool;
    this.env = options.env || process.env;
    this.customFetch = typeof options.customFetch === 'function' ? options.customFetch : null;
    this.verifier = null;
    this.verifierPending = null;
    this.discoveryFailedAt = 0;
  }

  issuerURL() {
    return this.env.AUTHENTIK_ISSUER || `${this.keycloakURL}/realms/${this.keycloakRealm}`;
  }

  audience() {
    return this.env.OIDC_AUDIENCE || this.keycloakClientID || null;
  }

  /**
   * Discovery and the remote JWKS, created on first use and kept. A failed
   * discovery is not cached; it is retried after DISCOVERY_RETRY_MS.
   */
  async jwtVerifier() {
    if (this.verifier) return this.verifier;
    if (!this.verifierPending) {
      if (Date.now() - this.discoveryFailedAt < DISCOVERY_RETRY_MS) {
        throw Object.assign(new Error('discovery failed recently'), { code: 'discovery_backoff' });
      }
      this.verifierPending = this.discoverVerifier()
        .then((verifier) => {
          this.verifier = verifier;
          return verifier;
        }, (err) => {
          this.discoveryFailedAt = Date.now();
          throw err;
        })
        .finally(() => {
          this.verifierPending = null;
        });
    }
    return this.verifierPending;
  }

  async discoverVerifier() {
    // Both are ESM-only; loaded lazily as routes/oauth.js does.
    const oidc = await import('openid-client');
    const jose = await import('jose');
    const discoveryOptions = { timeout: DISCOVERY_TIMEOUT_S };
    if (this.customFetch) discoveryOptions[oidc.customFetch] = this.customFetch;
    const config = await oidc.discovery(
      new URL(this.issuerURL()),
      this.keycloakClientID,
      undefined,
      undefined,
      discoveryOptions
    );
    const metadata = config.serverMetadata();
    if (typeof metadata.jwks_uri !== 'string') {
      throw Object.assign(new Error('issuer has no jwks_uri'), { code: 'jwks_uri_missing' });
    }
    const jwksURL = new URL(metadata.jwks_uri);
    if (jwksURL.protocol !== 'https:') {
      throw Object.assign(new Error('jwks_uri is not https'), { code: 'jwks_uri_insecure' });
    }
    if (jwksURL.origin !== new URL(metadata.issuer).origin) {
      throw Object.assign(new Error('jwks_uri is not on the issuer origin'), { code: 'jwks_uri_origin' });
    }
    const jwksOptions = { timeoutDuration: JWKS_TIMEOUT_MS };
    if (this.customFetch) jwksOptions[jose.customFetch] = this.customFetch;
    return {
      jose,
      issuer: metadata.issuer,
      keySet: jose.createRemoteJWKSet(jwksURL, jwksOptions)
    };
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
    const client = await this.db.connect();
    try {
      return await this.insertAPIKey(client, userId, name, options);
    } catch (error) {
      console.error('Failed to create API key:', error);
      throw new Error('Failed to create API key');
    } finally {
      client.release();
    }
  }

  /**
   * Generate, hash and insert one API key on the caller's client, so a
   * caller can do it inside its own transaction (scripts/bootstrap-admin.js).
   * Only the bcrypt hash is stored.
   * @returns {Promise<Object>} { keyId, keySecret }
   */
  async insertAPIKey(client, userId, name, options = {}) {
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
   * Verify a JWT against the discovered issuer and its JWKS. See Threats at
   * the top of this file.
   * @param {string} token - JWT token
   * @returns {Promise<Object|null>} Verified payload or null
   */
  async verifyJWTToken(token) {
    if (typeof token !== 'string' || token.length === 0 || token.length > JWT_MAX_LENGTH) return null;
    const audience = this.audience();
    if (!audience) {
      console.warn('JWT rejected: no audience configured');
      return null;
    }
    let verifier;
    try {
      verifier = await this.jwtVerifier();
    } catch (error) {
      console.warn('JWT rejected: OIDC discovery unavailable:', error.code || error.name);
      return null;
    }
    try {
      const { payload } = await verifier.jose.jwtVerify(token, verifier.keySet, {
        issuer: verifier.issuer,
        audience,
        algorithms: JWT_ALGORITHMS,
        clockTolerance: 30,
        requiredClaims: ['exp']
      });
      return payload;
    } catch (error) {
      console.warn('JWT verification failed:', error.code || error.name);
      return null;
    }
  }

  /**
   * Get user ID from JWT token
   * @param {string} token - JWT token
   * @returns {Promise<string|null>} user_id or null
   */
  async getUserFromToken(token) {
    const payload = await this.verifyJWTToken(token);
    if (!payload) {
      return null;
    }

    // Authentik/Keycloak uses 'sub' as user ID
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
          userId = await this.getUserFromToken(token);
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
