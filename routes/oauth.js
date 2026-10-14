/**
 * OAuth 2.0 / OpenID Connect Routes for After Dark Systems (Authentik)
 * Provides login, callback, logout, and user info endpoints
 */
// Threats: login CSRF and code injection (state, nonce and PKCE S256 are
// checked by openid-client), ID tokens signed with another algorithm (only
// RS256 is accepted), off-site redirects after login (safeReturnPath, checked
// at login and again at the callback), session fixation (the session id is
// regenerated at login and pre-login fields are dropped), cross-site logout
// and refresh (POST with the session CSRF token), and leaking error details,
// emails or subjects to the browser or the log (generic codes plus a request
// id; the log gets only the error name and code). The session stores the
// Authentik sub; who that sub may act as is decided by cp_sso_bindings, not
// here. Does NOT bind subs to members. allowInsecureRequests exists for tests
// against a local mock issuer and is refused in production.
'use strict';

const express = require('express');
const { safeReturnPath, sessionCsrf, csrfValid } = require('../controlplane/oauth');
const { randomToken } = require('../controlplane/token');

function failure(res, logger, what, err, status = 500) {
  const requestId = randomToken(16);
  logger.error(`[oauth] ${what} failed request_id=${requestId} name=${(err && err.name) || 'Error'} code=${(err && err.code) || 'none'}`);
  res.status(status).json({ error: what + '_failed', request_id: requestId });
}

// Unix seconds, as the v5 tokenSet.expires_at was.
function tokenExpiry(tokenSet) {
  const ttl = typeof tokenSet.expiresIn === 'function' ? tokenSet.expiresIn() : undefined;
  return typeof ttl === 'number' ? Math.floor(Date.now() / 1000) + ttl : undefined;
}

function createOAuthRouter(options = {}) {
  const env = options.env || process.env;
  const logger = options.logger || console;
  const AUTHENTIK_URL = env.AUTHENTIK_URL || 'https://auth.afterdarksys.com';
  const AUTHENTIK_ISSUER = env.AUTHENTIK_ISSUER || 'https://auth.afterdarksys.com/application/o/systemapi-io-client/';
  const CLIENT_ID = env.AUTHENTIK_CLIENT_ID || 'systemapi-io-client';
  const CLIENT_SECRET = env.AUTHENTIK_CLIENT_SECRET;
  const REDIRECT_URI = env.AUTHENTIK_REDIRECT_URI || 'https://systemapi.io/oauth/callback';
  const SCOPES = env.AUTHENTIK_SCOPES || 'openid profile email groups offline_access';
  const DEV_MODE = env.DEV_MODE === 'true';
  const DEV_REDIRECT_URI = env.DEV_REDIRECT_URI || 'http://localhost:3000/oauth/callback';
  const POST_LOGOUT = DEV_MODE ? 'http://localhost:3000' : 'https://systemapi.io';
  const insecure = options.allowInsecureRequests === true;
  if (insecure && env.NODE_ENV === 'production') throw new Error('allowInsecureRequests is refused in production');

  const router = express.Router();
  // openid-client 6 is ESM-only; loaded lazily on the first request.
  let oidc;
  let authentikClient = null;

  const redirectUri = () => (DEV_MODE ? DEV_REDIRECT_URI : REDIRECT_URI);

  async function client() {
    if (authentikClient) return authentikClient;
    if (!oidc) oidc = await import('openid-client');
    if (!CLIENT_SECRET) {
      const err = new Error('client secret missing');
      err.code = 'client_secret_missing';
      throw err;
    }
    const discoveryOptions = insecure ? { execute: [oidc.allowInsecureRequests] } : undefined;
    authentikClient = await oidc.discovery(
      new URL(AUTHENTIK_ISSUER),
      CLIENT_ID,
      { id_token_signed_response_alg: 'RS256' },
      oidc.ClientSecretBasic(CLIENT_SECRET),
      discoveryOptions
    );
    return authentikClient;
  }

  function saveSession(req) {
    return new Promise((resolve, reject) => {
      req.session.save((err) => (err ? reject(err) : resolve()));
    });
  }

  /**
   * GET /oauth/login
   * Initiates OAuth login flow by redirecting to Authentik
   */
  router.get('/login', async (req, res) => {
    try {
      const config = await client();
      const code_verifier = oidc.randomPKCECodeVerifier();
      const code_challenge = await oidc.calculatePKCECodeChallenge(code_verifier);
      const state = oidc.randomState();
      const nonce = oidc.randomNonce();

      req.session.oauth = {
        code_verifier,
        state,
        nonce,
        // Same-origin path only; checked again at the callback.
        return_to: safeReturnPath(req.query.return_to)
      };

      const authorizationUrl = oidc.buildAuthorizationUrl(config, {
        redirect_uri: redirectUri(),
        scope: SCOPES,
        state,
        nonce,
        code_challenge,
        code_challenge_method: 'S256'
      });

      res.redirect(authorizationUrl.href);
    } catch (error) {
      failure(res, logger, 'login', error);
    }
  });

  /**
   * GET /oauth/callback
   * Handles OAuth callback from Authentik
   */
  router.get('/callback', async (req, res) => {
    const pending = req.session.oauth || {};
    // One attempt per login: whatever happens next, the PKCE verifier, state
    // and nonce are gone.
    delete req.session.oauth;
    try {
      const { code_verifier, state, nonce, return_to } = pending;
      if (!code_verifier || !state || !nonce) {
        res.status(400).json({ error: 'login_session_missing' });
        return;
      }
      const config = await client();

      // The callback URL is rebuilt on the registered redirect URI (not the
      // Host header) with this request's query; openid-client checks state,
      // nonce, PKCE, issuer, audience and the RS256 ID-token signature.
      const currentUrl = new URL(redirectUri());
      currentUrl.search = new URL(req.originalUrl, 'http://callback.invalid').search;
      const tokenSet = await oidc.authorizationCodeGrant(config, currentUrl, {
        pkceCodeVerifier: code_verifier,
        expectedState: state,
        expectedNonce: nonce,
        idTokenExpected: true
      });

      // Get user info, bound to the ID token subject
      const claims = tokenSet.claims();
      const userinfo = await oidc.fetchUserInfo(config, tokenSet.access_token, claims.sub);

      // New session id at login, and nothing carried over from before it.
      await new Promise((resolve, reject) => {
        req.session.regenerate((err) => (err ? reject(err) : resolve()));
      });

      // id is the Authentik sub (sub_mode hashed_user_id). Email and name are
      // display data; cp_sso_bindings decides which member the sub may act as.
      req.session.user = {
        id: claims.sub,
        email: userinfo.email,
        name: userinfo.name || userinfo.preferred_username,
        groups: Array.isArray(userinfo.groups) ? userinfo.groups : [],
        picture: userinfo.picture
      };

      req.session.tokens = {
        access_token: tokenSet.access_token,
        refresh_token: tokenSet.refresh_token,
        id_token: tokenSet.id_token,
        expires_at: tokenExpiry(tokenSet)
      };

      res.redirect(safeReturnPath(return_to));
    } catch (error) {
      try {
        await saveSession(req);
      } catch (saveErr) {
        logger.error(`[oauth] session save failed name=${saveErr.name || 'Error'}`);
      }
      failure(res, logger, 'login_callback', error, 400);
    }
  });

  /**
   * POST /oauth/logout
   * Needs the session CSRF token. Destroys the session and redirects (303)
   * to the Authentik end-session endpoint, or to / when there is none.
   */
  router.post('/logout', express.urlencoded({ extended: false, limit: '8kb' }), async (req, res) => {
    const presented = req.body && typeof req.body.csrf === 'string' ? req.body.csrf : '';
    if (!req.session || !req.session.user) {
      res.redirect(303, '/');
      return;
    }
    if (!csrfValid(req, presented)) {
      res.status(403).json({ error: 'csrf_denied' });
      return;
    }
    const idToken = req.session.tokens && req.session.tokens.id_token;
    await new Promise((resolve) => {
      req.session.destroy((err) => {
        if (err) logger.error(`[oauth] session destroy failed name=${err.name || 'Error'}`);
        resolve();
      });
    });
    if (!authentikClient || !idToken) {
      res.redirect(303, '/');
      return;
    }
    try {
      const logoutUrl = oidc.buildEndSessionUrl(authentikClient, {
        id_token_hint: idToken,
        post_logout_redirect_uri: POST_LOGOUT
      });
      res.redirect(303, logoutUrl.href);
    } catch (error) {
      logger.error(`[oauth] logout url failed name=${error.name || 'Error'}`);
      res.redirect(303, '/');
    }
  });

  /**
   * GET /oauth/user
   * Returns current user info and the session CSRF token (requires login).
   * No CORS is served on /oauth, so other origins cannot read the token.
   */
  router.get('/user', (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (!req.session.user) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }
    res.json({
      user: req.session.user,
      authenticated: true,
      csrf: sessionCsrf(req)
    });
  });

  /**
   * POST /oauth/refresh
   * Refreshes access token using refresh token (needs the CSRF token).
   */
  router.post('/refresh', express.json({ limit: '8kb' }), async (req, res) => {
    try {
      const presented = req.body && typeof req.body.csrf === 'string' ? req.body.csrf : '';
      if (!req.session.user || !csrfValid(req, presented)) {
        res.status(403).json({ error: 'csrf_denied' });
        return;
      }
      const refresh_token = req.session.tokens && req.session.tokens.refresh_token;
      if (!refresh_token) {
        res.status(401).json({ error: 'no_refresh_token' });
        return;
      }
      const config = await client();
      const tokenSet = await oidc.refreshTokenGrant(config, refresh_token);
      req.session.tokens = {
        access_token: tokenSet.access_token,
        refresh_token: tokenSet.refresh_token || refresh_token,
        id_token: tokenSet.id_token || req.session.tokens.id_token,
        expires_at: tokenExpiry(tokenSet)
      };
      res.json({ success: true, expires_at: req.session.tokens.expires_at });
    } catch (error) {
      failure(res, logger, 'refresh', error);
    }
  });

  /**
   * GET /oauth/signup
   * Redirects to After Dark Systems sign up page
   */
  router.get('/signup', (req, res) => {
    res.redirect(`${AUTHENTIK_URL}/if/flow/enrollment/`);
  });

  return router;
}

module.exports = { createOAuthRouter };
