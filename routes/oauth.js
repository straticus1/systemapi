/**
 * OAuth 2.0 / OpenID Connect Routes for After Dark Systems (Authentik)
 * Provides login, callback, logout, and user info endpoints
 */

const express = require('express');
const crypto = require('crypto');
const { safeReturnPath } = require('../controlplane/oauth');

const router = express.Router();

// openid-client 6 is ESM-only and has no Issuer/generators (that was the v5
// API, which left every login failing). Loaded lazily.
let oidc;

// Environment variables
const AUTHENTIK_URL = process.env.AUTHENTIK_URL || 'https://auth.afterdarksys.com';
const AUTHENTIK_ISSUER = process.env.AUTHENTIK_ISSUER || 'https://auth.afterdarksys.com/application/o/systemapi-io-client/';
const CLIENT_ID = process.env.AUTHENTIK_CLIENT_ID || 'systemapi-io-client';
const CLIENT_SECRET = process.env.AUTHENTIK_CLIENT_SECRET;
const REDIRECT_URI = process.env.AUTHENTIK_REDIRECT_URI || 'https://systemapi.io/oauth/callback';
const SCOPES = process.env.AUTHENTIK_SCOPES || 'openid profile email groups offline_access';

// For local development override
const DEV_MODE = process.env.DEV_MODE === 'true';
const DEV_REDIRECT_URI = process.env.DEV_REDIRECT_URI || 'http://localhost:3000/oauth/callback';

let authentikClient = null;

function redirectUri() {
  return DEV_MODE ? DEV_REDIRECT_URI : REDIRECT_URI;
}

// Unix seconds, as the v5 tokenSet.expires_at was.
function tokenExpiry(tokenSet) {
  const ttl = typeof tokenSet.expiresIn === 'function' ? tokenSet.expiresIn() : undefined;
  return typeof ttl === 'number' ? Math.floor(Date.now() / 1000) + ttl : undefined;
}

/**
 * Initialize OpenID Connect client (discovery against the Authentik issuer)
 */
async function initializeOIDCClient() {
  try {
    if (!oidc) oidc = await import('openid-client');
    if (!CLIENT_SECRET) throw new Error('AUTHENTIK_CLIENT_SECRET is not set');

    authentikClient = await oidc.discovery(new URL(AUTHENTIK_ISSUER), CLIENT_ID, CLIENT_SECRET);
    console.log('Discovered Authentik issuer:', authentikClient.serverMetadata().issuer);

    console.log('OAuth client initialized for SystemAPI.io');
    return authentikClient;
  } catch (error) {
    console.error('Failed to initialize OIDC client:', error.message);
    throw error;
  }
}

// Initialize on module load (lazy loading)
(async () => {
  try {
    await initializeOIDCClient();
  } catch (err) {
    console.error('OIDC initialization failed (will retry on first request):', err.message);
  }
})();

/**
 * GET /oauth/login
 * Initiates OAuth login flow by redirecting to Authentik
 */
router.get('/login', async (req, res) => {
  try {
    if (!authentikClient) {
      await initializeOIDCClient();
    }

    // Generate PKCE challenge and state
    const code_verifier = oidc.randomPKCECodeVerifier();
    const code_challenge = await oidc.calculatePKCECodeChallenge(code_verifier);
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();

    // Store in session for verification in callback
    req.session.oauth = {
      code_verifier,
      state,
      nonce,
      // Same-origin path only; the device verify page returns here.
      return_to: safeReturnPath(req.query.return_to)
    };

    const authorizationUrl = oidc.buildAuthorizationUrl(authentikClient, {
      redirect_uri: redirectUri(),
      scope: SCOPES,
      state,
      nonce,
      code_challenge,
      code_challenge_method: 'S256'
    });

    res.redirect(authorizationUrl.href);
  } catch (error) {
    console.error('Error initiating OAuth login:', error);
    res.status(500).json({
      error: 'OAuth initialization failed',
      message: error.message
    });
  }
});

/**
 * GET /oauth/callback
 * Handles OAuth callback from Authentik
 */
router.get('/callback', async (req, res) => {
  try {
    if (!authentikClient) {
      await initializeOIDCClient();
    }

    const { code_verifier, state, nonce, return_to } = req.session.oauth || {};

    if (!code_verifier || !state) {
      return res.status(400).json({
        error: 'Invalid session',
        message: 'OAuth session data not found. Please try logging in again.'
      });
    }

    // Exchange authorization code for tokens. The callback URL is rebuilt on
    // the registered redirect URI (not the Host header) with this request's
    // query; openid-client checks state, nonce, PKCE and the ID token.
    const currentUrl = new URL(redirectUri());
    currentUrl.search = new URL(req.originalUrl, 'http://callback.invalid').search;
    const tokenSet = await oidc.authorizationCodeGrant(authentikClient, currentUrl, {
      pkceCodeVerifier: code_verifier,
      expectedState: state,
      expectedNonce: nonce,
      idTokenExpected: true
    });

    // Get user info, bound to the ID token subject
    const claims = tokenSet.claims();
    const userinfo = await oidc.fetchUserInfo(authentikClient, tokenSet.access_token, claims.sub);

    // New session id at login: a session id planted before login must not
    // become an authenticated one (the device approval trusts this session).
    await new Promise((resolve, reject) => {
      req.session.regenerate((err) => (err ? reject(err) : resolve()));
    });

    // Store user data and tokens in session. email_verified gates the
    // email-to-member mapping used by the device approval.
    req.session.user = {
      id: userinfo.sub,
      email: userinfo.email,
      email_verified: userinfo.email_verified === true,
      name: userinfo.name || userinfo.preferred_username,
      groups: userinfo.groups || [],
      picture: userinfo.picture
    };

    req.session.tokens = {
      access_token: tokenSet.access_token,
      refresh_token: tokenSet.refresh_token,
      id_token: tokenSet.id_token,
      expires_at: tokenExpiry(tokenSet)
    };

    console.log(`User logged in: ${userinfo.email} (${userinfo.sub})`);

    // Redirect to return URL or dashboard
    res.redirect(safeReturnPath(return_to));
  } catch (error) {
    console.error('Error in OAuth callback:', error);
    res.status(500).json({
      error: 'OAuth callback failed',
      message: error.message,
      details: process.env.NODE_ENV === 'production' ? undefined : error.stack
    });
  }
});

/**
 * GET /oauth/logout
 * Logs out user and redirects to Authentik logout
 */
router.get('/logout', async (req, res) => {
  try {
    const id_token = req.session.tokens?.id_token;

    // Destroy session
    req.session.destroy((err) => {
      if (err) {
        console.error('Error destroying session:', err);
      }
    });

    if (!authentikClient || !id_token) {
      return res.redirect('/');
    }

    // Redirect to Authentik end session endpoint
    const logoutUrl = oidc.buildEndSessionUrl(authentikClient, {
      id_token_hint: id_token,
      post_logout_redirect_uri: DEV_MODE ? 'http://localhost:3000' : 'https://systemapi.io'
    });

    res.redirect(logoutUrl.href);
  } catch (error) {
    console.error('Error during logout:', error);
    res.redirect('/');
  }
});

/**
 * GET /oauth/user
 * Returns current user info (requires authentication)
 */
router.get('/user', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Not logged in'
    });
  }

  res.json({
    user: req.session.user,
    authenticated: true
  });
});

/**
 * GET /oauth/refresh
 * Refreshes access token using refresh token
 */
router.post('/refresh', async (req, res) => {
  try {
    if (!authentikClient) {
      await initializeOIDCClient();
    }

    const refresh_token = req.session.tokens?.refresh_token;
    if (!refresh_token) {
      return res.status(401).json({
        error: 'No refresh token',
        message: 'Please log in again'
      });
    }

    const tokenSet = await oidc.refreshTokenGrant(authentikClient, refresh_token);

    // Update tokens in session
    req.session.tokens = {
      access_token: tokenSet.access_token,
      refresh_token: tokenSet.refresh_token || refresh_token,
      id_token: tokenSet.id_token || req.session.tokens.id_token,
      expires_at: tokenExpiry(tokenSet)
    };

    res.json({
      success: true,
      expires_at: req.session.tokens.expires_at
    });
  } catch (error) {
    console.error('Error refreshing token:', error);
    res.status(500).json({
      error: 'Token refresh failed',
      message: error.message
    });
  }
});

/**
 * GET /oauth/signup
 * Redirects to After Dark Systems sign up page
 */
router.get('/signup', (req, res) => {
  // Redirect to After Dark Systems sign up flow
  const signupUrl = `${AUTHENTIK_URL}/if/flow/enrollment/`;
  res.redirect(signupUrl);
});

module.exports = router;
