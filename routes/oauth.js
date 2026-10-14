/**
 * OAuth 2.0 / OpenID Connect Routes for After Dark Systems (Authentik)
 * Provides login, callback, logout, and user info endpoints
 */

const express = require('express');
const crypto = require('crypto');
const { safeReturnPath } = require('../controlplane/oauth');

const router = express.Router();

// Dynamic import for ESM module
let Issuer, generators;

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

/**
 * Initialize OpenID Connect client
 */
async function initializeOIDCClient() {
  try {
    // Dynamic import for ESM module
    if (!Issuer) {
      const oidcModule = await import('openid-client');
      Issuer = oidcModule.Issuer;
      generators = oidcModule.generators;
    }

    const authentikIssuer = await Issuer.discover(AUTHENTIK_ISSUER);
    console.log('Discovered Authentik issuer:', authentikIssuer.metadata.issuer);

    authentikClient = new authentikIssuer.Client({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uris: [DEV_MODE ? DEV_REDIRECT_URI : REDIRECT_URI],
      response_types: ['code'],
    });

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
    const code_verifier = generators.codeVerifier();
    const code_challenge = generators.codeChallenge(code_verifier);
    const state = generators.state();
    const nonce = generators.nonce();

    // Store in session for verification in callback
    req.session.oauth = {
      code_verifier,
      state,
      nonce,
      // Same-origin path only; the device verify page returns here.
      return_to: safeReturnPath(req.query.return_to)
    };

    const authorizationUrl = authentikClient.authorizationUrl({
      scope: SCOPES,
      state,
      nonce,
      code_challenge,
      code_challenge_method: 'S256'
    });

    console.log('Redirecting to Authentik login:', authorizationUrl);
    res.redirect(authorizationUrl);
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

    const params = authentikClient.callbackParams(req);
    const { code_verifier, state, nonce, return_to } = req.session.oauth || {};

    if (!code_verifier || !state) {
      return res.status(400).json({
        error: 'Invalid session',
        message: 'OAuth session data not found. Please try logging in again.'
      });
    }

    // Exchange authorization code for tokens
    const tokenSet = await authentikClient.callback(
      DEV_MODE ? DEV_REDIRECT_URI : REDIRECT_URI,
      params,
      { code_verifier, state, nonce }
    );

    console.log('Token exchange successful');

    // Get user info
    const userinfo = await authentikClient.userinfo(tokenSet.access_token);

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
      expires_at: tokenSet.expires_at
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
    const logoutUrl = authentikClient.endSessionUrl({
      id_token_hint: id_token,
      post_logout_redirect_uri: DEV_MODE ? 'http://localhost:3000' : 'https://systemapi.io'
    });

    res.redirect(logoutUrl);
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

    const tokenSet = await authentikClient.refresh(refresh_token);

    // Update tokens in session
    req.session.tokens = {
      access_token: tokenSet.access_token,
      refresh_token: tokenSet.refresh_token || refresh_token,
      id_token: tokenSet.id_token,
      expires_at: tokenSet.expires_at
    };

    res.json({
      success: true,
      expires_at: tokenSet.expires_at
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
