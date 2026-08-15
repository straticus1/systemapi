import React, { useState, useEffect } from 'react';
import { useAppStore } from '../store';
import { Lock, Server, ShieldAlert, LogIn, UserPlus } from 'lucide-react';
import { api } from '../api';

const Login = () => {
  const [key, setKeyInput] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showApiKeyLogin, setShowApiKeyLogin] = useState(false);

  const setApiKey = useAppStore(state => state.setApiKey);

  // Check if user is already authenticated via session
  useEffect(() => {
    checkSession();
  }, []);

  const checkSession = async () => {
    try {
      const res = await api.get('/oauth/user');
      if (res.data.authenticated) {
        // User is authenticated via OAuth, redirect to dashboard
        setApiKey('oauth_session'); // Use a placeholder to indicate OAuth auth
      }
    } catch (err) {
      // Not authenticated, show login options
    }
  };

  const handleOAuthLogin = () => {
    // Redirect to OAuth login endpoint
    window.location.href = '/oauth/login';
  };

  const handleSignUp = () => {
    // Redirect to After Dark Systems sign up
    window.location.href = '/oauth/signup';
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    if (!key.startsWith('ak_live_')) {
      setError('Invalid API Key format. Must start with ak_live_');
      return;
    }
    
    setLoading(true);
    setError('');
    
    try {
      // Very simple validation check against the fleet backend
      const res = await api.get('/api/v1/fleet', { headers: { 'X-API-Key': key } });
      if (res.status === 200) {
        setApiKey(key);
      }
    } catch (err) {
      console.error("Login Error:", err);
      if (err.response?.status === 401 || err.response?.status === 403) {
        setError('Unauthorized: Invalid API Key');
      } else {
        // Fallback error message
        setError(err.response?.data?.error || err.message || 'Network error connecting to SystemAPI.io');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-container" style={{ alignItems: 'center', justifyContent: 'center' }}>
      <div className="glass-panel" style={{ padding: '40px', width: '100%', maxWidth: '420px' }}>
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <ShieldAlert size={48} color="var(--accent-cyan)" />
          <h1 style={{ marginTop: '16px' }} className="text-gradient">SystemAPI.io</h1>
          <p style={{ color: 'var(--text-muted)' }}>Zero-Trust Fleet Management</p>
        </div>

        {/* OAuth Login (Primary) */}
        {!showApiKeyLogin && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <button
              onClick={handleOAuthLogin}
              className="btn btn-primary"
              style={{ width: '100%', padding: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
            >
              <LogIn size={18} />
              Login with After Dark Systems
            </button>

            <button
              onClick={handleSignUp}
              className="btn btn-secondary"
              style={{ width: '100%', padding: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
            >
              <UserPlus size={18} />
              Create Account
            </button>

            <div style={{ textAlign: 'center', margin: '16px 0' }}>
              <div style={{ borderTop: '1px solid var(--border-light)', marginBottom: '16px' }}></div>
              <button
                onClick={() => setShowApiKeyLogin(true)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  fontSize: '0.85rem',
                  textDecoration: 'underline'
                }}
              >
                Login with API Key instead
              </button>
            </div>
          </div>
        )}

        {/* API Key Login (Alternative) */}
        {showApiKeyLogin && (
          <form onSubmit={handleLogin}>
            <div style={{ marginBottom: '24px' }}>
              <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                Master API Key
              </label>
              <div style={{ position: 'relative' }}>
                <Lock size={18} style={{ position: 'absolute', left: '12px', top: '10px', color: 'var(--text-muted)' }} />
                <input
                  type="password"
                  value={key}
                  onChange={e => setKeyInput(e.target.value)}
                  placeholder="ak_live_..."
                  style={{
                    width: '100%',
                    padding: '10px 10px 10px 40px',
                    background: 'rgba(0,0,0,0.3)',
                    border: '1px solid var(--border-light)',
                    borderRadius: '6px',
                    color: 'white',
                    fontFamily: 'monospace',
                    outline: 'none'
                  }}
                />
              </div>
              {error && <div style={{ color: 'var(--accent-red)', fontSize: '0.85rem', marginTop: '8px' }}>{error}</div>}
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              style={{ width: '100%', padding: '12px' }}
              disabled={loading}
            >
              {loading ? 'Authenticating...' : 'Access Fleet Control'}
            </button>

            <div style={{ textAlign: 'center', marginTop: '16px' }}>
              <button
                type="button"
                onClick={() => setShowApiKeyLogin(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  fontSize: '0.85rem',
                  textDecoration: 'underline'
                }}
              >
                Back to OAuth login
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};

export default Login;
