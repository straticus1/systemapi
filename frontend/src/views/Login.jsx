import React, { useState } from 'react';
import { useAppStore } from '../store';
import { Lock, Server, ShieldAlert } from 'lucide-react';
import { api } from '../api';

const Login = () => {
  const [key, setKeyInput] = useState('ak_live_1234.demo');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  
  const setApiKey = useAppStore(state => state.setApiKey);

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
        </form>
      </div>
    </div>
  );
};

export default Login;
