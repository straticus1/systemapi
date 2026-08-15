import React from 'react';
import { useAppStore } from '../store';
import { Activity, ShieldCheck, LogOut, User } from 'lucide-react';

const Topbar = () => {
  const hosts = useAppStore(state => state.hosts);
  const user = useAppStore(state => state.user);
  const authMethod = useAppStore(state => state.authMethod);
  const logout = useAppStore(state => state.logout);
  const onlineCount = hosts.filter(h => h.status === 'online').length;

  return (
    <header className="topbar">
      <div>
        <h2 style={{ fontSize: '1.1rem', margin: 0, fontWeight: 600 }}>Command Center</h2>
      </div>
      
      <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
        {/* Fleet Health Indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(16, 185, 129, 0.1)', padding: '6px 12px', borderRadius: '20px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
          <span className="status-indicator status-online"></span>
          <span style={{ fontSize: '0.85rem', color: 'var(--accent-green)', fontWeight: 500 }}>
            {onlineCount}/{hosts.length} Nodes Online
          </span>
        </div>

        {/* System Status Indicators */}
        <div style={{ display: 'flex', gap: '16px', color: 'var(--text-muted)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }} title="WebSocket Telemetry Connected">
            <Activity size={16} />
            <span style={{ fontSize: '0.85rem' }}>Stream Active</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }} title="Zero-Trust Enforced">
            <ShieldCheck size={16} color="var(--accent-cyan)" />
            <span style={{ fontSize: '0.85rem', color: 'var(--text-main)' }}>Secure</span>
          </div>
        </div>

        {/* User Info & Logout */}
        {authMethod === 'oauth' && user && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', paddingLeft: '12px', borderLeft: '1px solid var(--border-light)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              {user.picture ? (
                <img src={user.picture} alt={user.name} style={{ width: '28px', height: '28px', borderRadius: '50%' }} />
              ) : (
                <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <User size={16} />
                </div>
              )}
              <span style={{ fontSize: '0.85rem', color: 'var(--text-main)' }}>{user.name || user.email}</span>
            </div>
            <button
              onClick={logout}
              style={{
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.3)',
                color: 'var(--accent-red)',
                padding: '6px 12px',
                borderRadius: '6px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '0.85rem'
              }}
              title="Logout"
            >
              <LogOut size={14} />
              Logout
            </button>
          </div>
        )}

        {authMethod === 'api_key' && (
          <button
            onClick={logout}
            style={{
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              color: 'var(--accent-red)',
              padding: '6px 12px',
              borderRadius: '6px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.85rem'
            }}
            title="Clear API Key"
          >
            <LogOut size={14} />
            Logout
          </button>
        )}
      </div>
    </header>
  );
};

export default Topbar;
