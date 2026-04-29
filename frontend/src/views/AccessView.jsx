import React, { useState } from 'react';
import { useAppStore } from '../store';
import { KeyRound, ShieldCheck, Server } from 'lucide-react';
import { FleetAPI } from '../api';

const AccessView = () => {
  const { hosts } = useAppStore();
  const [selectedHost, setSelectedHost] = useState(hosts[0]?.host_id || '');
  const [targetUser, setTargetUser] = useState('root');
  const [pubKey, setPubKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');

  const handlePushKey = async (e) => {
    e.preventDefault();
    if (!selectedHost || !pubKey) return;
    
    setLoading(true);
    setStatusMsg('');

    // Abstracted Sysscript execution to inject the SSH Key
    // The agent's `sys.ssh.add_key()` determines if it's linux ~/.ssh/authorized_keys
    // or Windows OpenSSH pathing automatically.
    const script = `
def run():
    return sys.ssh.add_key("${targetUser}", """${pubKey}""")

run()
`;
    try {
      await FleetAPI.executeScript(selectedHost, script, { allow_fs: true, allow_exec: true });
      setStatusMsg('SSH Key successfully deployed to the host.');
      setPubKey('');
    } catch (e) {
      console.error(e);
      setStatusMsg('Failed to deploy SSH key.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: '24px', flex: 1, overflowY: 'auto' }}>
      <div style={{ marginBottom: '32px' }}>
        <h1 style={{ marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <KeyRound color="var(--accent-green)" /> Access Management
        </h1>
        <p style={{ color: 'var(--text-muted)' }}>
          Cloud-agnostic SSH Key distribution. Provision zero-trust access safely across any cloud provider.
        </p>
      </div>

      <div style={{ display: 'flex', gap: '24px' }}>
        {/* Host Selector */}
        <div className="glass-panel" style={{ width: '280px', padding: '16px' }}>
          <h3 style={{ fontSize: '1rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Server size={16} /> Target Node
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {hosts.length === 0 ? (
                <div style={{color:'var(--text-muted)', fontSize:'0.9rem'}}>No active nodes.</div>
            ) : hosts.map(h => (
              <button 
                key={h.host_id}
                onClick={() => setSelectedHost(h.host_id)}
                className={`btn ${selectedHost === h.host_id ? 'btn-primary' : 'btn-ghost'}`}
                style={{ justifyContent: 'flex-start' }}
              >
                <div className={`status-indicator ${h.status === 'online' ? 'status-online' : 'status-offline'}`} />
                {h.hostname}
              </button>
            ))}
          </div>
        </div>

        {/* Key Injection Form */}
        <div className="glass-panel" style={{ flex: 1, padding: '24px', maxWidth: '600px' }}>
          <h3 style={{ fontSize: '1.1rem', marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '8px' }}>
             Deploy Public Key 
             <ShieldCheck size={16} color="var(--accent-cyan)" />
          </h3>
          
          <form onSubmit={handlePushKey}>
            <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', marginBottom: '8px', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                    System User Account
                </label>
                <input 
                    type="text" 
                    value={targetUser}
                    onChange={e => setTargetUser(e.target.value)}
                    style={{ 
                        width: '100%', padding: '10px', background: 'rgba(0,0,0,0.3)',
                        border: '1px solid var(--border-light)', borderRadius: '6px',
                        color: 'white', outline: 'none'
                    }}
                />
            </div>
            
            <div style={{ marginBottom: '24px' }}>
                <label style={{ display: 'block', marginBottom: '8px', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                    SSH Public Key (<code>ssh-rsa ...</code>)
                </label>
                <textarea 
                    value={pubKey}
                    onChange={e => setPubKey(e.target.value)}
                    rows={6}
                    style={{ 
                        width: '100%', padding: '10px', background: 'rgba(0,0,0,0.3)',
                        border: '1px solid var(--border-light)', borderRadius: '6px',
                        color: 'var(--accent-cyan)', fontFamily: 'monospace', outline: 'none',
                        resize: 'vertical'
                    }}
                    placeholder="ssh-rsa AAAAB3NzaC1yc2E..."
                />
            </div>

            {statusMsg && (
                <div style={{ marginBottom: '20px', padding: '12px', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid var(--accent-green)', borderRadius: '6px', color: 'var(--accent-green)', fontSize: '0.9rem' }}>
                    {statusMsg}
                </div>
            )}

            <button type="submit" className="btn btn-primary" disabled={loading} style={{ width: '100%' }}>
                {loading ? 'Deploying Key...' : 'Install Authorized Key'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default AccessView;
