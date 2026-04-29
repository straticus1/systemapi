import React, { useState } from 'react';
import { useAppStore } from '../store';
import { Box, Play, Square, RefreshCw, Server } from 'lucide-react';
import { FleetAPI } from '../api';

const ContainersView = () => {
  const { hosts } = useAppStore();
  const [selectedHost, setSelectedHost] = useState(hosts[0]?.host_id || '');
  const [loading, setLoading] = useState(false);

  // In a real app, this state would be populated via `sys.containers.list()` 
  // executed against the agent and returned via WebSocket command_result.
  const [containers, setContainers] = useState([
    { id: 'a1b2c3d4', image: 'nginx:latest', state: 'running', ports: '80:80', uptime: '12d' },
    { id: 'f9e8d7c6', image: 'redis:alpine', state: 'running', ports: '6379:6379', uptime: '4d' },
    { id: 'b5a49382', image: 'my-custom-app:v2', state: 'stopped', ports: '8080:8080', uptime: '-' }
  ]);

  const handleAction = async (containerId, action) => {
    if (!selectedHost) return;
    setLoading(true);
    
    // Abstracted Sysscript execution: The user doesn't care if it's Docker or Podman
    // The Go Agent's sys.containers module handles the OS-specific daemon abstraction.
    const script = `
def run():
    if "${action}" == "start":
        return sys.containers.start("${containerId}")
    elif "${action}" == "stop":
        return sys.containers.stop("${containerId}")
    elif "${action}" == "restart":
        return sys.containers.restart("${containerId}")

run()
`;
    try {
      await FleetAPI.executeScript(selectedHost, script, { allow_exec: true });
      // In real life, we wait for WS response to update UI
      setTimeout(() => setLoading(false), 500);
    } catch (e) {
      console.error(e);
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: '24px', flex: 1, overflowY: 'auto' }}>
      <div style={{ marginBottom: '32px' }}>
        <h1 style={{ marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Box color="var(--accent-purple)" /> Workload Orchestration
        </h1>
        <p style={{ color: 'var(--text-muted)' }}>
          Cloud-agnostic container management. Push and control workloads without cloud provider lock-in.
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

        {/* Container List */}
        <div className="glass-panel" style={{ flex: 1, padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
            <h3 style={{ fontSize: '1.1rem' }}>Active Containers</h3>
            <button className="btn btn-ghost"><RefreshCw size={14} /> Refresh</button>
          </div>

          <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-light)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '12px' }}>ID / Name</th>
                <th style={{ padding: '12px' }}>Image</th>
                <th style={{ padding: '12px' }}>State</th>
                <th style={{ padding: '12px' }}>Ports</th>
                <th style={{ padding: '12px' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {containers.map(c => (
                <tr key={c.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                  <td style={{ padding: '12px', fontFamily: 'monospace' }}>{c.id}</td>
                  <td style={{ padding: '12px' }}>{c.image}</td>
                  <td style={{ padding: '12px' }}>
                    <span style={{ 
                        color: c.state === 'running' ? 'var(--accent-green)' : 'var(--text-muted)',
                        background: c.state === 'running' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(255,255,255,0.05)',
                        padding: '4px 8px', borderRadius: '4px', fontSize: '0.85rem'
                    }}>
                        {c.state}
                    </span>
                  </td>
                  <td style={{ padding: '12px', fontFamily: 'monospace', fontSize: '0.9rem' }}>{c.ports}</td>
                  <td style={{ padding: '12px', display: 'flex', gap: '8px' }}>
                    {c.state === 'running' ? (
                        <button onClick={() => handleAction(c.id, 'stop')} disabled={loading} className="btn btn-ghost" style={{ padding: '6px' }} title="Stop">
                            <Square size={14} color="var(--accent-red)" />
                        </button>
                    ) : (
                        <button onClick={() => handleAction(c.id, 'start')} disabled={loading} className="btn btn-ghost" style={{ padding: '6px' }} title="Start">
                            <Play size={14} color="var(--accent-green)" />
                        </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default ContainersView;
