import React, { useState } from 'react';
import Editor from '@monaco-editor/react';
import { Terminal, Send, Server, CheckCircle2, XCircle } from 'lucide-react';
import { useAppStore } from '../store';
import { FleetAPI } from '../api';
import { scriptOutcome } from '../format';

const DEFAULT_SCRIPT = `# Runs on the agent. Requires the exec entitlement.
r = sys.exec.run("uname", "-a")
print(r["output"])
`;

const SysscriptsView = () => {
  const { hosts } = useAppStore();
  const [code, setCode] = useState(DEFAULT_SCRIPT);
  const [selectedHost, setSelectedHost] = useState(hosts[0]?.host_id || '');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  
  // Boolean entitlements the control plane honours. Path-scoped ones
  // (allow_fs_read, allow_fs_write, allow_net_outbound) are API-only for now.
  const [allowExec, setAllowExec] = useState(true);
  const [allowContainers, setAllowContainers] = useState(false);
  const [allowK3s, setAllowK3s] = useState(false);

  const handleExecute = async () => {
    if (!selectedHost) return;
    setLoading(true);
    setResult(null);

    try {
      const entitlements = {
        allow_exec: allowExec,
        allow_containers: allowContainers,
        allow_k3s: allowK3s
      };
      setResult(scriptOutcome(await FleetAPI.executeScript(selectedHost, code, entitlements)));
    } catch (e) {
      setResult({ success: false, data: e.response?.data?.error || e.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <div style={{ padding: '24px', borderBottom: '1px solid var(--border-light)' }}>
        <h1 style={{ marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Terminal color="var(--accent)" /> Sysscript Studio
        </h1>
        <p style={{ color: 'var(--text-muted)' }}>
          Write a Starlark script and run it on one host.
        </p>
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* Editor Area */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', borderRight: '1px solid var(--border-light)' }}>
          <div style={{ flex: 1 }}>
            <Editor
              height="100%"
              defaultLanguage="python"
              theme="vs-dark"
              value={code}
              onChange={val => setCode(val)}
              options={{
                minimap: { enabled: false },
                fontSize: 14,
                fontFamily: '"JetBrains Mono", monospace',
                padding: { top: 20 },
                scrollBeyondLastLine: false,
                renderLineHighlight: 'all',
                smoothScrolling: true,
              }}
            />
          </div>
          
          {/* Result Panel */}
          {result && (
             <div style={{ height: '250px', borderTop: '1px solid var(--border-light)', background: 'var(--bg-darker)', display: 'flex', flexDirection: 'column' }}>
                <div style={{ padding: '8px 16px', borderBottom: '1px solid var(--border-light)', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem' }}>
                    {result.success ? <CheckCircle2 size={16} color="var(--accent-green)" /> : <XCircle size={16} color="var(--accent-red)" />}
                    {result.success ? 'Execution Successful' : 'Execution Failed'}
                </div>
                <div style={{ padding: '16px', flex: 1, overflowY: 'auto', fontFamily: 'monospace', fontSize: '0.9rem', color: result.success ? 'var(--text-code)' : 'var(--accent-red)', whiteSpace: 'pre-wrap' }}>
                    {typeof result.data === 'string' ? result.data : JSON.stringify(result.data, null, 2)}
                </div>
             </div>
          )}
        </div>

        {/* Sidebar Configuration */}
        <div style={{ width: '320px', background: 'var(--bg-panel)', padding: '24px', overflowY: 'auto' }}>
          <h3 style={{ fontSize: '1rem', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
             <Server size={18} /> Target Node
          </h3>
          <select 
            value={selectedHost}
            onChange={e => setSelectedHost(e.target.value)}
            style={{ 
                width: '100%', padding: '10px', background: 'rgba(0,0,0,0.4)',
                border: '1px solid var(--border-light)', borderRadius: '6px',
                color: 'white', marginBottom: '32px', outline: 'none'
            }}
          >
            {hosts.length === 0 && <option value="">No hosts connected...</option>}
            {hosts.map(h => (
               <option key={h.host_id} value={h.host_id}>{h.hostname} ({h.status})</option>
            ))}
          </select>

          <h3 style={{ fontSize: '1rem', marginBottom: '16px' }}>Security Entitlements</h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
            Grants for this run. Containers and k3s need the admin role. Path-scoped grants (files, outbound network) are set through the API.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '32px' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input type="checkbox" checked={allowExec} onChange={e => setAllowExec(e.target.checked)} />
                <span>Allow Exec (`sys.exec`)</span>
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input type="checkbox" checked={allowContainers} onChange={e => setAllowContainers(e.target.checked)} />
                <span>Allow Containers (`sys.containers`)</span>
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input type="checkbox" checked={allowK3s} onChange={e => setAllowK3s(e.target.checked)} />
                <span>Allow k3s (`sys.k3s`)</span>
            </label>
          </div>

          <button 
            onClick={handleExecute}
            disabled={loading || !selectedHost}
            className="btn btn-primary" 
            style={{ width: '100%', padding: '12px' }}
          >
            <Send size={16} /> {loading ? 'Running...' : 'Run Script'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default SysscriptsView;
