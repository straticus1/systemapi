import React, { useState } from 'react';
import Editor from '@monaco-editor/react';
import { Terminal, Send, Server, CheckCircle2, XCircle } from 'lucide-react';
import { useAppStore } from '../store';
import { FleetAPI } from '../api';

const DEFAULT_SCRIPT = `def run():
    # Return OS-level details using the Sysscript API
    hostname = sys.os.hostname()
    platform = sys.os.platform()
    
    # You can also run commands directly
    # out = sys.exec.run("whoami", [])
    
    return {
        "hostname": hostname,
        "platform": platform,
        "status": "Healthy and under your command"
    }

run()`;

const SysscriptsView = () => {
  const { hosts } = useAppStore();
  const [code, setCode] = useState(DEFAULT_SCRIPT);
  const [selectedHost, setSelectedHost] = useState(hosts[0]?.host_id || '');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  
  // Entitlements
  const [allowExec, setAllowExec] = useState(true);
  const [allowFs, setAllowFs] = useState(false);
  const [allowNet, setAllowNet] = useState(false);

  const handleExecute = async () => {
    if (!selectedHost) return;
    setLoading(true);
    setResult(null);

    try {
      const entitlements = {
        allow_exec: allowExec,
        allow_fs: allowFs,
        allow_network: allowNet
      };
      
      const res = await FleetAPI.executeScript(selectedHost, code, entitlements);
      setResult({ success: true, data: res.output || res });
    } catch (e) {
      console.error(e);
      setResult({ success: false, data: e.response?.data?.error || e.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <div style={{ padding: '24px', borderBottom: '1px solid var(--border-light)' }}>
        <h1 style={{ marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Terminal color="var(--accent-blue)" /> Sysscript Studio
        </h1>
        <p style={{ color: 'var(--text-muted)' }}>
          Write and deploy Starlark (Python) scripts globally. The agent engine handles the OS abstraction natively.
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
                <div style={{ padding: '16px', flex: 1, overflowY: 'auto', fontFamily: 'monospace', fontSize: '0.9rem', color: result.success ? '#e5e7eb' : 'var(--accent-red)', whiteSpace: 'pre-wrap' }}>
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
            Zero-Trust Sandbox: explicitly define what this script is permitted to do on the endpoint.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '32px' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input type="checkbox" checked={allowExec} onChange={e => setAllowExec(e.target.checked)} />
                <span>Allow Exec (`sys.exec`)</span>
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input type="checkbox" checked={allowFs} onChange={e => setAllowFs(e.target.checked)} />
                <span>Allow Fileset (`sys.fs`)</span>
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
                <input type="checkbox" checked={allowNet} onChange={e => setAllowNet(e.target.checked)} />
                <span>Allow Network (`sys.net`)</span>
            </label>
          </div>

          <button 
            onClick={handleExecute}
            disabled={loading || !selectedHost}
            className="btn btn-primary" 
            style={{ width: '100%', padding: '12px' }}
          >
            <Send size={16} /> {loading ? 'Transmitting...' : 'Deploy Script'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default SysscriptsView;
