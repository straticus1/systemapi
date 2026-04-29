import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAppStore } from '../store';
import { Server, Cpu, HardDrive, Network, TerminalSquare, ShieldAlert } from 'lucide-react';
import { FleetAPI } from '../api';

const FleetDashboard = () => {
  const { apiKey, hosts, fetchHosts, updateHostTelemetry, isLoadingHosts } = useAppStore();
  const [ws, setWs] = useState(null);
  const [diagModal, setDiagModal] = useState({ open: false, title: '', output: '', loading: false });
  const navigate = useNavigate();

  const runDiagnostic = async (hostId, hostname, title, script) => {
    setDiagModal({ open: true, title: `${title} on ${hostname}`, output: '', loading: true });
    try {
        const res = await FleetAPI.executeScript(hostId, script, { allow_exec: true });
        const out = res.result?.output || res.result?.error || 'No output returned.';
        setDiagModal(prev => ({ ...prev, output: out, loading: false }));
    } catch (e) {
        setDiagModal(prev => ({ ...prev, output: 'Diagnostic failed: ' + e.message, loading: false }));
    }
  };

  // Load initial REST data
  useEffect(() => {
    fetchHosts();
  }, [fetchHosts]);

  // Connect WebSocket for live telemetry
  useEffect(() => {
    if (!apiKey) return;

    // Use wss:// in prod or ws:// in dev based config
    const wsUrl = (import.meta.env.VITE_WS_URL || 'ws://localhost:3003') + `/api/v1/systems/stream?api_key=${apiKey}`;
    const socket = new WebSocket(wsUrl);

    socket.onopen = () => console.log('Live Telemetry Stream Connected');
    
    socket.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'telemetry') {
          // Payload contains { timestamp: ..., host: {...}, cpu: {...}, memory: {...}, ... }
          // The backend usually determines host_id, but the agent doesn't know its host_id.
          // For the dashboard, the backend doesn't currently inject the hostId into the telemetry broadcast in `fleet.js`.
          // In a real robust app, `fleet.js` would intercept `msg.type = telemetry`, attach `host_id: hostId`, and broadcast to dashboard.
          // Since our current backend doesn't broadcast *to* the dashboard yet (only to terminal subscribers),
          // we will implement a periodic REST polling fallback here to simulate the live updates until backend is fully wired.
        }
      } catch (err) {
        console.error('WebSocket parsing error:', err);
      }
    };

    socket.onclose = () => console.log('Telemetry Stream Disconnected');
    setWs(socket);

    return () => socket.close();
  }, [apiKey]);
  
  // REST Polling fallback for the demo since the backend broadcast isn't fully complete for general telemetry yet
  useEffect(() => {
    const interval = setInterval(() => {
        fetchHosts();
    }, 5000);
    return () => clearInterval(interval);
  }, [fetchHosts]);

  return (
    <div style={{ padding: '24px', overflowY: 'auto', flex: 1 }}>
      <div style={{ marginBottom: '32px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ marginBottom: '8px' }}>Fleet Overview</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.95rem' }}>Monitor and manage connected endpoints in real-time.</p>
        </div>
        <button className="btn btn-primary" onClick={fetchHosts}>Refresh Data</button>
      </div>

      {isLoadingHosts && hosts.length === 0 ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: '60px', color: 'var(--text-muted)' }}>
          Loading fleet data...
        </div>
      ) : (
        <div className="dashboard-grid">
          {hosts.map(host => (
            <HostCard key={host.host_id} host={host} onConnect={() => navigate(`/terminal/${host.host_id}`)} onDiagnostic={(title, script) => runDiagnostic(host.host_id, host.hostname, title, script)} />
          ))}
          {hosts.length === 0 && (
            <div className="glass-panel" style={{ gridColumn: '1 / -1', padding: '40px', textAlign: 'center' }}>
              <Server size={48} color="var(--text-muted)" style={{ marginBottom: '16px', opacity: 0.5 }} />
              <h3 style={{ color: 'var(--text-muted)' }}>No hosts connected</h3>
              <p style={{ color: 'rgba(255,255,255,0.3)', marginTop: '8px', fontSize: '0.9rem' }}>Deploy the SystemAPI agent to a machine to see it here.</p>
            </div>
          )}
        </div>
      )}

      {diagModal.open && (
         <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.8)', zIndex: 999, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div className="glass-panel" style={{ width: '700px', maxWidth: '90%', display: 'flex', flexDirection: 'column' }}>
                <div style={{ padding: '20px', borderBottom: '1px solid var(--border-light)', display: 'flex', justifyContent: 'space-between' }}>
                    <h3>{diagModal.title}</h3>
                    <button onClick={() => setDiagModal({ open: false, title: '', output: '', loading: false })} style={{ background: 'none', border: 'none', color: 'white', cursor: 'pointer', fontSize: '1.2rem' }}>✕</button>
                </div>
                <div style={{ padding: '20px', background: '#000', fontFamily: 'monospace', minHeight: '300px', maxHeight: '600px', overflowY: 'auto', color: '#0f0', whiteSpace: 'pre-wrap', lineHeight: '1.4' }}>
                    {diagModal.loading ? "> Deploying diagnostic Sysscript to Agent...\n> Waiting for secure WebSocket execution callback..." : diagModal.output}
                </div>
            </div>
         </div>
      )}
    </div>
  );
};

const HostCard = ({ host, onConnect, onDiagnostic }) => {
  const isOnline = host.status === 'online';
  
  // Format uptime (minutes to human readable)
  const lastSeenDate = new Date(host.last_seen_at);
  const msAgo = Date.now() - lastSeenDate.getTime();
  const secondsAgo = Math.floor(msAgo / 1000);
  
  // Parse tags
  const tags = host.tags || [];

  const handleDiagnosticAction = (action) => {
      let script = '';
      if (action === 'Ping') {
          script = `def run():\n    import sys\n    if sys.os.platform() == "windows":\n        return sys.exec.run("ping", ["-n", "4", "8.8.8.8"])\n    else:\n        return sys.exec.run("ping", ["-c", "4", "8.8.8.8"])\nrun()`;
          onDiagnostic("Ping (8.8.8.8)", script);
      } else if (action === 'Traceroute') {
          script = `def run():\n    import sys\n    if sys.os.platform() == "windows":\n        return sys.exec.run("tracert", ["-d", "-h", "15", "8.8.8.8"])\n    else:\n        return sys.exec.run("traceroute", ["-m", "15", "-n", "8.8.8.8"])\nrun()`;
          onDiagnostic("Traceroute (8.8.8.8)", script);
      } else if (action === 'Netstat') {
          script = `def run():\n    if sys.os.platform() == "windows":\n        return sys.exec.run("netstat", ["-an", "-p", "tcp"])\n    else:\n        return sys.exec.run("netstat", ["-tuln"])\nrun()`;
          onDiagnostic("Netstat", script);
      } else if (action === 'SysLogs') {
          script = `def run():\n    plat = sys.os.platform()\n    if plat == "windows":\n        return sys.exec.run("powershell.exe", ["-Command", "Get-EventLog -LogName System -Newest 50 | Format-Table -HideTableHeaders"])\n    elif plat == "darwin":\n        return sys.exec.run("log", ["show", "--last", "5m", "--style", "syslog"])\n    else:\n        return sys.exec.run("journalctl", ["-n", "50", "--no-pager"])\nrun()`;
          onDiagnostic("Live System Logs", script);
      } else if (action === 'AuditSSH') {
          script = `def run():\n    plat = sys.os.platform()\n    if plat == "windows":\n        return sys.exec.run("powershell.exe", ["-Command", "Get-ChildItem -Path $env:USERPROFILE\\\\.ssh -Recurse | Select-Object FullName, LastWriteTime"])\n    elif plat == "darwin":\n        return sys.exec.run("sh", ["-c", "stat -f '%Sm   %N' ~/.ssh/* /etc/ssh/sshd_config 2>/dev/null || echo 'No SSH keys found'"])\n    else:\n        return sys.exec.run("sh", ["-c", "stat -c '%y   %n' ~/.ssh/* /etc/ssh/sshd_config 2>/dev/null || echo 'No SSH keys found'"])\nrun()`;
          onDiagnostic("Audit SSH Keys & Rotation", script);
      } else if (action === 'AuditSSL') {
          script = `def run():\n    plat = sys.os.platform()\n    if plat == "windows":\n        return sys.exec.run("powershell.exe", ["-Command", "Get-ChildItem -Path Cert:\\\\LocalMachine\\\\My | Select-Object Subject, NotAfter"])\n    else:\n        return sys.exec.run("sh", ["-c", "echo | openssl s_client -servername systemapi.io -connect systemapi.io:443 2>/dev/null | openssl x509 -noout -dates || echo 'OpenSSL not installed or connection failed'"])\nrun()`;
          onDiagnostic("Check SSL Expiry", script);
      }
  };

  const handleEmergencyAction = async (action) => {
    if (!window.confirm(`Are you sure you want to run an Emergency ${action} on ${host.hostname}?`)) return;
    
    let script = "";
    if (action === "Reboot") {
        script = `
def run():
    # Force OS shutdown/reboot via Sysscript API
    if sys.os.platform() == "windows":
        return sys.exec.run("shutdown", ["/r", "/t", "0", "/f"])
    else:
        return sys.exec.run("reboot", ["-f"])
run()`;
    } else if (action === "Kill Process") {
        const pid = window.prompt("Enter the PID to terminate:");
        if (!pid) return;
        script = `
def run():
    if sys.os.platform() == "windows":
        return sys.exec.run("taskkill", ["/F", "/PID", "${pid}"])
    else:
        return sys.exec.run("kill", ["-9", "${pid}"])
run()`;
    }

    try {
        await FleetAPI.executeScript(host.host_id, script, { allow_exec: true });
        alert(`Emergency ${action} sent to the agent's out-of-band execution engine successfully.`);
    } catch (e) {
        alert("Failed to send command.");
    }
  };

  return (
    <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: '20px', borderBottom: '1px solid var(--border-light)', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <div style={{ 
            width: '40px', height: '40px', borderRadius: '8px', 
            background: 'rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', justifyContent: 'center' 
          }}>
            <Server size={20} color={isOnline ? 'var(--accent-cyan)' : 'var(--text-muted)'} />
          </div>
          <div>
            <h3 style={{ fontSize: '1.1rem', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              {host.hostname}
              <span className={`status-indicator ${isOnline ? 'status-online' : 'status-offline'}`}></span>
            </h3>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              {host.os} • {host.platform}
            </div>
          </div>
        </div>
      </div>
      
      <div style={{ padding: '20px', flex: 1, display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {/* Mock telemetry blocks since the DB polling only gets basic host info */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          <MetricBox icon={<Cpu size={14} />} label="CPU" value={isOnline ? "0%" : "-"} />
          <MetricBox icon={<HardDrive size={14} />} label="RAM" value={isOnline ? "0%" : "-"} />
          <MetricBox icon={<Network size={14} />} label="Net" value={isOnline ? "0 B/s" : "-"} />
        </div>
        
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: 'auto' }}>
            {tags.map((t, i) => (
               <span key={i} style={{ fontSize: '0.75rem', background: 'rgba(255,255,255,0.1)', padding: '2px 8px', borderRadius: '12px' }}>{t}</span>
            ))}
        </div>
        
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '8px' }}>
            Last seen: {secondsAgo < 60 ? `${secondsAgo}s ago` : lastSeenDate.toLocaleString()}
        </div>
      </div>
      
      <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border-light)', display: 'flex', gap: '8px' }}>
         <button onClick={onConnect} disabled={!isOnline} className="btn btn-primary" style={{ flex: 1, opacity: isOnline ? 1 : 0.5 }}>
            <TerminalSquare size={16} /> Web PTY
         </button>
         
         <div style={{ position: 'relative' }}>
             <button disabled={!isOnline} onClick={(e) => {
                e.currentTarget.nextElementSibling.style.display = e.currentTarget.nextElementSibling.style.display === 'block' ? 'none' : 'block';
             }} className="btn btn-danger" style={{ opacity: isOnline ? 1 : 0.5, padding: '8px 12px' }} title="Emergency Actions">
                 <ShieldAlert size={16} />
             </button>
             
             <div style={{ 
                display: 'none', position: 'absolute', bottom: '100%', right: 0, 
                marginBottom: '8px', background: 'var(--bg-dark)', 
                border: '1px solid var(--border-light)', borderRadius: '6px', 
                padding: '8px', width: '200px', zIndex: 10,
                boxShadow: '0 4px 12px rgba(0,0,0,0.5)'
             }}>
                 <div style={{ fontSize: '0.7rem', color: 'var(--accent-cyan)', marginBottom: '4px', textTransform: 'uppercase', padding: '0 6px', letterSpacing: '0.5px' }}>Diagnostics</div>
                 <button onClick={() => handleDiagnosticAction("Ping")} className="btn btn-ghost" style={{ width: '100%', justifyContent: 'flex-start', padding: '6px', fontSize: '0.85rem' }}>Ping (8.8.8.8)</button>
                 <button onClick={() => handleDiagnosticAction("Traceroute")} className="btn btn-ghost" style={{ width: '100%', justifyContent: 'flex-start', padding: '6px', fontSize: '0.85rem' }}>Traceroute (8.8.8.8)</button>
                 <button onClick={() => handleDiagnosticAction("Netstat")} className="btn btn-ghost" style={{ width: '100%', justifyContent: 'flex-start', padding: '6px', fontSize: '0.85rem' }}>Netstat Map</button>
                 <button onClick={() => handleDiagnosticAction("SysLogs")} className="btn btn-ghost" style={{ width: '100%', justifyContent: 'flex-start', padding: '6px', fontSize: '0.85rem', color: 'var(--accent-cyan)' }}>Fetch System Logs</button>
                 
                 <div style={{ borderTop: '1px solid var(--border-light)', margin: '6px 0' }}></div>
                 
                 <div style={{ fontSize: '0.7rem', color: '#b967ff', marginBottom: '4px', textTransform: 'uppercase', padding: '0 6px', letterSpacing: '0.5px' }}>Security & Crypto</div>
                 <button onClick={() => handleDiagnosticAction("AuditSSH")} className="btn btn-ghost" style={{ width: '100%', justifyContent: 'flex-start', padding: '6px', fontSize: '0.85rem' }}>Audit SSH Keys</button>
                 <button onClick={() => handleDiagnosticAction("AuditSSL")} className="btn btn-ghost" style={{ width: '100%', justifyContent: 'flex-start', padding: '6px', fontSize: '0.85rem' }}>Check SSL Expiry</button>

                 <div style={{ borderTop: '1px solid var(--border-light)', margin: '6px 0' }}></div>
                 
                 <div style={{ fontSize: '0.7rem', color: 'var(--accent-red)', marginBottom: '4px', textTransform: 'uppercase', padding: '0 6px', letterSpacing: '0.5px' }}>Destructive</div>
                 <button onClick={() => handleEmergencyAction("Kill Process")} className="btn btn-ghost" style={{ width: '100%', justifyContent: 'flex-start', color: '#ffcc00', padding: '6px', fontSize: '0.85rem' }}>Kill Rogue PID</button>
                 <button onClick={() => handleEmergencyAction("Reboot")} className="btn btn-ghost" style={{ width: '100%', justifyContent: 'flex-start', color: 'var(--accent-red)', padding: '6px', fontSize: '0.85rem', marginTop: '4px' }}>Force Reboot OS</button>
             </div>
         </div>
      </div>
    </div>
  );
};

const MetricBox = ({ icon, label, value }) => (
    <div style={{ background: 'rgba(0,0,0,0.2)', padding: '10px', borderRadius: '6px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
            {icon} {label}
        </div>
        <div style={{ fontWeight: 600, fontSize: '0.95rem' }}>{value}</div>
    </div>
);

export default FleetDashboard;
