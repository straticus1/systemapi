import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAppStore } from '../store';
import { Server, Cpu, HardDrive, Network, TerminalSquare, ShieldAlert } from 'lucide-react';
import { FleetAPI } from '../api';

const FleetDashboard = () => {
  const { hosts, fetchHosts, isLoadingHosts } = useAppStore();
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

  // REST poll for fleet state
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
  const [expanded, setExpanded] = useState(false);
  const [software, setSoftware] = useState([]);
  const [cves, setCves] = useState([]);
  const [isLoadingExtras, setIsLoadingExtras] = useState(false);

  useEffect(() => {
     if (!expanded) return;
     let ignore = false;
     Promise.all([
        FleetAPI.getSoftware(host.host_id),
        FleetAPI.getCVEs(host.host_id)
     ]).then(([sw, cv]) => {
        if (ignore) return;
        if (sw?.software) setSoftware(sw.software);
        if (cv?.cves) setCves(cv.cves);
     }).finally(() => {
        if (!ignore) setIsLoadingExtras(false);
     });
     return () => { ignore = true; };
  }, [expanded, host.host_id]);
  
  const lastSeenDate = new Date(host.last_seen_at);
  const [secondsAgo, setSecondsAgo] = useState(null);
  useEffect(() => {
    const timer = setTimeout(() => {
      const msAgo = Date.now() - new Date(host.last_seen_at).getTime();
      setSecondsAgo(Math.floor(msAgo / 1000));
    }, 0);
    return () => clearTimeout(timer);
  }, [host.last_seen_at]);
  
  // Parse tags
  const tags = host.tags || [];

  const handleDiagnosticAction = (action) => {
      let script = '';
      if (action === 'Ping') {
          script = 'r = sys.exec.run("ping", "-c", "4", "8.8.8.8")\nprint(r["output"])';
          onDiagnostic("Ping (8.8.8.8)", script);
      } else if (action === 'Traceroute') {
          script = 'r = sys.exec.run("traceroute", "-n", "-m", "15", "8.8.8.8")\nprint(r["output"])';
          onDiagnostic("Traceroute (8.8.8.8)", script);
      } else if (action === 'Netstat') {
          script = 'r = sys.exec.run("netstat", "-tuln")\nprint(r["output"])';
          onDiagnostic("Netstat", script);
      } else if (action === 'SysLogs') {
          script = 'r = sys.exec.run("journalctl", "-n", "50", "--no-pager")\nprint(r["output"])';
          onDiagnostic("Live System Logs", script);
      } else if (action === 'AuditSSH') {
          script = 'r = sys.exec.run("ls", "-l", "/etc/ssh")\nprint(r["output"])';
          onDiagnostic("Audit SSH Keys & Rotation", script);
      } else if (action === 'AuditSSL') {
          script = 'r = sys.exec.run("openssl", "version")\nprint(r["output"])';
          onDiagnostic("Check SSL Expiry", script);
      }
  };

  const handleEmergencyAction = async (action) => {
    if (!window.confirm(`Are you sure you want to run an Emergency ${action} on ${host.hostname}?`)) return;
    
    let script = "";
    if (action === "Reboot") {
        script = 'r = sys.exec.run("reboot", "-f")\nprint(r["output"])';
    } else if (action === "Kill Process") {
        const pid = window.prompt("Enter the PID to terminate:");
        if (!pid) return;
        if (!/^[0-9]+$/.test(pid)) {
            alert('Refused: PID must be digits only.');
            return;
        }
        script = 'r = sys.exec.run("kill", "-9", "' + pid + '")\nprint(r["output"])';
    }

    try {
        await FleetAPI.executeScript(host.host_id, script, { allow_exec: true });
        alert(`Emergency ${action} sent to the agent's out-of-band execution engine successfully.`);
    } catch {
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
            {host.tenant_id ? (
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{host.tenant_id}</div>
            ) : null}
          </div>
        </div>
      </div>
      
      <div style={{ padding: '20px', flex: 1, display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {/* Mock telemetry blocks since the DB polling only gets basic host info */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
          <MetricBox icon={<Cpu size={14} />} label="CPU" value={typeof host.cpu_percent === 'number' && Number.isFinite(host.cpu_percent) ? `${host.cpu_percent}%` : (isOnline ? "0%" : "-")} />
          <MetricBox icon={<HardDrive size={14} />} label="RAM" value={isOnline ? "0%" : "-"} />
          <MetricBox icon={<Network size={14} />} label="Net" value={isOnline ? "0 B/s" : "-"} />
        </div>
        <Sparkline values={host.sparkline} />
        
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: 'auto' }}>
            {tags.map((t, i) => (
               <span key={i} style={{ fontSize: '0.75rem', background: 'rgba(255,255,255,0.1)', padding: '2px 8px', borderRadius: '12px' }}>{t}</span>
            ))}
        </div>
        
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '8px' }}>
            Last seen: {secondsAgo != null && secondsAgo < 60 ? `${secondsAgo}s ago` : lastSeenDate.toLocaleString()}
        </div>
      </div>
      
      <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border-light)', display: 'flex', gap: '8px' }}>
         <button onClick={() => { if (!expanded) setIsLoadingExtras(true); setExpanded(!expanded); }} className="btn btn-ghost" style={{ flex: 1 }}>
            {expanded ? 'Hide Info' : 'Show Info'}
         </button>
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
      
      {expanded && (
        <div style={{ padding: '20px', borderTop: '1px solid var(--border-light)', background: 'rgba(0,0,0,0.3)', maxHeight: '300px', overflowY: 'auto' }}>
            <h4 style={{ color: 'var(--accent-cyan)', marginBottom: '12px' }}>Software & CVE Inventory</h4>
            {isLoadingExtras ? (
                <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Loading inventory...</div>
            ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                    {cves.length > 0 && (
                        <div>
                            <h5 style={{ color: 'var(--accent-red)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <ShieldAlert size={14} /> Found {cves.length} Vulnerabilities
                            </h5>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                                {cves.map(c => (
                                    <div key={c.id} style={{ fontSize: '0.8rem', background: 'rgba(255,0,0,0.1)', padding: '8px', borderRadius: '4px', borderLeft: '3px solid var(--accent-red)' }}>
                                        <strong>{c.cve_id}</strong> - {c.software_name} v{c.software_version}
                                        <div style={{ color: 'var(--text-muted)', marginTop: '4px' }}>{c.description?.substring(0,100)}...</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                    
                    <div>
                        <h5 style={{ color: 'var(--text-muted)', marginBottom: '8px' }}>Installed Software</h5>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
                            {software.length > 0 ? software.map(s => (
                                <div key={s.id} style={{ fontSize: '0.75rem', padding: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px' }}>
                                    <div style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}><strong>{s.name}</strong></div>
                                    <div style={{ color: 'var(--text-muted)' }}>v{s.version}</div>
                                </div>
                            )) : <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No software detected yet.</div>}
                        </div>
                    </div>
                </div>
            )}
        </div>
      )}
    </div>
  );
};

const Sparkline = ({ values }) => {
    const series = (Array.isArray(values) ? values : []).filter((n) => typeof n === 'number' && Number.isFinite(n)).slice(-20);
    if (series.length === 0) return null;
    const width = 100;
    const height = 28;
    const min = Math.min(...series);
    const max = Math.max(...series);
    const span = max - min || 1;
    const points = series.map((value, index) => {
        const x = series.length === 1 ? width / 2 : (index / (series.length - 1)) * width;
        const y = height - ((value - min) / span) * (height - 2) - 1;
        return `${x},${y}`;
    }).join(' ');
    return (
        <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" aria-hidden="true">
            <polyline fill="none" stroke="var(--accent-cyan)" strokeWidth="1.5" vectorEffect="non-scaling-stroke" points={points} />
        </svg>
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
