import React, { useState } from 'react';
import { Settings, Plus, Play, BellRing, Webhook, Smartphone, Phone } from 'lucide-react';

const AlertsView = () => {
  const [rules, setRules] = useState([
    { id: 1, name: "High CPU Usage", metric: "cpu.percent", condition: ">", threshold: 90, action_type: "sms", action_target: "+15551234567" },
    { id: 2, name: "Critical Memory Exhaustion", metric: "mem.usedPercent", condition: ">", threshold: 95, action_type: "playbook", action_target: "auto_quarantine_script" },
    { id: 3, name: "Malware Detected (YARA)", metric: "sys.alerts.push", condition: "==", threshold: "malware_found", action_type: "playbook", action_target: "auto_nuke" },
    { id: 4, name: "AI Anomaly Detected", metric: "ai.anomaly_score", condition: ">", threshold: 0.85, action_type: "voice", action_target: "+15551234567" }
  ]);

  const [showNew, setShowNew] = useState(false);

  return (
    <div style={{ padding: '24px', flex: 1, overflowY: 'auto' }}>
      <div style={{ marginBottom: '32px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Settings color="var(--accent-red)" /> Alerting Engine & Automations
          </h1>
          <p style={{ color: 'var(--text-muted)' }}>
            Configure real-time telemetry triggers, AI Anomaly thresholds, and Automated Remediation Playbooks.
          </p>
        </div>
        
        <button className="btn btn-primary" onClick={() => setShowNew(true)}>
          <Plus size={16} /> New Rule
        </button>
      </div>

      <div style={{ display: 'grid', gap: '16px' }}>
        {rules.map(rule => (
          <div key={rule.id} className="glass-panel" style={{ padding: '20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
             <div>
                <h3 style={{ fontSize: '1.05rem', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {rule.name}
                    {rule.metric.startsWith('ai.') && <span style={{ fontSize: '0.7rem', background: 'rgba(139, 92, 246, 0.2)', color: 'var(--accent-purple)', padding: '2px 6px', borderRadius: '4px' }}>AI Baseline</span>}
                    {rule.action_type === 'playbook' && <span style={{ fontSize: '0.7rem', background: 'rgba(0, 240, 255, 0.2)', color: 'var(--accent-cyan)', padding: '2px 6px', borderRadius: '4px' }}>Auto-Remediation</span>}
                </h3>
                <div style={{ fontSize: '0.9rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span className="font-mono" style={{ background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: '4px' }}>
                        {rule.metric} {rule.condition} {rule.threshold}
                    </span>
                    <span>→</span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        {rule.action_type === 'sms' && <Smartphone size={14} />}
                        {rule.action_type === 'voice' && <Phone size={14} />}
                        {rule.action_type === 'playbook' && <Play size={14} />}
                        {rule.action_type === 'webhook' && <Webhook size={14} />}
                        {rule.action_target}
                    </span>
                </div>
             </div>
             
             <button className="btn btn-ghost" style={{ padding: '8px' }}>
                 Configure
             </button>
          </div>
        ))}

        {showNew && (
            <div className="glass-panel" style={{ padding: '20px', border: '1px solid var(--accent-blue)', background: 'rgba(59, 130, 246, 0.05)' }}>
                <h3 style={{ fontSize: '1rem', marginBottom: '16px' }}>Create New Alert Rule</h3>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '20px' }}>
                    <input type="text" placeholder="Rule Name" className="font-mono" style={{ width: '100%', padding: '10px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-light)', borderRadius: '6px', color: 'white', outline: 'none' }} />
                    <select style={{ width: '100%', padding: '10px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-light)', borderRadius: '6px', color: 'white', outline: 'none' }}>
                        <option value="sms">Send SMS via adstelco.io</option>
                        <option value="voice">Trigger Voice Call via adstelco.io</option>
                        <option value="playbook">Execute Remediation Playbook</option>
                    </select>
                </div>
                <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                    <button className="btn btn-ghost" onClick={() => setShowNew(false)}>Cancel</button>
                    <button className="btn btn-primary" onClick={() => setShowNew(false)}>Save Rule</button>
                </div>
            </div>
        )}
      </div>
    </div>
  );
};

export default AlertsView;
