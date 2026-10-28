import React, { useEffect, useState } from 'react';
import { BellRing } from 'lucide-react';
import { FleetAPI } from '../api';

// Lists alert events from GET /api/v1/alerts. The control plane raises them from
// its z-score check on CPU and memory telemetry (posted to tenant webhooks) and
// from sys.alerts.push in a script (rule_name 'sysscript', with severity and message).
// There is no rule editor yet, so this view is read-only.
const AlertsView = () => {
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let ignore = false;
    FleetAPI.getAlerts()
      .then((data) => { if (!ignore) setAlerts(data.alerts || []); })
      .catch((e) => { if (!ignore) setError(e.response?.data?.error || e.message); })
      .finally(() => { if (!ignore) setLoading(false); });
    return () => { ignore = true; };
  }, []);

  return (
    <div style={{ padding: '24px', flex: 1, overflowY: 'auto' }}>
      <div style={{ marginBottom: '32px' }}>
        <h1 style={{ marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <BellRing color="var(--accent-red)" /> Alerts
        </h1>
        <p style={{ color: 'var(--text-muted)' }}>
          Anomalies the control plane detected in CPU and memory telemetry, and alerts scripts raised with sys.alerts.push. Custom alert rules are not available in the dashboard yet.
        </p>
      </div>

      {loading ? (
        <div style={{ color: 'var(--text-muted)' }}>Loading alerts...</div>
      ) : error ? (
        <div style={{ color: 'var(--accent-red)' }}>Could not load alerts: {error}</div>
      ) : alerts.length === 0 ? (
        <div className="glass-panel" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
          No alerts have been raised.
        </div>
      ) : (
        <div style={{ display: 'grid', gap: '16px' }}>
          {alerts.map(a => (
            <div key={a.id} className="glass-panel" style={{ padding: '20px' }}>
              <h3 style={{ fontSize: '1.05rem', marginBottom: '8px' }}>{a.rule_name}</h3>
              {a.message ? (
                <p className="font-mono" style={{ fontSize: '0.9rem', marginBottom: '8px', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{a.message}</p>
              ) : null}
              <div style={{ fontSize: '0.9rem', color: 'var(--text-muted)', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                {a.metric ? <span className="font-mono">{a.metric} = {a.value}</span> : null}
                {a.severity ? <span>{a.severity}</span> : null}
                <span>{a.host_id}</span>
                <span>{a.status}</span>
                <span>{new Date(a.created_at).toLocaleString()}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default AlertsView;
