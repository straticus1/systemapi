import React, { useEffect, useState } from 'react';
import Editor from '@monaco-editor/react';
import { Terminal, Send, Server, CheckCircle2, XCircle, Loader2, Square } from 'lucide-react';
import { useAppStore } from '../store';
import { FleetAPI } from '../api';
import { scriptOutcome, jobActive, jobOutcome, jobClock } from '../format';

const JOB_POLL_MS = 2000;
const DEFAULT_TIMEOUT_S = 300;
// The control plane's ceiling (SYSTEMAPI_SYSSCRIPT_JOB_MAX_S, at most 3600);
// a larger value comes back as bad_timeout.
const MAX_TIMEOUT_S = 3600;

const errorOf = (e) => e.response?.data?.error || e.message;

const DEFAULT_SCRIPT = `# Runs on the agent. Requires the exec entitlement.
r = sys.exec.run("uname", "-a")
print(r["output"])
`;

const SysscriptsView = () => {
  const { hosts } = useAppStore();
  const [code, setCode] = useState(DEFAULT_SCRIPT);
  const [selectedHost, setSelectedHost] = useState(hosts[0]?.host_id || '');
  const [loading, setLoading] = useState(false);
  // Legacy /execute result, used only when the host cannot take jobs.
  const [result, setResult] = useState(null);
  const [timeoutS, setTimeoutS] = useState(DEFAULT_TIMEOUT_S);
  // The job being watched: its latest view, when it was submitted (for the
  // clock), and the last poll or cancel error.
  const [job, setJob] = useState(null);
  const [submittedAt, setSubmittedAt] = useState(0);
  const [now, setNow] = useState(0);
  const [jobError, setJobError] = useState('');
  const [cancelling, setCancelling] = useState(false);
  const jobId = job?.job_id;
  const active = jobActive(job?.status);

  // Poll every 2 s while the job runs; each request finishes (or fails)
  // before the next is scheduled.
  useEffect(() => {
    if (!jobId || !active) return undefined;
    let stopped = false;
    let timer;
    const tick = async () => {
      try {
        const data = await FleetAPI.getJob(jobId);
        if (!stopped && data?.job) {
          setJob(data.job);
          setJobError('');
        }
      } catch (e) {
        if (!stopped) setJobError(errorOf(e));
      }
      if (!stopped) timer = setTimeout(tick, JOB_POLL_MS);
    };
    timer = setTimeout(tick, JOB_POLL_MS);
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [jobId, active]);

  // The elapsed/deadline clock.
  useEffect(() => {
    if (!active) return undefined;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [active]);
  
  // Boolean entitlements the control plane honours. The control plane clamps
  // path-scoped ones (allow_fs_read, allow_fs_write, allow_net_outbound,
  // allow_config_write, allow_service_reload) to booleans, which the agent
  // treats as no grant, so they cannot be granted from here or the API yet.
  const [allowExec, setAllowExec] = useState(true);
  const [allowContainers, setAllowContainers] = useState(false);
  const [allowK3s, setAllowK3s] = useState(false);

  // Submits a job. A host whose agent cannot take jobs (501
  // agent_unsupported) or a control plane with jobs off (503 jobs_disabled)
  // falls back to the synchronous /execute.
  const handleExecute = async () => {
    if (!selectedHost) return;
    setLoading(true);
    setResult(null);
    setJob(null);
    setJobError('');

    const entitlements = {
      allow_exec: allowExec,
      allow_containers: allowContainers,
      allow_k3s: allowK3s
    };
    try {
      const started = Date.now();
      const data = await FleetAPI.submitJob(selectedHost, code, entitlements, timeoutS);
      setSubmittedAt(started);
      setNow(started);
      setJob(data.job || { job_id: data.job_id, status: data.status, deadline_unix: data.deadline_unix });
    } catch (e) {
      const code501 = e.response?.status === 501 && e.response?.data?.error === 'agent_unsupported';
      const code503 = e.response?.status === 503 && e.response?.data?.error === 'jobs_disabled';
      if (!code501 && !code503) {
        setResult({ success: false, data: errorOf(e) });
      } else {
        try {
          setResult(scriptOutcome(await FleetAPI.executeScript(selectedHost, code, entitlements)));
        } catch (e2) {
          setResult({ success: false, data: errorOf(e2) });
        }
      }
    } finally {
      setLoading(false);
    }
  };

  const handleCancel = async () => {
    if (!jobId) return;
    setCancelling(true);
    try {
      const data = await FleetAPI.cancelJob(jobId);
      if (data?.job) setJob(data.job);
      setJobError('');
    } catch (e) {
      // 409 job_finished: it ended first; the next view shows how.
      if (e.response?.status === 409) {
        try {
          const data = await FleetAPI.getJob(jobId);
          if (data?.job) setJob(data.job);
        } catch (e2) {
          setJobError(errorOf(e2));
        }
      } else {
        setJobError(errorOf(e));
      }
    } finally {
      setCancelling(false);
    }
  };

  const outcome = job && !active ? jobOutcome(job) : null;
  const statusColor = active ? 'var(--accent-amber)' : outcome?.success ? 'var(--accent-green)' : 'var(--accent-red)';

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
          
          {/* Job Panel */}
          {job && (
             <div style={{ height: '250px', borderTop: '1px solid var(--border-light)', background: 'var(--bg-darker)', display: 'flex', flexDirection: 'column' }}>
                <div style={{ padding: '8px 16px', borderBottom: '1px solid var(--border-light)', display: 'flex', alignItems: 'center', gap: '8px', fontSize: '0.85rem', flexWrap: 'wrap' }}>
                    {active ? <Loader2 size={16} color={statusColor} /> : outcome?.success ? <CheckCircle2 size={16} color={statusColor} /> : <XCircle size={16} color={statusColor} />}
                    <span style={{ color: statusColor, fontWeight: 600 }}>{job.status}</span>
                    <span style={{ color: 'var(--text-muted)', fontFamily: 'monospace' }}>{job.job_id}</span>
                    <span style={{ color: 'var(--text-muted)' }}>
                      {active
                        ? jobClock(submittedAt, job.deadline_unix, now)
                        : typeof job.duration_ms === 'number' ? `${Math.round(job.duration_ms / 100) / 10}s` : ''}
                    </span>
                    {job.cancel_requested_at && active && <span style={{ color: 'var(--text-muted)' }}>cancel requested</span>}
                    {active && (
                      <button
                        onClick={handleCancel}
                        disabled={cancelling || !!job.cancel_requested_at}
                        className="btn btn-danger"
                        style={{ marginLeft: 'auto', padding: '4px 10px', fontSize: '0.8rem' }}
                      >
                        <Square size={12} /> {cancelling ? 'Cancelling...' : 'Cancel'}
                      </button>
                    )}
                </div>
                {jobError && (
                  <div style={{ padding: '8px 16px', color: 'var(--accent-red)', fontSize: '0.85rem' }}>{jobError}</div>
                )}
                <div style={{ padding: '16px', flex: 1, overflowY: 'auto', fontFamily: 'monospace', fontSize: '0.9rem', color: outcome?.success ? 'var(--text-code)' : 'var(--accent-red)', whiteSpace: 'pre-wrap' }}>
                    {active && <span style={{ color: 'var(--text-muted)' }}>Waiting for the job to finish...</span>}
                    {outcome?.notice && <div style={{ color: 'var(--text-muted)', marginBottom: outcome.data ? '8px' : 0 }}>{outcome.notice}</div>}
                    {outcome?.data}
                </div>
             </div>
          )}

          {/* Result Panel (legacy /execute) */}
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
            Grants for this run. Containers and k3s need the admin role. Path-scoped grants (files, outbound network, config writes, service reloads) cannot be granted from the control plane yet.
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

          <h3 style={{ fontSize: '1rem', marginBottom: '16px' }}>Timeout</h3>
          <label style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '32px' }}>
            <input
              type="number"
              min={1}
              max={MAX_TIMEOUT_S}
              value={timeoutS}
              onChange={e => setTimeoutS(Math.min(MAX_TIMEOUT_S, Math.max(1, Math.trunc(Number(e.target.value)) || 1)))}
              style={{
                  width: '100px', padding: '8px', background: 'rgba(0,0,0,0.4)',
                  border: '1px solid var(--border-light)', borderRadius: '6px',
                  color: 'white', outline: 'none'
              }}
            />
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>seconds; the agent stops the script after this</span>
          </label>

          <button 
            onClick={handleExecute}
            disabled={loading || active || !selectedHost}
            className="btn btn-primary" 
            style={{ width: '100%', padding: '12px' }}
          >
            <Send size={16} /> {loading ? 'Submitting...' : active ? 'Running...' : 'Run Script'}
          </button>
        </div>
      </div>
    </div>
  );
};

export default SysscriptsView;
