// Threats: starting the API without a signer, and running a schedule twice in
// the same UTC minute. Boot failure in production is fatal. Does NOT listen.
'use strict';

const { loadSigner } = require('./keys');
const { createRegistry } = require('./registry');
const { mount, deliverWebhooks } = require('./router');
const { issueLease } = require('./lease');

function attach(app, fleet, env = process.env, logger = console) {
  fleet.env = env;
  fleet.signer = loadSigner(env, logger);
  fleet.tickets = new Map();
  if (!fleet.registry) fleet.registry = null;
  mount(app, fleet);
  return fleet;
}

async function boot(fleet, env = process.env, logger = console) {
  fleet.registry = await createRegistry({ pool: fleet.db, env, logger });
  fleet.env = env;
  if (env.REDIS_URL) {
    try {
      const { createClient } = require('redis');
      const client = createClient({ url: env.REDIS_URL });
      client.on('error', (err) => logger.error('[control] redis error:', err.message));
      await client.connect();
      fleet.redis = client;
      logger.log('[control] redis telemetry channel ready');
    } catch (err) {
      logger.error('[control] redis unavailable:', err.message);
    }
  }
  // Async sysscript jobs: this instance listens for dispatch, cancel and
  // state events; every tick sweeps overdue jobs and runs the fallback scan.
  if (fleet.jobs) fleet.jobs.listen();
  const timer = setInterval(() => {
    tickSchedules(fleet, logger).catch((err) => logger.error('[control] schedule tick failed:', err.message));
    refreshGauges(fleet).catch((err) => logger.error('[control] gauge refresh failed:', err.message));
    if (fleet.jobs) fleet.jobs.tick().catch((err) => logger.error('[control] job tick failed:', err.message));
  }, 30000);
  if (typeof timer.unref === 'function') timer.unref();
  fleet.scheduleTimer = timer;
  return fleet.registry;
}

async function tickSchedules(fleet, logger = console) {
  if (!fleet.registry || !fleet.signer) return;
  const now = new Date();
  const minuteKey = now.toISOString().slice(0, 16);
  const due = await fleet.registry.dueSchedules(now);
  for (const job of due) {
    const marked = await fleet.registry.markSchedule(job.id, minuteKey);
    if (!marked) continue;
    try {
      const lease = issueLease(fleet.signer, {
        hostId: job.host_id,
        action: 'sysscript',
        payload: job.script,
        ttl: 60
      });
      await fleet.pushSysscript(job.host_id, job.script, { allow_exec: true }, `sch-${job.id}`, lease);
      await fleet.registry.appendAudit({
        tenant_id: job.tenant_id,
        host_id: job.host_id,
        actor: 'scheduler',
        action: 'schedule',
        payload: { schedule_id: job.id, minute: minuteKey }
      });
    } catch (err) {
      logger.error('[control] schedule run failed:', err.message);
    }
  }
}

async function refreshGauges(fleet) {
  if (!fleet.metrics || !fleet.registry || !fleet.metrics.hostTotalGauge) return;
  const counts = await fleet.registry.countHosts();
  fleet.metrics.hostTotalGauge.set(counts.total);
  fleet.metrics.hostOnlineGauge.set(fleet.connectedAgents ? fleet.connectedAgents.size : counts.online);
  fleet.metrics.hostOfflineGauge.set(Math.max(0, counts.total - (fleet.connectedAgents ? fleet.connectedAgents.size : counts.online)));
  if (fleet.metrics.alertsActiveGauge && typeof fleet.registry.countOpenAlerts === 'function') {
    // Process-wide count of status=open. Not a per-tenant view.
    fleet.metrics.alertsActiveGauge.set(await fleet.registry.countOpenAlerts());
  }
}

module.exports = {
  attach,
  boot,
  refreshGauges,
  deliverWebhooks
};
