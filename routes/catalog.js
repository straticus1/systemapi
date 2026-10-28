/**
 * Area index routes (/api/v1/systems, /monitoring, /automation).
 * Each lists only routes the control plane actually serves;
 * tests/catalog.test.js fails if one is listed but not mounted.
 */

const CATALOG = {
    systems: {
        message: 'Systems API: registered hosts',
        endpoints: [
            'GET /api/v1/fleet - List hosts',
            'GET /api/v1/fleet/export - Export hosts as JSON or CSV',
            'GET /api/v1/fleet/:hostId/software - Installed software',
            'GET /api/v1/fleet/:hostId/cves - Known CVEs for installed software'
        ]
    },
    monitoring: {
        message: 'Monitoring API: telemetry and alerts',
        endpoints: [
            'GET /api/v1/fleet/:hostId/metrics - Aggregated metric series',
            'GET /api/v1/fleet/:hostId/forecast - Linear forecast of a metric',
            'GET /api/v1/fleet/:hostId/anomalies - Z-score check of a metric',
            'GET /api/v1/alerts - List alert events',
            'POST /api/v1/alerts/:id/ack - Acknowledge an alert',
            'POST /api/v1/alerts/:id/resolve - Resolve an alert'
        ]
    },
    automation: {
        message: 'Automation API: Sysscript execution and playbooks',
        endpoints: [
            'POST /api/v1/fleet/:hostId/execute - Run a Sysscript on one host',
            'POST /api/v1/fleet/execute - Run a Sysscript on up to 50 hosts',
            'POST /api/v1/fleet/:hostId/jobs - Submit an async Sysscript job',
            'GET /api/v1/jobs/:jobId - Job status (output for the submitter or a tenant admin)',
            'GET /api/v1/jobs - List jobs of tenants where exec:run is held',
            'POST /api/v1/jobs/:jobId/cancel - Cancel a job',
            'GET /api/v1/playbooks - List playbooks',
            'POST /api/v1/playbooks/:id/run - Run a playbook',
            'GET /api/v1/schedules - List schedules',
            'POST /api/v1/schedules - Create a schedule'
        ]
    }
};

function mountCatalog(app) {
    for (const [area, body] of Object.entries(CATALOG)) {
        app.get(`/api/v1/${area}`, (req, res) => res.json(body));
    }
}

module.exports = { CATALOG, mountCatalog };
