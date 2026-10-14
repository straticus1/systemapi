/**
 * SystemAPI.io - System/Infrastructure Management APIs
 * Provides system monitoring, infrastructure management, and automation APIs
 */

const fs = require('fs');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const session = require('express-session');
const promClient = require('prom-client');
require('dotenv').config({ path: '.env.production' });

// Threats: a production process that signs session cookies with a published
// default, and a database TLS dial that skips certificate checks. Does NOT
// print SESSION_SECRET. DB_SSL=disable is the local opt-out; a custom CA is
// DB_SSL_CA. rejectUnauthorized is never false.
const DEFAULT_SESSION_SECRET = 'default-secret-change-me';
if (process.env.NODE_ENV === 'production') {
    if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === DEFAULT_SESSION_SECRET) {
        console.error('[control] SESSION_SECRET is missing or still the default; refusing to start');
        process.exit(1);
    }
} else if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === DEFAULT_SESSION_SECRET) {
    console.warn('[control] SESSION_SECRET is the default; set a real secret before production');
}

function dbSsl(env) {
    if (env.DB_SSL === 'disable') return false;
    const ssl = { rejectUnauthorized: true, minVersion: 'TLSv1.3' };
    if (env.DB_SSL_CA) ssl.ca = fs.readFileSync(env.DB_SSL_CA);
    return ssl;
}

const app = express();
const PORT = process.env.PORT || 3003;

// Prometheus metrics registry
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

// Custom metrics
const hostTotalGauge = new promClient.Gauge({
    name: 'systemapi_hosts_total',
    help: 'Total number of registered hosts',
    registers: [register]
});

const hostOnlineGauge = new promClient.Gauge({
    name: 'systemapi_hosts_online',
    help: 'Number of hosts currently online',
    registers: [register]
});

const hostOfflineGauge = new promClient.Gauge({
    name: 'systemapi_hosts_offline',
    help: 'Number of hosts currently offline',
    registers: [register]
});

const cpuUsageGauge = new promClient.Gauge({
    name: 'systemapi_cpu_usage_percent',
    help: 'CPU usage percentage per host',
    labelNames: ['host_id', 'hostname'],
    registers: [register]
});

const memoryUsageGauge = new promClient.Gauge({
    name: 'systemapi_memory_usage_percent',
    help: 'Memory usage percentage per host',
    labelNames: ['host_id', 'hostname'],
    registers: [register]
});

const diskUsageGauge = new promClient.Gauge({
    name: 'systemapi_disk_usage_percent',
    help: 'Disk usage percentage per host',
    labelNames: ['host_id', 'hostname', 'path'],
    registers: [register]
});

const alertsActiveGauge = new promClient.Gauge({
    name: 'systemapi_alerts_active',
    help: 'Number of active alerts',
    registers: [register]
});

const executionsTotal = new promClient.Counter({
    name: 'systemapi_executions_total',
    help: 'Total number of sysscript executions',
    labelNames: ['status'],
    registers: [register]
});

// Threat intel source URLs (pull from cached data, not paid APIs)
const DNSSCIENCE_API = process.env.DNSSCIENCE_API_URL || 'https://api.dnsscience.io';
const DARKAPI_URL = process.env.DARKAPI_URL || 'https://api.darkapi.io';

// Middleware
app.use(helmet({
    contentSecurityPolicy: false
}));
app.use(compression());
morgan.token('urlpath', (req) => req.path || '-');
app.use(morgan(':remote-addr - :remote-user [:date[clf]] ":method :urlpath HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent"'));
app.use(cors({
    origin: [
        /\.afterdarksys\.com$/,
        /\.systemapi\.io$/,
        /\.auth\.afterdarksys\.com$/,
        'http://localhost:3000',
        'http://localhost:5173', // Vite dev server
        'https://systemapi.io'
    ],
    credentials: true
}));
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: true, limit: '256kb' }));

// Session middleware for OAuth
app.use(session({
    secret: process.env.SESSION_SECRET || DEFAULT_SESSION_SECRET,
    name: process.env.SESSION_COOKIE_NAME || 'systemapi-io_session',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.SESSION_COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production',
        httpOnly: process.env.SESSION_COOKIE_HTTPONLY !== 'false',
        sameSite: process.env.SESSION_COOKIE_SAMESITE || 'lax',
        maxAge: parseInt(process.env.SESSION_MAX_AGE || '86400') * 1000 // Default 24 hours
    }
}));

app.use(express.static('public'));

// ==============================================================================
// API PLAYGROUND SETUP (Optional - requires PostgreSQL and Redis)
// ==============================================================================
if (process.env.DB_PASSWORD && process.env.DB_PASSWORD !== '') {
    try {
        const { Pool } = require('pg');
        const { createClient } = require('redis');
        const createPlaygroundRouter = require('./playground/router');

        // Database connection (if using PostgreSQL)
        const dbPool = new Pool({
            host: process.env.DB_HOST || 'localhost',
            port: process.env.DB_PORT || 5432,
            database: process.env.DB_NAME || 'systemapi',
            user: process.env.DB_USER || 'systemapi',
            password: process.env.DB_PASSWORD
        });

        // Redis connection
        const redisClient = createClient({
            url: process.env.REDIS_URL || 'redis://localhost:6379'
        });

        redisClient.connect().then(() => {
            console.log('Redis connected for playground');
        }).catch(err => {
            console.error('Redis connection failed:', err.message);
        });

        // Playground configuration
        const playgroundConfig = {
            db: dbPool,
            redis: redisClient,
            keycloakURL: process.env.KEYCLOAK_URL || 'https://aftercloak.io',
            keycloakRealm: process.env.KEYCLOAK_REALM || 'afterdark',
            keycloakClientID: process.env.KEYCLOAK_CLIENT_ID || 'systemapi',
            apiSite: 'systemapi',
            baseURL: process.env.API_BASE_URL || 'https://api.systemapi.io'
        };

        // Register playground routes
        const playgroundRouter = createPlaygroundRouter(playgroundConfig);
        app.use('/playground', playgroundRouter);

        console.log('API Playground initialized at /playground');
    } catch (err) {
        console.error('Playground initialization failed:', err.message);
    }
} else {
    console.warn('Playground not configured (DB_PASSWORD not set) - playground endpoints disabled');
}



// OAuth routes
const oauthRouter = require('./routes/oauth');
app.use('/oauth', oauthRouter);

// Prometheus metrics endpoint
app.get('/metrics', async (req, res) => {
    try {
        // Update metrics from database
        const { rows } = await dbPool.query(`
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online,
                SUM(CASE WHEN status = 'offline' THEN 1 ELSE 0 END) as offline
            FROM playground_hosts
        `);

        if (rows[0]) {
            hostTotalGauge.set(parseInt(rows[0].total) || 0);
            hostOnlineGauge.set(parseInt(rows[0].online) || 0);
            hostOfflineGauge.set(parseInt(rows[0].offline) || 0);
        }

        res.set('Content-Type', register.contentType);
        res.end(await register.metrics());
    } catch (error) {
        console.error('Error generating metrics:', error);
        res.status(500).send('Error generating metrics');
    }
});

// Health endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'SystemAPI.io',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        authenticated: !!req.session.user
    });
});

// API docs/root endpoint - serve HTML for browsers, JSON for API clients
app.get('/', (req, res) => {
    const acceptsHtml = req.accepts('html');
    const acceptsJson = req.accepts('json');

    // If request prefers HTML (browser), serve the static index.html
    if (acceptsHtml && !req.query.format) {
        return res.sendFile('index.html', { root: './public' });
    }

    // Otherwise serve JSON (API clients, curl, etc.)
    res.json({
        service: 'SystemAPI.io',
        description: 'System/Infrastructure Management APIs',
        version: '1.0.0',
        endpoints: {
            health: '/health',
            systems: '/api/v1/systems',
            monitoring: '/api/v1/monitoring',
            automation: '/api/v1/automation',
            threat_intel: '/api/v1/threat-intel'
        },
        documentation: 'https://systemapi.io/docs',
        auth: {
            method: 'SSO',
            provider: 'login.afterdarksys.com'
        }
    });
});

// Area index routes for systems, monitoring and automation
require('./routes/catalog').mountCatalog(app);

// =============================================================================
// THREAT INTELLIGENCE API - Pulls from DNSScience/DarkAPI cached data
// =============================================================================

// Threat Intel API documentation
app.get('/api/v1/threat-intel', (req, res) => {
    res.json({
        message: 'Threat Intelligence API',
        description: 'Pulls from DNSScience.io and DarkAPI.io cached threat data',
        endpoints: [
            'GET /api/v1/threat-intel/ip/:ip - IP reputation lookup',
            'GET /api/v1/threat-intel/domain/:domain - Domain reputation lookup',
            'GET /api/v1/threat-intel/otx/:indicator - AlienVault OTX lookup',
            'GET /api/v1/threat-intel/crowdsec/:ip - CrowdSec IP lookup',
            'GET /api/v1/threat-intel/safebrowsing?url=... - Google Safe Browsing check',
            'POST /api/v1/threat-intel/check - Combined multi-source check'
        ]
    });
});

// IP Reputation check (from DarkAPI)
app.get('/api/v1/threat-intel/ip/:ip', async (req, res) => {
    try {
        const { ip } = req.params;
        const response = await fetch(`${DARKAPI_URL}/v1/ip/${ip}`, {
            headers: { 'X-API-Key': process.env.DARKAPI_KEY || '' }
        });
        const data = await response.json();
        res.json({ source: 'darkapi', ...data });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch IP reputation', message: error.message });
    }
});

// Domain reputation check (from DarkAPI)
app.get('/api/v1/threat-intel/domain/:domain', async (req, res) => {
    try {
        const { domain } = req.params;
        const response = await fetch(`${DARKAPI_URL}/v1/domain/${domain}`, {
            headers: { 'X-API-Key': process.env.DARKAPI_KEY || '' }
        });
        const data = await response.json();
        res.json({ source: 'darkapi', ...data });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch domain reputation', message: error.message });
    }
});

// AlienVault OTX check (from DNSScience cached)
app.get('/api/v1/threat-intel/otx/:indicator', async (req, res) => {
    try {
        const { indicator } = req.params;
        const type = req.query.type || 'domain';
        const response = await fetch(`${DNSSCIENCE_API}/api/threat-intel/alienvault?indicator=${encodeURIComponent(indicator)}&type=${type}`);
        const data = await response.json();
        res.json({ source: 'dnsscience-otx-cache', ...data });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch OTX data', message: error.message });
    }
});

// CrowdSec check (from DNSScience cached)
app.get('/api/v1/threat-intel/crowdsec/:ip', async (req, res) => {
    try {
        const { ip } = req.params;
        const response = await fetch(`${DNSSCIENCE_API}/api/threat-intel/crowdsec?ip=${encodeURIComponent(ip)}`);
        const data = await response.json();
        res.json({ source: 'dnsscience-crowdsec-cache', ...data });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch CrowdSec data', message: error.message });
    }
});

// Google Safe Browsing check (from DNSScience cached)
app.get('/api/v1/threat-intel/safebrowsing', async (req, res) => {
    try {
        const url = req.query.url;
        if (!url) return res.status(400).json({ error: 'URL parameter required' });
        const response = await fetch(`${DNSSCIENCE_API}/api/threat-intel/safebrowsing?url=${encodeURIComponent(url)}`);
        const data = await response.json();
        res.json({ source: 'dnsscience-safebrowsing-cache', ...data });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch Safe Browsing data', message: error.message });
    }
});

// Combined threat check (aggregates multiple sources)
app.post('/api/v1/threat-intel/check', async (req, res) => {
    try {
        const { indicator, type = 'domain' } = req.body;
        if (!indicator) return res.status(400).json({ error: 'Indicator required' });

        const results = { indicator, type, sources: {}, checked_at: new Date().toISOString() };

        // Fetch from DarkAPI
        try {
            const darkApiEndpoint = type === 'ip' ? 'ip' : 'domain';
            const darkRes = await fetch(`${DARKAPI_URL}/v1/${darkApiEndpoint}/${indicator}`, {
                headers: { 'X-API-Key': process.env.DARKAPI_KEY || '' }
            });
            results.sources.darkapi = await darkRes.json();
        } catch (e) { results.sources.darkapi = { error: e.message }; }

        // Fetch from DNSScience OTX cache
        try {
            const otxRes = await fetch(`${DNSSCIENCE_API}/api/threat-intel/alienvault?indicator=${encodeURIComponent(indicator)}&type=${type}`);
            results.sources.alienvault_otx = await otxRes.json();
        } catch (e) { results.sources.alienvault_otx = { error: e.message }; }

        // For IPs, also check CrowdSec
        if (type === 'ip') {
            try {
                const csRes = await fetch(`${DNSSCIENCE_API}/api/threat-intel/crowdsec?ip=${encodeURIComponent(indicator)}`);
                results.sources.crowdsec = await csRes.json();
            } catch (e) { results.sources.crowdsec = { error: e.message }; }
        }

        res.json(results);
    } catch (error) {
        res.status(500).json({ error: 'Combined threat check failed', message: error.message });
    }
});

// Initialize FleetManager
const { Pool } = require('pg');
const FleetManager = require('./playground/fleet');

let dbPool;
if (process.env.DB_PASSWORD && process.env.DB_PASSWORD !== '') {
    dbPool = new Pool({
        host: process.env.DB_HOST || 'db.systemapi.io',
        port: process.env.DB_PORT || 5432,
        user: process.env.DB_USER || 'playground_user',
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME || 'systemapi_playground',
        ssl: dbSsl(process.env)
    });
} else {
    // Local fallback for development & verification
    console.warn('Using local postgres DB settings (DB_PASSWORD not set).');
    dbPool = new Pool({
        connectionString: process.env.DATABASE_URL || 'postgres://localhost/postgres'
    });
}

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`SystemAPI.io listening on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
});

// Attach WebSocket multiplexer onto the HTTP server
console.log('Mounting SystemAPI.io Fleet Manager WebSockets...');
const prometheusMetrics = {
    cpuUsageGauge,
    memoryUsageGauge,
    diskUsageGauge,
    alertsActiveGauge,
    executionsTotal,
    hostTotalGauge,
    hostOnlineGauge,
    hostOfflineGauge
};
const fleetManager = new FleetManager(server, dbPool, 'systemapi', prometheusMetrics);
const control = require('./controlplane');
try {
    control.attach(app, fleetManager, process.env);
} catch (err) {
    console.error('[control] signer failed:', err.message);
    process.exit(1);
}
control.boot(fleetManager, process.env).catch((err) => {
    console.error('[control] boot failed:', err.message);
    if (process.env.NODE_ENV === 'production') process.exit(1);
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Not Found',
        message: `Endpoint ${req.method} ${req.path} not found`,
        documentation: 'https://systemapi.io/docs'
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'production' ? 'An error occurred' : err.message
    });
});


