/**
 * SystemAPI.io - System/Infrastructure Management APIs
 * Provides system monitoring, infrastructure management, and automation APIs
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 3003;

// Threat intel source URLs (pull from cached data, not paid APIs)
const DNSSCIENCE_API = process.env.DNSSCIENCE_API_URL || 'https://api.dnsscience.io';
const DARKAPI_URL = process.env.DARKAPI_URL || 'https://api.darkapi.io';

// Middleware
app.use(helmet({
    contentSecurityPolicy: false
}));
app.use(compression());
app.use(morgan('combined'));
app.use(cors({
    origin: [
        /\.afterdarksys\.com$/,
        /\.systemapi\.io$/,
        'http://localhost:3000',
        'https://systemapi.io'
    ],
    credentials: true
}));
app.use(express.json());
app.use(express.static('public'));

// Health endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'SystemAPI.io',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
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

// Systems API
app.get('/api/v1/systems', (req, res) => {
    res.json({
        message: 'Systems API',
        endpoints: [
            'GET /api/v1/systems - List systems',
            'GET /api/v1/systems/:id - Get system details',
            'POST /api/v1/systems - Create system',
            'PUT /api/v1/systems/:id - Update system',
            'DELETE /api/v1/systems/:id - Delete system'
        ]
    });
});

// Monitoring API
app.get('/api/v1/monitoring', (req, res) => {
    res.json({
        message: 'Monitoring API',
        endpoints: [
            'GET /api/v1/monitoring/metrics - Get metrics',
            'GET /api/v1/monitoring/alerts - List alerts',
            'POST /api/v1/monitoring/alerts - Create alert',
            'GET /api/v1/monitoring/dashboards - List dashboards'
        ]
    });
});

// Automation API
app.get('/api/v1/automation', (req, res) => {
    res.json({
        message: 'Automation API',
        endpoints: [
            'GET /api/v1/automation/workflows - List workflows',
            'POST /api/v1/automation/workflows - Create workflow',
            'POST /api/v1/automation/execute - Execute automation',
            'GET /api/v1/automation/jobs - List jobs'
        ]
    });
});

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

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`SystemAPI.io listening on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
});
