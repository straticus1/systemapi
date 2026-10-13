# SystemAPI.io - Feature Roadmap & Enhancement Proposals

The sections below are a historical proposal list from before the control plane. They are not product status. In particular, DarkStorage is not the audit of record, and nothing in this file is a completed integration. The wired surface is described in `README.md`.

## Current Data Available

SystemAPI.io collects rich telemetry from all connected agents:

### Real-time Metrics (Per Agent)
- **CPU**: Usage %, Core count
- **Memory**: Total, Used, Free, Usage %
- **Disk**: Path, Total, Used, Free, Usage % (per mount)
- **Network**: Bytes sent/received per second
- **Host**: Hostname, OS, Platform, Uptime
- **Timestamps**: Unix timestamp for every data point

### Execution & Audit Data
- **Sysscript Executions**: Complete audit trail with SHA256 hashing
- **Command Results**: stdout, stderr, execution time
- **WORM Logs**: Immutable logs stored in DarkStorage.io (S3-compatible)

### Alert & Incident Data
- **Rule Evaluations**: Metric, operator, threshold, triggered value
- **Alert History**: When, what, who
- **Integration Events**: SMS/Voice alerts via Adstelco.io

---

## 🎯 Priority 1: Metrics Visualization & Analytics

### 1.1 Grafana Integration
**Goal**: Provide professional-grade dashboards for fleet monitoring

**Implementation**:
```javascript
// Add Prometheus metrics exporter endpoint
app.get('/metrics', async (req, res) => {
  // Export metrics in Prometheus format
  const metrics = await generatePrometheusMetrics();
  res.set('Content-Type', 'text/plain');
  res.send(metrics);
});
```

**What to Add**:
- Prometheus metrics endpoint (`/metrics`)
- Time-series database integration (TimescaleDB or InfluxDB)
- Pre-built Grafana dashboards:
  - **Fleet Overview**: Total hosts, online/offline, aggregate resource usage
  - **Per-Host Detail**: CPU/Memory/Disk/Network charts
  - **Alert Dashboard**: Active alerts, alert history, MTTR (Mean Time To Recovery)
  - **Execution Analytics**: Sysscript execution frequency, success rates, error patterns
  - **Cost Analytics**: Resource utilization trends, optimization opportunities

**Database Schema**:
```sql
CREATE TABLE telemetry_timeseries (
    id BIGSERIAL PRIMARY KEY,
    host_id UUID NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DOUBLE PRECISION NOT NULL,
    tags JSONB,
    CONSTRAINT unique_metric UNIQUE (host_id, timestamp, metric_name)
);

CREATE INDEX idx_telemetry_time ON telemetry_timeseries (timestamp DESC);
CREATE INDEX idx_telemetry_host_time ON telemetry_timeseries (host_id, timestamp DESC);
CREATE INDEX idx_telemetry_metric ON telemetry_timeseries (metric_name, timestamp DESC);
```

**Grafana Dashboard Templates**:
- `grafana/fleet-overview.json`
- `grafana/host-detail.json`
- `grafana/alert-analytics.json`
- `grafana/sysscript-performance.json`

---

### 1.2 Historical Metrics Storage
**Goal**: Store metrics for long-term trend analysis

**Implementation**:
- Store telemetry in TimescaleDB (PostgreSQL extension for time-series)
- Configurable retention policies (7d, 30d, 90d, 1y)
- Data aggregation for older metrics (hourly → daily → monthly)
- Compression and partitioning for efficiency

**New Endpoints**:
```javascript
GET /api/v1/metrics/host/:hostId?from=<timestamp>&to=<timestamp>&metric=cpu.usage_percent
GET /api/v1/metrics/fleet/aggregate?from=<timestamp>&to=<timestamp>&metric=memory.used_percent
GET /api/v1/metrics/export?format=csv|json&from=<timestamp>&to=<timestamp>
```

---

### 1.3 Real-Time Dashboards Enhancement
**Goal**: Add rich visualizations to the existing React dashboard

**Components to Add**:
- **Sparkline Charts**: Inline CPU/Memory trends on fleet view (using Recharts or Chart.js)
- **Heatmap View**: Fleet-wide resource usage heatmap
- **Anomaly Highlights**: Visual indicators for hosts with unusual metrics
- **Compare View**: Side-by-side comparison of multiple hosts

**Libraries**:
- `recharts` or `chart.js` for React charts
- `react-grid-layout` for draggable dashboard widgets
- `react-chartjs-2` for advanced visualizations

---

## 🎯 Priority 2: Advanced Alerting & Automation

### 2.1 Machine Learning Anomaly Detection
**Goal**: Automatically detect unusual patterns without manual threshold configuration

**Implementation**:
- Baseline learning period (7 days minimum)
- Statistical anomaly detection (Z-score, IQR)
- Seasonal pattern recognition (daily/weekly cycles)
- Alert on deviations beyond 2-3 standard deviations

**Algorithm**:
```javascript
// Example: Simple moving average + standard deviation
function detectAnomaly(hostId, metric, currentValue, historicalData) {
  const mean = calculateMean(historicalData);
  const stdDev = calculateStdDev(historicalData);
  const zScore = (currentValue - mean) / stdDev;

  if (Math.abs(zScore) > 3) {
    return {
      anomaly: true,
      severity: Math.abs(zScore) > 5 ? 'critical' : 'warning',
      expectedRange: [mean - 2*stdDev, mean + 2*stdDev],
      actualValue: currentValue
    };
  }
  return { anomaly: false };
}
```

---

### 2.2 Alert Enrichment
**Goal**: Make alerts more actionable with context

**Features**:
- **Historical Context**: "CPU was 15% at this time yesterday, now 95%"
- **Correlated Metrics**: Show related metrics (high CPU + low disk IO = CPU-bound task)
- **Suggested Remediation**: Link to relevant Sysscripts or runbooks
- **Alert Grouping**: Combine related alerts to reduce noise
- **Escalation Policies**: Auto-escalate if not acknowledged in X minutes

**Database Schema**:
```sql
CREATE TABLE alert_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID REFERENCES playground_alerts(alert_id),
    host_id UUID REFERENCES playground_hosts(host_id),
    triggered_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    metric_value DOUBLE PRECISION,
    context JSONB, -- Historical data, correlated metrics
    status VARCHAR(50) DEFAULT 'active', -- active, acknowledged, resolved
    acknowledged_by VARCHAR(255),
    acknowledged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT
);
```

---

### 2.3 Playbook Library
**Goal**: Pre-built remediation scripts for common issues

**Examples**:
```python
# playbooks/high_cpu_investigation.star
def investigate_high_cpu():
    # Get top processes
    top_output = sys.exec.run("top -b -n 1 | head -20")

    # Check for runaway processes
    ps_output = sys.exec.run("ps aux --sort=-%cpu | head -10")

    # Get load average
    uptime = sys.exec.run("uptime")

    return {
        "top_processes": top_output,
        "cpu_hogs": ps_output,
        "load_average": uptime
    }

# playbooks/disk_cleanup.star
def cleanup_disk():
    # Find large files
    large_files = sys.exec.run("find /var/log -type f -size +100M")

    # Clean package cache
    if sys.os.platform == "linux":
        sys.exec.run("apt-get clean" if sys.os.has_command("apt-get") else "yum clean all")

    # Check disk usage after
    df = sys.exec.run("df -h")
    return {"cleaned": True, "disk_usage": df}
```

---

## 🎯 Priority 3: Cost Optimization & Insights

### 3.1 Resource Efficiency Dashboard
**Goal**: Identify underutilized hosts and optimization opportunities

**Metrics**:
- **Idle Hosts**: Hosts with <10% CPU and <30% memory for >24h
- **Right-Sizing**: Compare allocated resources vs actual usage
- **Waste Score**: Aggregate metric of resource waste
- **Cost Estimation**: If running on cloud (AWS/GCP/Azure), estimate wasted $$$

**Implementation**:
```javascript
GET /api/v1/analytics/efficiency
Response: {
  "idle_hosts": [
    {
      "host_id": "...",
      "hostname": "prod-worker-03",
      "avg_cpu_7d": 5.2,
      "avg_memory_7d": 22.1,
      "recommendation": "Consider downsizing or consolidating workloads",
      "potential_savings_monthly": "$47"
    }
  ],
  "optimization_opportunities": [
    {
      "type": "oversized",
      "hosts": 12,
      "potential_savings": "$560/month"
    }
  ]
}
```

---

### 3.2 Capacity Planning
**Goal**: Predict when you'll run out of resources

**Features**:
- Growth trend analysis (30d, 90d, 1y)
- Forecasting (linear regression, exponential smoothing)
- Alerts: "Disk will be full in 7 days at current growth rate"
- Recommendations: "Add 2 hosts in next 30 days to handle growth"

---

## 🎯 Priority 4: Security & Compliance

### 4.1 Execution Audit Dashboard
**Goal**: Full visibility into who ran what, when

**Features**:
- Searchable audit log UI
- Filter by user, host, time range, script
- Execution replay (show script + output)
- Anomaly detection (unusual execution patterns)
- Export for compliance (SOC2, HIPAA, PCI-DSS)

**Implementation**:
```javascript
GET /api/v1/audit/executions?user_id=...&from=...&to=...
GET /api/v1/audit/executions/:execution_id
GET /api/v1/audit/export?format=json|csv&from=...&to=...
```

---

### 4.2 Security Monitoring
**Goal**: Detect suspicious activity

**Alerts**:
- Unusual login patterns (new IP, unusual time)
- Privilege escalation attempts
- Unauthorized script executions
- Failed authentication spikes
- Data exfiltration patterns (unusual network egress)

**Database Schema**:
```sql
CREATE TABLE security_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL, -- login_failed, privilege_escalation, etc
    severity VARCHAR(20) NOT NULL, -- low, medium, high, critical
    host_id UUID,
    user_id VARCHAR(255),
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    details JSONB,
    investigated BOOLEAN DEFAULT FALSE,
    investigation_notes TEXT
);
```

---

### 4.3 Compliance Reports
**Goal**: Automated compliance reporting

**Reports**:
- Access log report (who accessed what)
- Change log report (all system changes)
- Security incident report
- Uptime SLA report
- Data retention compliance

---

## 🎯 Priority 5: Integrations & API Enhancements

### 5.1 Webhook Notifications
**Goal**: Send alerts to external systems

**Implementation**:
```javascript
POST /api/v1/webhooks
{
  "name": "Slack Production Alerts",
  "url": "https://hooks.slack.com/services/...",
  "events": ["alert.triggered", "host.offline", "execution.failed"],
  "filters": {
    "severity": ["high", "critical"],
    "hosts": ["prod-*"]
  }
}
```

**Supported Events**:
- `alert.triggered`
- `alert.resolved`
- `host.online`
- `host.offline`
- `execution.started`
- `execution.completed`
- `execution.failed`
- `anomaly.detected`

---

### 5.2 Third-Party Integrations
**Goal**: Connect with popular DevOps tools

**Integrations**:
- **Slack**: Alert notifications, command execution via slash commands
- **PagerDuty**: Incident management
- **Datadog**: Additional metrics forwarding
- **Jira**: Auto-create tickets for critical alerts
- **GitHub**: Link to relevant runbooks, track issue resolution
- **Terraform**: Auto-provision hosts based on load

---

### 5.3 Public API Enhancements
**Goal**: Make SystemAPI.io fully programmable

**New Endpoints**:
```javascript
// Bulk operations
POST /api/v1/fleet/bulk/execute
{
  "host_filter": { "tags": ["production"], "os": "linux" },
  "script": "df -h",
  "entitlements": { "allow_exec": true }
}

// Scheduled executions
POST /api/v1/schedules
{
  "name": "Nightly backup check",
  "cron": "0 2 * * *",
  "script": "check_backups.star",
  "targets": ["db-*"]
}

// API key scopes
POST /api/v1/api-keys
{
  "name": "Read-only monitoring",
  "scopes": ["metrics:read", "hosts:read"],
  "ip_whitelist": ["10.0.0.0/8"]
}
```

---

## 🎯 Priority 6: User Experience Improvements

### 6.1 Smart Search
**Goal**: Find hosts, scripts, alerts quickly

**Features**:
- Fuzzy search across hosts, tags, IPs
- Natural language: "show me all production linux hosts with high CPU"
- Saved searches
- Search history

---

### 6.2 Collaboration Features
**Goal**: Team-friendly fleet management

**Features**:
- **Teams & Permissions**: Role-based access (admin, operator, viewer)
- **Shared Scripts**: Team library of Sysscripts
- **Comments & Notes**: Annotate hosts, executions, alerts
- **Activity Feed**: "John executed cleanup.star on prod-db-01"
- **Runbooks**: Wiki-style documentation linked to hosts/alerts

---

### 6.3 Mobile App
**Goal**: Monitor fleet on the go

**Features**:
- View fleet status
- Acknowledge alerts
- Execute pre-approved scripts
- Terminal access (optional, security consideration)

---

## 🎯 Priority 7: Performance & Scalability

### 7.1 Metrics Aggregation
**Goal**: Handle 10,000+ hosts efficiently

**Implementation**:
- Pre-aggregate common queries (avg CPU per 5min, 1h, 1d)
- Materialized views for dashboard queries
- Redis caching for hot metrics
- Load balancing for WebSocket connections

---

### 7.2 Horizontal Scaling
**Goal**: Multi-instance deployment

**Features**:
- Redis pub/sub for WebSocket message routing
- Sticky sessions for terminal connections
- Shared PostgreSQL for state
- Load balancer configuration examples (nginx, HAProxy)

---

## Implementation Priority

### Phase 1 (Next 2-4 weeks)
1. **Metrics Storage**: Add TimescaleDB integration
2. **Grafana Dashboards**: Create 3-4 essential dashboards
3. **Historical API**: Add metrics query endpoints
4. **React Charts**: Add sparklines to fleet view

### Phase 2 (1-2 months)
1. **Alert Enrichment**: Add context to alerts
2. **Webhook Support**: Enable external notifications
3. **Audit Dashboard**: Searchable execution history
4. **Playbook Library**: 5-10 common remediation scripts

### Phase 3 (2-3 months)
1. **ML Anomaly Detection**: Baseline learning + detection
2. **Cost Analytics**: Efficiency dashboard
3. **Security Monitoring**: Suspicious activity detection
4. **Mobile App**: React Native or PWA

### Phase 4 (3-6 months)
1. **Collaboration**: Teams, permissions, shared resources
2. **Advanced Integrations**: Slack, PagerDuty, Jira
3. **Capacity Planning**: Growth forecasting
4. **Compliance Reports**: Automated reporting

---

## Quick Wins (Can Implement Today)

### 1. Prometheus Metrics Exporter
```javascript
// Add to server.js
const prometheusClient = require('prom-client');
const register = new prometheusClient.Registry();

const hostCount = new prometheusClient.Gauge({
  name: 'systemapi_hosts_total',
  help: 'Total number of registered hosts',
  registers: [register]
});

const hostOnline = new prometheusClient.Gauge({
  name: 'systemapi_hosts_online',
  help: 'Number of online hosts',
  registers: [register]
});

app.get('/metrics', async (req, res) => {
  const { rows } = await dbPool.query('SELECT COUNT(*) as total, SUM(CASE WHEN status = \'online\' THEN 1 ELSE 0 END) as online FROM playground_hosts');
  hostCount.set(parseInt(rows[0].total));
  hostOnline.set(parseInt(rows[0].online));

  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});
```

### 2. CSV Export for Metrics
```javascript
app.get('/api/v1/fleet/export', async (req, res) => {
  const { rows } = await dbPool.query('SELECT * FROM playground_hosts');
  const csv = convertToCSV(rows);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=fleet-export.csv');
  res.send(csv);
});
```

### 3. Webhook Notification (Simple)
```javascript
async function sendWebhook(url, event, data) {
  try {
    await axios.post(url, {
      event: event,
      timestamp: new Date().toISOString(),
      data: data
    });
  } catch (e) {
    console.error('Webhook failed:', e.message);
  }
}

// Use in alert trigger
async triggerIncident(rule, actualValue, hostname) {
  // ... existing code ...

  // Send webhook
  if (rule.webhook_url) {
    await sendWebhook(rule.webhook_url, 'alert.triggered', {
      rule: rule.name,
      host: hostname,
      value: actualValue,
      threshold: rule.threshold_value
    });
  }
}
```

---

## Technology Recommendations

### Metrics & Visualization
- **TimescaleDB**: PostgreSQL extension for time-series (easy migration)
- **Grafana**: Industry standard, free, powerful
- **Prometheus**: For metrics collection (optional, can export directly to Grafana)
- **Recharts**: React charting library (lightweight, good for dashboards)

### Analytics & ML
- **Simple-Statistics**: JavaScript library for basic stats
- **Brain.js**: Neural networks in JS (for anomaly detection)
- **TensorFlow.js**: Advanced ML (if needed)

### Real-time
- **Socket.io**: More reliable than raw WebSockets (auto-reconnect, etc)
- **Redis Pub/Sub**: For multi-instance WebSocket routing

### Storage
- **PostgreSQL + TimescaleDB**: Time-series data
- **Redis**: Caching, pub/sub, session store
- **S3/MinIO**: Already using for audit logs (DarkStorage)

---

## Estimated Impact

### Grafana Integration
- **User Value**: 10/10 (Essential for production monitoring)
- **Implementation Effort**: Medium (2-3 days)
- **Maintenance**: Low

### ML Anomaly Detection
- **User Value**: 8/10 (Reduces alert fatigue, catches unknown-unknowns)
- **Implementation Effort**: High (1-2 weeks)
- **Maintenance**: Medium (model tuning)

### Cost Analytics
- **User Value**: 9/10 (Direct $$$ impact)
- **Implementation Effort**: Medium (1 week)
- **Maintenance**: Low

### Webhook Integrations
- **User Value**: 9/10 (Essential for incident response)
- **Implementation Effort**: Low (1-2 days)
- **Maintenance**: Low

### Audit Dashboard
- **User Value**: 7/10 (Compliance requirement for enterprises)
- **Implementation Effort**: Medium (3-4 days)
- **Maintenance**: Low
