# Grafana Integration for SystemAPI.io

SystemAPI.io now exports Prometheus metrics that can be visualized in Grafana.

## Available Metrics

### Fleet Metrics
- `systemapi_hosts_total` - Total number of registered hosts
- `systemapi_hosts_online` - Number of hosts currently online
- `systemapi_hosts_offline` - Number of hosts currently offline

### Per-Host Metrics
- `systemapi_cpu_usage_percent{host_id, hostname}` - CPU usage percentage
- `systemapi_memory_usage_percent{host_id, hostname}` - Memory usage percentage
- `systemapi_disk_usage_percent{host_id, hostname, path}` - Disk usage percentage per mount

### Alert & Execution Metrics
- `systemapi_alerts_active` - Number of active alerts
- `systemapi_executions_total{status}` - Total executions (labeled by success/failure)

### Node.js Process Metrics (Auto-collected)
- `process_cpu_user_seconds_total` - CPU time in user mode
- `process_cpu_system_seconds_total` - CPU time in system mode
- `process_resident_memory_bytes` - Resident memory size
- `nodejs_eventloop_lag_seconds` - Event loop lag
- `nodejs_heap_size_total_bytes` - Heap size
- And many more...

## Quick Setup

### 1. Start Prometheus

**Using Docker:**
```bash
docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v $(pwd)/grafana/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus
```

**Using binary:**
```bash
prometheus --config.file=grafana/prometheus.yml
```

Access Prometheus at: http://localhost:9090

### 2. Start Grafana

**Using Docker:**
```bash
docker run -d \
  --name grafana \
  -p 3001:3000 \
  grafana/grafana
```

Access Grafana at: http://localhost:3001 (default login: admin/admin)

### 3. Add Prometheus as a Data Source

1. Go to Configuration → Data Sources
2. Click "Add data source"
3. Select "Prometheus"
4. Set URL to: `http://localhost:9090` (or `http://host.docker.internal:9090` if using Docker)
5. Click "Save & Test"

### 4. Create Dashboards

#### Example: Fleet Overview Dashboard

**Panel 1: Total Hosts**
```promql
systemapi_hosts_total
```

**Panel 2: Host Status**
```promql
systemapi_hosts_online
systemapi_hosts_offline
```

**Panel 3: Average CPU Usage**
```promql
avg(systemapi_cpu_usage_percent)
```

**Panel 4: Average Memory Usage**
```promql
avg(systemapi_memory_usage_percent)
```

**Panel 5: CPU Usage by Host (Heatmap)**
```promql
systemapi_cpu_usage_percent
```
Visualization: Time series, Legend: `{{hostname}}`

**Panel 6: Top 5 CPU Consumers**
```promql
topk(5, systemapi_cpu_usage_percent)
```

**Panel 7: Disk Space Warnings**
```promql
systemapi_disk_usage_percent > 80
```

## Pre-built Dashboard (Coming Soon)

We'll provide pre-built Grafana dashboard JSON files:
- `fleet-overview.json` - High-level fleet status
- `host-detail.json` - Deep dive into a single host
- `alert-analytics.json` - Alert history and trends
- `execution-performance.json` - Sysscript execution analytics

## Advanced Queries

### Hosts with high CPU (>80%)
```promql
systemapi_cpu_usage_percent > 80
```

### Memory usage trend (24h)
```promql
avg_over_time(systemapi_memory_usage_percent[24h])
```

### Hosts offline for >1 hour
```promql
time() - last_over_time(systemapi_hosts_online[1h]) > 3600
```

### Disk filling up fast (>10% increase in 1h)
```promql
delta(systemapi_disk_usage_percent[1h]) > 10
```

## Alerting in Grafana

Create alerts based on metrics:

**Example: High CPU Alert**
- Metric: `systemapi_cpu_usage_percent`
- Condition: `WHEN avg() OF query(A, 5m) IS ABOVE 90`
- Alert: Send to Slack/PagerDuty/Email

**Example: Host Offline Alert**
- Metric: `systemapi_hosts_offline`
- Condition: `WHEN last() OF query(A, 1m) IS ABOVE 0`

## Next Steps

1. Set up long-term metrics storage (Prometheus retention or VictoriaMetrics)
2. Create custom dashboards for your use case
3. Set up Grafana alerting rules
4. Export dashboards and share with team

## Troubleshooting

**Metrics not showing up?**
- Check if SystemAPI.io is running: `curl http://localhost:3003/metrics`
- Verify Prometheus is scraping: Check http://localhost:9090/targets
- Ensure database is connected (some metrics require DB access)

**Stale data?**
- Metrics are updated every time telemetry is received from agents
- Fleet counts update on each `/metrics` request
- Ensure agents are connected and sending telemetry
