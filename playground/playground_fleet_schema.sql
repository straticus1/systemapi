-- SystemAPI.io Fleet Management & Sysscript Schema
-- Adds support for remote agents, os-agnostic scripts, and alert rules

-- 1. Hosts / Agents
CREATE TABLE IF NOT EXISTS playground_hosts (
    host_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id UUID REFERENCES playground_api_keys(key_id) ON DELETE CASCADE,
    api_site VARCHAR(50) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    os VARCHAR(50),
    platform VARCHAR(100),
    status VARCHAR(20) DEFAULT 'offline', -- 'online' or 'offline'
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    tags TEXT[] DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_hosts_key_api ON playground_hosts(key_id, api_site);

-- 2. Sysscripts (Starlark)
CREATE TABLE IF NOT EXISTS playground_scripts (
    script_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    api_site VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    script_content TEXT NOT NULL,
    entitlements JSONB NOT NULL DEFAULT '{"allow_fs_write": [], "allow_fs_read": [], "allow_net_outbound": [], "allow_exec": false}',
    is_public BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scripts_user ON playground_scripts(user_id, api_site);

-- 3. Alert Rules
CREATE TABLE IF NOT EXISTS playground_alerts (
    alert_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,
    api_site VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    metric VARCHAR(100) NOT NULL, -- 'cpu.usage_percent', 'memory.used_percent', 'sysscript.trigger'
    operator VARCHAR(20) NOT NULL, -- '>', '<', '=', '!=', 'contains'
    threshold_value VARCHAR(255) NOT NULL,
    action_type VARCHAR(50) NOT NULL, -- 'sms', 'voice', 'webhook'
    action_target VARCHAR(255) NOT NULL, -- e.g. '+15555555555' for adstelco
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alerts_user ON playground_alerts(user_id, api_site);

-- 4. Audit Log / Execution History
CREATE TABLE IF NOT EXISTS playground_script_executions (
    exec_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    script_id UUID REFERENCES playground_scripts(script_id) ON DELETE SET NULL,
    host_id UUID REFERENCES playground_hosts(host_id) ON DELETE CASCADE,
    triggered_by VARCHAR(255) NOT NULL, -- User ID or 'alert_engine'
    status VARCHAR(50) NOT NULL, -- 'pending', 'success', 'failed'
    output TEXT,
    error_message TEXT,
    executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Software Inventory
CREATE TABLE IF NOT EXISTS playground_host_software (
    id SERIAL PRIMARY KEY,
    host_id UUID REFERENCES playground_hosts(host_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(255) NOT NULL,
    architecture VARCHAR(50),
    last_detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT idx_host_software_unique UNIQUE(host_id, name, version)
);

CREATE INDEX IF NOT EXISTS idx_software_host ON playground_host_software(host_id);

-- 6. Software Vulnerabilities (CVEs)
CREATE TABLE IF NOT EXISTS playground_host_cves (
    id SERIAL PRIMARY KEY,
    host_id UUID REFERENCES playground_hosts(host_id) ON DELETE CASCADE,
    software_name VARCHAR(255) NOT NULL,
    software_version VARCHAR(255) NOT NULL,
    cve_id VARCHAR(50) NOT NULL,
    severity VARCHAR(50),
    description TEXT,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT idx_host_cves_unique UNIQUE(host_id, software_name, software_version, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_cves_host ON playground_host_cves(host_id);

