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
