-- API Playground Schema for nerdapi.io
-- Separate tables to avoid conflicts with existing schema

-- ============================================================================
-- Playground API Keys (separate from main api_keys)
-- ============================================================================
CREATE TABLE IF NOT EXISTS playground_api_keys (
    id SERIAL PRIMARY KEY,
    key_id VARCHAR(64) UNIQUE NOT NULL,              -- Public key identifier (e.g., "ak_live_...")
    key_hash VARCHAR(255) NOT NULL,                   -- Bcrypt hash of the secret key
    user_id VARCHAR(255),                             -- User ID from Keycloak/afterdarksys (or local user.id as string)
    name VARCHAR(255) NOT NULL,                       -- User-friendly name for the key
    api_site VARCHAR(50) NOT NULL DEFAULT 'systemapi', -- API site identifier

    -- Lifecycle Management
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,                             -- NULL = never expires
    last_used_at TIMESTAMP,
    is_locked BOOLEAN DEFAULT FALSE,                  -- Manual lock/unlock
    is_active BOOLEAN DEFAULT TRUE,                   -- Soft delete flag

    -- Metadata
    description TEXT,
    ip_whitelist TEXT[],                              -- Optional IP restrictions
    allowed_endpoints TEXT[],                         -- Optional endpoint restrictions

    -- Indexes for fast lookups
    CONSTRAINT playground_api_keys_key_id_unique UNIQUE (key_id)
);

CREATE INDEX idx_playground_api_keys_user_id ON playground_api_keys(user_id);
CREATE INDEX idx_playground_api_keys_key_id ON playground_api_keys(key_id);
CREATE INDEX idx_playground_api_keys_api_site ON playground_api_keys(api_site);
CREATE INDEX idx_playground_api_keys_active ON playground_api_keys(is_active, is_locked);

-- ============================================================================
-- Playground Credits & Tiers
-- ============================================================================
CREATE TABLE IF NOT EXISTS playground_credits (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,                    -- User ID from Keycloak/afterdarksys (or local user.id as string)
    api_site VARCHAR(50) NOT NULL DEFAULT 'systemapi', -- API site identifier

    -- Credit Allocation
    tier VARCHAR(50) DEFAULT 'free',                  -- free, starter, professional, enterprise
    daily_limit INTEGER NOT NULL,                     -- Max requests per day
    monthly_limit INTEGER,                            -- Optional monthly cap

    -- Current Usage
    daily_used INTEGER DEFAULT 0,
    monthly_used INTEGER DEFAULT 0,

    -- Reset Tracking
    last_daily_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_monthly_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT playground_credits_user_site_unique UNIQUE (user_id, api_site)
);

CREATE INDEX idx_playground_credits_user_id ON playground_credits(user_id);
CREATE INDEX idx_playground_credits_tier ON playground_credits(tier);
CREATE INDEX idx_playground_credits_site ON playground_credits(api_site);

-- ============================================================================
-- Playground Usage Tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS playground_usage (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(255),                             -- NULL for anonymous users
    api_key_id VARCHAR(64),                           -- NULL if using session auth
    api_site VARCHAR(50) NOT NULL DEFAULT 'systemapi',

    -- Request Details
    endpoint VARCHAR(500) NOT NULL,
    http_method VARCHAR(10) NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Response Details
    status_code INTEGER,
    response_time_ms INTEGER,                         -- Latency tracking

    -- Metadata
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,

    CONSTRAINT playground_usage_check_method CHECK (http_method IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'))
);

CREATE INDEX idx_playground_usage_user_id ON playground_usage(user_id);
CREATE INDEX idx_playground_usage_api_key_id ON playground_usage(api_key_id);
CREATE INDEX idx_playground_usage_timestamp ON playground_usage(request_timestamp DESC);
CREATE INDEX idx_playground_usage_site ON playground_usage(api_site);
CREATE INDEX idx_playground_usage_endpoint ON playground_usage(endpoint);

-- ============================================================================
-- Anonymous User Rate Limiting (Redis-backed, PostgreSQL fallback)
-- ============================================================================
CREATE TABLE IF NOT EXISTS anonymous_rate_limits (
    id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL,
    api_site VARCHAR(50) NOT NULL DEFAULT 'systemapi',

    -- Daily Tracking
    daily_requests INTEGER DEFAULT 0,
    last_daily_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Metadata
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT anonymous_rate_limits_ip_site_unique UNIQUE (ip_address, api_site)
);

CREATE INDEX idx_anonymous_rate_limits_ip ON anonymous_rate_limits(ip_address);
CREATE INDEX idx_anonymous_rate_limits_site ON anonymous_rate_limits(api_site);

-- ============================================================================
-- Tier Configuration (Reference Table)
-- ============================================================================
CREATE TABLE IF NOT EXISTS playground_tiers (
    id SERIAL PRIMARY KEY,
    tier_name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,

    -- Limits
    daily_limit INTEGER NOT NULL,
    monthly_limit INTEGER,

    -- Features
    code_snippets BOOLEAN DEFAULT TRUE,
    api_explorer BOOLEAN DEFAULT TRUE,
    saved_requests BOOLEAN DEFAULT FALSE,
    team_sharing BOOLEAN DEFAULT FALSE,

    -- Pricing (for display purposes)
    price_monthly DECIMAL(10, 2),
    price_annual DECIMAL(10, 2),

    -- Metadata
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Default tier configuration for nerdapi.io
INSERT INTO playground_tiers (tier_name, display_name, daily_limit, monthly_limit, price_monthly, price_annual, description) VALUES
    ('anonymous', 'Anonymous', 50, NULL, 0.00, 0.00, 'No account required - 50 tests per day'),
    ('free', 'Free Account', 100, 3000, 0.00, 0.00, 'Sign up for free - 100 tests per day'),
    ('starter', 'Starter', 1000, 30000, 9.99, 99.00, 'Perfect for individual developers'),
    ('professional', 'Professional', 10000, 300000, 29.99, 299.00, 'For growing teams and projects'),
    ('enterprise', 'Enterprise', 100000, NULL, 99.99, 999.00, 'Unlimited testing for large organizations')
ON CONFLICT (tier_name) DO NOTHING;

-- ============================================================================
-- Saved Playground Requests (Premium Feature)
-- ============================================================================
CREATE TABLE IF NOT EXISTS saved_requests (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    api_site VARCHAR(50) NOT NULL DEFAULT 'systemapi',

    -- Request Configuration
    name VARCHAR(255) NOT NULL,
    description TEXT,
    endpoint VARCHAR(500) NOT NULL,
    http_method VARCHAR(10) NOT NULL,
    headers JSONB,
    query_params JSONB,
    body JSONB,

    -- Organization
    folder VARCHAR(255),
    tags TEXT[],
    is_public BOOLEAN DEFAULT FALSE,

    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_executed_at TIMESTAMP
);

CREATE INDEX idx_saved_requests_user_id ON saved_requests(user_id);
CREATE INDEX idx_saved_requests_site ON saved_requests(api_site);
CREATE INDEX idx_saved_requests_folder ON saved_requests(folder);
CREATE INDEX idx_saved_requests_tags ON saved_requests USING GIN(tags);

-- ============================================================================
-- Functions & Triggers
-- ============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_playground_credits_updated_at BEFORE UPDATE ON playground_credits
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_saved_requests_updated_at BEFORE UPDATE ON saved_requests
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Auto-reset daily/monthly counters
CREATE OR REPLACE FUNCTION reset_playground_credits()
RETURNS void AS $$
BEGIN
    -- Reset daily counters (if last reset was more than 24 hours ago)
    UPDATE playground_credits
    SET daily_used = 0,
        last_daily_reset = CURRENT_TIMESTAMP
    WHERE last_daily_reset < CURRENT_TIMESTAMP - INTERVAL '1 day';

    -- Reset monthly counters (if last reset was more than 30 days ago)
    UPDATE playground_credits
    SET monthly_used = 0,
        last_monthly_reset = CURRENT_TIMESTAMP
    WHERE last_monthly_reset < CURRENT_TIMESTAMP - INTERVAL '30 days';

    -- Reset anonymous rate limits
    UPDATE anonymous_rate_limits
    SET daily_requests = 0,
        last_daily_reset = CURRENT_TIMESTAMP
    WHERE last_daily_reset < CURRENT_TIMESTAMP - INTERVAL '1 day';
END;
$$ LANGUAGE plpgsql;

-- Clean up old usage records (keep 90 days)
CREATE OR REPLACE FUNCTION cleanup_old_playground_usage()
RETURNS void AS $$
BEGIN
    DELETE FROM playground_usage
    WHERE request_timestamp < CURRENT_TIMESTAMP - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;
