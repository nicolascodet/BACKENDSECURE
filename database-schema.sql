-- =============================================================================
-- ENTERPRISE BACKEND DATABASE SCHEMA
-- =============================================================================
-- This SQL creates the necessary tables for the enterprise backend
-- Compatible with PostgreSQL and Supabase

-- Enable UUID extension (for Supabase/PostgreSQL)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table (if not already exists)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255),
    hashed_password VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    is_government BOOLEAN DEFAULT FALSE,
    organization VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    
    -- Add indexes for performance
    CONSTRAINT users_email_unique UNIQUE (email)
);

-- Refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Add indexes for performance
    INDEX idx_refresh_tokens_token (token),
    INDEX idx_refresh_tokens_user_id (user_id),
    INDEX idx_refresh_tokens_expires_at (expires_at)
);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    endpoint VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    details JSONB,
    
    -- Add indexes for performance
    INDEX idx_audit_logs_user_id (user_id),
    INDEX idx_audit_logs_action (action),
    INDEX idx_audit_logs_timestamp (timestamp),
    INDEX idx_audit_logs_endpoint (endpoint)
);

-- API Keys table (optional)
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    api_key VARCHAR(255) UNIQUE NOT NULL,
    description VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE,
    
    -- Add indexes for performance
    INDEX idx_api_keys_api_key (api_key),
    INDEX idx_api_keys_user_id (user_id)
);

-- Password reset tokens table (optional)
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_used BOOLEAN DEFAULT FALSE,
    
    -- Add indexes for performance
    INDEX idx_password_reset_tokens_token (token),
    INDEX idx_password_reset_tokens_user_id (user_id),
    INDEX idx_password_reset_tokens_expires_at (expires_at)
);

-- Email monitoring tables (for future email processing features)
CREATE TABLE IF NOT EXISTS email_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email_address VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL, -- 'gmail', 'outlook', etc.
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_sync_at TIMESTAMP WITH TIME ZONE,
    sync_token TEXT, -- For incremental sync
    
    -- Add indexes for performance
    INDEX idx_email_accounts_user_id (user_id),
    INDEX idx_email_accounts_email_address (email_address),
    
    -- Ensure one email per user per provider
    CONSTRAINT email_accounts_user_email_provider_unique UNIQUE (user_id, email_address, provider)
);

CREATE TABLE IF NOT EXISTS email_messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_account_id UUID NOT NULL REFERENCES email_accounts(id) ON DELETE CASCADE,
    message_id VARCHAR(255) NOT NULL, -- Provider's message ID
    thread_id VARCHAR(255),
    subject TEXT,
    sender VARCHAR(255),
    recipient VARCHAR(255),
    received_at TIMESTAMP WITH TIME ZONE,
    body_text TEXT,
    body_html TEXT,
    is_processed BOOLEAN DEFAULT FALSE,
    is_government_related BOOLEAN DEFAULT FALSE,
    contract_keywords TEXT[], -- Array of detected keywords
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Add indexes for performance
    INDEX idx_email_messages_account_id (email_account_id),
    INDEX idx_email_messages_message_id (message_id),
    INDEX idx_email_messages_thread_id (thread_id),
    INDEX idx_email_messages_received_at (received_at),
    INDEX idx_email_messages_is_government_related (is_government_related),
    INDEX idx_email_messages_contract_keywords USING GIN (contract_keywords),
    
    -- Ensure unique message per account
    CONSTRAINT email_messages_account_message_unique UNIQUE (email_account_id, message_id)
);

-- Contract monitoring tables
CREATE TABLE IF NOT EXISTS contract_monitors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    keywords TEXT[] NOT NULL,
    agencies TEXT[],
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_check_at TIMESTAMP WITH TIME ZONE,
    
    -- Add indexes for performance
    INDEX idx_contract_monitors_user_id (user_id),
    INDEX idx_contract_monitors_keywords USING GIN (keywords),
    INDEX idx_contract_monitors_agencies USING GIN (agencies)
);

CREATE TABLE IF NOT EXISTS contract_opportunities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(500) NOT NULL,
    description TEXT,
    agency VARCHAR(255),
    posted_date TIMESTAMP WITH TIME ZONE,
    response_deadline TIMESTAMP WITH TIME ZONE,
    estimated_value DECIMAL(15,2),
    solicitation_number VARCHAR(255),
    naics_codes VARCHAR(255)[],
    keywords TEXT[],
    source_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Add indexes for performance
    INDEX idx_contract_opportunities_agency (agency),
    INDEX idx_contract_opportunities_posted_date (posted_date),
    INDEX idx_contract_opportunities_response_deadline (response_deadline),
    INDEX idx_contract_opportunities_keywords USING GIN (keywords),
    INDEX idx_contract_opportunities_naics_codes USING GIN (naics_codes),
    
    -- Ensure unique solicitation numbers
    CONSTRAINT contract_opportunities_solicitation_unique UNIQUE (solicitation_number)
);

-- Junction table for matched opportunities
CREATE TABLE IF NOT EXISTS contract_matches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    monitor_id UUID NOT NULL REFERENCES contract_monitors(id) ON DELETE CASCADE,
    opportunity_id UUID NOT NULL REFERENCES contract_opportunities(id) ON DELETE CASCADE,
    match_score DECIMAL(3,2), -- 0.00 to 1.00
    matched_keywords TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_notified BOOLEAN DEFAULT FALSE,
    
    -- Add indexes for performance
    INDEX idx_contract_matches_monitor_id (monitor_id),
    INDEX idx_contract_matches_opportunity_id (opportunity_id),
    INDEX idx_contract_matches_match_score (match_score),
    INDEX idx_contract_matches_created_at (created_at),
    
    -- Ensure unique matches
    CONSTRAINT contract_matches_monitor_opportunity_unique UNIQUE (monitor_id, opportunity_id)
);

-- =============================================================================
-- SECURITY POLICIES (Row Level Security for Supabase)
-- =============================================================================

-- Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE contract_monitors ENABLE ROW LEVEL SECURITY;
ALTER TABLE contract_opportunities ENABLE ROW LEVEL SECURITY;
ALTER TABLE contract_matches ENABLE ROW LEVEL SECURITY;

-- Users can only access their own data
CREATE POLICY "Users can view own profile" ON users
    FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can update own profile" ON users
    FOR UPDATE USING (auth.uid() = id);

-- Refresh tokens policies
CREATE POLICY "Users can view own refresh tokens" ON refresh_tokens
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own refresh tokens" ON refresh_tokens
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own refresh tokens" ON refresh_tokens
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own refresh tokens" ON refresh_tokens
    FOR DELETE USING (auth.uid() = user_id);

-- Audit logs policies (read-only for users)
CREATE POLICY "Users can view own audit logs" ON audit_logs
    FOR SELECT USING (auth.uid() = user_id);

-- API keys policies
CREATE POLICY "Users can manage own API keys" ON api_keys
    FOR ALL USING (auth.uid() = user_id);

-- Email accounts policies
CREATE POLICY "Users can manage own email accounts" ON email_accounts
    FOR ALL USING (auth.uid() = user_id);

-- Email messages policies
CREATE POLICY "Users can view own email messages" ON email_messages
    FOR SELECT USING (
        auth.uid() IN (
            SELECT user_id FROM email_accounts 
            WHERE id = email_messages.email_account_id
        )
    );

-- Contract monitors policies
CREATE POLICY "Users can manage own contract monitors" ON contract_monitors
    FOR ALL USING (auth.uid() = user_id);

-- Contract opportunities (public read, admin write)
CREATE POLICY "Public can view contract opportunities" ON contract_opportunities
    FOR SELECT USING (true);

-- Contract matches policies
CREATE POLICY "Users can view own contract matches" ON contract_matches
    FOR SELECT USING (
        auth.uid() IN (
            SELECT user_id FROM contract_monitors 
            WHERE id = contract_matches.monitor_id
        )
    );

-- =============================================================================
-- FUNCTIONS AND TRIGGERS
-- =============================================================================

-- Function to automatically clean up expired refresh tokens
CREATE OR REPLACE FUNCTION cleanup_expired_refresh_tokens()
RETURNS void AS $$
BEGIN
    DELETE FROM refresh_tokens 
    WHERE expires_at < NOW() AND is_active = false;
END;
$$ LANGUAGE plpgsql;

-- Function to automatically clean up old audit logs (keep last 90 days)
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs()
RETURNS void AS $$
BEGIN
    DELETE FROM audit_logs 
    WHERE timestamp < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;

-- Function to hash and validate passwords (if using database-level validation)
CREATE OR REPLACE FUNCTION validate_password_strength(password TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    -- Password must be at least 8 characters
    IF LENGTH(password) < 8 THEN
        RETURN FALSE;
    END IF;
    
    -- Must contain uppercase, lowercase, number, and special character
    IF NOT (password ~ '[A-Z]' AND 
            password ~ '[a-z]' AND 
            password ~ '[0-9]' AND 
            password ~ '[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]') THEN
        RETURN FALSE;
    END IF;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- INITIAL DATA AND INDEXES
-- =============================================================================

-- Create additional performance indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_lower ON users (LOWER(email));
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_composite ON audit_logs (user_id, timestamp DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_email_messages_composite ON email_messages (email_account_id, received_at DESC);

-- =============================================================================
-- MAINTENANCE JOBS (Optional - for automated cleanup)
-- =============================================================================

-- Note: These would typically be run by a cron job or scheduled task
-- Example cron job to run daily cleanup:
-- 0 2 * * * psql -d your_database -c "SELECT cleanup_expired_refresh_tokens(); SELECT cleanup_old_audit_logs();"

COMMENT ON TABLE users IS 'User accounts and profiles';
COMMENT ON TABLE refresh_tokens IS 'JWT refresh tokens for authentication';
COMMENT ON TABLE audit_logs IS 'Security and activity audit trail';
COMMENT ON TABLE api_keys IS 'API keys for service-to-service authentication';
COMMENT ON TABLE email_accounts IS 'Connected email accounts for monitoring';
COMMENT ON TABLE email_messages IS 'Processed email messages';
COMMENT ON TABLE contract_monitors IS 'User-defined contract monitoring rules';
COMMENT ON TABLE contract_opportunities IS 'Government contract opportunities';
COMMENT ON TABLE contract_matches IS 'Matched opportunities to user monitors';

-- Grant appropriate permissions (adjust as needed for your setup)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO authenticated;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO authenticated; 