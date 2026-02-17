-- AgentPass Database Schema
-- PostgreSQL 16+

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================
-- DID Registry
-- ============================================
CREATE TABLE agent_dids (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    did VARCHAR(256) UNIQUE NOT NULL,
    did_document JSONB NOT NULL,
    controller_did VARCHAR(256),
    network VARCHAR(32) NOT NULL DEFAULT 'testnet',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deactivated_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_agent_dids_did ON agent_dids(did);
CREATE INDEX idx_agent_dids_controller ON agent_dids(controller_did);
CREATE INDEX idx_agent_dids_network ON agent_dids(network);
CREATE INDEX idx_agent_dids_active ON agent_dids(is_active);

-- ============================================
-- Credentials
-- ============================================
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    credential_id VARCHAR(512) UNIQUE NOT NULL,
    issuer_did VARCHAR(256) NOT NULL REFERENCES agent_dids(did),
    subject_did VARCHAR(256) NOT NULL,
    credential_document JSONB NOT NULL,
    credential_type VARCHAR(128) NOT NULL DEFAULT 'AgentIdentityCredential',
    trust_level INTEGER NOT NULL DEFAULT 5 CHECK (trust_level BETWEEN 1 AND 10),
    capabilities TEXT[] NOT NULL DEFAULT '{}',
    is_revoked BOOLEAN NOT NULL DEFAULT false,
    revocation_reason TEXT,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_credentials_issuer ON credentials(issuer_did);
CREATE INDEX idx_credentials_subject ON credentials(subject_did);
CREATE INDEX idx_credentials_revoked ON credentials(is_revoked);
CREATE INDEX idx_credentials_expires ON credentials(expires_at);

-- ============================================
-- Audit Trail
-- ============================================
CREATE TABLE audit_trail (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_did VARCHAR(256) NOT NULL,
    action VARCHAR(128) NOT NULL,
    resource VARCHAR(512) NOT NULL,
    outcome VARCHAR(32) NOT NULL CHECK (outcome IN ('success', 'failure', 'denied', 'error')),
    credential_id VARCHAR(512),
    parent_agent_did VARCHAR(256),
    details JSONB DEFAULT '{}'::jsonb,
    signature JSONB,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_agent ON audit_trail(agent_did);
CREATE INDEX idx_audit_action ON audit_trail(action);
CREATE INDEX idx_audit_outcome ON audit_trail(outcome);
CREATE INDEX idx_audit_timestamp ON audit_trail(timestamp);
CREATE INDEX idx_audit_credential ON audit_trail(credential_id);

-- Partition audit trail by month for performance
-- (In production, use pg_partman for automatic partitioning)

-- ============================================
-- Revocation Registry
-- ============================================
CREATE TABLE revocation_registry (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    credential_id VARCHAR(512) NOT NULL REFERENCES credentials(credential_id),
    issuer_did VARCHAR(256) NOT NULL,
    reason TEXT,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    signature JSONB
);

CREATE INDEX idx_revocation_credential ON revocation_registry(credential_id);
CREATE INDEX idx_revocation_issuer ON revocation_registry(issuer_did);

-- ============================================
-- Organizations
-- ============================================
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(256) NOT NULL,
    org_did VARCHAR(256) UNIQUE,
    admin_email VARCHAR(256) NOT NULL,
    plan VARCHAR(32) NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'developer', 'team', 'business', 'enterprise')),
    compliance_frameworks TEXT[] DEFAULT '{}',
    max_agents INTEGER NOT NULL DEFAULT 50,
    api_key_hash VARCHAR(256),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_organizations_did ON organizations(org_did);

-- ============================================
-- Compliance Reports
-- ============================================
CREATE TABLE compliance_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    framework VARCHAR(32) NOT NULL,
    report_data JSONB NOT NULL,
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    period_from DATE NOT NULL,
    period_to DATE NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_compliance_org ON compliance_reports(organization_id);
CREATE INDEX idx_compliance_framework ON compliance_reports(framework);

-- ============================================
-- API Keys (for hosted service)
-- ============================================
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    key_hash VARCHAR(256) UNIQUE NOT NULL,
    key_prefix VARCHAR(16) NOT NULL, -- First 8 chars for identification
    name VARCHAR(128) NOT NULL,
    permissions TEXT[] NOT NULL DEFAULT '{read}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_org ON api_keys(organization_id);
