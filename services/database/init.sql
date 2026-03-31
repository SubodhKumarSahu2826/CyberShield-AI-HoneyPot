-- ============================================================
-- AI-Adaptive Honeypot Platform
-- Database Initialization Script (Day 3 Update)
-- ============================================================

-- Ensure UUID extension is available
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- REQUESTS TABLE
-- Stores every captured HTTP request from the honeypot
-- ============================================================
CREATE TABLE IF NOT EXISTS requests (
    id               SERIAL PRIMARY KEY,
    source_ip        TEXT        NOT NULL,
    method           TEXT        NOT NULL,
    endpoint         TEXT        NOT NULL,
    headers          JSONB       NOT NULL DEFAULT '{}',
    payload          TEXT        NOT NULL DEFAULT '',
    timestamp        TIMESTAMP   NOT NULL DEFAULT NOW(),
    -- Day 2: Rule-based detection results
    detection_status TEXT        NOT NULL DEFAULT 'suspicious',
    attack_type      TEXT        NOT NULL DEFAULT 'unknown',
    detection_score  REAL        NOT NULL DEFAULT 0.2,
    -- Day 3: Session tracking + dataset fields
    session_id          TEXT        NOT NULL DEFAULT '',
    response_generated  BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Day 4: AI classifier fields
    ai_attack_type      TEXT        NOT NULL DEFAULT '',
    ai_confidence_score REAL        NOT NULL DEFAULT 0.0,
    -- Day 4: Threat Intelligence
    country             TEXT        NOT NULL DEFAULT '',
    city                TEXT        NOT NULL DEFAULT '',
    asn                 TEXT        NOT NULL DEFAULT '',
    reputation_score    INTEGER     NOT NULL DEFAULT 0,
    reputation_tags     JSONB       NOT NULL DEFAULT '[]',
    -- Day 6: Milestone 2A dynamic deception
    response            TEXT        NOT NULL DEFAULT '',
    response_type       TEXT        NOT NULL DEFAULT '',
    -- Milestone 2B behaviour profiling
    attacker_score      REAL        NOT NULL DEFAULT 0.0,
    attacker_type       TEXT        NOT NULL DEFAULT '',
    attack_pattern      TEXT        NOT NULL DEFAULT ''
);

-- Idempotent upgrades: add columns safely to existing databases
ALTER TABLE requests ADD COLUMN IF NOT EXISTS detection_status    TEXT    NOT NULL DEFAULT 'suspicious';
ALTER TABLE requests ADD COLUMN IF NOT EXISTS attack_type         TEXT    NOT NULL DEFAULT 'unknown';
ALTER TABLE requests ADD COLUMN IF NOT EXISTS detection_score     REAL    NOT NULL DEFAULT 0.2;
ALTER TABLE requests ADD COLUMN IF NOT EXISTS session_id          TEXT    NOT NULL DEFAULT '';
ALTER TABLE requests ADD COLUMN IF NOT EXISTS response_generated  BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE requests ADD COLUMN IF NOT EXISTS ai_attack_type      TEXT    NOT NULL DEFAULT '';
ALTER TABLE requests ADD COLUMN IF NOT EXISTS ai_confidence_score REAL    NOT NULL DEFAULT 0.0;
ALTER TABLE requests ADD COLUMN IF NOT EXISTS country             TEXT    NOT NULL DEFAULT '';
ALTER TABLE requests ADD COLUMN IF NOT EXISTS city                TEXT    NOT NULL DEFAULT '';
ALTER TABLE requests ADD COLUMN IF NOT EXISTS asn                 TEXT    NOT NULL DEFAULT '';
ALTER TABLE requests ADD COLUMN IF NOT EXISTS reputation_score    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE requests ADD COLUMN IF NOT EXISTS reputation_tags     JSONB   NOT NULL DEFAULT '[]';
ALTER TABLE requests ADD COLUMN IF NOT EXISTS response            TEXT    NOT NULL DEFAULT '';
ALTER TABLE requests ADD COLUMN IF NOT EXISTS response_type       TEXT    NOT NULL DEFAULT '';
ALTER TABLE requests ADD COLUMN IF NOT EXISTS attacker_score      REAL    NOT NULL DEFAULT 0.0;
ALTER TABLE requests ADD COLUMN IF NOT EXISTS attacker_type       TEXT    NOT NULL DEFAULT '';
ALTER TABLE requests ADD COLUMN IF NOT EXISTS attack_pattern      TEXT    NOT NULL DEFAULT '';

-- ============================================================
-- SESSIONS TABLE (Day 3)
-- Tracks attacker sessions across multiple requests
-- ============================================================
CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT        PRIMARY KEY,
    source_ip     TEXT        NOT NULL,
    first_seen    TIMESTAMP   NOT NULL,
    last_seen     TIMESTAMP   NOT NULL,
    request_count INTEGER     NOT NULL DEFAULT 1,
    attack_types  JSONB       NOT NULL DEFAULT '[]'
);

-- ============================================================
-- INDEXES
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_requests_source_ip        ON requests (source_ip);
CREATE INDEX IF NOT EXISTS idx_requests_timestamp        ON requests (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_requests_endpoint         ON requests (endpoint);
CREATE INDEX IF NOT EXISTS idx_requests_method           ON requests (method);
-- Day 2: Detection indexes
CREATE INDEX IF NOT EXISTS idx_requests_detection_status ON requests (detection_status);
CREATE INDEX IF NOT EXISTS idx_requests_attack_type      ON requests (attack_type);
CREATE INDEX IF NOT EXISTS idx_requests_score            ON requests (detection_score DESC);
-- Day 3: Session correlation index
CREATE INDEX IF NOT EXISTS idx_requests_session_id       ON requests (session_id);
-- GIN index for JSONB header search
CREATE INDEX IF NOT EXISTS idx_requests_headers_gin      ON requests USING GIN (headers);

-- Session table indexes
CREATE INDEX IF NOT EXISTS idx_sessions_source_ip    ON sessions (source_ip);
CREATE INDEX IF NOT EXISTS idx_sessions_last_seen    ON sessions (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_request_count ON sessions (request_count DESC);

-- ============================================================
-- ATTACKER STATS VIEW
-- ============================================================
CREATE OR REPLACE VIEW attacker_stats AS
SELECT
    COUNT(*)                    AS total_requests,
    COUNT(DISTINCT source_ip)   AS unique_ips,
    MAX(timestamp)              AS last_seen
FROM requests;

-- ============================================================
-- TOP ENDPOINTS VIEW
-- ============================================================
CREATE OR REPLACE VIEW top_endpoints AS
SELECT
    endpoint,
    COUNT(*) AS hit_count
FROM requests
GROUP BY endpoint
ORDER BY hit_count DESC
LIMIT 20;

-- ============================================================
-- TOP SOURCE IPs VIEW
-- ============================================================
CREATE OR REPLACE VIEW top_source_ips AS
SELECT
    source_ip,
    COUNT(*)        AS request_count,
    MAX(timestamp)  AS last_seen
FROM requests
GROUP BY source_ip
ORDER BY request_count DESC
LIMIT 20;

-- ============================================================
-- ATTACK TYPE STATS VIEW (Day 2)
-- ============================================================
CREATE OR REPLACE VIEW attack_type_stats AS
SELECT
    attack_type,
    COUNT(*)             AS total_count,
    AVG(detection_score) AS avg_score,
    MAX(detection_score) AS max_score,
    MAX(timestamp)       AS last_seen
FROM requests
WHERE detection_status = 'malicious'
GROUP BY attack_type
ORDER BY total_count DESC;

-- ============================================================
-- SESSION STATS VIEW (Day 3)
-- Used by GET /sessions API endpoint
-- ============================================================
CREATE OR REPLACE VIEW session_stats AS
SELECT
    s.session_id,
    s.source_ip,
    s.first_seen,
    s.last_seen,
    s.request_count,
    s.attack_types,
    EXTRACT(EPOCH FROM (s.last_seen - s.first_seen)) AS duration_seconds
FROM sessions s
ORDER BY s.last_seen DESC;

-- ============================================================
-- ALERTS TABLE (Milestone 3)
-- Tracks security events triggered by the Alert Manager
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    id            SERIAL PRIMARY KEY,
    timestamp     TIMESTAMP NOT NULL DEFAULT NOW(),
    source_ip     TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    attack_type   TEXT NOT NULL,
    severity      TEXT NOT NULL,
    message       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
