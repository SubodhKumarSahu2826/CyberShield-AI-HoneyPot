# CyberShield AI Honeypot Platform — Project Context

> **Last updated:** Milestone 5 (AI Classification Pipeline, Three-Tier Detection & Dashboard Polish)
> **Development Timeline:** Milestone 5
> **Status:** ✅ Full hybrid detection pipeline (Rule-Based + AI), three-tier classification (safe/suspicious/malicious), async AI inference, LLM deception, behaviour profiling, export functionality, and production-ready dashboard.

---

## Project Overview

The **CyberShield AI Honeypot Platform** is a production-grade, AI-powered cybersecurity research platform designed to:

- **Capture** real-world attacker HTTP traffic
- **Store** structured threat intelligence in a PostgreSQL database with persistent Docker volumes
- **Analyze** attack patterns using a hybrid Rule-Based + AI classification pipeline
- **Classify** traffic into three tiers: `safe`, `suspicious`, and `malicious`
- **Deceive** attackers with context-aware, LLM-generated fake responses
- **Profile** attacker behaviour with sophistication scoring (0-10)
- **Export** all captured data as CSV/JSON for SIEM integration

The platform runs entirely inside Docker containers on macOS (development) or Linux (production).

---

## System Architecture

```
Internet Traffic
       │
       │ HTTP (all paths / all methods)
       ▼
┌──────────────────────────────┐
│  honeypot-container          │  Port 8080 (public)
│  FastAPI — Catch-All Capture │
│     ↓ detect.engine.analyze()│  73 regex rules, 7 attack categories
│  Rule-Based Detection Engine │  Three-tier: safe / suspicious / malicious
│     ↓ (suspicious only)      │
│  Async AI Queue → Classifier │  Qwen 2.5 / Phi-3.5 via Ollama
│     ↓                        │
│  LLM Deception Response Gen  │  Context-aware fake responses
└──────────────┬───────────────┘
               │ INSERT (detection_status, attack_type, ai_attack_type, ai_confidence_score)
               ▼
┌──────────────────────────────┐
│  postgres-container          │  Internal only (persistent volume)
│  PostgreSQL 15               │
│  requests, sessions, alerts  │
└──────────────┬───────────────┘
               │ SELECT
               ▼
┌──────────────────────────────┐
│  api-container               │  Internal only (port 3001)
│  FastAPI — Query REST API    │  12+ endpoints + CSV/JSON export
└──────────────┬───────────────┘
               │ HTTP Proxy
               ▼
┌──────────────────────────────┐
│  dashboard-container         │  Port 3000 (public)
│  aiohttp — CyberShield UI    │
│  Dark glassmorphism dashboard│
└──────────────────────────────┘

┌──────────────────────────────┐
│  classifier-container        │  Internal only (port 3003)
│  FastAPI — AI Classification │
│  Prompts Qwen 2.5 via Ollama │
└──────────────────────────────┘

┌──────────────────────────────┐
│  response-gen-container      │  Internal only (port 3002)
│  FastAPI — LLM Deception     │
│  Generates fake responses    │
└──────────────────────────────┘
```

All services communicate over the internal Docker bridge network `honeypot-net`.

---

## Components Implemented

### ✅ Day 1 — Foundation

#### Repository Structure
- Complete project directory layout, `.gitignore`, `.env.example`

#### Honeypot Capture Service (`services/honeypot/`)
- FastAPI with **wildcard catch-all route** (`/{path:path}`)
- Captures: `source_ip`, `method`, `endpoint`, `headers`, `payload`, `timestamp`
- Returns convincing fake responses; deceptive `Server: Apache/2.4.54` header
- Async asyncpg connection pool with retry logic
- Structured JSON logger → `/logs/honeypot.log`
- Input sanitization (null bytes, size limits, parameterized queries)

#### PostgreSQL Database (`services/database/`)
- `requests` table with JSONB headers column
- Views: `attacker_stats`, `top_endpoints`, `top_source_ips`
- Auto-initialized via `init.sql`

#### API Query Service (`services/api/`)
- `GET /requests`, `/requests/latest`, `/stats`, `/_health`
- Read-only async queries, fully parameterized

#### Monitoring Dashboard (`services/dashboard/`)
- Dark-themed single-page live monitor, auto-refresh every 10s
- `/api/*` proxy to internal API service

#### Docker Orchestration
- 4 containers with health checks, resource limits, persistent volumes

#### Centralized Logging
- Structured JSON: `timestamp, service_name, event_type, message, request_id`

---

### ✅ Day 2 — Rule-Based Detection Engine

#### Detection Module (`services/honeypot/app/detection/`)

A modular, zero-dependency detection engine embedded directly in the honeypot processing pipeline.

**`rules.py`** — 73 compiled regex patterns, pre-compiled at import time:

| Category | Rules | Key Patterns |
|----------|-------|--------------|
| SQL Injection | 14 | `' OR 1=1`, `UNION SELECT`, `DROP TABLE`, `SLEEP()`, `WAITFOR DELAY` |
| XSS | 13 | `<script>`, `onerror=`, `document.cookie`, `eval()`, HTML entity encoding |
| Command Injection | 12 | `; ls`, `\| bash`, `$(...)`, backtick exec, `/dev/tcp/` reverse shell |
| Path Traversal | 10 | `../../`, `%2e%2e%2f`, `/etc/passwd`, `/etc/shadow`, `C:\Windows` |
| Directory Enumeration | 12 | `/.env`, `/.git`, `/.htaccess`, `/wp-admin`, web shell extensions |
| Broken Access Control | 7 | `X-Original-URL`, `X-Forwarded-For: 127.0.0.1`, IDOR param patterns |
| Auth Failure | 5 | `admin:admin`, `root:root`, `password=password`, OAuth brute |

**`engine.py`** — `analyze(endpoint, payload, headers) -> DetectionResult`
- Scans combined surface: endpoint + payload + headers
- Returns best-match rule; early-exit at score ≥ 0.98 for performance
- **Three-tier classification:**
  - `safe` → No rules matched AND payload looks benign (short, no encoding, no suspicious keywords)
  - `suspicious` → No rules matched BUT payload contains suspicious indicators → queued for AI
  - `malicious` → Rule matched with confidence ≥ 0.50

**Output format:**
```json
// Safe (benign traffic):
{"status": "safe", "attack_type": "none", "detection_score": 0.0}

// Malicious match (regex):
{"status": "malicious", "attack_type": "SQL Injection", "detection_score": 0.98}

// Suspicious (queued for AI):
{"status": "suspicious", "attack_type": "unknown", "detection_score": 0.2}
```

#### Pipeline Integration
Detection runs **synchronously between request extraction and DB insert** — purely CPU-bound, adds ~100μs overhead per request:

```
HTTP Request → extract fields → engine.analyze() → insert_request(+detection) → fake response
```

#### Database Schema Update
- Added 3 columns: `detection_status TEXT`, `attack_type TEXT`, `detection_score REAL`
- `ALTER TABLE IF NOT EXISTS` guards for safe upgrades of existing databases
- 3 new indexes: `detection_status`, `attack_type`, `detection_score DESC`
- New view: `attack_type_stats` — malicious count, avg/max score per category

#### API Update
- All `/requests*` endpoints now return detection fields in every row
- `GET /stats` now includes `malicious_count` and `attack_breakdown` array
- **New:** `GET /detections` — returns confirmed malicious requests only

---

### ✅ Day 3 — Session Tracking & Structured Logging

#### Session Tracking Module (`services/honeypot/app/session/`)

**`session_manager.py`** — `SessionManager` class (singleton `session_manager` imported by routes)
- In-memory `dict[source_ip → Session]` with single `asyncio.Lock()`
- `get_or_create(source_ip, attack_type, pool)` — returns existing or new `Session`
- Session IDs: `sess_` + first 12 hex chars of `SHA-256(ip:timestamp)`
- Persists via `INSERT ... ON CONFLICT DO UPDATE` (upsert) into `sessions` table
- `evict_stale()` — removes sessions idle > `SESSION_TTL_SECONDS` (default: 3600s)
- Called on startup via `asyncio.create_task(_session_eviction_loop())` every 15m

**`Session` dataclass fields:**
```
session_id    str      # sess_<12hex>
source_ip     str
first_seen    str      # ISO-8601 UTC
last_seen     str      # ISO-8601 UTC
request_count int      # increments on every request from this IP
attack_types  list     # rolling log, capped at 50 entries
```

#### Structured Logging (`services/honeypot/app/logging/`)

**`structured_logger.py`** — drop-in complement to `app.logger`
- `_JSONFormatter`: serializes all log records to single-line JSON
- `get_structured_logger(name)` — returns cached logger writing to stdout + rotating file
- `log_event(slogger, event=..., session_id=..., ...)` — one-call structured emission
- Rotating file: `LOG_FILE=/logs/honeypot_structured.log`, 50MB × 5 backup files

**Example log entry (AI training schema):**
```json
{
  "timestamp": "2026-03-12T15:42:10Z",
  "service": "honeypot",
  "event": "attack_detected",
  "source_ip": "1.2.3.4",
  "session_id": "sess_d0df5b4f9d1f",
  "endpoint": "/login",
  "method": "POST",
  "attack_type": "SQL Injection",
  "classification_status": "malicious",
  "detection_score": 0.98
}
```

#### Updated Pipeline (`routes.py`)
```
capture_request()
    ↓ extract IP, endpoint, method, headers, payload
    ↓ detection_engine.analyze()            ← Day 2
    ↓ session_manager.get_or_create()       ← Day 3  ★
    ↓ log_event() with full session context  ← Day 3  ★
    ↓ insert_request(+session_id)            ← Day 3  ★
    ↓ return fake response
```

#### API Update (`GET /sessions`)
- Returns all attacker sessions from the `sessions` PostgreSQL table
- Includes: `session_id`, `source_ip`, `request_count`, `top_attack_type`, `first_seen`, `last_seen`, `duration_seconds`

#### Dashboard Update
- **5 stat cards:** Total Requests, Unique IPs, Malicious, **Active Sessions** ★, Capture Status
- **Attacker Sessions table:** 7 columns with session_id, IP, request count, top attack, first/last seen, duration
- **Attack Breakdown panel:** shows top attack types with counts (replaces old Top IPs panel)
- All tables now include `detection_status`, `attack_type`, and `session_id` columns

---

### ✅ Day 4 — AI Attack Classifier Integration

#### Classifier Service Architecture (`services/classifier/`)
- Fast API microservice encapsulating the AI classification logic.
- **`classifier_client.py`**: Interacts securely with remote models (via ngrok) or local models (via Ollama `host.docker.internal:11434`) relying on OpenAI-compatible formats. Instructs the model to output structured JSON predicting explicit attack taxonomy or benign/malicious anomalies.

#### Remote Model Integration & Pipeline
- In `services/honeypot/app/routes.py`: Requests flagged purely as `suspicious` by the regex engine bypass immediate cataloging and are fired at the AI Attack Classifier.
- If the remote AI parses the payload/metadata and returns `malicious`, the capture pipeline automatically segregates the traffic as `malicious` in real-time.

#### Database Schema Changes
- Augmented the `requests` table in `init.sql` adding: `ai_attack_type` (TEXT) and `ai_confidence_score` (FLOAT).
- Adapted `services/honeypot/app/database.py` and `services/api/app/database.py` to seamlessly execute inserts and queries incorporating these new metrics.
- Overriding gracefully when the remote model times out or goes offline via `model_unavailable` fallbacks, without crashing the honeypot.

#### Dashboard Re-Architecture
- Transformed the Live Monitor tables, substituting the standard Attack Type field for **Detection (Rule / AI)**.
- Integrates visual differential coloring: Standard regex alarms throw red UI elements; confirmed explicit AI captures broadcast blue/purple `🤖 AI:` signatures appended with decimal confidence scores.

---

### ✅ Day 5 — Async Inference Pipeline

#### Async Pipeline Architecture (`services/honeypot/app/async_pipeline/`)
- Abstracted the slow AI inference engine into a non-blocking background queue pool.
- **Queue Manager**: Maintains an `asyncio.Queue` array mapping payloads to database `request_id` keys automatically.
- **Classification Worker**: A daemon task that indefinitely polls the Queue Manager. Invokes the `classifier_client` microservice entirely in the background. Update queries (`update_request_classification()`) fire retroactively when predictions confirm.
- Honeypot capture loop latency lowered significantly: the payload persists to standard rules, commits its DB ID, and responds safely within milliseconds, queueing AI processing invisibly.

#### Dashboard Telemetry
- Attached an active telemetry API at `GET /_queue_size` on the honeypot, proxied through `Dashboard:3000/api/queue`.
- **Pending AI Jobs**: UI card visually counts the real-time backlog of unprocessed inference objects.

---

### ✅ Milestone 2A — LLM-Based Deception Engine

#### Response Generator Architecture (`services/response-generator/`)
- Fast API microservice running alongside the honeypot, linked to an LLM context (Ollama or remote ngrok API).
- Exposes `POST /generate-response` and generates deceptive honeypot responses dynamically using the payload, endpoint, method, attack classification, and attacker profile strategy.
- **Prompt Builder module**: Constructs highly realistic instructions for the LLM based on the attack type (e.g. generating fake SQL databases, authentic `/etc/passwd` linux file structures, or dummy authentication logs).

#### LLM Integration
- The generator executes asynchronous HTTP requests (via `httpx` with 90.0s custom timeouts for cold starts).
- Connected to remote configurable endpoints via `.env` (`LLM_URL`, `MODEL_NAME`).
- On LLM failure or API timeout, falls back structurally to dummy error payloads (`static_fallback`) to ensure attacker engagement never drops.

#### Response Caching System
- Implements an async PostgreSQL cache (`cache_manager.py`) directly querying the `requests` table.
- Cache key relies entirely on `payload` and `attack_type`. If an identical payload and attack type combination is detected in previous interactions, the system skips the LLM network call entirely and replays the persistent generated fake system response.

#### Updated Request Flow
```
Internet → Capture Service (Honeypot) → Rule-Based Detection Engine
     ↓
Session Tracking & AI Classification queueing
     ↓
Generates & Sends POST to Response Generator Microservice
     ↓
Response Generator consults DB Cache Manager 
   ├── [Cache Hit] Returns old response 
   └── [Cache Miss] Prompt Builder → Remote LLM API via ngrok → Returns new response
     ↓
Return Deceptive Falsified Response to Attacker
     ↓
Store original request + generated `response` & `response_type` in Postgres
```

### ✅ Milestone 2B — Behaviour Profiling & Adaptive Intelligence

#### Behaviour Profiling Engine (`services/honeypot/app/behavior/`)
- **`profiler.py`**: Monitors in-memory session intelligence. Computes endpoints, frequency, and duration.
- **`pattern_analyzer.py`**: Evaluates request sequences to detect scanning, brute force, fuzzing, and persistent patterns.
- **`scoring_engine.py`**: Computes an attacker sophistication score (0-10) and assigns an `attacker_type` classification.

#### Adaptive Response Engine (`services/honeypot/app/adaptive/`)
- **`decision_engine.py`**: Evaluates the profile context to pick a response strategy.
- **`strategy_manager.py`**: Maps sophistication to deception strategies (e.g., simplistic errors vs robust faux-system output). Directly integrated into LLM prompts.

---

### ✅ Milestone 3 — Monitoring, Visualization & Production Hardening

#### Security Hardening (`services/honeypot/app/security/`)
- **`rate_limiter.py`**: A sliding-window token bucket implementation tracking connections. Defends against volumetric attacks by returning 429 errors.
- **`firewall_rules.py`**: Dynamic firewall infrastructure (disabled by design — honeypots trap, don't block).
- **`input_sanitizer.py`**: Null-byte and unprintable character stripping protecting the system from log injection variants.
- Enforced hard `0.5` CPU limits across Docker orchestration.

> **Design Decision:** The `block_ip()` function exists but is intentionally disabled in the alert handler. A honeypot's purpose is to *attract and study* attackers, not block them. Blocking would stop intelligence collection. The alert still fires and gets logged.

#### Real-time Alerting (`services/honeypot/app/alerts/`)
- **`alert_manager.py`**: Background asynchronous task parsing incoming behavioral triggers against severity thresholds (e.g. Volume > 100, AI Score >= 9.0).
- **`channels.py`**: Webhook and Email dispatch stubs. Seamlessly broadcasts high-priority flags to external IT systems without blocking ingestion.
- Inserts actionable alerts directly to the `alerts` PostgreSQL table.

#### Dataset Exporting (`services/api/app/export/`)
- Export primitives structured in `dataset_exporter.py`
- Endpoints `GET /export/json` and `GET /export/csv` instantly fetch datasets for external analytical use (e.g., Pandas or ElasticSearch ingestion).

#### Visual Analytics & Advanced Dashboard
- Upgraded the aiohttp Dashboard to natively integrate `Chart.js` using isolated view controllers (`visualization.py` and `charts.py`).
- **Traffic Timeline**: Dynamic 24-hour line tracing HTTP injection requests parsed asynchronously out of Postgres.
- **Attack Methods**: Color-coded doughnut charts mapped dynamically to payload signatures.
- **Live Feed**: A continuous scrolling ticker pulling out threshold events from the newly generated `alerts` table.
- **Deception UI**: Added "Read Response" modal in the UI to visualize generated LLM Deceptive responses, including response caching status mapping.

---

### ✅ Milestone 4 — Validation & Attack Simulation Testing

#### Comprehensive Attack Simulation
- Executed broad spectrum automated attacks targeting the honeypot: SQL Injection, XSS, Command Injection, Path Traversal, and Directory Enumeration.
- Confirmed correct edge-case routing from internal classifiers and rule-engines dynamically assigning behavior scores.

#### Deception Engine Tuning
- Tuned context-aware LLM generation for timeouts & cold boot latency. Correctly configured fallback dummy errors for when the AI inference engine goes offline.
- Verified semantic caching logic: the system actively deduplicates repeat payloads natively reducing token billing and inference wait times without sacrificing engagement.

---

## Pending Tasks (Days 2–14)

| Day | Component | Status | Description |
|-----|-----------|--------|-------------|
| 1 | Foundation Infrastructure | ✅ Done | Docker, honeypot capture, DB, API, dashboard |
| 2 | Rule-Based Detection Engine | ✅ Done | 73-rule regex engine, 7 attack categories |
| 3 | Session Tracking & Logging | ✅ Done | Session manager, structured JSON logs, dataset pipeline |
| 4 | AI Attack Classifier | ✅ Done | FastAPI microservice, LLM segregation, Dashboard UI |
| 5 | Async Inference | ✅ Done | Deferred AI payload queueing via classification workers |
| 6 | Active Deception | ✅ Done | LLM generated fake responses, contextual prompts |
| 7 | Attacker Profiling | ✅ Done | Deep behavior analysis, session correlation, sophistication scoring |
| 8 | Analytics Engine | ✅ Done | Time-series analysis, attack trend detection |
| 9 | Alerting System | ✅ Done | Real-time alerts via webhook/email |
| 10 | Threat Intelligence | ✅ Done | IP geolocation, reputation lookup enrichment |
| 11 | API Enhancements | ✅ Done | Filtering, search, dataset export (CSV/JSON) |
| 12 | Hardening | ✅ Done | Rate limiting, input sanitization, production security |
| 13 | Testing & QA | ✅ Done | Attack simulation suite, LLM response validation, edge case handling |
| 14 | Three-Tier Detection | ✅ Done | Safe/suspicious/malicious classification, benign heuristic |
| 15 | Dashboard Polish | ✅ Done | CyberShield rebrand, export buttons, variable request view (20/100/500) |

---

## Infrastructure Setup

### Prerequisites
- Docker Engine 24+ and Docker Compose v2
- Ubuntu 22.04 (or any Docker-capable OS for development)

### First-Time Setup
```bash
# 1. Copy environment file
cp .env.example .env

# 2. Edit .env — change POSTGRES_PASSWORD before production deployment
nano .env

# 3. Build and start all services
docker-compose up --build

# 4. Verify all containers are running
docker-compose ps
```

### Useful Commands
```bash
# Send a test request to the honeypot
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"1234"}'

# Query latest captures via API
curl http://localhost:3001/requests/latest | jq .

# View aggregate stats
curl http://localhost:3001/stats | jq .

# View live dashboard
open http://localhost:3000

# Tail honeypot logs
docker-compose logs -f honeypot

# Check all container health
docker-compose ps
```

---

## Docker Services

| Service | Container | Ports | Memory Limit |
|---------|-----------|-------|-------------|
| honeypot | honeypot-capture | 8080 (public) | 256 MB |
| api | honeypot-api | 3001 (internal) | 128 MB |
| dashboard | honeypot-dashboard | 3000 (public) | 128 MB |
| postgres | honeypot-postgres | none (internal) | 256 MB |
| classifier | honeypot-classifier | 3003 (internal) | 256 MB |
| response-generator | honeypot-response-generator | 3002 (internal) | 256 MB |

**Total services:** 6 containers

---

## Database Schema

```sql
TABLE requests (
    id               SERIAL PRIMARY KEY,
    source_ip        TEXT        NOT NULL,
    method           TEXT        NOT NULL,
    endpoint         TEXT        NOT NULL,
    headers          JSONB       NOT NULL DEFAULT '{}',
    payload          TEXT        NOT NULL DEFAULT '',
    timestamp        TIMESTAMP   NOT NULL DEFAULT NOW(),
    -- Day 2: Detection fields
    detection_status TEXT        NOT NULL DEFAULT 'suspicious',
    attack_type      TEXT        NOT NULL DEFAULT 'unknown',
    detection_score  REAL        NOT NULL DEFAULT 0.2,
    -- Day 3: Session & dataset fields
    session_id          TEXT    NOT NULL DEFAULT '',
    response_generated  BOOLEAN NOT NULL DEFAULT FALSE,
    -- Milestone 2B: Behaviour Profiling
    attacker_score      REAL    NOT NULL DEFAULT 0.0,
    attacker_type       TEXT    NOT NULL DEFAULT 'unknown',
    attack_pattern      TEXT    NOT NULL DEFAULT 'none'
);

TABLE sessions (
    session_id    TEXT      PRIMARY KEY,     -- sess_<12hex SHA-256>
    source_ip     TEXT      NOT NULL,
    first_seen    TIMESTAMP NOT NULL,
    last_seen     TIMESTAMP NOT NULL,
    request_count INTEGER   NOT NULL DEFAULT 1,
    attack_types  JSONB     NOT NULL DEFAULT '[]'
);

TABLE alerts (
    id            SERIAL PRIMARY KEY,
    timestamp     TIMESTAMP NOT NULL DEFAULT NOW(),
    source_ip     TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    attack_type   TEXT,
    severity      TEXT NOT NULL,
    message       TEXT NOT NULL
);

INDEXES (requests):
  idx_requests_source_ip        — fast IP lookups
  idx_requests_timestamp        — time-range queries (DESC)
  idx_requests_endpoint         — endpoint frequency analysis
  idx_requests_method           — method filtering
  idx_requests_headers_gin      — full JSONB header search
  idx_requests_detection_status — filter malicious vs suspicious  [Day 2]
  idx_requests_attack_type      — group by attack category        [Day 2]
  idx_requests_score            — sort by confidence score        [Day 2]
  idx_requests_session_id       — correlate requests by session   [Day 3]

INDEXES (sessions):
  idx_sessions_source_ip      — IP lookup
  idx_sessions_last_seen      — recency ordering
  idx_sessions_request_count  — volume sorting

VIEWS:
  attacker_stats     — total_requests, unique_ips, last_seen
  top_endpoints      — endpoint hit counts (top 20)
  top_source_ips     — IP request counts (top 20)
  attack_type_stats  — malicious count/avg-score per category    [Day 2]
  session_stats      — sessions with duration_seconds             [Day 3]
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/requests` | Paginated request list with IP/method/date filters |
| GET | `/requests/latest` | Last 20 captured requests (incl. detection + AI + session fields) |
| GET | `/detections` | Confirmed malicious requests only |
| GET | `/sessions` | Attacker sessions with stats (request count, top attack, duration) |
| GET | `/sessions/{id}/timeline` | Chronological events for a specific attacker session |
| GET | `/attacker-profiles` | Aggregated attacker behaviour profiles with sophistication scores |
| GET | `/analytics` | Timeline buckets grouped by the hour for traffic charts |
| GET | `/alerts` | Chronological security alerts feed |
| GET | `/export/json` | Full dataset export as JSON |
| GET | `/export/csv` | Full dataset export as CSV |
| GET | `/stats` | Total, unique IPs, malicious count, attack breakdown, attacker types |
| GET | `/metrics` | Prometheus-compatible metrics format |
| GET | `/_health` | Docker health check |

---

## Security Considerations

| Area | Implementation |
|------|---------------|
| SQL Injection | All queries use asyncpg parameterization (`$1, $2, ...`) |
| Input Sanitization | Null byte stripping, field length caps (64KB payload) |
| Credential Management | All secrets via environment variables, never hardcoded |
| Network Isolation | PostgreSQL and API have no public port mappings |
| Container Security | Non-root users in all Dockerfiles |
| API Exposure | API service uses `expose` not `ports` — host-only |
| Deception | Fake `Server` header returned to fingerprinting tools |

---

## Startup Guide (Cold Boot)

```bash
# 1. Open Docker Desktop and Ollama app
# 2. Navigate to the project
cd "/Users/sks/Desktop/AI-Adaptive Cyber HoneyPot"

# 3. Start all services
docker-compose up -d

# 4. Verify all 6 containers are running
docker-compose ps

# 5. (Optional) Pre-warm the AI model
curl http://localhost:11434/api/generate -d '{"model": "qwen2.5:3b", "prompt": "Wake up", "stream": false}'

# 6. Access dashboard
open http://localhost:3000

# 7. Test with a sample attack
curl "http://localhost:8080/api/users/login?user=admin'%20OR%201=1--"

# 8. Shut down cleanly
docker-compose down
```

---

## Testing Commands

### Safe Requests (Green SAFE badge)
```bash
curl "http://localhost:8080/api/products"
curl "http://localhost:8080/api/search?q=laptop&category=electronics"
curl -X POST "http://localhost:8080/api/contact" -H "Content-Type: application/json" -d '{"name": "John", "message": "Hello"}'
```

### Rule-Based Detection (Red MALICIOUS badge — instant)
```bash
curl "http://localhost:8080/api/users/login?user=admin'%20OR%201=1--"
curl -X POST "http://localhost:8080/api/feedback" -d 'comment=<script>document.cookie</script>'
curl "http://localhost:8080/api/serve?file=../../../../../../etc/passwd"
```

### AI-Based Detection (Yellow SUSPICIOUS → Red MALICIOUS after ~10s)
```bash
curl -X POST "http://localhost:8080/api/v2/auth/login" -H "Content-Type: application/json" -d '{"username": {"$gt": ""}, "password": {"$ne": null}}'
curl -X POST "http://localhost:8080/api/import-data" -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///var/log/syslog">]><R><d>&e;</d></R>'
```

---

*This file is maintained as the single source of truth for CyberShield project context.*
*Update it whenever new components are implemented or the architecture changes.*
