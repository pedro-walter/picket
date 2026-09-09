-- Picket central store (Cloudflare D1 / SQLite).
--
--   wrangler d1 create picket           # once; copy database_id into wrangler.toml
--   wrangler d1 migrations apply picket --local     # local dev
--   wrangler d1 migrations apply picket --remote    # production

CREATE TABLE agents (
  id              TEXT PRIMARY KEY,            -- uuid
  name            TEXT NOT NULL UNIQUE,        -- e.g. prod-server
  token_hash      TEXT NOT NULL,              -- sha256(TOKEN_PEPPER || token), hex
  agent_version   TEXT,                       -- last reported running version
  desired_version TEXT,                       -- NULL => fall back to DEFAULT_DESIRED_VERSION
  rollout_bucket  TEXT NOT NULL DEFAULT 'default',
  last_report_at  TEXT,                       -- ISO8601 UTC
  notes           TEXT,
  created_at      TEXT NOT NULL
);
CREATE INDEX idx_agents_token_hash ON agents(token_hash);

CREATE TABLE reports (
  id           TEXT PRIMARY KEY,              -- uuid
  agent_id     TEXT NOT NULL REFERENCES agents(id),
  received_at  TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX idx_reports_received_at ON reports(received_at);
CREATE INDEX idx_reports_agent ON reports(agent_id, received_at);

-- One row per distinct problem, keyed by a stable fingerprint:
--   sha256(kind \n agent_name \n subject \n identifier)
-- The agent chooses `subject` so it is stable across version bumps
-- (bare repo "postgres", not "postgres:16-alpine") - this is the property
-- the old ignore/*.txt filename matching was reaching for.
CREATE TABLE findings (
  fingerprint TEXT PRIMARY KEY,               -- hex sha256
  agent_id    TEXT NOT NULL REFERENCES agents(id),
  kind        TEXT NOT NULL,                  -- image-cve | image-tag | apt | reboot | container-stale | host-health | cert-expiry
  subject     TEXT NOT NULL,
  identifier  TEXT NOT NULL,
  severity    TEXT NOT NULL DEFAULT 'info',   -- critical | high | medium | low | info
  title       TEXT NOT NULL,
  detail      TEXT,
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  status      TEXT NOT NULL,                  -- open | acked | muted | resolved
  state_json  TEXT                            -- last raw finding + lifecycle metadata
);
CREATE INDEX idx_findings_agent_status ON findings(agent_id, status);
CREATE INDEX idx_findings_kind ON findings(kind);

CREATE TABLE suppressions (
  id              TEXT PRIMARY KEY,
  kind            TEXT NOT NULL,
  subject_glob    TEXT NOT NULL DEFAULT '*',
  identifier_glob TEXT NOT NULL DEFAULT '*',
  cve_glob        TEXT NOT NULL DEFAULT '*',
  reason          TEXT NOT NULL,
  author          TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  expires_at      TEXT                        -- NULL => never expires
);
CREATE INDEX idx_suppressions_kind ON suppressions(kind);

CREATE TABLE metrics (
  agent_id         TEXT NOT NULL REFERENCES agents(id),
  ts               TEXT NOT NULL,
  cpu_pct          REAL,
  mem_pct          REAL,
  disk_pct         REAL,
  mongo_data_gb    REAL,
  registry_data_gb REAL,
  PRIMARY KEY (agent_id, ts)
);

-- Send-once dedupe. `kind` lets an alert and a later resolved/offline mail
-- for the same fingerprint coexist; rows for a fingerprint are deleted when
-- it resolves or the agent recovers, so a genuine re-open mails again.
CREATE TABLE notifications (
  fingerprint TEXT NOT NULL,
  sent_at     TEXT NOT NULL,
  channel     TEXT NOT NULL DEFAULT 'email',
  kind        TEXT NOT NULL DEFAULT 'alert',  -- alert | resolved | offline
  PRIMARY KEY (fingerprint, kind, channel)
);
