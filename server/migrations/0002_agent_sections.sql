-- Hash-gated report sections.
--
-- Lower-cadence check groups (image scan @ 12h, daily @ 24h) do not need to
-- re-send their full finding list on every 15m cheap report. The agent sends
-- a section's body only when its content hash changes from what central has
-- confirmed here; otherwise it sends the hash alone and central just bumps
-- confirmed_at (no per-finding writes) and leaves those findings untouched.
--
-- generated_at (when the agent produced the scan) drives stale-scan
-- detection: a section whose generated_at falls too far behind means the
-- heavy tier has silently stopped - alert, but do NOT resolve its findings.

CREATE TABLE agent_sections (
  agent_id     TEXT NOT NULL REFERENCES agents(id),
  section      TEXT NOT NULL,           -- 'image-scan' | 'daily'
  hash         TEXT NOT NULL,           -- sha256 hex of the section's canonical content
  generated_at TEXT NOT NULL,           -- agent-side scan time (ISO8601)
  confirmed_at TEXT NOT NULL,           -- last report that carried this hash
  PRIMARY KEY (agent_id, section)
);
