-- Registered agent releases. `agents.desired_version` names a row here; the
-- report response then carries that row's url + sha256 + sig_url for the
-- agent's arch, which the agent verifies before swapping its binary.
--
-- Populated by `picketctl release add <version> --base-url … --sha256sums …`
-- from the GitHub Release artifacts the release.yml workflow publishes.

CREATE TABLE releases (
  version       TEXT PRIMARY KEY,   -- e.g. "0.2.0" (no leading v)
  url_amd64     TEXT NOT NULL,
  sha256_amd64  TEXT NOT NULL,
  sig_url_amd64 TEXT NOT NULL,
  url_arm64     TEXT,
  sha256_arm64  TEXT,
  sig_url_arm64 TEXT,
  notes         TEXT,
  created_at    TEXT NOT NULL
);
