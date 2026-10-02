-- Image lineage + rule inheritance.
--
-- image_lineage declares "this finding subject is derived from that one"
-- (e.g. a custom-docker overlay and the upstream image it is built FROM), so
-- a suppression decision made for the upstream can keep applying to the
-- overlay. It is consulted only at suppression-match time: fingerprints and
-- subjects are untouched.
--
-- suppressions.inherit is the per-rule opt-in:
--   none    (default) rule matches only its own subject - behaviour unchanged
--   unfixed inherited by descendants only while the finding has no published
--           fix (a "no fix exists yet" rule must not cover an overlay that
--           could patch the package)
--   all     inherited regardless of fix availability (reachability decisions:
--           pip-vendored copies, unused binaries)

CREATE TABLE image_lineage (
  subject    TEXT PRIMARY KEY,          -- the derived image's finding subject (bare repo)
  upstream   TEXT NOT NULL,             -- what it is derived from
  source     TEXT NOT NULL DEFAULT 'manual',  -- manual | dockerfile
  note       TEXT,
  created_at TEXT NOT NULL
);

ALTER TABLE suppressions ADD COLUMN inherit TEXT NOT NULL DEFAULT 'none';
