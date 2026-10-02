-- Scan provenance: which image ref + digest produced an image finding, and
-- which images each hash-gated section's current scan covered.
--
-- All nullable / additive. Agents older than v0.3.0 send none of this, and a
-- Worker rolled back past this migration ignores the columns.

ALTER TABLE findings ADD COLUMN image_ref TEXT;      -- exact pinned ref that was scanned, e.g. reg.example/hc:4.4-2
ALTER TABLE findings ADD COLUMN image_digest TEXT;   -- repo digest of that scan (else local image id)
ALTER TABLE findings ADD COLUMN scanned_at TEXT;     -- generated_at of the section body that last carried the finding

ALTER TABLE agent_sections ADD COLUMN scans_json TEXT; -- [{"ref":"...","digest":"..."}] covered by the current scan
