-- Operator-requested rescan ("re-run these sections on the agent's next report").
--
-- Pull model: the agent already polls via POST /api/v1/report, so a pending
-- request rides back on that response as { rescan: { id, sections } }. The
-- agent echoes `rescan_done: <id>` once the scan finished; central clears the
-- row only if the id still matches, so a newer request made meanwhile survives.
-- Until acked, every report re-delivers it (agent crash / lost response safe).
-- Additive and nullable: older agents ignore the response field.

ALTER TABLE agents ADD COLUMN rescan_id TEXT;           -- NULL => nothing pending
ALTER TABLE agents ADD COLUMN rescan_sections TEXT;     -- JSON array: section names, or ["all"]
ALTER TABLE agents ADD COLUMN rescan_requested_at TEXT;
