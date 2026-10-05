-- Operator "update now": tells an agent to apply its desired_version immediately,
-- ignoring its local update_window. Delivered as `force_update: true` on the report
-- response and cleared by central once the agent reports running the desired
-- version (the swap restarts the process, so no explicit ack is needed).
-- Additive; agents that predate it ignore the field.

ALTER TABLE agents ADD COLUMN update_now INTEGER NOT NULL DEFAULT 0;
