-- Delivery per hook: each hook claims its own deliveries, so one slow
-- endpoint cannot hold up the others, and a dead delivery can be requeued.
-- Keep this file in step with migrations/sqlite.

-- When catraca outbox retry last requeued the delivery, 0 if it never did.
-- A hook's max_age counts from here, or from created_at_us before the first
-- requeue, so a requeued delivery gets its whole max_age again. Adding a
-- column with a constant default does not rewrite the table.
ALTER TABLE outbox ADD COLUMN requeued_at_us BIGINT NOT NULL DEFAULT 0;

-- Claim, per hook: one effect's pending deliveries that are due, oldest
-- first. Building it blocks writes to the outbox until it is done; on a
-- large outbox, create it with CREATE INDEX CONCURRENTLY, under this name,
-- before upgrading: IF NOT EXISTS then skips it. See docs/audit.md.
CREATE INDEX IF NOT EXISTS outbox_effect_due ON outbox (effect, next_attempt_at_us, id) WHERE status = 'pending';
