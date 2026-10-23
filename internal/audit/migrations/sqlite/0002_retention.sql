-- Indexes for audit.retention, which deletes old decisions and finished
-- deliveries oldest first, in small batches: each batch finds its rows
-- through these instead of reading the whole table. Keep this file in step
-- with migrations/postgres.

CREATE INDEX IF NOT EXISTS decisions_decided_at ON decisions (decided_at_us);

CREATE INDEX IF NOT EXISTS outbox_finished ON outbox (updated_at_us) WHERE status IN ('delivered', 'dead');
