-- Indexes for audit.retention, which deletes old decisions and finished
-- deliveries oldest first, in small batches: each batch finds its rows
-- through these instead of reading the whole table. Keep this file in step
-- with migrations/sqlite.
--
-- Building an index blocks writes to its table until it is done, which on a
-- large decisions table can take minutes. To avoid that, create both indexes
-- with CREATE INDEX CONCURRENTLY, under these names, before upgrading: IF NOT
-- EXISTS then skips them. See docs/audit.md.

CREATE INDEX IF NOT EXISTS decisions_decided_at ON decisions (decided_at_us);

CREATE INDEX IF NOT EXISTS outbox_finished ON outbox (updated_at_us) WHERE status IN ('delivered', 'dead');
