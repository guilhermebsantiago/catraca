-- RuleStats leaves out the matches of duplicate decisions, made for a
-- retried event that had counted already. Their decision_json carries the
-- duplicate key, which is only written when true. decisions_duplicate holds
-- just those decisions, few next to the rest, so the query finds them
-- without reading the JSON of every decision it counts. matches_stats
-- replaces matches_window with decision_id added, so that the count, which
-- now checks each match's decision, still reads only the index. Keep this
-- file in step with migrations/postgres.
--
-- Building an index blocks writes to its table until it is done. On a
-- large audit database, create these with CREATE INDEX CONCURRENTLY, under
-- these names, before upgrading: IF NOT EXISTS then skips them. See
-- docs/audit.md.

CREATE INDEX IF NOT EXISTS decisions_duplicate ON decisions (id) WHERE decision_json->>'duplicate' IS NOT NULL;

CREATE INDEX IF NOT EXISTS matches_stats ON matches (decided_at_us, rule_id, mode, verdict, errored, decision_id);

DROP INDEX IF EXISTS matches_window;
