-- RuleStats leaves out the matches of duplicate decisions, made for a
-- retried event that had counted already. Their decision_json carries the
-- duplicate key, which is only written when true. This partial index holds
-- just those decisions, few next to the rest, so the query finds them
-- without reading the JSON of every decision it counts. Keep this file in
-- step with migrations/postgres.

CREATE INDEX IF NOT EXISTS decisions_duplicate ON decisions (id) WHERE decision_json->>'duplicate' IS NOT NULL;
