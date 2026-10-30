-- Indexes for ListDecisions (GET /v1/decisions and catraca decisions),
-- which lists an account's, an API key's, an IP's or an action's decisions
-- newest first, a page at a time: each filter finds its rows through one of
-- these, in order, instead of reading every decision in the window. The ip
-- index is on the same expression the query filters on. Keep this file in
-- step with migrations/postgres.

CREATE INDEX IF NOT EXISTS decisions_account ON decisions (account_id, decided_at_us, id);

CREATE INDEX IF NOT EXISTS decisions_api_key ON decisions (api_key_id, decided_at_us, id);

CREATE INDEX IF NOT EXISTS decisions_ip ON decisions ((event_json->>'ip'), decided_at_us, id);

CREATE INDEX IF NOT EXISTS decisions_action ON decisions (action, decided_at_us, id);
