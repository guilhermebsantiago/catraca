-- Leaked-key reports from GitHub secret scanning, one per token and place
-- GitHub found it. A batch is acknowledged only once its reports are here,
-- and they are processed from here, so a report survives a restart, a
-- resolver outage and GitHub delivering it again. Keep this file in step
-- with migrations/postgres.
--
-- report_key is a hash of the token, its type, source and URL, so a report
-- GitHub sends twice is stored once. The token is kept as token_sha256,
-- which is what the resolver and GitHub's feedback take. sealed_token holds
-- the raw token, encrypted by Catraca, only for a resolver that needs it,
-- and only until the token resolves or the report is done: a dead report
-- keeps it so that it can be retried. It is '' otherwise.
CREATE TABLE leak_reports (
    id                 INTEGER PRIMARY KEY,
    report_key         TEXT NOT NULL UNIQUE,
    token_sha256       TEXT NOT NULL,
    sealed_token       TEXT NOT NULL DEFAULT '',
    token_type         TEXT NOT NULL,
    source             TEXT NOT NULL,
    url                TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('pending', 'done', 'dead')),
    outcome            TEXT NOT NULL DEFAULT '',
    attempts           INTEGER NOT NULL DEFAULT 0,
    api_key_id         TEXT NOT NULL DEFAULT '',
    account_id         TEXT NOT NULL DEFAULT '',
    decision_id        TEXT NOT NULL DEFAULT '',
    received_at_us     INTEGER NOT NULL,
    queued_at_us       INTEGER NOT NULL,
    next_attempt_at_us INTEGER NOT NULL,
    updated_at_us      INTEGER NOT NULL,
    last_error         TEXT NOT NULL DEFAULT ''
);

-- Claim: pending reports that are due, oldest first.
CREATE INDEX leak_reports_due ON leak_reports (next_attempt_at_us, id) WHERE status = 'pending';

-- Retention: done and dead reports, oldest first.
CREATE INDEX leak_reports_finished ON leak_reports (updated_at_us) WHERE status IN ('done', 'dead');
