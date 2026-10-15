-- The audit schema. Keep it in step with migrations/sqlite: the two files
-- describe the same tables, columns and indexes in each database's types.
-- Times are unix microseconds (UTC) in *_at_us columns, as in SQLite, so the
-- queries are the same for both databases.

-- One row per decision. The decision and the stored event are kept whole as
-- JSON; the other columns are copies for ad-hoc SQL.
CREATE TABLE decisions (
    id              TEXT PRIMARY KEY,
    event_id        TEXT NOT NULL,
    decided_at_us   BIGINT NOT NULL,
    action          TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    account_id      TEXT NOT NULL,
    api_key_id      TEXT NOT NULL,
    ruleset_version TEXT NOT NULL,
    degraded        BOOLEAN NOT NULL,
    decision_json   JSONB NOT NULL,
    event_json      JSONB NOT NULL
);

-- One row per rule that matched a decision, enforced or shadow. verdict is
-- the latest label that applies to the match (NULL while unlabeled), kept
-- here so rule stats and the review queue need no join on labels.
CREATE TABLE matches (
    decision_id   TEXT NOT NULL REFERENCES decisions (id) ON DELETE CASCADE,
    rule_id       TEXT NOT NULL,
    mode          TEXT NOT NULL CHECK (mode IN ('shadow', 'enforce')),
    action        TEXT NOT NULL,
    reason        TEXT NOT NULL,
    errored       BOOLEAN NOT NULL,
    decided_at_us BIGINT NOT NULL,
    verdict       TEXT CHECK (verdict IN ('true_positive', 'false_positive')),
    labeled_at_us BIGINT,
    PRIMARY KEY (decision_id, rule_id)
);

-- RuleStats: matches in a time window, grouped by rule and mode. Covering,
-- so the count can be an index-only scan.
CREATE INDEX matches_window ON matches (decided_at_us, rule_id, mode, verdict, errored);

-- ReviewQueue: the latest unlabeled matches of a rule.
CREATE INDEX matches_unlabeled ON matches (rule_id, mode, decided_at_us, decision_id) WHERE verdict IS NULL;

-- Every label ever given, in order. rule_id is '' for a label on the whole
-- decision, which applies to every rule that matched it.
CREATE TABLE labels (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    decision_id   TEXT NOT NULL REFERENCES decisions (id) ON DELETE CASCADE,
    rule_id       TEXT NOT NULL,
    verdict       TEXT NOT NULL CHECK (verdict IN ('true_positive', 'false_positive')),
    labeled_by    TEXT NOT NULL,
    reason        TEXT NOT NULL,
    labeled_at_us BIGINT NOT NULL,
    created_at_us BIGINT NOT NULL
);

CREATE INDEX labels_decision ON labels (decision_id, id);

-- Webhook deliveries for effects, written before they are attempted. There
-- is no foreign key to decisions: the outbox is written synchronously while
-- the decision log is written in batches, so the delivery can come first.
CREATE TABLE outbox (
    id                 BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    decision_id        TEXT NOT NULL,
    effect             TEXT NOT NULL,
    payload            TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('pending', 'delivered', 'dead')),
    attempts           INTEGER NOT NULL DEFAULT 0,
    next_attempt_at_us BIGINT NOT NULL,
    created_at_us      BIGINT NOT NULL,
    updated_at_us      BIGINT NOT NULL,
    last_status_code   INTEGER NOT NULL DEFAULT 0,
    last_error         TEXT NOT NULL DEFAULT '',
    UNIQUE (decision_id, effect)
);

-- Claim: pending deliveries that are due, oldest first.
CREATE INDEX outbox_due ON outbox (next_attempt_at_us, id) WHERE status = 'pending';
