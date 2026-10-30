-- The API token each label was given with, by its name in catraca.yaml,
-- next to the free-form labeled_by the caller sends: labeled_by says who
-- the caller claims labeled, client which credential sent the label. It is
-- '' for labels given before this column, and for labels not given through
-- the API. Keep this file in step with migrations/postgres.

ALTER TABLE labels ADD COLUMN client TEXT NOT NULL DEFAULT '';
