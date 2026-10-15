package audit

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations
var migrationsFS embed.FS

// migration is one numbered SQL file, such as 0001_init.sql.
type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations reads the migrations in dir, sorted by version.
func loadMigrations(dir string) ([]migration, error) {
	entries, err := fs.ReadDir(migrationsFS, dir)
	if err != nil {
		return nil, fmt.Errorf("audit: read migrations: %w", err)
	}
	var ms []migration
	seen := map[int]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			return nil, fmt.Errorf("audit: migration %s: name must be <version>_<name>.sql", name)
		}
		v, err := strconv.Atoi(prefix)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("audit: migration %s: bad version %q", name, prefix)
		}
		if other, dup := seen[v]; dup {
			return nil, fmt.Errorf("audit: migrations %s and %s share version %d", other, name, v)
		}
		seen[v] = name
		body, err := fs.ReadFile(migrationsFS, path.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("audit: read migration %s: %w", name, err)
		}
		ms = append(ms, migration{version: v, name: name, sql: string(body)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	return ms, nil
}

// migrate applies the migrations the database has not seen, in order, in one
// transaction, and records each in schema_migrations. Both databases run DDL
// transactionally, so a failed migration leaves the schema as it was.
func migrate(ctx context.Context, db *sql.DB, d dialect) error {
	ms, err := loadMigrations(d.migrations)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: migrate: %w", err)
	}
	defer tx.Rollback()

	if d.lockMigrations != "" {
		if _, err := tx.ExecContext(ctx, d.lockMigrations); err != nil {
			return fmt.Errorf("audit: migrate: lock: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
    version       BIGINT PRIMARY KEY,
    name          TEXT NOT NULL,
    applied_at_us BIGINT NOT NULL
)`); err != nil {
		return fmt.Errorf("audit: migrate: create schema_migrations: %w", err)
	}

	applied := map[int]bool{}
	latestApplied := 0
	rows, err := tx.QueryContext(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return fmt.Errorf("audit: migrate: read schema_migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("audit: migrate: read schema_migrations: %w", err)
		}
		applied[v] = true
		latestApplied = max(latestApplied, v)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("audit: migrate: read schema_migrations: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("audit: migrate: read schema_migrations: %w", err)
	}
	if len(ms) > 0 && latestApplied > ms[len(ms)-1].version {
		return fmt.Errorf("audit: database schema is at version %d, newer than this build of Catraca knows (%d)",
			latestApplied, ms[len(ms)-1].version)
	}

	insert := d.rebind("INSERT INTO schema_migrations (version, name, applied_at_us) VALUES (?, ?, ?)")
	for _, m := range ms {
		if applied[m.version] {
			continue
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			return fmt.Errorf("audit: migration %s: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, insert, m.version, m.name, toMicros(time.Now())); err != nil {
			return fmt.Errorf("audit: migration %s: record: %w", m.name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: migrate: commit: %w", err)
	}
	return nil
}
