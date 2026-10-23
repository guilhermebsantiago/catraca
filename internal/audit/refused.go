package audit

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// A write can fail because the database cannot take writes at all (it is
// down, out of disk, read-only after a failover, locked) or because it
// refuses the values in one statement. Only the second is worth retrying row
// by row: the other rows of the batch may well go in. Each dialect's refused
// function tells them apart from the driver's error, and anything it does
// not recognize counts as the database being unavailable.

// sqliteRefused reports a constraint violation, a trigger's RAISE among
// them, a value too big, or a type mismatch.
func sqliteRefused(err error) bool {
	var e *sqlite.Error
	if !errors.As(err, &e) {
		return false
	}
	// The low byte is the primary result code under an extended one.
	switch e.Code() & 0xff {
	case sqlite3.SQLITE_CONSTRAINT, sqlite3.SQLITE_TOOBIG, sqlite3.SQLITE_MISMATCH:
		return true
	}
	return false
}

// postgresRefused reports the SQLSTATE classes about the data in the
// statement: 22, data exception (a NUL byte or invalid UTF-8 in text, a
// \u0000 escape in jsonb, a number out of range), 23, integrity constraint
// violation, and 54, program limit exceeded (a row too big).
func postgresRefused(err error) bool {
	var e *pgconn.PgError
	if !errors.As(err, &e) || len(e.Code) < 2 {
		return false
	}
	switch e.Code[:2] {
	case "22", "23", "54":
		return true
	}
	return false
}
