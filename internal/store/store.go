// Package store persists projects, captures, decoded events and the derived
// asset inventory in SQLite, one database file per project set.
//
// SQLite is reached through modernc.org/sqlite, a pure Go implementation, so
// the binary stays static and needs no cgo.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // database/sql driver "sqlite"

	"github.com/rom/otinv/internal/model"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Store is a project database.
type Store struct {
	db   *sql.DB
	path string
}

// Open opens or creates the database at path and applies any migrations it is
// missing.
func Open(ctx context.Context, path string) (*Store, error) {
	// WAL keeps the GUI's readers from blocking the ingest writer; the busy
	// timeout covers the moments they still collide.
	dsn := "file:" + path + "?_pragma=journal_mode(wal)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(normal)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: opening %s: %w", path, err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: opening %s: %w", path, err)
	}

	s := &Store{db: db, path: path}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Path is the database file this store was opened from.
func (s *Store) Path() string { return s.path }

// DB exposes the handle for packages that need their own queries.
func (s *Store) DB() *sql.DB { return s.db }

// migrate applies every embedded migration that is not recorded yet, each in
// its own transaction.
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			name       TEXT    NOT NULL,
			applied_at INTEGER NOT NULL
		)`); err != nil {
		return fmt.Errorf("store: creating migration table: %w", err)
	}

	applied := map[int]bool{}
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("store: reading applied migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: reading applied migrations: %w", err)
		}
		applied[v] = true
	}
	if err := closeRows(rows); err != nil {
		return fmt.Errorf("store: reading applied migrations: %w", err)
	}

	names, err := migrationNames()
	if err != nil {
		return err
	}
	for _, name := range names {
		version, err := migrationVersion(name)
		if err != nil {
			return err
		}
		if applied[version] {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("store: reading migration %s: %w", name, err)
		}
		if err := s.applyMigration(ctx, version, name, string(body)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) applyMigration(ctx context.Context, version int, name, body string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: applying migration %s: %w", name, err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, body); err != nil {
		return fmt.Errorf("store: applying migration %s: %w", name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		version, name, time.Now().UTC().UnixNano()); err != nil {
		return fmt.Errorf("store: recording migration %s: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: committing migration %s: %w", name, err)
	}
	return nil
}

func migrationNames() ([]string, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("store: listing migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".sql" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// migrationVersion reads the numeric prefix of a migration file name.
func migrationVersion(name string) (int, error) {
	prefix, _, ok := strings.Cut(name, "_")
	if !ok {
		return 0, fmt.Errorf("store: migration %s has no version prefix", name)
	}
	v, err := strconv.Atoi(prefix)
	if err != nil {
		return 0, fmt.Errorf("store: migration %s has a non-numeric version: %w", name, err)
	}
	return v, nil
}

// SchemaVersion is the highest applied migration version.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("store: reading schema version: %w", err)
	}
	return int(v.Int64), nil
}

// EnsureProject returns the project with this name, creating it if needed.
func (s *Store) EnsureProject(ctx context.Context, name string) (model.Project, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return model.Project{}, errors.New("store: project name must not be empty")
	}

	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO projects (name, created_at) VALUES (?, ?)
		 ON CONFLICT (name) DO NOTHING`,
		name, now.UnixNano())
	if err != nil {
		return model.Project{}, fmt.Errorf("store: creating project %q: %w", name, err)
	}

	var (
		id      int64
		created int64
	)
	err = s.db.QueryRowContext(ctx,
		`SELECT id, created_at FROM projects WHERE name = ?`, name).Scan(&id, &created)
	if err != nil {
		return model.Project{}, fmt.Errorf("store: reading project %q: %w", name, err)
	}
	return model.Project{ID: id, Name: name, CreatedAt: time.Unix(0, created).UTC()}, nil
}

// Projects lists every project, oldest first.
func (s *Store) Projects(ctx context.Context) ([]model.Project, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, created_at FROM projects ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: listing projects: %w", err)
	}
	var out []model.Project
	for rows.Next() {
		var (
			p       model.Project
			created int64
		)
		if err := rows.Scan(&p.ID, &p.Name, &created); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: listing projects: %w", err)
		}
		p.CreatedAt = time.Unix(0, created).UTC()
		out = append(out, p)
	}
	return out, closeRows(rows)
}

// DeleteProject removes a project and everything recorded under it.
func (s *Store) DeleteProject(ctx context.Context, projectID int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM projects WHERE id = ?`, projectID); err != nil {
		return fmt.Errorf("store: deleting project %d: %w", projectID, err)
	}
	return nil
}

// CaptureRow is a stored capture.
type CaptureRow struct {
	PK int64 `json:"-"`
	model.Capture
	IngestedAt time.Time `json:"ingested_at"`
}

// SaveCapture records a capture. The digest identifies it, so re-ingesting the
// same file into the same project returns the existing row with inserted
// false rather than duplicating it.
func (s *Store) SaveCapture(ctx context.Context, projectID int64, c model.Capture) (pk int64, inserted bool, err error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO captures
			(project_id, capture_id, path, sha256, bytes, packets, link_type,
			 first_seen, last_seen, ingested_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (project_id, sha256) DO NOTHING`,
		projectID, c.ID, c.Path, c.SHA256, c.Bytes, c.Packets, c.LinkType,
		c.FirstSeen.UTC().UnixNano(), c.LastSeen.UTC().UnixNano(),
		time.Now().UTC().UnixNano())
	if err != nil {
		return 0, false, fmt.Errorf("store: saving capture %s: %w", c.Path, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, false, fmt.Errorf("store: saving capture %s: %w", c.Path, err)
	}

	err = s.db.QueryRowContext(ctx,
		`SELECT id FROM captures WHERE project_id = ? AND sha256 = ?`,
		projectID, c.SHA256).Scan(&pk)
	if err != nil {
		return 0, false, fmt.Errorf("store: reading capture %s: %w", c.Path, err)
	}
	return pk, affected > 0, nil
}

// UpdateCapture fills in the counts and time range once the capture has been
// read.
func (s *Store) UpdateCapture(ctx context.Context, pk int64, c model.Capture) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE captures
		 SET capture_id = ?, packets = ?, bytes = ?, link_type = ?, first_seen = ?, last_seen = ?
		 WHERE id = ?`,
		c.ID, c.Packets, c.Bytes, c.LinkType,
		c.FirstSeen.UTC().UnixNano(), c.LastSeen.UTC().UnixNano(), pk)
	if err != nil {
		return fmt.Errorf("store: updating capture %d: %w", pk, err)
	}
	return nil
}

// DeleteCapture removes a capture and its events, which is what a re-ingest of
// the same file needs.
func (s *Store) DeleteCapture(ctx context.Context, pk int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM captures WHERE id = ?`, pk); err != nil {
		return fmt.Errorf("store: deleting capture %d: %w", pk, err)
	}
	return nil
}

// Captures lists a project's captures, most recently ingested first.
func (s *Store) Captures(ctx context.Context, projectID int64) ([]CaptureRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, capture_id, path, sha256, bytes, packets, link_type,
		        first_seen, last_seen, ingested_at
		 FROM captures WHERE project_id = ? ORDER BY ingested_at DESC, id DESC`,
		projectID)
	if err != nil {
		return nil, fmt.Errorf("store: listing captures: %w", err)
	}
	var out []CaptureRow
	for rows.Next() {
		var (
			c                     CaptureRow
			first, last, ingested int64
		)
		if err := rows.Scan(&c.PK, &c.ID, &c.Path, &c.SHA256, &c.Bytes, &c.Packets,
			&c.LinkType, &first, &last, &ingested); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: listing captures: %w", err)
		}
		c.FirstSeen = time.Unix(0, first).UTC()
		c.LastSeen = time.Unix(0, last).UTC()
		c.IngestedAt = time.Unix(0, ingested).UTC()
		out = append(out, c)
	}
	return out, closeRows(rows)
}

// closeRows closes rows and reports the first of a close or iteration error.
func closeRows(rows *sql.Rows) error {
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	return rows.Close()
}
