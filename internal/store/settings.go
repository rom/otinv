package store

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// GUI settings.
//
// They are stored per project rather than per user, because the GUI has no
// accounts yet: everything on this database is visible to whoever can reach
// the loopback port. The table has room for a user column when accounts
// arrive, and a per-user value will win over the project-wide one.
//
// Keys and values are opaque here. What a key means, which values are legal
// and what the default is belong to the web package, which is what renders
// them; the store's job is to keep them.

// maxSettingKeys caps how many settings one project may hold, so that a
// client cannot grow the table by posting new keys.
const maxSettingKeys = 64

// maxSettingValueLen caps a stored value.
const maxSettingValueLen = 256

// Settings reads every setting of a project.
func (s *Store) Settings(ctx context.Context, projectID int64) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT key, value FROM settings WHERE project_id = ? ORDER BY key`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: reading settings: %w", err)
	}
	out := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: scanning a setting: %w", err)
		}
		out[key] = value
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("store: reading settings: %w", err)
	}
	return out, nil
}

// SaveSettings writes the given settings, leaving the rest alone. A value of
// the empty string deletes its key, which is how a setting is returned to its
// default.
func (s *Store) SaveSettings(ctx context.Context, projectID int64, values map[string]string) error {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxSettingKeys {
		return fmt.Errorf("store: %d settings at once exceeds the %d allowed", len(keys), maxSettingKeys)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: saving settings: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().UnixNano()
	for _, key := range keys {
		value := values[key]
		if len(value) > maxSettingValueLen {
			return fmt.Errorf("store: the value of %q is %d octets, more than the %d allowed",
				key, len(value), maxSettingValueLen)
		}
		if value == "" {
			if _, err := tx.ExecContext(ctx,
				`DELETE FROM settings WHERE project_id = ? AND key = ?`, projectID, key); err != nil {
				return fmt.Errorf("store: clearing the setting %q: %w", key, err)
			}
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO settings (project_id, key, value, updated_at) VALUES (?, ?, ?, ?)
			 ON CONFLICT (project_id, key) DO UPDATE SET value = excluded.value,
			 updated_at = excluded.updated_at`,
			projectID, key, value, now); err != nil {
			return fmt.Errorf("store: saving the setting %q: %w", key, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: saving settings: %w", err)
	}
	return nil
}
