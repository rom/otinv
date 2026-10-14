package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/rom/otinv/internal/model"
)

// findingColumns is the finding row as every query selects it.
const findingColumns = `finding_id, rule_id, title, summary, description, severity,
	technique, technique_name, status, assignee, note, src, dst, protocol,
	count, first_seen, last_seen, evidence, details`

// SaveFindings writes a run's findings, keeping the triage state.
//
// A finding's id is derived from the rule and what the finding is about, so a
// second run over the same project updates the same row: the counts and the
// time range move, the status, the assignee and the note do not. Findings the
// run did not produce are removed, because a project that no longer holds the
// traffic should not keep the finding about it.
func (s *Store) SaveFindings(ctx context.Context, projectID int64, findings []model.Finding) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: saving findings: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Every row this run writes carries the same stamp, so the rows it did
	// not write are exactly the ones left over from an earlier run — which
	// is a prune that needs no list of ids and no limit on how many there
	// can be.
	now := time.Now().UTC().UnixNano()
	for _, f := range findings {
		evidence, err := marshalJSON(f.Evidence)
		if err != nil {
			return fmt.Errorf("store: encoding finding evidence: %w", err)
		}
		details, err := marshalJSON(f.Details)
		if err != nil {
			return fmt.Errorf("store: encoding finding details: %w", err)
		}
		status := f.Status
		if !status.Valid() {
			status = model.StatusNew
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO findings
				(project_id, finding_id, rule_id, title, summary, description, severity,
				 technique, technique_name, status, assignee, note, src, dst, protocol,
				 count, first_seen, last_seen, evidence, details, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT (project_id, finding_id) DO UPDATE SET
				rule_id = excluded.rule_id,
				title = excluded.title,
				summary = excluded.summary,
				description = excluded.description,
				severity = excluded.severity,
				technique = excluded.technique,
				technique_name = excluded.technique_name,
				src = excluded.src,
				dst = excluded.dst,
				protocol = excluded.protocol,
				count = excluded.count,
				first_seen = excluded.first_seen,
				last_seen = excluded.last_seen,
				evidence = excluded.evidence,
				details = excluded.details,
				updated_at = excluded.updated_at`,
			projectID, f.ID, f.RuleID, f.Title, f.Summary, nullString(f.Description),
			string(f.Severity), nullString(f.Technique), nullString(f.TechniqueName),
			string(status), nullString(f.Assignee), nullString(f.Note),
			nullString(f.Src), nullString(f.Dst), nullString(f.Protocol),
			f.Count, f.FirstSeen.UTC().UnixNano(), f.LastSeen.UTC().UnixNano(),
			evidence, details, now, now); err != nil {
			return fmt.Errorf("store: inserting finding %s: %w", f.ID, err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM findings WHERE project_id = ? AND updated_at < ?`,
		projectID, now); err != nil {
		return fmt.Errorf("store: removing stale findings: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: saving findings: %w", err)
	}
	return nil
}

// FindingQuery selects and pages the findings list.
type FindingQuery struct {
	ProjectID int64
	Severity  string
	Status    string
	RuleID    string
	Protocol  string
	// Open narrows to the findings still wanting attention, which is what the
	// triage view opens on.
	Open bool
	// Search matches the summary, the endpoints and the rule.
	Search string
	Limit  int
	Offset int
	Sort   string
	Desc   bool
}

// FindingSortColumns are the orderings the findings table offers. As
// everywhere else, the map is a whitelist so that a column name from a URL
// never reaches a query.
var FindingSortColumns = map[string]string{
	"severity": "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3" +
		" WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END",
	"rule":   "rule_id",
	"status": "status",
	"src":    "src",
	"dst":    "dst",
	"count":  "count",
	"last":   "last_seen",
	"first":  "first_seen",
}

func (q FindingQuery) where() ([]string, []any) {
	where := []string{"project_id = ?"}
	args := []any{q.ProjectID}
	if q.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, q.Severity)
	}
	if q.Status != "" {
		where = append(where, "status = ?")
		args = append(args, q.Status)
	}
	if q.Open {
		where = append(where, "status IN ('new', 'investigating')")
	}
	if q.RuleID != "" {
		where = append(where, "rule_id = ?")
		args = append(args, q.RuleID)
	}
	if q.Protocol != "" {
		where = append(where, "protocol = ?")
		args = append(args, q.Protocol)
	}
	if q.Search != "" {
		like := "%" + q.Search + "%"
		where = append(where, `(summary LIKE ? OR title LIKE ? OR rule_id LIKE ?
			OR IFNULL(src, '') LIKE ? OR IFNULL(dst, '') LIKE ? OR IFNULL(note, '') LIKE ?)`)
		args = append(args, like, like, like, like, like, like)
	}
	return where, args
}

// Findings returns one page of findings with the total number of matches.
//
// The default order is the one triage wants: most serious first, then the
// most recent.
func (s *Store) Findings(ctx context.Context, q FindingQuery) ([]model.Finding, int, error) {
	where, args := q.where()

	var total int
	//nolint:gosec // G202: only clauses and placeholders are concatenated
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM findings WHERE `+joinAnd(where), args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: counting findings: %w", err)
	}

	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	order := FindingSortColumns["severity"] + " DESC, last_seen DESC"
	if column, ok := FindingSortColumns[q.Sort]; ok {
		order = column
		if q.Desc {
			order += " DESC"
		}
	}
	order += ", finding_id"

	//nolint:gosec // G202: the ordering comes from the FindingSortColumns whitelist
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+findingColumns+` FROM findings WHERE `+joinAnd(where)+
			` ORDER BY `+order+` LIMIT ? OFFSET ?`,
		append(args, limit, max(q.Offset, 0))...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: querying findings: %w", err)
	}
	out, err := scanFindings(rows)
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// Finding returns one finding by its id, or nil when the project has no such
// finding.
func (s *Store) Finding(ctx context.Context, projectID int64, id string) (*model.Finding, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+findingColumns+` FROM findings WHERE project_id = ? AND finding_id = ?`,
		projectID, id)
	if err != nil {
		return nil, fmt.Errorf("store: reading finding %s: %w", id, err)
	}
	out, err := scanFindings(rows)
	if err != nil || len(out) == 0 {
		return nil, err
	}
	return &out[0], nil
}

// Triage is the part of a finding that belongs to the analyst rather than to
// the rules.
type Triage struct {
	Status   model.FindingStatus
	Assignee string
	Note     string
}

// SetTriage records where a finding sits in the workflow. It is the one write
// the GUI makes to a finding, and a re-run of the rules leaves it alone.
func (s *Store) SetTriage(ctx context.Context, projectID int64, id string, t Triage) error {
	if !t.Status.Valid() {
		return fmt.Errorf("store: %q is not a triage status", t.Status)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE findings SET status = ?, assignee = ?, note = ?, updated_at = ?
		 WHERE project_id = ? AND finding_id = ?`,
		string(t.Status), nullString(t.Assignee), nullString(t.Note),
		time.Now().UTC().UnixNano(), projectID, id)
	if err != nil {
		return fmt.Errorf("store: updating finding %s: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("store: no finding %s in this project", id)
	}
	return nil
}

// SetTriageMany applies one triage state to several findings at once, which
// is the bulk action the findings view offers.
func (s *Store) SetTriageMany(ctx context.Context, projectID int64, ids []string, t Triage) (int, error) {
	if !t.Status.Valid() {
		return 0, fmt.Errorf("store: %q is not a triage status", t.Status)
	}
	if len(ids) == 0 {
		return 0, nil
	}

	args := []any{string(t.Status), time.Now().UTC().UnixNano(), projectID}
	for _, id := range ids {
		args = append(args, id)
	}
	//nolint:gosec // G202: only placeholders are concatenated
	res, err := s.db.ExecContext(ctx,
		`UPDATE findings SET status = ?, updated_at = ?
		 WHERE project_id = ? AND finding_id IN (`+inPlaceholders(len(ids))+`)`, args...)
	if err != nil {
		return 0, fmt.Errorf("store: updating findings: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: counting the findings updated: %w", err)
	}
	return int(n), nil
}

// findingDimensions are the columns the findings can be counted by.
var findingDimensions = map[string]string{
	"severity": "severity",
	"status":   "status",
	"rule":     "rule_id",
	"protocol": "COALESCE(NULLIF(protocol, ''), '')",
}

// CountFindingsBy groups the findings for the dashboard and the filter menus.
func (s *Store) CountFindingsBy(ctx context.Context, projectID int64, dimension string) ([]Bucket, error) {
	column, ok := findingDimensions[dimension]
	if !ok {
		return nil, fmt.Errorf("store: %q is not a dimension findings can be counted by", dimension)
	}
	//nolint:gosec // G202: the column comes from the findingDimensions whitelist
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+column+`, COUNT(*) FROM findings WHERE project_id = ?
		 GROUP BY `+column+` ORDER BY 2 DESC, 1 ASC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: counting findings by %s: %w", dimension, err)
	}
	return scanBuckets(rows, dimension)
}

// CountOpenFindings counts the findings still wanting attention, which is the
// number the dashboard puts on a tile.
func (s *Store) CountOpenFindings(ctx context.Context, projectID int64) (int64, error) {
	var n int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM findings WHERE project_id = ? AND status IN ('new', 'investigating')`,
		projectID).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: counting open findings: %w", err)
	}
	return n, nil
}

func scanFindings(rows *sql.Rows) ([]model.Finding, error) {
	var out []model.Finding
	for rows.Next() {
		var (
			f                   model.Finding
			severity, status    string
			description         sql.NullString
			technique, techName sql.NullString
			assignee, note      sql.NullString
			src, dst, protocol  sql.NullString
			firstSeen, lastSeen int64
			evidence, details   []byte
		)
		if err := rows.Scan(&f.ID, &f.RuleID, &f.Title, &f.Summary, &description, &severity,
			&technique, &techName, &status, &assignee, &note, &src, &dst, &protocol,
			&f.Count, &firstSeen, &lastSeen, &evidence, &details); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: scanning finding: %w", err)
		}
		f.Severity = model.Severity(severity)
		f.Status = model.FindingStatus(status)
		f.Description = description.String
		f.Technique = technique.String
		f.TechniqueName = techName.String
		f.Assignee = assignee.String
		f.Note = note.String
		f.Src = src.String
		f.Dst = dst.String
		f.Protocol = protocol.String
		f.FirstSeen = time.Unix(0, firstSeen).UTC()
		f.LastSeen = time.Unix(0, lastSeen).UTC()
		if err := unmarshalJSON(evidence, &f.Evidence); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: decoding finding evidence: %w", err)
		}
		if err := unmarshalJSON(details, &f.Details); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: decoding finding details: %w", err)
		}
		out = append(out, f)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("store: reading findings: %w", err)
	}
	return out, nil
}

// FindingRules lists the rules that produced findings in a project, for the
// filter menu.
func (s *Store) FindingRules(ctx context.Context, projectID int64) ([]string, error) {
	return s.distinct(ctx,
		`SELECT DISTINCT rule_id FROM findings WHERE project_id = ? ORDER BY rule_id`, projectID)
}
