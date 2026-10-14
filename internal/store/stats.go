package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rom/otinv/internal/model"
)

// Aggregates for the dashboard, the flow and matrix views and the per-protocol
// statistics.
//
// Every query here is a GROUP BY over the events table with the project as the
// first predicate, which is what the (project_id, …) indexes are for. The
// counts are read straight out of SQLite rather than by walking events in Go:
// a project with a million events has to answer these in well under the 300 ms
// CLAUDE.md asks of a page.

// Bucket is one labelled count.
type Bucket struct {
	Label string
	Count int64
}

// Summary is the project at a glance.
type Summary struct {
	Assets      int64
	Captures    int64
	Events      int64
	Malformed   int64
	Anomalies   int64
	Exceptions  int64
	Protocols   int64
	Flows       int64
	Packets     int64
	Bytes       int64
	FirstSeen   time.Time
	LastSeen    time.Time
	Controllers int64
	Gateways    int64
}

// Summary counts what the dashboard shows above its charts.
func (s *Store) Summary(ctx context.Context, projectID int64) (Summary, error) {
	var out Summary
	var first, last sql.NullInt64

	row := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*),
		       COALESCE(SUM(malformed), 0),
		       COALESCE(SUM(CASE WHEN exception IS NOT NULL AND exception <> '' THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN attrs LIKE '%"anomaly"%' THEN 1 ELSE 0 END), 0),
		       COUNT(DISTINCT protocol),
		       MIN(ts), MAX(ts)
		FROM events WHERE project_id = ?`, projectID)
	if err := row.Scan(&out.Events, &out.Malformed, &out.Exceptions, &out.Anomalies,
		&out.Protocols, &first, &last); err != nil {
		return out, fmt.Errorf("store: summarising events: %w", err)
	}
	if first.Valid {
		out.FirstSeen = time.Unix(0, first.Int64).UTC()
	}
	if last.Valid {
		out.LastSeen = time.Unix(0, last.Int64).UTC()
	}

	row = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*),
		       COALESCE(SUM(CASE WHEN role = ? THEN 1 ELSE 0 END), 0),
		       COALESCE(SUM(is_gateway), 0)
		FROM assets WHERE project_id = ?`, string(model.RoleController), projectID)
	if err := row.Scan(&out.Assets, &out.Controllers, &out.Gateways); err != nil {
		return out, fmt.Errorf("store: summarising assets: %w", err)
	}

	row = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(packets), 0), COALESCE(SUM(bytes), 0)
		FROM captures WHERE project_id = ?`, projectID)
	if err := row.Scan(&out.Captures, &out.Packets, &out.Bytes); err != nil {
		return out, fmt.Errorf("store: summarising captures: %w", err)
	}

	//nolint:gosec // G202: the endpoint expressions are this package's own
	row = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM (
			SELECT 1 FROM events WHERE project_id = ?
			GROUP BY `+endpointSQL("src")+`, `+endpointSQL("dst")+`, protocol)`, projectID)
	if err := row.Scan(&out.Flows); err != nil {
		return out, fmt.Errorf("store: counting flows: %w", err)
	}
	return out, nil
}

// endpointSQL is how an endpoint is identified: the IP where there is one, and
// the MAC where there is not. The layer 2 protocols — GOOSE, PROFINET DCP —
// have no IP at all, and a flow of theirs is identified by its MACs.
func endpointSQL(side string) string {
	return "CASE WHEN " + side + "_ip <> '' THEN " + side + "_ip ELSE COALESCE(" + side + "_mac, '') END"
}

// countColumns are the dimensions the dashboard and the statistics view can
// group events by. The map is a whitelist: a dimension name arriving from a
// URL is looked up here and never reaches the query.
var countColumns = map[string]string{
	"protocol":  "protocol",
	"class":     "class",
	"operation": "operation",
	"direction": "direction",
	"transport": "transport",
	"exception": "exception",
	"port":      "server_port",
}

// CountEventsBy groups events by one dimension, most frequent first.
func (s *Store) CountEventsBy(ctx context.Context, projectID int64, dimension, protocol string,
	limit int) ([]Bucket, error) {

	column, ok := countColumns[dimension]
	if !ok {
		return nil, fmt.Errorf("store: %q is not a dimension events can be counted by", dimension)
	}
	where := []string{"project_id = ?"}
	args := []any{projectID}
	if protocol != "" {
		where = append(where, "protocol = ?")
		args = append(args, protocol)
	}
	if dimension == "exception" {
		where = append(where, "exception IS NOT NULL", "exception <> ''")
	}
	if dimension == "port" {
		where = append(where, "server_port IS NOT NULL")
	}
	if limit <= 0 || limit > 200 {
		limit = 200
	}
	args = append(args, limit)

	//nolint:gosec // G202: the column comes from the countColumns whitelist
	rows, err := s.db.QueryContext(ctx,
		`SELECT CAST(`+column+` AS TEXT), COUNT(*) FROM events WHERE `+joinAnd(where)+
			` GROUP BY `+column+` ORDER BY 2 DESC, 1 ASC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: counting events by %s: %w", dimension, err)
	}
	return scanBuckets(rows, dimension)
}

// assetDimensions are the columns of the inventory the dashboard groups by.
var assetDimensions = map[string]string{
	"role":   "role",
	"vendor": "COALESCE(NULLIF(vendor, ''), '')",
	// An asset nothing placed is a bucket of its own rather than a gap: how
	// much of a plant could not be placed is worth seeing.
	"level": "COALESCE(CAST(purdue_level AS TEXT), '" + LevelUnplaced + "')",
}

// CountAssetsBy groups the inventory by one of its columns.
func (s *Store) CountAssetsBy(ctx context.Context, projectID int64, dimension string) ([]Bucket, error) {
	column, ok := assetDimensions[dimension]
	if !ok {
		return nil, fmt.Errorf("store: %q is not a dimension assets can be counted by", dimension)
	}
	//nolint:gosec // G202: the column comes from the assetDimensions whitelist
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+column+`, COUNT(*) FROM assets WHERE project_id = ?
		 GROUP BY `+column+` ORDER BY 2 DESC, 1 ASC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: counting assets by %s: %w", dimension, err)
	}
	return scanBuckets(rows, dimension)
}

func scanBuckets(rows *sql.Rows, what string) ([]Bucket, error) {
	var out []Bucket
	for rows.Next() {
		var (
			label sql.NullString
			count int64
		)
		if err := rows.Scan(&label, &count); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: scanning %s counts: %w", what, err)
		}
		out = append(out, Bucket{Label: label.String, Count: count})
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("store: counting %s: %w", what, err)
	}
	return out, nil
}

// TimeBucket is one interval of the timeline, with the classifications seen
// in it kept apart so that a burst of writes is visible against a background
// of reads.
type TimeBucket struct {
	Start   time.Time
	End     time.Time
	Count   int64
	Classes map[model.Classification]int64
}

// Timeline divides the project's events into equal intervals.
//
// The interval width is derived from the capture's own time range rather than
// from the clock, because a capture is minutes long and a project's captures
// may be years apart.
func (s *Store) Timeline(ctx context.Context, projectID int64, buckets int,
	protocol string) ([]TimeBucket, error) {

	if buckets <= 0 || buckets > 500 {
		buckets = 60
	}
	var first, last sql.NullInt64
	where := []string{"project_id = ?"}
	args := []any{projectID}
	if protocol != "" {
		where = append(where, "protocol = ?")
		args = append(args, protocol)
	}
	//nolint:gosec // G202: only clauses and placeholders are concatenated here
	row := s.db.QueryRowContext(ctx,
		`SELECT MIN(ts), MAX(ts) FROM events WHERE `+joinAnd(where), args...)
	if err := row.Scan(&first, &last); err != nil {
		return nil, fmt.Errorf("store: reading the event time range: %w", err)
	}
	if !first.Valid || !last.Valid {
		return nil, nil
	}

	span := last.Int64 - first.Int64 + 1
	width := span / int64(buckets)
	if width < 1 {
		width = 1
		buckets = int(span)
	}

	//nolint:gosec // G202: only clauses and placeholders are concatenated here
	rows, err := s.db.QueryContext(ctx,
		`SELECT MIN((ts - ?) / ?, ?), class, COUNT(*) FROM events WHERE `+joinAnd(where)+
			` GROUP BY 1, 2 ORDER BY 1`,
		append([]any{first.Int64, width, int64(buckets - 1)}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("store: building the timeline: %w", err)
	}

	out := make([]TimeBucket, buckets)
	for i := range out {
		start := first.Int64 + int64(i)*width
		out[i] = TimeBucket{
			Start:   time.Unix(0, start).UTC(),
			End:     time.Unix(0, start+width).UTC(),
			Classes: map[model.Classification]int64{},
		}
	}
	for rows.Next() {
		var (
			bucket int64
			class  string
			count  int64
		)
		if err := rows.Scan(&bucket, &class, &count); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: scanning the timeline: %w", err)
		}
		if bucket < 0 || bucket >= int64(len(out)) {
			continue
		}
		out[bucket].Count += count
		out[bucket].Classes[model.Classification(class)] += count
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("store: building the timeline: %w", err)
	}
	return out, nil
}

// Flow is one direction of traffic between two endpoints over one protocol,
// which is what the communication matrix is made of.
type Flow struct {
	Src        string
	Dst        string
	Protocol   string
	Transport  model.Transport
	ServerPort uint16
	Events     int64
	Malformed  int64
	Classes    map[model.Classification]int64
	FirstSeen  time.Time
	LastSeen   time.Time
}

// FlowQuery selects and orders flows.
type FlowQuery struct {
	ProjectID int64
	Protocol  string
	Class     string
	Endpoint  string
	Search    string
	Limit     int
	Offset    int
	Sort      string
	Desc      bool
}

// FlowSortColumns are the orderings the flow table offers. As with the asset
// list, the map is a whitelist so that a column name from a URL never reaches
// the query.
var FlowSortColumns = map[string]string{
	"src":      "src",
	"dst":      "dst",
	"protocol": "protocol",
	"events":   "events",
	"first":    "first_seen",
	"last":     "last_seen",
}

// Flows aggregates events into flows, with the total number of them.
func (s *Store) Flows(ctx context.Context, q FlowQuery) ([]Flow, int, error) {
	where := []string{"project_id = ?"}
	args := []any{q.ProjectID}
	if q.Protocol != "" {
		where = append(where, "protocol = ?")
		args = append(args, q.Protocol)
	}
	if q.Class != "" {
		where = append(where, "class = ?")
		args = append(args, q.Class)
	}
	if q.Endpoint != "" {
		where = append(where, "("+endpointSQL("src")+" = ? OR "+endpointSQL("dst")+" = ?)")
		args = append(args, q.Endpoint, q.Endpoint)
	}
	if q.Search != "" {
		like := "%" + q.Search + "%"
		where = append(where, "("+endpointSQL("src")+" LIKE ? OR "+endpointSQL("dst")+" LIKE ?"+
			" OR protocol LIKE ?)")
		args = append(args, like, like, like)
	}

	// The grouping repeats the endpoint expressions rather than the aliases,
	// because the count subquery below selects no columns to alias.
	group := `GROUP BY ` + endpointSQL("src") + `, ` + endpointSQL("dst") + `, protocol`
	selectSQL := `SELECT ` + endpointSQL("src") + ` AS src, ` + endpointSQL("dst") + ` AS dst,
		protocol, transport, MAX(COALESCE(server_port, 0)),
		COUNT(*) AS events, COALESCE(SUM(malformed), 0),
		MIN(ts) AS first_seen, MAX(ts) AS last_seen,
		` + classSumsSQL() + `
		FROM events WHERE ` + joinAnd(where) + ` ` + group

	//nolint:gosec // G202: only clauses and placeholders are concatenated here
	countRow := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM (SELECT 1 FROM events WHERE `+joinAnd(where)+` `+group+`)`, args...)
	var total int
	if err := countRow.Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: counting flows: %w", err)
	}

	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	order := "events DESC"
	if column, ok := FlowSortColumns[q.Sort]; ok {
		order = column
		if q.Desc {
			order += " DESC"
		}
	}
	//nolint:gosec // G202: the ordering comes from the FlowSortColumns whitelist
	rows, err := s.db.QueryContext(ctx,
		selectSQL+` ORDER BY `+order+`, src, dst, protocol LIMIT ? OFFSET ?`,
		append(args, limit, max(q.Offset, 0))...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: querying flows: %w", err)
	}

	var out []Flow
	for rows.Next() {
		var (
			f                   Flow
			transport           string
			port                int64
			firstSeen, lastSeen int64
			classes             = make([]int64, len(classOrder))
			targets             = make([]any, 0, 9+len(classOrder))
		)
		targets = append(targets, &f.Src, &f.Dst, &f.Protocol, &transport, &port,
			&f.Events, &f.Malformed, &firstSeen, &lastSeen)
		for i := range classes {
			targets = append(targets, &classes[i])
		}
		if err := rows.Scan(targets...); err != nil {
			_ = rows.Close()
			return nil, 0, fmt.Errorf("store: scanning a flow: %w", err)
		}
		f.Transport = model.Transport(transport)
		f.ServerPort = uint16(port)
		f.FirstSeen = time.Unix(0, firstSeen).UTC()
		f.LastSeen = time.Unix(0, lastSeen).UTC()
		f.Classes = map[model.Classification]int64{}
		for i, c := range classOrder {
			if classes[i] > 0 {
				f.Classes[c] = classes[i]
			}
		}
		out = append(out, f)
	}
	if err := closeRows(rows); err != nil {
		return nil, 0, fmt.Errorf("store: querying flows: %w", err)
	}
	return out, total, nil
}

// classOrder is the order the class columns are selected and scanned in. It
// is the shared presentation order, so a flow's columns line up with what the
// GUI and the exports show.
var classOrder = model.Classifications

// classSumsSQL counts each classification within a group, so that a flow
// carrying one write among a thousand reads says so.
func classSumsSQL() string {
	parts := make([]string, 0, len(classOrder))
	for _, c := range classOrder {
		// The classification set is this package's own constants, not input.
		parts = append(parts,
			"COALESCE(SUM(CASE WHEN class = '"+string(c)+"' THEN 1 ELSE 0 END), 0)")
	}
	return strings.Join(parts, ", ")
}

// MatrixCell is one square of the communication matrix.
type MatrixCell struct {
	Src    string
	Dst    string
	Events int64
}

// Matrix is a square of endpoints and the traffic between them.
type Matrix struct {
	Endpoints []string
	Cells     []MatrixCell
	Max       int64
	Truncated bool
}

// CommunicationMatrix builds the src × dst matrix of a project.
//
// The endpoints are the busiest ones, capped: a matrix of a thousand assets is
// neither renderable nor readable, and an analyst looking at a specific pair
// has the flow table for that.
func (s *Store) CommunicationMatrix(ctx context.Context, projectID int64, protocol, class string,
	limit int) (Matrix, error) {

	if limit <= 0 || limit > 60 {
		limit = 30
	}
	where := []string{"project_id = ?"}
	args := []any{projectID}
	if protocol != "" {
		where = append(where, "protocol = ?")
		args = append(args, protocol)
	}
	if class != "" {
		where = append(where, "class = ?")
		args = append(args, class)
	}

	// The busiest endpoints, counting traffic in either direction.
	//nolint:gosec // G202: only clauses and placeholders are concatenated here
	rows, err := s.db.QueryContext(ctx,
		`SELECT endpoint, SUM(n) AS total FROM (
			SELECT `+endpointSQL("src")+` AS endpoint, COUNT(*) AS n FROM events
			WHERE `+joinAnd(where)+` GROUP BY 1
			UNION ALL
			SELECT `+endpointSQL("dst")+` AS endpoint, COUNT(*) AS n FROM events
			WHERE `+joinAnd(where)+` GROUP BY 1)
		 WHERE endpoint <> '' GROUP BY endpoint ORDER BY total DESC, endpoint LIMIT ?`,
		append(append(append([]any{}, args...), args...), limit+1)...)
	if err != nil {
		return Matrix{}, fmt.Errorf("store: listing matrix endpoints: %w", err)
	}
	var out Matrix
	for rows.Next() {
		var (
			endpoint string
			total    int64
		)
		if err := rows.Scan(&endpoint, &total); err != nil {
			_ = rows.Close()
			return Matrix{}, fmt.Errorf("store: scanning a matrix endpoint: %w", err)
		}
		out.Endpoints = append(out.Endpoints, endpoint)
	}
	if err := closeRows(rows); err != nil {
		return Matrix{}, fmt.Errorf("store: listing matrix endpoints: %w", err)
	}
	if len(out.Endpoints) > limit {
		out.Endpoints = out.Endpoints[:limit]
		out.Truncated = true
	}
	if len(out.Endpoints) == 0 {
		return out, nil
	}
	sort.Strings(out.Endpoints)

	keep := make(map[string]bool, len(out.Endpoints))
	for _, e := range out.Endpoints {
		keep[e] = true
	}

	//nolint:gosec // G202: only clauses and placeholders are concatenated here
	cells, err := s.db.QueryContext(ctx,
		`SELECT `+endpointSQL("src")+` AS src, `+endpointSQL("dst")+` AS dst, COUNT(*)
		 FROM events WHERE `+joinAnd(where)+` GROUP BY 1, 2`, args...)
	if err != nil {
		return Matrix{}, fmt.Errorf("store: building the matrix: %w", err)
	}
	for cells.Next() {
		var cell MatrixCell
		if err := cells.Scan(&cell.Src, &cell.Dst, &cell.Events); err != nil {
			_ = cells.Close()
			return Matrix{}, fmt.Errorf("store: scanning a matrix cell: %w", err)
		}
		if !keep[cell.Src] || !keep[cell.Dst] {
			continue
		}
		if cell.Events > out.Max {
			out.Max = cell.Events
		}
		out.Cells = append(out.Cells, cell)
	}
	if err := closeRows(cells); err != nil {
		return Matrix{}, fmt.Errorf("store: building the matrix: %w", err)
	}
	return out, nil
}

// ProtocolStat is what the statistics view shows per protocol.
type ProtocolStat struct {
	Protocol  string
	Events    int64
	Malformed int64
	Anomalies int64
	Flows     int64
	Classes   map[model.Classification]int64
	FirstSeen time.Time
	LastSeen  time.Time
}

// ProtocolStats summarises every protocol seen in a project.
func (s *Store) ProtocolStats(ctx context.Context, projectID int64) ([]ProtocolStat, error) {
	//nolint:gosec // G202: the class sums are built from this package's own constants
	rows, err := s.db.QueryContext(ctx,
		`SELECT protocol, COUNT(*), COALESCE(SUM(malformed), 0),
		        COALESCE(SUM(CASE WHEN attrs LIKE '%"anomaly"%' THEN 1 ELSE 0 END), 0),
		        MIN(ts), MAX(ts), `+classSumsSQL()+`
		 FROM events WHERE project_id = ? GROUP BY protocol ORDER BY 2 DESC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: summarising protocols: %w", err)
	}
	var out []ProtocolStat
	for rows.Next() {
		var (
			st                  ProtocolStat
			firstSeen, lastSeen int64
			classes             = make([]int64, len(classOrder))
			targets             = make([]any, 0, 6+len(classOrder))
		)
		targets = append(targets, &st.Protocol, &st.Events, &st.Malformed, &st.Anomalies,
			&firstSeen, &lastSeen)
		for i := range classes {
			targets = append(targets, &classes[i])
		}
		if err := rows.Scan(targets...); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: scanning protocol statistics: %w", err)
		}
		st.FirstSeen = time.Unix(0, firstSeen).UTC()
		st.LastSeen = time.Unix(0, lastSeen).UTC()
		st.Classes = map[model.Classification]int64{}
		for i, c := range classOrder {
			if classes[i] > 0 {
				st.Classes[c] = classes[i]
			}
		}
		out = append(out, st)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("store: summarising protocols: %w", err)
	}

	// The endpoint and flow counts need their own pass, since counting
	// distinct pairs cannot be folded into the same GROUP BY.
	//nolint:gosec // G202: the endpoint expressions are this package's own
	counts, err := s.db.QueryContext(ctx,
		`SELECT protocol, COUNT(*), SUM(n) FROM (
			SELECT protocol, `+endpointSQL("src")+` AS src, `+endpointSQL("dst")+` AS dst,
			       COUNT(*) AS n
			FROM events WHERE project_id = ? GROUP BY protocol, src, dst)
		 GROUP BY protocol`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store: counting protocol flows: %w", err)
	}
	flows := map[string]int64{}
	for counts.Next() {
		var (
			protocol string
			n, total int64
		)
		if err := counts.Scan(&protocol, &n, &total); err != nil {
			_ = counts.Close()
			return nil, fmt.Errorf("store: scanning protocol flow counts: %w", err)
		}
		flows[protocol] = n
	}
	if err := closeRows(counts); err != nil {
		return nil, fmt.Errorf("store: counting protocol flows: %w", err)
	}
	for i := range out {
		out[i].Flows = flows[out[i].Protocol]
	}
	return out, nil
}
