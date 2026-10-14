package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/rom/otinv/internal/model"
)

// eventBatchSize is how many events go into one transaction. Batching is what
// makes ingest write at a useful rate; the number trades throughput against
// how much work a failed transaction discards.
const eventBatchSize = 1000

const insertEventSQL = `INSERT INTO events
	(project_id, capture_pk, capture_id, packet_index, ts, protocol, direction,
	 operation, function_code, class, unit_id, transaction_id, address, quantity,
	 exception, malformed, error, src_mac, dst_mac, src_ip, dst_ip, src_port,
	 dst_port, transport, server_port, vlan, identity, attrs)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// EventWriter batches events into transactions.
//
// It is the single writer CLAUDE.md asks for: one per capture, not safe for
// concurrent use. When dissection moves to a worker pool, the workers feed one
// of these rather than writing themselves.
type EventWriter struct {
	s         *Store
	projectID int64
	capturePK int64

	tx      *sql.Tx
	stmt    *sql.Stmt
	pending int
	written uint64
}

// NewEventWriter returns a writer for one capture of one project.
func (s *Store) NewEventWriter(projectID, capturePK int64) *EventWriter {
	return &EventWriter{s: s, projectID: projectID, capturePK: capturePK}
}

// Written is how many events have been handed to the database so far.
func (w *EventWriter) Written() uint64 { return w.written }

// Add queues one event, committing the batch when it is full.
func (w *EventWriter) Add(ctx context.Context, e model.Event) error {
	if w.tx == nil {
		if err := w.begin(ctx); err != nil {
			return err
		}
	}

	vlan, err := marshalJSON(e.Flow.VLAN)
	if err != nil {
		return fmt.Errorf("store: encoding event vlan: %w", err)
	}
	identity, err := marshalJSON(e.Identity)
	if err != nil {
		return fmt.Errorf("store: encoding event identity: %w", err)
	}
	attrs, err := marshalJSON(e.Attrs)
	if err != nil {
		return fmt.Errorf("store: encoding event attrs: %w", err)
	}

	_, err = w.stmt.ExecContext(ctx,
		w.projectID, w.capturePK, nullString(e.CaptureID), e.PacketIndex,
		e.Timestamp.UTC().UnixNano(), e.Protocol, string(e.Direction), e.Operation,
		e.FunctionCode, string(e.Class),
		nullUint16(e.UnitID), nullUint32(e.TransactionID),
		nullUint32(e.Address), nullUint32(e.Quantity),
		nullString(e.Exception), e.Malformed, nullString(e.Error),
		nullString(e.Flow.SrcMAC), nullString(e.Flow.DstMAC),
		e.Flow.SrcIP, e.Flow.DstIP, e.Flow.SrcPort, e.Flow.DstPort,
		string(e.Flow.Transport), nullPort(e.ServerPort), vlan, identity, attrs)
	if err != nil {
		return fmt.Errorf("store: inserting event: %w", err)
	}

	w.pending++
	w.written++
	if w.pending >= eventBatchSize {
		return w.Flush(ctx)
	}
	return nil
}

func (w *EventWriter) begin(ctx context.Context) error {
	tx, err := w.s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: beginning event batch: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, insertEventSQL)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("store: preparing event insert: %w", err)
	}
	w.tx, w.stmt, w.pending = tx, stmt, 0
	return nil
}

// Flush commits the current batch. A cancelled context rolls it back instead,
// so an interrupted ingest does not leave a half-written capture committed.
func (w *EventWriter) Flush(ctx context.Context) error {
	if w.tx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		_ = w.stmt.Close()
		_ = w.tx.Rollback()
		w.tx, w.stmt, w.pending = nil, nil, 0
		return fmt.Errorf("store: abandoning event batch: %w", err)
	}
	if err := w.stmt.Close(); err != nil {
		_ = w.tx.Rollback()
		w.tx, w.stmt, w.pending = nil, nil, 0
		return fmt.Errorf("store: closing event insert: %w", err)
	}
	err := w.tx.Commit()
	w.tx, w.stmt, w.pending = nil, nil, 0
	if err != nil {
		return fmt.Errorf("store: committing event batch: %w", err)
	}
	return nil
}

// Close flushes whatever is pending. It is safe to call twice.
func (w *EventWriter) Close(ctx context.Context) error { return w.Flush(ctx) }

// CountEvents counts a project's events.
func (s *Store) CountEvents(ctx context.Context, projectID int64) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events WHERE project_id = ?`, projectID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: counting events: %w", err)
	}
	return n, nil
}

const selectEventColumns = `capture_id, packet_index, ts, protocol, direction, operation,
	function_code, class, unit_id, transaction_id, address, quantity, exception,
	malformed, error, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
	transport, server_port, vlan, identity, attrs`

// EachEvent streams a project's events in insertion order. Streaming keeps the
// inventory rebuild bounded in memory however large the project is.
func (s *Store) EachEvent(ctx context.Context, projectID int64, fn func(model.Event) error) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+selectEventColumns+` FROM events WHERE project_id = ? ORDER BY id`,
		projectID)
	if err != nil {
		return fmt.Errorf("store: reading events: %w", err)
	}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			_ = rows.Close()
			return err
		}
		if err := fn(e); err != nil {
			_ = rows.Close()
			return err
		}
	}
	if err := closeRows(rows); err != nil {
		return fmt.Errorf("store: reading events: %w", err)
	}
	return nil
}

// EventQuery selects, filters and orders events for a view.
type EventQuery struct {
	ProjectID int64
	// Addresses matches any of these against either endpoint's IP or MAC,
	// which is how a multi-homed asset's own traffic is selected for its
	// detail page.
	Addresses []string
	// Protocol, Class and Operation are exact matches, as the facet filters
	// of the event table offer them.
	Protocol  string
	Class     string
	Operation string
	// Src and Dst match one direction of a flow, which is how the flow table
	// drills through to the events behind a row.
	Src string
	Dst string
	// Search matches the operation, the exception, the error text or either
	// endpoint, which is what a reader types into one box.
	Search string
	// Capture limits the view to one ingested file.
	Capture string
	// OnlyMalformed and OnlyAnomalous narrow the table to the frames that
	// did not decode and the ones a dissector flagged.
	OnlyMalformed bool
	OnlyAnomalous bool

	Limit  int
	Offset int
	Sort   string
	Desc   bool
}

// EventSortColumns are the orderings the event table offers. The map is a
// whitelist, so a column name arriving from a URL never reaches the query.
var EventSortColumns = map[string]string{
	"time":      "ts",
	"protocol":  "protocol",
	"operation": "operation",
	"class":     "class",
	"src":       "src_ip",
	"dst":       "dst_ip",
	"packet":    "packet_index",
}

// where builds the predicates and their arguments.
func (q EventQuery) where() ([]string, []any) {
	where := []string{"project_id = ?"}
	args := []any{q.ProjectID}
	if len(q.Addresses) > 0 {
		placeholders := inPlaceholders(len(q.Addresses))
		where = append(where, "(src_ip IN ("+placeholders+") OR dst_ip IN ("+placeholders+")"+
			" OR src_mac IN ("+placeholders+") OR dst_mac IN ("+placeholders+"))")
		for range 4 {
			for _, a := range q.Addresses {
				args = append(args, a)
			}
		}
	}
	for _, f := range []struct {
		column string
		value  string
	}{
		{"protocol", q.Protocol},
		{"class", q.Class},
		{"operation", q.Operation},
		{"capture_id", q.Capture},
	} {
		if f.value != "" {
			where = append(where, f.column+" = ?")
			args = append(args, f.value)
		}
	}
	if q.Src != "" {
		where = append(where, "("+endpointSQL("src")+" = ?)")
		args = append(args, q.Src)
	}
	if q.Dst != "" {
		where = append(where, "("+endpointSQL("dst")+" = ?)")
		args = append(args, q.Dst)
	}
	if q.Search != "" {
		like := "%" + q.Search + "%"
		where = append(where, "(operation LIKE ? OR COALESCE(exception, '') LIKE ?"+
			" OR COALESCE(error, '') LIKE ? OR "+endpointSQL("src")+" LIKE ?"+
			" OR "+endpointSQL("dst")+" LIKE ?)")
		args = append(args, like, like, like, like, like)
	}
	if q.OnlyMalformed {
		where = append(where, "malformed = 1")
	}
	if q.OnlyAnomalous {
		where = append(where, `attrs LIKE '%"anomaly"%'`)
	}
	return where, args
}

// Events returns the matching events, most recent first unless the query asks
// for another order.
func (s *Store) Events(ctx context.Context, q EventQuery) ([]model.Event, error) {
	events, _, err := s.eventsPage(ctx, q, false)
	return events, err
}

// EventsPage returns one page of matching events and how many there are in
// all, which is what a paged table needs.
func (s *Store) EventsPage(ctx context.Context, q EventQuery) ([]model.Event, int, error) {
	return s.eventsPage(ctx, q, true)
}

func (s *Store) eventsPage(ctx context.Context, q EventQuery, withTotal bool) ([]model.Event, int, error) {
	where, args := q.where()

	total := 0
	if withTotal {
		//nolint:gosec // G202: only clauses and placeholders are concatenated here
		row := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM events WHERE `+joinAnd(where), args...)
		if err := row.Scan(&total); err != nil {
			return nil, 0, fmt.Errorf("store: counting events: %w", err)
		}
	}

	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	order := "ts DESC, id DESC"
	if column, ok := EventSortColumns[q.Sort]; ok {
		order = column
		if q.Desc {
			order += " DESC"
		}
		order += ", id"
	}

	//nolint:gosec // G202: the ordering comes from the EventSortColumns whitelist
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+selectEventColumns+` FROM events WHERE `+joinAnd(where)+
			` ORDER BY `+order+` LIMIT ? OFFSET ?`,
		append(args, limit, max(q.Offset, 0))...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: querying events: %w", err)
	}
	var out []model.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			_ = rows.Close()
			return nil, 0, err
		}
		out = append(out, e)
	}
	if err := closeRows(rows); err != nil {
		return nil, 0, fmt.Errorf("store: querying events: %w", err)
	}
	if !withTotal {
		total = len(out)
	}
	return out, total, nil
}

// EventOperations lists the operations seen in a project, most frequent first,
// which is what the event table's operation filter offers.
func (s *Store) EventOperations(ctx context.Context, projectID int64, protocol string) ([]string, error) {
	if protocol == "" {
		return s.distinct(ctx,
			`SELECT operation FROM (SELECT operation, COUNT(*) AS n FROM events
			 WHERE project_id = ? GROUP BY operation ORDER BY n DESC LIMIT 200)`, projectID)
	}
	return s.distinct(ctx,
		`SELECT operation FROM (SELECT operation, COUNT(*) AS n FROM events
		 WHERE project_id = ? AND protocol = ? GROUP BY operation ORDER BY n DESC LIMIT 200)`,
		projectID, protocol)
}

func scanEvent(rows *sql.Rows) (model.Event, error) {
	var (
		e                               model.Event
		captureID, exception, errText   sql.NullString
		srcMAC, dstMAC                  sql.NullString
		unitID, transactionID           sql.NullInt64
		address, quantity               sql.NullInt64
		serverPort                      sql.NullInt64
		ts                              int64
		direction, class, transport     string
		vlanJSON, identityJSON, attrsJS []byte
	)
	err := rows.Scan(&captureID, &e.PacketIndex, &ts, &e.Protocol, &direction,
		&e.Operation, &e.FunctionCode, &class, &unitID, &transactionID,
		&address, &quantity, &exception, &e.Malformed, &errText,
		&srcMAC, &dstMAC, &e.Flow.SrcIP, &e.Flow.DstIP, &e.Flow.SrcPort,
		&e.Flow.DstPort, &transport, &serverPort, &vlanJSON, &identityJSON, &attrsJS)
	if err != nil {
		return model.Event{}, fmt.Errorf("store: scanning event: %w", err)
	}

	e.CaptureID = captureID.String
	e.Timestamp = time.Unix(0, ts).UTC()
	e.Direction = model.Direction(direction)
	e.Class = model.Classification(class)
	e.Exception = exception.String
	e.Error = errText.String
	e.Flow.SrcMAC = srcMAC.String
	e.Flow.DstMAC = dstMAC.String
	e.Flow.Transport = model.Transport(transport)

	if unitID.Valid {
		e.UnitID = model.Ptr(uint16(unitID.Int64))
	}
	if transactionID.Valid {
		e.TransactionID = model.Ptr(uint32(transactionID.Int64))
	}
	if address.Valid {
		e.Address = model.Ptr(uint32(address.Int64))
	}
	if quantity.Valid {
		e.Quantity = model.Ptr(uint32(quantity.Int64))
	}
	if serverPort.Valid {
		e.ServerPort = uint16(serverPort.Int64)
	}
	if err := unmarshalJSON(vlanJSON, &e.Flow.VLAN); err != nil {
		return model.Event{}, fmt.Errorf("store: decoding event vlan: %w", err)
	}
	if err := unmarshalJSON(identityJSON, &e.Identity); err != nil {
		return model.Event{}, fmt.Errorf("store: decoding event identity: %w", err)
	}
	if err := unmarshalJSON(attrsJS, &e.Attrs); err != nil {
		return model.Event{}, fmt.Errorf("store: decoding event attrs: %w", err)
	}
	return e, nil
}
