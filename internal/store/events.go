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
	 dst_port, transport, vlan, identity, attrs)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

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
		string(e.Flow.Transport), vlan, identity, attrs)
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
	transport, vlan, identity, attrs`

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

// EventQuery selects events for a view.
type EventQuery struct {
	ProjectID int64
	// Addresses matches any of these against either endpoint's IP or MAC,
	// which is how a multi-homed asset's own traffic is selected for its
	// detail page.
	Addresses []string
	Limit     int
}

// Events returns the most recent events matching the query.
func (s *Store) Events(ctx context.Context, q EventQuery) ([]model.Event, error) {
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
	limit := q.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	args = append(args, limit)

	//nolint:gosec // G202: only clauses and placeholders are concatenated here
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+selectEventColumns+` FROM events WHERE `+joinAnd(where)+
			` ORDER BY ts DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: querying events: %w", err)
	}
	var out []model.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, e)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("store: querying events: %w", err)
	}
	return out, nil
}

func scanEvent(rows *sql.Rows) (model.Event, error) {
	var (
		e                               model.Event
		captureID, exception, errText   sql.NullString
		srcMAC, dstMAC                  sql.NullString
		unitID, transactionID           sql.NullInt64
		address, quantity               sql.NullInt64
		ts                              int64
		direction, class, transport     string
		vlanJSON, identityJSON, attrsJS []byte
	)
	err := rows.Scan(&captureID, &e.PacketIndex, &ts, &e.Protocol, &direction,
		&e.Operation, &e.FunctionCode, &class, &unitID, &transactionID,
		&address, &quantity, &exception, &e.Malformed, &errText,
		&srcMAC, &dstMAC, &e.Flow.SrcIP, &e.Flow.DstIP, &e.Flow.SrcPort,
		&e.Flow.DstPort, &transport, &vlanJSON, &identityJSON, &attrsJS)
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
