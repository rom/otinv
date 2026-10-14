package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/rom/otinv/internal/model"
)

// Format is an output encoding.
type Format string

// The supported formats. CLAUDE.md also lists an HTML report and a
// CycloneDX-style asset export; both are later milestones and are not
// pretended to exist here.
const (
	FormatJSON Format = "json"
	FormatCSV  Format = "csv"
)

// ParseFormat reads a format name.
func ParseFormat(name string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(name))) {
	case FormatJSON:
		return FormatJSON, nil
	case FormatCSV:
		return FormatCSV, nil
	default:
		return "", fmt.Errorf("export: no format named %q; pick json or csv", name)
	}
}

// WriteJSON writes the whole document, events included.
func WriteJSON(w io.Writer, doc *Document, indent bool) error {
	enc := json.NewEncoder(w)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("export: writing JSON: %w", err)
	}
	return nil
}

// WriteCSV writes one table, header row first.
func WriteCSV(w io.Writer, t Table) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(t.Columns); err != nil {
		return fmt.Errorf("export: writing CSV header: %w", err)
	}
	for _, row := range t.Rows {
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("export: writing CSV row: %w", err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("export: writing CSV: %w", err)
	}
	return nil
}

// EventStream writes events one at a time.
//
// A project can hold millions of events, so an export of them is streamed
// straight from the query to the file: whatever the project's size, what is
// in memory is one event (CLAUDE.md, "memory bounded regardless of capture
// size").
type EventStream interface {
	Add(model.Event) error
	Close() error
}

// NewEventStream returns the stream for a format. For JSON the document is
// written around the events, so doc must not carry any of its own.
func NewEventStream(w io.Writer, format Format, doc *Document, indent bool) (EventStream, error) {
	switch format {
	case FormatCSV:
		return newCSVEventStream(w)
	case FormatJSON:
		return newJSONEventStream(w, doc, indent)
	default:
		return nil, fmt.Errorf("export: no format named %q", format)
	}
}

type csvEventStream struct {
	w *csv.Writer
}

func newCSVEventStream(w io.Writer) (*csvEventStream, error) {
	cw := csv.NewWriter(w)
	if err := cw.Write(EventColumns); err != nil {
		return nil, fmt.Errorf("export: writing CSV header: %w", err)
	}
	return &csvEventStream{w: cw}, nil
}

func (s *csvEventStream) Add(e model.Event) error {
	if err := s.w.Write(EventRow(e)); err != nil {
		return fmt.Errorf("export: writing CSV row: %w", err)
	}
	return nil
}

func (s *csvEventStream) Close() error {
	s.w.Flush()
	if err := s.w.Error(); err != nil {
		return fmt.Errorf("export: writing CSV: %w", err)
	}
	return nil
}

// jsonEventStream writes the document's own fields first and then the events
// as they arrive, so the result is one JSON object however many there are.
type jsonEventStream struct {
	w      io.Writer
	indent string
	first  bool
	err    error
}

func newJSONEventStream(w io.Writer, doc *Document, indent bool) (*jsonEventStream, error) {
	if doc == nil {
		return nil, fmt.Errorf("export: streaming events needs a document")
	}
	if len(doc.Events) > 0 {
		// The caller would otherwise get two "events" keys, one of which a
		// decoder would silently drop.
		return nil, fmt.Errorf("export: a streamed document must not already hold events")
	}

	var (
		header []byte
		err    error
		pad    string
	)
	if indent {
		header, err = json.MarshalIndent(doc, "", "  ")
		pad = "  "
	} else {
		header, err = json.Marshal(doc)
	}
	if err != nil {
		return nil, fmt.Errorf("export: writing JSON: %w", err)
	}

	// Reopen the object: everything but its closing brace, then the events
	// key. MarshalIndent puts the brace on its own line, Marshal does not.
	open := strings.TrimSuffix(string(header), "}")
	open = strings.TrimSuffix(open, "\n")
	s := &jsonEventStream{w: w, indent: pad, first: true}
	s.write(open + ",")
	if indent {
		s.write("\n" + pad + `"events": [`)
	} else {
		s.write(`"events":[`)
	}
	if s.err != nil {
		return nil, s.err
	}
	return s, nil
}

func (s *jsonEventStream) Add(e model.Event) error {
	if s.err != nil {
		return s.err
	}

	var (
		body []byte
		err  error
	)
	if s.indent != "" {
		body, err = json.MarshalIndent(e, s.indent+s.indent, s.indent)
	} else {
		body, err = json.Marshal(e)
	}
	if err != nil {
		return fmt.Errorf("export: encoding an event: %w", err)
	}

	if !s.first {
		s.write(",")
	}
	s.first = false
	if s.indent != "" {
		s.write("\n" + s.indent + s.indent)
	}
	s.write(string(body))
	return s.err
}

func (s *jsonEventStream) Close() error {
	if s.err != nil {
		return s.err
	}
	switch {
	case s.indent == "":
		s.write("]}\n")
	case s.first:
		s.write("]\n}\n")
	default:
		s.write("\n" + s.indent + "]\n}\n")
	}
	return s.err
}

func (s *jsonEventStream) write(text string) {
	if s.err != nil {
		return
	}
	if _, err := io.WriteString(s.w, text); err != nil {
		s.err = fmt.Errorf("export: writing JSON: %w", err)
	}
}
