// Package export writes a project's inventory out for other tools: JSON for
// programs, CSV for spreadsheets.
//
// An export is a document: the project it came from, what was asked for and
// the tables that answer it. Everything in it is already in the project
// database — exporting reads, it never decodes a capture again, and like the
// rest of otinv it touches no network.
package export

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/store"
)

// Kind names one exportable table.
type Kind string

// The exportable tables.
const (
	KindSummary   Kind = "summary"
	KindCaptures  Kind = "captures"
	KindProtocols Kind = "protocols"
	KindAssets    Kind = "assets"
	KindFlows     Kind = "flows"
	KindEvents    Kind = "events"
)

// Kinds lists the tables in the order a full export writes them: the project
// at a glance first, the individual events last.
var Kinds = []Kind{KindSummary, KindCaptures, KindProtocols, KindAssets, KindFlows, KindEvents}

// Overview is what "all" expands to. The events are left out because a
// project can hold millions of them and an overview is meant to be read; ask
// for them by name.
var Overview = []Kind{KindSummary, KindCaptures, KindProtocols, KindAssets, KindFlows}

// ParseKinds turns a comma-separated list of table names into kinds,
// expanding "all" into Overview. Duplicates collapse and the result keeps the
// order of Kinds, so two spellings of the same request export the same file.
func ParseKinds(spec string) ([]Kind, error) {
	wanted := map[Kind]bool{}
	for _, raw := range strings.Split(spec, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		switch name {
		case "":
			continue
		case "all":
			for _, k := range Overview {
				wanted[k] = true
			}
		default:
			k, err := parseKind(name)
			if err != nil {
				return nil, err
			}
			wanted[k] = true
		}
	}
	if len(wanted) == 0 {
		return nil, fmt.Errorf("export: no table named; pick from %s or all", KindList())
	}

	out := make([]Kind, 0, len(wanted))
	for _, k := range Kinds {
		if wanted[k] {
			out = append(out, k)
		}
	}
	return out, nil
}

func parseKind(name string) (Kind, error) {
	for _, k := range Kinds {
		if Kind(name) == k {
			return k, nil
		}
	}
	return "", fmt.Errorf("export: no table named %q; pick from %s or all", name, KindList())
}

// KindList renders the table names for a help string or an error message.
func KindList() string {
	names := make([]string, 0, len(Kinds))
	for _, k := range Kinds {
		names = append(names, string(k))
	}
	return strings.Join(names, ", ")
}

// Document is one export.
type Document struct {
	Tool      string    `json:"tool"`
	Version   string    `json:"version,omitempty"`
	Generated time.Time `json:"generated"`
	Project   string    `json:"project"`
	Database  string    `json:"database,omitempty"`

	// Filter records what was asked for, so that a file which holds part of a
	// project says so itself rather than looking like the whole of it.
	Filter *Filter `json:"filter,omitempty"`

	Summary   *Summary      `json:"summary,omitempty"`
	Captures  []Capture     `json:"captures,omitempty"`
	Protocols []Protocol    `json:"protocols,omitempty"`
	Assets    []model.Asset `json:"assets,omitempty"`
	Flows     []Flow        `json:"flows,omitempty"`
	Events    []model.Event `json:"events,omitempty"`
}

// Filter is the selection an export was made with.
type Filter struct {
	Tables   []Kind `json:"tables"`
	Protocol string `json:"protocol,omitempty"`
	Class    string `json:"class,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

// Summary is a project at a glance.
type Summary struct {
	Assets      int64     `json:"assets"`
	Controllers int64     `json:"controllers"`
	Gateways    int64     `json:"gateways"`
	Captures    int64     `json:"captures"`
	Packets     int64     `json:"packets"`
	Bytes       int64     `json:"bytes"`
	Events      int64     `json:"events"`
	Malformed   int64     `json:"malformed"`
	Anomalies   int64     `json:"anomalies"`
	Exceptions  int64     `json:"exceptions"`
	Protocols   int64     `json:"protocols"`
	Flows       int64     `json:"flows"`
	FirstSeen   time.Time `json:"first_seen,omitzero"`
	LastSeen    time.Time `json:"last_seen,omitzero"`
}

// Capture is one ingested file.
type Capture struct {
	ID         string    `json:"id"`
	Path       string    `json:"path"`
	SHA256     string    `json:"sha256"`
	Bytes      int64     `json:"bytes"`
	Packets    uint64    `json:"packets"`
	LinkType   string    `json:"link_type,omitempty"`
	FirstSeen  time.Time `json:"first_seen,omitzero"`
	LastSeen   time.Time `json:"last_seen,omitzero"`
	IngestedAt time.Time `json:"ingested_at,omitzero"`
}

// Protocol is what was observed of one protocol.
type Protocol struct {
	Protocol  string           `json:"protocol"`
	Events    int64            `json:"events"`
	Malformed int64            `json:"malformed"`
	Anomalies int64            `json:"anomalies"`
	Flows     int64            `json:"flows"`
	Classes   map[string]int64 `json:"classes,omitempty"`
	FirstSeen time.Time        `json:"first_seen,omitzero"`
	LastSeen  time.Time        `json:"last_seen,omitzero"`
}

// Flow is one direction of traffic between two endpoints over one protocol.
type Flow struct {
	Src        string           `json:"src"`
	Dst        string           `json:"dst"`
	Protocol   string           `json:"protocol"`
	Transport  string           `json:"transport,omitempty"`
	ServerPort uint16           `json:"server_port,omitempty"`
	Events     int64            `json:"events"`
	Malformed  int64            `json:"malformed"`
	Classes    map[string]int64 `json:"classes,omitempty"`
	FirstSeen  time.Time        `json:"first_seen,omitzero"`
	LastSeen   time.Time        `json:"last_seen,omitzero"`
}

// NewDocument starts an export of a project.
func NewDocument(project, database, version string, tables []Kind) *Document {
	return &Document{
		Tool:      "otinv",
		Version:   version,
		Generated: time.Now().UTC(),
		Project:   project,
		Database:  database,
		Filter:    &Filter{Tables: tables},
	}
}

// FromSummary converts the store's counts.
func FromSummary(s store.Summary) *Summary {
	return &Summary{
		Assets:      s.Assets,
		Controllers: s.Controllers,
		Gateways:    s.Gateways,
		Captures:    s.Captures,
		Packets:     s.Packets,
		Bytes:       s.Bytes,
		Events:      s.Events,
		Malformed:   s.Malformed,
		Anomalies:   s.Anomalies,
		Exceptions:  s.Exceptions,
		Protocols:   s.Protocols,
		Flows:       s.Flows,
		FirstSeen:   s.FirstSeen,
		LastSeen:    s.LastSeen,
	}
}

// FromCaptures converts the stored capture rows.
func FromCaptures(rows []store.CaptureRow) []Capture {
	out := make([]Capture, 0, len(rows))
	for _, c := range rows {
		out = append(out, Capture{
			ID:         c.ID,
			Path:       c.Path,
			SHA256:     c.SHA256,
			Bytes:      c.Bytes,
			Packets:    c.Packets,
			LinkType:   c.LinkType,
			FirstSeen:  c.FirstSeen,
			LastSeen:   c.LastSeen,
			IngestedAt: c.IngestedAt,
		})
	}
	return out
}

// FromProtocolStats converts the per-protocol statistics.
func FromProtocolStats(stats []store.ProtocolStat) []Protocol {
	out := make([]Protocol, 0, len(stats))
	for _, s := range stats {
		out = append(out, Protocol{
			Protocol:  s.Protocol,
			Events:    s.Events,
			Malformed: s.Malformed,
			Anomalies: s.Anomalies,
			Flows:     s.Flows,
			Classes:   classMap(s.Classes),
			FirstSeen: s.FirstSeen,
			LastSeen:  s.LastSeen,
		})
	}
	return out
}

// FromFlows converts the aggregated flows.
func FromFlows(flows []store.Flow) []Flow {
	out := make([]Flow, 0, len(flows))
	for _, f := range flows {
		out = append(out, Flow{
			Src:        f.Src,
			Dst:        f.Dst,
			Protocol:   f.Protocol,
			Transport:  string(f.Transport),
			ServerPort: f.ServerPort,
			Events:     f.Events,
			Malformed:  f.Malformed,
			Classes:    classMap(f.Classes),
			FirstSeen:  f.FirstSeen,
			LastSeen:   f.LastSeen,
		})
	}
	return out
}

// classMap turns the typed classification counts into plain keys, which is
// what both JSON and a CSV column name want.
func classMap(in map[model.Classification]int64) map[string]int64 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int64, len(in))
	for c, n := range in {
		out[string(c)] = n
	}
	return out
}

// Table is a rectangular view of one kind, which is what CSV writes and what
// a test can compare without parsing anything.
type Table struct {
	Kind    Kind
	Columns []string
	Rows    [][]string
}

// Table renders one of the document's tables. A table the document does not
// hold comes back empty rather than as an error: an export of a project with
// no flows has a flows table with no rows.
func (d *Document) Table(kind Kind) (Table, error) {
	switch kind {
	case KindSummary:
		return Table{Kind: kind, Columns: []string{"metric", "value"}, Rows: summaryRows(d.Summary)}, nil
	case KindCaptures:
		return Table{Kind: kind, Columns: CaptureColumns, Rows: rowsOf(d.Captures, CaptureRow)}, nil
	case KindProtocols:
		return Table{Kind: kind, Columns: ProtocolColumns(), Rows: rowsOf(d.Protocols, ProtocolRow)}, nil
	case KindAssets:
		return Table{Kind: kind, Columns: AssetColumns, Rows: rowsOf(d.Assets, AssetRow)}, nil
	case KindFlows:
		return Table{Kind: kind, Columns: FlowColumns(), Rows: rowsOf(d.Flows, FlowRow)}, nil
	case KindEvents:
		return Table{Kind: kind, Columns: EventColumns, Rows: rowsOf(d.Events, EventRow)}, nil
	default:
		return Table{}, fmt.Errorf("export: no table named %q", kind)
	}
}

func rowsOf[T any](items []T, row func(T) []string) [][]string {
	out := make([][]string, 0, len(items))
	for _, item := range items {
		out = append(out, row(item))
	}
	return out
}

// CaptureColumns are the columns of the captures table.
var CaptureColumns = []string{
	"id", "path", "sha256", "bytes", "packets", "link_type",
	"first_seen", "last_seen", "ingested_at",
}

// CaptureRow renders one capture.
func CaptureRow(c Capture) []string {
	return []string{
		c.ID, c.Path, c.SHA256,
		strconv.FormatInt(c.Bytes, 10), strconv.FormatUint(c.Packets, 10), c.LinkType,
		ts(c.FirstSeen), ts(c.LastSeen), ts(c.IngestedAt),
	}
}

// ProtocolColumns are the columns of the protocols table: the fixed ones and
// then one per classification.
func ProtocolColumns() []string {
	return append([]string{
		"protocol", "events", "malformed", "anomalies", "flows", "first_seen", "last_seen",
	}, classColumns()...)
}

// ProtocolRow renders one protocol's statistics.
func ProtocolRow(p Protocol) []string {
	row := []string{
		p.Protocol,
		strconv.FormatInt(p.Events, 10),
		strconv.FormatInt(p.Malformed, 10),
		strconv.FormatInt(p.Anomalies, 10),
		strconv.FormatInt(p.Flows, 10),
		ts(p.FirstSeen), ts(p.LastSeen),
	}
	return append(row, classCounts(p.Classes)...)
}

// FlowColumns are the columns of the flows table.
func FlowColumns() []string {
	return append([]string{
		"src", "dst", "protocol", "transport", "server_port", "events", "malformed",
		"first_seen", "last_seen",
	}, classColumns()...)
}

// FlowRow renders one flow.
func FlowRow(f Flow) []string {
	port := ""
	if f.ServerPort != 0 {
		port = strconv.Itoa(int(f.ServerPort))
	}
	row := []string{
		f.Src, f.Dst, f.Protocol, f.Transport, port,
		strconv.FormatInt(f.Events, 10), strconv.FormatInt(f.Malformed, 10),
		ts(f.FirstSeen), ts(f.LastSeen),
	}
	return append(row, classCounts(f.Classes)...)
}

// AssetColumns are the columns of the asset inventory, which is the table an
// analyst is most likely to open in a spreadsheet.
//
// The five identity columns are the ones a reader scans for; the attributes
// column carries every inferred field, so a spreadsheet holds the whole
// inference and not just the part that has a column of its own.
var AssetColumns = []string{
	"key", "label", "vendor", "model", "firmware_revision", "serial_number", "name",
	"role", "role_confidence", "role_reasons", "is_gateway", "macs", "ips", "vlans",
	"server_protocols", "client_protocols", "events", "first_seen", "last_seen",
	"attributes",
}

// AssetRow renders one asset. The inferred fields come with the confidence
// that produced them, because an inventory row without it reads as fact.
func AssetRow(a model.Asset) []string {
	var served, spoke []string
	for _, p := range a.Protocols {
		entry := p.Protocol + " (" + strconv.FormatUint(p.Events, 10) + ")"
		if p.Side == "server" {
			served = append(served, entry)
		} else {
			spoke = append(spoke, entry)
		}
	}
	return []string{
		a.Key, a.Label,
		attrValue(a, "vendor"), attrValue(a, "model"), attrValue(a, "firmware_revision"),
		attrValue(a, "serial_number"), attrValue(a, "name"),
		string(a.Role.Name), strconv.Itoa(a.Role.Confidence),
		strings.Join(a.Role.Reasons, "; "),
		boolText(a.IsGateway),
		strings.Join(a.MACs, " "), strings.Join(a.IPs, " "), joinUint16(a.VLANs),
		strings.Join(served, " "), strings.Join(spoke, " "),
		strconv.FormatUint(a.Events, 10), ts(a.FirstSeen), ts(a.LastSeen),
		allAttributes(a),
	}
}

// EventColumns are the columns of the event table. The identity and attribute
// maps are flattened into one key=value column each, so that a dissector
// gaining a field does not move every column after it.
var EventColumns = []string{
	"capture_id", "packet_index", "ts", "protocol", "direction", "operation",
	"function_code", "class", "src_mac", "src_ip", "src_port", "dst_mac", "dst_ip",
	"dst_port", "transport", "server_port", "vlan", "unit_id", "transaction_id",
	"address", "quantity", "exception", "malformed", "error", "identity", "attrs",
}

// EventRow renders one event.
func EventRow(e model.Event) []string {
	return []string{
		e.CaptureID, strconv.FormatUint(e.PacketIndex, 10), ts(e.Timestamp),
		e.Protocol, string(e.Direction), e.Operation,
		strconv.Itoa(e.FunctionCode), string(e.Class),
		e.Flow.SrcMAC, e.Flow.SrcIP, port(e.Flow.SrcPort),
		e.Flow.DstMAC, e.Flow.DstIP, port(e.Flow.DstPort),
		string(e.Flow.Transport), port(e.ServerPort), joinUint16(e.Flow.VLAN),
		optUint16(e.UnitID), optUint32(e.TransactionID),
		optUint32(e.Address), optUint32(e.Quantity),
		e.Exception, boolText(e.Malformed), e.Error,
		pairs(e.Identity), pairs(e.Attrs),
	}
}

func summaryRows(s *Summary) [][]string {
	if s == nil {
		return nil
	}
	rows := [][]string{
		{"assets", strconv.FormatInt(s.Assets, 10)},
		{"controllers", strconv.FormatInt(s.Controllers, 10)},
		{"gateways", strconv.FormatInt(s.Gateways, 10)},
		{"captures", strconv.FormatInt(s.Captures, 10)},
		{"packets", strconv.FormatInt(s.Packets, 10)},
		{"bytes", strconv.FormatInt(s.Bytes, 10)},
		{"events", strconv.FormatInt(s.Events, 10)},
		{"malformed", strconv.FormatInt(s.Malformed, 10)},
		{"anomalies", strconv.FormatInt(s.Anomalies, 10)},
		{"exceptions", strconv.FormatInt(s.Exceptions, 10)},
		{"protocols", strconv.FormatInt(s.Protocols, 10)},
		{"flows", strconv.FormatInt(s.Flows, 10)},
	}
	if !s.FirstSeen.IsZero() {
		rows = append(rows, []string{"first_seen", ts(s.FirstSeen)})
	}
	if !s.LastSeen.IsZero() {
		rows = append(rows, []string{"last_seen", ts(s.LastSeen)})
	}
	return rows
}

// classColumns names one column per classification, in the shared order.
func classColumns() []string {
	out := make([]string, 0, len(model.Classifications))
	for _, c := range model.Classifications {
		out = append(out, string(c))
	}
	return out
}

func classCounts(m map[string]int64) []string {
	out := make([]string, 0, len(model.Classifications))
	for _, c := range model.Classifications {
		out = append(out, strconv.FormatInt(m[string(c)], 10))
	}
	return out
}

// allAttributes renders every inferred field with its confidence, in the
// order the inventory stored them.
func allAttributes(a model.Asset) string {
	parts := make([]string, 0, len(a.Attributes))
	for _, at := range a.Attributes {
		parts = append(parts, at.Field+"="+at.Value+
			" ("+strconv.Itoa(at.Confidence)+"%, "+at.Source+")")
	}
	return strings.Join(parts, "; ")
}

// attrValue returns an inferred attribute with its confidence, e.g.
// "S7-300 (90%)". An attribute otinv never inferred is an empty cell.
func attrValue(a model.Asset, field string) string {
	for _, at := range a.Attributes {
		if at.Field == field {
			if at.Confidence > 0 {
				return at.Value + " (" + strconv.Itoa(at.Confidence) + "%)"
			}
			return at.Value
		}
	}
	return ""
}

// pairs renders a string map as "key=value; key=value", sorted so that two
// exports of the same project produce the same bytes.
func pairs(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, "; ")
}

func joinUint16(xs []uint16) string {
	parts := make([]string, 0, len(xs))
	for _, x := range xs {
		parts = append(parts, strconv.Itoa(int(x)))
	}
	return strings.Join(parts, " ")
}

func port(p uint16) string {
	if p == 0 {
		return ""
	}
	return strconv.Itoa(int(p))
}

func optUint16(p *uint16) string {
	if p == nil {
		return ""
	}
	return strconv.Itoa(int(*p))
}

func optUint32(p *uint32) string {
	if p == nil {
		return ""
	}
	return strconv.FormatUint(uint64(*p), 10)
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// ts renders a timestamp in UTC. A zero time is an empty cell rather than
// year one, which a spreadsheet would read as a date.
func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
