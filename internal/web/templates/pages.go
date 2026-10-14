package templates

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rom/otinv/internal/model"
)

// The view models of the views added beyond the asset list: the dashboard,
// the flow table, the communication matrix, the event table, the protocol
// statistics and the settings form.
//
// Each one owns its own filter state, its own sortable headers and its own
// URL builder, because CLAUDE.md asks every view and every filter state to be
// deep-linkable: a reader who has narrowed a table to one protocol and one
// classification can send the link.

// StatTile is one number on the dashboard, with the view it leads to.
type StatTile struct {
	Label string
	Value string
	Note  string
	Href  string
	// Tone colours the tile: "plain", "warn" for something that needs
	// looking at, "good" for something that is as it should be.
	Tone string
}

// DashboardView is the project at a glance.
type DashboardView struct {
	Page       PageView
	Tiles      []StatTile
	Protocols  BarsView
	Roles      BarsView
	Levels     BarsView
	Vendors    BarsView
	Classes    ProportionView
	Timeline   TimelineView
	Operations BarsView
	Exceptions BarsView
	Recent     []EventRow
	Theme      Theme
}

// FlowRow is one line of the flow table.
type FlowRow struct {
	Src        string
	Dst        string
	SrcHref    string
	DstHref    string
	Protocol   string
	Transport  string
	ServerPort string
	Events     int64
	Malformed  int64
	Classes    ProportionView
	FirstSeen  time.Time
	LastSeen   time.Time
	Href       string
}

// FlowsFilter is the flow table's filter state.
type FlowsFilter struct {
	Protocol string
	Class    string
	Endpoint string
	Search   string
}

// FlowsView is the flow table.
type FlowsView struct {
	Page      PageView
	Rows      []FlowRow
	Total     int
	Offset    int
	Limit     int
	Filter    FlowsFilter
	Sort      Sort
	Protocols []string
	Classes   []string
	Theme     Theme
}

// Headers are the flow table's column headers.
func (v FlowsView) Headers() []SortHeaderView {
	lang := v.Page.Lang
	return sortHeaders([]SortColumn{
		{Key: "src", Label: T(lang, "flows.source")},
		{Key: "dst", Label: T(lang, "flows.destination")},
		{Key: "protocol", Label: T(lang, "flows.protocol")},
		{Key: "events", Label: T(lang, "flows.events"), Numeric: true},
		{Key: "", Label: T(lang, "flows.mix")},
		{Key: "first", Label: T(lang, "flows.first"), Numeric: true},
		{Key: "last", Label: T(lang, "flows.last"), Numeric: true},
	}, v.Sort, v.SortURL, "#flow-table")
}

// SortURL links to the table under a different sort, back at the first page.
func (v FlowsView) SortURL(s Sort) string { return v.listURL(0, s) }

// PrevURL links to the previous page.
func (v FlowsView) PrevURL() string { return v.listURL(max(v.Offset-v.Limit, 0), v.Sort) }

// NextURL links to the next page.
func (v FlowsView) NextURL() string { return v.listURL(v.Offset+v.Limit, v.Sort) }

// HasPrev reports whether there is a page before this one.
func (v FlowsView) HasPrev() bool { return v.Offset > 0 }

// HasNext reports whether there is a page after this one.
func (v FlowsView) HasNext() bool { return v.Offset+v.Limit < v.Total }

// PageInfo is the page number and how many there are.
func (v FlowsView) PageInfo() (int, int) { return pageOf(v.Offset, v.Limit, v.Total) }

// PageLabel renders the pager's position.
func (v FlowsView) PageLabel() string {
	page, pages := v.PageInfo()
	return strconv.Itoa(page) + " / " + strconv.Itoa(pages)
}

func (v FlowsView) listURL(offset int, s Sort) string {
	q := url.Values{}
	setIf(q, "protocol", v.Filter.Protocol)
	setIf(q, "class", v.Filter.Class)
	setIf(q, "endpoint", v.Filter.Endpoint)
	setIf(q, "q", v.Filter.Search)
	return buildURL("/flows", q, offset, v.Limit, s, v.Page.Lang)
}

// MatrixFilter is the matrix view's filter state.
type MatrixFilter struct {
	Protocol string
	Class    string
	Size     int
}

// MatrixView is the communication matrix.
type MatrixView struct {
	Page      PageView
	Chart     MatrixChartView
	Filter    MatrixFilter
	Protocols []string
	Classes   []string
	Theme     Theme
	Total     int64
}

// FilterURL links to the matrix under a different filter.
func (v MatrixView) FilterURL(protocol, class string) string {
	q := url.Values{}
	setIf(q, "protocol", protocol)
	setIf(q, "class", class)
	if v.Filter.Size != 0 {
		q.Set("size", strconv.Itoa(v.Filter.Size))
	}
	return withLang("/matrix", q, v.Page.Lang)
}

// EventsFilter is the event table's filter state.
type EventsFilter struct {
	Protocol  string
	Class     string
	Operation string
	Search    string
	Src       string
	Dst       string
	Capture   string
	Malformed bool
	Anomalous bool
}

// Active reports whether anything is filtered, which is what decides whether
// the view offers to clear it.
func (f EventsFilter) Active() bool {
	return f.Protocol != "" || f.Class != "" || f.Operation != "" || f.Search != "" ||
		f.Src != "" || f.Dst != "" || f.Capture != "" || f.Malformed || f.Anomalous
}

// EventsView is the event table: every decoded operation in the project,
// filtered and paged.
type EventsView struct {
	Page       PageView
	Rows       []EventTableRow
	Total      int
	Offset     int
	Limit      int
	Filter     EventsFilter
	Sort       Sort
	Protocols  []string
	Classes    []string
	Operations []string
	Theme      Theme
}

// EventTableRow is one line of the event table. It differs from the row on an
// asset's page by naming both endpoints rather than one peer.
type EventTableRow struct {
	Time      time.Time
	Protocol  string
	Operation string
	Detail    string
	Class     string
	Direction string
	Src       string
	Dst       string
	SrcHref   string
	DstHref   string
	Packet    uint64
	Capture   string
	Exception string
	Malformed bool
}

// Headers are the event table's column headers.
func (v EventsView) Headers() []SortHeaderView {
	lang := v.Page.Lang
	return sortHeaders([]SortColumn{
		{Key: "time", Label: T(lang, "events.time"), Numeric: true},
		{Key: "protocol", Label: T(lang, "events.protocol")},
		{Key: "operation", Label: T(lang, "events.operation")},
		{Key: "class", Label: T(lang, "events.class")},
		{Key: "src", Label: T(lang, "events.source")},
		{Key: "dst", Label: T(lang, "events.destination")},
		{Key: "packet", Label: T(lang, "events.packet"), Numeric: true},
	}, v.Sort, v.SortURL, "#event-table")
}

// SortURL links to the table under a different sort, back at the first page.
func (v EventsView) SortURL(s Sort) string { return v.listURL(0, s) }

// PrevURL links to the previous page.
func (v EventsView) PrevURL() string { return v.listURL(max(v.Offset-v.Limit, 0), v.Sort) }

// NextURL links to the next page.
func (v EventsView) NextURL() string { return v.listURL(v.Offset+v.Limit, v.Sort) }

// HasPrev reports whether there is a page before this one.
func (v EventsView) HasPrev() bool { return v.Offset > 0 }

// HasNext reports whether there is a page after this one.
func (v EventsView) HasNext() bool { return v.Offset+v.Limit < v.Total }

// PageInfo is the page number and how many there are.
func (v EventsView) PageInfo() (int, int) { return pageOf(v.Offset, v.Limit, v.Total) }

// PageLabel renders the pager's position.
func (v EventsView) PageLabel() string {
	page, pages := v.PageInfo()
	return strconv.Itoa(page) + " / " + strconv.Itoa(pages)
}

// ClearURL drops every filter, keeping the sort.
func (v EventsView) ClearURL() string {
	empty := EventsView{Page: v.Page, Limit: v.Limit, Sort: v.Sort}
	return empty.listURL(0, v.Sort)
}

func (v EventsView) listURL(offset int, s Sort) string {
	q := url.Values{}
	setIf(q, "protocol", v.Filter.Protocol)
	setIf(q, "class", v.Filter.Class)
	setIf(q, "operation", v.Filter.Operation)
	setIf(q, "q", v.Filter.Search)
	setIf(q, "src", v.Filter.Src)
	setIf(q, "dst", v.Filter.Dst)
	setIf(q, "capture", v.Filter.Capture)
	if v.Filter.Malformed {
		q.Set("malformed", "1")
	}
	if v.Filter.Anomalous {
		q.Set("anomalous", "1")
	}
	return buildURL("/events", q, offset, v.Limit, s, v.Page.Lang)
}

// ProtocolStatRow is one protocol's line of the statistics view.
type ProtocolStatRow struct {
	Protocol  string
	Tier      int
	Events    int64
	Flows     int64
	Malformed int64
	Anomalies int64
	Health    string
	Classes   ProportionView
	FirstSeen time.Time
	LastSeen  time.Time
	Href      string
}

// ProtocolsView is the per-protocol statistics.
type ProtocolsView struct {
	Page       PageView
	Rows       []ProtocolStatRow
	Operations BarsView
	Timeline   TimelineView
	Ports      BarsView
	Selected   string
	Protocols  []string
	Theme      Theme
	Total      int64
}

// Headers are the statistics table's column labels. The table is one row per
// protocol and already in the order that matters — the busiest first — so
// nothing in it is sortable, and a header that looked like a link but went
// nowhere would be worse than a label.
func (v ProtocolsView) Headers() []PlainHeader {
	lang := v.Page.Lang
	return []PlainHeader{
		{Label: T(lang, "protocols.protocol")},
		{Label: T(lang, "protocols.events"), Numeric: true},
		{Label: T(lang, "protocols.flows"), Numeric: true},
		{Label: T(lang, "protocols.mix")},
		{Label: T(lang, "protocols.health")},
		{Label: T(lang, "protocols.range")},
	}
}

// PlainHeader is a column header that is not a link.
type PlainHeader struct {
	Label   string
	Numeric bool
}

// Class is the header cell's class list.
func (h PlainHeader) Class() string {
	if h.Numeric {
		return "num"
	}
	return ""
}

// FilterURL links the statistics view to one protocol.
func (v ProtocolsView) FilterURL(protocol string) string {
	q := url.Values{}
	setIf(q, "protocol", protocol)
	return withLang("/protocols", q, v.Page.Lang)
}

// SettingsGroup is one section of the settings form.
type SettingsGroup struct {
	Label    string
	Settings []SettingRow
}

// SettingRow is one setting, resolved against what is stored.
type SettingRow struct {
	Def     SettingDef
	Value   string
	Options []SettingOptionRow
}

// SettingOptionRow is one choice of a setting, with whether it is the
// current one.
type SettingOptionRow struct {
	Value    string
	Label    string
	Selected bool
}

// SettingsView is the settings form.
type SettingsView struct {
	Page   PageView
	Groups []SettingsGroup
	Theme  Theme
	CSRF   string
	Saved  bool
	// DatabasePath and Listen describe where this GUI is serving from, which
	// is the one thing on the page that is not a setting: it is read from the
	// command line and shown so that a reader knows which project they are
	// looking at.
	DatabasePath string
	Listen       string
	SchemaVer    int
	// ReadOnly mirrors serve --read-only: the form is shown, disabled, so
	// that a reader can see how the GUI is configured without being offered
	// a save that the server would refuse.
	ReadOnly bool
}

// ModeLabel names the catalogue key for the serving mode.
func (v SettingsView) ModeLabel() string {
	if v.ReadOnly {
		return "settings.mode.readonly"
	}
	return "settings.mode.readwrite"
}

// NewSettingsView groups the definitions for rendering.
func NewSettingsView(page PageView, theme Theme, csrf string, saved bool) SettingsView {
	v := SettingsView{Page: page, Theme: theme, CSRF: csrf, Saved: saved}
	byGroup := map[string]int{}
	for _, def := range SettingDefs {
		row := SettingRow{Def: def, Value: theme.Value(def.Key)}
		switch def.Kind {
		case KindToggle:
			row.Options = []SettingOptionRow{
				{Value: "on", Label: T(page.Lang, "settings.on"), Selected: row.Value == "on"},
				{Value: "off", Label: T(page.Lang, "settings.off"), Selected: row.Value != "on"},
			}
		default:
			for _, o := range def.Options {
				label := o.Label
				if strings.Contains(label, ".") {
					label = T(page.Lang, o.Label)
				}
				row.Options = append(row.Options, SettingOptionRow{
					Value:    o.Value,
					Label:    label,
					Selected: o.Value == row.Value,
				})
			}
		}
		idx, ok := byGroup[def.Group]
		if !ok {
			v.Groups = append(v.Groups, SettingsGroup{Label: def.Group})
			idx = len(v.Groups) - 1
			byGroup[def.Group] = idx
		}
		v.Groups[idx].Settings = append(v.Groups[idx].Settings, row)
	}
	return v
}

// buildURL assembles a list URL with its filters, paging and sort.
func buildURL(path string, q url.Values, offset, limit int, s Sort, lang Lang) string {
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if s.Column != "" {
		q.Set("sort", s.Column)
		if s.Desc {
			q.Set("dir", "desc")
		}
	}
	return withLang(path, q, lang)
}

// withLang keeps the language in a link when one was asked for explicitly,
// so that following a link does not switch the UI back.
func withLang(path string, q url.Values, lang Lang) string {
	if lang != "" && lang != LangEN {
		q.Set("lang", string(lang))
	}
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}

func setIf(q url.Values, key, value string) {
	if value != "" {
		q.Set(key, value)
	}
}

func pageOf(offset, limit, total int) (int, int) {
	if limit <= 0 {
		return 1, 1
	}
	pages := (total + limit - 1) / limit
	if pages < 1 {
		pages = 1
	}
	return offset/limit + 1, pages
}

// ClassLabel names a classification in the UI language.
func ClassLabel(lang Lang, class string) string {
	if class == "" {
		return "—"
	}
	if s := T(lang, "class."+class); s != "class."+class {
		return s
	}
	return class
}

// ClassOf is the stylesheet modifier for a classification, used to colour a
// bar or a segment.
func ClassOf(class string) string { return class }

// Count renders a number for a table cell, grouped in thousands unless the
// settings ask for plain digits. A six figure event count is unreadable
// without the grouping and unparseable by a script with it, which is why it
// is a setting.
func Count(theme Theme, n int64) string {
	if theme.Value(SettingNumbers) == "plain" {
		return strconv.FormatInt(n, 10)
	}
	return groupDigits(strconv.FormatInt(n, 10))
}

// CountU renders an unsigned count.
func CountU(theme Theme, n uint64) string {
	return Count(theme, int64(n))
}

func groupDigits(s string) string {
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var sb strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			// A narrow no-break space, which groups digits without making
			// them look like two numbers.
			sb.WriteString(" ")
		}
		sb.WriteRune(c)
	}
	if neg {
		return "-" + sb.String()
	}
	return sb.String()
}

// FormatTimeIn renders a timestamp the way the settings ask for.
func FormatTimeIn(theme Theme, t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	switch theme.Value(SettingTimeFormat) {
	case "short":
		return t.UTC().Format("01-02 15:04")
	case "precise":
		return t.UTC().Format("2006-01-02 15:04:05.000000Z")
	default:
		return t.UTC().Format("2006-01-02 15:04:05Z")
	}
}

// ProtocolLabel is how a protocol identifier is shown. The identifiers are
// short and lower case because they key configuration and events; the GUI
// shows the name an engineer would use.
func ProtocolLabel(protocol string) string {
	if name, ok := protocolNames[protocol]; ok {
		return name
	}
	return protocol
}

var protocolNames = map[string]string{
	"modbus":       "Modbus/TCP",
	"dnp3":         "DNP3",
	"s7comm":       "S7comm",
	"iec104":       "IEC 60870-5-104",
	"mms":          "IEC 61850 MMS",
	"goose":        "IEC 61850 GOOSE",
	"enip":         "EtherNet/IP",
	"profinet_dcp": "PROFINET DCP",
	"bacnet":       "BACnet/IP",
	"opcua":        "OPC UA",
}

// ProtocolTier is the parsing depth tier a protocol is dissected at, which
// the statistics view shows so that a reader knows how much detail to expect.
func ProtocolTier(protocol string) int {
	if _, ok := protocolNames[protocol]; ok {
		return 1
	}
	return 0
}

// HealthLabel describes a protocol's parse health in one word.
func HealthLabel(lang Lang, events, malformed int64) string {
	switch {
	case events == 0:
		return "—"
	case malformed == 0:
		return T(lang, "protocols.health.clean")
	case malformed*20 < events:
		return T(lang, "protocols.health.mostly")
	default:
		return T(lang, "protocols.health.poor")
	}
}

// HealthTone is the stylesheet modifier matching HealthLabel.
func HealthTone(events, malformed int64) string {
	switch {
	case events == 0 || malformed == 0:
		return "good"
	case malformed*20 < events:
		return "warn"
	default:
		return "bad"
	}
}

// Percent renders a share for a label.
func Percent(part, whole int64) string {
	if whole == 0 {
		return "0%"
	}
	return strconv.FormatFloat(float64(part)/float64(whole)*100, 'f', 1, 64) + "%"
}

// Duration renders a time span in units a reader can hold: a capture is
// seconds or minutes long and a project may span months.
func Duration(from, to time.Time) string {
	if from.IsZero() || to.IsZero() {
		return "—"
	}
	d := to.Sub(from)
	switch {
	case d < time.Second:
		return strconv.FormatInt(d.Milliseconds(), 10) + " ms"
	case d < time.Minute:
		return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + " s"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + " min"
	case d < 48*time.Hour:
		return strconv.FormatFloat(d.Hours(), 'f', 1, 64) + " h"
	case d < 400*24*time.Hour:
		return strconv.Itoa(int(d.Hours()/24)) + " d"
	default:
		// A project's captures can be years apart, and "4233 d" is not a
		// span anyone holds in their head.
		return strconv.FormatFloat(d.Hours()/24/365.25, 'f', 1, 64) + " y"
	}
}

// Bytes renders a byte count in the units a capture is measured in.
func Bytes(n int64) string {
	switch {
	case n <= 0:
		return "0 B"
	case n < 1024:
		return strconv.FormatInt(n, 10) + " B"
	case n < 1024*1024:
		return strconv.FormatFloat(float64(n)/1024, 'f', 1, 64) + " kB"
	case n < 1024*1024*1024:
		return strconv.FormatFloat(float64(n)/(1024*1024), 'f', 1, 64) + " MB"
	default:
		return strconv.FormatFloat(float64(n)/(1024*1024*1024), 'f', 2, 64) + " GB"
	}
}

// DirectionLabel names a direction in the UI language.
func DirectionLabel(lang Lang, direction string) string {
	switch model.Direction(direction) {
	case model.DirRequest:
		return T(lang, "direction.request")
	case model.DirResponse:
		return T(lang, "direction.response")
	default:
		return T(lang, "direction.unknown")
	}
}

// NavItem is one entry of the navigation.
type NavItem struct {
	Key   string
	Label string
	Href  string
}

// NavItems are the views, in the order they are worth visiting: the project
// at a glance, then the inventory, then the traffic behind it, then what was
// read and how the GUI looks.
func NavItems(lang Lang) []NavItem {
	return []NavItem{
		{Key: "dashboard", Label: T(lang, "nav.dashboard"), Href: "/dashboard"},
		{Key: "assets", Label: T(lang, "nav.assets"), Href: "/assets"},
		{Key: "topology", Label: T(lang, "nav.topology"), Href: "/topology"},
		{Key: "flows", Label: T(lang, "nav.flows"), Href: "/flows"},
		{Key: "matrix", Label: T(lang, "nav.matrix"), Href: "/matrix"},
		{Key: "events", Label: T(lang, "nav.events"), Href: "/events"},
		{Key: "protocols", Label: T(lang, "nav.protocols"), Href: "/protocols"},
		{Key: "captures", Label: T(lang, "nav.captures"), Href: "/captures"},
		{Key: "settings", Label: T(lang, "nav.settings"), Href: "/settings"},
	}
}
