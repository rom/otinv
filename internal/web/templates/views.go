package templates

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rom/otinv/internal/model"
)

// PageView is the chrome every page shares.
type PageView struct {
	Lang    Lang
	Title   string
	Project string
	Nav     string // "assets" or "captures"
}

// AssetsFilter is the asset list's filter state. It round-trips through the
// URL so that every view is deep-linkable.
type AssetsFilter struct {
	Search   string
	Role     string
	Protocol string
}

// Sort is a table's sort state, and like the filters it round-trips through
// the URL: a sorted view is a view, and CLAUDE.md asks every one of them to be
// deep-linkable.
//
// Column is empty for a table in its natural order, which is the order each
// one is most useful in before anyone asks otherwise: the busiest assets
// first, the newest events first.
type Sort struct {
	Column string
	Desc   bool
}

// SortColumn describes one sortable column.
type SortColumn struct {
	Key   string // what appears in the URL
	Label string // what the header shows
	// Numeric right-aligns the column and makes its first click sort
	// downwards, because for a count, a confidence or a timestamp the end
	// worth looking at first is the largest.
	Numeric bool
}

// SortHeaderView is one rendered column header.
type SortHeaderView struct {
	Label string
	URL   string
	// Direction is the aria-sort value: "ascending", "descending" or "none".
	// Screen readers read it, and the stylesheet draws the arrow from it, so
	// the two can never disagree.
	Direction string
	Numeric   bool
	// Target is the element htmx replaces with the sorted table, for a table
	// that is swapped on its own. Empty means the link is followed normally,
	// which is also what happens without htmx.
	Target string
}

// Class is the header cell's class list.
func (h SortHeaderView) Class() string {
	if h.Numeric {
		return "sortable num"
	}
	return "sortable"
}

// Next returns the sort state a click on this column asks for: the same
// column reversed, or a column not yet sorted in its own natural direction.
func (s Sort) Next(col SortColumn) Sort {
	if s.Column == col.Key {
		return Sort{Column: col.Key, Desc: !s.Desc}
	}
	return Sort{Column: col.Key, Desc: col.Numeric}
}

// sortHeaders renders a table's headers against the sort it is showing.
func sortHeaders(cols []SortColumn, current Sort, link func(Sort) string, target string) []SortHeaderView {
	out := make([]SortHeaderView, 0, len(cols))
	for _, col := range cols {
		h := SortHeaderView{
			Label:     col.Label,
			URL:       link(current.Next(col)),
			Direction: "none",
			Numeric:   col.Numeric,
			Target:    target,
		}
		if current.Column == col.Key {
			h.Direction = "ascending"
			if current.Desc {
				h.Direction = "descending"
			}
		}
		out = append(out, h)
	}
	return out
}

// AssetRow is one line of the asset table.
type AssetRow struct {
	Key       string
	Label     string
	Vendor    string
	Role      model.RoleName
	Addresses []string
	Protocols []string
	Events    uint64
	LastSeen  time.Time
	IsGateway bool
}

// AssetsView is the asset list.
type AssetsView struct {
	Page      PageView
	Rows      []AssetRow
	Total     int
	Offset    int
	Limit     int
	Filter    AssetsFilter
	Sort      Sort
	Roles     []string
	Protocols []string
}

// Headers are the asset list's column headers. The list is paged in the
// store, so every one of these orders the whole inventory rather than the
// fifty rows on screen.
func (v AssetsView) Headers() []SortHeaderView {
	lang := v.Page.Lang
	return sortHeaders([]SortColumn{
		{Key: "address", Label: T(lang, "assets.address")},
		{Key: "role", Label: T(lang, "assets.role")},
		{Key: "vendor", Label: T(lang, "assets.vendor")},
		{Key: "protocols", Label: T(lang, "assets.protocols")},
		{Key: "events", Label: T(lang, "assets.events"), Numeric: true},
		{Key: "seen", Label: T(lang, "assets.seen"), Numeric: true},
	}, v.Sort, v.SortURL, "#asset-table")
}

// SortURL links to the list under a different sort, keeping the filters and
// returning to the first page: the rows a second page holds depend on the
// order, so an offset from the old one means nothing.
func (v AssetsView) SortURL(s Sort) string {
	return v.listURL(0, s)
}

// EventRow is one line of an asset's event list.
type EventRow struct {
	Time      time.Time
	Operation string
	// Detail is the part of the operation that matters when reading a page:
	// which diagnostics sub-function, which register, which anomaly. Without
	// it an FC 8 that forces a device listen-only is indistinguishable from
	// one that reads a counter.
	Detail    string
	Class     string
	Direction string
	Peer      string
	Packet    uint64
	Unit      string
	Exception string
	Malformed bool
}

// AssetView is one asset's detail page.
//
// Its four tables share one sort state, with the column named for the table
// it belongs to. One pair of query parameters keeps the URL readable, and
// sorting two tables of the same page at once is not something anyone has
// needed to do.
type AssetView struct {
	Page   PageView
	Asset  model.Asset
	Events []EventRow
	Sort   Sort
}

// IdentityHeaders are the headers of the inferred identity table.
func (v AssetView) IdentityHeaders() []SortHeaderView {
	lang := v.Page.Lang
	return sortHeaders([]SortColumn{
		{Key: "identity.field", Label: T(lang, "asset.field")},
		{Key: "identity.value", Label: T(lang, "asset.value")},
		{Key: "identity.confidence", Label: T(lang, "asset.confidence"), Numeric: true},
		{Key: "identity.source", Label: T(lang, "asset.source")},
		{Key: "identity.evidence", Label: T(lang, "asset.evidence"), Numeric: true},
	}, v.Sort, v.SortURL, "")
}

// AddressHeaders are the headers of the observed address table.
func (v AssetView) AddressHeaders() []SortHeaderView {
	lang := v.Page.Lang
	return sortHeaders([]SortColumn{
		{Key: "addresses.mac", Label: "MAC"},
		{Key: "addresses.ip", Label: "IP"},
		{Key: "addresses.vlan", Label: "VLAN", Numeric: true},
		{Key: "addresses.events", Label: T(lang, "assets.events"), Numeric: true},
		{Key: "addresses.time", Label: T(lang, "asset.time"), Numeric: true},
	}, v.Sort, v.SortURL, "")
}

// ProtocolHeaders are the headers of the protocol usage table.
func (v AssetView) ProtocolHeaders() []SortHeaderView {
	lang := v.Page.Lang
	return sortHeaders([]SortColumn{
		{Key: "protocols.protocol", Label: T(lang, "assets.protocol")},
		{Key: "protocols.side", Label: T(lang, "asset.side")},
		{Key: "protocols.events", Label: T(lang, "assets.events"), Numeric: true},
		{Key: "protocols.class", Label: T(lang, "asset.class")},
		{Key: "protocols.unit", Label: T(lang, "asset.unit")},
	}, v.Sort, v.SortURL, "")
}

// EventHeaders are the headers of the recent event table.
func (v AssetView) EventHeaders() []SortHeaderView {
	lang := v.Page.Lang
	return sortHeaders([]SortColumn{
		{Key: "events.time", Label: T(lang, "asset.time"), Numeric: true},
		{Key: "events.operation", Label: T(lang, "asset.operation")},
		{Key: "events.class", Label: T(lang, "asset.class")},
		{Key: "events.peer", Label: T(lang, "asset.peer")},
		{Key: "events.unit", Label: T(lang, "asset.unit")},
		{Key: "events.packet", Label: T(lang, "asset.packet"), Numeric: true},
	}, v.Sort, v.SortURL, "")
}

// SortURL links to this asset under a different sort.
func (v AssetView) SortURL(s Sort) string {
	return AssetURL(v.Asset.Key) + sortQuery(s)
}

// CaptureRow is one ingested capture.
type CaptureRow struct {
	Path      string
	SHA256    string
	Packets   uint64
	LinkType  string
	FirstSeen time.Time
	LastSeen  time.Time
}

// CapturesView is the capture list.
type CapturesView struct {
	Page     PageView
	Captures []CaptureRow
	Sort     Sort
}

// Headers are the capture list's column headers.
func (v CapturesView) Headers() []SortHeaderView {
	lang := v.Page.Lang
	return sortHeaders([]SortColumn{
		{Key: "path", Label: T(lang, "captures.file")},
		{Key: "digest", Label: T(lang, "captures.digest")},
		{Key: "packets", Label: T(lang, "captures.packets"), Numeric: true},
		{Key: "range", Label: T(lang, "captures.range"), Numeric: true},
	}, v.Sort, v.SortURL, "")
}

// SortURL links to the capture list under a different sort.
func (v CapturesView) SortURL(s Sort) string {
	return "/captures" + sortQuery(s)
}

// sortQuery renders a sort as the query string that restores it.
func sortQuery(s Sort) string {
	if s.Column == "" {
		return ""
	}
	q := url.Values{"sort": {s.Column}}
	if s.Desc {
		q.Set("dir", "desc")
	}
	return "?" + q.Encode()
}

// RoleLabel translates a role name for display.
func RoleLabel(lang Lang, role model.RoleName) string {
	return T(lang, "role."+string(role))
}

// FormatTime renders a timestamp in the fixed, unambiguous form an analyst
// needs; capture times are UTC and are never localised.
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04:05Z")
}

// ShortDigest shortens a hash for display.
func ShortDigest(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

// Join renders a list of addresses or protocols.
func Join(xs []string) string {
	if len(xs) == 0 {
		return "—"
	}
	return strings.Join(xs, ", ")
}

// FormatUnits renders a protocol's unit ids.
func FormatUnits(units []uint16) string {
	if len(units) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(units))
	for _, u := range units {
		parts = append(parts, strconv.Itoa(int(u)))
	}
	return strings.Join(parts, ", ")
}

// FormatClasses renders the class histogram of a protocol usage in a stable
// order.
func FormatClasses(classes map[model.Classification]uint64) string {
	if len(classes) == 0 {
		return "—"
	}
	order := []model.Classification{
		model.ClassRead, model.ClassWrite, model.ClassControl, model.ClassProgram,
		model.ClassFirmware, model.ClassDiagnostic, model.ClassDiscovery, model.ClassOther,
	}
	parts := make([]string, 0, len(classes))
	for _, c := range order {
		if n, ok := classes[c]; ok {
			parts = append(parts, fmt.Sprintf("%s %d", c, n))
		}
	}
	return strings.Join(parts, " · ")
}

// PageInfo is the state the pager needs.
func (v AssetsView) PageInfo() (page, pages int) {
	if v.Limit <= 0 {
		return 1, 1
	}
	page = v.Offset/v.Limit + 1
	pages = (v.Total + v.Limit - 1) / v.Limit
	if pages < 1 {
		pages = 1
	}
	return page, pages
}

// HasPrev reports whether there is a page before this one.
func (v AssetsView) HasPrev() bool { return v.Offset > 0 }

// HasNext reports whether there is a page after this one.
func (v AssetsView) HasNext() bool { return v.Offset+v.Limit < v.Total }

// PrevURL links to the previous page, keeping the filter and sort state so
// that paging is deep-linkable too.
func (v AssetsView) PrevURL() string {
	return v.listURL(max(v.Offset-v.Limit, 0), v.Sort)
}

// NextURL links to the next page, keeping the filter and sort state.
func (v AssetsView) NextURL() string {
	return v.listURL(v.Offset+v.Limit, v.Sort)
}

func (v AssetsView) listURL(offset int, s Sort) string {
	q := url.Values{}
	if v.Filter.Search != "" {
		q.Set("q", v.Filter.Search)
	}
	if v.Filter.Role != "" {
		q.Set("role", v.Filter.Role)
	}
	if v.Filter.Protocol != "" {
		q.Set("protocol", v.Filter.Protocol)
	}
	if s.Column != "" {
		q.Set("sort", s.Column)
		if s.Desc {
			q.Set("dir", "desc")
		}
	}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	if v.Limit > 0 {
		q.Set("limit", strconv.Itoa(v.Limit))
	}
	if len(q) == 0 {
		return "/assets"
	}
	return "/assets?" + q.Encode()
}

// AssetURL is the deep link to one asset.
func AssetURL(key string) string {
	return "/assets/" + url.PathEscape(key)
}

// ConfidenceLabel renders a confidence as a percentage.
func ConfidenceLabel(c int) string { return strconv.Itoa(c) + "%" }
