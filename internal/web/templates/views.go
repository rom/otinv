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
	Roles     []string
	Protocols []string
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
type AssetView struct {
	Page   PageView
	Asset  model.Asset
	Events []EventRow
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

// PrevURL links to the previous page, keeping the filter state so that paging
// is deep-linkable too.
func (v AssetsView) PrevURL() string {
	return v.pageURL(max(v.Offset-v.Limit, 0))
}

// NextURL links to the next page, keeping the filter state.
func (v AssetsView) NextURL() string {
	return v.pageURL(v.Offset + v.Limit)
}

func (v AssetsView) pageURL(offset int) string {
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
