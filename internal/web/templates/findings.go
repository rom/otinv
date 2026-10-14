package templates

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/rules"
)

// The findings views: the triage list, one finding with its evidence, and the
// rules that produce them.

// FindingsFilter is the filter state of the triage list, which is also the
// URL.
type FindingsFilter struct {
	Severity string
	Status   string
	Rule     string
	Protocol string
	Search   string
	// Open narrows the list to what still wants attention, which is what the
	// view opens on.
	Open bool
}

// Query renders the filter as URL values.
func (f FindingsFilter) Query() url.Values {
	v := url.Values{}
	if f.Severity != "" {
		v.Set("severity", f.Severity)
	}
	if f.Status != "" {
		v.Set("status", f.Status)
	}
	if f.Rule != "" {
		v.Set("rule", f.Rule)
	}
	if f.Protocol != "" {
		v.Set("protocol", f.Protocol)
	}
	if f.Search != "" {
		v.Set("q", f.Search)
	}
	if f.Open {
		v.Set("open", "1")
	}
	return v
}

// FindingRow is one line of the triage list.
type FindingRow struct {
	ID        string
	RuleID    string
	Title     string
	Summary   string
	Severity  string
	Status    string
	Src       string
	Dst       string
	SrcHref   string
	DstHref   string
	Protocol  string
	Count     int64
	LastSeen  time.Time
	Href      string
	Technique string
}

// FindingsView is the triage list.
type FindingsView struct {
	Page       PageView
	Theme      Theme
	Rows       []FindingRow
	Total      int
	Open       int64
	Offset     int
	Limit      int
	Filter     FindingsFilter
	Sort       Sort
	Severities []string
	Statuses   []string
	Rules      []string
	Protocols  []string
	CSRF       string
	// Saved says a triage change was just stored, which the page confirms.
	Saved string
}

// Headers are the triage list's column headers.
func (v FindingsView) Headers() []SortHeaderView {
	lang := v.Page.Lang
	return sortHeaders([]SortColumn{
		{Key: "severity", Label: T(lang, "findings.severity")},
		{Key: "rule", Label: T(lang, "findings.rule")},
		{Key: "src", Label: T(lang, "findings.src")},
		{Key: "dst", Label: T(lang, "findings.dst")},
		{Key: "count", Label: T(lang, "findings.count"), Numeric: true},
		{Key: "last", Label: T(lang, "findings.last"), Numeric: true},
		{Key: "status", Label: T(lang, "findings.status")},
	}, v.Sort, v.SortURL, "")
}

// SortURL links to the list under a different sort, keeping the filters.
func (v FindingsView) SortURL(s Sort) string { return v.listURL(0, s) }

// PrevURL and NextURL page the list.
func (v FindingsView) PrevURL() string { return v.listURL(max(v.Offset-v.Limit, 0), v.Sort) }

// NextURL links to the next page.
func (v FindingsView) NextURL() string { return v.listURL(v.Offset+v.Limit, v.Sort) }

// HasPrev reports whether there is a page before this one.
func (v FindingsView) HasPrev() bool { return v.Offset > 0 }

// HasNext reports whether there is a page after this one.
func (v FindingsView) HasNext() bool { return v.Offset+len(v.Rows) < v.Total }

// Range renders which findings this page holds.
func (v FindingsView) Range() string {
	if v.Total == 0 {
		return "0"
	}
	return strconv.Itoa(v.Offset+1) + "–" + strconv.Itoa(v.Offset+len(v.Rows)) +
		" / " + strconv.Itoa(v.Total)
}

func (v FindingsView) listURL(offset int, s Sort) string {
	q := v.Filter.Query()
	if s.Column != "" {
		q.Set("sort", s.Column)
		if s.Desc {
			q.Set("dir", "desc")
		}
	}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	if len(q) == 0 {
		return "/findings"
	}
	return "/findings?" + q.Encode()
}

// FindingView is one finding with everything behind it.
type FindingView struct {
	Page    PageView
	Theme   Theme
	Finding model.Finding
	CSRF    string
	Saved   bool
	// Evidence links point at the traffic the finding rests on.
	EventsHref  string
	CaptureHref string
	SrcHref     string
	DstHref     string
	// TechniqueURL links to the ATT&CK page for the technique.
	TechniqueURL string
	// Details are the rule's own fields, sorted for a stable page.
	Details  []DetailRow
	Statuses []StatusOption
	Back     string
}

// DetailRow is one key and value of a finding's details.
type DetailRow struct {
	Field string
	Value string
}

// StatusOption is one triage state in the form.
type StatusOption struct {
	Value    string
	Label    string
	Selected bool
}

// Observations renders how many times a rule saw what it reports, with the
// noun in the right number: "1 observation", "5 observations".
func (v FindingView) Observations() string {
	key := "finding.observations"
	if v.Finding.Count == 1 {
		key = "finding.observation"
	}
	return Count(v.Theme, v.Finding.Count) + " " + T(v.Page.Lang, key)
}

// SeverityLabel renders a severity in the reader's language.
func SeverityLabel(lang Lang, severity string) string {
	if severity == "" {
		return ""
	}
	return T(lang, "severity."+severity)
}

// StatusLabel renders a triage state in the reader's language.
func StatusLabel(lang Lang, status string) string {
	if status == "" {
		return ""
	}
	return T(lang, "status."+status)
}

// SeverityCSS is the class that colours a severity tag.
func SeverityCSS(severity string) string { return "tag severity-" + severity }

// StatusCSS is the class that colours a triage state.
func StatusCSS(status string) string { return "tag status-" + status }

// SeverityNames lists the severities for a filter menu, most serious first.
func SeverityNames() []string {
	out := make([]string, 0, len(model.Severities))
	for _, s := range model.Severities {
		out = append(out, string(s))
	}
	return out
}

// StatusNames lists the triage states in workflow order.
func StatusNames() []string {
	out := make([]string, 0, len(model.Statuses))
	for _, s := range model.Statuses {
		out = append(out, string(s))
	}
	return out
}

// RuleRow is one rule in the rules view.
type RuleRow struct {
	ID            string
	Title         string
	Description   string
	Severity      string
	Technique     string
	TechniqueName string
	TechniqueURL  string
	Custom        bool
	Inactive      string
	// Findings is how many findings the rule has in this project, and Href
	// the list filtered to them.
	Findings int64
	Href     string
}

// RulesView lists the rules the server runs.
type RulesView struct {
	Page  PageView
	Theme Theme
	Rows  []RuleRow
	CSRF  string
	// ReadOnly mirrors serve --read-only: re-running the rules is a write,
	// so a read-only GUI does not offer it.
	ReadOnly bool
	// Reran says a re-run has just finished, with what it found.
	Reran string
	// CustomFiles are the rule files the configuration loads, which is where
	// a custom rule is edited for now.
	CustomFiles []string
}

// NewRuleRows turns the engine's descriptions into rows, with the finding
// counts the project holds for each.
func NewRuleRows(in []rules.Description, counts map[string]int64) []RuleRow {
	out := make([]RuleRow, 0, len(in))
	for _, d := range in {
		out = append(out, RuleRow{
			ID:            d.ID,
			Title:         d.Title,
			Description:   d.Description,
			Severity:      string(d.Severity),
			Technique:     d.Technique,
			TechniqueName: d.TechniqueName(),
			TechniqueURL:  rules.TechniqueURL(d.Technique),
			Custom:        d.Custom,
			Inactive:      d.Inactive,
			Findings:      counts[d.ID],
			Href:          "/findings?rule=" + url.QueryEscape(d.ID),
		})
	}
	return out
}

// DetailRows sorts a finding's details for the page.
func DetailRows(details map[string]string) []DetailRow {
	out := make([]DetailRow, 0, len(details))
	for field, value := range details {
		if value == "" {
			continue
		}
		out = append(out, DetailRow{Field: field, Value: value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

// FindingURL is the deep link to one finding.
func FindingURL(id string) string { return "/findings/" + url.PathEscape(id) }

// EvidenceHref links a finding to the events behind it: the capture and the
// endpoints it names, which is as close as a list gets to the packet.
func EvidenceHref(f model.Finding) string {
	q := url.Values{}
	if f.Evidence.CaptureID != "" {
		q.Set("capture", f.Evidence.CaptureID)
	}
	if f.Protocol != "" {
		q.Set("protocol", f.Protocol)
	}
	if f.Evidence.Operation != "" {
		q.Set("operation", f.Evidence.Operation)
	}
	if f.Src != "" && f.Dst != "" {
		q.Set("src", f.Src)
		q.Set("dst", f.Dst)
	} else if f.Src != "" {
		q.Set("q", f.Src)
	}
	if len(q) == 0 {
		return "/events"
	}
	return "/events?" + q.Encode()
}

// TrimID shortens a finding id for a table, where the whole hash is noise.
func TrimID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// JoinIDs renders selected ids for a bulk action.
func JoinIDs(ids []string) string { return strings.Join(ids, ",") }
