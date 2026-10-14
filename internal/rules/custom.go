package rules

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rom/otinv/internal/model"
)

// Custom rules: the YAML DSL CLAUDE.md asks for, matching on protocol,
// classification, source and destination sets, function codes, time windows
// and rate thresholds.
//
// A rule file is validated on load and the errors say what is wrong and
// where, because a rule nobody can load is a rule nobody writes twice.

// RuleFile is the shape of a custom rule file.
//
//	rules:
//	  - id: PLANT-001
//	    title: Writes to the turbine controller outside the maintenance window
//	    severity: high
//	    technique: T0836
//	    match:
//	      protocol: [modbus]
//	      classification: [write, control]
//	      dst: [192.168.1.40]
//	      not_src: [192.168.1.10]
//	    window:
//	      days: [mon, tue, wed, thu, fri]
//	      from: "06:00"
//	      to: "18:00"
//	    threshold:
//	      count: 10
//	      within: 5m
type RuleFile struct {
	Rules []CustomSpec `yaml:"rules"`
}

// CustomSpec is one rule as it is written in YAML.
type CustomSpec struct {
	ID          string    `yaml:"id"`
	Title       string    `yaml:"title"`
	Description string    `yaml:"description"`
	Severity    string    `yaml:"severity"`
	Technique   string    `yaml:"technique"`
	Match       MatchSpec `yaml:"match"`
	Window      *Window   `yaml:"window"`
	Threshold   *Thresh   `yaml:"threshold"`
}

// MatchSpec selects the events a rule is about. Every field that is set has
// to match; a field that is not set matches everything.
type MatchSpec struct {
	Protocol       []string `yaml:"protocol"`
	Classification []string `yaml:"classification"`
	Operation      []string `yaml:"operation"`
	FunctionCodes  []int    `yaml:"function_codes"`
	UnitIDs        []uint16 `yaml:"unit_ids"`
	Src            []string `yaml:"src"`
	Dst            []string `yaml:"dst"`
	NotSrc         []string `yaml:"not_src"`
	NotDst         []string `yaml:"not_dst"`
	// Malformed matches the frames that did not decode, and Anomaly the ones
	// a dissector flagged.
	Malformed *bool  `yaml:"malformed"`
	Anomaly   string `yaml:"anomaly"`
}

// Window limits a rule to a time of day and a set of weekdays, in UTC —
// capture timestamps are UTC throughout otinv, so a window in local time
// would mean something different for every capture.
type Window struct {
	Days []string `yaml:"days"`
	From string   `yaml:"from"`
	To   string   `yaml:"to"`
	// Outside inverts the window: the rule fires outside it rather than
	// inside, which is how a maintenance window is written.
	Outside bool `yaml:"outside"`
}

// Thresh makes a rule fire only when it matches often enough, which is what
// separates one write from a flood of them.
type Thresh struct {
	Count  int    `yaml:"count"`
	Within string `yaml:"within"`
}

// CustomRule is a loaded, validated custom rule.
type CustomRule struct {
	spec      CustomSpec
	severity  model.Severity
	protocol  map[string]bool
	class     map[string]bool
	operation map[string]bool
	codes     map[int]bool
	units     map[uint16]bool
	src, dst  *addressSet
	notSrc    *addressSet
	notDst    *addressSet
	days      map[time.Weekday]bool
	from, to  time.Duration
	hasWindow bool
	within    time.Duration

	// hits counts the matches per key for a rule with a threshold.
	hits map[string]*window
}

type window struct {
	times    []time.Time
	reported bool
	first    Finding
}

// LoadRuleFiles reads custom rules from files, in the order given.
func LoadRuleFiles(paths ...string) ([]*CustomRule, error) {
	var out []*CustomRule
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("rules: reading %s: %w", path, err)
		}
		loaded, err := ParseRules(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, loaded...)
	}
	return out, nil
}

// ParseRules reads a rule file and validates every rule in it.
func ParseRules(data []byte) ([]*CustomRule, error) {
	var file RuleFile
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true) // a misspelled key is an error, not a silent no-op
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if len(file.Rules) == 0 {
		return nil, fmt.Errorf("rules: the file defines no rules")
	}

	seen := map[string]bool{}
	out := make([]*CustomRule, 0, len(file.Rules))
	for i, spec := range file.Rules {
		rule, err := compile(spec)
		if err != nil {
			where := spec.ID
			if where == "" {
				where = fmt.Sprintf("rule %d", i+1)
			}
			return nil, fmt.Errorf("rules: %s: %w", where, err)
		}
		if seen[rule.spec.ID] {
			return nil, fmt.Errorf("rules: %s: a rule with this id is already defined", rule.spec.ID)
		}
		seen[rule.spec.ID] = true
		out = append(out, rule)
	}
	return out, nil
}

// compile turns one written rule into one that can run, rejecting whatever
// cannot.
func compile(spec CustomSpec) (*CustomRule, error) {
	if strings.TrimSpace(spec.ID) == "" {
		return nil, fmt.Errorf("id is required")
	}
	if strings.TrimSpace(spec.Title) == "" {
		return nil, fmt.Errorf("title is required")
	}

	severity := model.Severity(strings.ToLower(strings.TrimSpace(spec.Severity)))
	if severity == "" {
		severity = model.SeverityMedium
	}
	if !severity.Valid() {
		return nil, fmt.Errorf("severity %q is not one of info, low, medium, high or critical", spec.Severity)
	}
	if spec.Technique != "" && TechniqueName(spec.Technique) == "" {
		// A technique this build cannot name is kept rather than refused: the
		// matrix grows, and a rule should not stop loading because of it.
		// Nothing else depends on the name being known.
		_ = spec.Technique
	}

	rule := &CustomRule{spec: spec, severity: severity, hits: map[string]*window{}}

	for _, class := range spec.Match.Classification {
		c := model.Classification(strings.ToLower(strings.TrimSpace(class)))
		if !c.Valid() {
			return nil, fmt.Errorf("match.classification: %q is not a classification", class)
		}
		if rule.class == nil {
			rule.class = map[string]bool{}
		}
		rule.class[string(c)] = true
	}
	rule.protocol = lowerSet(spec.Match.Protocol)
	rule.operation = exactSet(spec.Match.Operation)
	if len(spec.Match.FunctionCodes) > 0 {
		rule.codes = map[int]bool{}
		for _, code := range spec.Match.FunctionCodes {
			rule.codes[code] = true
		}
	}
	if len(spec.Match.UnitIDs) > 0 {
		rule.units = map[uint16]bool{}
		for _, unit := range spec.Match.UnitIDs {
			rule.units[unit] = true
		}
	}

	var err error
	for _, field := range []struct {
		name   string
		values []string
		target **addressSet
	}{
		{"match.src", spec.Match.Src, &rule.src},
		{"match.dst", spec.Match.Dst, &rule.dst},
		{"match.not_src", spec.Match.NotSrc, &rule.notSrc},
		{"match.not_dst", spec.Match.NotDst, &rule.notDst},
	} {
		if len(field.values) == 0 {
			continue
		}
		if *field.target, err = newAddressSet(field.values); err != nil {
			return nil, fmt.Errorf("%s: %w", field.name, err)
		}
	}

	if spec.Window != nil {
		if err := rule.compileWindow(*spec.Window); err != nil {
			return nil, err
		}
	}
	if spec.Threshold != nil {
		if spec.Threshold.Count < 2 {
			return nil, fmt.Errorf("threshold.count must be at least 2; a rule without a threshold already fires on one match")
		}
		if spec.Threshold.Within == "" {
			return nil, fmt.Errorf("threshold.within is required, for example 5m")
		}
		if rule.within, err = time.ParseDuration(spec.Threshold.Within); err != nil {
			return nil, fmt.Errorf("threshold.within: %w", err)
		}
		if rule.within <= 0 {
			return nil, fmt.Errorf("threshold.within must be positive")
		}
	}

	if rule.matchesEverything() {
		return nil, fmt.Errorf("match selects every event; name at least one protocol, classification, operation, function code, address or anomaly")
	}
	return rule, nil
}

func (r *CustomRule) compileWindow(w Window) error {
	weekdays := map[string]time.Weekday{
		"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
		"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
	}
	for _, day := range w.Days {
		wd, ok := weekdays[strings.ToLower(strings.TrimSpace(day))[:min(3, len(strings.TrimSpace(day)))]]
		if !ok {
			return fmt.Errorf("window.days: %q is not a weekday (mon, tue, wed, thu, fri, sat, sun)", day)
		}
		if r.days == nil {
			r.days = map[time.Weekday]bool{}
		}
		r.days[wd] = true
	}

	if (w.From == "") != (w.To == "") {
		return fmt.Errorf("window: from and to come as a pair")
	}
	if w.From != "" {
		from, err := parseClock(w.From)
		if err != nil {
			return fmt.Errorf("window.from: %w", err)
		}
		to, err := parseClock(w.To)
		if err != nil {
			return fmt.Errorf("window.to: %w", err)
		}
		r.from, r.to = from, to
		r.hasWindow = true
	}
	if len(r.days) == 0 && !r.hasWindow {
		return fmt.Errorf("window: name days, or a from and to time, or both")
	}
	return nil
}

// parseClock reads "HH:MM" as a duration since midnight UTC.
func parseClock(value string) (time.Duration, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("%q is not a time of day as HH:MM", value)
	}
	return time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute, nil
}

// matchesEverything reports whether a rule has no selector at all, which
// would make every event a finding.
func (r *CustomRule) matchesEverything() bool {
	m := r.spec.Match
	return len(r.protocol) == 0 && len(r.class) == 0 && len(r.operation) == 0 &&
		len(r.codes) == 0 && len(r.units) == 0 && r.src == nil && r.dst == nil &&
		r.notSrc == nil && r.notDst == nil && m.Malformed == nil && m.Anomaly == ""
}

// Describe reports the rule as the GUI lists it.
func (r *CustomRule) Describe() Description {
	return Description{
		ID:          r.spec.ID,
		Title:       r.spec.Title,
		Description: r.spec.Description,
		Severity:    r.severity,
		Technique:   r.spec.Technique,
		Custom:      true,
	}
}

// Check matches one event.
func (r *CustomRule) Check(ctx *Context, ev model.Event) []Finding {
	if !r.matches(ev) {
		return nil
	}

	src, dst := endpoints(ev)
	finding := Finding{
		Key:      r.spec.ID + "|" + src + "|" + dst + "|" + ev.Protocol + "|" + ev.Operation,
		Summary:  fmt.Sprintf("%s: %s %s from %s to %s", r.spec.Title, ev.Protocol, ev.Operation, ctx.Label(src), ctx.Label(dst)),
		Src:      src,
		Dst:      dst,
		Protocol: ev.Protocol,
		Details: map[string]string{
			"operation":      ev.Operation,
			"classification": string(ev.Class),
		},
		Evidence: evidenceOf(ev),
	}

	if r.within == 0 {
		return []Finding{finding}
	}
	return r.threshold(finding, ev.Timestamp)
}

// threshold holds a finding back until the rule has matched often enough
// inside its window, and then reports once.
func (r *CustomRule) threshold(finding Finding, at time.Time) []Finding {
	w := r.hits[finding.Key]
	if w == nil {
		w = &window{first: finding}
		r.hits[finding.Key] = w
	}
	w.times = append(w.times, at)

	// Drop what has fallen out of the window.
	cut := at.Add(-r.within)
	keep := w.times[:0]
	for _, t := range w.times {
		if !t.Before(cut) {
			keep = append(keep, t)
		}
	}
	w.times = keep

	if len(w.times) < r.spec.Threshold.Count || w.reported {
		return nil
	}
	w.reported = true

	// The evidence is the first match, which is where the burst started.
	out := w.first
	out.Summary = fmt.Sprintf("%s: %d matches within %s, from %s",
		r.spec.Title, len(w.times), r.within, out.Src)
	if out.Details == nil {
		out.Details = map[string]string{}
	}
	out.Details["matches"] = fmt.Sprint(len(w.times))
	out.Details["within"] = r.within.String()
	return []Finding{out}
}

func (r *CustomRule) matches(ev model.Event) bool {
	m := r.spec.Match
	if len(r.protocol) > 0 && !r.protocol[strings.ToLower(ev.Protocol)] {
		return false
	}
	if len(r.class) > 0 && !r.class[string(ev.Class)] {
		return false
	}
	if len(r.operation) > 0 && !r.operation[ev.Operation] {
		return false
	}
	if len(r.codes) > 0 && !r.codes[ev.FunctionCode] {
		return false
	}
	if len(r.units) > 0 && (ev.UnitID == nil || !r.units[*ev.UnitID]) {
		return false
	}
	if m.Malformed != nil && *m.Malformed != ev.Malformed {
		return false
	}
	if m.Anomaly != "" && !strings.Contains(ev.Attrs["anomaly"], m.Anomaly) {
		return false
	}

	src, dst := endpoints(ev)
	if r.src != nil && !r.src.has(src) {
		return false
	}
	if r.dst != nil && !r.dst.has(dst) {
		return false
	}
	if r.notSrc != nil && r.notSrc.has(src) {
		return false
	}
	if r.notDst != nil && r.notDst.has(dst) {
		return false
	}
	return r.inWindow(ev.Timestamp)
}

// inWindow reports whether an event's time satisfies the rule's window.
func (r *CustomRule) inWindow(at time.Time) bool {
	if r.spec.Window == nil {
		return true
	}
	at = at.UTC()

	inside := len(r.days) == 0 || r.days[at.Weekday()]
	if inside && r.hasWindow {
		since := time.Duration(at.Hour())*time.Hour + time.Duration(at.Minute())*time.Minute
		if r.from <= r.to {
			inside = since >= r.from && since < r.to
		} else {
			// A window that runs past midnight, such as 18:00 to 06:00.
			inside = since >= r.from || since < r.to
		}
	}
	if r.spec.Window.Outside {
		return !inside
	}
	return inside
}

// addressSet is a set of addresses and CIDR blocks a rule matches on.
type addressSet struct {
	exact map[string]bool
	nets  []*net.IPNet
}

func newAddressSet(values []string) (*addressSet, error) {
	set := &addressSet{exact: map[string]bool{}}
	for _, raw := range values {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			set.nets = append(set.nets, network)
			continue
		}
		if net.ParseIP(entry) == nil && !isMAC(entry) {
			return nil, fmt.Errorf("%q is not an address, a MAC or a CIDR block", entry)
		}
		set.exact[strings.ToLower(entry)] = true
	}
	if len(set.exact) == 0 && len(set.nets) == 0 {
		return nil, fmt.Errorf("the list is empty")
	}
	return set, nil
}

func (s *addressSet) has(addr string) bool {
	if s.exact[strings.ToLower(addr)] {
		return true
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func lowerSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]bool, len(values))
	for _, v := range values {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out[v] = true
		}
	}
	return out
}

func exactSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]bool, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			out[v] = true
		}
	}
	return out
}

// SortRules orders rule descriptions for a listing: built-ins first, then by
// id, which is the order a reader expects.
func SortRules(in []Description) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Custom != in[j].Custom {
			return !in[i].Custom
		}
		return in[i].ID < in[j].ID
	})
}
