// Package rules turns decoded events and the topology into findings.
//
// A rule is a question about traffic that an analyst would otherwise have to
// ask by hand: did anyone stop a CPU, did a write come from somewhere it
// should not, is a protocol running where it has no business. Every answer
// carries the packet that produced it, because CLAUDE.md is categorical about
// it — "No finding without traceable evidence" — and because a finding an
// analyst cannot check is a finding they cannot act on.
//
// Nothing here looks at a network: rules read stored events, exactly as the
// rest of otinv does.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/topology"
)

// Description is what a rule says about itself: the list the GUI shows and
// the header of every finding it raises.
type Description struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Description says what the rule looks for and why it matters. It is the
	// text an analyst reads when deciding whether a finding is real.
	Description string         `json:"description"`
	Severity    model.Severity `json:"severity"`
	// Technique is a MITRE ATT&CK for ICS technique id.
	Technique string `json:"technique,omitempty"`
	// Custom marks a rule loaded from YAML rather than built in.
	Custom bool `json:"custom,omitempty"`
	// Inactive says why a rule cannot fire in this run — an allow-list it
	// needs is not configured, for example. A rule that silently does
	// nothing is worse than one that says what it is waiting for.
	Inactive string `json:"inactive,omitempty"`
}

// TechniqueName returns the ATT&CK name behind the rule's technique id.
func (d Description) TechniqueName() string { return TechniqueName(d.Technique) }

// Rule is the common part of every rule: what it is.
type Rule interface {
	Describe() Description
}

// EventRule examines one decoded event at a time, in capture order.
//
// A rule may keep state between events — counting exceptions per endpoint,
// remembering a GOOSE publisher — so an engine builds its rules fresh for
// each run.
type EventRule interface {
	Rule
	Check(ctx *Context, ev model.Event) []Finding
}

// GraphRule examines the network as a whole once every event has been seen,
// which is how a flow that skips a Purdue level is found: no single packet
// shows it.
type GraphRule interface {
	Rule
	CheckGraph(ctx *Context, g topology.Graph) []Finding
}

// Finding is what a rule reports. The engine fills in the rule's own fields
// and merges findings that share a key.
type Finding struct {
	// Key groups the observations that are the same finding — one key per
	// (rule, device, operation) in most rules. The engine keeps the first
	// evidence and counts the rest, so a thousand identical writes are one
	// finding with a count rather than a thousand rows nobody reads.
	Key string
	// Summary is this finding in one line.
	Summary string
	// Severity overrides the rule's own, for a rule whose seriousness
	// depends on what it found.
	Severity model.Severity
	// Technique overrides the rule's own, for the same reason.
	Technique string

	Src      string
	Dst      string
	Protocol string
	Details  map[string]string
	Evidence model.Evidence
}

// AssetInfo is what the rules know about one device, from the inventory.
type AssetInfo struct {
	Key   string
	Label string
	Role  model.RoleName
	Level int
}

// Config configures an engine.
type Config struct {
	// Assets is the inventory, which places the endpoints of an event.
	Assets []model.Asset

	// EngineeringStations are the addresses allowed to write, control and
	// program, as addresses or CIDR blocks. CLAUDE.md calls it the
	// engineering allow-list. Empty leaves the rule that needs it inactive
	// rather than flagging every write in the plant.
	EngineeringStations []string

	// Registry supplies the default ports, which is what makes "a protocol on
	// a non-standard port" answerable. Defaults to dissect.Default().
	Registry *dissect.Registry

	// Custom holds the rules loaded from YAML.
	Custom []*CustomRule

	// Disabled lists rule ids to leave out of this run.
	Disabled []string
}

// Context is what a rule may ask about the project while it checks an event.
type Context struct {
	assets      map[string]AssetInfo
	engineering map[string]bool
	engNets     []*net.IPNet
	ports       map[string]map[uint16]bool
	hasAllow    bool

	// edges remembers the first event seen between two assets over one
	// protocol, so that a rule which looks at the finished graph can still
	// point at a packet. CLAUDE.md allows no finding without one.
	edges map[string]model.Evidence
}

// noteEvent records an event as the evidence for the edge it belongs to.
func (c *Context) noteEvent(ev model.Event) {
	src, dst := endpoints(ev)
	srcKey, dstKey := c.assetKey(src), c.assetKey(dst)
	if srcKey == "" || dstKey == "" || ev.Protocol == "" {
		return
	}
	for _, key := range []string{
		srcKey + "|" + dstKey + "|" + ev.Protocol,
		dstKey + "|" + srcKey + "|" + ev.Protocol,
	} {
		if _, seen := c.edges[key]; !seen {
			c.edges[key] = evidenceOf(ev)
		}
	}
}

// assetKey returns the asset an address belongs to, or the address itself for
// an endpoint the inventory does not hold — a multicast group, say, which the
// graph draws as a node of its own.
func (c *Context) assetKey(addr string) string {
	if a, ok := c.assets[addr]; ok {
		return a.Key
	}
	return addr
}

// edgeEvidence returns the first event seen on an edge of the graph.
func (c *Context) edgeEvidence(src, dst, protocol string) (model.Evidence, bool) {
	e, ok := c.edges[src+"|"+dst+"|"+protocol]
	return e, ok
}

// Asset returns what the inventory knows about an address.
func (c *Context) Asset(addr string) (AssetInfo, bool) {
	a, ok := c.assets[addr]
	return a, ok
}

// Label renders an address for a reader: the asset's label, and the address
// itself as well when the two differ.
//
// A device with several addresses is labelled by one of them, so a finding
// about traffic from another of its addresses would otherwise name an address
// that is nowhere in the evidence.
func (c *Context) Label(addr string) string {
	a, ok := c.assets[addr]
	switch {
	case !ok || a.Label == "":
		return addr
	case a.Label == addr:
		return addr
	default:
		return a.Label + " (" + addr + ")"
	}
}

// Identity returns the asset an address belongs to, or the address itself for
// one the inventory does not hold. Rules key their findings on it, so that a
// device with several addresses raises one finding rather than one per
// address.
func (c *Context) Identity(addr string) string {
	if a, ok := c.assets[addr]; ok && a.Key != "" {
		return a.Key
	}
	return addr
}

// Level returns the Purdue level an address was placed in, or
// model.LevelUnknown.
func (c *Context) Level(addr string) int {
	if a, ok := c.assets[addr]; ok {
		return a.Level
	}
	return model.LevelUnknown
}

// HasAllowList reports whether an engineering allow-list was configured.
func (c *Context) HasAllowList() bool { return c.hasAllow }

// IsEngineering reports whether an address is on the engineering allow-list.
func (c *Context) IsEngineering(addr string) bool {
	if c.engineering[addr] {
		return true
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range c.engNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// StandardPort reports whether a port is one of the protocol's own, as the
// dissector registry and the configuration file define them.
func (c *Context) StandardPort(protocol string, port uint16) bool {
	return c.ports[protocol][port]
}

// KnownPorts reports whether the registry knows any port for a protocol. A
// protocol carried under an EtherType has none, and "not on its usual port"
// means nothing for it.
func (c *Context) KnownPorts(protocol string) bool { return len(c.ports[protocol]) > 0 }

// Engine runs the rules over a project.
type Engine struct {
	event []EventRule
	graph []GraphRule
	rules []Rule
	ctx   *Context

	// findings are merged by rule and key as they arrive.
	findings map[string]*model.Finding
	order    []string
}

// New builds an engine with the built-in rules, the custom ones, and the
// context they read the project through.
func New(cfg Config) (*Engine, error) {
	registry := cfg.Registry
	if registry == nil {
		registry = dissect.Default()
	}

	ctx := &Context{
		assets:      map[string]AssetInfo{},
		engineering: map[string]bool{},
		ports:       map[string]map[uint16]bool{},
		edges:       map[string]model.Evidence{},
	}
	for _, a := range cfg.Assets {
		info := AssetInfo{Key: a.Key, Label: a.Label, Role: a.Role.Name, Level: a.Level.Value}
		for _, addr := range a.IPs {
			ctx.assets[addr] = info
		}
		for _, addr := range a.MACs {
			ctx.assets[addr] = info
		}
	}
	for _, raw := range cfg.EngineeringStations {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		ctx.hasAllow = true
		if _, network, err := net.ParseCIDR(entry); err == nil {
			ctx.engNets = append(ctx.engNets, network)
			continue
		}
		if net.ParseIP(entry) == nil && !isMAC(entry) {
			return nil, fmt.Errorf("rules: engineering station %q is not an address, a MAC or a CIDR block", entry)
		}
		ctx.engineering[entry] = true
	}
	for _, reg := range registry.Registered() {
		ports := map[uint16]bool{}
		for _, p := range reg.TCPPorts {
			ports[p] = true
		}
		for _, p := range reg.UDPPorts {
			ports[p] = true
		}
		if len(ports) > 0 {
			ctx.ports[reg.Name] = ports
		}
	}

	disabled := map[string]bool{}
	for _, id := range cfg.Disabled {
		disabled[strings.TrimSpace(id)] = true
	}

	e := &Engine{ctx: ctx, findings: map[string]*model.Finding{}}
	for _, rule := range builtins() {
		e.add(rule, disabled)
	}
	for _, rule := range cfg.Custom {
		if rule == nil {
			continue
		}
		e.add(rule, disabled)
	}
	return e, nil
}

func (e *Engine) add(rule Rule, disabled map[string]bool) {
	if disabled[rule.Describe().ID] {
		return
	}
	e.rules = append(e.rules, rule)
	if r, ok := rule.(EventRule); ok {
		e.event = append(e.event, r)
	}
	if r, ok := rule.(GraphRule); ok {
		e.graph = append(e.graph, r)
	}
}

// Rules describes the rules this engine runs, built-ins first, in id order.
func (e *Engine) Rules() []Description {
	out := make([]Description, 0, len(e.rules))
	for _, rule := range e.rules {
		d := rule.Describe()
		if d.Inactive == "" {
			d.Inactive = e.inactive(rule)
		}
		out = append(out, d)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Custom != out[j].Custom {
			return !out[i].Custom
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// inactive asks a rule whether it can fire at all in this run.
func (e *Engine) inactive(rule Rule) string {
	if r, ok := rule.(interface{ InactiveReason(*Context) string }); ok {
		return r.InactiveReason(e.ctx)
	}
	return ""
}

// Add folds one event into every event rule.
func (e *Engine) Add(ev model.Event) {
	e.ctx.noteEvent(ev)
	for _, rule := range e.event {
		for _, f := range rule.Check(e.ctx, ev) {
			e.record(rule.Describe(), f, ev.Timestamp)
		}
	}
}

// AddTopology runs the rules that look at the network as a whole. It is
// called once, after every event.
func (e *Engine) AddTopology(g topology.Graph) {
	for _, rule := range e.graph {
		for _, f := range rule.CheckGraph(e.ctx, g) {
			e.record(rule.Describe(), f, f.Evidence.Timestamp)
		}
	}
}

// record merges one reported finding into the result.
func (e *Engine) record(d Description, f Finding, at time.Time) {
	if f.Evidence.CaptureID == "" && f.Evidence.Protocol == "" {
		// CLAUDE.md: no finding without traceable evidence. A rule that
		// reports one without is a bug, and dropping it is better than
		// showing an analyst something they cannot check.
		return
	}

	key := f.Key
	if key == "" {
		key = fmt.Sprintf("%s|%s|%s|%d", f.Src, f.Dst, f.Protocol, f.Evidence.PacketIndex)
	}
	id := findingID(d.ID, key)

	if existing, ok := e.findings[id]; ok {
		existing.Count++
		if at.Before(existing.FirstSeen) && !at.IsZero() {
			existing.FirstSeen = at
		}
		if at.After(existing.LastSeen) {
			existing.LastSeen = at
		}
		return
	}

	severity := d.Severity
	if f.Severity != "" {
		severity = f.Severity
	}
	technique := d.Technique
	if f.Technique != "" {
		technique = f.Technique
	}

	finding := &model.Finding{
		ID:            id,
		RuleID:        d.ID,
		Title:         d.Title,
		Summary:       f.Summary,
		Description:   d.Description,
		Severity:      severity,
		Technique:     technique,
		TechniqueName: TechniqueName(technique),
		Status:        model.StatusNew,
		Src:           f.Src,
		Dst:           f.Dst,
		Protocol:      f.Protocol,
		Count:         1,
		FirstSeen:     at,
		LastSeen:      at,
		Evidence:      f.Evidence,
		Details:       f.Details,
	}
	e.findings[id] = finding
	e.order = append(e.order, id)
}

// Findings returns what the rules found: most serious first, then the busiest,
// then by id so that two runs over one project agree.
func (e *Engine) Findings() []model.Finding {
	out := make([]model.Finding, 0, len(e.order))
	for _, id := range e.order {
		out = append(out, *e.findings[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := out[i].Severity.Rank(), out[j].Severity.Rank(); a != b {
			return a > b
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// findingID is the stable identity of a finding: the rule and what the
// finding is about. Re-running the rules over the same project produces the
// same id, which is what lets a triaged finding stay triaged.
func findingID(ruleID, key string) string {
	sum := sha256.Sum256([]byte(ruleID + "\x00" + key))
	return hex.EncodeToString(sum[:8])
}

// endpoints returns an event's endpoints the way the flow views spell them:
// the IP when there is one, the MAC otherwise.
func endpoints(ev model.Event) (src, dst string) {
	src, dst = ev.Flow.SrcIP, ev.Flow.DstIP
	if src == "" {
		src = ev.Flow.SrcMAC
	}
	if dst == "" {
		dst = ev.Flow.DstMAC
	}
	return src, dst
}

// evidenceOf builds the evidence an event provides.
func evidenceOf(ev model.Event) model.Evidence {
	return model.Evidence{
		CaptureID:    ev.CaptureID,
		PacketIndex:  ev.PacketIndex,
		Timestamp:    ev.Timestamp,
		Protocol:     ev.Protocol,
		Operation:    ev.Operation,
		FunctionCode: ev.FunctionCode,
		SrcIP:        ev.Flow.SrcIP,
		DstIP:        ev.Flow.DstIP,
	}
}

func isMAC(s string) bool {
	_, err := net.ParseMAC(s)
	return err == nil
}
