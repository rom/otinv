package topology

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/otinv/internal/model"
)

// Link is one aggregated conversation between two endpoints over one
// protocol, which is what the store's flow aggregate produces. An endpoint is
// an IP address, or a MAC address for a protocol with no IP layer.
type Link struct {
	Src        string
	Dst        string
	Protocol   string
	Transport  model.Transport
	ServerPort uint16
	Events     int64
	Malformed  int64
	Classes    map[model.Classification]int64
	FirstSeen  time.Time
	LastSeen   time.Time
}

// Node kinds. A group is a multicast or broadcast address rather than a
// device: GOOSE publishes to one and nothing answers from it, so it is drawn
// as what it is instead of being hidden or mistaken for a host.
const (
	KindDevice  = "device"
	KindGateway = "gateway"
	KindGroup   = "group"
	KindUnknown = "unknown"
)

// Node is one vertex of the topology: an asset, a forwarding device, a
// multicast group, or an address that appears in a flow but in no asset.
type Node struct {
	ID        string           `json:"id"`
	Label     string           `json:"label"`
	Kind      string           `json:"kind"`
	Role      model.RoleName   `json:"role,omitempty"`
	Vendor    string           `json:"vendor,omitempty"`
	Level     int              `json:"level"`
	LevelNote string           `json:"level_note,omitempty"`
	Subnet    string           `json:"subnet,omitempty"`
	VLANs     []uint16         `json:"vlans,omitempty"`
	Protocols []string         `json:"protocols,omitempty"`
	Addresses []string         `json:"addresses,omitempty"`
	Classes   map[string]int64 `json:"classes,omitempty"`
	Events    int64            `json:"events"`
	Href      string           `json:"href,omitempty"`
	// Context marks a node that is drawn because the selection talks to it
	// rather than because it matched the filter. A filtered topology that hid
	// the other end of every edge would hide what the selection does.
	Context bool `json:"context,omitempty"`
}

// Edge is one protocol spoken between two nodes, oriented from the client to
// the server where the inventory knows which side served it.
type Edge struct {
	ID       string `json:"id"`
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Protocol string `json:"protocol"`
	// Class is the most consequential classification observed on the edge, so
	// that an edge carrying one write among a thousand reads is not drawn as
	// a read.
	Class      string           `json:"class"`
	Classes    map[string]int64 `json:"classes,omitempty"`
	Events     int64            `json:"events"`
	Malformed  int64            `json:"malformed"`
	ServerPort uint16           `json:"server_port,omitempty"`
	Transport  string           `json:"transport,omitempty"`
	// Directed says the orientation is evidence rather than the order the
	// addresses happened to appear in.
	Directed  bool      `json:"directed"`
	FirstSeen time.Time `json:"first_seen,omitzero"`
	LastSeen  time.Time `json:"last_seen,omitzero"`
	Href      string    `json:"href,omitempty"`
}

// SubnetGroup is one address group with the nodes in it, which is what the
// subnet layout draws its boxes from.
type SubnetGroup struct {
	CIDR     string   `json:"cidr"`
	Observed bool     `json:"observed"`
	Nodes    []string `json:"nodes"`
	Level    int      `json:"level"`
}

// LevelGroup is one Purdue level with the nodes placed in it, which is what
// the layered layout draws its rows from.
type LevelGroup struct {
	Level int      `json:"level"`
	Nodes []string `json:"nodes"`
}

// Graph is the topology of a project, ready to be drawn.
type Graph struct {
	Nodes   []Node        `json:"nodes"`
	Edges   []Edge        `json:"edges"`
	Subnets []SubnetGroup `json:"subnets,omitempty"`
	Levels  []LevelGroup  `json:"levels,omitempty"`
	// Truncated says the graph was capped and what was left out, so that a
	// view never silently shows part of a project as the whole of it.
	Truncated string `json:"truncated,omitempty"`
}

// DefaultMaxNodes and DefaultMaxEdges cap a graph. A browser draws a few
// thousand elements comfortably and tens of thousands not at all, and a
// picture nobody can read is worse than a filtered one that says it is
// filtered.
const (
	DefaultMaxNodes = 500
	DefaultMaxEdges = 2000
)

// Options bound a graph.
type Options struct {
	MaxNodes int
	MaxEdges int
}

// classOrder ranks the classifications by how much they say about an
// operation, so that an edge takes the most consequential one it carries.
var classOrder = []model.Classification{
	model.ClassProgram, model.ClassFirmware, model.ClassControl, model.ClassWrite,
	model.ClassRead, model.ClassDiagnostic, model.ClassDiscovery, model.ClassOther,
}

// Build turns an inventory and its flows into a graph.
//
// Assets are matched to flow endpoints by every address they were observed
// with, so an asset with several IPs is one node however many of its
// addresses the flows name. An endpoint no asset claims becomes a node of its
// own — a multicast group, or an address seen only in traffic the inventory
// dropped — because an edge has to end somewhere, and a graph that quietly
// drops an edge lies about who talks to whom.
func Build(assets []model.Asset, links []Link, opts Options) Graph {
	if opts.MaxNodes <= 0 {
		opts.MaxNodes = DefaultMaxNodes
	}
	if opts.MaxEdges <= 0 {
		opts.MaxEdges = DefaultMaxEdges
	}

	b := &builder{
		byAddress: make(map[string]*model.Asset, len(assets)*2),
		serves:    map[string]map[string]bool{},
		nodes:     map[string]*Node{},
		edges:     map[string]*Edge{},
	}
	for i := range assets {
		a := &assets[i]
		for _, addr := range a.IPs {
			b.byAddress[addr] = a
		}
		for _, addr := range a.MACs {
			b.byAddress[addr] = a
		}
		for _, p := range a.Protocols {
			if p.Side != "server" {
				continue
			}
			if b.serves[a.Key] == nil {
				b.serves[a.Key] = map[string]bool{}
			}
			b.serves[a.Key][p.Protocol] = true
		}
	}

	// Busiest links first, so a cap keeps the traffic that matters.
	ordered := append([]Link(nil), links...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Events > ordered[j].Events })

	dropped := 0
	for _, link := range ordered {
		if !b.add(link, opts) {
			dropped++
		}
	}
	// An asset that spoke to nobody in the filtered traffic is still part of
	// the inventory, so it is drawn alone rather than left out.
	for i := range assets {
		if len(b.nodes) >= opts.MaxNodes {
			break
		}
		b.ensureAsset(&assets[i])
	}

	g := b.graph()
	if dropped > 0 {
		g.Truncated = droppedNote(dropped)
	}
	return g
}

type builder struct {
	byAddress map[string]*model.Asset
	// serves[assetKey][protocol] records that an asset answered that
	// protocol, which is how the client and the server end of an edge are
	// told apart.
	serves    map[string]map[string]bool
	nodes     map[string]*Node
	order     []string
	edges     map[string]*Edge
	edgeOrder []string
}

// add folds one link into the graph, reporting whether it fitted.
func (b *builder) add(link Link, opts Options) bool {
	src, srcOK := b.endpoint(link.Src, opts)
	dst, dstOK := b.endpoint(link.Dst, opts)
	if !srcOK || !dstOK {
		return false
	}
	if src.ID == dst.ID {
		// Two addresses of one asset, or a device reaching itself through its
		// own gateway. There is no edge to draw.
		return true
	}

	// Orient the edge from the client to the server, so that an arrow means
	// "asks of" rather than "sent the first packet of this aggregate". The
	// inventory already decided which side served which protocol, from the
	// listening port of each event.
	from, to, srcAddr, dstAddr := src, dst, link.Src, link.Dst
	directed := false
	swap := func() {
		from, to = to, from
		srcAddr, dstAddr = dstAddr, srcAddr
	}
	switch {
	// A multicast group asks for nothing. A GOOSE publisher serves the
	// protocol and the group it publishes to does not, so the client-to-
	// server rule below would draw the publication backwards: a publication
	// always runs from the publisher to the group.
	case to.Kind == KindGroup && from.Kind != KindGroup:
		directed = true
	case from.Kind == KindGroup && to.Kind != KindGroup:
		swap()
		directed = true

	case b.servesProtocol(dst.ID, link.Protocol) && !b.servesProtocol(src.ID, link.Protocol):
		directed = true
	case b.servesProtocol(src.ID, link.Protocol) && !b.servesProtocol(dst.ID, link.Protocol):
		swap()
		directed = true
	}

	id := edgeID(from.ID, to.ID, link.Protocol)
	edge := b.edges[id]
	if edge == nil {
		if other := b.edges[edgeID(to.ID, from.ID, link.Protocol)]; other != nil {
			// The answering direction of a conversation already drawn.
			b.mergeEdge(other, link)
			return true
		}
		if len(b.edges) >= opts.MaxEdges {
			return false
		}
		edge = &Edge{
			ID:         id,
			Src:        from.ID,
			Dst:        to.ID,
			Protocol:   link.Protocol,
			ServerPort: link.ServerPort,
			Transport:  string(link.Transport),
			Directed:   directed,
			Classes:    map[string]int64{},
			Href:       eventsHref(srcAddr, dstAddr, link.Protocol),
		}
		b.edges[id] = edge
		b.edgeOrder = append(b.edgeOrder, id)
	}
	b.mergeEdge(edge, link)
	from.Events += link.Events
	return true
}

// edgeID names an edge by its ends and its protocol. The separator is a
// character that cannot appear in an asset key, an address or a protocol
// name, so two different edges cannot collide on one id.
func edgeID(src, dst, protocol string) string { return src + "|" + dst + "|" + protocol }

func (b *builder) servesProtocol(nodeID, protocol string) bool {
	return b.serves[nodeID][protocol]
}

func (b *builder) mergeEdge(edge *Edge, link Link) {
	edge.Events += link.Events
	edge.Malformed += link.Malformed
	for class, n := range link.Classes {
		edge.Classes[string(class)] += n
	}
	edge.Class = primaryClass(edge.Classes)
	if edge.ServerPort == 0 && link.ServerPort != 0 {
		edge.ServerPort = link.ServerPort
	}
	if !link.FirstSeen.IsZero() && (edge.FirstSeen.IsZero() || link.FirstSeen.Before(edge.FirstSeen)) {
		edge.FirstSeen = link.FirstSeen
	}
	if link.LastSeen.After(edge.LastSeen) {
		edge.LastSeen = link.LastSeen
	}
}

// endpoint returns the node for a flow endpoint, creating it if the cap
// allows.
func (b *builder) endpoint(addr string, opts Options) (*Node, bool) {
	if asset := b.byAddress[addr]; asset != nil {
		if n := b.nodes[asset.Key]; n != nil {
			return n, true
		}
		if len(b.nodes) >= opts.MaxNodes {
			return nil, false
		}
		return b.ensureAsset(asset), true
	}

	if n := b.nodes[addr]; n != nil {
		return n, true
	}
	if len(b.nodes) >= opts.MaxNodes {
		return nil, false
	}
	n := &Node{
		ID:        addr,
		Label:     addr,
		Kind:      kindOfAddress(addr),
		Level:     model.LevelUnknown,
		Addresses: []string{addr},
	}
	b.nodes[addr] = n
	b.order = append(b.order, addr)
	return n, true
}

// ensureAsset adds an asset's node, or returns the one already there.
func (b *builder) ensureAsset(a *model.Asset) *Node {
	if n := b.nodes[a.Key]; n != nil {
		return n
	}

	kind := KindDevice
	if a.IsGateway {
		kind = KindGateway
	}
	n := &Node{
		ID:        a.Key,
		Label:     a.Label,
		Kind:      kind,
		Role:      a.Role.Name,
		Vendor:    a.Vendor(),
		Level:     a.Level.Value,
		LevelNote: firstReason(a.Level.Reasons),
		VLANs:     a.VLANs,
		Addresses: append(append([]string{}, a.IPs...), a.MACs...),
		Protocols: protocolNames(a),
		Classes:   assetClasses(a),
		Href:      "/assets/" + url.PathEscape(a.Key),
	}
	if subnets := subnetsOf(*a); len(subnets) > 0 {
		n.Subnet = subnets[0].CIDR
	}
	b.nodes[a.Key] = n
	b.order = append(b.order, a.Key)
	return n
}

func (b *builder) graph() Graph {
	g := Graph{
		Nodes: make([]Node, 0, len(b.order)),
		Edges: make([]Edge, 0, len(b.edgeOrder)),
	}

	levels := map[int][]string{}
	subnets := map[string]*SubnetGroup{}
	observed := map[string]bool{}
	for _, id := range b.order {
		n := b.nodes[id]
		g.Nodes = append(g.Nodes, *n)
		levels[n.Level] = append(levels[n.Level], n.ID)
		if n.Subnet == "" {
			continue
		}
		group := subnets[n.Subnet]
		if group == nil {
			group = &SubnetGroup{CIDR: n.Subnet, Level: model.LevelUnknown}
			subnets[n.Subnet] = group
		}
		group.Nodes = append(group.Nodes, n.ID)
		if n.Level > group.Level {
			group.Level = n.Level
		}
		if asset := b.byAddress[firstOf(n.Addresses)]; asset != nil {
			for _, s := range subnetsOf(*asset) {
				if s.CIDR == n.Subnet && s.Observed {
					observed[n.Subnet] = true
				}
			}
		}
	}
	for _, id := range b.edgeOrder {
		g.Edges = append(g.Edges, *b.edges[id])
	}

	for level, nodes := range levels {
		g.Levels = append(g.Levels, LevelGroup{Level: level, Nodes: nodes})
	}
	sort.Slice(g.Levels, func(i, j int) bool { return g.Levels[i].Level < g.Levels[j].Level })

	for _, group := range subnets {
		group.Observed = observed[group.CIDR]
		g.Subnets = append(g.Subnets, *group)
	}
	sort.Slice(g.Subnets, func(i, j int) bool { return g.Subnets[i].CIDR < g.Subnets[j].CIDR })
	return g
}

// MarkContext marks every node outside the selection as context, which is
// how a filtered view shows what the selection talks to without pretending
// those neighbours matched the filter. An empty selection marks nothing.
func (g *Graph) MarkContext(selected map[string]bool) {
	if len(selected) == 0 {
		return
	}
	for i := range g.Nodes {
		g.Nodes[i].Context = !selected[g.Nodes[i].ID]
	}
}

// CrossLevel reports the edges that skip a level of the reference model,
// which is the shape of CLAUDE.md's rule on flows that bypass the DMZ. The
// rules package will decide what to do about them; the graph only has to be
// able to point at them.
func (g Graph) CrossLevel() []Edge {
	level := make(map[string]int, len(g.Nodes))
	for _, n := range g.Nodes {
		level[n.ID] = n.Level
	}

	var out []Edge
	for _, e := range g.Edges {
		src, dst := level[e.Src], level[e.Dst]
		if src == model.LevelUnknown || dst == model.LevelUnknown {
			continue
		}
		if diff := src - dst; diff > 1 || diff < -1 {
			out = append(out, e)
		}
	}
	return out
}

// primaryClass returns the most consequential classification on an edge.
func primaryClass(counts map[string]int64) string {
	for _, class := range classOrder {
		if counts[string(class)] > 0 {
			return string(class)
		}
	}
	return ""
}

func protocolNames(a *model.Asset) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range a.Protocols {
		if !seen[p.Protocol] {
			seen[p.Protocol] = true
			out = append(out, p.Protocol)
		}
	}
	return out
}

func assetClasses(a *model.Asset) map[string]int64 {
	out := map[string]int64{}
	for _, p := range a.Protocols {
		for class, n := range p.Classes {
			out[string(class)] += int64(n)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// kindOfAddress names an endpoint no asset claimed. A multicast or broadcast
// address is a subscription rather than a device.
func kindOfAddress(addr string) string {
	if isGroupAddress(addr) {
		return KindGroup
	}
	return KindUnknown
}

// isGroupAddress reports whether an address is multicast or broadcast: the
// low bit of the first octet of a MAC, or an IPv4 multicast or broadcast
// address.
func isGroupAddress(addr string) bool {
	if strings.Count(addr, ":") == 5 {
		first, err := strconv.ParseUint(addr[:2], 16, 8)
		return err == nil && first&0x01 != 0
	}
	if addr == "255.255.255.255" {
		return true
	}
	head, _, found := strings.Cut(addr, ".")
	if !found {
		return false
	}
	first, err := strconv.ParseUint(head, 10, 16)
	return err == nil && first >= 224 && first <= 239
}

func firstReason(reasons []string) string { return firstOf(reasons) }

func firstOf(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[0]
}

// eventsHref links an edge to the events behind it. The endpoints are the
// addresses the flow named, which is what the event table filters on.
func eventsHref(src, dst, protocol string) string {
	v := url.Values{"src": {src}, "dst": {dst}, "protocol": {protocol}}
	return "/events?" + v.Encode()
}

func droppedNote(n int) string {
	if n == 1 {
		return "1 link left out by the graph cap"
	}
	return strconv.Itoa(n) + " links left out by the graph cap"
}
