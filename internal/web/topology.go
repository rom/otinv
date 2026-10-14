package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/store"
	"github.com/rom/otinv/internal/topology"
	"github.com/rom/otinv/internal/web/templates"
)

// How much of a project one topology request reads.
//
// The graph is drawn from the inventory and the flow aggregate, and both are
// read per request so that a page reflects the project as it is. Both are
// capped: a browser cannot draw tens of thousands of elements, and a picture
// nobody can read is worse than a filtered one that says it is filtered.
const (
	// maxTopologyAssets bounds the address index. Every asset is read, not
	// only the filtered ones, because the other end of a filtered device's
	// conversation has to be drawn as the device it is rather than as a bare
	// address.
	maxTopologyAssets = 2000
	// maxTopologyFlows bounds how many conversations are considered, busiest
	// first.
	maxTopologyFlows = 4000
	// topologyAssetPage and topologyFlowPage are the store's page sizes.
	topologyAssetPage = 500
	topologyFlowPage  = 1000
)

// handleTopology renders the topology page.
func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	page := s.page(r, "topology")
	page.Title = templates.T(page.Lang, "topology.title")

	built, err := s.buildTopology(r.Context(), r.URL.Query())
	if err != nil {
		s.fail(w, r, "building the topology", err)
		return
	}

	levels, err := s.store.AssetLevels(r.Context(), s.project.ID)
	if err != nil {
		s.fail(w, r, "listing levels", err)
		return
	}
	protocols, err := s.store.AssetProtocols(r.Context(), s.project.ID)
	if err != nil {
		s.fail(w, r, "listing protocols", err)
		return
	}

	view := templates.TopologyView{
		Page:        page,
		Theme:       page.Theme,
		Filter:      built.filter,
		Nodes:       len(built.graph.Nodes),
		Edges:       len(built.graph.Edges),
		Truncated:   built.graph.Truncated,
		Protocols:   protocols,
		Classes:     classNames(),
		Levels:      levels,
		LevelRows:   levelRows(page.Lang, built),
		SubnetRows:  subnetRows(built.graph),
		CrossLevel:  crossLevelRows(page.Lang, built.graph),
		Picture:     templates.NewTopologySVG(page.Lang, built.graph),
		GraphHref:   "/topology.json?" + built.query.Encode(),
		PictureHref: "/topology.svg?" + built.query.Encode(),
		LevelLabels: templates.NewLevelLabels(page.Lang, levels),
	}
	s.render(w, r, templates.TopologyPage(view))
}

// handleTopologyJSON serves the graph the Cytoscape island draws.
func (s *Server) handleTopologyJSON(w http.ResponseWriter, r *http.Request) {
	built, err := s.buildTopology(r.Context(), r.URL.Query())
	if err != nil {
		s.fail(w, r, "building the topology", err)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// OT data must not linger in a cache, the same as every rendered page.
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	if err := enc.Encode(built.graph); err != nil {
		s.log.Error("writing the topology graph failed", "err", err)
	}
}

// handleTopologySVG serves the server-drawn picture as a standalone file,
// which is the SVG export. The extension that would export SVG from
// Cytoscape is GPLv3; this needs no extension and no script at all.
func (s *Server) handleTopologySVG(w http.ResponseWriter, r *http.Request) {
	page := s.page(r, "topology")
	built, err := s.buildTopology(r.Context(), r.URL.Query())
	if err != nil {
		s.fail(w, r, "building the topology", err)
		return
	}

	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	view := templates.TopologyView{
		Page:    page,
		Theme:   page.Theme,
		Filter:  built.filter,
		Picture: templates.NewTopologySVG(page.Lang, built.graph),
	}
	if err := templates.TopologyFile(view).Render(r.Context(), w); err != nil {
		s.log.Error("writing the topology picture failed", "err", err)
	}
}

// builtTopology is one request's graph with the filter that produced it.
type builtTopology struct {
	graph    topology.Graph
	filter   templates.TopologyFilter
	query    url.Values
	assets   []model.Asset
	selected map[string]bool
	labels   map[string]string
	levels   map[string]int
}

// buildTopology reads the inventory and the flows, filters them and builds the
// graph. The same path serves the page, the JSON and the SVG, so the three
// cannot disagree about what the project looks like.
func (s *Server) buildTopology(ctx context.Context, q url.Values) (builtTopology, error) {
	filter := templates.TopologyFilter{
		Protocol:  q.Get("protocol"),
		Class:     q.Get("class"),
		Level:     q.Get("level"),
		Search:    strings.TrimSpace(q.Get("q")),
		MinEvents: clampInt(q.Get("min"), 0, 0, 1<<30),
		Layout:    templates.ParseLayout(q.Get("layout")),
	}
	// A classification the model does not define is dropped rather than sent
	// to the store, the same as elsewhere in the GUI.
	if filter.Class != "" && !model.Classification(filter.Class).Valid() {
		filter.Class = ""
	}

	assets, truncatedAssets, err := s.topologyAssets(ctx)
	if err != nil {
		return builtTopology{}, err
	}
	links, truncatedLinks, err := s.topologyLinks(ctx, filter)
	if err != nil {
		return builtTopology{}, err
	}

	built := builtTopology{
		filter:   filter,
		query:    filter.Query(),
		assets:   assets,
		selected: selectAssets(assets, filter),
		labels:   map[string]string{},
		levels:   map[string]int{},
	}
	for _, a := range assets {
		built.labels[a.Key] = a.Label
		built.levels[a.Key] = a.Level.Value
	}

	if filter.Active() {
		// A filtered topology shows what the selection talks to: a link is
		// kept when either end is selected, and the far end is drawn as
		// context.
		kept := make([]topology.Link, 0, len(links))
		for _, link := range links {
			if built.isSelected(link.Src) || built.isSelected(link.Dst) {
				kept = append(kept, link)
			}
		}
		links = kept
	}

	built.graph = topology.Build(assets, links, topology.Options{})
	if filter.Active() {
		built.graph.MarkContext(built.selected)
		built.graph = keepConnected(built.graph, built.selected)
	}
	for _, note := range []string{truncatedAssets, truncatedLinks} {
		if note == "" {
			continue
		}
		if built.graph.Truncated != "" {
			built.graph.Truncated += "; "
		}
		built.graph.Truncated += note
	}
	return built, nil
}

// isSelected reports whether a flow endpoint belongs to a selected asset.
func (b builtTopology) isSelected(addr string) bool {
	for i := range b.assets {
		for _, ip := range b.assets[i].IPs {
			if ip == addr {
				return b.selected[b.assets[i].Key]
			}
		}
		for _, mac := range b.assets[i].MACs {
			if mac == addr {
				return b.selected[b.assets[i].Key]
			}
		}
	}
	return false
}

// topologyAssets reads the inventory, page by page, up to the cap.
func (s *Server) topologyAssets(ctx context.Context) ([]model.Asset, string, error) {
	var out []model.Asset
	for offset := 0; offset < maxTopologyAssets; offset += topologyAssetPage {
		page, total, err := s.store.Assets(ctx, store.AssetQuery{
			ProjectID: s.project.ID,
			Limit:     topologyAssetPage,
			Offset:    offset,
		})
		if err != nil {
			return nil, "", err
		}
		out = append(out, page...)
		if len(page) == 0 || len(out) >= total {
			return out, "", nil
		}
		if len(out) >= maxTopologyAssets {
			return out, strconv.Itoa(total-len(out)) + " assets beyond the first " +
				strconv.Itoa(maxTopologyAssets) + " were left out", nil
		}
	}
	return out, "", nil
}

// topologyLinks reads the flow aggregate, busiest first, up to the cap.
func (s *Server) topologyLinks(ctx context.Context, filter templates.TopologyFilter) (
	[]topology.Link, string, error,
) {
	var out []topology.Link
	for offset := 0; offset < maxTopologyFlows; offset += topologyFlowPage {
		page, total, err := s.store.Flows(ctx, store.FlowQuery{
			ProjectID: s.project.ID,
			Protocol:  filter.Protocol,
			Class:     filter.Class,
			Limit:     topologyFlowPage,
			Offset:    offset,
		})
		if err != nil {
			return nil, "", err
		}
		for _, f := range page {
			if filter.MinEvents > 0 && f.Events < int64(filter.MinEvents) {
				continue
			}
			out = append(out, topology.Link{
				Src:        f.Src,
				Dst:        f.Dst,
				Protocol:   f.Protocol,
				Transport:  f.Transport,
				ServerPort: f.ServerPort,
				Events:     f.Events,
				Malformed:  f.Malformed,
				Classes:    f.Classes,
				FirstSeen:  f.FirstSeen,
				LastSeen:   f.LastSeen,
			})
		}
		if len(page) == 0 || offset+len(page) >= total {
			return out, "", nil
		}
		if offset+len(page) >= maxTopologyFlows {
			return out, strconv.Itoa(total-maxTopologyFlows) + " quieter flows were left out", nil
		}
	}
	return out, "", nil
}

// selectAssets returns the assets the filter names. An inactive filter
// selects nothing, which the graph reads as "no context to dim".
func selectAssets(assets []model.Asset, filter templates.TopologyFilter) map[string]bool {
	if !filter.Active() {
		return nil
	}
	out := map[string]bool{}
	for i := range assets {
		if matchesAsset(&assets[i], filter) {
			out[assets[i].Key] = true
		}
	}
	return out
}

func matchesAsset(a *model.Asset, filter templates.TopologyFilter) bool {
	if filter.Level != "" {
		if filter.Level == templates.LevelUnplaced {
			if a.Level.Known() {
				return false
			}
		} else if strconv.Itoa(a.Level.Value) != filter.Level {
			return false
		}
	}
	if filter.Protocol != "" {
		spoken := false
		for _, p := range a.Protocols {
			if p.Protocol == filter.Protocol {
				spoken = true
				break
			}
		}
		if !spoken {
			return false
		}
	}
	if filter.Search != "" {
		needle := strings.ToLower(filter.Search)
		haystack := []string{strings.ToLower(a.Label), strings.ToLower(a.Vendor())}
		for _, addr := range append(append([]string{}, a.IPs...), a.MACs...) {
			haystack = append(haystack, strings.ToLower(addr))
		}
		found := false
		for _, candidate := range haystack {
			if candidate != "" && strings.Contains(candidate, needle) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// keepConnected drops the context nodes that ended up with no edge at all.
// A filtered graph should show the selection and what it talks to, not every
// device in the project drawn faintly in a corner.
func keepConnected(g topology.Graph, selected map[string]bool) topology.Graph {
	connected := make(map[string]bool, len(g.Edges)*2)
	for _, e := range g.Edges {
		connected[e.Src] = true
		connected[e.Dst] = true
	}

	out := g
	out.Nodes = make([]topology.Node, 0, len(g.Nodes))
	keep := make(map[string]bool, len(g.Nodes))
	for _, n := range g.Nodes {
		if selected[n.ID] || connected[n.ID] {
			out.Nodes = append(out.Nodes, n)
			keep[n.ID] = true
		}
	}

	out.Levels = nil
	for _, group := range g.Levels {
		kept := filterIDs(group.Nodes, keep)
		if len(kept) > 0 {
			group.Nodes = kept
			out.Levels = append(out.Levels, group)
		}
	}
	out.Subnets = nil
	for _, group := range g.Subnets {
		kept := filterIDs(group.Nodes, keep)
		if len(kept) > 0 {
			group.Nodes = kept
			out.Subnets = append(out.Subnets, group)
		}
	}
	return out
}

func filterIDs(ids []string, keep map[string]bool) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if keep[id] {
			out = append(out, id)
		}
	}
	return out
}

// levelRows summarises the inventory by level, which doubles as the legend of
// the layered layout.
func levelRows(lang templates.Lang, built builtTopology) []templates.LevelRow {
	counts := map[string]int{}
	for i := range built.assets {
		counts[templates.LevelValue(built.assets[i].Level.Value)]++
	}

	order := []string{"0", "1", "2", "3", "4", templates.LevelUnplaced}
	var out []templates.LevelRow
	for _, level := range order {
		if counts[level] == 0 {
			continue
		}
		q := built.query
		next := url.Values{}
		for k, v := range q {
			next[k] = v
		}
		next.Set("level", level)
		out = append(out, templates.LevelRow{
			Level:  level,
			Label:  templates.LevelLabel(lang, level),
			Count:  counts[level],
			Href:   "/topology?" + next.Encode(),
			Active: built.filter.Level == level,
		})
	}
	return out
}

// subnetRows lists the address groups the graph used, biggest first.
func subnetRows(g topology.Graph) []templates.SubnetRow {
	out := make([]templates.SubnetRow, 0, len(g.Subnets))
	for _, group := range g.Subnets {
		out = append(out, templates.SubnetRow{
			CIDR:     group.CIDR,
			Count:    len(group.Nodes),
			Observed: group.Observed,
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// crossLevelRows renders the flows that skip a level, with the labels of the
// devices at each end rather than their asset keys.
func crossLevelRows(lang templates.Lang, g topology.Graph) []templates.CrossLevelRow {
	label := make(map[string]string, len(g.Nodes))
	level := make(map[string]int, len(g.Nodes))
	for _, n := range g.Nodes {
		label[n.ID] = n.Label
		level[n.ID] = n.Level
	}

	var out []templates.CrossLevelRow
	for _, e := range g.CrossLevel() {
		out = append(out, templates.CrossLevelRow{
			Src:      label[e.Src],
			Dst:      label[e.Dst],
			Protocol: e.Protocol,
			Class:    e.Class,
			Levels: templates.LevelLabel(lang, templates.LevelValue(level[e.Src])) + " → " +
				templates.LevelLabel(lang, templates.LevelValue(level[e.Dst])),
			Events: e.Events,
			Href:   e.Href,
		})
	}
	return out
}

// classNames lists the classifications for a filter menu.
func classNames() []string {
	out := make([]string, 0, len(model.Classifications))
	for _, c := range model.Classifications {
		out = append(out, string(c))
	}
	return out
}
