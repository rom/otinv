package templates

import (
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/topology"
)

// The topology view: a filter panel, a legend, and the graph itself.
//
// The graph is drawn twice, from the same data. Cytoscape draws the
// interactive one in the browser, which is what CLAUDE.md asks for and what
// an analyst needs to drag a node out of a hairball. The server draws a
// static SVG of the same graph in Purdue rows, which is the no-script
// fallback and the SVG export — the extension that would export SVG from
// Cytoscape is GPLv3, and the picture is more useful as a file the server can
// hand over anyway.

// The layouts the interactive graph offers.
const (
	LayoutPurdue = "purdue"
	LayoutSubnet = "subnet"
	LayoutForce  = "force"
)

// Layouts lists them in the order the page offers them.
var Layouts = []string{LayoutPurdue, LayoutSubnet, LayoutForce}

// ParseLayout reads a layout name from a URL, falling back to the layered
// one: a link with a stale layout still draws a graph.
func ParseLayout(raw string) string {
	for _, l := range Layouts {
		if raw == l {
			return l
		}
	}
	return LayoutPurdue
}

// LevelUnplaced is how the filter and the level groups name the assets no
// level was inferred for. It mirrors the store's spelling.
const LevelUnplaced = "unknown"

// TopologyFilter is the filter state, which is also the URL: every view in
// this GUI is deep-linkable, and a topology nobody can link to is a topology
// nobody can discuss.
type TopologyFilter struct {
	Protocol  string
	Class     string
	Level     string
	Search    string
	MinEvents int
	Layout    string
}

// Query renders the filter as URL values, without the layout, which only the
// client cares about.
func (f TopologyFilter) Query() url.Values {
	v := url.Values{}
	if f.Protocol != "" {
		v.Set("protocol", f.Protocol)
	}
	if f.Class != "" {
		v.Set("class", f.Class)
	}
	if f.Level != "" {
		v.Set("level", f.Level)
	}
	if f.Search != "" {
		v.Set("q", f.Search)
	}
	if f.MinEvents > 0 {
		v.Set("min", strconv.Itoa(f.MinEvents))
	}
	return v
}

// Active reports whether anything is filtered, which decides whether the
// legend explains what a dimmed node is.
func (f TopologyFilter) Active() bool {
	return f.Protocol != "" || f.Class != "" || f.Level != "" || f.Search != "" || f.MinEvents > 0
}

// MinEventsValue renders the threshold for the form, where zero is empty
// rather than "0".
func (f TopologyFilter) MinEventsValue() string {
	if f.MinEvents <= 0 {
		return ""
	}
	return strconv.Itoa(f.MinEvents)
}

// TopologyView is the topology page.
type TopologyView struct {
	Page   PageView
	Filter TopologyFilter
	Theme  Theme

	// Nodes and Edges are what the graph holds after filtering, which the
	// page states: a picture that was capped has to say so.
	Nodes      int
	Edges      int
	Truncated  string
	CrossLevel []CrossLevelRow

	// LevelRows is the inventory by level, which doubles as the legend of the
	// layered layout, and SubnetRows says how each address group was decided.
	LevelRows  []LevelRow
	SubnetRows []SubnetRow
	// Protocols, Classes and Levels fill the filter menus.
	Protocols []string
	Classes   []string
	Levels    []string

	// Picture is the server-drawn graph: the fallback and the export.
	Picture TopologySVG

	// GraphHref and PictureHref are where the island fetches the graph and
	// where the export link points.
	GraphHref   string
	PictureHref string

	// LevelLabels is the level names as JSON, so that the island can label
	// the layered layout's bands in the reader's language without an inline
	// script carrying them.
	LevelLabels string
}

// NewLevelLabels renders the level names the island needs as a JSON object.
func NewLevelLabels(lang Lang, levels []string) string {
	out := make(map[string]string, len(levels)+1)
	for _, level := range levels {
		out[level] = LevelLabel(lang, level)
	}
	out[LevelUnplaced] = LevelLabel(lang, LevelUnplaced)
	encoded, err := json.Marshal(out)
	if err != nil {
		// The map holds nothing but strings, so this cannot fail; an empty
		// object leaves the island labelling bands by their number.
		return "{}"
	}
	return string(encoded)
}

// SubnetRow is one address group the graph placed devices in, with how the
// prefix was decided: a netmask a device reported, or the assumption otinv
// has to make when nothing did.
type SubnetRow struct {
	CIDR     string
	Count    int
	Observed bool
}

// LevelRow is one Purdue level with how many assets are in it.
type LevelRow struct {
	Level  string
	Label  string
	Count  int
	Href   string
	Active bool
}

// CrossLevelRow is one flow that skips a level of the reference model.
type CrossLevelRow struct {
	Src      string
	Dst      string
	Protocol string
	Class    string
	Levels   string
	Events   int64
	Href     string
}

// LevelLabel renders a level for a reader. The number alone is meaningless to
// anyone who does not have the reference model in their head.
func LevelLabel(lang Lang, level string) string {
	if level == LevelUnplaced || level == "" {
		return T(lang, "level.unknown")
	}
	if key := "level." + level; catalogue[key] != nil {
		return T(lang, key)
	}
	return T(lang, "level.other") + " " + level
}

// LevelValue renders a level number as a filter value, with the unplaced
// assets spelled the way the store spells them.
func LevelValue(level int) string {
	if level < 0 {
		return LevelUnplaced
	}
	return strconv.Itoa(level)
}

// LevelHref links a level to the topology filtered by it, which is where a
// level means something: the band it puts a device in.
func LevelHref(level model.Level) string {
	return "/topology?level=" + url.QueryEscape(LevelValue(level.Value))
}

// TopologySVG is the server-drawn picture of a graph, laid out in Purdue
// rows: every level is a band, and an edge that crosses several bands is
// visibly a flow that crosses levels.
type TopologySVG struct {
	Width  int
	Height int
	Rows   []SVGRow
	Nodes  []SVGNode
	Edges  []SVGEdge
	// TooLarge says the graph has more nodes than a static picture can show
	// legibly, so the page offers the interactive one instead of a smear.
	TooLarge bool
	Count    int
}

// SVGRow is one level band.
type SVGRow struct {
	Label string
	Y     int
	Count int
}

// SVGNode is one device in the picture.
type SVGNode struct {
	X, Y  int
	Label string
	Title string
	Kind  string
	Level string
}

// SVGEdge is one conversation in the picture.
type SVGEdge struct {
	X1, Y1, X2, Y2 int
	Class          string
	Title          string
	Directed       bool
}

// Geometry of the static picture. The numbers are in user units and the SVG
// scales to the page; they only set the proportions.
const (
	svgRowHeight  = 110
	svgTopPadding = 46
	svgSidePad    = 120
	svgMinWidth   = 960
	svgNodeRadius = 9
	// svgPerRow wraps a crowded level over several lines. A plant with
	// thirty controllers on one level would otherwise be drawn as one band
	// four thousand units wide, which no page can show legibly.
	svgPerRow     = 12
	svgSubRowStep = 64
	// svgMaxNodes is where a static picture stops being readable. Beyond it
	// the page says so rather than drawing a smear.
	svgMaxNodes = 150
	// svgLabelLen is how much of a label fits under a node.
	svgLabelLen = 18
)

// NewTopologySVG lays a graph out in level rows.
//
// The layout is deterministic — level, then subnet, then label — so the same
// project draws the same picture every time, which is what makes the SVG
// export worth keeping next to a report.
func NewTopologySVG(lang Lang, g topology.Graph) TopologySVG {
	out := TopologySVG{Count: len(g.Nodes)}
	if len(g.Nodes) == 0 {
		return out
	}
	if len(g.Nodes) > svgMaxNodes {
		out.TooLarge = true
		return out
	}

	byLevel := map[int][]topology.Node{}
	for _, n := range g.Nodes {
		byLevel[n.Level] = append(byLevel[n.Level], n)
	}
	levels := make([]int, 0, len(byLevel))
	for level := range byLevel {
		levels = append(levels, level)
	}
	// The unplaced band sits below the levels rather than above level 0.
	sort.Slice(levels, func(i, j int) bool {
		a, b := levels[i], levels[j]
		if a < 0 || b < 0 {
			return b < 0 && a >= 0
		}
		return a < b
	})

	widest := 0
	for _, nodes := range byLevel {
		if n := min(len(nodes), svgPerRow); n > widest {
			widest = n
		}
	}
	out.Width = max(svgMinWidth, widest*150)

	positions := make(map[string]SVGNode, len(g.Nodes))
	y := svgTopPadding
	for _, level := range levels {
		nodes := byLevel[level]
		sort.Slice(nodes, func(a, b int) bool {
			if nodes[a].Subnet != nodes[b].Subnet {
				return nodes[a].Subnet < nodes[b].Subnet
			}
			return nodes[a].Label < nodes[b].Label
		})
		out.Rows = append(out.Rows, SVGRow{
			Label: LevelLabel(lang, LevelValue(level)),
			Y:     y,
			Count: len(nodes),
		})

		// A crowded level wraps over several lines inside its own band, so
		// the picture keeps a readable shape whatever the plant looks like.
		subRows := (len(nodes) + svgPerRow - 1) / svgPerRow
		perRow := (len(nodes) + subRows - 1) / subRows
		for j, n := range nodes {
			column := j % perRow
			node := SVGNode{
				X:     svgSidePad + (out.Width-2*svgSidePad)*(column+1)/(perRow+1),
				Y:     y + (j/perRow)*svgSubRowStep,
				Label: Ellipsis(n.Label, svgLabelLen),
				Title: svgNodeTitle(lang, n),
				Kind:  n.Kind,
				Level: LevelValue(n.Level),
			}
			positions[n.ID] = node
			out.Nodes = append(out.Nodes, node)
		}
		y += max(svgRowHeight, subRows*svgSubRowStep+46)
	}
	out.Height = y

	for _, e := range g.Edges {
		src, okSrc := positions[e.Src]
		dst, okDst := positions[e.Dst]
		if !okSrc || !okDst {
			continue
		}
		out.Edges = append(out.Edges, SVGEdge{
			X1: src.X, Y1: src.Y, X2: dst.X, Y2: dst.Y,
			Class:    e.Class,
			Directed: e.Directed,
			Title: e.Protocol + " · " + strconv.FormatInt(e.Events, 10) + " " +
				T(lang, "topology.events"),
		})
	}
	return out
}

func svgNodeTitle(lang Lang, n topology.Node) string {
	parts := []string{n.Label}
	if n.Vendor != "" {
		parts = append(parts, n.Vendor)
	}
	if n.Role != "" {
		parts = append(parts, RoleLabel(lang, n.Role))
	}
	if len(n.Protocols) > 0 {
		parts = append(parts, strings.Join(n.Protocols, ", "))
	}
	return strings.Join(parts, " · ")
}

// Dimensions renders the viewBox of the picture.
func (p TopologySVG) Dimensions() string {
	return "0 0 " + strconv.Itoa(p.Width) + " " + strconv.Itoa(p.Height)
}

// HeightPx renders the drawn height for the style attribute-free sizing in
// the stylesheet.
func (p TopologySVG) HeightPx() string { return strconv.Itoa(p.Height) }

// WidthPx renders the drawn width.
func (p TopologySVG) WidthPx() string { return strconv.Itoa(p.Width) }

// CSS renders the class of one node.
func (n SVGNode) CSS() string { return "topo-node kind-" + n.Kind + " level-" + n.Level }

// LabelY is where a node's label sits.
func (n SVGNode) LabelY() string { return strconv.Itoa(n.Y + svgNodeRadius + 12) }

// Radius is the node radius.
func (n SVGNode) Radius() string { return strconv.Itoa(svgNodeRadius) }

// CX renders the node centre's x coordinate.
func (n SVGNode) CX() string { return strconv.Itoa(n.X) }

// CY renders the node centre's y coordinate.
func (n SVGNode) CY() string { return strconv.Itoa(n.Y) }

// CSS renders the class of one edge.
func (e SVGEdge) CSS() string {
	css := "topo-edge class-" + e.Class
	if !e.Directed {
		css += " undirected"
	}
	return css
}

// SX renders the edge's first x coordinate. The geometry travels as
// attributes rather than as a style, so the stylesheet keeps the colours and
// the markup keeps the shape.
func (e SVGEdge) SX() string { return strconv.Itoa(e.X1) }

// SY renders the edge's first y coordinate.
func (e SVGEdge) SY() string { return strconv.Itoa(e.Y1) }

// EX renders the edge's second x coordinate.
func (e SVGEdge) EX() string { return strconv.Itoa(e.X2) }

// EY renders the edge's second y coordinate.
func (e SVGEdge) EY() string { return strconv.Itoa(e.Y2) }

// RowY renders a band's y coordinate.
func (r SVGRow) RowY() string { return strconv.Itoa(r.Y) }

// LabelY renders where a band's label sits.
func (r SVGRow) LabelY() string { return strconv.Itoa(r.Y - 24) }

// Ellipsis shortens a label for a place that has no room for all of it. The
// full value belongs in a title or a table, never truncated silently.
func Ellipsis(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	if limit <= 1 {
		return "…"
	}
	return string(runes[:limit-1]) + "…"
}
