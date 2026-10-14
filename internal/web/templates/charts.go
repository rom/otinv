package templates

import (
	"strconv"
	"strings"
	"time"

	"github.com/rom/otinv/internal/model"
)

// The chart view models.
//
// Every chart is drawn by the server: a bar is an SVG rectangle whose width
// is an attribute, a heatmap is a table of cells with an intensity class, and
// the colours come from the stylesheet. Nothing here needs a script, which is
// what lets the content security policy stay strict, lets a chart render with
// scripting switched off or in a printout, and lets the tests assert on what
// a page actually shows rather than on a blob of configuration handed to a
// charting library.
//
// The geometry is computed here rather than in the templates, because an
// arithmetic mistake in a template is invisible and one in a view model is a
// test.

// chartScale is the logical width every bar is drawn against. The SVG scales
// to the container, so the unit does not matter as long as it is the same for
// every bar in a chart.
const chartScale = 100.0

// maxChartBars caps how many bars one chart draws. A protocol mix has a
// handful; an operation histogram of a large project has hundreds, and the
// tail of a histogram is noise on a chart and belongs in a table.
const maxChartBars = 14

// Bar is one row of a bar chart.
type Bar struct {
	Label string
	Count int64
	// Class is the stylesheet modifier that colours the bar, which for a
	// classification chart is the classification itself.
	Class string
	// Href makes a bar a link to the view it stands for.
	Href string

	width float64 // percent of the largest bar
	share float64 // percent of the total
}

// Width is the bar's width as an SVG attribute: a percentage of the chart's
// logical width.
func (b Bar) Width() string { return formatFloat(b.width) }

// Share is the bar's share of the total, for the label. One decimal is as
// much as a share on a chart is worth.
func (b Bar) Share() string { return formatShare(b.share) }

// BarsView is a horizontal bar chart: the shape that reads best for counts
// with long labels, which protocol names and operation names are.
type BarsView struct {
	Title   string
	Caption string
	Bars    []Bar
	Total   int64
	More    int
}

// Empty reports whether there is nothing to draw.
func (v BarsView) Empty() bool { return len(v.Bars) == 0 }

// NewBars builds a bar chart from counted buckets, scaled to the largest.
func NewBars(title string, buckets []Bucket, class func(string) string, href func(string) string) BarsView {
	v := BarsView{Title: title}
	var maxCount int64
	for _, b := range buckets {
		v.Total += b.Count
		if b.Count > maxCount {
			maxCount = b.Count
		}
	}
	if maxCount == 0 {
		return v
	}
	for i, b := range buckets {
		if i >= maxChartBars {
			v.More = len(buckets) - maxChartBars
			break
		}
		bar := Bar{
			Label: dash(b.Label),
			Count: b.Count,
			width: float64(b.Count) / float64(maxCount) * chartScale,
			share: float64(b.Count) / float64(v.Total) * 100,
		}
		if class != nil {
			bar.Class = class(b.Label)
		}
		if href != nil {
			bar.Href = href(b.Label)
		}
		v.Bars = append(v.Bars, bar)
	}
	return v
}

// Bucket is a labelled count, which is what every chart is built from. It
// mirrors the store's own bucket so that the templates package does not
// depend on the store.
type Bucket struct {
	Label string
	Count int64
}

// Segment is one part of a proportion bar.
type Segment struct {
	Label string
	Class string
	Count int64
	Href  string

	offset float64
	width  float64
}

// Offset is the segment's left edge in percent.
func (s Segment) Offset() string { return formatFloat(s.offset) }

// Width is the segment's width in percent.
func (s Segment) Width() string { return formatFloat(s.width) }

// Share is the segment's share of the whole, for the legend.
func (s Segment) Share() string {
	if s.width == 0 {
		return "0"
	}
	return formatShare(s.width)
}

// ProportionView is a single bar divided into its parts: what fraction of the
// traffic was a read, a write, a control. It answers a different question
// from the bar chart — the mix rather than the magnitudes — which is why it
// is worth its own shape.
type ProportionView struct {
	Title    string
	Caption  string
	Segments []Segment
	Total    int64
}

// Empty reports whether there is nothing to draw.
func (v ProportionView) Empty() bool { return len(v.Segments) == 0 }

// NewProportion builds a proportion bar from counted buckets.
func NewProportion(title string, buckets []Bucket, class func(string) string,
	href func(string) string) ProportionView {

	v := ProportionView{Title: title}
	for _, b := range buckets {
		v.Total += b.Count
	}
	if v.Total == 0 {
		return v
	}
	var offset float64
	for _, b := range buckets {
		width := float64(b.Count) / float64(v.Total) * chartScale
		seg := Segment{
			Label:  dash(b.Label),
			Count:  b.Count,
			offset: offset,
			width:  width,
		}
		if class != nil {
			seg.Class = class(b.Label)
		}
		if href != nil {
			seg.Href = href(b.Label)
		}
		v.Segments = append(v.Segments, seg)
		offset += width
	}
	return v
}

// ColumnSegment is one classification's share of one interval of the
// timeline.
type ColumnSegment struct {
	Class string
	Count int64

	y      float64
	height float64
}

// Y is the segment's top edge in the chart's logical units.
func (s ColumnSegment) Y() string { return formatFloat(s.y) }

// Height is the segment's height in the chart's logical units.
func (s ColumnSegment) Height() string { return formatFloat(s.height) }

// Column is one interval of the timeline.
type Column struct {
	Count    int64
	Title    string
	Segments []ColumnSegment

	x     float64
	width float64
}

// X is the column's left edge in the chart's logical units.
func (c Column) X() string { return formatFloat(c.x) }

// Width is the column's width in the chart's logical units.
func (c Column) Width() string { return formatFloat(c.width) }

// TimelineView is the event count over time, each interval divided by
// classification so that a burst of writes is visible against a background of
// polling.
type TimelineView struct {
	Title   string
	Caption string
	Columns []Column
	Max     int64
	Total   int64
	Start   string
	Middle  string
	End     string
	// Height is the drawing height in the SVG's own units, which the chart
	// size setting chooses.
	Height int
}

// Empty reports whether there is nothing to draw.
func (v TimelineView) Empty() bool { return len(v.Columns) == 0 || v.Max == 0 }

// ViewBox is the SVG view box: the logical drawing area.
func (v TimelineView) ViewBox() string {
	return "0 0 " + strconv.Itoa(int(chartScale)) + " " + strconv.Itoa(v.Height)
}

// TimeBucket is one interval of the timeline, mirroring the store's own so
// that this package does not depend on it.
type TimeBucket struct {
	Start   time.Time
	End     time.Time
	Count   int64
	Classes map[model.Classification]int64
}

// NewTimeline builds the timeline chart. Intervals with no events are kept as
// gaps rather than dropped, because the gap is the information: a controller
// that goes quiet for ten minutes is what an analyst is looking for.
func NewTimeline(title string, buckets []TimeBucket, height int, format func(time.Time) string) TimelineView {
	v := TimelineView{Title: title, Height: height}
	if len(buckets) == 0 {
		return v
	}
	for _, b := range buckets {
		v.Total += b.Count
		if b.Count > v.Max {
			v.Max = b.Count
		}
	}
	if v.Max == 0 {
		return v
	}

	width := chartScale / float64(len(buckets))
	// A one pixel gap between columns at the usual widths, which keeps a
	// hundred columns readable without a border on each.
	gap := width * 0.15
	for i, b := range buckets {
		col := Column{
			Count: b.Count,
			x:     float64(i) * width,
			width: width - gap,
			Title: format(b.Start) + " · " + strconv.FormatInt(b.Count, 10),
		}
		// The segments are stacked in the classification order, so the same
		// class is always at the same end of every column.
		var top float64
		for _, c := range classDisplayOrder {
			n := b.Classes[c]
			if n == 0 {
				continue
			}
			h := float64(n) / float64(v.Max) * float64(height)
			col.Segments = append(col.Segments, ColumnSegment{
				Class:  string(c),
				Count:  n,
				y:      float64(height) - top - h,
				height: h,
			})
			top += h
		}
		v.Columns = append(v.Columns, col)
	}
	v.Start = format(buckets[0].Start)
	v.Middle = format(buckets[len(buckets)/2].Start)
	v.End = format(buckets[len(buckets)-1].End)
	return v
}

// classDisplayOrder is the order classifications are stacked and listed in:
// the most consequential at the top of a column and the first in a legend.
var classDisplayOrder = []model.Classification{
	model.ClassFirmware, model.ClassProgram, model.ClassControl, model.ClassWrite,
	model.ClassRead, model.ClassDiagnostic, model.ClassDiscovery, model.ClassOther,
}

// ClassDisplayOrder is the same order, for the views that build their own
// buckets.
func ClassDisplayOrder() []model.Classification { return classDisplayOrder }

// heatLevels is how many intensity steps a heatmap cell can have. Six is
// enough to read a matrix at a glance and few enough that each step is
// distinguishable in both themes.
const heatLevels = 5

// HeatCell is one square of the communication matrix.
type HeatCell struct {
	Count int64
	// Level is 0 for no traffic and 1 to heatLevels for increasing volume,
	// which the stylesheet turns into a shade.
	Level int
	Title string
	Href  string
}

// HeatRow is one source endpoint's row of the matrix.
type HeatRow struct {
	Label string
	Href  string
	Cells []HeatCell
	Total int64
}

// MatrixChartView is the communication matrix: who talks to whom, and how
// much. It is a table rather than a drawing, so a screen reader can read it
// and a browser can search it.
type MatrixChartView struct {
	Columns   []string
	Rows      []HeatRow
	Max       int64
	Truncated bool
}

// Empty reports whether there is nothing to draw.
func (v MatrixChartView) Empty() bool { return len(v.Rows) == 0 }

// NewMatrixChart builds the matrix from the cells the store returned.
func NewMatrixChart(endpoints []string, cells map[[2]string]int64, maxCount int64,
	truncated bool, title func(src, dst string, n int64) string,
	href func(src, dst string) string) MatrixChartView {

	v := MatrixChartView{Columns: endpoints, Max: maxCount, Truncated: truncated}
	for _, src := range endpoints {
		row := HeatRow{Label: src, Href: AssetURLByAddress(src)}
		for _, dst := range endpoints {
			n := cells[[2]string{src, dst}]
			row.Total += n
			cell := HeatCell{Count: n, Level: heatLevel(n, maxCount)}
			if n > 0 {
				if title != nil {
					cell.Title = title(src, dst, n)
				}
				if href != nil {
					cell.Href = href(src, dst)
				}
			}
			row.Cells = append(row.Cells, cell)
		}
		v.Rows = append(v.Rows, row)
	}
	return v
}

// heatLevel maps a count onto an intensity step.
//
// The steps are logarithmic, because traffic volumes are: a matrix scaled
// linearly against its busiest pair shows one dark square and a field of
// white, which says less than the pattern of who talks to whom at all.
func heatLevel(n, maxCount int64) int {
	switch {
	case n <= 0:
		return 0
	case maxCount <= 1:
		return heatLevels
	default:
		ratio := float64(n) / float64(maxCount)
		for level := heatLevels; level > 1; level-- {
			// Each step down is a factor of four: the top step is the busiest
			// quarter of the range, the next a sixteenth, and so on.
			if ratio > pow4(level-heatLevels-1) {
				return level
			}
		}
		return 1
	}
}

func pow4(exp int) float64 {
	v := 1.0
	for range -exp {
		v /= 4
	}
	return v
}

// formatFloat renders a geometry value with at most three decimals and no
// trailing zeroes, which keeps the rendered SVG stable across runs and
// readable in a diff.
// formatShare renders a percentage for a label, where one decimal is as much
// precision as a reader can use.
func formatShare(v float64) string {
	return strconv.FormatFloat(v, 'f', 1, 64)
}

func formatFloat(v float64) string {
	s := strconv.FormatFloat(v, 'f', 3, 64)
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}

// The class lists the templates use. They are built here so that a template
// carries no logic and so that a missing modifier is a compile error rather
// than a silently unstyled element.

// CSS is the bar's class list.
func (b Bar) CSS() string { return withModifier("bar", b.Class) }

// CSS is the segment's class list.
func (s Segment) CSS() string { return withModifier("seg", s.Class) }

// CSS is the column segment's class list.
func (s ColumnSegment) CSS() string { return withModifier("col", s.Class) }

// CSS is the heat cell's class list.
func (c HeatCell) CSS() string {
	return "heat heat-" + strconv.Itoa(c.Level)
}

// CSS is the stat tile's class list.
func (t StatTile) CSS() string { return withModifier("tile", t.Tone) }

func withModifier(base, modifier string) string {
	if modifier == "" {
		return base
	}
	return base + " " + base + "-" + modifier
}
