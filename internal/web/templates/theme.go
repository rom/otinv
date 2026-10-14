package templates

import (
	"strconv"

	"github.com/a-h/templ"
)

// The GUI's appearance and behaviour settings.
//
// Everything here is a stored choice with a default, resolved on the server
// and rendered into the page as data attributes on the root element. The
// stylesheet reads those attributes, so switching a theme or a density
// changes one attribute rather than reloading a different stylesheet, and a
// page is themed before the first paint — there is no script involved and
// nothing flashes.
//
// Settings are per project rather than per user, because the GUI has no
// accounts yet. The definitions live here, next to the form that renders them
// and the layout that applies them, so that a new setting is one entry rather
// than a change in three places.

// SettingKind is how a setting is presented.
type SettingKind string

// The kinds of setting the form knows how to render.
const (
	// KindChoice is a closed set of values, rendered as radio buttons so
	// that every option is visible rather than hidden in a menu.
	KindChoice SettingKind = "choice"
	// KindToggle is on or off.
	KindToggle SettingKind = "toggle"
	// KindNumber is a closed set of numbers, rendered as a menu.
	KindNumber SettingKind = "number"
)

// SettingOption is one value a setting may take.
type SettingOption struct {
	Value string
	Label string // an i18n key
}

// SettingDef describes one setting: where it is stored, what it is called,
// what it may be and what it is when nobody has said.
type SettingDef struct {
	Key     string
	Group   string // an i18n key naming the section of the form
	Label   string // an i18n key
	Help    string // an i18n key, or empty
	Kind    SettingKind
	Options []SettingOption
	Default string
}

// Allows reports whether a value is one this setting may take.
func (d SettingDef) Allows(value string) bool {
	if d.Kind == KindToggle {
		return value == "on" || value == "off"
	}
	for _, o := range d.Options {
		if o.Value == value {
			return true
		}
	}
	return false
}

// Setting keys. They appear in the settings table and in the form, so they
// are named here once.
const (
	SettingTheme      = "theme"
	SettingAccent     = "accent"
	SettingDensity    = "density"
	SettingFont       = "font"
	SettingContrast   = "contrast"
	SettingStripes    = "stripes"
	SettingMonospace  = "monospace"
	SettingCharts     = "charts"
	SettingChartSize  = "chart_size"
	SettingPageSize   = "page_size"
	SettingBuckets    = "timeline_buckets"
	SettingMatrixSize = "matrix_size"
	SettingTimeFormat = "time_format"
	SettingLang       = "lang"
	SettingNumbers    = "numbers"
)

// SettingDefs are every setting the GUI has, in the order the form shows them.
var SettingDefs = []SettingDef{
	{
		Key: SettingTheme, Group: "settings.group.appearance", Label: "settings.theme",
		Help: "settings.theme.help", Kind: KindChoice, Default: "auto",
		Options: []SettingOption{
			{Value: "auto", Label: "settings.theme.auto"},
			{Value: "light", Label: "settings.theme.light"},
			{Value: "dark", Label: "settings.theme.dark"},
		},
	},
	{
		Key: SettingAccent, Group: "settings.group.appearance", Label: "settings.accent",
		Help: "settings.accent.help", Kind: KindChoice, Default: "blue",
		Options: []SettingOption{
			{Value: "blue", Label: "settings.accent.blue"},
			{Value: "teal", Label: "settings.accent.teal"},
			{Value: "violet", Label: "settings.accent.violet"},
			{Value: "amber", Label: "settings.accent.amber"},
			{Value: "crimson", Label: "settings.accent.crimson"},
			{Value: "slate", Label: "settings.accent.slate"},
		},
	},
	{
		Key: SettingContrast, Group: "settings.group.appearance", Label: "settings.contrast",
		Help: "settings.contrast.help", Kind: KindChoice, Default: "normal",
		Options: []SettingOption{
			{Value: "normal", Label: "settings.contrast.normal"},
			{Value: "high", Label: "settings.contrast.high"},
		},
	},
	{
		Key: SettingDensity, Group: "settings.group.layout", Label: "settings.density",
		Help: "settings.density.help", Kind: KindChoice, Default: "regular",
		Options: []SettingOption{
			{Value: "compact", Label: "settings.density.compact"},
			{Value: "regular", Label: "settings.density.regular"},
			{Value: "roomy", Label: "settings.density.roomy"},
		},
	},
	{
		Key: SettingFont, Group: "settings.group.layout", Label: "settings.font",
		Help: "settings.font.help", Kind: KindChoice, Default: "regular",
		Options: []SettingOption{
			{Value: "small", Label: "settings.font.small"},
			{Value: "regular", Label: "settings.font.regular"},
			{Value: "large", Label: "settings.font.large"},
		},
	},
	{
		Key: SettingStripes, Group: "settings.group.layout", Label: "settings.stripes",
		Help: "settings.stripes.help", Kind: KindToggle, Default: "on",
	},
	{
		Key: SettingMonospace, Group: "settings.group.layout", Label: "settings.monospace",
		Help: "settings.monospace.help", Kind: KindToggle, Default: "on",
	},
	{
		Key: SettingCharts, Group: "settings.group.charts", Label: "settings.charts",
		Help: "settings.charts.help", Kind: KindToggle, Default: "on",
	},
	{
		Key: SettingChartSize, Group: "settings.group.charts", Label: "settings.chart_size",
		Help: "settings.chart_size.help", Kind: KindChoice, Default: "regular",
		Options: []SettingOption{
			{Value: "short", Label: "settings.chart_size.short"},
			{Value: "regular", Label: "settings.chart_size.regular"},
			{Value: "tall", Label: "settings.chart_size.tall"},
		},
	},
	{
		Key: SettingBuckets, Group: "settings.group.charts", Label: "settings.buckets",
		Help: "settings.buckets.help", Kind: KindNumber, Default: "60",
		Options: []SettingOption{
			{Value: "30", Label: "30"},
			{Value: "60", Label: "60"},
			{Value: "120", Label: "120"},
			{Value: "240", Label: "240"},
		},
	},
	{
		Key: SettingMatrixSize, Group: "settings.group.charts", Label: "settings.matrix_size",
		Help: "settings.matrix_size.help", Kind: KindNumber, Default: "30",
		Options: []SettingOption{
			{Value: "10", Label: "10"},
			{Value: "20", Label: "20"},
			{Value: "30", Label: "30"},
			{Value: "45", Label: "45"},
		},
	},
	{
		Key: SettingPageSize, Group: "settings.group.tables", Label: "settings.page_size",
		Help: "settings.page_size.help", Kind: KindNumber, Default: "50",
		Options: []SettingOption{
			{Value: "25", Label: "25"},
			{Value: "50", Label: "50"},
			{Value: "100", Label: "100"},
			{Value: "200", Label: "200"},
		},
	},
	{
		Key: SettingNumbers, Group: "settings.group.tables", Label: "settings.numbers",
		Help: "settings.numbers.help", Kind: KindChoice, Default: "grouped",
		Options: []SettingOption{
			{Value: "grouped", Label: "settings.numbers.grouped"},
			{Value: "plain", Label: "settings.numbers.plain"},
		},
	},
	{
		Key: SettingTimeFormat, Group: "settings.group.tables", Label: "settings.time_format",
		Help: "settings.time_format.help", Kind: KindChoice, Default: "iso",
		Options: []SettingOption{
			{Value: "iso", Label: "settings.time_format.iso"},
			{Value: "short", Label: "settings.time_format.short"},
			{Value: "precise", Label: "settings.time_format.precise"},
		},
	},
	{
		Key: SettingLang, Group: "settings.group.tables", Label: "settings.lang",
		Help: "settings.lang.help", Kind: KindChoice, Default: string(LangEN),
		Options: []SettingOption{
			{Value: string(LangEN), Label: "settings.lang.en"},
			{Value: string(LangSV), Label: "settings.lang.sv"},
		},
	},
}

// Theme is the resolved appearance and behaviour of the GUI, carried on every
// page view.
type Theme struct {
	values map[string]string
}

// NewTheme resolves stored settings against the defaults. A stored value the
// definitions do not allow is dropped rather than refused, so a hand-edited
// or outdated database still renders a usable page.
func NewTheme(stored map[string]string) Theme {
	values := make(map[string]string, len(SettingDefs))
	for _, def := range SettingDefs {
		value := def.Default
		if v, ok := stored[def.Key]; ok && def.Allows(v) {
			value = v
		}
		values[def.Key] = value
	}
	return Theme{values: values}
}

// Value is the resolved value of one setting.
func (t Theme) Value(key string) string {
	if t.values == nil {
		return defaultOf(key)
	}
	if v, ok := t.values[key]; ok {
		return v
	}
	return defaultOf(key)
}

// On reports whether a toggle is on.
func (t Theme) On(key string) bool { return t.Value(key) == "on" }

// Number is a numeric setting's value.
func (t Theme) Number(key string) int {
	n, err := strconv.Atoi(t.Value(key))
	if err != nil {
		n, _ = strconv.Atoi(defaultOf(key))
	}
	return n
}

// Lang is the UI language the settings ask for.
func (t Theme) Lang() Lang { return Lang(t.Value(SettingLang)) }

// PageSize is how many rows a paged table shows.
func (t Theme) PageSize() int { return t.Number(SettingPageSize) }

// Charts reports whether the views draw their charts. Turning them off leaves
// every number in its table, which is also what a reader using a screen
// reader or printing a page gets.
func (t Theme) Charts() bool { return t.On(SettingCharts) }

// ChartHeight is the drawing height of a chart in pixels, from the chart size
// setting. The width is the container's, so only the height is a choice.
func (t Theme) ChartHeight() int {
	switch t.Value(SettingChartSize) {
	case "short":
		return 120
	case "tall":
		return 280
	default:
		return 180
	}
}

// RootAttrs are the data attributes the stylesheet reads, in a stable order.
func (t Theme) RootAttrs() []Attr {
	return []Attr{
		{Name: "data-theme", Value: t.Value(SettingTheme)},
		{Name: "data-accent", Value: t.Value(SettingAccent)},
		{Name: "data-density", Value: t.Value(SettingDensity)},
		{Name: "data-font", Value: t.Value(SettingFont)},
		{Name: "data-contrast", Value: t.Value(SettingContrast)},
		{Name: "data-stripes", Value: t.Value(SettingStripes)},
		{Name: "data-mono", Value: t.Value(SettingMonospace)},
	}
}

// Attr is one rendered attribute.
type Attr struct {
	Name  string
	Value string
}

// HTMLAttrs are the theme's data attributes, for the root element. The
// stylesheet selects on them, so a change of theme is a change of one
// attribute and the page is themed before the first paint.
func (t Theme) HTMLAttrs() templ.Attributes {
	attrs := templ.Attributes{}
	for _, a := range t.RootAttrs() {
		attrs[a.Name] = a.Value
	}
	return attrs
}

func defaultOf(key string) string {
	for _, def := range SettingDefs {
		if def.Key == key {
			return def.Default
		}
	}
	return ""
}
