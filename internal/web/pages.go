package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/store"
	"github.com/rom/otinv/internal/web/templates"
)

// The views beyond the asset list: the dashboard, the flow table, the
// communication matrix, the event table, the protocol statistics and the
// settings form.
//
// Each handler reads the filter state out of the URL, asks the store for the
// rows and the aggregates, and hands a view model to a template. The
// aggregation is SQL rather than Go: a project of a million events has to
// answer a page in well under the 300 ms CLAUDE.md asks for, and that is only
// possible if SQLite does the counting.

const (
	// dashboardRecentEvents is how many of the latest events the dashboard
	// lists under its charts.
	dashboardRecentEvents = 10

	// maxChartBuckets caps the operation and exception charts, which have a
	// long tail that is noise on a chart.
	maxChartBuckets = 14
)

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	page := s.page(r, "dashboard")
	page.Title = templates.T(page.Lang, "dashboard.title")
	theme := page.Theme
	lang := page.Lang

	summary, err := s.store.Summary(ctx, s.project.ID)
	if err != nil {
		s.fail(w, r, "summarising the project", err)
		return
	}

	view := templates.DashboardView{Page: page, Theme: theme}
	view.Tiles = dashboardTiles(lang, theme, summary)

	byProtocol, err := s.store.CountEventsBy(ctx, s.project.ID, "protocol", "", 0)
	if err != nil {
		s.fail(w, r, "counting events by protocol", err)
		return
	}
	byClass, err := s.store.CountEventsBy(ctx, s.project.ID, "class", "", 0)
	if err != nil {
		s.fail(w, r, "counting events by class", err)
		return
	}
	byOperation, err := s.store.CountEventsBy(ctx, s.project.ID, "operation", "", maxChartBuckets)
	if err != nil {
		s.fail(w, r, "counting events by operation", err)
		return
	}
	byException, err := s.store.CountEventsBy(ctx, s.project.ID, "exception", "", maxChartBuckets)
	if err != nil {
		s.fail(w, r, "counting events by exception", err)
		return
	}
	byRole, err := s.store.CountAssetsBy(ctx, s.project.ID, "role")
	if err != nil {
		s.fail(w, r, "counting assets by role", err)
		return
	}
	byVendor, err := s.store.CountAssetsBy(ctx, s.project.ID, "vendor")
	if err != nil {
		s.fail(w, r, "counting assets by vendor", err)
		return
	}

	view.Protocols = templates.NewBars(templates.T(lang, "chart.protocols"),
		buckets(byProtocol), nil, func(label string) string {
			return "/events?protocol=" + url.QueryEscape(label)
		})
	view.Classes = templates.NewProportion(templates.T(lang, "chart.classes"),
		classBuckets(byClass), templates.ClassOf, func(label string) string {
			return "/events?class=" + url.QueryEscape(classKey(lang, label))
		})
	view.Classes.Caption = templates.Count(theme, summary.Events) + " " +
		templates.T(lang, "chart.of_total")
	// The buckets are keyed by the classification so that the links filter on
	// it; the legend shows the name in the UI language.
	for i := range view.Classes.Segments {
		view.Classes.Segments[i].Label =
			templates.ClassLabel(lang, view.Classes.Segments[i].Label)
	}
	view.Roles = templates.NewBars(templates.T(lang, "chart.roles"),
		roleBuckets(lang, byRole), nil, func(label string) string {
			return "/assets?role=" + url.QueryEscape(roleKey(lang, label))
		})
	view.Vendors = templates.NewBars(templates.T(lang, "chart.vendors"),
		buckets(byVendor), nil, func(label string) string {
			if label == "" {
				return ""
			}
			return "/assets?q=" + url.QueryEscape(label)
		})
	view.Operations = templates.NewBars(templates.T(lang, "chart.operations"),
		buckets(byOperation), nil, func(label string) string {
			return "/events?operation=" + url.QueryEscape(label)
		})
	view.Exceptions = templates.NewBars(templates.T(lang, "chart.exceptions"),
		buckets(byException), func(string) string { return "warn" },
		func(label string) string { return "/events?q=" + url.QueryEscape(label) })

	timeline, err := s.store.Timeline(ctx, s.project.ID, theme.Number(templates.SettingBuckets), "")
	if err != nil {
		s.fail(w, r, "building the timeline", err)
		return
	}
	view.Timeline = templates.NewTimeline(templates.T(lang, "chart.timeline"),
		timeBuckets(timeline), theme.ChartHeight(),
		func(t time.Time) string { return templates.FormatTimeIn(theme, t) })

	recent, err := s.store.Events(ctx, store.EventQuery{
		ProjectID: s.project.ID,
		Limit:     dashboardRecentEvents,
	})
	if err != nil {
		s.fail(w, r, "reading the latest events", err)
		return
	}
	for _, e := range recent {
		peer := e.Flow.DstIP
		if peer == "" {
			peer = e.Flow.DstMAC
		}
		view.Recent = append(view.Recent, templates.EventRow{
			Time:      e.Timestamp,
			Operation: e.Operation,
			Detail:    eventDetail(e),
			Class:     string(e.Class),
			Direction: string(e.Direction),
			Peer:      peer,
			Packet:    e.PacketIndex,
			Exception: e.Exception,
			Malformed: e.Malformed,
		})
	}

	s.render(w, r, templates.DashboardPage(view))
}

// dashboardTiles are the numbers worth knowing before any filtering. Each one
// links to the view that explains it, so a count of malformed frames is one
// click from the frames themselves.
func dashboardTiles(lang templates.Lang, theme templates.Theme, sum store.Summary) []templates.StatTile {
	tone := func(n int64) string {
		if n > 0 {
			return "warn"
		}
		return "good"
	}
	note := func(n int64, key string) string {
		if n == 0 {
			return templates.T(lang, "tile.none")
		}
		return templates.Count(theme, n) + " " + templates.T(lang, key)
	}
	return []templates.StatTile{
		{
			Label: templates.T(lang, "tile.assets"),
			Value: templates.Count(theme, sum.Assets),
			Note:  note(sum.Controllers, "tile.controllers"),
			Href:  "/assets",
		},
		{
			Label: templates.T(lang, "tile.events"),
			Value: templates.Count(theme, sum.Events),
			Note:  templates.Count(theme, sum.Flows) + " " + templates.T(lang, "tile.flows"),
			Href:  "/events",
		},
		{
			Label: templates.T(lang, "tile.protocols"),
			Value: templates.Count(theme, sum.Protocols),
			Href:  "/protocols",
		},
		{
			Label: templates.T(lang, "tile.captures"),
			Value: templates.Count(theme, sum.Captures),
			Note:  templates.Count(theme, sum.Packets) + " " + templates.T(lang, "tile.packets"),
			Href:  "/captures",
		},
		{
			Label: templates.T(lang, "tile.malformed"),
			Value: templates.Count(theme, sum.Malformed),
			Note:  templates.Percent(sum.Malformed, sum.Events),
			Href:  "/events?malformed=1",
			Tone:  tone(sum.Malformed),
		},
		{
			Label: templates.T(lang, "tile.anomalies"),
			Value: templates.Count(theme, sum.Anomalies),
			Note:  templates.Percent(sum.Anomalies, sum.Events),
			Href:  "/events?anomalous=1",
			Tone:  tone(sum.Anomalies),
		},
		{
			Label: templates.T(lang, "tile.exceptions"),
			Value: templates.Count(theme, sum.Exceptions),
			Note:  templates.Percent(sum.Exceptions, sum.Events),
			Href:  "/events",
			Tone:  tone(sum.Exceptions),
		},
		{
			Label: templates.T(lang, "tile.span"),
			Value: templates.Duration(sum.FirstSeen, sum.LastSeen),
			Note:  templates.FormatTimeIn(theme, sum.FirstSeen),
		},
	}
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	page := s.page(r, "flows")
	page.Title = templates.T(page.Lang, "flows.title")
	theme := page.Theme

	filter := templates.FlowsFilter{
		Protocol: q.Get("protocol"),
		Class:    q.Get("class"),
		Endpoint: q.Get("endpoint"),
		Search:   q.Get("q"),
	}
	limit := clampInt(q.Get("limit"), theme.PageSize(), 1, 500)
	offset := clampInt(q.Get("offset"), 0, 0, 1<<30)
	order := parseSort(q.Get("sort"), q.Get("dir"))
	if _, ok := store.FlowSortColumns[order.Column]; !ok {
		order.Column = ""
	}

	flows, total, err := s.store.Flows(ctx, store.FlowQuery{
		ProjectID: s.project.ID,
		Protocol:  filter.Protocol,
		Class:     filter.Class,
		Endpoint:  filter.Endpoint,
		Search:    filter.Search,
		Limit:     limit,
		Offset:    offset,
		Sort:      order.Column,
		Desc:      order.Desc,
	})
	if err != nil {
		s.fail(w, r, "listing flows", err)
		return
	}
	protocols, classes, err := s.facets(ctx)
	if err != nil {
		s.fail(w, r, "listing facets", err)
		return
	}

	view := templates.FlowsView{
		Page:      page,
		Total:     total,
		Offset:    offset,
		Limit:     limit,
		Filter:    filter,
		Sort:      order,
		Protocols: protocols,
		Classes:   classes,
		Theme:     theme,
	}
	for _, f := range flows {
		row := templates.FlowRow{
			Src:       f.Src,
			Dst:       f.Dst,
			SrcHref:   templates.AssetURLByAddress(f.Src),
			DstHref:   templates.AssetURLByAddress(f.Dst),
			Protocol:  f.Protocol,
			Transport: string(f.Transport),
			Events:    f.Events,
			Malformed: f.Malformed,
			FirstSeen: f.FirstSeen,
			LastSeen:  f.LastSeen,
			Href:      eventsURL(f.Src, f.Dst, f.Protocol),
		}
		if f.ServerPort != 0 {
			row.ServerPort = strconv.Itoa(int(f.ServerPort))
		}
		row.Classes = classMix(page.Lang, theme, f.Classes)
		view.Rows = append(view.Rows, row)
	}

	if r.Header.Get("HX-Request") == "true" {
		s.render(w, r, templates.FlowTable(view))
		return
	}
	s.render(w, r, templates.FlowsPage(view))
}

// classMix renders a flow's or a protocol's operation mix as a proportion
// bar, with the counts in the title so that the bar is readable without
// hovering it.
func classMix(lang templates.Lang, theme templates.Theme,
	counts map[model.Classification]int64) templates.ProportionView {

	var (
		list    []templates.Bucket
		caption []string
	)
	for _, c := range templates.ClassDisplayOrder() {
		n := counts[c]
		if n == 0 {
			continue
		}
		list = append(list, templates.Bucket{Label: string(c), Count: n})
		caption = append(caption, templates.ClassLabel(lang, string(c))+" "+
			templates.Count(theme, n))
	}
	mix := templates.NewProportion("", list, templates.ClassOf, nil)
	mix.Caption = strings.Join(caption, " · ")
	for i := range mix.Segments {
		mix.Segments[i].Label = templates.ClassLabel(lang, mix.Segments[i].Label)
	}
	return mix
}

func (s *Server) handleMatrix(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	page := s.page(r, "matrix")
	page.Title = templates.T(page.Lang, "matrix.title")
	theme := page.Theme

	size := clampInt(q.Get("size"), theme.Number(templates.SettingMatrixSize), 2, 60)
	filter := templates.MatrixFilter{
		Protocol: q.Get("protocol"),
		Class:    q.Get("class"),
		Size:     size,
	}

	matrix, err := s.store.CommunicationMatrix(ctx, s.project.ID, filter.Protocol, filter.Class, size)
	if err != nil {
		s.fail(w, r, "building the communication matrix", err)
		return
	}
	protocols, classes, err := s.facets(ctx)
	if err != nil {
		s.fail(w, r, "listing facets", err)
		return
	}

	cells := make(map[[2]string]int64, len(matrix.Cells))
	var total int64
	for _, c := range matrix.Cells {
		cells[[2]string{c.Src, c.Dst}] = c.Events
		total += c.Events
	}
	chart := templates.NewMatrixChart(matrix.Endpoints, cells, matrix.Max, matrix.Truncated,
		func(src, dst string, n int64) string {
			return src + " → " + dst + ": " + templates.Count(theme, n) + " " +
				templates.T(page.Lang, "flows.events")
		},
		func(src, dst string) string { return eventsURL(src, dst, filter.Protocol) })

	s.render(w, r, templates.MatrixPage(templates.MatrixView{
		Page:      page,
		Chart:     chart,
		Filter:    filter,
		Protocols: protocols,
		Classes:   classes,
		Theme:     theme,
		Total:     total,
	}))
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	page := s.page(r, "events")
	page.Title = templates.T(page.Lang, "events.title")
	theme := page.Theme

	filter := templates.EventsFilter{
		Protocol:  q.Get("protocol"),
		Class:     q.Get("class"),
		Operation: q.Get("operation"),
		Search:    q.Get("q"),
		Src:       q.Get("src"),
		Dst:       q.Get("dst"),
		Capture:   q.Get("capture"),
		Malformed: q.Get("malformed") == "1",
		Anomalous: q.Get("anomalous") == "1",
	}
	limit := clampInt(q.Get("limit"), theme.PageSize(), 1, 500)
	offset := clampInt(q.Get("offset"), 0, 0, 1<<30)
	order := parseSort(q.Get("sort"), q.Get("dir"))
	if _, ok := store.EventSortColumns[order.Column]; !ok {
		order.Column = ""
	}

	events, total, err := s.store.EventsPage(ctx, store.EventQuery{
		ProjectID:     s.project.ID,
		Protocol:      filter.Protocol,
		Class:         filter.Class,
		Operation:     filter.Operation,
		Search:        filter.Search,
		Src:           filter.Src,
		Dst:           filter.Dst,
		Capture:       filter.Capture,
		OnlyMalformed: filter.Malformed,
		OnlyAnomalous: filter.Anomalous,
		Limit:         limit,
		Offset:        offset,
		Sort:          order.Column,
		Desc:          order.Desc,
	})
	if err != nil {
		s.fail(w, r, "listing events", err)
		return
	}
	protocols, classes, err := s.facets(ctx)
	if err != nil {
		s.fail(w, r, "listing facets", err)
		return
	}
	operations, err := s.store.EventOperations(ctx, s.project.ID, filter.Protocol)
	if err != nil {
		s.fail(w, r, "listing operations", err)
		return
	}

	view := templates.EventsView{
		Page:       page,
		Total:      total,
		Offset:     offset,
		Limit:      limit,
		Filter:     filter,
		Sort:       order,
		Protocols:  protocols,
		Classes:    classes,
		Operations: operations,
		Theme:      theme,
	}
	for _, e := range events {
		src, dst := endpointsOf(e)
		view.Rows = append(view.Rows, templates.EventTableRow{
			Time:      e.Timestamp,
			Protocol:  e.Protocol,
			Operation: e.Operation,
			Detail:    eventDetail(e),
			Class:     string(e.Class),
			Direction: string(e.Direction),
			Src:       src,
			Dst:       dst,
			SrcHref:   templates.AssetURLByAddress(src),
			DstHref:   templates.AssetURLByAddress(dst),
			Packet:    e.PacketIndex,
			Capture:   e.CaptureID,
			Exception: e.Exception,
			Malformed: e.Malformed,
		})
	}

	if r.Header.Get("HX-Request") == "true" {
		s.render(w, r, templates.EventTable(view))
		return
	}
	s.render(w, r, templates.EventsPage(view))
}

// endpointsOf names an event's two ends the way the flow views do: the IP
// where there is one, and the MAC where there is not, since GOOSE and
// PROFINET DCP have no IP at all.
func endpointsOf(e model.Event) (string, string) {
	src, dst := e.Flow.SrcIP, e.Flow.DstIP
	if src == "" {
		src = e.Flow.SrcMAC
	}
	if dst == "" {
		dst = e.Flow.DstMAC
	}
	return src, dst
}

func (s *Server) handleProtocols(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	page := s.page(r, "protocols")
	page.Title = templates.T(page.Lang, "protocols.title")
	theme := page.Theme
	lang := page.Lang
	selected := r.URL.Query().Get("protocol")

	stats, err := s.store.ProtocolStats(ctx, s.project.ID)
	if err != nil {
		s.fail(w, r, "summarising protocols", err)
		return
	}

	view := templates.ProtocolsView{Page: page, Theme: theme, Selected: selected}
	for _, st := range stats {
		view.Protocols = append(view.Protocols, st.Protocol)
		if selected != "" && st.Protocol != selected {
			continue
		}
		view.Total += st.Events
		view.Rows = append(view.Rows, templates.ProtocolStatRow{
			Protocol:  st.Protocol,
			Tier:      templates.ProtocolTier(st.Protocol),
			Events:    st.Events,
			Flows:     st.Flows,
			Malformed: st.Malformed,
			Anomalies: st.Anomalies,
			Health:    templates.HealthLabel(lang, st.Events, st.Malformed),
			Classes:   classMix(lang, theme, st.Classes),
			FirstSeen: st.FirstSeen,
			LastSeen:  st.LastSeen,
			Href:      "/events?protocol=" + url.QueryEscape(st.Protocol),
		})
	}

	byOperation, err := s.store.CountEventsBy(ctx, s.project.ID, "operation", selected, maxChartBuckets)
	if err != nil {
		s.fail(w, r, "counting operations", err)
		return
	}
	byPort, err := s.store.CountEventsBy(ctx, s.project.ID, "port", selected, maxChartBuckets)
	if err != nil {
		s.fail(w, r, "counting server ports", err)
		return
	}
	view.Operations = templates.NewBars(templates.T(lang, "chart.operations"),
		buckets(byOperation), nil, func(label string) string {
			return "/events?operation=" + url.QueryEscape(label) +
				optionalParam("protocol", selected)
		})
	view.Ports = templates.NewBars(templates.T(lang, "chart.ports"), buckets(byPort), nil, nil)

	timeline, err := s.store.Timeline(ctx, s.project.ID, theme.Number(templates.SettingBuckets), selected)
	if err != nil {
		s.fail(w, r, "building the timeline", err)
		return
	}
	view.Timeline = templates.NewTimeline(templates.T(lang, "chart.timeline"),
		timeBuckets(timeline), theme.ChartHeight(),
		func(t time.Time) string { return templates.FormatTimeIn(theme, t) })

	s.render(w, r, templates.ProtocolsPage(view))
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	page := s.page(r, "settings")
	page.Title = templates.T(page.Lang, "settings.title")

	token, err := s.csrfToken(w, r)
	if err != nil {
		s.fail(w, r, "issuing a CSRF token", err)
		return
	}
	schema, err := s.store.SchemaVersion(r.Context())
	if err != nil {
		s.fail(w, r, "reading the schema version", err)
		return
	}

	view := templates.NewSettingsView(page, page.Theme, token, r.URL.Query().Get("saved") == "1")
	view.DatabasePath = s.store.Path()
	view.Listen = s.addr
	view.SchemaVer = schema
	s.render(w, r, templates.SettingsPage(view))
}

// handleSaveSettings stores the posted settings.
//
// The GUI has no accounts, so this is the one place a browser can change
// server state, and a page on another origin must not be able to do it: the
// request carries a token that matches the cookie, and its Origin must be
// this server. CLAUDE.md asks for a CSRF token on every state-changing
// request, and this is that.
func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if err := s.checkCSRF(r); err != nil {
		s.log.Warn("rejected a settings post", "err", err, "remote", r.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	values := map[string]string{}
	if r.PostFormValue("action") == "reset" {
		// An empty value clears a setting, which returns it to its default.
		for _, def := range templates.SettingDefs {
			values[def.Key] = ""
		}
	} else {
		for _, def := range templates.SettingDefs {
			raw := r.PostFormValue(def.Key)
			if def.Kind == templates.KindToggle && raw == "" {
				// An unchecked box sends nothing, which for a toggle means
				// off rather than unset.
				raw = "off"
			}
			if raw == "" {
				continue
			}
			if !def.Allows(raw) {
				// A value the definition does not allow is dropped rather
				// than stored, so a hand-posted form cannot put nonsense in
				// the database.
				s.log.Warn("ignored a settings value", "key", def.Key, "value", raw)
				continue
			}
			values[def.Key] = raw
		}
	}

	if err := s.store.SaveSettings(r.Context(), s.project.ID, values); err != nil {
		s.fail(w, r, "saving settings", err)
		return
	}
	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

// csrfCookie is the name of the double submit cookie.
const csrfCookie = "otinv_csrf"

// csrfToken returns the token for this browser, issuing one when there is
// none. It is a random value that the form carries and the cookie repeats:
// another origin can make a browser post, but it cannot read or set this
// cookie, so it cannot make the two match.
func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) >= 32 {
		return c.Value, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("web: reading random bytes: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	//nolint:gosec // G124: Secure is deliberately unset, see the comment below
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// Secure is not set: the GUI serves plain HTTP on loopback until it
		// has TLS, and a cookie marked Secure would never be sent back. It
		// is set here the moment the server has a certificate.
	})
	return token, nil
}

// checkCSRF verifies a state-changing request.
func (s *Server) checkCSRF(r *http.Request) error {
	cookie, err := r.Cookie(csrfCookie)
	if err != nil {
		return fmt.Errorf("no CSRF cookie")
	}
	posted := r.PostFormValue("csrf")
	if posted == "" {
		posted = r.Header.Get("X-CSRF-Token")
	}
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(posted)) != 1 {
		return fmt.Errorf("the CSRF token does not match the cookie")
	}
	// A browser sends Origin on a cross-origin post, and Sec-Fetch-Site on
	// every modern one. Either is enough to refuse a post from elsewhere.
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host {
			return fmt.Errorf("the Origin %q is not this server", origin)
		}
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return fmt.Errorf("the request comes from %q", site)
	}
	return nil
}

// facets lists the protocols and classifications a project holds, which is
// what every filtered view offers in its menus.
func (s *Server) facets(ctx context.Context) ([]string, []string, error) {
	protocols, err := s.store.CountEventsBy(ctx, s.project.ID, "protocol", "", 0)
	if err != nil {
		return nil, nil, err
	}
	classes, err := s.store.CountEventsBy(ctx, s.project.ID, "class", "", 0)
	if err != nil {
		return nil, nil, err
	}
	return labels(protocols), labels(classes), nil
}

func labels(bs []store.Bucket) []string {
	out := make([]string, 0, len(bs))
	for _, b := range bs {
		if b.Label != "" {
			out = append(out, b.Label)
		}
	}
	return out
}

// buckets converts the store's counts into the chart's.
func buckets(bs []store.Bucket) []templates.Bucket {
	out := make([]templates.Bucket, 0, len(bs))
	for _, b := range bs {
		out = append(out, templates.Bucket{Label: b.Label, Count: b.Count})
	}
	return out
}

// classBuckets keeps the classifications in their display order rather than
// by count, so that the same colour is always in the same place.
func classBuckets(bs []store.Bucket) []templates.Bucket {
	counts := map[string]int64{}
	for _, b := range bs {
		counts[b.Label] = b.Count
	}
	var out []templates.Bucket
	for _, c := range templates.ClassDisplayOrder() {
		if n := counts[string(c)]; n > 0 {
			out = append(out, templates.Bucket{Label: string(c), Count: n})
		}
	}
	return out
}

// classKey recovers the classification behind a translated label, so that a
// chart in Swedish still links to a filter the store understands.
func classKey(lang templates.Lang, label string) string {
	for _, c := range templates.ClassDisplayOrder() {
		if templates.ClassLabel(lang, string(c)) == label || string(c) == label {
			return string(c)
		}
	}
	return label
}

// roleBuckets translates the role names for display.
func roleBuckets(lang templates.Lang, bs []store.Bucket) []templates.Bucket {
	out := make([]templates.Bucket, 0, len(bs))
	for _, b := range bs {
		out = append(out, templates.Bucket{
			Label: templates.RoleLabel(lang, model.RoleName(b.Label)),
			Count: b.Count,
		})
	}
	return out
}

// roleKey recovers the role behind a translated label.
func roleKey(lang templates.Lang, label string) string {
	for _, role := range []model.RoleName{
		model.RoleController, model.RoleOperator, model.RoleEngineering,
		model.RoleGateway, model.RoleUnknown,
	} {
		if templates.RoleLabel(lang, role) == label {
			return string(role)
		}
	}
	return label
}

// timeBuckets converts the store's timeline into the chart's.
func timeBuckets(bs []store.TimeBucket) []templates.TimeBucket {
	out := make([]templates.TimeBucket, 0, len(bs))
	for _, b := range bs {
		out = append(out, templates.TimeBucket{
			Start:   b.Start,
			End:     b.End,
			Count:   b.Count,
			Classes: b.Classes,
		})
	}
	return out
}

// eventsURL links to the events of one flow.
func eventsURL(src, dst, protocol string) string {
	q := url.Values{}
	if src != "" {
		q.Set("src", src)
	}
	if dst != "" {
		q.Set("dst", dst)
	}
	if protocol != "" {
		q.Set("protocol", protocol)
	}
	if len(q) == 0 {
		return "/events"
	}
	return "/events?" + q.Encode()
}

func optionalParam(key, value string) string {
	if value == "" {
		return ""
	}
	return "&" + key + "=" + url.QueryEscape(value)
}
