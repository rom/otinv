package web_test

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/store"
	"github.com/rom/otinv/internal/web"
	"github.com/rom/otinv/internal/web/templates"
)

// The views beyond the asset list: the dashboard, the flow table, the
// communication matrix, the event table, the protocol statistics and the
// settings form.
//
// Each test asserts on what the page shows rather than on the view model
// behind it, because the charts are server-drawn: a bar's width is in the
// rendered SVG, so a mistake in the geometry is visible to a test.

// sampleTraffic writes a handful of events covering three protocols, both
// directions, a control command, a malformed frame and an anomaly, which is
// enough for every aggregate the new views show.
func sampleTraffic(t *testing.T, s *store.Store, project model.Project) {
	t.Helper()
	ctx := context.Background()
	capturePK, _, err := s.SaveCapture(ctx, project.ID, model.Capture{
		ID: "part1", Path: "testdata/pcaps/part1.pcap", SHA256: "abc123",
		Packets: 118, LinkType: "Ethernet", FirstSeen: seen, LastSeen: seen.Add(time.Hour),
	})
	require.NoError(t, err)

	w := s.NewEventWriter(project.ID, capturePK)
	add := func(e model.Event) {
		t.Helper()
		require.NoError(t, w.Add(ctx, e))
	}
	modbus := model.Flow{
		SrcIP: "10.0.0.57", DstIP: "10.0.0.3", SrcPort: 2578, DstPort: 502,
		Transport: model.TransportTCP,
	}
	for i := range 4 {
		add(model.Event{
			CaptureID: "part1", PacketIndex: uint64(i + 1), Timestamp: seen.Add(time.Duration(i) * time.Minute),
			Flow: modbus, Protocol: "modbus", Direction: model.DirRequest, ServerPort: 502,
			Operation: "ReadHoldingRegisters", FunctionCode: 3, Class: model.ClassRead,
			UnitID: model.Ptr(uint16(10)), Address: model.Ptr(uint32(40001)),
		})
	}
	add(model.Event{
		CaptureID: "part1", PacketIndex: 5, Timestamp: seen.Add(5 * time.Minute),
		Flow: modbus, Protocol: "modbus", Direction: model.DirRequest, ServerPort: 502,
		Operation: "Diagnostics", FunctionCode: 8, Class: model.ClassControl,
		UnitID: model.Ptr(uint16(10)),
		// The name the dissector really produces, so that a rule matching on
		// it fires here exactly as it would on a capture.
		Attrs: map[string]string{"anomaly": "force_listen_only", "sub_function_name": "ForceListenOnlyMode"},
	})
	add(model.Event{
		CaptureID: "part1", PacketIndex: 6, Timestamp: seen.Add(6 * time.Minute),
		Flow: modbus.Reverse(), Protocol: "modbus", Direction: model.DirResponse, ServerPort: 502,
		Operation: "ReadHoldingRegisters", FunctionCode: 3, Class: model.ClassRead,
		Exception: "IllegalDataAddress",
	})
	add(model.Event{
		CaptureID: "part1", PacketIndex: 7, Timestamp: seen.Add(7 * time.Minute),
		Flow: modbus, Protocol: "modbus", Direction: model.DirUnknown, ServerPort: 502,
		Operation: "FramingError", FunctionCode: -1, Class: model.ClassOther,
		Malformed: true, Error: "MBAP length 34820 exceeds the segment",
	})
	// A second protocol with no IP layer at all, which the flow and matrix
	// views have to name by MAC.
	add(model.Event{
		CaptureID: "part1", PacketIndex: 8, Timestamp: seen.Add(8 * time.Minute),
		Flow: model.Flow{
			SrcMAC: "0a:bb:fe:10:c9:02", DstMAC: "01:0c:cd:01:00:00",
			Transport: model.TransportEthernet,
		},
		Protocol: "goose", Direction: model.DirResponse,
		Operation: "StateChange", FunctionCode: -1, Class: model.ClassRead,
	})
	// A third, writing: the one event a reader filtering for writes wants.
	add(model.Event{
		CaptureID: "part1", PacketIndex: 9, Timestamp: seen.Add(9 * time.Minute),
		Flow: model.Flow{
			SrcIP: "10.0.0.57", DstIP: "10.0.0.9", SrcPort: 49271, DstPort: 44818,
			Transport: model.TransportTCP,
		},
		Protocol: "enip", Direction: model.DirRequest, ServerPort: 44818,
		Operation: "Write_Tag", FunctionCode: 0x4d, Class: model.ClassWrite,
		Attrs: map[string]string{"cip_symbol": "PumpRun"},
	})
	require.NoError(t, w.Close(ctx))
}

func TestDashboardShowsTheProjectAtAGlance(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	sampleTraffic(t, s, project)

	rec := get(t, h, "/dashboard", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// The tiles: two assets, nine events, three protocols, one malformed
	// frame and one anomaly.
	assert.Contains(t, body, "Assets")
	assert.Contains(t, body, ">2<")
	assert.Contains(t, body, ">9<")
	assert.Contains(t, body, "Malformed frames")
	assert.Contains(t, body, "/events?malformed=1")
	assert.Contains(t, body, "/events?anomalous=1")

	// The charts are drawn by the server, so the bars are in the page: the
	// busiest protocol gets the full width and the others a share of it.
	assert.Contains(t, body, `aria-label="modbus: 7"`)
	assert.Contains(t, body, `aria-label="goose: 1"`)
	assert.Contains(t, body, `<rect class="bar" x="0" y="1" height="8" width="100">`)
	assert.Contains(t, body, "Events over time")
	assert.Contains(t, body, `class="col col-control"`, "the control command stacks in its own colour")
	assert.Contains(t, body, "Operation mix")
	assert.Contains(t, body, "Latest events")
	assert.Contains(t, body, "Write_Tag")
}

// With the charts switched off every number is still in its table, which is
// also what a printout and a screen reader get.
func TestDashboardWithoutCharts(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	sampleTraffic(t, s, project)
	require.NoError(t, s.SaveSettings(context.Background(), project.ID,
		map[string]string{templates.SettingCharts: "off"}))

	body := get(t, h, "/dashboard", nil).Body.String()
	assert.Contains(t, body, "Charts are switched off")
	assert.NotContains(t, body, "timeline-chart")
	assert.Contains(t, body, `aria-label="modbus: 7"`, "the bar chart is a table either way")
}

func TestFlowsView(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	sampleTraffic(t, s, project)

	body := get(t, h, "/flows", nil).Body.String()
	assert.Contains(t, body, "4 matching flows")
	assert.Contains(t, body, "10.0.0.57")
	assert.Contains(t, body, "Modbus/TCP")
	// A layer 2 protocol has no IP, so its flow is named by its MACs.
	assert.Contains(t, body, "0a:bb:fe:10:c9:02")
	assert.Contains(t, body, "01:0c:cd:01:00:00")
	// Each row links to the events behind it.
	assert.Contains(t, body, "/events?dst=10.0.0.3&amp;protocol=modbus&amp;src=10.0.0.57")
	// The mix bar is drawn per flow, with the counts in its title.
	assert.Contains(t, body, `class="seg seg-control"`)

	// Filtering by protocol narrows it, and the filter round-trips.
	body = get(t, h, "/flows?protocol=goose", nil).Body.String()
	assert.Contains(t, body, "1 matching flows")
	assert.NotContains(t, body, "<td>Modbus/TCP",
		"the filtered table holds one protocol; the menu still offers them all")

	// htmx asks for the table alone.
	rec := get(t, h, "/flows?protocol=modbus", map[string]string{"HX-Request": "true"})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), "<html")
	assert.Contains(t, rec.Body.String(), `id="flow-table"`)
}

func TestMatrixView(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	sampleTraffic(t, s, project)

	body := get(t, h, "/matrix", nil).Body.String()
	assert.Contains(t, body, "Communication matrix")
	// Five endpoints appear: three IPs and two MACs.
	assert.Contains(t, body, "10.0.0.3")
	assert.Contains(t, body, "0a:bb:fe:10:c9:02")
	// A cell carries its count in a title and links to the events.
	assert.Regexp(t, regexp.MustCompile(`title="10\.0\.0\.57 → 10\.0\.0\.3: 6 `), body)
	assert.Contains(t, body, `class="heat heat-5"`)
	// An endpoint pair with no traffic is an empty cell rather than a gap.
	assert.Contains(t, body, `class="heat heat-0"`)
}

func TestEventsView(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	sampleTraffic(t, s, project)

	body := get(t, h, "/events", nil).Body.String()
	assert.Contains(t, body, "9 matching events")
	assert.Contains(t, body, "ReadHoldingRegisters")
	assert.Contains(t, body, "ForceListenOnly", "the detail line says which sub-function")
	assert.Contains(t, body, "IllegalDataAddress")
	assert.Contains(t, body, "row-malformed")

	// The facet filters narrow the table.
	body = get(t, h, "/events?class=write", nil).Body.String()
	assert.Contains(t, body, "1 matching events")
	assert.Contains(t, body, "Write_Tag")
	assert.NotContains(t, body, "<td>ReadHoldingRegisters",
		"the filtered table holds one row; the operation menu still offers the rest")

	// Only the malformed frames, which is one click from the dashboard.
	body = get(t, h, "/events?malformed=1", nil).Body.String()
	assert.Contains(t, body, "1 matching events")
	assert.Contains(t, body, "MBAP length 34820")

	// Only the anomalies.
	body = get(t, h, "/events?anomalous=1", nil).Body.String()
	assert.Contains(t, body, "1 matching events")
	assert.Contains(t, body, "force_listen_only")

	// One flow's events, which is where the flow table and the matrix lead.
	body = get(t, h, "/events?src=10.0.0.57&dst=10.0.0.3&protocol=modbus", nil).Body.String()
	assert.Contains(t, body, "6 matching events")
	assert.Contains(t, body, "Clear filters")

	// A search covers the operation, the error and both endpoints.
	body = get(t, h, "/events?q=Diagnostics", nil).Body.String()
	assert.Contains(t, body, "1 matching events")
}

func TestEventsPagingAndSorting(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	sampleTraffic(t, s, project)

	body := get(t, h, "/events?limit=4", nil).Body.String()
	assert.Contains(t, body, "1 / 3", "nine events over four rows is three pages")
	assert.Contains(t, body, "offset=4")

	// Sorting by packet index ascending puts the first frame at the top.
	body = get(t, h, "/events?sort=packet&dir=asc&limit=2", nil).Body.String()
	first := strings.Index(body, "ReadHoldingRegisters")
	require.Positive(t, first)
	assert.Contains(t, body, `aria-sort="ascending"`)
}

func TestProtocolsView(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	sampleTraffic(t, s, project)

	body := get(t, h, "/protocols", nil).Body.String()
	assert.Contains(t, body, "Modbus/TCP")
	assert.Contains(t, body, "IEC 61850 GOOSE")
	assert.Contains(t, body, "EtherNet/IP")
	// Parse health: one of seven modbus frames did not decode, which is one
	// in seven and so not "mostly".
	assert.Contains(t, body, "many frames undecodable")
	assert.Contains(t, body, "every frame decoded")
	assert.Contains(t, body, "malformed: 1")

	// One protocol at a time, with its own operation chart.
	body = get(t, h, "/protocols?protocol=modbus", nil).Body.String()
	assert.Contains(t, body, `aria-label="ReadHoldingRegisters: 5"`)
	assert.NotContains(t, body, "<td>EtherNet/IP")
	assert.Contains(t, body, `aria-label="502: 7"`, "the server port chart")
}

func TestSettingsRoundTrip(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())

	rec := get(t, h, "/settings", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Appearance")
	assert.Contains(t, body, "Rows per page")
	assert.Contains(t, body, `value="dark"`)

	token, cookie := csrfOf(t, rec)
	require.NotEmpty(t, token)

	// Saving applies to the next page: the theme, the accent and the density
	// are attributes on the root element, and the page size is the table's.
	form := url.Values{
		"csrf":                      {token},
		"action":                    {"save"},
		templates.SettingTheme:      {"dark"},
		templates.SettingAccent:     {"teal"},
		templates.SettingDensity:    {"compact"},
		templates.SettingPageSize:   {"25"},
		templates.SettingNumbers:    {"plain"},
		templates.SettingTimeFormat: {"short"},
		templates.SettingLang:       {"sv"},
		templates.SettingStripes:    {"off"},
		templates.SettingCharts:     {"on"},
		templates.SettingMonospace:  {"on"},
		templates.SettingContrast:   {"high"},
		templates.SettingFont:       {"large"},
		templates.SettingChartSize:  {"tall"},
		templates.SettingBuckets:    {"120"},
		templates.SettingMatrixSize: {"20"},
	}
	rec = post(t, h, form, cookie)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/settings?saved=1", rec.Header().Get("Location"))

	body = get(t, h, "/dashboard", nil).Body.String()
	assert.Contains(t, body, `data-theme="dark"`)
	assert.Contains(t, body, `data-accent="teal"`)
	assert.Contains(t, body, `data-density="compact"`)
	assert.Contains(t, body, `data-contrast="high"`)
	assert.Contains(t, body, `data-stripes="off"`)
	assert.Contains(t, body, `lang="sv"`, "the stored language applies without a query parameter")
	assert.Contains(t, body, "Översikt")

	// Resetting clears every stored value, so the defaults come back.
	rec = get(t, h, "/settings", nil)
	token, cookie = csrfOf(t, rec)
	rec = post(t, h, url.Values{"csrf": {token}, "action": {"reset"}}, cookie)
	require.Equal(t, http.StatusSeeOther, rec.Code)

	body = get(t, h, "/dashboard", nil).Body.String()
	assert.Contains(t, body, `data-theme="auto"`)
	assert.Contains(t, body, `lang="en"`)
}

// A page on another origin must not be able to change settings: the GUI has
// no accounts, so the token and the Origin are what stand between a browser
// and this server.
func TestSettingsRefusesForgedPosts(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())
	rec := get(t, h, "/settings", nil)
	token, cookie := csrfOf(t, rec)

	t.Run("no token", func(t *testing.T) {
		rec := post(t, h, url.Values{"theme": {"dark"}}, cookie)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
	t.Run("wrong token", func(t *testing.T) {
		rec := post(t, h, url.Values{"csrf": {"nope"}, "theme": {"dark"}}, cookie)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
	t.Run("no cookie", func(t *testing.T) {
		rec := post(t, h, url.Values{"csrf": {token}, "theme": {"dark"}}, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
	t.Run("cross origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/settings",
			strings.NewReader(url.Values{"csrf": {token}, "theme": {"dark"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://evil.example")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
	t.Run("cross site fetch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/settings",
			strings.NewReader(url.Values{"csrf": {token}, "theme": {"dark"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

// A value the definitions do not allow is dropped rather than stored, so a
// hand-posted form cannot put nonsense in the database.
func TestSettingsRejectsUnknownValues(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	rec := get(t, h, "/settings", nil)
	token, cookie := csrfOf(t, rec)

	rec = post(t, h, url.Values{
		"csrf":                  {token},
		templates.SettingTheme:  {"neon"},
		templates.SettingAccent: {"teal"},
		"not_a_setting":         {"x"},
	}, cookie)
	require.Equal(t, http.StatusSeeOther, rec.Code)

	stored, err := s.Settings(context.Background(), project.ID)
	require.NoError(t, err)
	// The accent was stored, the unknown theme and the unknown key were
	// dropped, and the three toggles the form did not send are off: an
	// unchecked box sends nothing, which for a toggle means off.
	assert.Equal(t, map[string]string{
		templates.SettingAccent:    "teal",
		templates.SettingStripes:   "off",
		templates.SettingMonospace: "off",
		templates.SettingCharts:    "off",
	}, stored)
}

// Every view renders from an empty project: a GUI that only works once there
// is data is a GUI nobody can open.
func TestViewsRenderWhenEmpty(t *testing.T) {
	h, _, _ := serve(t, nil)
	for _, path := range []string{
		"/dashboard", "/assets", "/flows", "/matrix", "/events", "/protocols",
		"/captures", "/settings",
	} {
		t.Run(path, func(t *testing.T) {
			rec := get(t, h, path, nil)
			require.Equal(t, http.StatusOK, rec.Code)
			assert.Contains(t, rec.Body.String(), "<html")
		})
	}
}

// The content security policy forbids inline styles and scripts, so the pages
// must carry none: the charts are SVG with their geometry in attributes, and
// the theme is data attributes on the root element.
func TestPagesCarryNoInlineStyleOrScript(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	sampleTraffic(t, s, project)

	for _, path := range []string{"/dashboard", "/flows", "/matrix", "/events", "/protocols", "/settings"} {
		t.Run(path, func(t *testing.T) {
			body := get(t, h, path, nil).Body.String()
			assert.NotContains(t, body, "style=")
			assert.NotContains(t, body, "<style")
			// The one script is the vendored htmx, loaded from this origin.
			assert.Equal(t, 1, strings.Count(body, "<script"))
			assert.Contains(t, body, `src="/static/vendor/htmx.min.js"`)
		})
	}
}

// post sends the settings form, which is the one state-changing request the
// GUI has.
func post(t *testing.T, h http.Handler, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// csrfOf reads the token out of a rendered form and the cookie that must
// match it.
func csrfOf(t *testing.T, rec *httptest.ResponseRecorder) (string, *http.Cookie) {
	t.Helper()
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(rec.Body.String())
	require.Len(t, m, 2, "the settings form must carry a token")
	for _, c := range rec.Result().Cookies() {
		if c.Name == "otinv_csrf" {
			return m[1], c
		}
	}
	t.Fatal("no CSRF cookie was set")
	return "", nil
}

var _ = filepath.Join

// serveWith builds a server with options, which is how the flags of
// `otinv serve` are exercised.
func serveWith(t *testing.T, opts web.Options) (http.Handler, *store.Store, model.Project) {
	t.Helper()
	ctx := context.Background()

	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "project.db"))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, s.Close()) })

	project, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)
	require.NoError(t, s.SaveAssets(ctx, project.ID, sampleAssets()))

	opts.Store = s
	opts.Project = project
	srv, err := web.New(opts)
	require.NoError(t, err)
	return srv.Handler(), s, project
}

// --read-only shows the configuration and refuses to change it.
func TestReadOnlyServerRefusesToSaveSettings(t *testing.T) {
	h, s, project := serveWith(t, web.Options{ReadOnly: true})

	rec := get(t, h, "/settings", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "read-only")
	assert.Contains(t, body, "<fieldset disabled>", "the form is shown, disabled")
	assert.NotContains(t, body, `value="save"`, "no button offers a save that would be refused")
	assert.NotContains(t, body, `value="reset"`)

	// A hand-made post with a valid token is refused all the same: the
	// disabled form is a courtesy, the server is the rule.
	token, cookie := csrfOf(t, rec)
	rec = post(t, h, url.Values{
		"csrf":                 {token},
		"action":               {"save"},
		templates.SettingTheme: {"dark"},
	}, cookie)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	stored, err := s.Settings(context.Background(), project.ID)
	require.NoError(t, err)
	assert.Empty(t, stored, "nothing was written")
}

func TestReadWriteServerStillSavesSettings(t *testing.T) {
	h, _, _ := serveWith(t, web.Options{})

	rec := get(t, h, "/settings", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `value="save"`)
	assert.NotContains(t, rec.Body.String(), "<fieldset disabled>")

	token, cookie := csrfOf(t, rec)
	rec = post(t, h, url.Values{
		"csrf":                 {token},
		"action":               {"save"},
		templates.SettingTheme: {"dark"},
	}, cookie)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
}

// --lang decides the language of a project that has none stored, and nothing
// more: a stored setting and an explicit ?lang= both still win.
func TestServerLanguageFallback(t *testing.T) {
	swedish := func(body string) bool { return strings.Contains(body, "Översikt") }

	h, s, project := serveWith(t, web.Options{Lang: "sv"})
	assert.True(t, swedish(get(t, h, "/dashboard", nil).Body.String()))

	// The browser asking for English does not override the flag.
	assert.True(t, swedish(get(t, h, "/dashboard",
		map[string]string{"Accept-Language": "en-GB,en;q=0.9"}).Body.String()))

	// A link that names its language does.
	assert.False(t, swedish(get(t, h, "/dashboard?lang=en", nil).Body.String()))

	// And so does a stored setting.
	require.NoError(t, s.SaveSettings(context.Background(), project.ID,
		map[string]string{templates.SettingLang: "en"}))
	assert.False(t, swedish(get(t, h, "/dashboard", nil).Body.String()))
}

// Without the flag the browser decides, as before.
func TestServerLanguageFollowsTheBrowserByDefault(t *testing.T) {
	h, _, _ := serveWith(t, web.Options{})

	body := get(t, h, "/dashboard", map[string]string{"Accept-Language": "sv-SE,sv;q=0.9"}).Body.String()
	assert.Contains(t, body, "Översikt")

	body = get(t, h, "/dashboard", nil).Body.String()
	assert.Contains(t, body, "Dashboard")
}

func TestServerRefusesAnUnknownLanguage(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "project.db"))
	require.NoError(t, err)
	defer func() { assert.NoError(t, s.Close()) }()

	_, err = web.New(web.Options{Store: s, Lang: "de"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no UI language")
	assert.Contains(t, err.Error(), "en, sv")

	// A tag with a region is still the language it names.
	for _, tag := range []string{"sv", "SV", "sv-SE", "en-GB"} {
		_, err := web.New(web.Options{Store: s, Lang: tag})
		require.NoError(t, err, tag)
	}
}

// The topology view: the graph the island fetches, the picture the server
// draws, and the filters that narrow both.

// topologyGraph is the JSON shape the island consumes. It is declared here
// rather than imported so that a change to the wire format has to be made
// twice, once on each side.
type topologyGraph struct {
	Nodes []struct {
		ID        string   `json:"id"`
		Label     string   `json:"label"`
		Kind      string   `json:"kind"`
		Role      string   `json:"role"`
		Level     int      `json:"level"`
		LevelNote string   `json:"level_note"`
		Subnet    string   `json:"subnet"`
		Protocols []string `json:"protocols"`
		Href      string   `json:"href"`
		Context   bool     `json:"context"`
		Events    int64    `json:"events"`
	} `json:"nodes"`
	Edges []struct {
		ID       string           `json:"id"`
		Src      string           `json:"src"`
		Dst      string           `json:"dst"`
		Protocol string           `json:"protocol"`
		Class    string           `json:"class"`
		Classes  map[string]int64 `json:"classes"`
		Events   int64            `json:"events"`
		Directed bool             `json:"directed"`
		Href     string           `json:"href"`
	} `json:"edges"`
	Levels []struct {
		Level int      `json:"level"`
		Nodes []string `json:"nodes"`
	} `json:"levels"`
	Subnets []struct {
		CIDR  string   `json:"cidr"`
		Nodes []string `json:"nodes"`
	} `json:"subnets"`
	Truncated string `json:"truncated"`
}

func graphOf(t *testing.T, h http.Handler, target string) topologyGraph {
	t.Helper()
	rec := get(t, h, target, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"),
		"OT data must not linger in a cache")

	var g topologyGraph
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &g))
	return g
}

func TestTopologyGraphIsBuiltFromTheStoredFlows(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	sampleTraffic(t, s, project)

	g := graphOf(t, h, "/topology.json")

	nodes := map[string]int{}
	for i, n := range g.Nodes {
		nodes[n.ID] = i
	}
	require.Contains(t, nodes, "mac:00:02:b3:ce:70:51")
	require.Contains(t, nodes, "mac:00:20:78:00:62:0d")

	plc := g.Nodes[nodes["mac:00:02:b3:ce:70:51"]]
	assert.Equal(t, "10.0.0.3", plc.Label)
	assert.Equal(t, "device", plc.Kind)
	assert.Equal(t, 1, plc.Level)
	assert.Equal(t, "serves modbus (32 operations observed)", plc.LevelNote)
	assert.Equal(t, "10.0.0.0/24", plc.Subnet)
	assert.Equal(t, "/assets/mac:00:02:b3:ce:70:51", plc.Href)

	// The multicast address a GOOSE publication is sent to is a subscription,
	// not a device, and nothing answers from it.
	var group string
	for _, n := range g.Nodes {
		if n.Kind == "group" {
			group = n.ID
		}
	}
	assert.Equal(t, "01:0c:cd:01:00:00", group)

	// The modbus conversation is one edge from the client to the server,
	// whichever direction the aggregate happened to hold.
	var modbus *struct {
		ID       string           `json:"id"`
		Src      string           `json:"src"`
		Dst      string           `json:"dst"`
		Protocol string           `json:"protocol"`
		Class    string           `json:"class"`
		Classes  map[string]int64 `json:"classes"`
		Events   int64            `json:"events"`
		Directed bool             `json:"directed"`
		Href     string           `json:"href"`
	}
	for i := range g.Edges {
		if g.Edges[i].Protocol == "modbus" {
			modbus = &g.Edges[i]
		}
	}
	require.NotNil(t, modbus)
	assert.Equal(t, "mac:00:20:78:00:62:0d", modbus.Src, "the client is the source of the edge")
	assert.Equal(t, "mac:00:02:b3:ce:70:51", modbus.Dst)
	assert.True(t, modbus.Directed)
	assert.Equal(t, "control", modbus.Class, "one control command decides the edge, not four reads")
	// Both directions are one edge, so the four requests and the answer that
	// came back are counted together.
	assert.EqualValues(t, 5, modbus.Classes["read"])
	assert.Contains(t, modbus.Href, "protocol=modbus")

	levels := map[int]int{}
	for _, l := range g.Levels {
		levels[l.Level] = len(l.Nodes)
	}
	assert.Equal(t, 1, levels[1])
	assert.Equal(t, 1, levels[2])
	assert.Empty(t, g.Truncated)
}

func TestTopologyFiltersNarrowTheGraph(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	sampleTraffic(t, s, project)

	// One protocol: only the conversations that carried it.
	g := graphOf(t, h, "/topology.json?protocol=goose")
	for _, e := range g.Edges {
		assert.Equal(t, "goose", e.Protocol)
	}

	// One classification: the Modbus edge survives on its control command.
	g = graphOf(t, h, "/topology.json?class=control")
	require.NotEmpty(t, g.Edges)
	for _, e := range g.Edges {
		assert.Equal(t, "control", e.Class)
	}

	// A threshold drops the quiet conversations.
	g = graphOf(t, h, "/topology.json?min=100")
	assert.Empty(t, g.Edges, "nothing in the sample carries a hundred events")

	// A level selects devices, and the devices they talk to are drawn as
	// context rather than hidden: a selection with no counterpart says
	// nothing about what it does.
	g = graphOf(t, h, "/topology.json?level=1")
	byID := map[string]bool{}
	for _, n := range g.Nodes {
		byID[n.ID] = n.Context
	}
	require.Contains(t, byID, "mac:00:02:b3:ce:70:51")
	assert.False(t, byID["mac:00:02:b3:ce:70:51"], "the selected device is not context")
	require.Contains(t, byID, "mac:00:20:78:00:62:0d")
	assert.True(t, byID["mac:00:20:78:00:62:0d"], "its peer is drawn as context")

	// A search that matches nothing leaves an empty graph rather than the
	// whole project.
	g = graphOf(t, h, "/topology.json?q=203.0.113.9")
	assert.Empty(t, g.Nodes)
}

func TestTopologyPageDrawsAPictureAndSaysWhatItRestsOn(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	sampleTraffic(t, s, project)

	rec := get(t, h, "/topology", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// The server-drawn picture is on the page whether or not a script ever
	// runs, with a band per level.
	assert.Contains(t, body, "<svg")
	assert.Contains(t, body, "topo-node")
	assert.Contains(t, body, "Level 1 — basic control")
	assert.Contains(t, body, "Level 2 — supervisory")

	// The island and the library it needs, and nothing else loading them.
	assert.Contains(t, body, `src="/static/vendor/cytoscape.min.js"`)
	assert.Contains(t, body, `src="/static/topology.js"`)
	assert.Contains(t, body, `id="__________cytoscape_stylesheet"`)
	assert.Contains(t, body, `data-graph="/topology.json`)

	// The level summary and the cross-level panel, which is the rule this
	// view exists to make visible.
	assert.Contains(t, body, "Flows that skip a level")
	assert.Contains(t, body, "No flow skips a level.")

	// And the export, which is a server route rather than a library.
	assert.Contains(t, body, `href="/topology.svg`)
}

func TestTopologyPictureIsAStandaloneSVG(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	sampleTraffic(t, s, project)

	rec := get(t, h, "/topology.svg", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "image/svg+xml; charset=utf-8", rec.Header().Get("Content-Type"))

	body := rec.Body.String()
	assert.Contains(t, body, `xmlns="http://www.w3.org/2000/svg"`)
	assert.Contains(t, body, "<style>", "a saved picture carries its own colours")
	assert.NotContains(t, body, "templ.Raw", "the stylesheet must be rendered, not printed")
	assert.Contains(t, body, "10.0.0.3")

	var doc any
	require.NoError(t, xml.Unmarshal(rec.Body.Bytes(), &doc), "the export must be valid XML")
}

// A device's level is an inference, so the asset page shows the reasoning and
// links to where a level means something.
func TestAssetPageShowsItsLevelAndWhy(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())

	rec := get(t, h, "/assets/mac:00:02:b3:ce:70:51", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Level 1 — basic control")
	assert.Contains(t, body, "Why this level")
	assert.Contains(t, body, "serves modbus (32 operations observed)")
	assert.Contains(t, body, `href="/topology?level=1"`)
}

func TestAssetListFiltersByLevel(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())

	body := get(t, h, "/assets", nil).Body.String()
	assert.Contains(t, body, "Level 1 — basic control")
	assert.Contains(t, body, "Level 2 — supervisory")

	body = get(t, h, "/assets?level=1", nil).Body.String()
	assert.Contains(t, body, "10.0.0.3")
	assert.NotContains(t, body, "10.0.0.57")

	body = get(t, h, "/assets?level=unknown", nil).Body.String()
	assert.Contains(t, body, "No assets match this filter.")
}

// The findings views: the triage queue, one finding with its evidence, and
// the rules that produce them.

// storedFindings writes a couple of findings the way a rule run would.
func storedFindings(t *testing.T, s *store.Store, project model.Project) {
	t.Helper()
	require.NoError(t, s.SaveFindings(context.Background(), project.ID, []model.Finding{
		{
			ID: "f1", RuleID: "OT-003",
			Title:    "Modbus diagnostic that changes how a device answers",
			Summary:  "10.0.0.57 sent ForceListenOnlyMode to 10.0.0.3",
			Severity: model.SeverityHigh, Status: model.StatusNew,
			Technique: "T0813", TechniqueName: "Denial of Control",
			Src: "10.0.0.57", Dst: "10.0.0.3", Protocol: "modbus",
			Count: 3, FirstSeen: seen, LastSeen: seen.Add(time.Hour),
			Evidence: model.Evidence{
				CaptureID: "part1", PacketIndex: 5, Timestamp: seen,
				Protocol: "modbus", Operation: "Diagnostics", FunctionCode: 8,
			},
			Details: map[string]string{"sub_function": "ForceListenOnlyMode"},
		},
		{
			ID: "f2", RuleID: "OT-010",
			Title:    "Industrial protocol on a non-standard port",
			Summary:  "modbus served on port 1502 by 10.0.0.9",
			Severity: model.SeverityLow, Status: model.StatusNew,
			Technique: "T0885", TechniqueName: "Commonly Used Port",
			Dst: "10.0.0.9", Protocol: "modbus",
			Count: 1, FirstSeen: seen, LastSeen: seen,
			Evidence: model.Evidence{
				CaptureID: "part1", PacketIndex: 9, Timestamp: seen, Protocol: "modbus",
			},
		},
	}))
}

func TestFindingsListAndFilters(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	storedFindings(t, s, project)

	body := get(t, h, "/findings", nil).Body.String()
	assert.Contains(t, body, "ForceListenOnlyMode")
	assert.Contains(t, body, "OT-003")
	assert.Contains(t, body, "OT-010")
	assert.Contains(t, body, "severity-high")
	assert.Contains(t, body, "2 findings")
	assert.Contains(t, body, "2 open")

	// Each filter narrows the queue.
	body = get(t, h, "/findings?severity=low", nil).Body.String()
	assert.NotContains(t, body, "ForceListenOnlyMode")
	assert.Contains(t, body, "port 1502")

	body = get(t, h, "/findings?rule=OT-003", nil).Body.String()
	assert.Contains(t, body, "ForceListenOnlyMode")
	assert.NotContains(t, body, "port 1502")

	body = get(t, h, "/findings?q=1502", nil).Body.String()
	assert.Contains(t, body, "port 1502")
	assert.NotContains(t, body, "ForceListenOnlyMode")

	// A severity nobody defined is dropped rather than refused.
	body = get(t, h, "/findings?severity=apocalyptic", nil).Body.String()
	assert.Contains(t, body, "ForceListenOnlyMode")
	assert.Contains(t, body, "port 1502")
}

// CLAUDE.md: no finding without traceable evidence. The page is where that
// promise is kept.
func TestFindingPageShowsTheEvidence(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	storedFindings(t, s, project)

	rec := get(t, h, "/findings/f1", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "10.0.0.57 sent ForceListenOnlyMode to 10.0.0.3")
	assert.Contains(t, body, "part1", "the capture it came from")
	assert.Contains(t, body, ">5<", "the packet index")
	assert.Contains(t, body, "Diagnostics", "the operation")
	assert.Contains(t, body, "ForceListenOnlyMode", "what the rule matched")
	assert.Contains(t, body, "https://attack.mitre.org/techniques/T0813")
	assert.Contains(t, body, "Denial of Control")
	assert.Contains(t, body, "3 observations")
	// And a way through to the traffic itself.
	assert.Contains(t, body, "/events?")
	assert.Contains(t, body, "capture=part1")

	assert.Equal(t, http.StatusNotFound, get(t, h, "/findings/nope", nil).Code)
}

func TestTriageRoundTrip(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	storedFindings(t, s, project)

	rec := get(t, h, "/findings/f1", nil)
	token, cookie := csrfOf(t, rec)

	rec = postTo(t, h, "/findings/f1", url.Values{
		"csrf":     {token},
		"status":   {"investigating"},
		"assignee": {"rom"},
		"note":     {"planned maintenance?"},
	}, cookie)
	require.Equal(t, http.StatusSeeOther, rec.Code)

	body := get(t, h, "/findings/f1", nil).Body.String()
	assert.Contains(t, body, "Investigating")
	assert.Contains(t, body, "rom")
	assert.Contains(t, body, "planned maintenance?")

	stored, err := s.Finding(context.Background(), project.ID, "f1")
	require.NoError(t, err)
	assert.Equal(t, model.StatusInvestigating, stored.Status)

	// A status nobody defined is refused rather than stored.
	rec = postTo(t, h, "/findings/f1", url.Values{
		"csrf": {token}, "status": {"ignored"},
	}, cookie)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// And a post with no token at all gets nowhere.
	rec = postTo(t, h, "/findings/f1", url.Values{"status": {"resolved"}}, cookie)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestBulkTriageFromTheList(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	storedFindings(t, s, project)

	rec := get(t, h, "/findings", nil)
	token, cookie := csrfOf(t, rec)

	rec = postTo(t, h, "/findings", url.Values{
		"csrf":   {token},
		"status": {"accepted_risk"},
		"id":     {"f1", "f2"},
		"return": {"/findings?severity=high"},
	}, cookie)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	// The filter the analyst was looking at survives the round trip, rebuilt
	// rather than echoed.
	back, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "/findings", back.Path)
	assert.Equal(t, "high", back.Query().Get("severity"))
	assert.Equal(t, "1", back.Query().Get("saved"))

	open, err := s.CountOpenFindings(context.Background(), project.ID)
	require.NoError(t, err)
	assert.Zero(t, open, "both findings were accepted")

	// A return address pointing anywhere else is replaced rather than
	// followed: an open redirect out of a triage form would be a gift.
	rec = get(t, h, "/findings", nil)
	token, cookie = csrfOf(t, rec)
	rec = postTo(t, h, "/findings", url.Values{
		"csrf": {token}, "status": {"new"}, "id": {"f1"},
		"return": {"https://evil.example/"},
	}, cookie)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/findings?saved=1", rec.Header().Get("Location"))
}

// A browser served with a strict referrer policy posts forms with an opaque
// origin. The check reads Sec-Fetch-Site as well, so a real browser can save
// a form while a cross-site post still cannot.
func TestOpaqueOriginIsAcceptedOnlyForASameOriginPost(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	storedFindings(t, s, project)

	rec := get(t, h, "/findings/f1", nil)
	token, cookie := csrfOf(t, rec)

	post := func(headers map[string]string) int {
		req := httptest.NewRequest(http.MethodPost, "/findings/f1",
			strings.NewReader(url.Values{"csrf": {token}, "status": {"resolved"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		req.AddCookie(cookie)
		out := httptest.NewRecorder()
		h.ServeHTTP(out, req)
		return out.Code
	}

	assert.Equal(t, http.StatusSeeOther, post(map[string]string{
		"Origin": "null", "Sec-Fetch-Site": "same-origin",
	}), "a form posted from this GUI saves")
	assert.Equal(t, http.StatusForbidden, post(map[string]string{
		"Origin": "null", "Sec-Fetch-Site": "cross-site",
	}), "a post from another site does not")
	assert.Equal(t, http.StatusForbidden, post(map[string]string{
		"Origin": "null",
	}), "and neither does one that says nothing about where it came from")
}

func TestRulesPageListsWhatTheServerRuns(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	storedFindings(t, s, project)

	rec := get(t, h, "/rules", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "OT-001")
	assert.Contains(t, body, "OT-013")
	assert.Contains(t, body, "https://attack.mitre.org/techniques/T0813")
	// The rule that cannot fire says why.
	assert.Contains(t, body, "no engineering allow-list is configured")
	// And the ones with findings link to them.
	assert.Contains(t, body, "/findings?rule=OT-003")
	assert.Contains(t, body, "Run the rules again")
}

func TestRerunningTheRulesKeepsTheTriage(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	sampleTraffic(t, s, project)

	// A first run from the GUI finds what the sample traffic holds.
	rec := get(t, h, "/rules", nil)
	token, cookie := csrfOf(t, rec)
	rec = postTo(t, h, "/rules", url.Values{"csrf": {token}}, cookie)
	require.Equal(t, http.StatusSeeOther, rec.Code)

	ctx := context.Background()
	findings, total, err := s.Findings(ctx, store.FindingQuery{ProjectID: project.ID})
	require.NoError(t, err)
	require.NotZero(t, total, "the sample traffic holds a force listen only and a write")
	first := findings[0]
	assert.NotEmpty(t, first.Evidence.CaptureID)

	require.NoError(t, s.SetTriage(ctx, project.ID, first.ID,
		store.Triage{Status: model.StatusAcceptedRisk, Assignee: "rom"}))

	// A second run updates the findings and leaves the triage alone, which is
	// what makes re-running safe.
	rec = get(t, h, "/rules", nil)
	token, cookie = csrfOf(t, rec)
	rec = postTo(t, h, "/rules", url.Values{"csrf": {token}}, cookie)
	require.Equal(t, http.StatusSeeOther, rec.Code)

	again, err := s.Finding(ctx, project.ID, first.ID)
	require.NoError(t, err)
	require.NotNil(t, again)
	assert.Equal(t, model.StatusAcceptedRisk, again.Status)
	assert.Equal(t, "rom", again.Assignee)
}

func TestReadOnlyServerRefusesTriageAndReruns(t *testing.T) {
	h, s, project := serveWith(t, web.Options{ReadOnly: true})
	storedFindings(t, s, project)

	rec := get(t, h, "/findings/f1", nil)
	token, cookie := csrfOf(t, rec)
	assert.Equal(t, http.StatusForbidden,
		postTo(t, h, "/findings/f1", url.Values{"csrf": {token}, "status": {"resolved"}}, cookie).Code)
	assert.Equal(t, http.StatusForbidden,
		postTo(t, h, "/findings", url.Values{"csrf": {token}, "status": {"resolved"}, "id": {"f1"}}, cookie).Code)
	assert.Equal(t, http.StatusForbidden,
		postTo(t, h, "/rules", url.Values{"csrf": {token}}, cookie).Code)

	// And the page does not offer what the server would refuse.
	assert.NotContains(t, get(t, h, "/rules", nil).Body.String(), "Run the rules again")
}

func TestDashboardShowsWhatTheRulesFound(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	storedFindings(t, s, project)

	body := get(t, h, "/dashboard", nil).Body.String()
	assert.Contains(t, body, "Open findings")
	assert.Contains(t, body, "Findings by severity")
	assert.Contains(t, body, "/findings?open=1")
	assert.Contains(t, body, "most serious")
}

// postTo sends a form to any path, which the findings views need as well as
// the settings.
func postTo(t *testing.T, h http.Handler, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://example.com")
	req.Host = "example.com"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
