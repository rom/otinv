package web_test

import (
	"context"
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
		Attrs:  map[string]string{"anomaly": "force_listen_only", "sub_function_name": "ForceListenOnly"},
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
