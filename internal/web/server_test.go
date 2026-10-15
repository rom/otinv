package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	_ "github.com/rom/otinv/internal/dissect/modbus"
	"github.com/rom/otinv/internal/ingest"
	"github.com/rom/otinv/internal/inventory"
	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/store"
	"github.com/rom/otinv/internal/web"
	"github.com/rom/otinv/internal/web/templates"
)

var seen = time.Unix(1093521694, 0).UTC()

func sampleAssets() []model.Asset {
	vlan := uint16(100)
	return []model.Asset{
		{
			Key:   "mac:00:02:b3:ce:70:51",
			Label: "10.0.0.3",
			MACs:  []string{"00:02:b3:ce:70:51"},
			IPs:   []string{"10.0.0.3"},
			VLANs: []uint16{vlan},
			Addresses: []model.Address{{
				MAC: "00:02:b3:ce:70:51", IP: "10.0.0.3", VLAN: &vlan,
				Events: 32, FirstSeen: seen, LastSeen: seen.Add(time.Hour),
			}},
			Role: model.Role{
				Name: model.RoleController, Confidence: 80,
				Reasons: []string{"serves modbus (32 operations observed)"},
			},
			Level: model.Level{
				Value: 1, Confidence: 80,
				Reasons: []string{"serves modbus (32 operations observed)"},
			},
			Attributes: []model.Attribute{{
				Field: "vendor", Value: "Wingpath Limited", Confidence: 70,
				Source: "modbus_ReportServerID",
				Evidence: model.Evidence{
					CaptureID: "part1", PacketIndex: 41, Timestamp: seen,
					Protocol: "modbus", Operation: "ReportServerID", FunctionCode: 17,
				},
			}},
			Protocols: []model.ProtocolUsage{{
				Protocol: "modbus", Side: "server", Events: 32,
				Classes: map[model.Classification]uint64{model.ClassControl: 8},
				UnitIDs: []uint16{10}, FirstSeen: seen, LastSeen: seen.Add(time.Hour),
			}},
			Events: 32, FirstSeen: seen, LastSeen: seen.Add(time.Hour),
		},
		{
			Key:   "mac:00:20:78:00:62:0d",
			Label: "10.0.0.57",
			MACs:  []string{"00:20:78:00:62:0d"},
			IPs:   []string{"10.0.0.57"},
			Role: model.Role{
				Name: model.RoleOperator, Confidence: 60,
				Reasons: []string{"issues modbus requests (38 observed)"},
			},
			Level: model.Level{
				Value: 2, Confidence: 65,
				Reasons: []string{"polls modbus devices (38 operations observed)"},
			},
			Protocols: []model.ProtocolUsage{{
				Protocol: "modbus", Side: "client", Events: 38,
				FirstSeen: seen, LastSeen: seen.Add(time.Hour),
			}},
			Events: 38, FirstSeen: seen, LastSeen: seen.Add(time.Hour),
		},
	}
}

func serve(t *testing.T, assets []model.Asset) (http.Handler, *store.Store, model.Project) {
	t.Helper()
	ctx := context.Background()

	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "project.db"))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, s.Close()) })

	project, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)
	require.NoError(t, s.SaveAssets(ctx, project.ID, assets))

	srv, err := web.New(web.Options{Store: s, Project: project})
	require.NoError(t, err)
	return srv.Handler(), s, project
}

func get(t *testing.T, h http.Handler, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Binding beyond loopback would expose OT data with no authentication in
// front of it, so the server refuses to start rather than doing that.
func TestListenAddressPolicy(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "p.db"))
	require.NoError(t, err)
	defer s.Close()

	tests := []struct {
		addr      string
		wantError bool
	}{
		{addr: "127.0.0.1:8080"},
		{addr: "localhost:8080"},
		{addr: "[::1]:8080"},
		{addr: "127.0.0.5:9000"},
		{addr: "0.0.0.0:8080", wantError: true},
		{addr: ":8080", wantError: true},
		{addr: "192.168.1.5:8080", wantError: true},
		{addr: "plc-inventory.local:8080", wantError: true},
	}

	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			_, err := web.New(web.Options{Store: s, Addr: tc.addr})
			if tc.wantError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "authentication")
				return
			}
			require.NoError(t, err)
		})
	}
}

// The root lands on the dashboard: a reader opening the GUI wants the project
// at a glance before any one table of it.
func TestRootRedirectsToDashboard(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())
	rec := get(t, h, "/", nil)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/dashboard", rec.Header().Get("Location"))
}

func TestAssetListShowsInventory(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())
	rec := get(t, h, "/assets", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"),
		"pages of OT data must not be cached")

	assert.Contains(t, body, "10.0.0.3")
	assert.Contains(t, body, "10.0.0.57")
	assert.Contains(t, body, "Wingpath Limited")
	assert.Contains(t, body, "PLC / RTU / IED")
	assert.Contains(t, body, "HMI / SCADA")
	assert.Contains(t, body, "modbus (server)")
	assert.Contains(t, body, "2 matching assets")
	// Busiest first.
	assert.Less(t, strings.Index(body, "10.0.0.57"), strings.Index(body, "10.0.0.3"))
}

// The filter panel offers the vendors the project holds, so a vendor read
// from a MAC block can be picked rather than typed.
func TestAssetListOffersAVendorFacet(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())
	body := get(t, h, "/assets", nil).Body.String()

	assert.Contains(t, body, `<select name="vendor">`)
	assert.Contains(t, body, `<option value="Wingpath Limited">Wingpath Limited</option>`)

	selected := get(t, h, "/assets?vendor=Wingpath+Limited", nil).Body.String()
	assert.Contains(t, selected, `<option value="Wingpath Limited" selected>`)
}

func TestAssetListFilters(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())

	tests := []struct {
		name      string
		target    string
		wantIn    string
		wantNotIn string
		wantCount string
	}{
		{
			name:      "by role",
			target:    "/assets?role=plc_rtu_ied",
			wantIn:    "10.0.0.3",
			wantNotIn: "10.0.0.57",
			wantCount: "1 matching assets",
		},
		{
			name:      "by search",
			target:    "/assets?q=wingpath",
			wantIn:    "Wingpath Limited",
			wantNotIn: "10.0.0.57",
			wantCount: "1 matching assets",
		},
		{
			name:      "by protocol",
			target:    "/assets?protocol=modbus",
			wantIn:    "10.0.0.3",
			wantCount: "2 matching assets",
		},
		{
			name:      "by vendor",
			target:    "/assets?vendor=Wingpath+Limited",
			wantIn:    "10.0.0.3",
			wantNotIn: "10.0.0.57",
			wantCount: "1 matching assets",
		},
		{
			name:      "by vendor, which is exact",
			target:    "/assets?vendor=Wingpath",
			wantIn:    "No assets match this filter.",
			wantCount: "0 matching assets",
		},
		{
			name:      "no match",
			target:    "/assets?q=203.0.113.9",
			wantIn:    "No assets match this filter.",
			wantNotIn: "10.0.0.3",
			wantCount: "0 matching assets",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := get(t, h, tc.target, nil)
			require.Equal(t, http.StatusOK, rec.Code)
			body := rec.Body.String()
			assert.Contains(t, body, tc.wantIn)
			assert.Contains(t, body, tc.wantCount)
			if tc.wantNotIn != "" {
				assert.NotContains(t, body, tc.wantNotIn)
			}
		})
	}
}

// htmx asks for the table alone, which is what keeps filtering and paging on
// the server.
func TestAssetListHTMXFragment(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())
	rec := get(t, h, "/assets", map[string]string{"HX-Request": "true"})
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, `id="asset-table"`)
	assert.Contains(t, body, "10.0.0.3")
	assert.NotContains(t, body, "<html", "a fragment must not repeat the page chrome")
	assert.NotContains(t, body, "<form", "the filter form stays where it is")
}

func TestAssetListPaging(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())

	rec := get(t, h, "/assets?limit=1", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "2 matching assets")
	assert.Contains(t, body, "1 / 2")
	assert.Contains(t, body, "offset=1", "the next link keeps the filter state")
	assert.Contains(t, body, "10.0.0.57")
	assert.NotContains(t, body, ">10.0.0.3<")

	rec = get(t, h, "/assets?limit=1&offset=1", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "2 / 2")
	assert.Contains(t, rec.Body.String(), "10.0.0.3")
}

func TestAssetDetailShowsEvidence(t *testing.T) {
	h, s, project := serve(t, sampleAssets())

	ctx := context.Background()
	capturePK, _, err := s.SaveCapture(ctx, project.ID, model.Capture{
		ID: "part1", Path: "testdata/pcaps/part1.pcap", SHA256: "abc123",
		Packets: 118, LinkType: "Ethernet", FirstSeen: seen, LastSeen: seen.Add(time.Hour),
	})
	require.NoError(t, err)

	w := s.NewEventWriter(project.ID, capturePK)
	require.NoError(t, w.Add(ctx, model.Event{
		CaptureID: "part1", PacketIndex: 8, Timestamp: seen,
		Flow: model.Flow{
			SrcIP: "10.0.0.57", DstIP: "10.0.0.3", SrcPort: 2578, DstPort: 502,
			Transport: model.TransportTCP,
		},
		Protocol: "modbus", Direction: model.DirRequest,
		Operation: "Diagnostics", FunctionCode: 8, Class: model.ClassControl,
		UnitID: model.Ptr(uint16(10)),
	}))
	// A control command whose select step is what distinguishes arming it
	// from issuing it.
	require.NoError(t, w.Add(ctx, model.Event{
		CaptureID: "part1", PacketIndex: 9, Timestamp: seen,
		Flow: model.Flow{
			SrcIP: "10.0.0.57", DstIP: "10.0.0.3", SrcPort: 2578, DstPort: 2404,
			Transport: model.TransportTCP,
		},
		Protocol: "iec104", Direction: model.DirRequest, ServerPort: 2404,
		Operation: "C_SC_NA_1", FunctionCode: 45, Class: model.ClassControl,
		UnitID: model.Ptr(uint16(3)), Address: model.Ptr(uint32(10010)),
		Attrs: map[string]string{"value": "on", "command_mode": "select"},
	}))
	// A report, which addresses its object by name rather than by number.
	require.NoError(t, w.Add(ctx, model.Event{
		CaptureID: "part1", PacketIndex: 10, Timestamp: seen,
		Flow: model.Flow{
			SrcIP: "10.0.0.3", DstIP: "10.0.0.57", SrcPort: 102, DstPort: 1069,
			Transport: model.TransportTCP,
		},
		Protocol: "mms", Direction: model.DirResponse, ServerPort: 102,
		Operation: "informationReport", FunctionCode: 0, Class: model.ClassRead,
		Attrs: map[string]string{
			"object":    "RPT",
			"report_id": "AA1C1Q01A1LD0/LLN0$rcb_I02",
		},
	}))
	require.NoError(t, w.Close(ctx))

	rec := get(t, h, "/assets/mac:00:02:b3:ce:70:51", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.Contains(t, body, "10.0.0.3")
	assert.Contains(t, body, "PLC / RTU / IED")
	assert.Contains(t, body, "80%")
	assert.Contains(t, body, "serves modbus (32 operations observed)", "the role must say why")
	assert.Contains(t, body, "Wingpath Limited")
	assert.Contains(t, body, "ReportServerID", "the identity evidence names the operation")
	assert.Contains(t, body, "41", "and the packet that proves it")
	assert.Contains(t, body, "00:02:b3:ce:70:51")
	assert.Contains(t, body, "control 8", "the class histogram")
	assert.Contains(t, body, "Diagnostics", "the asset's own events")
	assert.Contains(t, body, "10.0.0.57", "with the peer it talked to")
	assert.Contains(t, body, "value on · select",
		"a command shows whether it was the select or the execute step")
	assert.Contains(t, body, "AA1C1Q01A1LD0/LLN0$rcb_I02",
		"an object addressed by name is named in the detail line")
}

func TestAssetDetailNotFound(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())
	rec := get(t, h, "/assets/ip:192.0.2.1", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestSecurityHeaders(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())
	for _, target := range []string{"/assets", "/static/vendor/htmx.min.js", "/healthz"} {
		t.Run(target, func(t *testing.T) {
			rec := get(t, h, target, nil)
			require.Equal(t, http.StatusOK, rec.Code)
			csp := rec.Header().Get("Content-Security-Policy")
			assert.Contains(t, csp, "default-src 'self'")
			assert.Contains(t, csp, "frame-ancestors 'none'")
			assert.NotContains(t, csp, "unsafe-inline", "no inline scripts anywhere")
			assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
			// same-origin rather than no-referrer: a referrer still never
			// leaves this origin, and a browser posting a form keeps sending
			// a real Origin header, which the CSRF check reads.
			assert.Equal(t, "same-origin", rec.Header().Get("Referrer-Policy"))
			assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
		})
	}
}

// CLAUDE.md: never render packet bytes as HTML. Anything a device put on the
// wire reaches these pages as text, so it must arrive escaped.
func TestDeviceSuppliedStringsAreEscaped(t *testing.T) {
	hostile := sampleAssets()
	hostile[0].Attributes[0].Value = `<script>alert('pwn')</script>`
	hostile[0].Label = `10.0.0.3"><img src=x onerror=alert(1)>`
	hostile[0].Role.Reasons = []string{`<img src=x onerror=alert(2)>`}

	h, _, _ := serve(t, hostile)

	for _, target := range []string{"/assets", "/assets/mac:00:02:b3:ce:70:51"} {
		t.Run(target, func(t *testing.T) {
			rec := get(t, h, target, nil)
			require.Equal(t, http.StatusOK, rec.Code)
			body := rec.Body.String()
			assert.NotContains(t, body, "<script>alert")
			assert.NotContains(t, body, "<img src=x")
			assert.Contains(t, body, "&lt;script&gt;")
		})
	}
}

// The GUI must work on an air-gapped laptop: every asset is served from this
// origin, with no CDN anywhere.
func TestNoExternalOrigins(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())
	rec := get(t, h, "/assets", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	assert.NotContains(t, body, "https://")
	assert.NotContains(t, body, "http://")
	assert.Contains(t, body, `src="/static/vendor/htmx.min.js"`)
	assert.Contains(t, body, `href="/static/css/app.css"`)

	js := get(t, h, "/static/vendor/htmx.min.js", nil)
	require.Equal(t, http.StatusOK, js.Code)
	assert.Contains(t, js.Header().Get("Content-Type"), "javascript")
	assert.Contains(t, js.Body.String(), "htmx")

	css := get(t, h, "/static/css/app.css", nil)
	require.Equal(t, http.StatusOK, css.Code)
	assert.Contains(t, css.Header().Get("Content-Type"), "text/css")
}

func TestUILanguage(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())

	tests := []struct {
		name   string
		target string
		header map[string]string
		want   string
	}{
		{name: "default english", target: "/assets", want: "<title>Assets · otinv</title>"},
		{name: "explicit swedish", target: "/assets?lang=sv", want: "<title>Tillgångar · otinv</title>"},
		{
			name:   "accept-language swedish",
			target: "/assets",
			header: map[string]string{"Accept-Language": "sv-SE,sv;q=0.9,en;q=0.8"},
			want:   "Tillgångar",
		},
		{
			name:   "unknown language falls back",
			target: "/assets",
			header: map[string]string{"Accept-Language": "de-DE"},
			want:   "Assets",
		},
		{
			name:   "explicit choice beats the header",
			target: "/assets?lang=en",
			header: map[string]string{"Accept-Language": "sv"},
			want:   "Assets",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := get(t, h, tc.target, tc.header)
			require.Equal(t, http.StatusOK, rec.Code)
			assert.Contains(t, rec.Body.String(), tc.want)
		})
	}
}

func TestTranslationFallbacks(t *testing.T) {
	assert.Equal(t, "Assets", templates.T(templates.LangEN, "assets.title"))
	assert.Equal(t, "Tillgångar", templates.T(templates.LangSV, "assets.title"))
	assert.Equal(t, "Assets", templates.T(templates.Lang("de"), "assets.title"),
		"an unknown language falls back to English")
	assert.Equal(t, "nope.missing", templates.T(templates.LangEN, "nope.missing"),
		"a missing key is visible rather than blank")
}

func TestCapturesPage(t *testing.T) {
	h, s, project := serve(t, sampleAssets())

	rec := get(t, h, "/captures", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "No captures ingested yet.")

	_, _, err := s.SaveCapture(context.Background(), project.ID, model.Capture{
		ID: "part1", Path: "testdata/pcaps/modbus_test_data_part1.pcap",
		SHA256:  "94942b3d014810710f50836c95d3faf6df6e6370a6560bae541397c1df50213d",
		Packets: 118, LinkType: "Ethernet", FirstSeen: seen, LastSeen: seen.Add(time.Hour),
	})
	require.NoError(t, err)

	rec = get(t, h, "/captures", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "modbus_test_data_part1.pcap")
	assert.Contains(t, body, "94942b3d0148")
	assert.Contains(t, body, "118")
}

// The whole slice, end to end: a public capture becomes a browsable
// inventory.
func TestEndToEndFromCaptureToPage(t *testing.T) {
	ctx := context.Background()
	root, err := filepath.Abs("../..")
	require.NoError(t, err)

	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "project.db"))
	require.NoError(t, err)
	defer s.Close()

	project, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)

	res, err := ingest.File(filepath.Join(root, "testdata", "pcaps", "modbus_test_data_part1.pcap"),
		ingest.Options{Registry: dissect.Default()})
	require.NoError(t, err)

	capturePK, inserted, err := s.SaveCapture(ctx, project.ID, res.Capture)
	require.NoError(t, err)
	require.True(t, inserted)

	w := s.NewEventWriter(project.ID, capturePK)
	_, err = ingest.File(filepath.Join(root, "testdata", "pcaps", "modbus_test_data_part1.pcap"),
		ingest.Options{
			CaptureID: res.Capture.ID,
			Registry:  dissect.Default(),
			Sink: func(e model.Event) {
				require.NoError(t, w.Add(ctx, e))
			},
		})
	require.NoError(t, err)
	require.NoError(t, w.Close(ctx))

	assets, err := inventory.Rebuild(ctx, s, s, project.ID)
	require.NoError(t, err)
	require.Len(t, assets, 3)

	srv, err := web.New(web.Options{Store: s, Project: project})
	require.NoError(t, err)
	h := srv.Handler()

	rec := get(t, h, "/assets", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "3 matching assets")
	assert.Contains(t, body, "Wingpath Limited", "the device identity from the capture")
	assert.Contains(t, body, "10.0.0.3")
	assert.Contains(t, body, "PLC / RTU / IED")

	rec = get(t, h, "/assets/mac:00:02:b3:ce:70:51", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	detail := rec.Body.String()
	assert.Contains(t, detail, "ReportServerID")
	assert.Contains(t, detail, "ForceListenOnlyMode", "the control operation is visible on the device")
	assert.Contains(t, detail, "control")
}

// Every column of every table sorts, both ways, and the state lives in the
// URL so that a sorted view is as deep-linkable as a filtered one.
func TestAssetListColumnsAreSortable(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())

	// An unsorted list offers every column, and claims none of them as the
	// one it is sorted by.
	rec := get(t, h, "/assets", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	for _, column := range []string{"address", "role", "level", "vendor", "protocols", "events", "seen"} {
		assert.Contains(t, body, "sort="+column, "the %s column must offer a sort link", column)
	}
	assert.Equal(t, 7, strings.Count(body, `aria-sort="none"`))

	// Each column, once sorted, says which way it is sorted and offers the
	// other way. The counts and timestamps start at the largest, because that
	// is the end worth reading first.
	tests := []struct {
		target    string
		direction string
		toggle    string
	}{
		{target: "/assets?sort=address", direction: `aria-sort="ascending"`, toggle: "dir=desc"},
		{target: "/assets?sort=address&dir=desc", direction: `aria-sort="descending"`, toggle: "sort=address"},
		{target: "/assets?sort=events&dir=desc", direction: `aria-sort="descending"`, toggle: "sort=events"},
		{target: "/assets?sort=seen&dir=desc", direction: `aria-sort="descending"`, toggle: "sort=seen"},
	}
	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			rec := get(t, h, tc.target, nil)
			require.Equal(t, http.StatusOK, rec.Code)
			body := rec.Body.String()
			assert.Contains(t, body, tc.direction)
			assert.Equal(t, 6, strings.Count(body, `aria-sort="none"`),
				"only the sorted column claims a direction")
			assert.Contains(t, body, tc.toggle, "the header must offer the other direction")
		})
	}
}

// The order decides which assets a page holds, so a sort is applied in the
// store rather than to the page after it has been read.
func TestAssetListSortOrdersTheWholeInventory(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())

	// sampleAssets holds 10.0.0.3 with 32 events and 10.0.0.57 with 38.
	ascending := get(t, h, "/assets?sort=events", nil).Body.String()
	assert.Less(t, rowIndex(ascending, "10.0.0.3"), rowIndex(ascending, "10.0.0.57"),
		"the quietest asset comes first ascending")

	descending := get(t, h, "/assets?sort=events&dir=desc", nil).Body.String()
	assert.Less(t, rowIndex(descending, "10.0.0.57"), rowIndex(descending, "10.0.0.3"),
		"and the busiest comes first descending")
}

// A paged, filtered, sorted list has to keep all three in its links, or
// following one of them loses the other two.
func TestAssetListSortSurvivesFilteringAndPaging(t *testing.T) {
	assets := make([]model.Asset, 0, 4)
	for i := range 4 {
		assets = append(assets, model.Asset{
			Key:    "ip:10.0.0." + strconv.Itoa(i),
			Label:  "10.0.0." + strconv.Itoa(i),
			Role:   model.Role{Name: model.RoleController, Confidence: 80},
			Events: uint64(i),
		})
	}
	h, _, _ := serve(t, assets)

	rec := get(t, h, "/assets?sort=events&role=plc_rtu_ied&limit=2", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "sort=events")
	assert.Contains(t, body, "role=plc_rtu_ied")
	assert.Contains(t, body, "offset=2", "the pager keeps the sort and the filter")

	// A sort link returns to the first page, because the rows a second page
	// holds depend on the order.
	assert.NotContains(t, body, "offset=2&amp;role=plc_rtu_ied&amp;sort=seen")
}

// A link from an older version, or one edited by hand, must not break the
// page: an unknown column is ignored.
func TestAssetListIgnoresAnUnknownSortColumn(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())

	for _, target := range []string{
		"/assets?sort=nonsense",
		"/assets?sort=a.events);DROP+TABLE+assets--",
		"/assets?sort=events&dir=sideways",
	} {
		rec := get(t, h, target, nil)
		assert.Equal(t, http.StatusOK, rec.Code, target)
		assert.Contains(t, rec.Body.String(), "10.0.0.3", target)
	}
}

// rowIndex is where an asset's row begins in the rendered table, which is
// what says whether one row comes before another. The label also appears in
// the row's link, so a plain string search would find either.
func rowIndex(body, label string) int {
	table := strings.Index(body, "<tbody>")
	if table < 0 {
		return -1
	}
	return strings.Index(body[table:], ">"+label+"</a>")
}

// The detail page's four tables share one sort state, with each column named
// for the table it belongs to.
func TestAssetDetailTablesAreSortable(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())

	rec := get(t, h, "/assets/mac:00:02:b3:ce:70:51", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	for _, column := range []string{
		"identity.field", "identity.confidence",
		"addresses.mac", "addresses.ip", "addresses.vlan",
		"protocols.protocol", "protocols.events",
		"events.time", "events.packet",
	} {
		assert.Contains(t, body, "sort="+column, "the %s column must offer a sort link", column)
	}

	// Sorting one table claims a direction for one column only.
	rec = get(t, h, "/assets/mac:00:02:b3:ce:70:51?sort=events.packet&dir=asc", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body = rec.Body.String()
	assert.Equal(t, 1, strings.Count(body, `aria-sort="ascending"`))
	assert.Equal(t, 0, strings.Count(body, `aria-sort="descending"`))
}

func TestCaptureListIsSortable(t *testing.T) {
	h, s, project := serve(t, sampleAssets())
	ctx := context.Background()

	for i, c := range []model.Capture{
		{ID: "b", Path: "b.pcap", SHA256: "bbb", Packets: 10, LinkType: "Ethernet"},
		{ID: "a", Path: "a.pcap", SHA256: "aaa", Packets: 90, LinkType: "Ethernet"},
	} {
		c.FirstSeen = seen.Add(time.Duration(i) * time.Hour)
		c.LastSeen = c.FirstSeen.Add(time.Minute)
		_, _, err := s.SaveCapture(ctx, project.ID, c)
		require.NoError(t, err)
	}

	rec := get(t, h, "/captures?sort=packets&dir=desc", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Less(t, strings.Index(body, "a.pcap"), strings.Index(body, "b.pcap"),
		"the largest capture comes first")
	assert.Contains(t, body, `aria-sort="descending"`)
	assert.Contains(t, body, "sort=path")

	ascending := get(t, h, "/captures?sort=packets", nil).Body.String()
	assert.Less(t, strings.Index(ascending, "b.pcap"), strings.Index(ascending, "a.pcap"))
}

// The header is a link, which is what gives it keyboard access for free:
// CLAUDE.md asks for keyboard navigation in tables, and a link is reachable
// by tab and activated by enter without a line of script.
func TestSortHeadersAreLinks(t *testing.T) {
	h, _, _ := serve(t, sampleAssets())
	body := get(t, h, "/assets", nil).Body.String()

	assert.Contains(t, body, `<th aria-sort="none" class="sortable"><a href="/assets?`)
	assert.Contains(t, body, `hx-target="#asset-table"`,
		"the asset table is swapped on its own, so its headers go through htmx")

	// The only script on the page is the vendored htmx, which the strict CSP
	// requires: sorting adds no inline script of its own.
	assert.Equal(t, 1, strings.Count(body, "<script"))
	assert.Contains(t, body, `<script src="/static/vendor/htmx.min.js" defer></script>`)
}
