package store_test

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/store"
)

func open(t *testing.T) (*store.Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "project.db"))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, s.Close()) })
	return s, ctx
}

func TestOpenAppliesMigrationsAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "project.db")

	s, err := store.Open(ctx, path)
	require.NoError(t, err)
	v, err := s.SchemaVersion(ctx)
	require.NoError(t, err)
	assert.Positive(t, v, "migrations must be recorded")
	require.NoError(t, s.Close())

	// Reopening an existing database must not reapply migrations.
	s2, err := store.Open(ctx, path)
	require.NoError(t, err)
	defer s2.Close()
	v2, err := s2.SchemaVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, v, v2)
}

func TestEnsureProjectIsIdempotent(t *testing.T) {
	s, ctx := open(t)

	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)
	assert.Equal(t, "demo", p.Name)
	assert.Positive(t, p.ID)
	assert.False(t, p.CreatedAt.IsZero())

	again, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)
	assert.Equal(t, p.ID, again.ID, "the same name is the same project")

	other, err := s.EnsureProject(ctx, "other")
	require.NoError(t, err)
	assert.NotEqual(t, p.ID, other.ID)

	projects, err := s.Projects(ctx)
	require.NoError(t, err)
	assert.Len(t, projects, 2)
}

func capture(sha string) model.Capture {
	return model.Capture{
		ID:        sha,
		Path:      "testdata/pcaps/x.pcap",
		SHA256:    sha,
		Bytes:     10181,
		Packets:   118,
		LinkType:  "Ethernet",
		FirstSeen: time.Unix(1093521678, 945447000).UTC(),
		LastSeen:  time.Unix(1093523220, 676663000).UTC(),
	}
}

// Re-ingesting the same file into the same project must be caught, not
// silently duplicated.
func TestSaveCaptureDeduplicatesByDigest(t *testing.T) {
	s, ctx := open(t)
	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)

	id, inserted, err := s.SaveCapture(ctx, p.ID, capture("aa11"))
	require.NoError(t, err)
	assert.True(t, inserted)
	assert.Positive(t, id)

	again, inserted, err := s.SaveCapture(ctx, p.ID, capture("aa11"))
	require.NoError(t, err)
	assert.False(t, inserted, "the same digest is the same capture")
	assert.Equal(t, id, again)

	// The same file in another project is a separate capture.
	other, err := s.EnsureProject(ctx, "other")
	require.NoError(t, err)
	otherID, inserted, err := s.SaveCapture(ctx, other.ID, capture("aa11"))
	require.NoError(t, err)
	assert.True(t, inserted)
	assert.NotEqual(t, id, otherID)

	captures, err := s.Captures(ctx, p.ID)
	require.NoError(t, err)
	require.Len(t, captures, 1)
	assert.Equal(t, capture("aa11").SHA256, captures[0].SHA256)
	assert.Equal(t, uint64(118), captures[0].Packets)
	assert.True(t, capture("aa11").FirstSeen.Equal(captures[0].FirstSeen))
}

func sampleEvents() []model.Event {
	vlan := uint16(100)
	return []model.Event{
		{
			CaptureID:   "aa11",
			PacketIndex: 8,
			Timestamp:   time.Unix(1093521694, 211940000).UTC(),
			Flow: model.Flow{
				SrcMAC: "00:20:78:00:62:0d", DstMAC: "00:02:b3:ce:70:51",
				SrcIP: "10.0.0.57", DstIP: "10.0.0.3",
				SrcPort: 2578, DstPort: 502,
				Transport: model.TransportTCP,
				VLAN:      []uint16{vlan},
			},
			Protocol: "modbus", Direction: model.DirRequest, ServerPort: 502,
			Operation: "Diagnostics", FunctionCode: 8, Class: model.ClassControl,
			UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(0)),
			Attrs: map[string]string{"sub_function": "4", "sub_function_name": "ForceListenOnlyMode"},
		},
		{
			CaptureID:   "aa11",
			PacketIndex: 41,
			Timestamp:   time.Unix(1093522000, 292566000).UTC(),
			Flow: model.Flow{
				SrcIP: "10.0.0.3", DstIP: "10.0.0.57",
				SrcPort: 502, DstPort: 2578,
				Transport: model.TransportTCP,
			},
			Protocol: "modbus", Direction: model.DirResponse, ServerPort: 502,
			Operation: "ReportServerID", FunctionCode: 17, Class: model.ClassDiscovery,
			UnitID:   model.Ptr(uint16(10)),
			Identity: map[string]string{"report_server_id": "Wingpath Limited"},
		},
		{
			CaptureID:   "aa11",
			PacketIndex: 76,
			Timestamp:   time.Unix(1093522963, 917913000).UTC(),
			Flow: model.Flow{
				SrcIP: "10.0.0.57", DstIP: "10.0.0.8",
				SrcPort: 2585, DstPort: 502,
				Transport: model.TransportTCP,
			},
			Protocol: "modbus", Direction: model.DirRequest,
			Operation: "FramingError", FunctionCode: -1, Class: model.ClassOther,
			Malformed: true, Error: "malformed PDU: MBAP length field 34820 outside 2..254",
		},
	}
}

// Events must come back exactly as they went in: optional fields still nil,
// maps intact, timestamps to the nanosecond.
func TestEventRoundTrip(t *testing.T) {
	s, ctx := open(t)
	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)
	capturePK, _, err := s.SaveCapture(ctx, p.ID, capture("aa11"))
	require.NoError(t, err)

	w := s.NewEventWriter(p.ID, capturePK)
	for _, e := range sampleEvents() {
		require.NoError(t, w.Add(ctx, e))
	}
	require.NoError(t, w.Close(ctx))

	n, err := s.CountEvents(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)

	var got []model.Event
	require.NoError(t, s.EachEvent(ctx, p.ID, func(e model.Event) error {
		got = append(got, e)
		return nil
	}))
	require.Len(t, got, 3)
	assert.Equal(t, sampleEvents(), got, "events must round-trip unchanged")
}

// The writer batches, so a flush in the middle must not lose or duplicate.
func TestEventWriterBatches(t *testing.T) {
	s, ctx := open(t)
	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)
	capturePK, _, err := s.SaveCapture(ctx, p.ID, capture("bb22"))
	require.NoError(t, err)

	w := s.NewEventWriter(p.ID, capturePK)
	const total = 2500 // more than one batch
	for i := range total {
		e := sampleEvents()[0]
		e.PacketIndex = uint64(i + 1)
		require.NoError(t, w.Add(ctx, e))
	}
	require.NoError(t, w.Close(ctx))

	n, err := s.CountEvents(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(total), n)
	assert.Equal(t, uint64(total), w.Written())
}

func TestDeleteProjectCascades(t *testing.T) {
	s, ctx := open(t)
	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)
	capturePK, _, err := s.SaveCapture(ctx, p.ID, capture("cc33"))
	require.NoError(t, err)

	w := s.NewEventWriter(p.ID, capturePK)
	require.NoError(t, w.Add(ctx, sampleEvents()[0]))
	require.NoError(t, w.Close(ctx))

	require.NoError(t, s.DeleteProject(ctx, p.ID))

	n, err := s.CountEvents(ctx, p.ID)
	require.NoError(t, err)
	assert.Zero(t, n, "events must go with the project")

	captures, err := s.Captures(ctx, p.ID)
	require.NoError(t, err)
	assert.Empty(t, captures)
}

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
				Events:    40,
				FirstSeen: time.Unix(1093521694, 0).UTC(),
				LastSeen:  time.Unix(1093522000, 0).UTC(),
			}},
			Role: model.Role{
				Name: model.RoleController, Confidence: 80,
				Reasons: []string{"serves modbus"},
			},
			Attributes: []model.Attribute{{
				Field: "vendor", Value: "Wingpath Limited", Confidence: 70,
				Source: "modbus_report_server_id",
				Evidence: model.Evidence{
					CaptureID: "aa11", PacketIndex: 41,
					Timestamp: time.Unix(1093522000, 292566000).UTC(),
					Protocol:  "modbus", Operation: "ReportServerID", FunctionCode: 17,
				},
			}},
			Protocols: []model.ProtocolUsage{{
				Protocol: "modbus", Side: "server", Events: 40,
				Classes:   map[model.Classification]uint64{model.ClassRead: 10, model.ClassControl: 4},
				UnitIDs:   []uint16{10},
				FirstSeen: time.Unix(1093521694, 0).UTC(),
				LastSeen:  time.Unix(1093522000, 0).UTC(),
			}},
			Events:    40,
			FirstSeen: time.Unix(1093521694, 0).UTC(),
			LastSeen:  time.Unix(1093522000, 0).UTC(),
		},
		{
			Key:   "ip:10.0.0.57",
			Label: "10.0.0.57",
			IPs:   []string{"10.0.0.57"},
			Role: model.Role{
				Name: model.RoleOperator, Confidence: 60,
				Reasons: []string{"polls modbus servers"},
			},
			Protocols: []model.ProtocolUsage{{
				Protocol: "modbus", Side: "client", Events: 20,
				FirstSeen: time.Unix(1093521694, 0).UTC(),
				LastSeen:  time.Unix(1093522000, 0).UTC(),
			}},
			Events:    20,
			FirstSeen: time.Unix(1093521694, 0).UTC(),
			LastSeen:  time.Unix(1093522000, 0).UTC(),
		},
	}
}

func TestSaveAndQueryAssets(t *testing.T) {
	s, ctx := open(t)
	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)

	require.NoError(t, s.SaveAssets(ctx, p.ID, sampleAssets()))

	assets, total, err := s.Assets(ctx, store.AssetQuery{ProjectID: p.ID})
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	require.Len(t, assets, 2)

	// Sorted by event count, busiest first: the controller leads.
	assert.Equal(t, "mac:00:02:b3:ce:70:51", assets[0].Key)
	assert.Equal(t, model.RoleController, assets[0].Role.Name)
	assert.Equal(t, "Wingpath Limited", assets[0].Vendor())

	// Saving again replaces rather than duplicates: the inventory is derived.
	require.NoError(t, s.SaveAssets(ctx, p.ID, sampleAssets()))
	_, total, err = s.Assets(ctx, store.AssetQuery{ProjectID: p.ID})
	require.NoError(t, err)
	assert.Equal(t, 2, total)
}

func TestAssetDetailRoundTrip(t *testing.T) {
	s, ctx := open(t)
	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)
	require.NoError(t, s.SaveAssets(ctx, p.ID, sampleAssets()))

	got, err := s.Asset(ctx, p.ID, "mac:00:02:b3:ce:70:51")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, sampleAssets()[0], *got, "asset detail must round-trip unchanged")

	missing, err := s.Asset(ctx, p.ID, "ip:192.0.2.1")
	require.NoError(t, err)
	assert.Nil(t, missing, "a missing asset is not an error")
}

func TestAssetQueryFilters(t *testing.T) {
	s, ctx := open(t)
	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)
	require.NoError(t, s.SaveAssets(ctx, p.ID, sampleAssets()))

	tests := []struct {
		name     string
		query    store.AssetQuery
		wantKeys []string
	}{
		{
			name:     "by role",
			query:    store.AssetQuery{ProjectID: p.ID, Role: string(model.RoleOperator)},
			wantKeys: []string{"ip:10.0.0.57"},
		},
		{
			name:     "by protocol",
			query:    store.AssetQuery{ProjectID: p.ID, Protocol: "modbus"},
			wantKeys: []string{"mac:00:02:b3:ce:70:51", "ip:10.0.0.57"},
		},
		{
			name:     "by search on address",
			query:    store.AssetQuery{ProjectID: p.ID, Search: "10.0.0.3"},
			wantKeys: []string{"mac:00:02:b3:ce:70:51"},
		},
		{
			name:     "by search on vendor",
			query:    store.AssetQuery{ProjectID: p.ID, Search: "wingpath"},
			wantKeys: []string{"mac:00:02:b3:ce:70:51"},
		},
		{
			name:     "paged",
			query:    store.AssetQuery{ProjectID: p.ID, Limit: 1, Offset: 1},
			wantKeys: []string{"ip:10.0.0.57"},
		},
		{
			name:     "no match",
			query:    store.AssetQuery{ProjectID: p.ID, Search: "203.0.113.9"},
			wantKeys: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assets, _, err := s.Assets(ctx, tc.query)
			require.NoError(t, err)
			var keys []string
			for _, a := range assets {
				keys = append(keys, a.Key)
			}
			assert.Equal(t, tc.wantKeys, keys)
		})
	}
}

// A search string must be a value, never SQL.
func TestAssetSearchIsNotInjectable(t *testing.T) {
	s, ctx := open(t)
	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)
	require.NoError(t, s.SaveAssets(ctx, p.ID, sampleAssets()))

	assets, _, err := s.Assets(ctx, store.AssetQuery{
		ProjectID: p.ID,
		Search:    "'; DROP TABLE assets; --",
	})
	require.NoError(t, err)
	assert.Empty(t, assets)

	_, total, err := s.Assets(ctx, store.AssetQuery{ProjectID: p.ID})
	require.NoError(t, err)
	assert.Equal(t, 2, total, "the table must still be there")
}

func TestProtocolAndRoleFacets(t *testing.T) {
	s, ctx := open(t)
	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)
	require.NoError(t, s.SaveAssets(ctx, p.ID, sampleAssets()))

	protocols, err := s.AssetProtocols(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"modbus"}, protocols)

	roles, err := s.AssetRoles(ctx, p.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{string(model.RoleController), string(model.RoleOperator)}, roles)
}

func TestEventsByAddress(t *testing.T) {
	s, ctx := open(t)
	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)
	capturePK, _, err := s.SaveCapture(ctx, p.ID, capture("dd44"))
	require.NoError(t, err)

	w := s.NewEventWriter(p.ID, capturePK)
	for _, e := range sampleEvents() {
		require.NoError(t, w.Add(ctx, e))
	}
	require.NoError(t, w.Close(ctx))

	// 10.0.0.3 appears as the source of one event and the destination of
	// another, and both must match.
	got, err := s.Events(ctx, store.EventQuery{ProjectID: p.ID, Addresses: []string{"10.0.0.3"}})
	require.NoError(t, err)
	assert.Len(t, got, 2)

	// A multi-homed asset matches on any of its addresses.
	got, err = s.Events(ctx, store.EventQuery{
		ProjectID: p.ID,
		Addresses: []string{"10.0.0.8", "00:20:78:00:62:0d"},
	})
	require.NoError(t, err)
	assert.Len(t, got, 2)

	// Newest first, so a detail page shows recent activity.
	got, err = s.Events(ctx, store.EventQuery{ProjectID: p.ID, Limit: 1})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, uint64(76), got[0].PacketIndex)

	got, err = s.Events(ctx, store.EventQuery{ProjectID: p.ID, Addresses: []string{"203.0.113.9"}})
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestUpdateAndDeleteCapture(t *testing.T) {
	s, ctx := open(t)
	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)

	// A capture row exists before its events do, so it starts without counts.
	pk, inserted, err := s.SaveCapture(ctx, p.ID, model.Capture{
		ID: "ee55", Path: "x.pcap", SHA256: "ee55",
	})
	require.NoError(t, err)
	require.True(t, inserted)

	w := s.NewEventWriter(p.ID, pk)
	require.NoError(t, w.Add(ctx, sampleEvents()[0]))
	require.NoError(t, w.Close(ctx))

	done := capture("ee55")
	require.NoError(t, s.UpdateCapture(ctx, pk, done))

	captures, err := s.Captures(ctx, p.ID)
	require.NoError(t, err)
	require.Len(t, captures, 1)
	assert.Equal(t, uint64(118), captures[0].Packets)
	assert.Equal(t, "Ethernet", captures[0].LinkType)
	assert.True(t, done.FirstSeen.Equal(captures[0].FirstSeen))

	// Deleting the capture takes its events with it, which is what a
	// re-ingest of the same file relies on.
	require.NoError(t, s.DeleteCapture(ctx, pk))
	captures, err = s.Captures(ctx, p.ID)
	require.NoError(t, err)
	assert.Empty(t, captures)
	n, err := s.CountEvents(ctx, p.ID)
	require.NoError(t, err)
	assert.Zero(t, n)
}

// sortableAssets are three assets that differ in every sortable column, so
// that each column's order is distinguishable from the others.
func sortableAssets() []model.Asset {
	base := time.Unix(1093521694, 0).UTC()
	return []model.Asset{
		{
			Key: "mac:aa:00:00:00:00:01", Label: "10.0.0.3",
			Role:       model.Role{Name: model.RoleController, Confidence: 80},
			Attributes: []model.Attribute{{Field: "vendor", Value: "Siemens", Confidence: 90}},
			Protocols: []model.ProtocolUsage{
				{Protocol: "s7comm", Side: "server", Events: 7},
			},
			Events: 7, FirstSeen: base, LastSeen: base.Add(3 * time.Hour),
		},
		{
			Key: "mac:aa:00:00:00:00:02", Label: "10.0.0.20",
			Role: model.Role{Name: model.RoleOperator, Confidence: 60},
			Protocols: []model.ProtocolUsage{
				{Protocol: "modbus", Side: "client", Events: 90},
			},
			Events: 90, FirstSeen: base, LastSeen: base.Add(time.Hour),
		},
		{
			Key: "mac:aa:00:00:00:00:03", Label: "10.0.0.7",
			Role:       model.Role{Name: model.RoleEngineering, Confidence: 70},
			Attributes: []model.Attribute{{Field: "vendor", Value: "ABB", Confidence: 90}},
			Protocols: []model.ProtocolUsage{
				{Protocol: "goose", Side: "server", Events: 30},
			},
			Events: 30, FirstSeen: base, LastSeen: base.Add(2 * time.Hour),
		},
	}
}

// The asset list is paged, so its order has to be decided in SQL: sorting a
// page after it has been read would sort the wrong fifty assets.
func TestAssetQuerySortsEveryColumn(t *testing.T) {
	s, ctx := open(t)
	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)
	require.NoError(t, s.SaveAssets(ctx, p.ID, sortableAssets()))

	tests := []struct {
		column string
		asc    []string
	}{
		// The label, which is what the address column shows.
		{column: "address", asc: []string{"10.0.0.20", "10.0.0.3", "10.0.0.7"}},
		{column: "role", asc: []string{"10.0.0.7", "10.0.0.20", "10.0.0.3"}},
		// An unknown vendor sorts last whichever way the column is read.
		{column: "vendor", asc: []string{"10.0.0.7", "10.0.0.3", "10.0.0.20"}},
		{column: "protocols", asc: []string{"10.0.0.7", "10.0.0.20", "10.0.0.3"}},
		{column: "events", asc: []string{"10.0.0.3", "10.0.0.7", "10.0.0.20"}},
		{column: "seen", asc: []string{"10.0.0.20", "10.0.0.7", "10.0.0.3"}},
	}

	for _, tc := range tests {
		t.Run(tc.column, func(t *testing.T) {
			_, ok := store.AssetSortColumns[tc.column]
			require.True(t, ok, "the column must be one the store will order by")

			got, _, err := s.Assets(ctx, store.AssetQuery{ProjectID: p.ID, Sort: tc.column})
			require.NoError(t, err)
			assert.Equal(t, tc.asc, labels(got), "ascending")

			got, _, err = s.Assets(ctx, store.AssetQuery{
				ProjectID: p.ID, Sort: tc.column, Desc: true,
			})
			require.NoError(t, err)
			if tc.column == "vendor" {
				// Reversing the column does not promote the unknown value:
				// a missing vendor is not the largest one either.
				assert.Equal(t, []string{"10.0.0.3", "10.0.0.7", "10.0.0.20"}, labels(got),
					"descending, unknown last")
				return
			}
			assert.Equal(t, reversed(tc.asc), labels(got), "descending")
		})
	}
}

// Without a sort the list keeps the order it is most useful in, and a column
// the store does not know is ignored rather than refused.
func TestAssetQueryDefaultAndUnknownSort(t *testing.T) {
	s, ctx := open(t)
	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)
	require.NoError(t, s.SaveAssets(ctx, p.ID, sortableAssets()))

	for _, sortColumn := range []string{"", "nonsense", "a.events); DROP TABLE assets --"} {
		got, total, err := s.Assets(ctx, store.AssetQuery{ProjectID: p.ID, Sort: sortColumn})
		require.NoError(t, err, "sort %q", sortColumn)
		assert.Equal(t, 3, total)
		assert.Equal(t, []string{"10.0.0.20", "10.0.0.7", "10.0.0.3"}, labels(got),
			"busiest first, for sort %q", sortColumn)
	}
}

// Paging a sorted list has to be stable: without a tiebreaker two assets with
// the same value could swap places between pages and one of them would never
// be seen.
func TestSortedPagingIsStable(t *testing.T) {
	s, ctx := open(t)
	p, err := s.EnsureProject(ctx, "demo")
	require.NoError(t, err)

	// Six assets that all share a role, so only the tiebreaker separates them.
	assets := make([]model.Asset, 0, 6)
	for i := range 6 {
		assets = append(assets, model.Asset{
			Key:    "mac:aa:00:00:00:00:0" + strconv.Itoa(i),
			Label:  "10.0.0." + strconv.Itoa(i),
			Role:   model.Role{Name: model.RoleController, Confidence: 80},
			Events: 10,
		})
	}
	require.NoError(t, s.SaveAssets(ctx, p.ID, assets))

	var paged []string
	for offset := 0; offset < 6; offset += 2 {
		got, _, err := s.Assets(ctx, store.AssetQuery{
			ProjectID: p.ID, Sort: "role", Limit: 2, Offset: offset,
		})
		require.NoError(t, err)
		paged = append(paged, labels(got)...)
	}
	assert.Len(t, paged, 6)
	assert.Len(t, dedupe(paged), 6, "every asset appears exactly once across the pages")
}

func labels(assets []model.Asset) []string {
	out := make([]string, 0, len(assets))
	for _, a := range assets {
		out = append(out, a.Label)
	}
	return out
}

func reversed(xs []string) []string {
	out := make([]string, 0, len(xs))
	for i := len(xs) - 1; i >= 0; i-- {
		out = append(out, xs[i])
	}
	return out
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
