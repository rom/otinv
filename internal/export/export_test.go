package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/store"
)

func TestParseKinds(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want []Kind
		err  string
	}{
		{name: "one", spec: "assets", want: []Kind{KindAssets}},
		{name: "spelling", spec: " Assets , flows ", want: []Kind{KindAssets, KindFlows}},
		{name: "order follows the tables", spec: "events,summary", want: []Kind{KindSummary, KindEvents}},
		{name: "duplicates collapse", spec: "flows,flows", want: []Kind{KindFlows}},
		{name: "all leaves out the events", spec: "all", want: Overview},
		{name: "all plus events", spec: "all,events", want: Kinds},
		{name: "unknown", spec: "rumours", err: `no table named "rumours"`},
		{name: "empty", spec: " , ", err: "no table named"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseKinds(tc.spec)
			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseFormat(t *testing.T) {
	for _, name := range []string{"json", "JSON", " csv "} {
		f, err := ParseFormat(name)
		require.NoError(t, err)
		assert.Contains(t, []Format{FormatJSON, FormatCSV}, f)
	}
	_, err := ParseFormat("xlsx")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pick json or csv")
}

// sampleDocument is a project with one of everything, which is what the
// tables are rendered from.
func sampleDocument(t *testing.T) *Document {
	t.Helper()
	first := time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC)
	last := first.Add(90 * time.Second)

	doc := NewDocument("plant", "plant.otinv.db", "1.2.3", []Kind{KindAssets})
	doc.Summary = FromSummary(store.Summary{
		Assets: 2, Controllers: 1, Captures: 1, Packets: 40, Bytes: 4096,
		Events: 3, Malformed: 1, Anomalies: 1, Protocols: 2, Flows: 2,
		FirstSeen: first, LastSeen: last,
	})
	doc.Captures = FromCaptures([]store.CaptureRow{{
		Capture: model.Capture{
			ID: "abc123", Path: "testdata/pcaps/modbus.pcap", SHA256: "deadbeef",
			Bytes: 4096, Packets: 40, LinkType: "Ethernet",
			FirstSeen: first, LastSeen: last,
		},
		IngestedAt: last,
	}})
	doc.Protocols = FromProtocolStats([]store.ProtocolStat{{
		Protocol: "modbus", Events: 3, Malformed: 1, Anomalies: 1, Flows: 2,
		Classes:   map[model.Classification]int64{model.ClassRead: 2, model.ClassWrite: 1},
		FirstSeen: first, LastSeen: last,
	}})
	doc.Flows = FromFlows([]store.Flow{{
		Src: "10.0.0.5", Dst: "10.0.0.9", Protocol: "modbus",
		Transport: model.TransportTCP, ServerPort: 502, Events: 3, Malformed: 1,
		Classes:   map[model.Classification]int64{model.ClassRead: 2, model.ClassWrite: 1},
		FirstSeen: first, LastSeen: last,
	}})
	doc.Assets = []model.Asset{{
		Key:   "mac:00:0c:29:11:22:33",
		Label: "10.0.0.9",
		MACs:  []string{"00:0c:29:11:22:33"},
		IPs:   []string{"10.0.0.9"},
		VLANs: []uint16{100, 200},
		Role: model.Role{
			Name: model.RoleController, Confidence: 80,
			Reasons: []string{"served modbus", "answered writes"},
		},
		Attributes: []model.Attribute{
			{Field: "vendor", Value: "Siemens", Confidence: 90, Source: "oui"},
			{Field: "model", Value: "S7-300", Confidence: 85, Source: "s7comm"},
			{Field: "firmware_revision", Value: "V3.2.6"},
		},
		Protocols: []model.ProtocolUsage{
			{Protocol: "modbus", Side: "server", Events: 3},
			{Protocol: "arp", Side: "client", Events: 1},
		},
		Events: 4, FirstSeen: first, LastSeen: last,
	}}
	doc.Findings = []model.Finding{{
		ID: "9f2c", RuleID: "OT-003", Title: "Modbus diagnostic that changes how a device answers",
		Summary:  "10.0.0.5 sent ForceListenOnlyMode to 10.0.0.9",
		Severity: model.SeverityHigh, Status: model.StatusInvestigating,
		Technique: "T0813", TechniqueName: "Denial of Control",
		Assignee: "rom", Note: "ask the integrator",
		Src: "10.0.0.5", Dst: "10.0.0.9", Protocol: "modbus",
		Count: 3, FirstSeen: first, LastSeen: last,
		Evidence: model.Evidence{
			CaptureID: "abc123", PacketIndex: 12, Timestamp: first,
			Protocol: "modbus", Operation: "Diagnostics", FunctionCode: 8,
		},
		Details: map[string]string{"sub_function": "ForceListenOnlyMode"},
	}}
	doc.Events = []model.Event{{
		CaptureID: "abc123", PacketIndex: 7, Timestamp: first,
		Protocol: "modbus", Direction: model.DirRequest, Operation: "WriteSingleCoil",
		FunctionCode: 5, Class: model.ClassWrite,
		Flow: model.Flow{
			SrcMAC: "00:0c:29:aa:bb:cc", DstMAC: "00:0c:29:11:22:33",
			SrcIP: "10.0.0.5", DstIP: "10.0.0.9", SrcPort: 45000, DstPort: 502,
			Transport: model.TransportTCP, VLAN: []uint16{100},
		},
		ServerPort: 502,
		UnitID:     model.Ptr(uint16(1)),
		Address:    model.Ptr(uint32(17)),
		Identity:   map[string]string{"vendor_name": "Wingpath", "product_code": "MB"},
		Attrs:      map[string]string{"coil_state": "on"},
	}}
	return doc
}

func TestTablesRenderEveryKind(t *testing.T) {
	doc := sampleDocument(t)

	for _, kind := range Kinds {
		table, err := doc.Table(kind)
		require.NoError(t, err, kind)
		assert.NotEmpty(t, table.Columns, kind)
		require.NotEmpty(t, table.Rows, kind)
		if kind != KindSummary {
			// The summary is a column of metrics; the rest are one row per item.
			assert.Len(t, table.Rows, 1, kind)
		}
		for _, row := range table.Rows {
			assert.Len(t, row, len(table.Columns), "%s row matches its header", kind)
		}
	}

	_, err := doc.Table(Kind("rumours"))
	require.Error(t, err, "a table nobody defined is an error, not an empty file")
}

func TestSummaryTableIsVertical(t *testing.T) {
	doc := sampleDocument(t)
	table, err := doc.Table(KindSummary)
	require.NoError(t, err)

	assert.Equal(t, []string{"metric", "value"}, table.Columns)
	got := map[string]string{}
	for _, row := range table.Rows {
		got[row[0]] = row[1]
	}
	assert.Equal(t, "2", got["assets"])
	assert.Equal(t, "4096", got["bytes"])
	assert.Equal(t, "2024-03-01T10:00:00Z", got["first_seen"])

	// A project with no events has no time range, and an empty cell is better
	// than year one in a spreadsheet.
	empty := &Document{Summary: &Summary{}}
	table, err = empty.Table(KindSummary)
	require.NoError(t, err)
	for _, row := range table.Rows {
		assert.NotContains(t, []string{"first_seen", "last_seen"}, row[0])
	}
}

func TestAssetRowCarriesInferenceConfidence(t *testing.T) {
	doc := sampleDocument(t)
	table, err := doc.Table(KindAssets)
	require.NoError(t, err)
	row := rowMap(table)

	assert.Equal(t, "Siemens (90%)", row["vendor"])
	assert.Equal(t, "S7-300 (85%)", row["model"])
	// An attribute with no confidence is the value alone, not "(0%)".
	assert.Equal(t, "V3.2.6", row["firmware_revision"])
	// And every inferred field is there, named, whether it has a column of
	// its own or not.
	assert.Equal(t, "vendor=Siemens (90%, oui); model=S7-300 (85%, s7comm); "+
		"firmware_revision=V3.2.6 (0%, )", row["attributes"])
	assert.Empty(t, row["name"], "nothing inferred a name")
	assert.Equal(t, "plc_rtu_ied", row["role"])
	assert.Equal(t, "80", row["role_confidence"])
	assert.Equal(t, "served modbus; answered writes", row["role_reasons"])
	assert.Equal(t, "false", row["is_gateway"])
	assert.Equal(t, "100 200", row["vlans"])
	assert.Equal(t, "modbus (3)", row["server_protocols"])
	assert.Equal(t, "arp (1)", row["client_protocols"])
}

func TestEventRowFlattensMapsAndOmitsAbsentFields(t *testing.T) {
	doc := sampleDocument(t)
	table, err := doc.Table(KindEvents)
	require.NoError(t, err)
	row := rowMap(table)

	assert.Equal(t, "WriteSingleCoil", row["operation"])
	assert.Equal(t, "write", row["class"])
	assert.Equal(t, "502", row["server_port"])
	assert.Equal(t, "1", row["unit_id"])
	assert.Equal(t, "17", row["address"])
	assert.Empty(t, row["quantity"], "an absent field is an empty cell, not a zero")
	assert.Empty(t, row["transaction_id"])
	assert.Equal(t, "100", row["vlan"])
	// Sorted, so that two exports of one project produce the same bytes.
	assert.Equal(t, "product_code=MB; vendor_name=Wingpath", row["identity"])
	assert.Equal(t, "coil_state=on", row["attrs"])
	assert.Equal(t, "false", row["malformed"])
}

func TestFlowAndProtocolRowsHaveAColumnPerClassification(t *testing.T) {
	doc := sampleDocument(t)
	for _, kind := range []Kind{KindFlows, KindProtocols} {
		table, err := doc.Table(kind)
		require.NoError(t, err)
		row := rowMap(table)

		for _, class := range model.Classifications {
			assert.Contains(t, table.Columns, string(class), kind)
		}
		assert.Equal(t, "2", row["read"], kind)
		assert.Equal(t, "1", row["write"], kind)
		assert.Equal(t, "0", row["control"], "a class nobody used counts zero")
	}
}

func TestEmptyDocumentRendersHeadersOnly(t *testing.T) {
	doc := NewDocument("empty", "empty.db", "dev", Kinds)
	for _, kind := range Kinds {
		table, err := doc.Table(kind)
		require.NoError(t, err, kind)
		assert.NotEmpty(t, table.Columns, kind)
		assert.Empty(t, table.Rows, kind)

		var buf bytes.Buffer
		require.NoError(t, WriteCSV(&buf, table))
		assert.Equal(t, 1, strings.Count(buf.String(), "\n"), "%s writes just a header", kind)
	}
}

func TestWriteCSVQuotesSeparators(t *testing.T) {
	doc := sampleDocument(t)
	doc.Assets[0].Role.Reasons = []string{"wrote, repeatedly", `said "hello"`}
	table, err := doc.Table(KindAssets)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, WriteCSV(&buf, table))

	records, err := csv.NewReader(&buf).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, table.Columns, records[0])
	parsed := map[string]string{}
	for i, name := range records[0] {
		parsed[name] = records[1][i]
	}
	assert.Equal(t, `wrote, repeatedly; said "hello"`, parsed["role_reasons"],
		"a reason with a comma and a quote in it survives the round trip")
}

func TestWriteJSONRoundTrips(t *testing.T) {
	doc := sampleDocument(t)

	var buf bytes.Buffer
	require.NoError(t, WriteJSON(&buf, doc, true))

	var back Document
	require.NoError(t, json.Unmarshal(buf.Bytes(), &back))
	assert.Equal(t, "otinv", back.Tool)
	assert.Equal(t, "plant", back.Project)
	assert.Equal(t, "1.2.3", back.Version)
	require.NotNil(t, back.Summary)
	assert.EqualValues(t, 2, back.Summary.Assets)
	require.Len(t, back.Assets, 1)
	assert.Equal(t, "10.0.0.9", back.Assets[0].Label)
	require.Len(t, back.Events, 1)
	assert.Equal(t, "WriteSingleCoil", back.Events[0].Operation)
	require.Len(t, back.Flows, 1)
	assert.EqualValues(t, 2, back.Flows[0].Classes["read"])
}

func TestJSONOmitsTablesTheExportDidNotAskFor(t *testing.T) {
	doc := NewDocument("plant", "plant.db", "dev", []Kind{KindSummary})
	doc.Summary = FromSummary(store.Summary{Assets: 1})

	var buf bytes.Buffer
	require.NoError(t, WriteJSON(&buf, doc, false))

	// The keys of the document itself, not of the summary nested in it: an
	// export of one table must not look like an empty project in the others.
	var top map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(buf.Bytes(), &top))
	for _, key := range []string{"assets", "flows", "events", "captures", "protocols", "findings"} {
		assert.NotContains(t, top, key)
	}
	assert.Contains(t, top, "summary")
}

func TestEventStreamJSONStaysOneObject(t *testing.T) {
	for _, indent := range []bool{false, true} {
		for _, count := range []int{0, 1, 3} {
			doc := NewDocument("plant", "plant.db", "dev", []Kind{KindEvents})
			doc.Summary = FromSummary(store.Summary{Events: int64(count)})

			var buf bytes.Buffer
			stream, err := NewEventStream(&buf, FormatJSON, doc, indent)
			require.NoError(t, err)
			for i := range count {
				require.NoError(t, stream.Add(model.Event{
					PacketIndex: uint64(i), Protocol: "modbus",
					Operation: "ReadHoldingRegisters", Class: model.ClassRead,
				}))
			}
			require.NoError(t, stream.Close())

			var back Document
			require.NoError(t, json.Unmarshal(buf.Bytes(), &back),
				"indent=%v count=%d: %s", indent, count, buf.String())
			assert.Equal(t, "plant", back.Project)
			require.NotNil(t, back.Summary)
			assert.EqualValues(t, count, back.Summary.Events)
			require.Len(t, back.Events, count)
			for i, e := range back.Events {
				assert.EqualValues(t, i, e.PacketIndex)
			}
		}
	}
}

func TestEventStreamRefusesADocumentThatAlreadyHasEvents(t *testing.T) {
	doc := sampleDocument(t)
	_, err := NewEventStream(&bytes.Buffer{}, FormatJSON, doc, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not already hold events")
}

func TestEventStreamCSVWritesAHeaderAndRows(t *testing.T) {
	var buf bytes.Buffer
	stream, err := NewEventStream(&buf, FormatCSV, nil, false)
	require.NoError(t, err)
	require.NoError(t, stream.Add(model.Event{
		Protocol: "modbus", Operation: "ReadCoils", Class: model.ClassRead,
		Flow: model.Flow{SrcIP: "10.0.0.5", DstIP: "10.0.0.9", DstPort: 502},
	}))
	require.NoError(t, stream.Close())

	records, err := csv.NewReader(&buf).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, EventColumns, records[0])
	row := map[string]string{}
	for i, name := range records[0] {
		row[name] = records[1][i]
	}
	assert.Equal(t, "ReadCoils", row["operation"])
	assert.Equal(t, "10.0.0.5", row["src_ip"])
	assert.Equal(t, "502", row["dst_port"])
	assert.Empty(t, row["ts"], "an event with no timestamp leaves the cell empty")
}

// rowMap pairs a table's header with its first row.
func rowMap(t Table) map[string]string {
	out := make(map[string]string, len(t.Columns))
	for i, name := range t.Columns {
		out[name] = t.Rows[0][i]
	}
	return out
}

func TestFindingRowCarriesTheEvidenceAndTheTriage(t *testing.T) {
	doc := sampleDocument(t)
	table, err := doc.Table(KindFindings)
	require.NoError(t, err)
	row := rowMap(table)

	assert.Equal(t, "OT-003", row["rule_id"])
	assert.Equal(t, "high", row["severity"])
	assert.Equal(t, "investigating", row["status"], "triage travels with the finding")
	assert.Equal(t, "rom", row["assignee"])
	assert.Equal(t, "T0813", row["technique"])
	assert.Equal(t, "Denial of Control", row["technique_name"])
	// The packet behind it, which is the point of the row.
	assert.Equal(t, "abc123", row["capture_id"])
	assert.Equal(t, "12", row["packet_index"])
	assert.Equal(t, "Diagnostics", row["operation"])
	assert.Equal(t, "8", row["function_code"])
	assert.Equal(t, "sub_function=ForceListenOnlyMode", row["details"])
}
