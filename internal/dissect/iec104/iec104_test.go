package iec104_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/iec104"
	"github.com/rom/otinv/internal/model"
)

// APDUs taken verbatim from the public IEC 60870-5-104 sample captures in
// testdata/pcaps; the comment names the file and packet each came from. Both
// captures were decoded independently before these expectations were written.
const (
	// test_dissect #4 and #5: a master starts data transfer.
	apduStartDTAct = "680407000000"
	apduStartDTCon = "68040b000000"
	// test_dissect #13 and #14: the connection keep-alive.
	apduTestFRAct = "680443000000"
	apduTestFRCon = "680483000000"
	// test_dissect #110: an acknowledgement with no data to carry it.
	apduSupervisory = "680401000200"

	// test_dissect #107: the station reports it has finished initialising.
	apduEndOfInit = "680e00000000460104000d9100000000"
	// test_dissect #109, #110 and #113: a general interrogation and its
	// confirmation and termination.
	apduInterrogationAct = "680e00000200640106000d9100000014"
	apduInterrogationCon = "680e02000200640107000d9100000014"
	apduInterrogationEnd = "680e0800020064010a000d9100000014"
	// test_dissect #110: nine single points in one sequence, answering the
	// interrogation.
	apduSinglePointSeq = "681604000200018914000d911a2700d0808080c080808080"
	// test_dissect #110: three double points in one sequence.
	apduDoublePointSeq = "681006000200038314000d912a4e00808080"
	// test_dissect #124 and #125: select a single command and confirm it.
	apduSingleCommandSelect = "680e04000e002d0106010d911a270081"
	apduSingleCommandCon    = "680e0e0006002d0107010d911a270081"
	// test_dissect #134: a refusal, marked as test traffic.
	apduSingleCommandNegCon = "680e14000a002d01c7020d91ce560081"
	// test_dissect #136: an activation with the negative bit set, which the
	// standard leaves undefined in the control direction.
	apduSingleCommandNegAct = "680e0a0016002d0146030d9135820081"
	// test_dissect #117 and #118: a double command and its refusal.
	apduDoubleCommandSelect = "680e02000a002e0106010d91983a0082"
	apduDoubleCommandNegCon = "680e0a0004002e0147010d91983a0082"
	// test_dissect #139: the master sets the station's clock.
	apduClockSync = "68140c001600670106040d91000000c83239081d0808"
	// test_dissect #129: a time tagged single point reported spontaneously.
	apduSinglePointTime = "6815120008001e0103000d911a2700d1552a0000010100"

	// diverse #51 and #59: a floating point set point, selected and executed.
	apduSetPointFloatSelect = "68123400b0003201060003009c13000000404180"
	apduSetPointFloatEnd    = "6812b400380032010a0003009c13000000404100"
	// diverse #39: the same with a time tag.
	apduSetPointFloatTime = "68193000aa003f01060003009d13000000f64280080018130d086d"
	// diverse #154: a normalised set point with a time tag.
	apduSetPointNormTime = "68174a00f6003d0106000300d51200744080c8001a130d086d"
	// diverse #9: a single command with a time tag.
	apduSingleCommandTime = "681528009c003a010600030095110081080017130d086d"
	// diverse #91: a double command issued directly, with a short pulse.
	apduDoubleCommandExec = "680e3e00ca002e0106000300f8110006"
	// diverse #1: two measured values reported periodically.
	apduMeasuredFloats = "681a9a0028000d02010003001405000000f041001505000000314400"
	// diverse #77: two single points, each with its own address.
	apduSinglePointList = "6812be003e000102140003000100000102000000"
	// diverse #85: one measured value reported spontaneously.
	apduMeasuredFloatSpont = "6812c4003e000d01030003001505000000444200"
)

func frame(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	require.NoError(t, err, "test fixture is not valid hex")
	return b
}

func ctxFor(dir model.Direction) *dissect.FlowContext {
	flow := model.Flow{
		SrcIP: "172.27.248.109", DstIP: "172.27.248.79",
		SrcPort: 1578, DstPort: iec104.DefaultPort,
		Transport: model.TransportTCP,
	}
	if dir == model.DirResponse {
		flow = flow.Reverse()
	}
	return &dissect.FlowContext{
		CaptureID:   "test",
		Flow:        flow,
		PacketIndex: 109,
		Timestamp:   time.Unix(1219995600, 0).UTC(),
		Direction:   dir,
		ServerPort:  iec104.DefaultPort,
	}
}

func parseOne(t *testing.T, ctx *dissect.FlowContext, raw []byte) model.Event {
	t.Helper()
	events, err := iec104.New().Parse(ctx, raw)
	require.NoError(t, err)
	require.Len(t, events, 1, "one APDU yields one event")
	return events[0]
}

func TestIdentity(t *testing.T) {
	d := iec104.New()
	assert.Equal(t, "iec104", d.Name())
	assert.Equal(t, 1, d.Tier())
}

func TestRegisteredOnDefaultPort(t *testing.T) {
	reg := dissect.Default()
	d, ok := reg.Lookup("iec104")
	require.True(t, ok, "iec104 must register itself in init()")
	require.NotNil(t, d)
	assert.True(t, reg.HasPort("iec104", model.TransportTCP, 2404),
		"IEC 60870-5-104 is registered on TCP port 2404")
}

func TestPDULen(t *testing.T) {
	d := iec104.New()

	tests := []struct {
		name    string
		in      string
		want    int
		wantErr error
	}{
		{name: "empty", in: "", wantErr: dissect.ErrNeedMore},
		{name: "start octet only", in: "68", wantErr: dissect.ErrNeedMore},
		{name: "header without body", in: "680e0000", wantErr: dissect.ErrNeedMore},
		{name: "wrong start octet", in: "690400000000", wantErr: dissect.ErrMalformed},
		{name: "length below the minimum", in: "680300000000", wantErr: dissect.ErrMalformed},
		{name: "length above the maximum", in: "68fe00000000", wantErr: dissect.ErrMalformed},
		{name: "exact U frame", in: apduStartDTAct, want: 6},
		{name: "exact I frame", in: apduInterrogationAct, want: 16},
		{name: "trailing bytes belong to the next APDU",
			in: apduStartDTAct + apduStartDTCon, want: 6},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := d.PDULen(frame(t, tc.in))
			if tc.wantErr != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.wantErr), "got %v", err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, n)
		})
	}
}

func TestProbe(t *testing.T) {
	d := iec104.New()
	ctx := ctxFor(model.DirRequest)

	tests := []struct {
		name    string
		in      string
		wantMin int
		wantMax int
	}{
		{name: "STARTDT act", in: apduStartDTAct, wantMin: 70, wantMax: 100},
		{name: "TESTFR con", in: apduTestFRCon, wantMin: 70, wantMax: 100},
		{name: "supervisory frame", in: apduSupervisory, wantMin: 70, wantMax: 100},
		{name: "interrogation command", in: apduInterrogationAct, wantMin: 70, wantMax: 100},
		{name: "measured values", in: apduMeasuredFloats, wantMin: 70, wantMax: 100},
		{name: "two APDUs in one segment",
			in: apduStartDTAct + apduStartDTCon, wantMin: 70, wantMax: 100},

		{name: "too short to judge", in: "6804", wantMax: 0},
		{name: "wrong start octet", in: "690400000000", wantMax: 0},
		{name: "U format with a reserved function", in: "680417000000", wantMax: 0},
		{name: "U format with control octets set", in: "680407000100", wantMax: 0},
		{name: "supervisory frame carrying a body", in: "680e01000200640106000d91", wantMax: 0},
		// Other protocols that a stray stream could offer us.
		{name: "modbus read holding registers", in: "0001000000060103006b0003", wantMax: 0},
		{name: "dnp3 link frame", in: "0564050964010400176f", wantMax: 0},
		{name: "http request", in: hex.EncodeToString([]byte("GET / HTTP/1.1\r\n")), wantMax: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := d.Probe(ctx, frame(t, tc.in))
			assert.GreaterOrEqual(t, got, tc.wantMin)
			assert.LessOrEqual(t, got, tc.wantMax)
		})
	}
}

// A heuristic that fired on any 0x68 would bind IEC 104 to half the streams in
// a capture, so the floor the registry uses to accept a non-port match is the
// bar these frames have to clear.
func TestProbeMeetsTheHeuristicFloor(t *testing.T) {
	d := iec104.New()
	ctx := ctxFor(model.DirRequest)
	for _, in := range []string{apduStartDTAct, apduSupervisory, apduSingleCommandSelect} {
		assert.GreaterOrEqual(t, d.Probe(ctx, frame(t, in)), dissect.DefaultMinConfidence, in)
	}
}

func TestParseUFormat(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		op      string
		class   model.Classification
		wantDir model.Direction
	}{
		{"STARTDT act", apduStartDTAct, "STARTDT_act", model.ClassOther, model.DirRequest},
		{"STARTDT con", apduStartDTCon, "STARTDT_con", model.ClassOther, model.DirResponse},
		{"TESTFR act", apduTestFRAct, "TESTFR_act", model.ClassDiagnostic, model.DirRequest},
		{"TESTFR con", apduTestFRCon, "TESTFR_con", model.ClassDiagnostic, model.DirResponse},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := parseOne(t, ctxFor(model.DirUnknown), frame(t, tc.in))
			assert.Equal(t, "iec104", ev.Protocol)
			assert.Equal(t, tc.op, ev.Operation)
			assert.Equal(t, tc.class, ev.Class)
			assert.Equal(t, tc.wantDir, ev.Direction)
			assert.Equal(t, "U", ev.Attrs["apci_format"])
			assert.Equal(t, tc.op, ev.Attrs["u_function"])
			assert.Equal(t, -1, ev.FunctionCode, "a U frame has no type identification")
			assert.Nil(t, ev.UnitID)
			assert.False(t, ev.Malformed)
		})
	}
}

func TestParseSupervisoryFormat(t *testing.T) {
	ev := parseOne(t, ctxFor(model.DirResponse), frame(t, apduSupervisory))
	assert.Equal(t, "SUPERVISORY", ev.Operation)
	assert.Equal(t, "S", ev.Attrs["apci_format"])
	assert.Equal(t, "1", ev.Attrs["recv_seq"])
	assert.Equal(t, model.ClassOther, ev.Class)
	assert.Equal(t, model.DirResponse, ev.Direction, "a supervisory frame says nothing about direction")
	assert.Equal(t, -1, ev.FunctionCode)
}

func TestParseInformationFrames(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		dir       model.Direction
		op        string
		typeID    int
		class     model.Classification
		wantDir   model.Direction
		unit      *uint16
		address   *uint32
		quantity  *uint32
		exception string
		attrs     map[string]string
		absent    []string
	}{
		{
			name: "end of initialisation", in: apduEndOfInit, dir: model.DirUnknown,
			op: "M_EI_NA_1", typeID: 70, class: model.ClassDiagnostic,
			wantDir: model.DirResponse, unit: model.Ptr(uint16(37133)),
			attrs: map[string]string{
				"cause":      "initialized",
				"init_cause": "local_power_on",
				"send_seq":   "0",
				"recv_seq":   "0",
			},
			// The information object address of a station-wide ASDU is zero,
			// which the standard defines as "not used".
			absent: []string{"anomaly", "originator"},
		},
		{
			name: "general interrogation", in: apduInterrogationAct, dir: model.DirUnknown,
			op: "C_IC_NA_1", typeID: 100, class: model.ClassRead,
			wantDir: model.DirRequest, unit: model.Ptr(uint16(37133)),
			attrs: map[string]string{
				"cause":         "activation",
				"interrogation": "station_interrogation",
				"apci_format":   "I",
			},
			absent: []string{"anomaly"},
		},
		{
			name: "interrogation confirmation", in: apduInterrogationCon, dir: model.DirUnknown,
			op: "C_IC_NA_1", typeID: 100, class: model.ClassRead,
			wantDir: model.DirResponse, unit: model.Ptr(uint16(37133)),
			attrs: map[string]string{"cause": "activation_confirmation"},
		},
		{
			name: "interrogation termination", in: apduInterrogationEnd, dir: model.DirUnknown,
			op: "C_IC_NA_1", typeID: 100, class: model.ClassRead,
			wantDir: model.DirResponse, unit: model.Ptr(uint16(37133)),
			attrs: map[string]string{"cause": "activation_termination"},
		},
		{
			name: "single points in a sequence", in: apduSinglePointSeq, dir: model.DirResponse,
			op: "M_SP_NA_1", typeID: 1, class: model.ClassRead,
			wantDir: model.DirResponse, unit: model.Ptr(uint16(37133)),
			address: model.Ptr(uint32(10010)), quantity: model.Ptr(uint32(9)),
			attrs: map[string]string{
				"cause":    "interrogated_by_station",
				"sequence": "true",
				"objects":  "10010-10018",
				"value":    "off",
				"quality":  "blocked,not_topical,invalid",
			},
		},
		{
			name: "double points in a sequence", in: apduDoublePointSeq, dir: model.DirResponse,
			op: "M_DP_NA_1", typeID: 3, class: model.ClassRead,
			wantDir: model.DirResponse, unit: model.Ptr(uint16(37133)),
			address: model.Ptr(uint32(20010)), quantity: model.Ptr(uint32(3)),
			attrs: map[string]string{
				"objects": "20010-20012",
				"value":   "indeterminate",
				"quality": "invalid",
			},
		},
		{
			name: "single command, select", in: apduSingleCommandSelect, dir: model.DirUnknown,
			op: "C_SC_NA_1", typeID: 45, class: model.ClassControl,
			wantDir: model.DirRequest, unit: model.Ptr(uint16(37133)),
			address: model.Ptr(uint32(10010)),
			attrs: map[string]string{
				"cause":             "activation",
				"originator":        "1",
				"value":             "on",
				"command_mode":      "select",
				"command_qualifier": "no_additional_definition",
			},
			absent: []string{"anomaly", "negative", "test"},
		},
		{
			name: "single command, confirmed", in: apduSingleCommandCon, dir: model.DirUnknown,
			op: "C_SC_NA_1", typeID: 45, class: model.ClassControl,
			wantDir: model.DirResponse, unit: model.Ptr(uint16(37133)),
			address: model.Ptr(uint32(10010)),
			attrs:   map[string]string{"cause": "activation_confirmation"},
			absent:  []string{"negative"},
		},
		{
			name: "single command, refused", in: apduSingleCommandNegCon, dir: model.DirUnknown,
			op: "C_SC_NA_1", typeID: 45, class: model.ClassControl,
			wantDir: model.DirResponse, unit: model.Ptr(uint16(37133)),
			address: model.Ptr(uint32(22222)), exception: "negative_confirmation",
			attrs: map[string]string{
				"cause":      "activation_confirmation",
				"negative":   "true",
				"test":       "true",
				"originator": "2",
			},
		},
		{
			name: "activation with the negative bit set", in: apduSingleCommandNegAct,
			dir: model.DirUnknown, op: "C_SC_NA_1", typeID: 45, class: model.ClassControl,
			wantDir: model.DirRequest, unit: model.Ptr(uint16(37133)),
			address: model.Ptr(uint32(33333)),
			attrs: map[string]string{
				"cause":    "activation",
				"negative": "true",
				"anomaly":  "negative_bit_in_control_direction",
			},
			absent: []string{"test"},
		},
		{
			name: "double command, select", in: apduDoubleCommandSelect, dir: model.DirUnknown,
			op: "C_DC_NA_1", typeID: 46, class: model.ClassControl,
			wantDir: model.DirRequest, unit: model.Ptr(uint16(37133)),
			address: model.Ptr(uint32(15000)),
			attrs: map[string]string{
				"value":             "on",
				"command_mode":      "select",
				"command_qualifier": "no_additional_definition",
			},
		},
		{
			name: "double command, refused", in: apduDoubleCommandNegCon, dir: model.DirUnknown,
			op: "C_DC_NA_1", typeID: 46, class: model.ClassControl,
			wantDir: model.DirResponse, unit: model.Ptr(uint16(37133)),
			address: model.Ptr(uint32(15000)), exception: "negative_confirmation",
			attrs:  map[string]string{"cause": "activation_confirmation", "negative": "true"},
			absent: []string{"test"},
		},
		{
			name: "clock synchronisation", in: apduClockSync, dir: model.DirUnknown,
			op: "C_CS_NA_1", typeID: 103, class: model.ClassWrite,
			wantDir: model.DirRequest, unit: model.Ptr(uint16(37133)),
			attrs: map[string]string{
				"cause":      "activation",
				"originator": "4",
				"clock_time": "2008-08-29T08:57:13.000",
			},
			absent: []string{"anomaly", "object_time"},
		},
		{
			name: "time tagged single point", in: apduSinglePointTime, dir: model.DirResponse,
			op: "M_SP_TB_1", typeID: 30, class: model.ClassRead,
			wantDir: model.DirResponse, unit: model.Ptr(uint16(37133)),
			address: model.Ptr(uint32(10010)),
			attrs: map[string]string{
				"cause":       "spontaneous",
				"value":       "on",
				"quality":     "blocked,not_topical,invalid",
				"object_time": "2000-01-01T00:00:10.837",
			},
		},
		{
			name: "floating point set point, select", in: apduSetPointFloatSelect,
			dir: model.DirUnknown, op: "C_SE_NC_1", typeID: 50, class: model.ClassControl,
			wantDir: model.DirRequest, unit: model.Ptr(uint16(3)),
			address: model.Ptr(uint32(5020)),
			attrs: map[string]string{
				"cause":        "activation",
				"value":        "12",
				"command_mode": "select",
			},
			absent: []string{"anomaly", "originator"},
		},
		{
			name: "floating point set point, terminated", in: apduSetPointFloatEnd,
			dir: model.DirUnknown, op: "C_SE_NC_1", typeID: 50, class: model.ClassControl,
			wantDir: model.DirResponse, unit: model.Ptr(uint16(3)),
			address: model.Ptr(uint32(5020)),
			attrs: map[string]string{
				"cause":        "activation_termination",
				"value":        "12",
				"command_mode": "execute",
			},
		},
		{
			name: "time tagged floating point set point", in: apduSetPointFloatTime,
			dir: model.DirUnknown, op: "C_SE_TC_1", typeID: 63, class: model.ClassControl,
			wantDir: model.DirRequest, unit: model.Ptr(uint16(3)),
			address: model.Ptr(uint32(5021)),
			attrs: map[string]string{
				"value":        "123",
				"command_mode": "select",
				// The sender writes the year less 1900, which the standard
				// does not allow and which reads as a date a century out.
				"object_time": "2109-08-13T19:24:00.008",
				"anomaly":     "time_tag_out_of_range",
			},
		},
		{
			name: "time tagged normalised set point", in: apduSetPointNormTime,
			dir: model.DirUnknown, op: "C_SE_TA_1", typeID: 61, class: model.ClassControl,
			wantDir: model.DirRequest, unit: model.Ptr(uint16(3)),
			address: model.Ptr(uint32(4821)),
			attrs: map[string]string{
				"value":        "0.503540",
				"value_raw":    "16500",
				"command_mode": "select",
				"object_time":  "2109-08-13T19:26:00.200",
			},
		},
		{
			name: "time tagged single command", in: apduSingleCommandTime,
			dir: model.DirUnknown, op: "C_SC_TA_1", typeID: 58, class: model.ClassControl,
			wantDir: model.DirRequest, unit: model.Ptr(uint16(3)),
			address: model.Ptr(uint32(4501)),
			attrs: map[string]string{
				"value":        "on",
				"command_mode": "select",
				"object_time":  "2109-08-13T19:23:00.008",
			},
		},
		{
			name: "double command, direct with a short pulse", in: apduDoubleCommandExec,
			dir: model.DirUnknown, op: "C_DC_NA_1", typeID: 46, class: model.ClassControl,
			wantDir: model.DirRequest, unit: model.Ptr(uint16(3)),
			address: model.Ptr(uint32(4600)),
			attrs: map[string]string{
				"value":             "on",
				"command_mode":      "execute",
				"command_qualifier": "short_pulse",
			},
		},
		{
			name: "measured values, periodic", in: apduMeasuredFloats, dir: model.DirResponse,
			op: "M_ME_NC_1", typeID: 13, class: model.ClassRead,
			wantDir: model.DirResponse, unit: model.Ptr(uint16(3)),
			address: model.Ptr(uint32(1300)), quantity: model.Ptr(uint32(2)),
			attrs: map[string]string{
				"cause":   "periodic",
				"objects": "1300,1301",
				"value":   "30",
			},
			absent: []string{"sequence", "quality"},
		},
		{
			name: "single points, each addressed", in: apduSinglePointList, dir: model.DirResponse,
			op: "M_SP_NA_1", typeID: 1, class: model.ClassRead,
			wantDir: model.DirResponse, unit: model.Ptr(uint16(3)),
			address: model.Ptr(uint32(1)), quantity: model.Ptr(uint32(2)),
			attrs: map[string]string{
				"cause":   "interrogated_by_station",
				"objects": "1,2",
				"value":   "on",
			},
			absent: []string{"sequence", "quality"},
		},
		{
			name: "measured value, spontaneous", in: apduMeasuredFloatSpont, dir: model.DirResponse,
			op: "M_ME_NC_1", typeID: 13, class: model.ClassRead,
			wantDir: model.DirResponse, unit: model.Ptr(uint16(3)),
			address: model.Ptr(uint32(1301)),
			attrs:   map[string]string{"cause": "spontaneous", "value": "49"},
			absent:  []string{"objects"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := parseOne(t, ctxFor(tc.dir), frame(t, tc.in))
			assert.Equal(t, "iec104", ev.Protocol)
			assert.Equal(t, tc.op, ev.Operation)
			assert.Equal(t, tc.typeID, ev.FunctionCode)
			assert.Equal(t, tc.class, ev.Class)
			assert.Equal(t, tc.wantDir, ev.Direction)
			assert.Equal(t, tc.unit, ev.UnitID)
			assert.Equal(t, tc.address, ev.Address)
			assert.Equal(t, tc.quantity, ev.Quantity)
			assert.Equal(t, tc.exception, ev.Exception)
			assert.False(t, ev.Malformed, "error: %s", ev.Error)
			assert.Equal(t, "I", ev.Attrs["apci_format"])
			for k, want := range tc.attrs {
				assert.Equal(t, want, ev.Attrs[k], "attribute %q", k)
			}
			for _, k := range tc.absent {
				assert.NotContains(t, ev.Attrs, k)
			}
		})
	}
}

// The send sequence number is the only thing in IEC 104 that says an APDU is
// missing, which is what an injected or dropped frame looks like.
func TestSendSequenceGapIsReported(t *testing.T) {
	ctx := ctxFor(model.DirRequest)

	first := parseOne(t, ctx, frame(t, apduInterrogationAct)) // send sequence 0
	assert.NotContains(t, first.Attrs, "anomaly", "the first frame sets the expectation")

	// The next frame of the capture carries send sequence 2, so one was lost.
	next := parseOne(t, ctx, frame(t, "680e04000200640106000d9100000014"))
	assert.Equal(t, "send_seq_gap", next.Attrs["anomaly"])
	assert.Equal(t, "1", next.Attrs["expected_send_seq"])
	assert.Equal(t, "2", next.Attrs["send_seq"])

	// The expectation follows the frame that was actually seen, so one gap
	// does not turn into a gap on every frame afterwards.
	third := parseOne(t, ctx, frame(t, "680e06000200640106000d9100000014"))
	assert.NotContains(t, third.Attrs, "anomaly")
}

func TestTransactionIDIsTheSendSequenceNumber(t *testing.T) {
	ev := parseOne(t, ctxFor(model.DirResponse), frame(t, apduMeasuredFloats))
	require.NotNil(t, ev.TransactionID)
	assert.Equal(t, uint32(77), *ev.TransactionID)
	assert.Equal(t, "77", ev.Attrs["send_seq"])
	assert.Equal(t, "20", ev.Attrs["recv_seq"])
}

func TestGlobalCommonAddressIsNotADevice(t *testing.T) {
	// The same interrogation addressed to every station on the link.
	ev := parseOne(t, ctxFor(model.DirRequest), frame(t, "680e0000020064010600ffff00000014"))
	assert.Nil(t, ev.UnitID, "the global address names every station, not one device")
	assert.Equal(t, "global", ev.Attrs["address_kind"])
	assert.Equal(t, "true", ev.Attrs["broadcast"])
}

func TestRejectionByPeerIsAnException(t *testing.T) {
	// An interrogation answered with "unknown common address of ASDU".
	ev := parseOne(t, ctxFor(model.DirResponse), frame(t, "680e0200020064012e000d9100000014"))
	assert.Equal(t, "unknown_common_address", ev.Attrs["cause"])
	assert.Equal(t, "unknown_common_address", ev.Exception)
	assert.Equal(t, "asdu_rejected", ev.Attrs["anomaly"])
}

func TestUnknownTypeIdentificationIsFlagged(t *testing.T) {
	// Type 90 is reserved by the standard and carries no defined element.
	ev := parseOne(t, ctxFor(model.DirRequest), frame(t, "680e000002005a0106000d9100000014"))
	assert.Equal(t, "Reserved", ev.Operation)
	assert.Equal(t, 90, ev.FunctionCode)
	assert.Equal(t, model.ClassOther, ev.Class)
	assert.Equal(t, "unknown_type_identification", ev.Attrs["anomaly"])
	assert.Equal(t, "true", ev.Attrs["objects_truncated"],
		"an undefined type has no element layout, so the walk stops at the first address")
	assert.NotContains(t, ev.Attrs, "trailing_bytes")
}

func TestParseMalformed(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		op     string
		reason string
	}{
		{
			name: "truncated APCI", in: "680407", op: "APCI",
			reason: "cannot hold an APCI",
		},
		{
			name: "wrong start octet", in: "690407000000", op: "APCI",
			reason: "not 0x68",
		},
		{
			name: "reserved control function", in: "680417000000", op: "U_FORMAT",
			reason: "not one of STARTDT",
		},
		{
			name: "information frame without an ASDU", in: "680400000000", op: "I_FORMAT",
			reason: "fewer than the 6 octet header",
		},
		{
			name: "more objects than octets",
			// A single point sequence claiming nine elements with one present.
			in: "680e04000200018914000d911a2700d0", op: "M_SP_NA_1",
			reason: "needing 12 octets, 4 present",
		},
		{
			name: "more addressed objects than octets",
			// Two measured values claimed, one present.
			in: "68110400020002021400030014050001020304", op: "M_SP_TA_1",
			reason: "declares 2 objects",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events, err := iec104.New().Parse(ctxFor(model.DirRequest), frame(t, tc.in))
			require.Error(t, err)
			assert.True(t, errors.Is(err, dissect.ErrMalformed), "got %v", err)
			require.Len(t, events, 1, "a malformed PDU is still evidence")
			assert.True(t, events[0].Malformed)
			assert.Equal(t, tc.op, events[0].Operation)
			assert.Contains(t, events[0].Error, tc.reason)
		})
	}
}

// Nothing in a frame may be trusted, so every prefix of every fixture has to
// come back as an event or an error, never a panic.
func TestParseNeverPanicsOnTruncation(t *testing.T) {
	d := iec104.New()
	for _, fixture := range []string{
		apduStartDTAct, apduSupervisory, apduEndOfInit, apduSinglePointSeq,
		apduSingleCommandSelect, apduClockSync, apduSetPointFloatTime,
		apduMeasuredFloats, apduSinglePointTime, apduDoublePointSeq,
	} {
		raw := frame(t, fixture)
		for i := range len(raw) + 1 {
			ctx := ctxFor(model.DirRequest)
			assert.NotPanics(t, func() { _, _ = d.Parse(ctx, raw[:i]) }, "%s truncated to %d", fixture, i)
			assert.NotPanics(t, func() { _ = d.Probe(ctx, raw[:i]) }, "%s truncated to %d", fixture, i)
			assert.NotPanics(t, func() { _, _ = d.PDULen(raw[:i]) }, "%s truncated to %d", fixture, i)
		}
	}
}

// CLAUDE.md's built-in rule reads "IEC 104 control commands (C_SC/C_DC/C_RC/
// C_SE*) from unexpected sources". A rule matches on the classification, not
// on type numbers, so the whole command family has to carry the same one.
func TestCommandFamilyIsClassifiedAsControl(t *testing.T) {
	d := iec104.New()
	// Every type identification in the control direction, with and without a
	// time tag, each with one object and the element octets it requires.
	commands := map[uint8]string{
		45: "C_SC_NA_1", 46: "C_DC_NA_1", 47: "C_RC_NA_1", 48: "C_SE_NA_1",
		49: "C_SE_NB_1", 50: "C_SE_NC_1", 51: "C_BO_NA_1", 58: "C_SC_TA_1",
		59: "C_DC_TA_1", 60: "C_RC_TA_1", 61: "C_SE_TA_1", 62: "C_SE_TB_1",
		63: "C_SE_TC_1", 64: "C_BO_TA_1",
	}

	for id, name := range commands {
		t.Run(name, func(t *testing.T) {
			events, err := d.Parse(ctxFor(model.DirRequest), commandFrame(t, id))
			require.NoError(t, err)
			require.Len(t, events, 1)
			assert.Equal(t, name, events[0].Operation)
			assert.Equal(t, model.ClassControl, events[0].Class,
				"a command that operates the plant is a control operation")
			assert.False(t, events[0].Malformed, "error: %s", events[0].Error)
		})
	}
}

// Reset process is the one system command that changes what a station does,
// so it is a control operation too; the rest of the system commands read,
// write or diagnose.
func TestSystemCommandClassification(t *testing.T) {
	d := iec104.New()
	want := map[uint8]model.Classification{
		70:  model.ClassDiagnostic, // end of initialisation
		100: model.ClassRead,       // interrogation
		101: model.ClassRead,       // counter interrogation
		102: model.ClassRead,       // read command
		103: model.ClassWrite,      // clock synchronisation
		104: model.ClassDiagnostic, // test command
		105: model.ClassControl,    // reset process
		106: model.ClassDiagnostic, // delay acquisition
		110: model.ClassWrite,      // parameter of measured value
		113: model.ClassControl,    // parameter activation
		122: model.ClassProgram,    // file: call directory, select, call file
		125: model.ClassProgram,    // file segment
	}

	for id, class := range want {
		events, err := d.Parse(ctxFor(model.DirRequest), commandFrame(t, id))
		require.NoError(t, err, "type %d", id)
		require.Len(t, events, 1)
		assert.Equal(t, class, events[0].Class, "type %d (%s)", id, events[0].Operation)
	}
}

// commandFrame builds an activation of one object of the given type, sized
// from the element length the standard fixes for it.
func commandFrame(t *testing.T, id uint8) []byte {
	t.Helper()
	sizes := map[uint8]int{
		45: 1, 46: 1, 47: 1, 48: 3, 49: 3, 50: 5, 51: 4,
		58: 8, 59: 8, 60: 8, 61: 10, 62: 10, 63: 12, 64: 11,
		70: 1, 100: 1, 101: 1, 102: 0, 103: 7, 104: 2, 105: 1, 106: 2,
		110: 3, 113: 1, 122: 4, 125: 3,
	}
	size, ok := sizes[id]
	require.True(t, ok, "no element size for type %d", id)

	// Type, one object, activation, originator 0, common address 3, then the
	// object address and an element of the right length. A double or step
	// command of zero is a value the standard reserves, so the element bytes
	// are 1 rather than 0.
	asdu := append([]byte{id, 0x01, 0x06, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00},
		bytes(size, 0x01)...)
	apdu := append([]byte{0x68, byte(4 + len(asdu)), 0x00, 0x00, 0x00, 0x00}, asdu...)
	return apdu
}

func bytes(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}
