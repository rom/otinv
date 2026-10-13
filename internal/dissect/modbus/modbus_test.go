package modbus_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/modbus"
	"github.com/rom/otinv/internal/model"
)

// adu decodes a whitespace-formatted hex string into bytes.
func adu(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "\n", ""))
	require.NoError(t, err, "test fixture is not valid hex")
	return b
}

func ctxFor(dir model.Direction) *dissect.FlowContext {
	flow := model.Flow{
		SrcIP: "10.0.0.9", DstIP: "10.0.0.3",
		SrcPort: 3082, DstPort: 502,
		Transport: model.TransportTCP,
	}
	if dir == model.DirResponse {
		flow = flow.Reverse()
	}
	return &dissect.FlowContext{
		CaptureID:   "test",
		Flow:        flow,
		PacketIndex: 1,
		Timestamp:   time.Unix(1093521694, 211940000).UTC(),
		Direction:   dir,
		ServerPort:  502,
	}
}

// strip removes the ingest-owned fields so a case can state only protocol
// facts.
func strip(e model.Event) model.Event {
	e.CaptureID = ""
	e.PacketIndex = 0
	e.Timestamp = time.Time{}
	e.Flow = model.Flow{}
	return e
}

func TestIdentity(t *testing.T) {
	d := modbus.New()
	assert.Equal(t, "modbus", d.Name())
	assert.Equal(t, 1, d.Tier(), "Modbus/TCP is a Tier 1 deep-parsing dissector")
}

func TestRegisteredOnDefaultPort(t *testing.T) {
	d, ok := dissect.Default().Lookup("modbus")
	require.True(t, ok, "modbus must register itself in init()")
	require.NotNil(t, d)

	matched, _ := dissect.Default().Candidates(model.TransportTCP, 3082, 502)
	var names []string
	for _, m := range matched {
		names = append(names, m.Name())
	}
	assert.Contains(t, names, "modbus", "port 502 must map to modbus")
}

func TestPDULen(t *testing.T) {
	d := modbus.New()

	tests := []struct {
		name    string
		in      string
		want    int
		wantErr error
	}{
		{
			name:    "empty buffer needs more",
			in:      "",
			wantErr: dissect.ErrNeedMore,
		},
		{
			name:    "header alone needs more",
			in:      "0001 0000 0006",
			wantErr: dissect.ErrNeedMore,
		},
		{
			name:    "truncated body needs more",
			in:      "0001 0000 0006 0a 03 0005",
			wantErr: dissect.ErrNeedMore,
		},
		{
			name: "complete request",
			in:   "0001 0000 0006 0a 03 0005 0002",
			want: 12,
		},
		{
			name: "first of two concatenated ADUs",
			in:   "0001 0000 0006 0a 03 0005 0002 0002 0000 0006 0a 03 0007 0002",
			want: 12,
		},
		{
			// MBAP length counts the unit id plus the PDU, so the smallest
			// legal value is 2 (unit id + function code).
			name:    "length below minimum is malformed",
			in:      "0001 0000 0001 0a",
			wantErr: dissect.ErrMalformed,
		},
		{
			name:    "zero length is malformed",
			in:      "0001 0000 0000 0a 03",
			wantErr: dissect.ErrMalformed,
		},
		{
			// The real bogus length from modbus_test_data_part1.pcap: the
			// protocol maximum is 254 (unit id + 253 byte PDU).
			name:    "length above protocol maximum is malformed",
			in:      "0001 0000 8804 05 07 0809",
			wantErr: dissect.ErrMalformed,
		},
		{
			// A non-zero protocol identifier is an anomaly, not a framing
			// error: the frame is still cut at the declared length so that the
			// operation and the anomaly both reach the rules.
			name: "non-zero protocol id still frames",
			in:   "0001 0010 0006 0a 01 0001 0003",
			want: 12,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := d.PDULen(adu(t, tc.in))
			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, n)
		})
	}
}

func TestProbe(t *testing.T) {
	d := modbus.New()

	tests := []struct {
		name    string
		in      string
		dir     model.Direction
		minWant int
		maxWant int
	}{
		{
			name:    "well formed request scores high",
			in:      "0001 0000 0006 0a 03 0005 0002",
			dir:     model.DirRequest,
			minWant: 90,
			maxWant: 100,
		},
		{
			name:    "well formed response scores high",
			in:      "0001 0000 0007 0a 03 04 0009 0018",
			dir:     model.DirResponse,
			minWant: 90,
			maxWant: 100,
		},
		{
			name:    "non-zero protocol id scores low but non-zero",
			in:      "0001 0010 0006 0a 01 0001 0003",
			dir:     model.DirRequest,
			minWant: 1,
			maxWant: 40,
		},
		{
			name:    "too short to hold a frame scores zero",
			in:      "0001 0000",
			dir:     model.DirRequest,
			minWant: 0,
			maxWant: 0,
		},
		{
			name:    "HTTP request scores zero",
			in:      hex.EncodeToString([]byte("GET / HTTP/1.1\r\nHost: plc\r\n\r\n")),
			dir:     model.DirRequest,
			minWant: 0,
			maxWant: 0,
		},
		{
			name:    "length inconsistent with payload scores below threshold",
			in:      "0001 0000 00fe 0a 03 0005 0002",
			dir:     model.DirRequest,
			minWant: 0,
			maxWant: 69,
		},
		{
			// From modbus_test_data_part1.pcap. The protocol identifier is
			// zero, so this is crafted Modbus rather than another protocol,
			// and the stream must still be bound and reported.
			name:    "modbus shaped header with impossible length still scores",
			in:      "0001 0000 8804 05 07 0809",
			dir:     model.DirRequest,
			minWant: 1,
			maxWant: 30,
		},
		{
			// modbus_test_data_part2.pcap opens its function code sweep with
			// code 0, which does not exist. Dropping that stream would lose
			// the whole capture.
			name:    "function code zero still scores as modbus",
			in:      "0000 0000 0006 01 00 0000 0000",
			dir:     model.DirRequest,
			minWant: 50,
			maxWant: 85,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := d.Probe(ctxFor(tc.dir), adu(t, tc.in))
			assert.GreaterOrEqual(t, got, tc.minWant)
			assert.LessOrEqual(t, got, tc.maxWant)
		})
	}
}

func TestParseRequests(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want model.Event
	}{
		{
			name: "read coils",
			in:   "0001 0000 0006 0a 01 0000 0001",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirRequest,
				Operation: "ReadCoils", FunctionCode: 1, Class: model.ClassRead,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Address: model.Ptr(uint32(0)), Quantity: model.Ptr(uint32(1)),
			},
		},
		{
			name: "read holding registers",
			in:   "0001 0000 0006 0a 03 0005 0002",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirRequest,
				Operation: "ReadHoldingRegisters", FunctionCode: 3, Class: model.ClassRead,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Address: model.Ptr(uint32(5)), Quantity: model.Ptr(uint32(2)),
			},
		},
		{
			name: "write single coil off",
			in:   "0001 0000 0006 0a 05 0002 0000",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirRequest,
				Operation: "WriteSingleCoil", FunctionCode: 5, Class: model.ClassWrite,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Address: model.Ptr(uint32(2)), Quantity: model.Ptr(uint32(1)),
				Attrs: map[string]string{"value": "0x0000", "coil_state": "off"},
			},
		},
		{
			name: "write single coil on",
			in:   "0001 0000 0006 0a 05 0002 ff00",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirRequest,
				Operation: "WriteSingleCoil", FunctionCode: 5, Class: model.ClassWrite,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Address: model.Ptr(uint32(2)), Quantity: model.Ptr(uint32(1)),
				Attrs: map[string]string{"value": "0xff00", "coil_state": "on"},
			},
		},
		{
			name: "write single register",
			in:   "0001 0000 0006 0a 06 0005 000b",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirRequest,
				Operation: "WriteSingleRegister", FunctionCode: 6, Class: model.ClassWrite,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Address: model.Ptr(uint32(5)), Quantity: model.Ptr(uint32(1)),
				Attrs: map[string]string{"value": "11"},
			},
		},
		{
			name: "write multiple registers",
			in:   "0001 0000 000b 0a 10 0010 0002 04 0001 0002",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirRequest,
				Operation: "WriteMultipleRegisters", FunctionCode: 16, Class: model.ClassWrite,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Address: model.Ptr(uint32(16)), Quantity: model.Ptr(uint32(2)),
				Attrs: map[string]string{"byte_count": "4"},
			},
		},
		{
			name: "read exception status has no body",
			in:   "0001 0000 0002 0a 07",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirRequest,
				Operation: "ReadExceptionStatus", FunctionCode: 7, Class: model.ClassDiagnostic,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
			},
		},
		{
			name: "report server id request",
			in:   "0000 0000 0002 0a 11",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirRequest,
				Operation: "ReportServerID", FunctionCode: 17, Class: model.ClassDiscovery,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(0)),
			},
		},
		{
			name: "mask write register",
			in:   "0001 0000 0008 0a 16 0004 00f2 0025",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirRequest,
				Operation: "MaskWriteRegister", FunctionCode: 22, Class: model.ClassWrite,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Address: model.Ptr(uint32(4)), Quantity: model.Ptr(uint32(1)),
				Attrs: map[string]string{"and_mask": "0x00f2", "or_mask": "0x0025"},
			},
		},
		{
			name: "read device identification",
			in:   "0001 0000 0005 0a 2b 0e 03 01",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirRequest,
				Operation: "ReadDeviceIdentification", FunctionCode: 43, Class: model.ClassDiscovery,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Attrs: map[string]string{
					"mei_type":            "14",
					"read_device_id_code": "3",
					"object_id":           "1",
				},
			},
		},
		{
			// Seen in modbus_test_data_part1.pcap: one byte more than the
			// spec's three. Trailing bytes are evidence, not a parse failure.
			name: "read device identification with trailing byte",
			in:   "0001 0000 0006 0a 2b 0e 03 01 00",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirRequest,
				Operation: "ReadDeviceIdentification", FunctionCode: 43, Class: model.ClassDiscovery,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Attrs: map[string]string{
					"mei_type":            "14",
					"read_device_id_code": "3",
					"object_id":           "1",
					"trailing_bytes":      "1",
				},
			},
		},
		{
			// A non-zero protocol identifier violates the Modbus/TCP spec and
			// is kept as an anomaly attribute for the rules engine.
			name: "non-zero protocol id is an anomaly",
			in:   "0001 0010 0006 0a 01 0001 0003",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirRequest,
				Operation: "ReadCoils", FunctionCode: 1, Class: model.ClassRead,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Address: model.Ptr(uint32(1)), Quantity: model.Ptr(uint32(3)),
				Attrs: map[string]string{
					"protocol_id": "16",
					"anomaly":     "non_zero_protocol_id",
				},
			},
		},
		{
			// Function code 42 is reserved for legacy use (Modbus Application
			// Protocol v1.1b3, section 5).
			name: "reserved function code",
			in:   "0001 0000 0005 0a 2a 0e 04 01",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirRequest,
				Operation: "Reserved", FunctionCode: 42, Class: model.ClassOther,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Attrs: map[string]string{"body": "0e0401"},
			},
		},
		{
			name: "user defined function code",
			in:   "0001 0000 0003 0a 41 07",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirRequest,
				Operation: "UserDefined", FunctionCode: 65, Class: model.ClassOther,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Attrs: map[string]string{"body": "07"},
			},
		},
	}

	d := modbus.New()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events, err := d.Parse(ctxFor(model.DirRequest), adu(t, tc.in))
			require.NoError(t, err)
			require.Len(t, events, 1, "one PDU yields exactly one event")
			assert.Equal(t, tc.want, strip(events[0]))
		})
	}
}

func TestParseDiagnostics(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantName string
		wantSub  string
		wantCls  model.Classification
	}{
		{
			name:     "return query data",
			in:       "0000 0000 0006 0a 08 0000 1234",
			wantName: "ReturnQueryData",
			wantSub:  "0",
			wantCls:  model.ClassDiagnostic,
		},
		{
			// Restarting communications drops the current session: treated as
			// a control action, not a read-only diagnostic.
			name:     "restart communications option",
			in:       "0000 0000 0006 0a 08 0001 0000",
			wantName: "RestartCommunicationsOption",
			wantSub:  "1",
			wantCls:  model.ClassControl,
		},
		{
			// Force Listen Only silences the device on the bus. CLAUDE.md
			// calls this out as a built-in detection rule.
			name:     "force listen only mode",
			in:       "0000 0000 0006 0a 08 0004 0000",
			wantName: "ForceListenOnlyMode",
			wantSub:  "4",
			wantCls:  model.ClassControl,
		},
		{
			name:     "clear counters",
			in:       "0000 0000 0006 0a 08 000a 0000",
			wantName: "ClearCountersAndDiagnosticRegister",
			wantSub:  "10",
			wantCls:  model.ClassDiagnostic,
		},
		{
			name:     "unknown sub-function",
			in:       "0000 0000 0006 0a 08 00ff 0000",
			wantName: "Unknown",
			wantSub:  "255",
			wantCls:  model.ClassDiagnostic,
		},
	}

	d := modbus.New()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events, err := d.Parse(ctxFor(model.DirRequest), adu(t, tc.in))
			require.NoError(t, err)
			require.Len(t, events, 1)
			got := events[0]
			assert.Equal(t, "Diagnostics", got.Operation)
			assert.Equal(t, 8, got.FunctionCode)
			assert.Equal(t, tc.wantCls, got.Class)
			assert.Equal(t, tc.wantSub, got.Attrs["sub_function"])
			assert.Equal(t, tc.wantName, got.Attrs["sub_function_name"])
		})
	}
}

func TestParseResponses(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want model.Event
	}{
		{
			name: "read coils response",
			in:   "0001 0000 0004 0a 01 01 00",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirResponse,
				Operation: "ReadCoils", FunctionCode: 1, Class: model.ClassRead,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Attrs: map[string]string{"byte_count": "1", "values": "00"},
			},
		},
		{
			name: "read holding registers response",
			in:   "0001 0000 0007 0a 03 04 0009 0018",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirResponse,
				Operation: "ReadHoldingRegisters", FunctionCode: 3, Class: model.ClassRead,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Quantity: model.Ptr(uint32(2)),
				Attrs:    map[string]string{"byte_count": "4", "values": "00090018"},
			},
		},
		{
			name: "write single coil response echoes the request",
			in:   "0001 0000 0006 0a 05 0002 0000",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirResponse,
				Operation: "WriteSingleCoil", FunctionCode: 5, Class: model.ClassWrite,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Address: model.Ptr(uint32(2)), Quantity: model.Ptr(uint32(1)),
				Attrs: map[string]string{"value": "0x0000", "coil_state": "off"},
			},
		},
		{
			// From modbus_test_data_part1.pcap: the ASCII run is device
			// identity evidence for the inventory.
			name: "report server id response carries device identity",
			in:   "0000 0000 0015 0a 11 12 00 ff 57 69 6e 67 70 61 74 68 20 4c 69 6d 69 74 65 64",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirResponse,
				Operation: "ReportServerID", FunctionCode: 17, Class: model.ClassDiscovery,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(0)),
				Identity: map[string]string{"report_server_id": "Wingpath Limited"},
				Attrs: map[string]string{
					"byte_count":    "18",
					"server_id":     "0",
					"run_indicator": "on",
				},
			},
		},
		{
			name: "read device identification response carries vendor and product",
			in: "0001 0000 001d 0a 2b 0e 01 81 00 00 03" +
				" 00 08 57 69 6e 67 70 61 74 68" +
				" 01 04 50 4c 43 31" +
				" 02 03 31 2e 30",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirResponse,
				Operation: "ReadDeviceIdentification", FunctionCode: 43, Class: model.ClassDiscovery,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Identity: map[string]string{
					"vendor_name":          "Wingpath",
					"product_code":         "PLC1",
					"major_minor_revision": "1.0",
				},
				Attrs: map[string]string{
					"mei_type":            "14",
					"read_device_id_code": "1",
					"conformity_level":    "0x81",
					"more_follows":        "false",
					"object_count":        "3",
				},
			},
		},
		{
			name: "exception response",
			in:   "0001 0000 0003 0a 81 06",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirResponse,
				Operation: "ReadCoils", FunctionCode: 1, Class: model.ClassRead,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(1)),
				Exception: "ServerDeviceBusy",
				Attrs:     map[string]string{"exception_code": "6"},
			},
		},
		{
			name: "gateway exception response",
			in:   "0000 0000 0003 0a 88 0b",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirResponse,
				Operation: "Diagnostics", FunctionCode: 8, Class: model.ClassDiagnostic,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(0)),
				Exception: "GatewayTargetDeviceFailedToRespond",
				Attrs:     map[string]string{"exception_code": "11"},
			},
		},
		{
			name: "unknown exception code keeps the number",
			in:   "0000 0000 0003 0a 81 7f",
			want: model.Event{
				Protocol: "modbus", Direction: model.DirResponse,
				Operation: "ReadCoils", FunctionCode: 1, Class: model.ClassRead,
				UnitID: model.Ptr(uint16(10)), TransactionID: model.Ptr(uint32(0)),
				Exception: "Unknown",
				Attrs:     map[string]string{"exception_code": "127"},
			},
		},
	}

	d := modbus.New()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events, err := d.Parse(ctxFor(model.DirResponse), adu(t, tc.in))
			require.NoError(t, err)
			require.Len(t, events, 1)
			assert.Equal(t, tc.want, strip(events[0]))
		})
	}
}

// An exception reply is a response whatever ingest guessed from the ports: the
// high bit of the function code says so.
func TestExceptionOverridesDirection(t *testing.T) {
	d := modbus.New()
	ctx := ctxFor(model.DirRequest)
	events, err := d.Parse(ctx, adu(t, "0001 0000 0003 0a 81 06"))
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, model.DirResponse, events[0].Direction)
	assert.Equal(t, model.DirRequest, ctx.Direction, "Parse must not mutate the context")
}

func TestParseTruncatedBodyIsMalformed(t *testing.T) {
	tests := []struct {
		name string
		in   string
		dir  model.Direction
	}{
		{name: "read request missing quantity", in: "0001 0000 0004 0a 03 0005", dir: model.DirRequest},
		{name: "read request missing address", in: "0001 0000 0002 0a 03", dir: model.DirRequest},
		{name: "exception without code", in: "0001 0000 0002 0a 81", dir: model.DirResponse},
		{name: "read response byte count beyond body", in: "0001 0000 0004 0a 03 08 00", dir: model.DirResponse},
		{name: "write multiple missing byte count", in: "0001 0000 0006 0a 10 0010 0002", dir: model.DirRequest},
		{name: "diagnostics missing data", in: "0001 0000 0003 0a 08 00", dir: model.DirRequest},
		{name: "device id request truncated", in: "0001 0000 0003 0a 2b 0e", dir: model.DirRequest},
	}

	d := modbus.New()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events, err := d.Parse(ctxFor(tc.dir), adu(t, tc.in))
			require.Error(t, err)
			assert.ErrorIs(t, err, dissect.ErrMalformed)
			// The evidence is kept: a crafted frame is itself interesting.
			require.Len(t, events, 1)
			assert.True(t, events[0].Malformed)
			assert.NotEmpty(t, events[0].Error)
			assert.Equal(t, "modbus", events[0].Protocol)
		})
	}
}

func TestParseShortHeaderIsMalformed(t *testing.T) {
	d := modbus.New()
	for n := 0; n < 8; n++ {
		full := adu(t, "0001 0000 0006 0a 03 0005 0002")
		_, err := d.Parse(ctxFor(model.DirRequest), full[:n])
		require.Error(t, err, "a %d byte PDU cannot hold an MBAP header and a function code", n)
		assert.ErrorIs(t, err, dissect.ErrMalformed)
	}
}

// Every prefix of every sample ADU must be handled without panicking. This is
// the cheap, deterministic sibling of the fuzz target.
func TestParseNeverPanicsOnTruncation(t *testing.T) {
	samples := []string{
		"0001 0000 0006 0a 01 0000 0001",
		"0001 0000 0007 0a 03 04 0009 0018",
		"0000 0000 0015 0a 11 12 00 ff 57 69 6e 67 70 61 74 68 20 4c 69 6d 69 74 65 64",
		"0001 0000 001d 0a 2b 0e 01 81 00 00 03 00 08 57 69 6e 67 70 61 74 68 01 04 50 4c 43 31 02 03 31 2e 30",
		"0000 0000 0006 0a 08 0004 0000",
		"0001 0000 0003 0a 81 06",
		"0001 0000 000b 0a 10 0010 0002 04 0001 0002",
		"0001 0000 0008 0a 17 0003 0006 000e 0003 06 0102 0304 0506",
	}

	d := modbus.New()
	for _, s := range samples {
		full := adu(t, s)
		for n := 0; n <= len(full); n++ {
			prefix := full[:n]
			require.NotPanics(t, func() {
				events, err := d.Parse(ctxFor(model.DirRequest), prefix)
				if err != nil && !errors.Is(err, dissect.ErrMalformed) {
					t.Errorf("prefix %d of %q: error must wrap ErrMalformed, got %v", n, s, err)
				}
				for _, e := range events {
					assert.True(t, e.Class.Valid(), "class %q must be one of the defined set", e.Class)
				}
			}, "prefix %d of %q", n, s)
			require.NotPanics(t, func() { _ = d.Probe(ctxFor(model.DirRequest), prefix) })
			require.NotPanics(t, func() { _, _ = d.PDULen(prefix) })
		}
	}
}

// Every function code the table knows must have a name and a valid
// classification, and every code must be classified somehow.
func TestFunctionTableIsComplete(t *testing.T) {
	d := modbus.New()
	for fc := 1; fc <= 127; fc++ {
		pdu := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x0a, byte(fc)}
		events, err := d.Parse(ctxFor(model.DirRequest), pdu)
		// A bodyless PDU is malformed for most codes; either way we must get
		// an event with a name and a valid class, and never a panic.
		if err != nil {
			require.Len(t, events, 1, "fc %d", fc)
		}
		require.NotEmpty(t, events, "fc %d produced no event", fc)
		e := events[0]
		assert.NotEmpty(t, e.Operation, "fc %d has no operation name", fc)
		assert.True(t, e.Class.Valid(), "fc %d has invalid class %q", fc, e.Class)
		assert.Equal(t, fc, e.FunctionCode, "fc %d", fc)
	}
}
