package dnp3_test

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/dnp3"
	"github.com/rom/otinv/internal/model"
)

// Frames taken verbatim from the public Digital Bond Quickdraw DNP3 captures
// in testdata/pcaps; the comment names the packet each one came from.
const (
	// part1 #70: master tells outstation 4 to cold restart.
	frameColdRestart = "056408c404000300b4b8cdc30daf84"
	// part1 #7: master writes the time (group 50 variation 1).
	frameWriteTime = "056412c4040003001e7cc1c10232010701ebe45a87ff002801"
	// part1 #11: master disables unsolicited reporting for classes 1, 2 and 3.
	frameDisableUnsolicited = "056411c4040003004eefc2c2153c02063c03063c0406b1ec"
	// part1 #71: outstation replies, no internal indications set.
	frameResponseTimeDelay = "0564104403000400d66ad6c381000034020701881373fb"
	// part1 #19: the same disable/enable request with a corrupted start byte,
	// 0x05 0x05 instead of 0x05 0x64.
	frameBadStart = "050511c40400030046a2c2c2143c02063c03063c0406d32f"
	// part2 #4: master selects a control relay output block, latch on, on
	// index 34463.
	frameSelectCROB = "05641ac404000300c2e6d2c3030c012801009f86030164000000ec416400000000005b"
	// part2 #5: the outstation rejects it with a parameter error.
	frameSelectReject = "05641c440300040064bdf9c38100040c012801009f8603016400ed30000064000000047882"
	// part2 #19: a read of object group 255, which does not exist.
	frameReadUnknownGroup = "05640bc404000300e42bd7c801ff000607fb"
	// A link layer reset with no application data, from IEEE 1815.
	frameResetLink = "056405c001000004e921"
)

func frame(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	require.NoError(t, err, "test fixture is not valid hex")
	return b
}

func ctxFor(dir model.Direction) *dissect.FlowContext {
	flow := model.Flow{
		SrcIP: "10.0.0.8", DstIP: "10.0.0.3",
		SrcPort: 2828, DstPort: dnp3.DefaultPort,
		Transport: model.TransportTCP,
	}
	if dir == model.DirResponse {
		flow = flow.Reverse()
	}
	return &dissect.FlowContext{
		CaptureID:   "test",
		Flow:        flow,
		PacketIndex: 7,
		Timestamp:   time.Unix(1093521694, 0).UTC(),
		Direction:   dir,
		ServerPort:  dnp3.DefaultPort,
	}
}

func parseOne(t *testing.T, d *dnp3.Dissector, ctx *dissect.FlowContext, raw []byte) model.Event {
	t.Helper()
	events, err := d.Parse(ctx, raw)
	require.NoError(t, err)
	require.Len(t, events, 1, "one application fragment yields one event")
	return events[0]
}

func TestIdentity(t *testing.T) {
	d := dnp3.New()
	assert.Equal(t, "dnp3", d.Name())
	assert.Equal(t, 1, d.Tier())
}

func TestRegisteredOnDefaultPorts(t *testing.T) {
	reg := dissect.Default()
	d, ok := reg.Lookup("dnp3")
	require.True(t, ok, "dnp3 must register itself in init()")
	require.NotNil(t, d)
	assert.True(t, reg.HasPort("dnp3", model.TransportTCP, 20000))
	assert.True(t, reg.HasPort("dnp3", model.TransportUDP, 20000),
		"CLAUDE.md lists DNP3 on 20000/TCP+UDP")
}

// The CRC is the one from IEEE 1815; this vector is a link reset frame whose
// header CRC is part of the standard's own example.
func TestCRC(t *testing.T) {
	header := frame(t, frameResetLink)[:8]
	assert.Equal(t, uint16(0x21e9), dnp3.CRC(header))
}

func TestPDULen(t *testing.T) {
	d := dnp3.New()

	tests := []struct {
		name    string
		in      string
		want    int
		wantErr error
	}{
		{name: "empty", in: "", wantErr: dissect.ErrNeedMore},
		{name: "partial header", in: "056408c4", wantErr: dissect.ErrNeedMore},
		{
			name: "link layer frame with no body",
			in:   frameResetLink,
			want: 10,
		},
		{
			name: "single block frame",
			in:   frameColdRestart,
			want: 15, // 10 header + 3 data + 2 CRC
		},
		{
			name: "two block frame",
			in:   frameSelectCROB,
			want: 35, // 10 header + 16 + 2 + 5 + 2
		},
		{
			name:    "truncated body needs more",
			in:      frameColdRestart[:20],
			wantErr: dissect.ErrNeedMore,
		},
		{
			name: "first of two concatenated frames",
			in:   frameColdRestart + frameColdRestart,
			want: 15,
		},
		{
			// The start octets are the only thing that marks a frame, so a
			// wrong pair means the stream is not where it thinks it is.
			name:    "wrong start octets",
			in:      frameBadStart,
			wantErr: dissect.ErrMalformed,
		},
		{
			// The length octet counts the control and address fields, so
			// anything below 5 is impossible.
			name:    "length below the minimum",
			in:      "056404c001000004e921",
			wantErr: dissect.ErrMalformed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := d.PDULen(frame(t, tc.in))
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
	d := dnp3.New()

	tests := []struct {
		name    string
		in      string
		minWant int
		maxWant int
	}{
		{name: "real request scores high", in: frameColdRestart, minWant: 90, maxWant: 100},
		{name: "real response scores high", in: frameResponseTimeDelay, minWant: 90, maxWant: 100},
		{name: "link layer frame scores high", in: frameResetLink, minWant: 70, maxWant: 100},
		{name: "corrupted start octets score zero", in: frameBadStart, minWant: 0, maxWant: 0},
		{name: "too short scores zero", in: "0564", minWant: 0, maxWant: 0},
		{
			name:    "http scores zero",
			in:      hex.EncodeToString([]byte("GET / HTTP/1.1\r\nHost: rtu\r\n\r\n")),
			minWant: 0,
			maxWant: 0,
		},
		{
			// A Modbus/TCP frame must not be mistaken for DNP3.
			name:    "modbus frame scores zero",
			in:      "0001000000060a030005 0002",
			minWant: 0,
			maxWant: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := d.Probe(ctxFor(model.DirRequest), frame(t, tc.in))
			assert.GreaterOrEqual(t, got, tc.minWant)
			assert.LessOrEqual(t, got, tc.maxWant)
		})
	}
}

func TestParseRequests(t *testing.T) {
	d := dnp3.New()

	tests := []struct {
		name      string
		in        string
		operation string
		fc        int
		class     model.Classification
		unit      uint16
		address   *uint32
		quantity  *uint32
		attrs     map[string]string
	}{
		{
			// CLAUDE.md names cold restart as a built-in detection rule, so it
			// has to classify as a control action.
			name:      "cold restart",
			in:        frameColdRestart,
			operation: "COLD_RESTART",
			fc:        13,
			class:     model.ClassControl,
			unit:      4,
			attrs: map[string]string{
				"link_function": "CONFIRMED_USER_DATA",
				"link_source":   "3",
				"link_dest":     "4",
				"from_master":   "true",
				"transport_seq": "13",
				"app_seq":       "3",
			},
		},
		{
			name:      "write time and date",
			in:        frameWriteTime,
			operation: "WRITE",
			fc:        2,
			class:     model.ClassWrite,
			unit:      4,
			quantity:  model.Ptr(uint32(1)),
			attrs: map[string]string{
				"objects":     "g50v1",
				"group":       "50",
				"variation":   "1",
				"qualifier":   "0x07",
				"object_name": "TimeAndDate",
			},
		},
		{
			// Suppressing unsolicited reporting hides events from the master,
			// which CLAUDE.md also names as a rule.
			name:      "disable unsolicited",
			in:        frameDisableUnsolicited,
			operation: "DISABLE_UNSOLICITED",
			fc:        21,
			class:     model.ClassControl,
			unit:      4,
			attrs: map[string]string{
				"objects":     "g60v2,g60v3,g60v4",
				"object_name": "ClassData",
			},
		},
		{
			name:      "select a control relay output block",
			in:        frameSelectCROB,
			operation: "SELECT",
			fc:        3,
			class:     model.ClassControl,
			unit:      4,
			address:   model.Ptr(uint32(34463)),
			quantity:  model.Ptr(uint32(1)),
			attrs: map[string]string{
				"objects":       "g12v1",
				"group":         "12",
				"variation":     "1",
				"qualifier":     "0x28",
				"object_name":   "BinaryOutputCommand",
				"control_code":  "LATCH_ON",
				"control_count": "1",
				"on_time_ms":    "100",
				"off_time_ms":   "100",
				// The status octet is unused in a request, so it must not be
				// reported as though the outstation had already answered.
				"control_status": "",
			},
		},
		{
			name:      "read of an object group that does not exist",
			in:        frameReadUnknownGroup,
			operation: "READ",
			fc:        1,
			class:     model.ClassRead,
			unit:      4,
			attrs: map[string]string{
				"objects": "g255v0",
				"group":   "255",
				"anomaly": "unknown_object_group",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOne(t, d, ctxFor(model.DirRequest), frame(t, tc.in))

			assert.Equal(t, "dnp3", got.Protocol)
			assert.Equal(t, model.DirRequest, got.Direction)
			assert.Equal(t, tc.operation, got.Operation)
			assert.Equal(t, tc.fc, got.FunctionCode)
			assert.Equal(t, tc.class, got.Class)
			require.NotNil(t, got.UnitID)
			assert.Equal(t, tc.unit, *got.UnitID, "the unit is the outstation's link address")
			assert.Equal(t, tc.address, got.Address)
			assert.Equal(t, tc.quantity, got.Quantity)
			for k, want := range tc.attrs {
				assert.Equal(t, want, got.Attrs[k], "attribute %q", k)
			}
			assert.False(t, got.Malformed)
		})
	}
}

func TestParseResponses(t *testing.T) {
	d := dnp3.New()

	t.Run("response with no internal indications", func(t *testing.T) {
		got := parseOne(t, d, ctxFor(model.DirResponse), frame(t, frameResponseTimeDelay))
		assert.Equal(t, "RESPONSE", got.Operation)
		assert.Equal(t, 129, got.FunctionCode)
		assert.Equal(t, model.DirResponse, got.Direction)
		require.NotNil(t, got.UnitID)
		assert.Equal(t, uint16(4), *got.UnitID, "the outstation is the source of a response")
		assert.Equal(t, "0x0000", got.Attrs["iin"])
		assert.Empty(t, got.Attrs["iin_flags"])
		assert.Equal(t, "g52v2", got.Attrs["objects"])
	})

	t.Run("rejected select carries the internal indication", func(t *testing.T) {
		got := parseOne(t, d, ctxFor(model.DirResponse), frame(t, frameSelectReject))
		assert.Equal(t, "RESPONSE", got.Operation)
		assert.Equal(t, model.DirResponse, got.Direction)
		assert.Contains(t, got.Attrs["iin_flags"], "parameter_error",
			"the outstation said why it refused")
		assert.Equal(t, "12", got.Attrs["group"])
		assert.Equal(t, "NOT_SUPPORTED", got.Attrs["control_status"],
			"a reply carries the command status; a request does not")
	})
}

// A response is a response however the ports were read, and so is an
// unsolicited one, which arrives without any request at all.
func TestFunctionCodeDecidesDirection(t *testing.T) {
	d := dnp3.New()
	ctx := ctxFor(model.DirRequest)
	got := parseOne(t, d, ctx, frame(t, frameResponseTimeDelay))
	assert.Equal(t, model.DirResponse, got.Direction)
	assert.Equal(t, model.DirRequest, ctx.Direction, "Parse must not mutate the context")
}

// A frame with no application data is still evidence that DNP3 is spoken here.
func TestLinkLayerOnlyFrame(t *testing.T) {
	d := dnp3.New()
	got := parseOne(t, d, ctxFor(model.DirRequest), frame(t, frameResetLink))
	assert.Equal(t, "RESET_LINK_STATES", got.Operation)
	assert.Equal(t, -1, got.FunctionCode, "there is no application function code")
	assert.Equal(t, model.ClassOther, got.Class)
	assert.Equal(t, "link", got.Attrs["layer"])
	require.NotNil(t, got.UnitID)
	assert.Equal(t, uint16(1), *got.UnitID)
}

func TestHeaderCRCMismatchIsMalformed(t *testing.T) {
	d := dnp3.New()
	raw := frame(t, frameColdRestart)
	raw[8] ^= 0xff // corrupt the header CRC

	events, err := d.Parse(ctxFor(model.DirRequest), raw)
	require.Error(t, err)
	assert.ErrorIs(t, err, dissect.ErrMalformed)
	require.Len(t, events, 1)
	assert.True(t, events[0].Malformed)
	assert.Contains(t, events[0].Error, "header CRC")
}

// A corrupt data block is reported but still decoded: the frame is evidence
// either way, and the analyst needs to know the bytes were not trustworthy.
func TestBlockCRCMismatchIsAnomaly(t *testing.T) {
	d := dnp3.New()
	raw := frame(t, frameColdRestart)
	raw[len(raw)-1] ^= 0xff // corrupt the data block CRC

	got := parseOne(t, d, ctxFor(model.DirRequest), raw)
	assert.Equal(t, "COLD_RESTART", got.Operation)
	assert.Equal(t, "1", got.Attrs["crc_errors"])
	assert.Contains(t, got.Attrs["anomaly"], "crc_mismatch")
}

// buildFrame assembles a link frame with correct CRCs, so that tests can craft
// traffic the spec would accept.
func buildFrame(t *testing.T, control byte, dst, src uint16, body []byte) []byte {
	t.Helper()
	header := []byte{0x05, 0x64, byte(len(body) + 5), control, 0, 0, 0, 0}
	binary.LittleEndian.PutUint16(header[4:6], dst)
	binary.LittleEndian.PutUint16(header[6:8], src)

	out := append([]byte{}, header...)
	out = binary.LittleEndian.AppendUint16(out, dnp3.CRC(header))
	for len(body) > 0 {
		n := min(16, len(body))
		out = append(out, body[:n]...)
		out = binary.LittleEndian.AppendUint16(out, dnp3.CRC(body[:n]))
		body = body[n:]
	}
	return out
}

// An application fragment too big for one link frame is split by the transport
// function and must be reassembled before it means anything.
func TestTransportReassembly(t *testing.T) {
	d := dnp3.New()
	ctx := ctxFor(model.DirResponse)

	// RESPONSE, no IIN bits, reading analog inputs 0..1 (group 30 variation 2,
	// three bytes each), split across two link frames.
	app := []byte{0xc1, 0x81, 0x00, 0x00, 30, 2, 0x00, 0x00, 0x01,
		0x01, 0x10, 0x27, 0x01, 0x20, 0x4e}
	first := buildFrame(t, 0x44, 3, 4, append([]byte{0x40 | 5}, app[:8]...))  // FIR, seq 5
	second := buildFrame(t, 0x44, 3, 4, append([]byte{0x80 | 6}, app[8:]...)) // FIN, seq 6

	events, err := d.Parse(ctx, first)
	require.NoError(t, err)
	assert.Empty(t, events, "an incomplete fragment produces nothing yet")

	events, err = d.Parse(ctx, second)
	require.NoError(t, err)
	require.Len(t, events, 1, "the reassembled fragment is one event")
	assert.Equal(t, "RESPONSE", events[0].Operation)
	assert.Equal(t, "g30v2", events[0].Attrs["objects"])
	assert.Equal(t, "2", events[0].Attrs["transport_frames"])
}

// A gap in the transport sequence means a frame was lost, so the partial
// fragment must be dropped rather than stitched into nonsense.
func TestTransportSequenceGapIsReported(t *testing.T) {
	d := dnp3.New()
	ctx := ctxFor(model.DirResponse)

	app := []byte{0xc1, 0x81, 0x00, 0x00, 30, 2, 0x00, 0x00, 0x01}
	first := buildFrame(t, 0x44, 3, 4, append([]byte{0x40 | 5}, app[:8]...)) // FIR, seq 5
	// seq jumps from 5 to 9.
	second := buildFrame(t, 0x44, 3, 4, append([]byte{0x80 | 9}, app[8:]...))

	_, err := d.Parse(ctx, first)
	require.NoError(t, err)

	events, err := d.Parse(ctx, second)
	require.Error(t, err)
	assert.ErrorIs(t, err, dissect.ErrMalformed)
	require.Len(t, events, 1)
	assert.Contains(t, events[0].Error, "sequence")
}

// A continuation that never ends must not grow without bound.
func TestReassemblyBufferIsCapped(t *testing.T) {
	d := dnp3.New()
	ctx := ctxFor(model.DirResponse)

	body := make([]byte, 249)
	for i := range body {
		body[i] = 0x41
	}

	var lastErr error
	for seq := 0; seq < 64; seq++ {
		control := byte(seq & 0x3f)
		if seq == 0 {
			control |= 0x40 // FIR
		}
		raw := buildFrame(t, 0x44, 3, 4, append([]byte{control}, body...))
		if _, err := d.Parse(ctx, raw); err != nil {
			lastErr = err
			break
		}
	}
	require.Error(t, lastErr, "the dissector must refuse an endless fragment")
	assert.ErrorIs(t, lastErr, dissect.ErrMalformed)
}

func TestParseTruncatedIsMalformed(t *testing.T) {
	d := dnp3.New()
	tests := []struct {
		name string
		in   string
	}{
		{name: "header only", in: "056405c0010000"},
		{name: "no transport byte", in: "056405c001000004e921" + ""},
	}
	// A frame whose length promises a body it does not carry.
	raw := frame(t, frameColdRestart)
	short := append([]byte{}, raw[:12]...)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := d.Parse(ctxFor(model.DirRequest), frame(t, tc.in))
			if err != nil {
				assert.ErrorIs(t, err, dissect.ErrMalformed)
			}
		})
	}

	_, err := d.Parse(ctxFor(model.DirRequest), short)
	require.Error(t, err)
	assert.ErrorIs(t, err, dissect.ErrMalformed)
}

func TestParseNeverPanicsOnTruncation(t *testing.T) {
	d := dnp3.New()
	samples := []string{
		frameColdRestart, frameWriteTime, frameDisableUnsolicited,
		frameResponseTimeDelay, frameSelectCROB, frameSelectReject,
		frameReadUnknownGroup, frameResetLink, frameBadStart,
	}

	for _, s := range samples {
		full := frame(t, s)
		for n := 0; n <= len(full); n++ {
			prefix := full[:n]
			require.NotPanics(t, func() {
				events, err := d.Parse(ctxFor(model.DirRequest), prefix)
				if err != nil && !errors.Is(err, dissect.ErrMalformed) {
					t.Errorf("prefix %d of %q: error must wrap ErrMalformed, got %v", n, s, err)
				}
				for _, e := range events {
					assert.True(t, e.Class.Valid(), "class %q", e.Class)
				}
			}, "prefix %d of %q", n, s)
			require.NotPanics(t, func() { _ = d.Probe(ctxFor(model.DirRequest), prefix) })
			require.NotPanics(t, func() { _, _ = d.PDULen(prefix) })
		}
	}
}

// Every application function code must have a name and a valid
// classification, so that no operation shows up nameless in the GUI.
func TestFunctionTableIsComplete(t *testing.T) {
	d := dnp3.New()
	for fc := range 256 {
		body := []byte{0xc1, 0xc1, byte(fc)}
		raw := buildFrame(t, 0xc4, 4, 3, body)
		events, _ := d.Parse(ctxFor(model.DirRequest), raw)
		require.Len(t, events, 1, "fc %d", fc)
		e := events[0]
		assert.NotEmpty(t, e.Operation, "fc %d has no name", fc)
		assert.True(t, e.Class.Valid(), "fc %d has invalid class %q", fc, e.Class)
	}
}

// The operations CLAUDE.md calls out as detection rules must classify as
// something a rule can match without knowing DNP3 function numbers.
func TestSecurityRelevantOperationsAreClassified(t *testing.T) {
	d := dnp3.New()
	tests := []struct {
		fc    byte
		name  string
		class model.Classification
	}{
		{fc: 13, name: "COLD_RESTART", class: model.ClassControl},
		{fc: 14, name: "WARM_RESTART", class: model.ClassControl},
		{fc: 18, name: "STOP_APPL", class: model.ClassProgram},
		{fc: 17, name: "START_APPL", class: model.ClassProgram},
		{fc: 21, name: "DISABLE_UNSOLICITED", class: model.ClassControl},
		{fc: 20, name: "ENABLE_UNSOLICITED", class: model.ClassControl},
		{fc: 27, name: "DELETE_FILE", class: model.ClassProgram},
		{fc: 25, name: "OPEN_FILE", class: model.ClassProgram},
		{fc: 28, name: "GET_FILE_INFO", class: model.ClassRead},
		{fc: 31, name: "ACTIVATE_CONFIG", class: model.ClassProgram},
		{fc: 2, name: "WRITE", class: model.ClassWrite},
		{fc: 4, name: "OPERATE", class: model.ClassControl},
		{fc: 5, name: "DIRECT_OPERATE", class: model.ClassControl},
		{fc: 1, name: "READ", class: model.ClassRead},
		{fc: 23, name: "DELAY_MEASURE", class: model.ClassDiagnostic},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildFrame(t, 0xc4, 4, 3, []byte{0xc1, 0xc1, tc.fc})
			got := parseOne(t, d, ctxFor(model.DirRequest), raw)
			assert.Equal(t, tc.name, got.Operation)
			assert.Equal(t, tc.class, got.Class)
		})
	}
}

// A broadcast address names every outstation on the link, not a device. The
// sample capture has a master broadcasting DISABLE_UNSOLICITED and STOP_APPL,
// which reaches every device at once.
func TestBroadcastAddressIsNotAUnit(t *testing.T) {
	d := dnp3.New()

	tests := []struct {
		name     string
		dest     uint16
		wantKind string
	}{
		{name: "all stations", dest: 0xFFFF, wantKind: "broadcast"},
		{name: "broadcast lower bound", dest: 0xFFFD, wantKind: "broadcast"},
		{name: "self address", dest: 0xFFFC, wantKind: "self_address"},
		{name: "reserved", dest: 0xFFF5, wantKind: "reserved"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildFrame(t, 0xc4, tc.dest, 3, []byte{0xc1, 0xc1, 18}) // STOP_APPL
			got := parseOne(t, d, ctxFor(model.DirRequest), raw)

			assert.Equal(t, "STOP_APPL", got.Operation)
			assert.Equal(t, model.ClassProgram, got.Class)
			assert.Nil(t, got.UnitID, "a special address is not one device")
			assert.Equal(t, tc.wantKind, got.Attrs["address_kind"])
			assert.Equal(t, strconv.Itoa(int(tc.dest)), got.Attrs["link_dest"],
				"the address itself is still recorded")
			if tc.wantKind == "broadcast" {
				assert.Equal(t, "true", got.Attrs["broadcast"],
					"a broadcast program operation reaches every outstation")
			} else {
				assert.Empty(t, got.Attrs["broadcast"])
			}
		})
	}

	// An ordinary address is still reported as the unit.
	raw := buildFrame(t, 0xc4, 4, 3, []byte{0xc1, 0xc1, 18})
	got := parseOne(t, d, ctxFor(model.DirRequest), raw)
	require.NotNil(t, got.UnitID)
	assert.Equal(t, uint16(4), *got.UnitID)
	assert.Empty(t, got.Attrs["address_kind"])
}
