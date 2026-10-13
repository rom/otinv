package s7comm_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/s7comm"
	"github.com/rom/otinv/internal/model"
)

// Frames taken verbatim from the public S7comm sample captures in
// testdata/pcaps; the comment names the file and packet each came from.
const (
	// varservice #7: STEP 7 opens an ISO connection to rack 0, slot 2.
	frameConnectRequest = "0300001611e00000000100c1020100c2020102c00109"
	// varservice #8: the CPU confirms it.
	frameConnectConfirm = "0300001611d00001000300c00109c1020100c2020102"
	// varservice #9 and #10: the negotiated PDU size.
	frameSetupComm    = "0300001902f08032010000ffff00080000f000000100010780"
	frameSetupCommAck = "0300001b02f08032030000ffff000800000000f0000001000100f0"
	// varservice #11: read 64 bytes from DB1.
	frameReadVar = "0300001f02f080320100000000000e00000401120a10020040000184000000"
	// varservice #12: the reply, 64 bytes of data.
	frameReadVarAck = "0300005902f0803203000000000002004400000401ff0402000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000000000000000" +
		"00000000000000000000000000000000000000000000000000"
	// varservice #15: write four bytes of flag memory.
	frameWriteVar = "0300002702f080320100000002000e00080501120a1002000400008300000000040020a9100001"
	// varservice #16: the reply.
	frameWriteVarAck = "0300001602f0803203000000020002000100000501ff"
	// downloading_block_db1 #43: STEP 7 asks to download DB1.
	frameRequestDownload = "0300003102f080320100000e00002000001a00010000000000095f3041303030" +
		"3031500d31303030353030303030343030"
	// downloading_block_db1 #46: a block of DB1 on the wire.
	frameDownloadBlock = "0300002302f080320100000100001200001b00000000000000095f3041303030303150"
	// downloading_block_db1 #55: the download is finished.
	frameDownloadEnded = "0300002302f080320100000700001200001c00000000000000095f3041303030303150"
	// downloading_block_db1 #58: the PI service that activates the block.
	framePLCControlInsert = "0300002b02f080320100000f00001a000028000000000000fd000a0100304130" +
		"3030303150055f494e5345"
	// reading_plc_status #58: a request for SZL list 0x0011.
	frameReadSZLRequest = "0300002102f080320700001100000800080001120411440100ff09000400110000"
	// reading_plc_status #59: the module identification, with the order number.
	frameReadSZLModule = "0300009902f080320700001100000c007c000112081284010200000000ff0900780011" +
		"0000001c0004000136455337203135312d38414230312d304142302000c00003000100063645" +
		"53372031 35312d38414230312d304142302000c00003000100072020202020202020202020202020" +
		"2020202020 2000c0560302060081426f6f74204c6f61646572202020202020202020000041200909"
	// reading_plc_status #69: the component identification, with the model and
	// the serial number.
	frameReadSZLComponent = "030000f702f080320700001400000c00da000112081284010206010000ff0900d6001c" +
		"00000022000a0001494d3135312d382d4350550000000000000000000000000000000000000000" +
		"0002494d3135312d3820504e2f44502043505500000000000000000000000000000000030000000" +
		"0000000000000000000000000000000000000000000000000000000000000044f726967696e616c2" +
		"05369656d656e732045717569706d656e7400000000000000055320432d4336545737343838323031" +
		"32000000000000000000000000000000000007494d3135312d3820504e2f445020435055000000000" +
		"0000000000000000000000008"
)

func frame(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "\n", ""))
	require.NoError(t, err, "test fixture is not valid hex")
	return b
}

func ctxFor(dir model.Direction) *dissect.FlowContext {
	flow := model.Flow{
		SrcIP: "192.168.1.10", DstIP: "192.168.1.40",
		SrcPort: 4258, DstPort: s7comm.DefaultPort,
		Transport: model.TransportTCP,
	}
	if dir == model.DirResponse {
		flow = flow.Reverse()
	}
	return &dissect.FlowContext{
		CaptureID:   "test",
		Flow:        flow,
		PacketIndex: 11,
		Timestamp:   time.Unix(1256130000, 0).UTC(),
		Direction:   dir,
		ServerPort:  s7comm.DefaultPort,
	}
}

func parseOne(t *testing.T, d *s7comm.Dissector, ctx *dissect.FlowContext, raw []byte) model.Event {
	t.Helper()
	events, err := d.Parse(ctx, raw)
	require.NoError(t, err)
	require.Len(t, events, 1, "one PDU yields one event")
	return events[0]
}

func TestIdentity(t *testing.T) {
	d := s7comm.New()
	assert.Equal(t, "s7comm", d.Name())
	assert.Equal(t, 1, d.Tier())
}

func TestRegisteredOnDefaultPort(t *testing.T) {
	reg := dissect.Default()
	d, ok := reg.Lookup("s7comm")
	require.True(t, ok, "s7comm must register itself in init()")
	require.NotNil(t, d)
	assert.True(t, reg.HasPort("s7comm", model.TransportTCP, 102),
		"S7comm runs over ISO-on-TCP, port 102")
}

func TestPDULen(t *testing.T) {
	d := s7comm.New()

	tests := []struct {
		name    string
		in      string
		want    int
		wantErr error
	}{
		{name: "empty", in: "", wantErr: dissect.ErrNeedMore},
		{name: "partial tpkt header", in: "030000", wantErr: dissect.ErrNeedMore},
		{name: "connection request", in: frameConnectRequest, want: 22},
		{name: "read var job", in: frameReadVar, want: 31},
		{
			// A COTP data frame with no S7 payload: STEP 7 sends these as
			// keep-alives and they are seven octets long.
			name: "empty data frame",
			in:   "0300000702f000",
			want: 7,
		},
		{name: "truncated body needs more", in: frameReadVar[:20], wantErr: dissect.ErrNeedMore},
		{
			name: "first of two concatenated frames",
			in:   frameSetupComm + frameReadVar,
			want: 25,
		},
		{
			name:    "wrong tpkt version",
			in:      "0400001902f08032010000ffff00080000f000000100010780",
			wantErr: dissect.ErrMalformed,
		},
		{
			// A TPKT length below the header plus a COTP length indicator
			// cannot be a frame.
			name:    "length below the minimum",
			in:      "0300000402f000",
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
	d := s7comm.New()

	tests := []struct {
		name    string
		in      string
		minWant int
		maxWant int
	}{
		{name: "s7 job scores high", in: frameReadVar, minWant: 90, maxWant: 100},
		{name: "connection request scores high", in: frameConnectRequest, minWant: 80, maxWant: 100},
		{name: "empty data frame scores moderately", in: "0300000702f000", minWant: 40, maxWant: 85},
		{name: "too short scores zero", in: "0300", minWant: 0, maxWant: 0},
		{name: "wrong version scores zero", in: "0400001902f08032010000ffff0008", minWant: 0, maxWant: 0},
		{
			name:    "http scores zero",
			in:      hex.EncodeToString([]byte("GET / HTTP/1.1\r\nHost: plc\r\n\r\n")),
			minWant: 0,
			maxWant: 0,
		},
		{
			// A DNP3 frame must not be mistaken for ISO-on-TCP.
			name:    "dnp3 frame scores zero",
			in:      "056408c404000300b4b8cdc30daf84",
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

// The ISO connection request names the rack and slot of the CPU it is aimed
// at, which is structural information about the device.
func TestConnectionRequestDecodesRackAndSlot(t *testing.T) {
	d := s7comm.New()

	req := parseOne(t, d, ctxFor(model.DirRequest), frame(t, frameConnectRequest))
	assert.Equal(t, "ConnectionRequest", req.Operation)
	assert.Equal(t, model.ClassOther, req.Class)
	assert.Equal(t, "0x0100", req.Attrs["src_tsap"])
	assert.Equal(t, "0x0102", req.Attrs["dst_tsap"])
	assert.Equal(t, "0", req.Attrs["rack"])
	assert.Equal(t, "2", req.Attrs["slot"])
	assert.Equal(t, "512", req.Attrs["tpdu_size"])
	assert.Empty(t, req.Identity, "a request only says what the client asked for")

	// The confirm proves that rack and slot answered, so it is evidence about
	// the device.
	conf := parseOne(t, d, ctxFor(model.DirResponse), frame(t, frameConnectConfirm))
	assert.Equal(t, "ConnectionConfirm", conf.Operation)
	assert.Equal(t, "0", conf.Identity["rack"])
	assert.Equal(t, "2", conf.Identity["slot"])
}

func TestParseJobs(t *testing.T) {
	d := s7comm.New()

	tests := []struct {
		name      string
		in        string
		dir       model.Direction
		operation string
		fc        int
		class     model.Classification
		address   *uint32
		quantity  *uint32
		attrs     map[string]string
	}{
		{
			name:      "setup communication",
			in:        frameSetupComm,
			dir:       model.DirRequest,
			operation: "SETUP_COMMUNICATION",
			fc:        0xf0,
			class:     model.ClassOther,
			attrs: map[string]string{
				"rosctr":        "Job",
				"pdu_length":    "1920",
				"pdu_reference": "65535",
			},
		},
		{
			name:      "read a data block",
			in:        frameReadVar,
			dir:       model.DirRequest,
			operation: "READ_VAR",
			fc:        0x04,
			class:     model.ClassRead,
			address:   model.Ptr(uint32(0)),
			quantity:  model.Ptr(uint32(64)),
			attrs: map[string]string{
				"area":           "DB",
				"db_number":      "1",
				"transport_size": "BYTE",
				"item_count":     "1",
			},
		},
		{
			name:      "write flag memory",
			in:        frameWriteVar,
			dir:       model.DirRequest,
			operation: "WRITE_VAR",
			fc:        0x05,
			class:     model.ClassWrite,
			address:   model.Ptr(uint32(0)),
			quantity:  model.Ptr(uint32(4)),
			attrs: map[string]string{
				"area":       "Flags",
				"item_count": "1",
			},
		},
		{
			// CLAUDE.md names program upload and download as a rule, so these
			// classify as program rather than as a plain write.
			name:      "request a block download",
			in:        frameRequestDownload,
			dir:       model.DirRequest,
			operation: "REQUEST_DOWNLOAD",
			fc:        0x1a,
			class:     model.ClassProgram,
			attrs: map[string]string{
				"block_type":   "DB",
				"block_number": "1",
				"filename":     "_0A00001P",
			},
		},
		{
			name:      "download a block",
			in:        frameDownloadBlock,
			dir:       model.DirRequest,
			operation: "DOWNLOAD_BLOCK",
			fc:        0x1b,
			class:     model.ClassProgram,
			attrs: map[string]string{
				"block_type":   "DB",
				"block_number": "1",
			},
		},
		{
			name:      "download ended",
			in:        frameDownloadEnded,
			dir:       model.DirRequest,
			operation: "DOWNLOAD_ENDED",
			fc:        0x1c,
			class:     model.ClassProgram,
			attrs:     map[string]string{"block_type": "DB"},
		},
		{
			// Activating a downloaded block changes the program, so it is a
			// program operation rather than a plain control action.
			name:      "activate a block",
			in:        framePLCControlInsert,
			dir:       model.DirRequest,
			operation: "PLC_CONTROL",
			fc:        0x28,
			class:     model.ClassProgram,
			attrs:     map[string]string{"pi_service": "_INSE"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOne(t, d, ctxFor(tc.dir), frame(t, tc.in))

			assert.Equal(t, "s7comm", got.Protocol)
			assert.Equal(t, tc.operation, got.Operation)
			assert.Equal(t, tc.fc, got.FunctionCode)
			assert.Equal(t, tc.class, got.Class)
			assert.Equal(t, tc.address, got.Address)
			assert.Equal(t, tc.quantity, got.Quantity)
			for k, want := range tc.attrs {
				assert.Equal(t, want, got.Attrs[k], "attribute %q", k)
			}
			assert.False(t, got.Malformed)
		})
	}
}

func TestParseAcknowledgements(t *testing.T) {
	d := s7comm.New()

	t.Run("read reply reports the data it returned", func(t *testing.T) {
		got := parseOne(t, d, ctxFor(model.DirResponse), frame(t, frameReadVarAck))
		assert.Equal(t, "READ_VAR", got.Operation)
		assert.Equal(t, model.DirResponse, got.Direction)
		assert.Equal(t, "AckData", got.Attrs["rosctr"])
		assert.Equal(t, "SUCCESS", got.Attrs["return_code"])
		assert.Empty(t, got.Exception)
	})

	t.Run("write reply", func(t *testing.T) {
		got := parseOne(t, d, ctxFor(model.DirResponse), frame(t, frameWriteVarAck))
		assert.Equal(t, "WRITE_VAR", got.Operation)
		assert.Equal(t, model.ClassWrite, got.Class)
		assert.Equal(t, "SUCCESS", got.Attrs["return_code"])
	})

	t.Run("setup communication reply", func(t *testing.T) {
		got := parseOne(t, d, ctxFor(model.DirResponse), frame(t, frameSetupCommAck))
		assert.Equal(t, "SETUP_COMMUNICATION", got.Operation)
		assert.Equal(t, "240", got.Attrs["pdu_length"])
	})
}

// An error class and code in a reply is the CPU saying no, and must be
// readable without a lookup table in hand.
func TestErrorInReplyIsReported(t *testing.T) {
	d := s7comm.New()
	raw := frame(t, frameReadVarAck)
	// The error class and code sit after the ten byte header in an Ack_Data.
	raw[17] = 0x87 // error class: access error
	raw[18] = 0x00

	got := parseOne(t, d, ctxFor(model.DirResponse), raw)
	assert.Equal(t, "AccessError", got.Exception)
	assert.Equal(t, "0x87", got.Attrs["error_class"])
}

// The SZL lists are the S7 equivalent of an identity reply: CLAUDE.md names
// them as the enrichment source for CPU model and firmware.
func TestReadSZLIdentity(t *testing.T) {
	d := s7comm.New()

	t.Run("request", func(t *testing.T) {
		got := parseOne(t, d, ctxFor(model.DirRequest), frame(t, frameReadSZLRequest))
		assert.Equal(t, "ReadSZL", got.Operation)
		assert.Equal(t, model.ClassDiscovery, got.Class)
		assert.Equal(t, "Userdata", got.Attrs["rosctr"])
		assert.Equal(t, "0x0011", got.Attrs["szl_id"])
		assert.Empty(t, got.Identity, "a request carries no identity")
	})

	t.Run("module identification", func(t *testing.T) {
		got := parseOne(t, d, ctxFor(model.DirResponse), frame(t, frameReadSZLModule))
		assert.Equal(t, "ReadSZL", got.Operation)
		assert.Equal(t, model.ClassDiscovery, got.Class)
		assert.Equal(t, "0x0011", got.Attrs["szl_id"])
		assert.Equal(t, "6ES7 151-8AB01-0AB0", got.Identity["order_number"],
			"the Siemens order number of the module")
		assert.Equal(t, "V3.2.6", got.Identity["firmware_revision"])
	})

	t.Run("component identification", func(t *testing.T) {
		got := parseOne(t, d, ctxFor(model.DirResponse), frame(t, frameReadSZLComponent))
		assert.Equal(t, "0x001c", got.Attrs["szl_id"])
		assert.Equal(t, "IM151-8 PN/DP CPU", got.Identity["model"])
		assert.Equal(t, "S C-C6TW74882012", got.Identity["serial_number"])
		assert.Equal(t, "IM151-8-CPU", got.Identity["plc_name"])
		assert.Equal(t, "Siemens", got.Identity["vendor_name"],
			"the copyright string names the manufacturer")

		// This reply is one data unit of a longer list, which the event says
		// rather than pretending the list was complete.
		assert.Equal(t, "true", got.Attrs["more_follows"])
	})
}

// A CPU stop is a control action on the plant and CLAUDE.md names it as a
// rule. No sample capture holds one, so this frame is crafted.
func TestPLCStopIsControl(t *testing.T) {
	d := s7comm.New()
	raw := buildJob(t, 0x29, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x50, 0x5f,
		0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d})

	got := parseOne(t, d, ctxFor(model.DirRequest), raw)
	assert.Equal(t, "PLC_STOP", got.Operation)
	assert.Equal(t, 0x29, got.FunctionCode)
	assert.Equal(t, model.ClassControl, got.Class)
}

// buildJob wraps S7 job parameters in an S7 header, a COTP data frame and a
// TPKT header, so that tests can craft traffic the stack would accept.
func buildJob(t *testing.T, function byte, params []byte) []byte {
	t.Helper()
	body := append([]byte{function}, params...)

	s7 := []byte{0x32, 0x01, 0x00, 0x00, 0x00, 0x01,
		byte(len(body) >> 8), byte(len(body)), 0x00, 0x00}
	s7 = append(s7, body...)

	cotp := []byte{0x02, 0xf0, 0x80}
	total := 4 + len(cotp) + len(s7)
	out := []byte{0x03, 0x00, byte(total >> 8), byte(total)}
	out = append(out, cotp...)
	return append(out, s7...)
}

// A COTP data frame with no S7 payload is a keep-alive. It says nothing about
// the device, so it yields no event, and the frame still counts as handled.
func TestEmptyDataFrameYieldsNoEvent(t *testing.T) {
	d := s7comm.New()
	events, err := d.Parse(ctxFor(model.DirRequest), frame(t, "0300000702f000"))
	require.NoError(t, err)
	assert.Empty(t, events)
}

// S7comm-plus, which the S7-1200 and S7-1500 speak, shares port 102 but is a
// different protocol and a separate milestone. It must be reported once per
// stream rather than flooding or being silently dropped.
func TestS7CommPlusIsReportedOncePerStream(t *testing.T) {
	d := s7comm.New()
	ctx := ctxFor(model.DirRequest)
	// Protocol id 0x72 is S7comm-plus.
	raw := frame(t, "0300001b02f08072030000ffff000800000000f0000001000100f0")

	first, err := d.Parse(ctx, raw)
	require.NoError(t, err)
	require.Len(t, first, 1)
	assert.Equal(t, "UnsupportedPayload", first[0].Operation)
	assert.Equal(t, "0x72", first[0].Attrs["protocol_id"])
	assert.Equal(t, "s7comm-plus", first[0].Attrs["protocol_hint"])
	assert.False(t, first[0].Malformed, "another protocol is not a broken frame")

	second, err := d.Parse(ctx, raw)
	require.NoError(t, err)
	assert.Empty(t, second, "the same stream must not report it again")
}

func TestParseTruncatedIsMalformed(t *testing.T) {
	d := s7comm.New()
	tests := []struct {
		name string
		in   string
	}{
		{name: "tpkt only", in: "0300000a"},
		{name: "cotp without type", in: "0300000a02"},
		{name: "s7 header truncated", in: "0300000d02f0803201000000"},
		{name: "s7 parameters promise more than the frame holds", in: "0300001002f080320100000000ff0000"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := d.Parse(ctxFor(model.DirRequest), frame(t, tc.in))
			if err != nil {
				assert.ErrorIs(t, err, dissect.ErrMalformed)
			}
		})
	}
}

func TestParseNeverPanicsOnTruncation(t *testing.T) {
	d := s7comm.New()
	samples := []string{
		frameConnectRequest, frameConnectConfirm, frameSetupComm, frameSetupCommAck,
		frameReadVar, frameReadVarAck, frameWriteVar, frameWriteVarAck,
		frameRequestDownload, frameDownloadBlock, frameDownloadEnded,
		framePLCControlInsert, frameReadSZLRequest, frameReadSZLModule,
		frameReadSZLComponent,
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
			}, "prefix %d", n)
			require.NotPanics(t, func() { _ = d.Probe(ctxFor(model.DirRequest), prefix) })
			require.NotPanics(t, func() { _, _ = d.PDULen(prefix) })
		}
	}
}

// Every function code must have a name and a valid classification.
func TestFunctionTableIsComplete(t *testing.T) {
	d := s7comm.New()
	for fc := range 256 {
		raw := buildJob(t, byte(fc), []byte{0x00})
		events, _ := d.Parse(ctxFor(model.DirRequest), raw)
		require.Len(t, events, 1, "fc 0x%02x", fc)
		e := events[0]
		assert.NotEmpty(t, e.Operation, "fc 0x%02x has no name", fc)
		assert.True(t, e.Class.Valid(), "fc 0x%02x has invalid class %q", fc, e.Class)
	}
}

// The operations CLAUDE.md names as S7 rules must classify so that a rule
// never needs an S7 function number.
func TestSecurityRelevantOperationsAreClassified(t *testing.T) {
	tests := []struct {
		fc    byte
		name  string
		class model.Classification
	}{
		{fc: 0x04, name: "READ_VAR", class: model.ClassRead},
		{fc: 0x05, name: "WRITE_VAR", class: model.ClassWrite},
		{fc: 0x1a, name: "REQUEST_DOWNLOAD", class: model.ClassProgram},
		{fc: 0x1b, name: "DOWNLOAD_BLOCK", class: model.ClassProgram},
		{fc: 0x1c, name: "DOWNLOAD_ENDED", class: model.ClassProgram},
		{fc: 0x1d, name: "START_UPLOAD", class: model.ClassProgram},
		{fc: 0x1e, name: "UPLOAD", class: model.ClassProgram},
		{fc: 0x1f, name: "END_UPLOAD", class: model.ClassProgram},
		{fc: 0x29, name: "PLC_STOP", class: model.ClassControl},
		{fc: 0xf0, name: "SETUP_COMMUNICATION", class: model.ClassOther},
	}

	d := s7comm.New()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOne(t, d, ctxFor(model.DirRequest), buildJob(t, tc.fc, []byte{0x00}))
			assert.Equal(t, tc.name, got.Operation)
			assert.Equal(t, tc.class, got.Class)
		})
	}
}

// Block manipulation through the PI services is a program change, whatever
// else PLC_CONTROL is used for.
func TestPIServiceClassification(t *testing.T) {
	d := s7comm.New()
	tests := []struct {
		service string
		class   model.Classification
	}{
		{service: "_INSE", class: model.ClassProgram},
		{service: "_DELE", class: model.ClassProgram},
		{service: "P_PROGRAM", class: model.ClassControl},
		{service: "_GARB", class: model.ClassControl},
	}

	for _, tc := range tests {
		t.Run(tc.service, func(t *testing.T) {
			// Seven octets before the parameter block length, which is zero
			// here, matching the layout in the sample capture.
			params := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00}
			params = append(params, byte(len(tc.service)))
			params = append(params, []byte(tc.service)...)
			got := parseOne(t, d, ctxFor(model.DirRequest), buildJob(t, 0x28, params))

			assert.Equal(t, "PLC_CONTROL", got.Operation)
			assert.Equal(t, tc.service, got.Attrs["pi_service"])
			assert.Equal(t, tc.class, got.Class)
		})
	}
}
