package enip_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/enip"
	"github.com/rom/otinv/internal/model"
)

// PDUs taken verbatim from the public EtherNet/IP sample captures in
// testdata/pcaps, from the first octet of the encapsulation header onward;
// the comment names the file and packet each came from. Every capture was
// decoded independently before these expectations were written.
const (
	// list_identity #6 and #7: a client asks what is out there, and a
	// 1756-ENBT/A communications adapter answers with its whole identity.
	pduListIdentityRequest = "63000000000000000000000000000000c1debed100000000"
	pduListIdentityReply   = "63003300000000000000000000000000c1debed1000000000100" +
		"0c002d0001000002af120a0101a4000000000000000001000c003a00040330008e4d52000b31" +
		"3735362d454e42542f4103"

	// cip_start #1 and cip_stop #1: a Start and a Stop of the object at
	// class 0x8E instance 1, sent over a connection.
	pduStart = "70001c0001002a00000000000000000000000000000000000000000001000200a100" +
		"0400224095ffb1000800e7000602208e2401"
	pduStop = "70001c0001002a00000000000000000000000000000000000000000001000200a100" +
		"0400224095ffb100080006010702208e2401"

	// cip_set_attribute #1: a device answers a Set_Attribute_Single with
	// success, over an unconnected message.
	pduSetAttributeReply = "6f0014000001021200000000ec6d8601701ee10000000000000000000500" +
		"020000000000b200040090000000"

	// cip_vendor_service #1: service 0x4C sent to class 0x74, which defines
	// no such service. On a symbol it would be Read_Tag; here nothing says
	// what it is.
	pduVendorService = "7000200000010212000000000000000000000000000000000000000001000200a1" +
		"000400016b0700b1000c004c1c4c04208e240120742401"

	// cip_batch_request #1 and cip_batch_reply #1: eleven attribute list
	// reads batched into one Multiple_Service_Packet, and their replies.
	pduBatchRequest = "7000ba0000010211000000000000000000000000000000000000000001000200a1000400" +
		"010b7c00b100a60089070a02200224010b00180022002c0036004c005800640072007c008a00" +
		"94000302200124010100050003022069240001000b0003022073240101000200030220ac2401" +
		"07000100020003000500070009000a000303206825002024010013000302207024010200120013" +
		"000302208e240103000300080010000302206924000100090003022068240003000f0018001900" +
		"030220772401010002000302208b240101000600"
	pduBatchReply = "70000d0100010211000000000000000000000000000000000000000000000200a1000400" +
		"2800fe80b100f90089078a0000000b001800240030003c0074007f009500ad00b900d500e10083" +
		"00000001000500000060308300000001000b00000003008300000001000200000000008300000007" +
		"000100000005000200000001000300000095291f04050000000000070000000200000009000000" +
		"010001000a0000008422df488300000001001300000000830000000200120000000000000013000000" +
		"000000008300000003000300000014000800000000001000000001008300000001000900000000008" +
		"300000003000f00000000001800000000000000190000000000000083000000010002000000020183" +
		"00000001000600000073b4ea05f4590400"

	// rockwell_session #10 and #12: a Get_Attributes_All of the Identity
	// object, routed to the backplane behind the bridge, and the reply that
	// names a 1756-L61/B controller.
	pduRoutedIdentityRead = "6f002400000102110000000022a902002008e100000000000000000020000200" +
		"00000000b200140052022006240107f9060001022001240101000100"
	pduRoutedIdentityReply = "6f003700000102110000000022a902002008e10000000000000000002000020000" +
		"000000b20027008100000001000e003600101460303f82510014313735362d4c36312f42204c4f4" +
		"7495835353631"

	// rockwell_session #23 and #24: a class 3 connection opened to the
	// message router on slot 0 of the chassis, and the target's answer.
	pduForwardOpen = "6f004000000102110000000035a902002008e10000000000000000002000020000000000" +
		"b200300054022006240107f9190000801800fe8019004d00f32b95320000000000127a00f44300127a" +
		"00f443a303010020022401"
	pduForwardOpenReply = "6f002e00000102110000000035a902002008e10000000000000000002000020000" +
		"000000b2001e00d4000000010d79001800fe8019004d00f32b953200127a0000127a000000"
)

func bytesOf(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
	require.NoError(t, err, "test fixture is not valid hex")
	return b
}

// tcpCtx is a flow to the explicit messaging port.
func tcpCtx(dir model.Direction) *dissect.FlowContext {
	flow := model.Flow{
		SrcIP: "192.168.10.105", DstIP: "192.168.10.120",
		SrcPort: 3033, DstPort: enip.DefaultPort, Transport: model.TransportTCP,
	}
	if dir == model.DirResponse {
		flow = flow.Reverse()
	}
	return &dissect.FlowContext{
		CaptureID:   "test",
		Flow:        flow,
		PacketIndex: 1,
		Timestamp:   time.Unix(1224804545, 0).UTC(),
		Direction:   dir,
		ServerPort:  enip.DefaultPort,
	}
}

// ioCtx is a flow of cyclic I/O, which has its own port because its frames
// carry no encapsulation header.
func ioCtx() *dissect.FlowContext {
	return &dissect.FlowContext{
		CaptureID: "test",
		Flow: model.Flow{
			SrcIP: "192.168.10.120", DstIP: "239.192.1.1",
			SrcPort: 2048, DstPort: enip.IOPort, Transport: model.TransportUDP,
		},
		PacketIndex: 1,
		Timestamp:   time.Unix(1224804545, 0).UTC(),
		Direction:   model.DirUnknown,
	}
}

func parseOne(t *testing.T, ctx *dissect.FlowContext, pdu string) model.Event {
	t.Helper()
	events, err := enip.New().Parse(ctx, bytesOf(t, pdu))
	require.NoError(t, err)
	require.Len(t, events, 1)
	return events[0]
}

func TestListIdentityRequest(t *testing.T) {
	ev := parseOne(t, tcpCtx(model.DirRequest), pduListIdentityRequest)
	assert.Equal(t, "ListIdentity", ev.Operation)
	assert.Equal(t, model.ClassDiscovery, ev.Class)
	assert.Equal(t, model.DirRequest, ev.Direction)
	assert.Empty(t, ev.Identity)
	// No session is registered for a list command, so there is no handle.
	assert.NotContains(t, ev.Attrs, "session_handle")
}

func TestListIdentityReplyCarriesTheWholeIdentity(t *testing.T) {
	ev := parseOne(t, tcpCtx(model.DirResponse), pduListIdentityReply)
	assert.Equal(t, "ListIdentity", ev.Operation)
	assert.Equal(t, model.ClassDiscovery, ev.Class)
	assert.Equal(t, model.DirResponse, ev.Direction)
	assert.Equal(t, map[string]string{
		"vendor_id":            "1",
		"vendor_name":          "Rockwell Automation/Allen-Bradley",
		"device_type":          "Communications Adapter",
		"product_code":         "58",
		"product_name":         "1756-ENBT/A",
		"major_minor_revision": "4.3",
		"serial_number":        "0x00524d8e",
	}, ev.Identity)
	assert.Equal(t, "10.1.1.164:44818", ev.Attrs["reported_address"])
	assert.Equal(t, "1", ev.Attrs["encapsulation_version"])
	assert.Equal(t, "0x0030", ev.Attrs["device_status"])
	assert.Equal(t, "3", ev.Attrs["device_state"])
	assert.Equal(t, "ListIdentityResponse", ev.Attrs["item"])
}

func TestControlServicesAreClassifiedAsControl(t *testing.T) {
	for _, tc := range []struct {
		name, pdu, op string
		seq           uint32
	}{
		{"start", pduStart, "Start", 231},
		{"stop", pduStop, "Stop", 262},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := parseOne(t, tcpCtx(model.DirRequest), tc.pdu)
			assert.Equal(t, tc.op, ev.Operation)
			assert.Equal(t, model.ClassControl, ev.Class)
			assert.Equal(t, model.DirRequest, ev.Direction)
			assert.Equal(t, "SendUnitData", ev.Attrs["command"])
			assert.Equal(t, "class=Class_0x008e,instance=1", ev.Attrs["cip_path"])
			assert.Equal(t, "0xff954022", ev.Attrs["connection_id"])
			// The connection's sequence count is what pairs a reply with its
			// request inside a connection.
			require.NotNil(t, ev.TransactionID)
			assert.Equal(t, tc.seq, *ev.TransactionID)
		})
	}
}

func TestReplyStatusIsRecorded(t *testing.T) {
	ev := parseOne(t, tcpCtx(model.DirResponse), pduSetAttributeReply)
	assert.Equal(t, "Set_Attribute_Single", ev.Operation)
	assert.Equal(t, model.ClassWrite, ev.Class)
	assert.Equal(t, model.DirResponse, ev.Direction)
	assert.Equal(t, "Success", ev.Attrs["cip_status"])
	assert.Empty(t, ev.Exception)
	assert.Equal(t, "0x12020100", ev.Attrs["session_handle"])
}

// A service code above the common range means whatever the object it was sent
// to says it means. Sent to a class that defines no such service, all that is
// known is the number.
func TestVendorServiceOnAnUnknownClassIsNotNamed(t *testing.T) {
	ev := parseOne(t, tcpCtx(model.DirRequest), pduVendorService)
	assert.Equal(t, "Service_0x4c", ev.Operation)
	assert.Equal(t, 0x4c, ev.FunctionCode)
	assert.Equal(t, model.ClassOther, ev.Class)
	assert.Equal(t, "vendor_specific", ev.Attrs["service_scope"])
	// The last class and instance in the path are the ones addressed.
	assert.Equal(t, "class=Class_0x008e,instance=1,class=Class_0x0074,instance=1",
		ev.Attrs["cip_path"])
	assert.Equal(t, "Class_0x0074", ev.Attrs["cip_class"])
}

func TestServiceBatch(t *testing.T) {
	req := parseOne(t, tcpCtx(model.DirRequest), pduBatchRequest)
	assert.Equal(t, "Multiple_Service_Packet", req.Operation)
	assert.Equal(t, model.ClassRead, req.Class, "a batch of reads is a read")
	assert.Equal(t, "11", req.Attrs["embedded_count"])
	assert.Equal(t, "Get_Attribute_List", req.Attrs["embedded_services"])
	assert.Equal(t, "class=MessageRouter,instance=1", req.Attrs["cip_path"])
	assert.NotContains(t, req.Attrs, "anomaly")

	reply := parseOne(t, tcpCtx(model.DirResponse), pduBatchReply)
	assert.Equal(t, "Multiple_Service_Packet", reply.Operation)
	assert.Equal(t, model.ClassRead, reply.Class)
	assert.Equal(t, "11", reply.Attrs["embedded_count"])
	assert.Equal(t, "Success", reply.Attrs["cip_status"])
	assert.NotContains(t, reply.Attrs, "anomaly")
}

// A write batched among reads must still be a write, or a rule watching for
// writes to a controller would not see it.
func TestBatchTakesTheMostConsequentialClass(t *testing.T) {
	batch := multipleServicePacket(t,
		"0302200124010100050000", // Get_Attribute_List of the Identity object
		"0802206b2401",           // Create an instance of the Symbol class
		"1002206b24013000",       // Set_Attribute_Single on it
	)
	ev := parseOne(t, tcpCtx(model.DirRequest), batch)
	assert.Equal(t, "Multiple_Service_Packet", ev.Operation)
	assert.Equal(t, model.ClassProgram, ev.Class)
	assert.Equal(t, "3", ev.Attrs["embedded_count"])
	assert.Equal(t, "Get_Attribute_List,Create,Set_Attribute_Single", ev.Attrs["embedded_services"])
}

// A request a bridge passes to the device behind it is the operation that
// happens, not the routing service that carried it.
func TestRoutedRequestIsTheOperationItCarries(t *testing.T) {
	ev := parseOne(t, tcpCtx(model.DirRequest), pduRoutedIdentityRead)
	assert.Equal(t, "Get_Attributes_All", ev.Operation)
	assert.Equal(t, model.ClassRead, ev.Class)
	assert.Equal(t, "Unconnected_Send", ev.Attrs["transport_service"])
	assert.Equal(t, "class=Identity,instance=1", ev.Attrs["cip_path"])
	// Port 1 is the backplane and link 0 the first slot, so the request was
	// for the controller next to the bridge it was sent to.
	assert.Equal(t, "port1/link0", ev.Attrs["cip_route"])
}

// The reply to a read of the Identity object is the one place a CIP device
// names itself outside discovery, and it arrives with nothing to say which
// object answered. See identityFromAttributes.
func TestIdentityIsRecoveredFromAnAttributeReply(t *testing.T) {
	ev := parseOne(t, tcpCtx(model.DirResponse), pduRoutedIdentityReply)
	assert.Equal(t, "Get_Attributes_All", ev.Operation)
	assert.Equal(t, model.DirResponse, ev.Direction)
	assert.Equal(t, "identity_object_layout", ev.Attrs["identity_match"])
	assert.Equal(t, map[string]string{
		"vendor_id":            "1",
		"vendor_name":          "Rockwell Automation/Allen-Bradley",
		"device_type":          "Programmable Logic Controller",
		"product_code":         "54",
		"product_name":         "1756-L61/B LOGIX5561",
		"major_minor_revision": "16.20",
		"serial_number":        "0x0051823f",
	}, ev.Identity)
}

// The reply to a read of any other object must not be read as an identity.
func TestOtherAttributeRepliesAreNotIdentities(t *testing.T) {
	for name, data := range map[string]string{
		"counters":     "81000000000000000000000000000000",
		"short":        "810000000100",
		"unknown_type": "8100000001001f003600101460303f82510014313735362d4c36312f42204c4f47495835353631",
		"no_revision":  "8100000001000e00360000000000000014313735362d4c36312f42204c4f47495835353631",
		"unprintable":  "8100000001000e003600101460303f8251001401020304050607080102030405060708010203",
	} {
		t.Run(name, func(t *testing.T) {
			ev := parseOne(t, tcpCtx(model.DirResponse), unconnectedMessage(t, data))
			assert.Empty(t, ev.Identity)
			assert.NotContains(t, ev.Attrs, "identity_match")
		})
	}
}

func TestForwardOpenDescribesTheConnection(t *testing.T) {
	req := parseOne(t, tcpCtx(model.DirRequest), pduForwardOpen)
	assert.Equal(t, "Forward_Open", req.Operation)
	assert.Equal(t, model.ClassOther, req.Class)
	assert.Equal(t, "0x80000019", req.Attrs["connection_o2t"])
	assert.Equal(t, "0x80fe0018", req.Attrs["connection_t2o"])
	assert.Equal(t, "0x0019", req.Attrs["connection_serial"])
	assert.Equal(t, "8000000", req.Attrs["o2t_interval_us"])
	assert.Equal(t, "3", req.Attrs["transport_class"])
	assert.Equal(t, "port1/link0,class=MessageRouter,instance=1", req.Attrs["connection_path"])
	// The originator is the client, so what it says about itself is not
	// identity, which is attributed to the server.
	assert.Equal(t, "77", req.Attrs["originator_vendor_id"])
	assert.Equal(t, "0x32952bf3", req.Attrs["originator_serial"])
	assert.Empty(t, req.Identity)

	// A reply carries no path, and 0x54 means Forward_Open on the one object
	// that defines it, so it can be named from the code alone.
	reply := parseOne(t, tcpCtx(model.DirResponse), pduForwardOpenReply)
	assert.Equal(t, "Forward_Open", reply.Operation)
	assert.Equal(t, model.DirResponse, reply.Direction)
	assert.Equal(t, "0x00790d01", reply.Attrs["connection_o2t"], "the target assigns its own")
	assert.Equal(t, "Success", reply.Attrs["cip_status"])
	assert.NotContains(t, reply.Attrs, "service_scope")
}

// 0x52 is a fragmented tag read on a symbol and Unconnected_Send on the
// connection manager, so a reply carrying it says only its number.
func TestAmbiguousReplyCodeIsNotNamed(t *testing.T) {
	ev := parseOne(t, tcpCtx(model.DirResponse), unconnectedMessage(t, "d2000000"))
	assert.Equal(t, "Service_0x52", ev.Operation)
	assert.Equal(t, model.ClassOther, ev.Class)
	assert.Equal(t, "vendor_specific", ev.Attrs["service_scope"])
}

// A tag read addresses its object by name, which is as good as a class at
// saying which service this is.
func TestSymbolicPathNamesATagService(t *testing.T) {
	// Read_Tag of the tag "PumpRun", one element.
	ev := parseOne(t, tcpCtx(model.DirRequest),
		unconnectedMessage(t, "4c05910750756d7052756e000100"))
	assert.Equal(t, "Read_Tag", ev.Operation)
	assert.Equal(t, model.ClassRead, ev.Class)
	assert.Equal(t, "PumpRun", ev.Attrs["cip_symbol"])
	require.NotNil(t, ev.Quantity)
	assert.Equal(t, uint32(1), *ev.Quantity)
	assert.NotContains(t, ev.Attrs, "service_scope")
}

func TestPathSegmentForms(t *testing.T) {
	for _, tc := range []struct {
		name, path, text string
		attrs            map[string]string
	}{
		{
			// A sixteen bit class and instance, each preceded by a pad octet.
			name: "wide_logical",
			path: "21003403250012003000",
			text: "class=Class_0x0334,instance=18,attribute=0",
		},
		{
			name: "member_and_connection_point",
			path: "20042406280a2c01",
			text: "class=Assembly,instance=6,member=10,connection_point=1",
		},
		{
			// An electronic key asserts which device must answer.
			name:  "electronic_key",
			path:  "3404010036009000100120022401",
			text:  "key,class=MessageRouter,instance=1",
			attrs: map[string]string{"connection_key": "vendor=1 device_type=54 product_code=144 revision=16.1"},
		},
		{
			// An extended link address, which is how an IP address is given
			// as a hop of a route.
			name: "extended_link",
			path: "120b3139322e3136382e312e310020022401",
			text: "port2/link192.168.1.1,class=MessageRouter,instance=1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			words := len(tc.path) / 4
			pdu := unconnectedMessage(t, "0e"+hex.EncodeToString([]byte{byte(words)})+tc.path)
			ev := parseOne(t, tcpCtx(model.DirRequest), pdu)
			assert.Equal(t, tc.text, ev.Attrs["cip_path"])
			assert.NotContains(t, ev.Attrs, "anomaly")
			for k, v := range tc.attrs {
				assert.Equal(t, v, ev.Attrs[k])
			}
		})
	}
}

// Cyclic I/O frames carry no encapsulation header at all, only the item list
// (EtherNet/IP specification, 3-2.1). The frame below is built to that shape:
// a sequenced address item naming the connection, and the connected data item
// with its sequence count and eight octets of process data.
func TestImplicitIOFrame(t *testing.T) {
	const frame = "0200" + "02800800" + "01000080" + "2a000000" +
		"b1000a00" + "0400" + "0102030405060708"
	ev := parseOne(t, ioCtx(), frame)
	assert.Equal(t, "IO_Data", ev.Operation)
	assert.Equal(t, model.ClassOther, ev.Class)
	assert.Equal(t, "0x80000001", ev.Attrs["connection_id"])
	assert.Equal(t, "10", ev.Attrs["data_bytes"])
	assert.Equal(t, "4", ev.Attrs["connection_seq"])
	require.NotNil(t, ev.TransactionID)
	assert.Equal(t, uint32(42), *ev.TransactionID)

	d := enip.New()
	assert.Equal(t, 90, d.Probe(ioCtx(), bytesOf(t, frame)))
	// The same octets on the explicit messaging port are not an I/O frame,
	// and read as a header they are nonsense.
	assert.Equal(t, 0, d.Probe(tcpCtx(model.DirRequest), bytesOf(t, frame)))

	n, err := d.PDULen(bytesOf(t, frame))
	require.NoError(t, err)
	assert.Equal(t, len(bytesOf(t, frame)), n)
}

func TestMalformedPDUs(t *testing.T) {
	for _, tc := range []struct {
		name, pdu, want string
	}{
		{
			name: "short_header",
			pdu:  "6f0014000001",
			want: "cannot hold an encapsulation header",
		},
		{
			name: "body_length_mismatch",
			pdu:  "6f00ff000001021200000000000000000000000000000000",
			want: "header declares 255 body octets",
		},
		{
			name: "item_runs_past_the_list",
			pdu:  encap(t, "6f00", "00000000"+"0500"+"0100"+"b200ff00"),
			want: "item 1 declares 255 octets",
		},
		{
			name: "too_many_items",
			pdu:  encap(t, "6f00", "00000000"+"0500"+"2000"),
			want: "item list declares 32 items",
		},
		{
			name: "request_path_overruns",
			pdu:  unconnectedMessage(t, "0eff2001"),
			want: "request path declares 510 octets",
		},
		{
			name: "reply_additional_status_overruns",
			pdu:  unconnectedMessage(t, "8e00ffff"),
			want: "additional status declares 510 octets",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events, err := enip.New().Parse(tcpCtx(model.DirRequest), bytesOf(t, tc.pdu))
			require.Error(t, err)
			assert.True(t, errors.Is(err, dissect.ErrMalformed), "error must wrap ErrMalformed")
			assert.Contains(t, err.Error(), tc.want)
			require.Len(t, events, 1)
			assert.True(t, events[0].Malformed)
			assert.Contains(t, events[0].Error, tc.want)
			assert.Equal(t, "enip", events[0].Protocol)
		})
	}
}

// A batch whose offsets point outside the data it carries is reported rather
// than followed.
func TestBatchWithBogusOffsets(t *testing.T) {
	ev := parseOne(t, tcpCtx(model.DirRequest),
		unconnectedMessage(t, "0a0220022401"+"0200"+"0600ff00"))
	assert.Equal(t, "Multiple_Service_Packet", ev.Operation)
	assert.Equal(t, "service_batch_offset_out_of_range", ev.Attrs["anomaly"])
	assert.False(t, ev.Malformed, "the frame itself is well formed")
}

func TestUnreadablePathSegmentIsReported(t *testing.T) {
	ev := parseOne(t, tcpCtx(model.DirRequest), unconnectedMessage(t, "0e02ff00ff00"))
	assert.Equal(t, "unreadable_path_segment", ev.Attrs["anomaly"])
	assert.Equal(t, "Get_Attribute_Single", ev.Operation)
}

func TestEncapsulationStatusIsAnException(t *testing.T) {
	// A session handle the device does not know, which is how it refuses a
	// request that claims a session it never opened.
	ev := parseOne(t, tcpCtx(model.DirResponse),
		"6f0000000001021264000000000000000000000000000000")
	assert.Equal(t, "InvalidSessionHandle", ev.Exception)
	assert.Equal(t, "InvalidSessionHandle", ev.Attrs["encapsulation_status"])
	assert.Equal(t, model.DirResponse, ev.Direction)
}

func TestRegisterSession(t *testing.T) {
	ev := parseOne(t, tcpCtx(model.DirRequest),
		"6500040000000000000000000000000000000000000000000100 0000")
	assert.Equal(t, "RegisterSession", ev.Operation)
	assert.Equal(t, "1", ev.Attrs["protocol_version"])
	assert.NotContains(t, ev.Attrs, "anomaly")
}

func TestUnknownCommandIsReported(t *testing.T) {
	ev := parseOne(t, tcpCtx(model.DirRequest),
		"ff000000000102120000000000000000000000000000 0000")
	assert.Equal(t, "Command_0x00ff", ev.Operation)
	assert.Equal(t, "unknown_command", ev.Attrs["anomaly"])
	assert.False(t, ev.Malformed)
}

func TestOptionsFieldIsReserved(t *testing.T) {
	d := enip.New()
	pdu := bytesOf(t, "6500040000000000000000000000000000000000ffffffff01000000")
	// The specification requires zero, so a PDU with the field set is not
	// claimed on a heuristic.
	assert.Equal(t, 0, d.Probe(tcpCtx(model.DirRequest), pdu))
	events, err := d.Parse(tcpCtx(model.DirRequest), pdu)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Contains(t, events[0].Attrs["anomaly"], "options_field_set")
}

func TestProbe(t *testing.T) {
	d := enip.New()
	for _, tc := range []struct {
		name, pdu string
		min       int
	}{
		{"list_identity", pduListIdentityRequest, 70},
		{"list_identity_reply", pduListIdentityReply, 80},
		{"send_unit_data", pduStart, 80},
		{"send_rr_data", pduForwardOpen, 80},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.GreaterOrEqual(t, d.Probe(tcpCtx(model.DirRequest), bytesOf(t, tc.pdu)), tc.min)
		})
	}

	for _, tc := range []struct{ name, payload string }{
		{"empty", ""},
		{"short", "6f0014"},
		{"http", "474554202f20485454502f312e310d0a486f73743a20780d0a0d0a0000"},
		{"modbus", "000100000006010300000001000000000000000000000000"},
		{"unknown_status", "6f001400000102120a0000000000000000000000 00000000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, 0, d.Probe(tcpCtx(model.DirRequest), bytesOf(t, tc.payload)))
		})
	}
}

func TestPDULen(t *testing.T) {
	d := enip.New()

	t.Run("need_more", func(t *testing.T) {
		for _, s := range []string{"", "6f", "6f0014", "6f0014000001"} {
			_, err := d.PDULen(bytesOf(t, s))
			assert.True(t, errors.Is(err, dissect.ErrNeedMore), "%q: %v", s, err)
		}
	})

	t.Run("exact", func(t *testing.T) {
		n, err := d.PDULen(bytesOf(t, pduStart))
		require.NoError(t, err)
		assert.Equal(t, len(bytesOf(t, pduStart)), n)
	})

	t.Run("pipelined", func(t *testing.T) {
		n, err := d.PDULen(bytesOf(t, pduStart+pduStop))
		require.NoError(t, err)
		assert.Equal(t, len(bytesOf(t, pduStart)), n)
	})

	t.Run("beyond_the_reassembly_cap", func(t *testing.T) {
		// A sixteen bit length can ask for more than one stream may buffer.
		_, err := d.PDULen(bytesOf(t, "6f00ffff0000000000000000000000000000000000000000"))
		assert.True(t, errors.Is(err, dissect.ErrMalformed))
		assert.Contains(t, err.Error(), "exceeds the")
	})
}

func TestNameAndTier(t *testing.T) {
	d := enip.New()
	assert.Equal(t, "enip", d.Name())
	assert.Equal(t, 1, d.Tier())
}

// encap wraps a body in an encapsulation header with the length the body
// actually has, so that a fixture exercising what is inside cannot fail on
// the header instead.
func encap(t *testing.T, command, bodyHex string) string {
	t.Helper()
	length := len(bytesOf(t, bodyHex))
	return command + hex.EncodeToString([]byte{byte(length), byte(length >> 8)}) +
		"0001021200000000" + "0000000000000000" + "00000000" + bodyHex
}

// unconnectedMessage wraps a CIP message in a SendRRData, which is the
// smallest envelope that carries one: an interface handle, a timeout, and an
// item list of a null address and the message.
func unconnectedMessage(t *testing.T, cipHex string) string {
	t.Helper()
	cip := bytesOf(t, cipHex)
	return encap(t, "6f00", "00000000"+"0500"+"0200"+"00000000"+"b200"+
		hex.EncodeToString([]byte{byte(len(cip)), byte(len(cip) >> 8)})+cipHex)
}

// multipleServicePacket builds a batch of the given CIP messages, with the
// count and offset table the service defines.
func multipleServicePacket(t *testing.T, services ...string) string {
	t.Helper()
	offset := 2 + 2*len(services)
	var table, body string
	for _, s := range services {
		table += hex.EncodeToString([]byte{byte(offset), byte(offset >> 8)})
		offset += len(bytesOf(t, s))
		body += s
	}
	count := hex.EncodeToString([]byte{byte(len(services)), byte(len(services) >> 8)})
	return unconnectedMessage(t, "0a02200224 01"+count+table+body)
}
