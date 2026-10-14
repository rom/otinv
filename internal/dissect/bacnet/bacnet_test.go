package bacnet_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/bacnet"
	"github.com/rom/otinv/internal/model"
)

// Datagrams taken verbatim from the public BACnet sample captures in
// testdata/pcaps, from the first octet of the virtual link layer onward; the
// comment names the file and packet each came from. Every capture was decoded
// independently before these expectations were written.
const (
	// device_identity #7 and #8: a client reads the vendor name of the
	// device object, and a Johnson Controls automation engine answers.
	dgReadVendorName  = "810a001101040005010c0c023fffff1979"
	dgVendorNameReply = "810a001b010030010c0c023fffff19793e750704004a004300493f"

	// device_identity #9 and #10: the firmware revision, as a UCS-2 string.
	dgFirmwareReply = "810a0029010030010c0c023fffff192c3e7515040035002e0031002e0030002e003400340030" +
		"00303f"

	// device_identity #15 and #16: the model name.
	dgModelReply = "810a002d010030010c0c023fffff19463e751904004d0053002d004e0041004500340035003100" +
		"30002d00323f"

	// device_identity #21, #22, #25 and #26: the virtual link layer on its
	// own — a broadcast distribution table read and a foreign device
	// registration, both refused.
	dgReadBDT         = "81020004"
	dgReadBDTRefused  = "810000060020"
	dgRegisterFDT     = "810500060010"
	dgRegisterRefused = "810000060030"

	// read_multiple #1 and #2: fifteen properties of a schedule object read
	// in one exchange, and the answer.
	dgReadMultiple = "810a002f01040003080e0c044000581e094b094d094f0955091c0920097b092609ae0936095809" +
		"6f0967095109a81f"
	dgReadMultipleReply = "810a0083010030080e0c044000581e294b4ec4044000584f294d4e74003132334f294f4e9111" +
		"4f29554e004f291c4e74003132334f29204ea4720101ffa4730101ff4f297b4e0e0f0e0f0e0f0e0f0e0f0e0f" +
		"0e0f4f29264e4f29ae4e004f29364e4f29584e210a4f296f4e8204004f29674e91004f29514e104f29a85e9102" +
		"91205f1f"
)

// Datagrams built to the shapes the public captures do not contain, each
// following the clause of ASHRAE 135 named in the comment.
const (
	// Clause 16.10: a device announcing itself to the whole internetwork,
	// which is the richest identity BACnet gives away unasked.
	dgIAm = "810b00180120ffff00ff1000c4020001f42205c491032105"

	// Clause 16.10 again, the question: who is out there between instance 1
	// and instance 100.
	dgWhoIs = "810b00100120ffff00ff100809011964"

	// Clause 15.9: a write of 100.0 to the present value of an analog
	// output, at priority 8.
	dgWriteProperty = "810a001a010400052a0f0c0040000a19553e4442c800003f4908"
	// Its acknowledgement.
	dgWriteAck = "810a00090100202a0f"

	// Clause 16.4: a warm start, with the password BACnet sends in the clear.
	dgReinitialize = "810a00130104000533140901" + "1d050070617373"

	// Clause 16.1: silencing a device for an hour, password and all.
	dgCommControl = "810a001501040005441109 3c1901" + "2d050070617373"

	// Clause 18.7: a device refusing a read of a property it does not have.
	dgError = "810a000d010050050c91029133"

	// Clause 18.8: a device refusing to look at a request at all.
	dgReject = "810a00090100600709"

	// Annex J.4.5: a BBMD passing on a broadcast for a device on another
	// subnet, which is the only place the real origin appears.
	dgForwarded = "8104000ec0a8012abac001001008"

	// Clause 6.4.1: a router discovery message, which is the network layer
	// talking about itself rather than an application service.
	dgWhoIsRouter = "810b00090180000002"
)

func bytesOf(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
	require.NoError(t, err, "test fixture is not valid hex")
	return b
}

func ctxFor() *dissect.FlowContext {
	return &dissect.FlowContext{
		CaptureID: "test",
		Flow: model.Flow{
			SrcIP: "10.1.1.167", DstIP: "10.1.1.165",
			SrcPort: bacnet.DefaultPort, DstPort: bacnet.DefaultPort,
			Transport: model.TransportUDP,
		},
		PacketIndex: 1,
		Timestamp:   time.Unix(1427822983, 0).UTC(),
		Direction:   model.DirRequest,
		ServerPort:  bacnet.DefaultPort,
	}
}

func parseOne(t *testing.T, datagram string) model.Event {
	t.Helper()
	events, err := bacnet.New().Parse(ctxFor(), bytesOf(t, datagram))
	require.NoError(t, err)
	require.Len(t, events, 1)
	return events[0]
}

func TestReadProperty(t *testing.T) {
	ev := parseOne(t, dgReadVendorName)
	assert.Equal(t, "readProperty", ev.Operation)
	assert.Equal(t, model.ClassRead, ev.Class)
	assert.Equal(t, model.DirRequest, ev.Direction)
	assert.Equal(t, "device:4194303", ev.Attrs["object"],
		"the wildcard instance, which asks whichever device answers")
	assert.Equal(t, "vendor-name", ev.Attrs["property"])
	assert.Equal(t, "Original-Unicast-NPDU", ev.Attrs["bvlc_function"])
	assert.Equal(t, "true", ev.Attrs["expecting_reply"])
	require.NotNil(t, ev.TransactionID)
	assert.Equal(t, uint32(1), *ev.TransactionID)
	assert.Empty(t, ev.Identity, "a question says nothing about the device")
}

// A BACnet answer echoes the object and property it answers for, so a device
// can be inventoried from the answers alone.
func TestReadPropertyRepliesCarryIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, datagram, property, value, field string
	}{
		{"vendor_name", dgVendorNameReply, "vendor-name", "JCI", "vendor_name"},
		{"firmware", dgFirmwareReply, "firmware-revision", "5.1.0.4400", "firmware_revision"},
		{"model", dgModelReply, "model-name", "MS-NAE4510-2", "model_name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := parseOne(t, tc.datagram)
			assert.Equal(t, "readProperty", ev.Operation)
			assert.Equal(t, model.DirResponse, ev.Direction)
			assert.Equal(t, tc.property, ev.Attrs["property"])
			// The strings are UCS-2 on this device, which is one of the four
			// character sets BACnet allows.
			assert.Equal(t, tc.value, ev.Attrs["value"])
			assert.Equal(t, tc.value, ev.Identity[tc.field])
		})
	}
}

func TestReadPropertyMultiple(t *testing.T) {
	req := parseOne(t, dgReadMultiple)
	assert.Equal(t, "readPropertyMultiple", req.Operation)
	assert.Equal(t, model.ClassRead, req.Class)
	assert.Equal(t, "schedule:88", req.Attrs["object"])
	assert.Equal(t, "15", req.Attrs["property_count"])
	require.NotNil(t, req.Quantity)
	assert.Equal(t, uint32(15), *req.Quantity)
	assert.Contains(t, req.Attrs["properties"], "weekly-schedule")
	assert.Nil(t, req.UnitID, "the instance of a point is not a unit identifier")

	reply := parseOne(t, dgReadMultipleReply)
	assert.Equal(t, "readPropertyMultiple", reply.Operation)
	assert.Equal(t, model.DirResponse, reply.Direction)
	assert.Equal(t, "schedule:88", reply.Attrs["object"])
	assert.Equal(t, "15", reply.Attrs["property_count"])
	assert.Empty(t, reply.Identity,
		"a schedule object describes a schedule, not the device")
}

// The virtual link layer on its own: table reads, foreign device
// registration, and the results that refuse them.
func TestVirtualLinkLayer(t *testing.T) {
	ev := parseOne(t, dgReadBDT)
	assert.Equal(t, "Read-Broadcast-Distribution-Table", ev.Operation)
	assert.Equal(t, model.ClassOther, ev.Class)

	refused := parseOne(t, dgReadBDTRefused)
	assert.Equal(t, "BVLC-Result", refused.Operation)
	assert.Equal(t, model.DirResponse, refused.Direction)
	assert.Equal(t, "Read-Broadcast-Distribution-Table NAK", refused.Exception)

	register := parseOne(t, dgRegisterFDT)
	assert.Equal(t, "Register-Foreign-Device", register.Operation)
	assert.Equal(t, "16", register.Attrs["time_to_live"])

	registerRefused := parseOne(t, dgRegisterRefused)
	assert.Equal(t, "Register-Foreign-Device NAK", registerRefused.Exception)
}

// A device announcing itself names its instance, its vendor and how much of
// an answer it can take.
func TestIAm(t *testing.T) {
	ev := parseOne(t, dgIAm)
	assert.Equal(t, "i-Am", ev.Operation)
	assert.Equal(t, model.ClassDiscovery, ev.Class)
	assert.Equal(t, model.DirResponse, ev.Direction, "an answer, whatever the protocol calls it")
	assert.Equal(t, "device:500", ev.Attrs["object"])
	assert.Equal(t, "1476", ev.Attrs["max_apdu"])
	assert.Equal(t, "none", ev.Attrs["segmentation"])
	assert.Equal(t, "Original-Broadcast-NPDU", ev.Attrs["bvlc_function"])
	assert.Equal(t, "broadcast", ev.Attrs["destination"])
	assert.Equal(t, map[string]string{
		"device_instance": "500",
		"vendor_id":       "5",
		"vendor_name":     "Johnson Controls",
	}, ev.Identity)
	require.NotNil(t, ev.UnitID)
	assert.Equal(t, uint16(500), *ev.UnitID)
}

func TestWhoIs(t *testing.T) {
	ev := parseOne(t, dgWhoIs)
	assert.Equal(t, "who-Is", ev.Operation)
	assert.Equal(t, model.ClassDiscovery, ev.Class)
	assert.Equal(t, model.DirRequest, ev.Direction)
	assert.Equal(t, "1-100", ev.Attrs["instance_range"])
}

func TestWriteProperty(t *testing.T) {
	ev := parseOne(t, dgWriteProperty)
	assert.Equal(t, "writeProperty", ev.Operation)
	assert.Equal(t, model.ClassWrite, ev.Class)
	assert.Equal(t, "analog-output:10", ev.Attrs["object"])
	assert.Equal(t, "present-value", ev.Attrs["property"])
	assert.Equal(t, "100", ev.Attrs["value"])
	assert.Equal(t, "8", ev.Attrs["write_priority"])
	require.NotNil(t, ev.Address)
	assert.Equal(t, uint32(85), *ev.Address)

	ack := parseOne(t, dgWriteAck)
	assert.Equal(t, "writeProperty", ack.Operation)
	assert.Equal(t, model.ClassWrite, ack.Class, "the answer to a write is the write")
	assert.Equal(t, model.DirResponse, ack.Direction)
	assert.Equal(t, "SimpleACK", ack.Attrs["apdu_type"])
}

// The two services that act on the device rather than on data, and the
// password BACnet sends in the clear with them.
func TestControlServices(t *testing.T) {
	reinit := parseOne(t, dgReinitialize)
	assert.Equal(t, "reinitializeDevice.warmstart", reinit.Operation)
	assert.Equal(t, model.ClassControl, reinit.Class)
	assert.Equal(t, "warmstart", reinit.Attrs["reinitialize_state"])
	assert.Equal(t, "sent", reinit.Attrs["password"],
		"that a password was sent is evidence; the value is not recorded")
	for _, v := range reinit.Attrs {
		assert.NotContains(t, v, "pass", "the password itself must not be stored")
	}

	comm := parseOne(t, dgCommControl)
	assert.Equal(t, "deviceCommunicationControl.disable", comm.Operation)
	assert.Equal(t, model.ClassControl, comm.Class)
	assert.Equal(t, "60", comm.Attrs["duration_minutes"])
	assert.Equal(t, "sent", comm.Attrs["password"])
}

func TestRefusals(t *testing.T) {
	ev := parseOne(t, dgError)
	assert.Equal(t, "readProperty", ev.Operation)
	assert.Equal(t, model.DirResponse, ev.Direction)
	assert.Equal(t, "property/unknown-property", ev.Exception)

	reject := parseOne(t, dgReject)
	assert.Equal(t, "Reject", reject.Operation)
	assert.Equal(t, "unrecognized-service", reject.Exception)
}

// A BBMD forwarding a broadcast is the only place the real origin of the
// message appears, since the IP header is the BBMD's own.
func TestForwardedNPDU(t *testing.T) {
	ev := parseOne(t, dgForwarded)
	assert.Equal(t, "who-Is", ev.Operation)
	assert.Equal(t, "192.168.1.42:47808", ev.Attrs["forwarded_from"])
	assert.Equal(t, "Forwarded-NPDU", ev.Attrs["bvlc_function"])
}

func TestNetworkLayerMessage(t *testing.T) {
	ev := parseOne(t, dgWhoIsRouter)
	assert.Equal(t, "Who-Is-Router-To-Network", ev.Operation)
	assert.Equal(t, model.ClassDiscovery, ev.Class)
	assert.Equal(t, "2", ev.Attrs["networks"])
}

// A known service whose arguments do not decode is still a known service: the
// event keeps what it has and says what broke, rather than becoming a
// malformed frame with nothing in it.
func TestUnreadableArgumentsAreAnAnomaly(t *testing.T) {
	ev := parseOne(t, "810a000c01040005010c0cff")
	assert.Equal(t, "readProperty", ev.Operation)
	assert.False(t, ev.Malformed)
	assert.Contains(t, ev.Attrs["anomaly"], "service_arguments_unreadable")
	assert.NotEmpty(t, ev.Attrs["argument_error"])
}

func TestMalformedDatagrams(t *testing.T) {
	for _, tc := range []struct{ name, datagram, want string }{
		{"short", "810a", "cannot hold a BVLL header"},
		{"not_bacnet", "820a000400", "BVLL type is 0x82"},
		{"length_mismatch", "810a00ff0104", "declares 255 octets"},
		{"npdu_version", "810a0006020 0", "network layer version is 2"},
		{"no_apdu", "810a00060100", "no application PDU"},
		{"result_without_code", "81000004", "no result code"},
		{"forwarded_without_origin", "810400060100", "no originating address"},
		{"destination_runs_past", "810a0007012001", "destination address runs past"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events, err := bacnet.New().Parse(ctxFor(), bytesOf(t, tc.datagram))
			require.Error(t, err)
			assert.True(t, errors.Is(err, dissect.ErrMalformed), "must wrap ErrMalformed: %v", err)
			assert.Contains(t, err.Error(), tc.want)
			require.Len(t, events, 1)
			assert.True(t, events[0].Malformed)
			assert.Equal(t, "bacnet", events[0].Protocol)
		})
	}
}

func TestProbe(t *testing.T) {
	d := bacnet.New()
	for _, tc := range []struct {
		name, datagram string
		min            int
	}{
		{"read_property", dgReadVendorName, 90},
		{"i_am", dgIAm, 90},
		{"bvlc_result", dgReadBDTRefused, 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.GreaterOrEqual(t, d.Probe(ctxFor(), bytesOf(t, tc.datagram)), tc.min)
		})
	}

	for _, tc := range []struct{ name, datagram string }{
		{"empty", ""},
		{"wrong_type", "810a000400"},
		{"unknown_function", "81ff000400"},
		{"npdu_version_wrong", "810a0006 0200"},
		{"dns", "0001010000010000000000000377777706676f6f676c6503636f6d0000010001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, 0, d.Probe(ctxFor(), bytesOf(t, tc.datagram)))
		})
	}
}

func TestPDULen(t *testing.T) {
	d := bacnet.New()
	n, err := d.PDULen(bytesOf(t, dgReadVendorName))
	require.NoError(t, err)
	assert.Equal(t, len(bytesOf(t, dgReadVendorName)), n)

	// Two messages in one datagram, which the standard allows and ingest
	// frames with this.
	n, err = d.PDULen(bytesOf(t, dgReadBDT+dgReadBDTRefused))
	require.NoError(t, err)
	assert.Equal(t, 4, n)

	for _, s := range []string{"", "81", "810a00"} {
		_, err := d.PDULen(bytesOf(t, s))
		assert.True(t, errors.Is(err, dissect.ErrNeedMore), "%q: %v", s, err)
	}
	_, err = d.PDULen(bytesOf(t, "810a0002"))
	assert.True(t, errors.Is(err, dissect.ErrMalformed))
}

func TestNameAndTier(t *testing.T) {
	d := bacnet.New()
	assert.Equal(t, "bacnet", d.Name())
	assert.Equal(t, 1, d.Tier())
}
