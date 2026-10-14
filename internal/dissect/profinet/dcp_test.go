package profinet_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/profinet"
	"github.com/rom/otinv/internal/model"
)

// Frames taken verbatim from the public PROFINET sample captures in
// testdata/pcaps, from the frame identifier onward; the comment names the
// file and packet each came from. Every capture was decoded independently
// before these expectations were written.
const (
	// change_ip #1: an engineering station asking every station on the
	// segment to identify itself.
	frameIdentifyAll = "fefe05000100000100010004ffff0000000000000000000000000000000000000000000000" +
		"0000000000"

	// change_ip #2: a SCALANCE switch answering with everything it knows
	// about itself.
	frameIdentifyReply = "feff0501010000010000005e0205001c000001010102020102020203020402050" +
		"33d0501050205030504ffff020100050000494e43000202000b0000583230382d424f52440" +
		"0020300060000002a0a0102040004000001000102000e0001c0a80006ffffff00c0a80001"

	// change_ip #3 and #4: the same station's IP address being changed, and
	// the station accepting the change.
	frameSetIP      = "fefd040001000001000000120102000e0001c0a8000affffff00c0a80001000000000000000000000000"
	frameSetIPReply = "fefd0401010000010000000805040003010200000000000000000000000000000000000000" +
		"000000000000000000"

	// crafted_name #2: a station whose name of station is a format string
	// padded with NULs, which is what the capture was published for.
	frameCraftedName = "feff050101000001000000b802050010000002010202020302040205010101020201000a0000" +
		"53372d3330304543" +
		// The name of station: a block of 110 octets whose value is seven
		// printable characters and 101 octets of NUL padding.
		"0202006e0000256e256e256e20" +
		"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
		"020300060000002a010102040004000002000102000e0001c0a8000bffffff00c0a8000b"

	// identify_scan #2: an Identify filtered by name of station, whose
	// Ethernet padding still carries the previous frame's contents.
	frameIdentifyByName = "fefe0500030086470001000c020200077377697463683100a6e9c3d687fe789e03a1acdbe5bf00000000"
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
			SrcMAC:    "00:0c:29:ba:09:ea",
			DstMAC:    "01:0e:cf:00:00:00",
			Transport: model.TransportEthernet,
		},
		PacketIndex: 1,
		Timestamp:   time.Unix(1321868480, 0).UTC(),
		Direction:   model.DirUnknown,
	}
}

func parseOne(t *testing.T, frame string) model.Event {
	t.Helper()
	events, err := profinet.New().Parse(ctxFor(), bytesOf(t, frame))
	require.NoError(t, err)
	require.Len(t, events, 1)
	return events[0]
}

func TestIdentifyRequest(t *testing.T) {
	ev := parseOne(t, frameIdentifyAll)
	assert.Equal(t, "Identify", ev.Operation)
	assert.Equal(t, model.ClassDiscovery, ev.Class)
	assert.Equal(t, model.DirRequest, ev.Direction)
	assert.Equal(t, "AllSelector", ev.Attrs["blocks"])
	assert.Equal(t, "1", ev.Attrs["response_delay"])
	assert.Equal(t, "0xfefe", ev.Attrs["frame_id"])
	require.NotNil(t, ev.TransactionID)
	assert.Equal(t, uint32(0x01000001), *ev.TransactionID)
	assert.Empty(t, ev.Identity, "a request says nothing about the station")
	assert.NotContains(t, ev.Attrs, "anomaly")
}

// A station answering an Identify states its own name, vendor, model, role
// and address, which is the best asset evidence a passive observer gets
// without asking anything.
func TestIdentifyReplyCarriesTheStationsOwnDescription(t *testing.T) {
	ev := parseOne(t, frameIdentifyReply)
	assert.Equal(t, "Identify", ev.Operation)
	assert.Equal(t, model.ClassDiscovery, ev.Class)
	assert.Equal(t, model.DirResponse, ev.Direction)
	assert.Equal(t, map[string]string{
		"station_name":     "X208-BORD",
		"model":            "INC",
		"vendor_id":        "42",
		"vendor_name":      "Siemens",
		"device_id":        "0x0a01",
		"device_role":      "io_device",
		"reported_address": "192.168.0.6",
	}, ev.Identity)
	assert.Equal(t, "192.168.0.6", ev.Attrs["ip_address"])
	assert.Equal(t, "255.255.255.0", ev.Attrs["netmask"])
	assert.Equal(t, "192.168.0.1", ev.Attrs["gateway"])
	assert.Equal(t, "ip_set", ev.Attrs["ip_state"])
	assert.Equal(t, "13", ev.Attrs["supported_options"])
	assert.Equal(t,
		"DeviceOptions,DeviceVendorValue,NameOfStation,DeviceID,DeviceRole,IPParameter",
		ev.Attrs["blocks"])
	assert.NotContains(t, ev.Attrs, "anomaly")
}

// Changing a station's IP address is a write to the one field PROFINET
// addresses it by.
func TestSetIPParameter(t *testing.T) {
	ev := parseOne(t, frameSetIP)
	assert.Equal(t, "Set", ev.Operation)
	assert.Equal(t, model.ClassWrite, ev.Class)
	assert.Equal(t, model.DirRequest, ev.Direction)
	assert.Equal(t, "192.168.0.10", ev.Attrs["ip_address"])
	assert.Equal(t, "true", ev.Attrs["set_permanent"],
		"the qualifier says the address survives a power cycle")
	assert.Empty(t, ev.Identity, "a Set says what a station will be, not what it is")

	reply := parseOne(t, frameSetIPReply)
	assert.Equal(t, "Set", reply.Operation)
	assert.Equal(t, model.ClassWrite, reply.Class)
	assert.Equal(t, model.DirResponse, reply.Direction)
	assert.Equal(t, "IPParameter", reply.Attrs["acked_block"])
	assert.Equal(t, "Ok", reply.Attrs["block_result"])
	assert.Empty(t, reply.Exception)
}

// The name of station is the field a device is addressed by, and this capture
// was published because one carries format specifiers and NUL padding.
func TestCraftedNameOfStationIsReported(t *testing.T) {
	ev := parseOne(t, frameCraftedName)
	assert.Equal(t, "Identify", ev.Operation)
	assert.Contains(t, ev.Attrs["anomaly"], "name_of_station_not_printable")
	assert.Equal(t, "%n%n%n ", ev.Attrs["name_of_station"])
	assert.Equal(t, "S7-300EC", ev.Identity["model"])
	assert.Equal(t, "io_controller", ev.Identity["device_role"],
		"this station states it is the controller")
}

// Ethernet pads a short frame, and a station that pads with whatever was in
// its buffer is leaking the previous frame onto the wire.
func TestNonZeroPaddingIsReported(t *testing.T) {
	ev := parseOne(t, frameIdentifyByName)
	assert.Equal(t, "Identify", ev.Operation)
	assert.Equal(t, model.DirRequest, ev.Direction)
	assert.Equal(t, "switch1", ev.Attrs["name_of_station"], "the scan filters on one name")
	assert.Contains(t, ev.Attrs["anomaly"], "padding_not_zero")
	assert.Equal(t, "18", ev.Attrs["padding_bytes"])
}

// Frames built to the shapes the public captures do not contain. The comment
// gives the clause of IEC 61158-6-10 each follows.
func TestCraftedServices(t *testing.T) {
	for _, tc := range []struct {
		name, frame, operation string
		class                  model.Classification
		attrs                  map[string]string
		identity               map[string]string
		anomaly                string
	}{
		{
			// Clause 4.3.1.4.2: a Get naming the options it wants, each with
			// an empty value.
			name:      "get_request",
			frame:     "fefd03000000000200000 00c" + "02020000" + "02030000" + "01040000",
			operation: "Get",
			class:     model.ClassRead,
			attrs:     map[string]string{"blocks": "NameOfStation,DeviceID,Option_1/4"},
		},
		{
			// Clause 4.3.1.4.3: the answer, which carries block info and the
			// value, like an Identify response.
			name: "get_response",
			frame: "fefd0301000000020000 0014" + "020200080000706c632d3031" +
				"0204000400000200",
			operation: "Get",
			class:     model.ClassRead,
			identity:  map[string]string{"station_name": "plc-01", "device_role": "io_controller"},
		},
		{
			// Clause 4.3.1.4.5: a station announcing itself unasked, which
			// is how one appears after a power cycle.
			name: "hello",
			frame: "fefc0600000000030000 0014" + "020200080000706c632d3032" +
				"0204000400000200",
			operation: "Hello",
			class:     model.ClassDiscovery,
			identity:  map[string]string{"station_name": "plc-02"},
		},
		{
			// Clause 4.3.1.4.4 with the Control/FactoryReset block: the
			// station loses its name and address and leaves the network.
			name:      "factory_reset",
			frame:     "fefd040000000004000000080505000400010000",
			operation: "Set.FactoryReset",
			class:     model.ClassControl,
			attrs:     map[string]string{"control": "FactoryReset", "reset_mode": "0x0000"},
		},
		{
			// The same service flashing the station's LED, which changes
			// nothing and is how an engineer finds it in a cabinet.
			name:      "signal",
			frame:     "fefd04000000000500000008050300040001 0000",
			operation: "Set.Signal",
			class:     model.ClassDiagnostic,
			attrs:     map[string]string{"control": "Signal"},
		},
		{
			// A station refusing to let this interface change its name.
			name:      "set_refused",
			frame:     "fefd04010000000600000008050400030202 0600",
			operation: "Set",
			class:     model.ClassWrite,
			attrs: map[string]string{
				"acked_block":  "NameOfStation",
				"block_result": "InUseByInterface",
			},
		},
		{
			// Two stations answering for one address, which is a cloned
			// device or a misconfigured one.
			name:      "address_conflict",
			frame:     "feff05010000000700000012 0102000e0081c0a80006ffffff00c0a80001",
			operation: "Identify",
			class:     model.ClassDiscovery,
			attrs:     map[string]string{"ip_state": "ip_set_address_conflict"},
			anomaly:   "ip_address_conflict",
		},
		{
			// A service identifier the standard does not define.
			name:      "unknown_service",
			frame:     "fefd0b00000000080000000000000000",
			operation: "Service_11",
			class:     model.ClassOther,
			anomaly:   "unknown_service",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := parseOne(t, tc.frame)
			assert.Equal(t, tc.operation, ev.Operation)
			assert.Equal(t, tc.class, ev.Class)
			for k, v := range tc.attrs {
				assert.Equal(t, v, ev.Attrs[k], "attr %s", k)
			}
			for k, v := range tc.identity {
				assert.Equal(t, v, ev.Identity[k], "identity %s", k)
			}
			if tc.anomaly != "" {
				assert.Contains(t, ev.Attrs["anomaly"], tc.anomaly)
			}
			assert.False(t, ev.Malformed, ev.Error)
		})
	}
}

func TestSetRefusedIsAnException(t *testing.T) {
	ev := parseOne(t, "fefd04010000000600000008050400030202 0600")
	assert.Equal(t, "InUseByInterface", ev.Exception)
}

func TestMalformedFrames(t *testing.T) {
	for _, tc := range []struct{ name, frame, want string }{
		{"short", "fefe0500", "cannot hold a DCP header"},
		{"not_dcp", "80000500010000010001000400000000", "is not a DCP one"},
		{"data_beyond_frame", "fefe050001000001000100ff0102", "exceeds the"},
		{"block_overruns", "fefd03000000000200000008" + "0202ff0000000000", "declares 65280 octets"},
		{"block_header_split", "fefd0300000000020000000502020000 00", "octets before the end"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events, err := profinet.New().Parse(ctxFor(), bytesOf(t, tc.frame))
			require.Error(t, err)
			assert.True(t, errors.Is(err, dissect.ErrMalformed), "must wrap ErrMalformed: %v", err)
			assert.Contains(t, err.Error(), tc.want)
			require.Len(t, events, 1)
			assert.True(t, events[0].Malformed)
			assert.Equal(t, "profinet_dcp", events[0].Protocol)
		})
	}
}

func TestProbe(t *testing.T) {
	d := profinet.New()
	for _, tc := range []struct {
		name  string
		frame string
		min   int
	}{
		{"identify_request", frameIdentifyAll, 90},
		{"identify_reply", frameIdentifyReply, 90},
		{"set", frameSetIP, 90},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.GreaterOrEqual(t, d.Probe(ctxFor(), bytesOf(t, tc.frame)), tc.min)
		})
	}

	// The EtherType carries several protocols, and the ones this does not
	// decode must be left alone rather than claimed: a cyclic RT frame, an
	// alarm, and a frame too short to be anything.
	for _, tc := range []struct{ name, frame string }{
		{"rt_cyclic", "8000010203040506070800000035"},
		{"rt_class3", "0100010203040506070800000035"},
		{"alarm_high", "fc01010203040506070800000035"},
		{"short", "fefe05"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, 0, d.Probe(ctxFor(), bytesOf(t, tc.frame)))
		})
	}
}

func TestNameAndTier(t *testing.T) {
	d := profinet.New()
	assert.Equal(t, "profinet_dcp", d.Name())
	assert.Equal(t, 1, d.Tier())
}
