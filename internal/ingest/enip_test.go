package ingest_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/model"
)

// The facts below were cross-checked against an independent decode of the
// capture, PDU by PDU: 791 encapsulation PDUs, each carrying one data item,
// and the service codes and reply statuses tallied separately from this
// implementation.
func TestENIPRockwellSessionFacts(t *testing.T) {
	root := repoRoot(t)
	res, events := run(t, filepath.Join(root, "testdata", "pcaps", "enip_rockwell_session.pcap"))

	assert.Equal(t, "Ethernet", res.Capture.LinkType)
	assert.Equal(t,
		"8439230c8c1a3e824fc8e5f0637160ad6d88fcd78cae94c60c1e6f9df9358f57",
		res.Capture.SHA256)
	require.Len(t, events, 791, "one event per encapsulation PDU")

	byOperation := map[string]int{}
	byException := map[string]int{}
	var routed, connections int
	for _, e := range events {
		assert.Equal(t, "enip", e.Protocol)
		assert.False(t, e.Malformed, "packet %d: %s", e.PacketIndex, e.Error)
		assert.True(t, e.Class.Valid(), "class %q", e.Class)
		byOperation[e.Operation]++
		if e.Exception != "" {
			byException[e.Exception]++
		}
		if e.Attrs["transport_service"] == "Unconnected_Send" {
			routed++
		}
		if e.Attrs["connection_o2t"] != "" && !strings.HasPrefix(e.Operation, "Forward_Close") {
			connections++
		}
	}

	assert.Equal(t, map[string]int{
		"Get_Attribute_List":      562,
		"Multiple_Service_Packet": 73,
		"Service_0x4f":            38,
		"Get_Attributes_All":      36,
		"Execute_PCCC":            25,
		"Service_0x4b":            25,
		"Forward_Open":            14,
		"Forward_Close":           12,
		"Service_0x4c":            4,
		"Set_Attribute_List":      2,
	}, byOperation)

	// Service 0x4B is Execute_PCCC on the PCCC object, and this client sends
	// it to a vendor class instead, so the request carries a class that says
	// the code is not the one this project knows and is reported as its
	// number. Its reply carries no class at all to contradict the one
	// meaning there is, so it is named. The asymmetry is the rule working:
	// evidence against a name is not the same as no evidence.
	assert.Equal(t, 25, byOperation["Service_0x4b"], "requests, on a class 0x4B is not defined for")
	assert.Equal(t, 25, byOperation["Execute_PCCC"], "their replies, which name no class")

	// Four requests were refused because the path named something that is
	// not there, and one with the device's own general error.
	assert.Equal(t, map[string]int{"PathDestinationUnknown": 4, "GeneralError": 1}, byException)

	// Eighteen requests were routed through the bridge to the controller
	// behind it, which is how the Identity object was read.
	assert.Equal(t, 18, routed)
	assert.Equal(t, 14, connections, "seven connections opened, and their confirmations")

	// The controller names itself in the reply to a read of its Identity
	// object, which is the only identity in this capture: there is no
	// ListIdentity exchange in it at all.
	identities := map[string]string{}
	for _, e := range events {
		for k, v := range e.Identity {
			identities[k] = v
		}
	}
	assert.Equal(t, map[string]string{
		"vendor_id":            "1",
		"vendor_name":          "Rockwell Automation/Allen-Bradley",
		"device_type":          "Programmable Logic Controller",
		"product_code":         "54",
		"product_name":         "1756-L61/B LOGIX5561",
		"major_minor_revision": "16.20",
		"serial_number":        "0x0051823f",
	}, identities)
}

// EtherNet/IP discovery runs over UDP, where a client broadcasts ListIdentity
// and everything that hears it answers. The two datagrams below are the ones
// from enip_list_identity.pcap, carried over UDP instead of TCP.
func TestENIPDiscoveryOverUDP(t *testing.T) {
	request := frame(t, "63000000000000000000000000000000c1debed100000000")
	reply := frame(t, "63003300000000000000000000000000c1debed1000000000100"+
		"0c002d0001000002af120a0101a4000000000000000001000c003a00040330008e4d52000b31"+
		"3735362d454e42542f4103")

	res, events := run(t, writePcap(t, [][]byte{
		udpDatagram(t, 61696, 44818, request),
		udpDatagram(t, 44818, 61696, reply),
	}))

	assert.Equal(t, uint64(2), res.UDPDatagrams)
	require.Len(t, events, 2)
	assert.Equal(t, "ListIdentity", events[0].Operation)
	assert.Equal(t, model.ClassDiscovery, events[0].Class)
	assert.Equal(t, model.DirRequest, events[0].Direction, "the port it was sent to is the server's")
	assert.Equal(t, model.DirResponse, events[1].Direction)
	assert.Equal(t, "1756-ENBT/A", events[1].Identity["product_name"])
	assert.Equal(t, "10.1.1.164:44818", events[1].Attrs["reported_address"],
		"the address the device believes it has, which a broadcast reply is the way to learn")
}

// Cyclic I/O has its own port because its frames carry no encapsulation
// header, only the item list, so the framer has to recognise them by shape.
func TestENIPImplicitIOOverUDP(t *testing.T) {
	io := frame(t, "0200"+"02800800"+"01000080"+"2a000000"+"b1000a00"+"0400"+"0102030405060708")

	res, events := run(t, writePcap(t, [][]byte{udpDatagram(t, 2048, 2222, io)}))
	assert.Equal(t, uint64(1), res.UDPDatagrams)
	assert.Zero(t, res.UnboundPayloads)
	require.Len(t, events, 1)
	assert.Equal(t, "IO_Data", events[0].Operation)
	assert.Equal(t, "0x80000001", events[0].Attrs["connection_id"])
	assert.Equal(t, model.TransportUDP, events[0].Flow.Transport)
}
