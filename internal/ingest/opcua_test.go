package ingest_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/model"
)

// The OPC UA counts below were cross-checked against an independent decode of
// the capture, message by message, after reassembling each direction of both
// connections.
//
// The capture is a robustness test tool working on a stack test server, which
// makes it better material than an ordinary session: it carries the full
// handshake, the endpoint descriptions, and two deliberately absurd method
// calls — one of whose method identifiers declares a quarter of a megabyte of
// name, which is what the file was published for.
func TestOPCUACaptureFacts(t *testing.T) {
	root := repoRoot(t)
	res, events := run(t, filepath.Join(root, "testdata", "pcaps", "opcua_method_call.pcap"))

	assert.Equal(t, uint64(90), res.Capture.Packets)
	require.Len(t, events, 24, "twelve messages in each of the two connections")

	byOp := map[string]int{}
	for _, e := range events {
		assert.Equal(t, "opcua", e.Protocol)
		assert.False(t, e.Malformed, "packet %d: %s", e.PacketIndex, e.Error)
		assert.True(t, e.Class.Valid())
		byOp[e.Operation]++
	}
	assert.Equal(t, map[string]int{
		"Hello":                     2,
		"Acknowledge":               2,
		"OpenSecureChannelRequest":  2,
		"OpenSecureChannelResponse": 2,
		"GetEndpointsRequest":       2,
		"GetEndpointsResponse":      2,
		"CreateSessionRequest":      2,
		"CreateSessionResponse":     2,
		"ActivateSessionRequest":    2,
		"ActivateSessionResponse":   2,
		"CallRequest":               2,
		"Error":                     2,
	}, byOp)

	// The server is on 12001 rather than the registered 4840, so this is
	// also the test that heuristic detection finds it.
	for _, e := range events {
		assert.Equal(t, uint16(12001), e.ServerPort)
	}

	// Both channels are opened with no security at all, and the server's
	// endpoint list offers an insecure endpoint alongside the signed ones.
	var insecureChannels, insecureEndpoints int
	var modes, tokens string
	for _, e := range events {
		if e.Attrs["insecure_channel"] == "true" {
			insecureChannels++
		}
		if e.Attrs["offers_insecure_endpoint"] == "true" {
			insecureEndpoints++
			modes = e.Attrs["security_modes"]
			tokens = e.Attrs["user_tokens"]
		}
	}
	assert.Equal(t, 4, insecureChannels, "both ends of both channels")
	assert.Equal(t, 4, insecureEndpoints, "the endpoint list arrives twice per connection")
	assert.Equal(t, "None,SignAndEncrypt,Sign", modes)
	assert.Equal(t, "Anonymous", tokens, "the server takes sessions with no user named")

	// The server describes itself in its endpoint descriptions, which is the
	// identity OPC UA gives up.
	identity := map[string]string{}
	for _, e := range events {
		for k, v := range e.Identity {
			identity[k] = v
		}
	}
	assert.Equal(t, "UA StackTest Server (AnsiC/2048)", identity["application_name"])
	assert.Equal(t, "opc.tcp://vm-xp-steven:12001/UA/StackTestServer", identity["endpoint_url"])

	// The client names itself too, which stays an attribute because identity
	// is attributed to the server.
	var clientURI string
	for _, e := range events {
		if v := e.Attrs["client_application_uri"]; v != "" {
			clientURI = v
		}
	}
	assert.Contains(t, clientURI, "Opc.Ua.ServerTestTool")

	// The two method calls are the reason the capture exists: the object is
	// readable, the method identifier is not, and the dissector says so
	// rather than reading a quarter of a megabyte that is not there.
	calls := 0
	for _, e := range events {
		if e.Operation != "CallRequest" {
			continue
		}
		calls++
		assert.Equal(t, model.ClassControl, e.Class, "a method call makes a device act")
		assert.Equal(t, "i=342", e.Attrs["object"])
		assert.Contains(t, e.Attrs["anomaly"], "service_arguments_unreadable")
	}
	assert.Equal(t, 2, calls)

	// Both connections end with the server refusing.
	var faults []string
	for _, e := range events {
		if e.Exception != "" {
			faults = append(faults, e.Exception)
		}
	}
	assert.ElementsMatch(t, []string{"BadInternalError", "BadDecodingError"}, faults)
}
