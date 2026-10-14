package opcua_test

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/opcua"
	"github.com/rom/otinv/internal/model"
)

// Messages taken verbatim from the public OPC UA sample capture in
// testdata/pcaps, from the first octet of the message header onward; the
// comment names the packet each came from. The capture was decoded
// independently before these expectations were written.
const (
	// #4: the client opens the connection and names the endpoint it wants.
	msgHello = "48454c464f00000000000000ffff0000ffff0000a00f0000000000002f0000006f70632e7463703a" +
		"2f2f766d2d78702d73746576656e3a31323030312f55412f537461636b54657374536572766572"

	// #6: the server agrees the buffer sizes.
	msgAcknowledge = "41434b461c00000000000000ffff0000ffff0000a00f000000000000"

	// #8: the channel is opened with no security at all.
	msgOpenChannel = "4f504e4684000000000000002f000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f" +
		"55412f5365637572697479506f6c696379234e6f6e65ffffffffffffffff01000000010000000100be" +
		"010000003c7d0c5c2bca0101000000ff030000ffffffff0000000000000000000000000000000100000" +
		"000000000808d5b00"

	// #11: the client asks which endpoints the server offers.
	msgGetEndpoints = "4d534746450000005f1900000100000002000000020000000100ac010000003c7d0c5c2bca010100" +
		"0000ff030000ffffffff00000000000000ffffffff0000000000000000"

	// #35: the session is activated with an anonymous identity token.
	msgActivateSession = "4d5347466a0000005f1900000100000004000000040000000100d30101007f19003c7d0c5c2bca01" +
		"01000000ff030000ffffffff00000000000000ffffffffffffffff000000000100000005000000656e" +
		"2d55530100410101050000000100000030ffffffffffffffff"

	// #43: the server gives up on the connection.
	msgTransportError = "455252461000000000000280ffffffff"
)

func bytesOf(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
	require.NoError(t, err, "test fixture is not valid hex")
	return b
}

func ctxFor(dir model.Direction) *dissect.FlowContext {
	flow := model.Flow{
		SrcIP: "192.168.41.176", DstIP: "192.168.41.212",
		SrcPort: 58674, DstPort: 12001, Transport: model.TransportTCP,
	}
	if dir == model.DirResponse {
		flow = flow.Reverse()
	}
	return &dissect.FlowContext{
		CaptureID:   "test",
		Flow:        flow,
		PacketIndex: 1,
		Timestamp:   time.Unix(1251847768, 0).UTC(),
		Direction:   dir,
		ServerPort:  12001,
	}
}

func parseOne(t *testing.T, ctx *dissect.FlowContext, message []byte) model.Event {
	t.Helper()
	events, err := opcua.New().Parse(ctx, message)
	require.NoError(t, err)
	require.Len(t, events, 1)
	return events[0]
}

func TestHelloNamesTheServer(t *testing.T) {
	ev := parseOne(t, ctxFor(model.DirRequest), bytesOf(t, msgHello))
	assert.Equal(t, "Hello", ev.Operation)
	assert.Equal(t, model.DirRequest, ev.Direction)
	assert.Equal(t, "opc.tcp://vm-xp-steven:12001/UA/StackTestServer", ev.Attrs["endpoint_url"])
	assert.Equal(t, "65535", ev.Attrs["receive_buffer"])
	// The URL is how a client names the server, so it is evidence about the
	// device being connected to.
	assert.Equal(t, "opc.tcp://vm-xp-steven:12001/UA/StackTestServer", ev.Identity["endpoint_url"])
}

func TestAcknowledge(t *testing.T) {
	ev := parseOne(t, ctxFor(model.DirResponse), bytesOf(t, msgAcknowledge))
	assert.Equal(t, "Acknowledge", ev.Operation)
	assert.Equal(t, model.DirResponse, ev.Direction)
	assert.Equal(t, "4000", ev.Attrs["max_message_size"])
	assert.NotContains(t, ev.Attrs, "anomaly")
}

// The channel handshake is the one place the security policy appears in the
// clear, and this server's channel has none.
func TestOpenSecureChannelWithoutSecurity(t *testing.T) {
	ev := parseOne(t, ctxFor(model.DirRequest), bytesOf(t, msgOpenChannel))
	assert.Equal(t, "OpenSecureChannelRequest", ev.Operation)
	assert.Equal(t, model.DirRequest, ev.Direction)
	assert.Equal(t, "None", ev.Attrs["security_policy"])
	assert.Equal(t, "None", ev.Attrs["security_mode"])
	assert.Equal(t, "true", ev.Attrs["insecure_channel"],
		"nothing on this channel is signed or encrypted")
	assert.Equal(t, "issue", ev.Attrs["request_type"])
	assert.Equal(t, "6000000", ev.Attrs["requested_lifetime_ms"])
	assert.NotContains(t, ev.Attrs, "sender_certificate_bytes",
		"an unsigned channel sends no certificate")
	require.NotNil(t, ev.TransactionID)
	assert.Equal(t, uint32(1), *ev.TransactionID)
}

func TestGetEndpointsRequest(t *testing.T) {
	ev := parseOne(t, ctxFor(model.DirRequest), bytesOf(t, msgGetEndpoints))
	assert.Equal(t, "GetEndpointsRequest", ev.Operation)
	assert.Equal(t, model.ClassDiscovery, ev.Class)
	assert.Equal(t, "6495", ev.Attrs["secure_channel"])
	assert.Equal(t, "2", ev.Attrs["sequence"])
}

func TestActivateSessionCarriesTheIdentityToken(t *testing.T) {
	ev := parseOne(t, ctxFor(model.DirRequest), bytesOf(t, msgActivateSession))
	assert.Equal(t, "ActivateSessionRequest", ev.Operation)
	assert.Equal(t, "Anonymous", ev.Attrs["identity_token"],
		"this server lets a client in without naming a user")
	assert.NotContains(t, ev.Attrs, "anomaly")
}

func TestTransportError(t *testing.T) {
	ev := parseOne(t, ctxFor(model.DirResponse), bytesOf(t, msgTransportError))
	assert.Equal(t, "Error", ev.Operation)
	assert.Equal(t, "BadInternalError", ev.Exception)
	assert.Equal(t, "0x80020000", ev.Attrs["status_code"])
}

// Services built to the shapes the capture does not contain.
func TestCraftedServices(t *testing.T) {
	for _, tc := range []struct {
		name      string
		serviceID uint32
		body      []byte
		operation string
		class     model.Classification
		attrs     map[string]string
		quantity  uint32
	}{
		{
			name:      "read",
			serviceID: 631,
			body: concat(requestHeader(),
				u64(0), u32(0), // max age and timestamps to return
				u32(2),
				nodeID(0, 2002), u32(13), nullString(), qualifiedName(),
				nodeID(1, 4711), u32(13), nullString(), qualifiedName()),
			operation: "ReadRequest",
			class:     model.ClassRead,
			attrs: map[string]string{
				"node_count": "2",
				"nodes":      "i=2002,ns=1;i=4711",
				"attributes": "Value",
			},
			quantity: 2,
		},
		{
			name:      "write",
			serviceID: 673,
			body: concat(requestHeader(), u32(1),
				nodeID(2, 1234), u32(13), nullString()),
			operation: "WriteRequest",
			class:     model.ClassWrite,
			attrs: map[string]string{
				"node_count": "1",
				"nodes":      "ns=2;i=1234",
				"attributes": "Value",
			},
			quantity: 1,
		},
		{
			name:      "browse",
			serviceID: 527,
			body: concat(requestHeader(),
				// A view description with a real timestamp, which is how a
				// client asks to browse the address space as it was.
				[]byte{0x00, 0x00}, u64(0x01cc5c0c7d3c0000), u32(0),
				u32(0),
				u32(1),
				nodeID(0, 85), u32(0), nodeID(0, 35), []byte{0x00}, u32(0), u32(0x3f)),
			operation: "BrowseRequest",
			class:     model.ClassRead,
			attrs:     map[string]string{"node_count": "1", "nodes": "i=85"},
			quantity:  1,
		},
		{
			name:      "call",
			serviceID: 712,
			body: concat(requestHeader(), u32(1),
				nodeID(0, 1234), nodeID(2, 5678), u32(3),
				// Three null variants, which is what the count promises.
				[]byte{0x00, 0x00, 0x00}),
			operation: "CallRequest",
			class:     model.ClassControl,
			attrs: map[string]string{
				"object":         "i=1234",
				"method":         "ns=2;i=5678",
				"argument_count": "3",
			},
			quantity: 1,
		},
		{
			name:      "add_nodes",
			serviceID: 488,
			body:      concat(requestHeader(), u32(0)),
			operation: "AddNodesRequest",
			class:     model.ClassProgram,
		},
		{
			name:      "write_response_refused",
			serviceID: 676,
			body:      responseHeader(0x801F0000),
			operation: "WriteResponse",
			class:     model.ClassWrite,
			attrs:     map[string]string{"status": "BadUserAccessDenied"},
		},
		{
			name:      "service_fault",
			serviceID: 397,
			body:      responseHeader(0x80130000),
			operation: "ServiceFault",
			class:     model.ClassOther,
			attrs:     map[string]string{"status": "BadSecurityChecksFailed"},
		},
		{
			name:      "unknown_service",
			serviceID: 65000,
			body:      requestHeader(),
			operation: "Service_65000",
			class:     model.ClassOther,
			attrs:     map[string]string{"anomaly": "unknown_service"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := secureMessage(t, 1, 1, 1, 1, tc.serviceID, tc.body)
			ev := parseOne(t, ctxFor(model.DirRequest), msg)
			assert.Equal(t, tc.operation, ev.Operation)
			assert.Equal(t, tc.class, ev.Class)
			assert.False(t, ev.Malformed, ev.Error)
			for k, v := range tc.attrs {
				assert.Equal(t, v, ev.Attrs[k], "attr %s", k)
			}
			if tc.quantity != 0 {
				require.NotNil(t, ev.Quantity)
				assert.Equal(t, tc.quantity, *ev.Quantity)
			}
		})
	}
}

// A message may be split into chunks, and only the first carries the service
// identifier. The rest must be reported as continuations rather than having
// their first octets read as a service.
func TestChunkedMessage(t *testing.T) {
	d := opcua.New()
	ctx := ctxFor(model.DirRequest)

	first := secureMessageChunk(t, 'C', 1, 1, 1, 1, 631, concat(requestHeader(), u64(0), u32(0), u32(0)))
	events, err := d.Parse(ctx, first)
	require.NoError(t, err)
	assert.Equal(t, "ReadRequest", events[0].Operation)
	assert.Equal(t, "intermediate", events[0].Attrs["chunk"])

	// The continuation carries body octets that are not a service identifier.
	second := secureMessageChunkRaw(t, 'F', 1, 1, 2, 1, []byte{0xde, 0xad, 0xbe, 0xef})
	events, err = d.Parse(ctx, second)
	require.NoError(t, err)
	assert.Equal(t, "Message", events[0].Operation, "a continuation names no service")
	assert.Equal(t, "continuation", events[0].Attrs["chunk"])

	// After the final chunk the next message is read as a service again.
	third := secureMessageChunk(t, 'F', 1, 1, 3, 2, 673, concat(requestHeader(), u32(0)))
	events, err = d.Parse(ctx, third)
	require.NoError(t, err)
	assert.Equal(t, "WriteRequest", events[0].Operation)
}

// An abort chunk is the sender giving up part way through, and carries a
// status rather than a service.
func TestAbortChunk(t *testing.T) {
	msg := secureMessageChunkRaw(t, 'A', 1, 1, 1, 1, concat(u32(0x80850000), nullString()))
	ev := parseOne(t, ctxFor(model.DirRequest), msg)
	assert.Equal(t, "abort", ev.Attrs["chunk"])
	assert.Equal(t, "BadRequestTimeout", ev.Exception)
}

// A sequence number that skips means chunks were lost from the capture or
// injected into it.
func TestSequenceGap(t *testing.T) {
	d := opcua.New()
	ctx := ctxFor(model.DirRequest)
	body := concat(requestHeader(), u64(0), u32(0), u32(0))

	_, err := d.Parse(ctx, secureMessageChunk(t, 'F', 1, 1, 1, 1, 631, body))
	require.NoError(t, err)
	events, err := d.Parse(ctx, secureMessageChunk(t, 'F', 1, 1, 5, 2, 631, body))
	require.NoError(t, err)
	assert.Contains(t, events[0].Attrs["anomaly"], "sequence_gap")
	assert.Equal(t, "2", events[0].Attrs["expected_sequence"])
}

func TestMalformedMessages(t *testing.T) {
	for _, tc := range []struct{ name, message, want string }{
		{"short", "48454c46", "cannot hold a message header"},
		{"unknown_type", "585858461000000000000000", "not an OPC UA message type"},
		{"size_too_small", "48454c4604000000", "shorter than its own header"},
		{"size_mismatch", "48454c46ff00000000000000", "declares 255 octets"},
		{"size_beyond_cap", "48454c4600000200" + "0000000000000000", "exceeds the"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events, err := opcua.New().Parse(ctxFor(model.DirRequest), bytesOf(t, tc.message))
			require.Error(t, err)
			assert.True(t, errors.Is(err, dissect.ErrMalformed), "must wrap ErrMalformed: %v", err)
			assert.Contains(t, err.Error(), tc.want)
			require.Len(t, events, 1)
			assert.True(t, events[0].Malformed)
			assert.Equal(t, "opcua", events[0].Protocol)
		})
	}
}

func TestProbe(t *testing.T) {
	d := opcua.New()
	for _, tc := range []struct {
		name, message string
		min           int
	}{
		{"hello", msgHello, 90},
		{"open_channel", msgOpenChannel, 70},
		{"get_endpoints", msgGetEndpoints, 90},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.GreaterOrEqual(t, d.Probe(ctxFor(model.DirRequest), bytesOf(t, tc.message)), tc.min)
		})
	}

	for _, tc := range []struct{ name, message string }{
		{"empty", ""},
		{"short", "48454c46"},
		{"unknown_type", "58595a461000000000000000"},
		{"bad_chunk_marker", "4d53475a1000000000000000"},
		{"http", "474554202f20485454502f312e310d0a0d0a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, 0, d.Probe(ctxFor(model.DirRequest), bytesOf(t, tc.message)))
		})
	}
}

func TestPDULen(t *testing.T) {
	d := opcua.New()
	hello := bytesOf(t, msgHello)
	n, err := d.PDULen(hello)
	require.NoError(t, err)
	assert.Equal(t, len(hello), n)

	// Two messages in one segment.
	n, err = d.PDULen(append(append([]byte{}, hello...), bytesOf(t, msgAcknowledge)...))
	require.NoError(t, err)
	assert.Equal(t, len(hello), n)

	for _, s := range []string{"", "48454c", "48454c464f000000"} {
		_, err := d.PDULen(bytesOf(t, s))
		assert.True(t, errors.Is(err, dissect.ErrNeedMore), "%q: %v", s, err)
	}
}

func TestNameAndTier(t *testing.T) {
	d := opcua.New()
	assert.Equal(t, "opcua", d.Name())
	assert.Equal(t, 1, d.Tier())
}

// Builders for crafted messages, following the binary encoding of OPC UA
// Part 6 so that a fixture exercises the decoder rather than the hex.

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func u64(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func nullString() []byte { return u32(0xFFFFFFFF) }

func qualifiedName() []byte { return concat([]byte{0x00, 0x00}, nullString()) }

// nodeID encodes a numeric node identifier in the four byte form.
func nodeID(namespace uint8, ident uint16) []byte {
	b := []byte{0x01, namespace, 0, 0}
	binary.LittleEndian.PutUint16(b[2:], ident)
	return b
}

// requestHeader is the shortest legal request header: no authentication
// token, no audit entry, no additional header.
func requestHeader() []byte {
	return concat(
		[]byte{0x00, 0x00},       // authentication token, two byte node id
		u64(0),                   // timestamp
		u32(0),                   // request handle
		u32(0),                   // return diagnostics
		nullString(),             // audit entry id
		u32(0),                   // timeout hint
		[]byte{0x00, 0x00, 0x00}, // additional header: a node id and no body
	)
}

// responseHeader is the shortest legal response header, carrying one status.
func responseHeader(status uint32) []byte {
	return concat(
		u64(0),                   // timestamp
		u32(0),                   // request handle
		u32(status),              // service result
		[]byte{0x00},             // diagnostic info: nothing set
		nullString(),             // string table
		[]byte{0x00, 0x00, 0x00}, // additional header
	)
}

func secureMessage(t *testing.T, channel, token, seq, request, serviceID uint32, body []byte) []byte {
	t.Helper()
	return secureMessageChunk(t, 'F', channel, token, seq, request, serviceID, body)
}

func secureMessageChunk(t *testing.T, chunk byte, channel, token, seq, request, serviceID uint32,
	body []byte) []byte {
	t.Helper()
	return secureMessageChunkRaw(t, chunk, channel, token, seq, request,
		concat(nodeID(0, uint16(serviceID)), body))
}

func secureMessageChunkRaw(t *testing.T, chunk byte, channel, token, seq, request uint32,
	body []byte) []byte {
	t.Helper()
	payload := concat(u32(channel), u32(token), u32(seq), u32(request), body)
	out := append([]byte("MSG"), chunk)
	out = append(out, u32(uint32(8+len(payload)))...)
	return append(out, payload...)
}
