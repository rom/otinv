// Package opcua dissects the OPC UA binary protocol, the one modern
// industrial protocol designed with security in it — which is exactly why it
// is worth checking whether the security is switched on.
//
// A connection opens with a Hello and an Acknowledge agreeing buffer sizes,
// then an OpenSecureChannel naming the security policy the two ends will use,
// then a session: CreateSession, ActivateSession with a user identity token,
// and from then on services. The transport frames every message with a three
// letter type and a length, so framing is simple; what takes care is the body,
// which is a binary encoding of nested structures with length prefixed strings
// and arrays, all of it attacker controlled.
//
// Three things make this dissector worth its length. The security policy and
// message security mode are in the clear in the channel handshake and in
// every endpoint description, so a channel carrying "SecurityPolicy#None" can
// be reported as what it is: unsigned, unencrypted traffic that anyone on the
// segment can read and forge, which is what CLAUDE.md's rule on SecurityMode
// None is for. The endpoint descriptions a server returns also carry its own
// application description — the name, the application URI and the product URI
// — which is the identity CLAUDE.md names for this protocol. And the service
// identifiers say what is being done: a Write, a Call of a method, or an
// AddNodes that changes the server's own address space.
//
// The protocol allows a message to be split into chunks, where only the first
// carries the service identifier. Chunks are not reassembled here; the state
// of the stream remembers that a message is in progress, so a continuation is
// reported as one rather than having its first octets read as a service.
package opcua

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/model"
)

// DefaultPort is the registered OPC UA TCP port. A server is commonly
// configured elsewhere — the sample capture in testdata runs on 12001 — which
// is what Probe and the extra ports in otinv.yaml are for.
const DefaultPort = 4840

const (
	// headerLen is the message type, the chunk marker and the message size.
	headerLen = 8

	// minMessageSize is the smallest legal value of the size field.
	minMessageSize = headerLen

	// secureChannelHeaderLen is the channel identifier, the token and the
	// sequence header of a MSG or CLO message.
	secureChannelHeaderLen = 16

	// maxListedItems caps how many nodes or endpoints one event names.
	maxListedItems = 8
)

// Dissector decodes the OPC UA binary protocol. It holds no mutable state:
// the per-stream chunk and sequence tracking lives in the FlowContext the
// caller owns.
type Dissector struct{}

// New returns an OPC UA dissector.
func New() *Dissector { return &Dissector{} }

func init() {
	dissect.Register(New(), dissect.TCPPorts(DefaultPort))
}

// Name implements dissect.Dissector.
func (*Dissector) Name() string { return "opcua" }

// Tier implements dissect.Dissector.
func (*Dissector) Tier() int { return 1 }

// PDULen implements dissect.Framer.
func (*Dissector) PDULen(buf []byte) (int, error) {
	if len(buf) < headerLen {
		return 0, dissect.ErrNeedMore
	}
	if !knownType(string(buf[:3])) {
		return 0, fmt.Errorf("%w: %q is not an OPC UA message type",
			dissect.ErrMalformed, sanitise(string(buf[:3])))
	}
	total := int(uint32(buf[4]) | uint32(buf[5])<<8 | uint32(buf[6])<<16 | uint32(buf[7])<<24)
	switch {
	case total < minMessageSize:
		return 0, fmt.Errorf("%w: message size %d is shorter than its own header",
			dissect.ErrMalformed, total)
	case total > dissect.MaxPDUSize:
		return 0, fmt.Errorf("%w: message size %d exceeds the %d octet maximum",
			dissect.ErrMalformed, total, dissect.MaxPDUSize)
	case len(buf) < total:
		return 0, dissect.ErrNeedMore
	default:
		return total, nil
	}
}

func knownType(t string) bool {
	_, ok := messageTypes[t]
	return ok
}

// Probe implements dissect.Dissector.
//
// The three letter type and the chunk marker are the strongest evidence: four
// octets of printable ASCII from a set of seven values, followed by a length
// that accounts for the payload. A known service identifier in the body is
// what separates a real session from a lucky header.
func (d *Dissector) Probe(_ *dissect.FlowContext, payload []byte) int {
	if len(payload) < headerLen {
		return 0
	}
	kind := string(payload[:3])
	if !knownType(kind) {
		return 0
	}
	switch payload[3] {
	case chunkFinal, chunkIntermediate, chunkAbort:
	default:
		return 0
	}
	total := int(binary.LittleEndian.Uint32(payload[4:8]))
	if total < minMessageSize || total > dissect.MaxPDUSize {
		return 0
	}

	score := 50
	switch {
	case total == len(payload):
		score += 25
	case total < len(payload):
		// The segment runs straight into another message, which is the
		// strongest framing evidence there is.
		if _, err := d.PDULen(payload[total:]); err == nil {
			score += 25
		}
	}

	// Only a message that is all here is read into: this is the first bytes
	// of a stream, so the message may well continue beyond them.
	if total > len(payload) {
		return min(score, 100)
	}
	body := payload[headerLen:total]

	// A Hello carries an endpoint URL, which every OPC UA server has.
	if kind == msgHello {
		r := newReader(body)
		r.skip(20)
		if url := r.str(); r.ok() && strings.HasPrefix(url, "opc.tcp://") {
			score += 25
		}
	}
	if kind == msgMessage && len(body) > secureChannelHeaderLen {
		r := newReader(body[secureChannelHeaderLen:])
		if id, ok := r.numericNodeID(); ok {
			if _, known := services[id]; known {
				score += 25
			}
		}
	}
	return min(score, 100)
}

// streamState remembers what this direction of the stream is in the middle
// of: a chunked message whose continuation carries no service identifier, and
// the sequence number the next chunk should have.
type streamState struct {
	inChunk    bool
	expectSeq  uint32
	haveSeq    bool
	chunkCount int
}

func state(ctx *dissect.FlowContext) *streamState {
	if s, ok := ctx.State.(*streamState); ok {
		return s
	}
	s := &streamState{}
	ctx.State = s
	return s
}

// Parse implements dissect.Dissector. It decodes one message, or one chunk of
// a message that was split.
func (d *Dissector) Parse(ctx *dissect.FlowContext, payload []byte) ([]model.Event, error) {
	ev := model.Event{
		CaptureID:    ctx.CaptureID,
		PacketIndex:  ctx.PacketIndex,
		Timestamp:    ctx.Timestamp,
		Flow:         ctx.Flow,
		Protocol:     "opcua",
		Direction:    ctx.Direction,
		ServerPort:   ctx.ServerPort,
		Operation:    "Message",
		FunctionCode: -1,
		Class:        model.ClassOther,
	}
	if ev.Direction == "" {
		ev.Direction = model.DirUnknown
	}

	if len(payload) < headerLen {
		msg := fmt.Sprintf("%d octets cannot hold a message header", len(payload))
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}
	kind := string(payload[:3])
	typeName, known := messageTypes[kind]
	if !known {
		msg := fmt.Sprintf("%q is not an OPC UA message type", sanitise(kind))
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}
	ev.Operation = typeName
	setAttr(&ev, "message_type", kind)

	chunk := payload[3]
	switch chunk {
	case chunkFinal:
	case chunkIntermediate:
		setAttr(&ev, "chunk", "intermediate")
	case chunkAbort:
		setAttr(&ev, "chunk", "abort")
	default:
		addAnomaly(&ev, "unknown_chunk_marker")
	}

	// The framer sized this slice from the same field, so a mismatch here
	// means a caller handed over something else.
	total := int(binary.LittleEndian.Uint32(payload[4:8]))
	switch {
	case total < minMessageSize:
		msg := fmt.Sprintf("message size %d is shorter than its own header", total)
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	case total > dissect.MaxPDUSize:
		msg := fmt.Sprintf("message size %d exceeds the %d octet maximum", total, dissect.MaxPDUSize)
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	case total != len(payload):
		msg := fmt.Sprintf("message declares %d octets, %d present", total, len(payload))
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}
	body := payload[headerLen:]

	switch kind {
	case msgHello, msgReverseHello:
		d.hello(&ev, body, kind)
	case msgAcknowledge:
		d.acknowledge(&ev, body)
	case msgError:
		d.transportError(&ev, body)
	case msgOpen:
		d.openChannel(ctx, &ev, body, chunk)
	case msgMessage, msgClose:
		d.secureMessage(ctx, &ev, body, chunk, kind)
	}
	return []model.Event{ev}, nil
}

// hello reads the first message of a connection, which names the endpoint the
// client is asking for — and so the host and port the server is known by.
func (d *Dissector) hello(ev *model.Event, body []byte, kind string) {
	ev.Direction = model.DirRequest
	ev.Class = model.ClassOther
	r := newReader(body)
	if kind == msgHello {
		setAttr(ev, "protocol_version", strconv.FormatUint(uint64(r.u32()), 10))
		setAttr(ev, "receive_buffer", strconv.FormatUint(uint64(r.u32()), 10))
		setAttr(ev, "send_buffer", strconv.FormatUint(uint64(r.u32()), 10))
		setAttr(ev, "max_message_size", strconv.FormatUint(uint64(r.u32()), 10))
		setAttr(ev, "max_chunk_count", strconv.FormatUint(uint64(r.u32()), 10))
	}
	url := r.str()
	if !r.ok() {
		addAnomaly(ev, "hello_truncated")
		return
	}
	if kind == msgReverseHello {
		// A server reaching out to a client through a firewall, which
		// reverses who connects to whom.
		ev.Direction = model.DirResponse
		setAttr(ev, "server_uri", url)
		url = r.str()
	}
	setAttr(ev, "endpoint_url", url)
	if url != "" {
		// The URL names the server: a client asks for it by host, port and
		// path, so this is evidence about the device being connected to.
		setIdentity(ev, "endpoint_url", url)
	}
}

// acknowledge reads the server's answer to a Hello: the buffer sizes it will
// actually use.
func (d *Dissector) acknowledge(ev *model.Event, body []byte) {
	ev.Direction = model.DirResponse
	r := newReader(body)
	setAttr(ev, "protocol_version", strconv.FormatUint(uint64(r.u32()), 10))
	setAttr(ev, "receive_buffer", strconv.FormatUint(uint64(r.u32()), 10))
	setAttr(ev, "send_buffer", strconv.FormatUint(uint64(r.u32()), 10))
	setAttr(ev, "max_message_size", strconv.FormatUint(uint64(r.u32()), 10))
	setAttr(ev, "max_chunk_count", strconv.FormatUint(uint64(r.u32()), 10))
	if !r.ok() {
		addAnomaly(ev, "acknowledge_truncated")
	}
}

// transportError reads an ERR message: the transport itself refusing, which
// is how a connection ends when the handshake or the security does not hold.
func (d *Dissector) transportError(ev *model.Event, body []byte) {
	ev.Direction = model.DirResponse
	r := newReader(body)
	code := r.u32()
	reason := r.str()
	if !r.ok() {
		addAnomaly(ev, "error_truncated")
		return
	}
	name := statusName(code)
	ev.Exception = name
	setAttr(ev, "status", name)
	setAttr(ev, "status_code", "0x"+hex32(code))
	if reason != "" {
		setAttr(ev, "reason", reason)
	}
}

// openChannel reads an OpenSecureChannel message, where the two ends agree
// what security the channel will have — the one place the policy appears in
// the clear.
func (d *Dissector) openChannel(ctx *dissect.FlowContext, ev *model.Event, body []byte, chunk byte) {
	r := newReader(body)
	setAttr(ev, "secure_channel", strconv.FormatUint(uint64(r.u32()), 10))
	policy := r.str()
	certLen := r.byteStringLen()
	thumbLen := r.byteStringLen()
	if !r.ok() {
		addAnomaly(ev, "channel_header_truncated")
		return
	}
	short := securityPolicy(policy)
	setAttr(ev, "security_policy", short)
	if certLen > 0 {
		// A sender certificate is only present when the channel is signed,
		// so its presence is itself evidence about the security in use.
		setAttr(ev, "sender_certificate_bytes", strconv.Itoa(certLen))
	}
	if thumbLen > 0 {
		setAttr(ev, "receiver_thumbprint_bytes", strconv.Itoa(thumbLen))
	}
	if short == "None" {
		// Nothing in this channel is signed or encrypted: every message on it
		// can be read and forged by anyone on the segment.
		setAttr(ev, "insecure_channel", "true")
	}

	seq, request := r.u32(), r.u32()
	d.sequence(ctx, ev, seq, request)
	if !r.ok() {
		addAnomaly(ev, "sequence_header_truncated")
		return
	}
	d.serviceBody(ctx, ev, r, chunk)
}

// secureMessage reads a MSG or CLO message: the channel and token it belongs
// to, the sequence header, and the service inside.
func (d *Dissector) secureMessage(ctx *dissect.FlowContext, ev *model.Event, body []byte, chunk byte, kind string) {
	r := newReader(body)
	setAttr(ev, "secure_channel", strconv.FormatUint(uint64(r.u32()), 10))
	setAttr(ev, "security_token", strconv.FormatUint(uint64(r.u32()), 10))
	seq, request := r.u32(), r.u32()
	d.sequence(ctx, ev, seq, request)
	if !r.ok() {
		addAnomaly(ev, "sequence_header_truncated")
		return
	}
	if kind == msgClose {
		ev.Direction = model.DirRequest
	}
	d.serviceBody(ctx, ev, r, chunk)
}

// sequence records the sequence and request numbers and reports a gap, which
// means chunks were lost from the capture or injected into it.
func (d *Dissector) sequence(ctx *dissect.FlowContext, ev *model.Event, seq, request uint32) {
	setAttr(ev, "sequence", strconv.FormatUint(uint64(seq), 10))
	ev.TransactionID = model.Ptr(request)

	st := state(ctx)
	if st.haveSeq && seq != st.expectSeq {
		setAttr(ev, "expected_sequence", strconv.FormatUint(uint64(st.expectSeq), 10))
		addAnomaly(ev, "sequence_gap")
	}
	st.expectSeq = seq + 1
	st.haveSeq = true
}

// serviceBody reads the service identifier a message carries and what the
// service says, unless this chunk is the continuation of one that already
// named it.
func (d *Dissector) serviceBody(ctx *dissect.FlowContext, ev *model.Event, r *reader, chunk byte) {
	st := state(ctx)
	continuation := st.inChunk

	switch chunk {
	case chunkIntermediate:
		st.inChunk = true
		st.chunkCount++
	case chunkAbort:
		// An abort ends the message and carries a status rather than a
		// service: the sender giving up part way through.
		st.inChunk = false
		st.chunkCount = 0
		code := r.u32()
		reason := r.str()
		if r.ok() {
			ev.Exception = statusName(code)
			setAttr(ev, "status", statusName(code))
			if reason != "" {
				setAttr(ev, "reason", reason)
			}
		}
		return
	default:
		st.inChunk = false
		st.chunkCount = 0
	}

	if continuation {
		// The service identifier was in the first chunk; these octets are
		// the rest of the body and say nothing on their own.
		setAttr(ev, "chunk", "continuation")
		return
	}

	id, ok := r.numericNodeID()
	if !ok {
		addAnomaly(ev, "service_identifier_unreadable")
		return
	}
	info, known := service(id)
	ev.Operation = info.name
	ev.Class = info.class
	ev.FunctionCode = int(id)
	setAttr(ev, "service", info.name)
	if !known {
		addAnomaly(ev, "unknown_service")
		return
	}
	if strings.HasSuffix(info.name, "Request") {
		ev.Direction = model.DirRequest
	} else if strings.HasSuffix(info.name, "Response") || info.name == "ServiceFault" {
		ev.Direction = model.DirResponse
	}
	if chunk == chunkIntermediate {
		// The first chunk of a long message: the service is known, the
		// arguments are not all here.
		return
	}
	d.describeService(ev, id, r)
}

// describeService reads the part of a service this project has use for. The
// rest are left as the name and classification of the service itself, which
// is what the tier requires; a service whose arguments do not decode keeps
// its name and says what broke.
func (d *Dissector) describeService(ev *model.Event, id uint32, r *reader) {
	switch id {
	case 428: // GetEndpointsRequest
		r.requestHeader()
		setAttr(ev, "endpoint_url", r.str())
	case 431: // GetEndpointsResponse
		d.serviceResult(ev, r.responseHeader())
		d.endpoints(ev, r)
	case 446: // OpenSecureChannelRequest
		r.requestHeader()
		setAttr(ev, "client_protocol_version", strconv.FormatUint(uint64(r.u32()), 10))
		if kind := r.u32(); kind == 0 {
			setAttr(ev, "request_type", "issue")
		} else {
			setAttr(ev, "request_type", "renew")
		}
		d.securityMode(ev, r.u32())
		r.byteStringLen() // client nonce
		setAttr(ev, "requested_lifetime_ms", strconv.FormatUint(uint64(r.u32()), 10))
	case 449: // OpenSecureChannelResponse
		d.serviceResult(ev, r.responseHeader())
		setAttr(ev, "server_protocol_version", strconv.FormatUint(uint64(r.u32()), 10))
		setAttr(ev, "secure_channel", strconv.FormatUint(uint64(r.u32()), 10))
		setAttr(ev, "security_token", strconv.FormatUint(uint64(r.u32()), 10))
	case 461: // CreateSessionRequest
		r.requestHeader()
		d.applicationDescription(ev, r, false)
		setAttr(ev, "server_uri", r.str())
		setAttr(ev, "endpoint_url", r.str())
		setAttr(ev, "session_name", r.str())
	case 464: // CreateSessionResponse
		d.serviceResult(ev, r.responseHeader())
		setAttr(ev, "session_id", r.nodeID())
		r.nodeID() // authentication token, which is a secret
		if timeout := r.f64(); r.ok() && timeout > 0 {
			setAttr(ev, "session_timeout_ms", strconv.FormatFloat(timeout, 'f', 0, 64))
		}
		r.byteStringLen() // server nonce
		if n := r.byteStringLen(); n > 0 {
			setAttr(ev, "server_certificate_bytes", strconv.Itoa(n))
		}
		d.endpoints(ev, r)
	case 467: // ActivateSessionRequest
		r.requestHeader()
		d.activateSession(ev, r)
	case 470: // ActivateSessionResponse
		d.serviceResult(ev, r.responseHeader())
	case 631: // ReadRequest
		r.requestHeader()
		r.f64() // max age
		r.u32() // timestamps to return
		d.nodeList(ev, r, nodesRead)
	case 673: // WriteRequest
		r.requestHeader()
		d.nodeList(ev, r, nodesWritten)
	case 527: // BrowseRequest
		r.requestHeader()
		r.nodeID() // view id
		r.u64()    // view timestamp
		r.u32()    // view version
		r.u32()    // requested max references
		d.nodeList(ev, r, nodesBrowsed)
	case 712: // CallRequest
		r.requestHeader()
		d.methodList(ev, r)
	case 397: // ServiceFault
		d.serviceResult(ev, r.responseHeader())
	default:
		// Every response opens with the same header, so the service result
		// is readable even where the rest of the body is not entered.
		if strings.HasSuffix(ev.Operation, "Response") {
			d.serviceResult(ev, r.responseHeader())
		}
	}
	if !r.ok() {
		addAnomaly(ev, "service_arguments_unreadable")
	}
}

// serviceResult records how a service went. A bad status is the protocol's
// own error reply.
func (d *Dissector) serviceResult(ev *model.Event, code uint32) {
	if !isBad(code) {
		return
	}
	name := statusName(code)
	ev.Exception = name
	setAttr(ev, "status", name)
	setAttr(ev, "status_code", "0x"+hex32(code))
}

// securityMode records the message security mode a channel asks for.
func (d *Dissector) securityMode(ev *model.Event, mode uint32) {
	name := securityModeName(mode)
	setAttr(ev, "security_mode", name)
	if name == "None" {
		setAttr(ev, "insecure_channel", "true")
	}
}

// applicationDescription reads how an application describes itself: the URI
// that identifies it, the product it is, and the name it goes by. For a
// server this is the identity CLAUDE.md names for this protocol; for a client
// it describes the other end, so it is kept as attributes.
func (d *Dissector) applicationDescription(ev *model.Event, r *reader, isServer bool) {
	uri := r.str()
	product := r.str()
	name := r.localizedText()
	kind := applicationTypeName(r.u32())
	r.str() // gateway server uri
	r.str() // discovery profile uri
	if n := r.arrayLen(); n > 0 {
		for i := 0; i < n && r.ok(); i++ {
			r.str()
		}
	}
	if !r.ok() {
		return
	}
	prefix := "client_"
	if isServer {
		prefix = "server_"
	}
	setAttr(ev, prefix+"application_uri", uri)
	setAttr(ev, prefix+"product_uri", product)
	setAttr(ev, prefix+"application_name", name)
	setAttr(ev, prefix+"application_type", kind)
	if isServer {
		setIdentity(ev, "application_uri", uri)
		setIdentity(ev, "product_uri", product)
		setIdentity(ev, "application_name", name)
	}
}

// endpoints reads the endpoint descriptions a server returns: every way it
// can be connected to, with the security each offers. A server that offers an
// endpoint with security mode None accepts unprotected traffic, whatever the
// client in this capture happened to choose.
func (d *Dissector) endpoints(ev *model.Event, r *reader) {
	n := r.arrayLen()
	if n == 0 || !r.ok() {
		return
	}
	setAttr(ev, "endpoint_count", strconv.Itoa(n))
	var (
		urls     []string
		modes    []string
		policies []string
		tokens   []string
		insecure bool
	)
	for i := 0; i < n && i < maxEndpoints && r.ok(); i++ {
		url := r.str()
		d.applicationDescription(ev, r, true)
		r.byteStringLen() // server certificate
		mode := securityModeName(r.u32())
		policy := securityPolicy(r.str())
		if tokenCount := r.arrayLen(); tokenCount > 0 {
			for j := 0; j < tokenCount && r.ok(); j++ {
				r.str() // policy id
				kind := userTokenName(r.u32())
				r.str() // issued token type
				r.str() // issuer endpoint url
				r.str() // security policy uri
				tokens = appendUnique(tokens, kind)
			}
		}
		r.str() // transport profile uri
		r.u8()  // security level
		if !r.ok() {
			addAnomaly(ev, "endpoint_truncated")
			break
		}
		urls = appendUnique(urls, url)
		modes = appendUnique(modes, mode)
		policies = appendUnique(policies, policy)
		if mode == "None" || policy == "None" {
			insecure = true
		}
	}
	setAttr(ev, "endpoint_urls", join(urls))
	setAttr(ev, "security_modes", join(modes))
	setAttr(ev, "security_policies", join(policies))
	setAttr(ev, "user_tokens", join(tokens))
	if insecure {
		// At least one endpoint takes unsigned, unencrypted connections.
		setAttr(ev, "offers_insecure_endpoint", "true")
	}
}

// activateSession reads which user identity a client is activating a session
// with, which is the closest OPC UA comes to saying who is at the keyboard.
func (d *Dissector) activateSession(ev *model.Event, r *reader) {
	// Client signature: an algorithm and a signature, both opaque.
	r.str()
	r.byteStringLen()
	if n := r.arrayLen(); n > 0 {
		for i := 0; i < n && r.ok(); i++ {
			r.byteStringLen()
			r.str()
			r.byteStringLen()
		}
	}
	if n := r.arrayLen(); n > 0 {
		for i := 0; i < n && r.ok(); i++ {
			r.str()
		}
	}
	// The user identity token is an extension object whose type node says
	// which kind of token it is. Anonymous, a user name with a password, or
	// a certificate: the three are told apart by that node and not by
	// anything in the token body, which may be encrypted.
	token := r.nodeID()
	if r.ok() && token != "" {
		setAttr(ev, "identity_token", identityTokenKind(token))
	}
}

// identityTokenKind names a user identity token from the node identifier of
// its binary encoding (OPC UA Part 6, annex A.2). A password token's contents
// are never read: this tool does not store credentials.
func identityTokenKind(node string) string {
	switch node {
	case "i=321":
		return "Anonymous"
	case "i=324":
		return "UserName"
	case "i=327":
		return "X509Certificate"
	case "i=940":
		return "IssuedToken"
	default:
		return node
	}
}

// nodeKind is the shape of the per-node structure a service carries, which
// differs between the three services that name nodes (OPC UA Part 4, clauses
// 7.24, 7.39 and 7.3).
type nodeKind int

const (
	// nodesRead is a ReadValueId: a node, an attribute, an index range and
	// the data encoding asked for.
	nodesRead nodeKind = iota
	// nodesWritten is a WriteValue, which ends in the value itself.
	nodesWritten
	// nodesBrowsed is a BrowseDescription: a node and what to follow from it.
	nodesBrowsed
)

// nodeList reads the nodes a service names and the attribute of each. It
// records how many and the first few, which is what says whether a client
// read one value or swept the whole address space.
func (d *Dissector) nodeList(ev *model.Event, r *reader, kind nodeKind) {
	n := r.arrayLen()
	if n == 0 || !r.ok() {
		return
	}
	setAttr(ev, "node_count", strconv.Itoa(n))
	ev.Quantity = model.Ptr(uint32(n))
	var nodes, attrs []string
	for i := 0; i < n && i < maxListedItems && r.ok(); i++ {
		node := r.nodeID()
		if !r.ok() {
			break
		}
		nodes = appendUnique(nodes, node)
		switch kind {
		case nodesRead:
			attrs = appendUnique(attrs, attributeName(r.u32()))
			r.str()           // index range
			r.qualifiedName() // data encoding
		case nodesWritten:
			attrs = appendUnique(attrs, attributeName(r.u32()))
			r.str() // index range
			// The value follows, whose encoding this does not enter: the
			// node and the attribute are what the operation is about, and
			// the value of a write is not something to store.
			i = n
		case nodesBrowsed:
			r.u32()    // browse direction
			r.nodeID() // reference type
			r.u8()     // include subtypes
			r.u32()    // node class mask
			r.u32()    // result mask
		}
	}
	setAttr(ev, "nodes", join(nodes))
	setAttr(ev, "attributes", join(attrs))
}

// methodList reads a Call: which object a method is being invoked on and
// which method it is.
func (d *Dissector) methodList(ev *model.Event, r *reader) {
	n := r.arrayLen()
	if n == 0 || !r.ok() {
		return
	}
	setAttr(ev, "method_count", strconv.Itoa(n))
	ev.Quantity = model.Ptr(uint32(n))
	// Each field is recorded as it is read, so a message that stops making
	// sense half way through keeps what was readable before it did. The
	// sample capture is a robustness test tool whose method identifier
	// declares a quarter of a megabyte of name, and the object it was
	// calling into is still worth knowing.
	if object := r.nodeID(); r.ok() {
		setAttr(ev, "object", object)
	}
	if method := r.nodeID(); r.ok() {
		setAttr(ev, "method", method)
	}
	if args := r.arrayLen(); r.ok() && args > 0 {
		setAttr(ev, "argument_count", strconv.Itoa(args))
	}
}

func appendUnique(list []string, v string) []string {
	if v == "" || len(list) >= maxListedItems {
		return list
	}
	for _, have := range list {
		if have == v {
			return list
		}
	}
	return append(list, v)
}

func join(list []string) string { return strings.Join(list, ",") }

func setAttr(ev *model.Event, key, value string) {
	if value == "" {
		return
	}
	if ev.Attrs == nil {
		ev.Attrs = make(map[string]string, 8)
	}
	ev.Attrs[key] = value
}

func setIdentity(ev *model.Event, key, value string) {
	if value == "" {
		return
	}
	if ev.Identity == nil {
		ev.Identity = make(map[string]string, 4)
	}
	ev.Identity[key] = value
}

func addAnomaly(ev *model.Event, name string) {
	existing := ev.Attrs["anomaly"]
	switch {
	case existing == "":
		setAttr(ev, "anomaly", name)
	case strings.Contains(existing, name):
	default:
		setAttr(ev, "anomaly", existing+","+name)
	}
}

func malformed(ev model.Event, reason string) model.Event {
	ev.Malformed = true
	ev.Error = reason
	return ev
}
