// Package enip dissects EtherNet/IP and the CIP messages it carries, the
// protocol pair spoken to Rockwell and other ODVA controllers on port 44818.
//
// EtherNet/IP is an encapsulation: a 24 octet header names a command, and the
// commands that matter carry a Common Packet Format list of items, inside
// which sits a CIP message. CIP is where the meaning is — a service code
// saying what is to be done, and a path saying to which object of which class
// on which device — and it is deliberately extensible, so the same service
// code means different things on different objects, and above 0x4A whatever
// each vendor decided. This dissector names a service only where the path
// says which object it belongs to; see codes.go.
//
// Three shapes of traffic arrive here. Explicit messaging on TCP 44818 is
// request and reply, one CIP message at a time, optionally routed onward
// through a bridge to a device on a backplane. Discovery on UDP 44818 is a
// broadcast ListIdentity and the replies of everything that hears it, which
// is the richest identity a passive observer gets. Implicit messaging on UDP
// 2222 is cyclic I/O data with no encapsulation header at all, only the item
// list and a connection identifier assigned when the connection was opened.
package enip

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/model"
)

// Ports. Explicit messaging and discovery share 44818; cyclic I/O has its own
// port because its frames are not encapsulated (EtherNet/IP specification,
// chapter 2 and 3-2).
const (
	DefaultPort = 44818
	IOPort      = 2222
)

const (
	// encapHeaderLen is the command, length, session handle, status, sender
	// context and options.
	encapHeaderLen = 24

	// maxEncapLength is the largest body a header may declare. The length
	// field is sixteen bits, which together with the header exceeds the
	// per-stream reassembly cap, so the cap is what bounds it.
	maxEncapLength = dissect.MaxPDUSize - encapHeaderLen

	// maxCPFItems caps the item list. Real traffic uses one or two items;
	// the count field allows 65535.
	maxCPFItems = 8

	// maxListedServices caps how many of a batch's services one event names.
	maxListedServices = 8

	// sendDataHeaderLen is the interface handle and the timeout that precede
	// the item list of SendRRData and SendUnitData.
	sendDataHeaderLen = 6

	// cipInterfaceHandle is the interface handle that says the items carry
	// CIP. No other interface is defined.
	cipInterfaceHandle = 0
)

// Dissector decodes EtherNet/IP and CIP. It holds no mutable state.
type Dissector struct{}

// New returns an EtherNet/IP dissector.
func New() *Dissector { return &Dissector{} }

func init() {
	dissect.Register(New(), dissect.TCPPorts(DefaultPort), dissect.UDPPorts(DefaultPort, IOPort))
}

// Name implements dissect.Dissector.
func (*Dissector) Name() string { return "enip" }

// Tier implements dissect.Dissector.
func (*Dissector) Tier() int { return 1 }

// PDULen implements dissect.Framer.
//
// An encapsulated PDU is the fixed header and the body length it declares. A
// cyclic I/O frame has no header, so it is recognised by its item list and
// taken whole; that test comes first because such a frame's first octets are
// an item count, which read as a header would be a nonsense command with a
// length field far beyond the frame. The test is narrow enough that no
// encapsulated PDU can match it: it demands a two item list whose first item
// is a sequenced address of exactly eight octets, whose second is connected
// data, and whose items account for every octet of the buffer.
func (*Dissector) PDULen(buf []byte) (int, error) {
	if n, ok := ioFrameLen(buf); ok {
		return n, nil
	}
	if len(buf) < 4 {
		return 0, dissect.ErrNeedMore
	}
	length := int(binary.LittleEndian.Uint16(buf[2:4]))
	if length > maxEncapLength {
		return 0, fmt.Errorf("%w: encapsulated length %d exceeds the %d octet maximum",
			dissect.ErrMalformed, length, maxEncapLength)
	}
	total := encapHeaderLen + length
	if len(buf) < total {
		return 0, dissect.ErrNeedMore
	}
	return total, nil
}

// ioFrameLen reports the length of a cyclic I/O frame at the start of buf.
func ioFrameLen(buf []byte) (int, bool) {
	const (
		addressItemLen = 8
		ioHeaderLen    = 2 + 4 + addressItemLen + 4
	)
	if len(buf) < ioHeaderLen {
		return 0, false
	}
	if binary.LittleEndian.Uint16(buf[0:2]) != 2 ||
		binary.LittleEndian.Uint16(buf[2:4]) != itemSequencedAddress ||
		binary.LittleEndian.Uint16(buf[4:6]) != addressItemLen ||
		binary.LittleEndian.Uint16(buf[14:16]) != itemConnectedData {
		return 0, false
	}
	total := ioHeaderLen + int(binary.LittleEndian.Uint16(buf[16:18]))
	if total != len(buf) {
		return 0, false
	}
	return total, true
}

// isIO reports whether this flow is cyclic I/O rather than encapsulated
// messaging. The two run on different ports precisely because their framing
// differs, so the port is what decides.
func isIO(ctx *dissect.FlowContext) bool {
	return ctx.Flow.SrcPort == IOPort || ctx.Flow.DstPort == IOPort
}

// Probe implements dissect.Dissector.
//
// The header is mostly fixed values: the options field is reserved and must
// be zero, the status is one of a handful of codes, and the length accounts
// for the rest of the payload or runs into the next PDU. Taken together those
// are what separate EtherNet/IP from any other little endian header; a
// command this does not know is not disqualifying, since the specification
// has grown commands, but it earns nothing.
func (d *Dissector) Probe(ctx *dissect.FlowContext, payload []byte) int {
	if isIO(ctx) {
		if _, ok := ioFrameLen(payload); ok {
			return 90
		}
		return 0
	}
	if len(payload) < encapHeaderLen {
		return 0
	}
	cmd := binary.LittleEndian.Uint16(payload[0:2])
	length := int(binary.LittleEndian.Uint16(payload[2:4]))
	status := binary.LittleEndian.Uint32(payload[8:12])
	options := binary.LittleEndian.Uint32(payload[20:24])

	if options != 0 {
		return 0
	}
	if _, known := encapStatus[status]; !known {
		return 0
	}
	if length > maxEncapLength {
		return 0
	}
	score := 35
	if _, known := commands[cmd]; known {
		score += 30
	}

	total := encapHeaderLen + length
	switch {
	case total == len(payload):
		score += 25
	case total < len(payload):
		if _, err := d.PDULen(payload[total:]); err == nil {
			score += 25
		}
	}

	// A body that decodes as an item list carrying CIP is the last piece of
	// corroboration, and the one that tells a session apart from any other
	// protocol that happens to open with zeroes. Only a body that is all
	// there is read: this is the first bytes of a stream, so the PDU may
	// well continue beyond them.
	if total <= len(payload) {
		if body, ok := commandBody(cmd, payload[encapHeaderLen:total]); ok {
			if items, err := parseCPF(body); err == nil && len(items) > 0 {
				score += 10
			}
		}
	}
	return min(score, 100)
}

// commandBody returns the part of a command's body that is an item list.
func commandBody(cmd uint16, data []byte) ([]byte, bool) {
	switch cmd {
	case cmdSendRRData, cmdSendUnitData:
		if len(data) < sendDataHeaderLen {
			return nil, false
		}
		return data[sendDataHeaderLen:], true
	case cmdListIdentity, cmdListServices, cmdListInterfaces:
		if len(data) == 0 {
			return nil, false
		}
		return data, true
	default:
		return nil, false
	}
}

// cpfItem is one item of a Common Packet Format list.
type cpfItem struct {
	typ  uint16
	data []byte
}

// parseCPF reads an item list: a count, then each item's type, length and
// body. Nothing in it is trusted: every declared length is checked against
// what is present before it is used.
func parseCPF(b []byte) ([]cpfItem, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("%w: %d octets cannot hold an item count", dissect.ErrMalformed, len(b))
	}
	count := int(binary.LittleEndian.Uint16(b[:2]))
	if count > maxCPFItems {
		return nil, fmt.Errorf("%w: item list declares %d items, more than the %d allowed",
			dissect.ErrMalformed, count, maxCPFItems)
	}
	items := make([]cpfItem, 0, count)
	off := 2
	for i := 0; i < count; i++ {
		if off+4 > len(b) {
			return nil, fmt.Errorf("%w: item %d of %d starts past the end of the list",
				dissect.ErrMalformed, i+1, count)
		}
		typ := binary.LittleEndian.Uint16(b[off : off+2])
		length := int(binary.LittleEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if off+length > len(b) {
			return nil, fmt.Errorf("%w: item %d declares %d octets, %d present",
				dissect.ErrMalformed, i+1, length, len(b)-off)
		}
		items = append(items, cpfItem{typ: typ, data: b[off : off+length]})
		off += length
	}
	return items, nil
}

// header is the encapsulation header.
type header struct {
	command uint16
	length  int
	session uint32
	status  uint32
	context []byte
	options uint32
}

func decodeHeader(b []byte) header {
	return header{
		command: binary.LittleEndian.Uint16(b[0:2]),
		length:  int(binary.LittleEndian.Uint16(b[2:4])),
		session: binary.LittleEndian.Uint32(b[4:8]),
		status:  binary.LittleEndian.Uint32(b[8:12]),
		context: b[12:20],
		options: binary.LittleEndian.Uint32(b[20:24]),
	}
}

// Parse implements dissect.Dissector. It decodes one encapsulated PDU, or one
// cyclic I/O frame.
func (d *Dissector) Parse(ctx *dissect.FlowContext, payload []byte) ([]model.Event, error) {
	base := model.Event{
		CaptureID:    ctx.CaptureID,
		PacketIndex:  ctx.PacketIndex,
		Timestamp:    ctx.Timestamp,
		Flow:         ctx.Flow,
		Protocol:     "enip",
		Direction:    ctx.Direction,
		FunctionCode: -1,
		Class:        model.ClassOther,
	}
	if base.Direction == "" {
		base.Direction = model.DirUnknown
	}
	if isIO(ctx) {
		return parseIO(base, payload)
	}

	if len(payload) < encapHeaderLen {
		msg := fmt.Sprintf("%d octets cannot hold an encapsulation header", len(payload))
		base.Operation = "Encapsulation"
		return []model.Event{malformed(base, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	h := decodeHeader(payload)
	info := command(h.command)
	base.Operation = info.name
	base.FunctionCode = int(h.command)
	base.Class = info.class
	setAttr(&base, "command", info.name)
	if h.session != 0 {
		setAttr(&base, "session_handle", "0x"+hex32be(h.session))
	}
	if _, known := commands[h.command]; !known {
		addAnomaly(&base, "unknown_command")
	}
	if h.options != 0 {
		// The field is reserved and the specification requires zero.
		addAnomaly(&base, "options_field_set")
	}
	if h.status != 0 {
		// The encapsulation layer refusing says nothing about CIP: the
		// session itself was rejected.
		name, known := encapStatus[h.status]
		if !known {
			name = "Status_0x" + hex32be(h.status)
			addAnomaly(&base, "unknown_encapsulation_status")
		}
		base.Exception = name
		setAttr(&base, "encapsulation_status", name)
		base.Direction = model.DirResponse
	}

	body := payload[encapHeaderLen:]
	if h.length != len(body) {
		msg := fmt.Sprintf("header declares %d body octets, %d present", h.length, len(body))
		return []model.Event{malformed(base, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	if len(body) == 0 && h.status != 0 {
		// A device refusing at the encapsulation layer answers with the
		// header alone: there is no CIP message, and the refusal is the
		// whole message.
		return []model.Event{base}, nil
	}

	switch h.command {
	case cmdRegisterSession:
		describeRegister(&base, body)
		return []model.Event{base}, nil
	case cmdSendRRData, cmdSendUnitData:
		return parseSendData(base, body)
	case cmdListIdentity, cmdListServices, cmdListInterfaces:
		return parseList(base, body)
	default:
		if len(body) > 0 {
			setAttr(&base, "body_bytes", strconv.Itoa(len(body)))
		}
		return []model.Event{base}, nil
	}
}

// describeRegister reads a RegisterSession body: the encapsulation revision
// the two ends will speak.
func describeRegister(ev *model.Event, body []byte) {
	if len(body) < 4 {
		if len(body) > 0 {
			addAnomaly(ev, "register_session_truncated")
		}
		return
	}
	setAttr(ev, "protocol_version", strconv.Itoa(int(binary.LittleEndian.Uint16(body[:2]))))
	if flags := binary.LittleEndian.Uint16(body[2:4]); flags != 0 {
		// No option flag is defined, so one that is set is worth seeing.
		setAttr(ev, "session_options", "0x"+hex16(flags))
		addAnomaly(ev, "session_option_flags_set")
	}
}

// parseList decodes the reply to one of the three list commands, each of
// which carries its answers as items. The request itself has an empty body.
func parseList(base model.Event, body []byte) ([]model.Event, error) {
	if len(body) == 0 {
		// The request, which is a device asking what is out there.
		base.Direction = model.DirRequest
		return []model.Event{base}, nil
	}
	base.Direction = model.DirResponse

	items, err := parseCPF(body)
	if err != nil {
		return []model.Event{malformed(base, err.Error())}, err
	}
	setAttr(&base, "item_count", strconv.Itoa(len(items)))

	var out []model.Event
	for _, item := range items {
		ev := base
		setAttr(&ev, "item", itemName(item.typ))
		switch item.typ {
		case itemListIdentityResponse:
			id, ok := parseIdentityItem(item.data)
			if !ok {
				addAnomaly(&ev, "identity_item_unreadable")
				break
			}
			id.fill(
				func(k, v string) { setIdentity(&ev, k, v) },
				func(k, v string) { setAttr(&ev, k, v) },
			)
		case itemListServiceResponse:
			version, flags, name, ok := listServicesItem(item.data)
			if !ok {
				addAnomaly(&ev, "service_item_unreadable")
				break
			}
			setAttr(&ev, "service_name", name)
			setAttr(&ev, "encapsulation_version", strconv.Itoa(int(version)))
			setAttr(&ev, "service_capability", "0x"+hex16(flags))
		}
		out = append(out, ev)
	}
	if len(out) == 0 {
		// A reply with an empty item list is a device answering that it has
		// nothing to list, which ListInterfaces commonly does.
		return []model.Event{base}, nil
	}
	return out, nil
}

// parseSendData decodes SendRRData and SendUnitData: the interface handle, a
// timeout, and an item list whose data items carry CIP.
func parseSendData(base model.Event, body []byte) ([]model.Event, error) {
	if len(body) < sendDataHeaderLen {
		msg := fmt.Sprintf("%d octets cannot hold an interface handle and timeout", len(body))
		return []model.Event{malformed(base, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}
	if iface := binary.LittleEndian.Uint32(body[:4]); iface != cipInterfaceHandle {
		// Only the CIP interface is defined; anything else means the items
		// are not CIP and nothing below would be reading what it thinks.
		setAttr(&base, "interface_handle", "0x"+hex32be(iface))
		addAnomaly(&base, "non_cip_interface")
		return []model.Event{base}, nil
	}

	items, err := parseCPF(body[sendDataHeaderLen:])
	if err != nil {
		return []model.Event{malformed(base, err.Error())}, err
	}

	var (
		out      []model.Event
		connID   string
		connSeq  *uint32
		hasAddr  bool
		firstErr error
	)
	for _, item := range items {
		switch item.typ {
		case itemConnectedAddress:
			// The address item says which connection the data item belongs
			// to, and precedes it in the list.
			if len(item.data) >= 4 {
				connID = "0x" + hex32be(binary.LittleEndian.Uint32(item.data[:4]))
				hasAddr = true
			}
		case itemSequencedAddress:
			if len(item.data) >= 8 {
				connID = "0x" + hex32be(binary.LittleEndian.Uint32(item.data[:4]))
				connSeq = model.Ptr(binary.LittleEndian.Uint32(item.data[4:8]))
				hasAddr = true
			}
		case itemConnectedData, itemUnconnectedData:
			ev := base
			setAttr(&ev, "item", itemName(item.typ))
			if hasAddr {
				setAttr(&ev, "connection_id", connID)
			}
			msg := item.data
			if item.typ == itemConnectedData {
				// Connected data opens with a sequence count, which is how a
				// reply is matched to its request within a connection.
				if len(msg) < 2 {
					addAnomaly(&ev, "connected_data_truncated")
					out = append(out, ev)
					continue
				}
				ev.TransactionID = model.Ptr(uint32(binary.LittleEndian.Uint16(msg[:2])))
				msg = msg[2:]
			} else if connSeq != nil {
				ev.TransactionID = connSeq
			}
			cip, err := decodeCIP(msg, 0)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				out = append(out, malformed(ev, err.Error()))
				continue
			}
			describeCIP(&ev, cip)
			out = append(out, ev)
		}
	}
	if len(out) == 0 {
		// An item list with no data item carries no operation: a connection
		// address on its own, or a socket address of an I/O connection.
		setAttr(&base, "item_count", strconv.Itoa(len(items)))
		return []model.Event{base}, nil
	}
	return out, firstErr
}

// parseIO decodes a cyclic I/O frame.
//
// Such a frame is process data, not an operation: the connection decides what
// the octets mean and only the Forward_Open that opened it said what that is,
// so the frame itself is classified as neither a read nor a write. What it
// does prove is that the connection is live, which is what the communication
// matrix needs it for.
func parseIO(base model.Event, payload []byte) ([]model.Event, error) {
	base.Operation = "IO_Data"
	base.Class = model.ClassOther
	if _, ok := ioFrameLen(payload); !ok {
		msg := "frame is not a sequenced address and connected data item pair"
		return []model.Event{malformed(base, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}
	items, err := parseCPF(payload)
	if err != nil {
		return []model.Event{malformed(base, err.Error())}, err
	}
	for _, item := range items {
		switch item.typ {
		case itemSequencedAddress:
			setAttr(&base, "connection_id", "0x"+hex32be(binary.LittleEndian.Uint32(item.data[:4])))
			base.TransactionID = model.Ptr(binary.LittleEndian.Uint32(item.data[4:8]))
		case itemConnectedData:
			setAttr(&base, "data_bytes", strconv.Itoa(len(item.data)))
			if len(item.data) >= 2 {
				setAttr(&base, "connection_seq",
					strconv.Itoa(int(binary.LittleEndian.Uint16(item.data[:2]))))
			}
		}
	}
	return []model.Event{base}, nil
}

// describeCIP records a decoded CIP message on the event.
func describeCIP(ev *model.Event, m *cipMessage) {
	op := m
	if m.routing && len(m.embedded) == 1 {
		// The wrapper only carries the request onward, so the operation is
		// the one it carries: a write routed through a bridge is a write.
		setAttr(ev, "transport_service", m.info.name)
		op = m.embedded[0]
	}

	ev.Operation = op.info.name
	ev.FunctionCode = int(op.service)
	ev.Class = op.info.class
	if op.reply {
		ev.Direction = model.DirResponse
	} else {
		ev.Direction = model.DirRequest
	}
	if !op.named {
		// The code is above the common range and nothing said which object
		// it belongs to, so its number is all that is known.
		setAttr(ev, "service_scope", "vendor_specific")
	}
	if op.element != nil {
		ev.Quantity = op.element
	}

	describePath(ev, op.path)
	describeStatus(ev, op)
	describeBatch(ev, op)
	describeConnection(ev, op)
	if id, ok := identityOf(op); ok {
		id.fill(
			func(k, v string) { setIdentity(ev, k, v) },
			func(k, v string) { setAttr(ev, k, v) },
		)
		setAttr(ev, "identity_match", "identity_object_layout")
	}
	for _, a := range m.anomalies {
		addAnomaly(ev, a)
	}
	if op != m {
		for _, a := range op.anomalies {
			addAnomaly(ev, a)
		}
	}
}

// describePath records which object a request addressed.
func describePath(ev *model.Event, p *epath) {
	if p == nil {
		return
	}
	if p.hasClass {
		setAttr(ev, "cip_class", className(p.class))
		setAttr(ev, "cip_class_id", "0x"+hex32(p.class))
	}
	if p.hasInst {
		setAttr(ev, "cip_instance", strconv.FormatUint(uint64(p.instance), 10))
	}
	if p.hasAttr {
		setAttr(ev, "cip_attribute", strconv.FormatUint(uint64(p.attribute), 10))
		ev.Address = model.Ptr(p.attribute)
	}
	if p.symbol != "" {
		setAttr(ev, "cip_symbol", p.symbol)
	}
	if len(p.text) > 0 {
		setAttr(ev, "cip_path", p.String())
	}
	if len(p.route) > 0 {
		// A route says the request was not for the device it was sent to but
		// for one behind it, which is how a bridge is passed through.
		setAttr(ev, "cip_route", strings.Join(p.route, ">"))
	}
	if p.key != "" {
		setAttr(ev, "connection_key", p.key)
	}
}

// describeStatus records how a device answered.
func describeStatus(ev *model.Event, m *cipMessage) {
	if !m.reply {
		return
	}
	name := statusName(m.status)
	setAttr(ev, "cip_status", name)
	if m.status != 0 {
		// A refusal is the protocol's own error reply. Which refusal it is
		// separates a client asking for what does not exist from one asking
		// for what it may not have.
		ev.Exception = name
	}
	if len(m.addl) > 0 {
		parts := make([]string, 0, len(m.addl))
		for _, v := range m.addl {
			parts = append(parts, "0x"+hex16(v))
		}
		setAttr(ev, "cip_extended_status", strings.Join(parts, ","))
	}
}

// describeBatch records a Multiple_Service_Packet.
//
// The batch takes the classification of the most consequential service in it,
// because a single write batched among a dozen reads is still a write and a
// rule that only saw the wrapper would miss it.
func describeBatch(ev *model.Event, m *cipMessage) {
	if m.service != svcMultipleServicePacket || len(m.embedded) == 0 {
		return
	}
	setAttr(ev, "embedded_count", strconv.Itoa(len(m.embedded)))
	var names []string
	seen := map[string]bool{}
	for _, inner := range m.embedded {
		// The batch is named by the distinct services in it. A dozen reads
		// of a dozen objects is one kind of operation repeated, and listing
		// the name a dozen times says nothing the count does not.
		if !seen[inner.info.name] && len(names) < maxListedServices {
			seen[inner.info.name] = true
			names = append(names, inner.info.name)
		}
		if classRank(inner.info.class) > classRank(ev.Class) {
			ev.Class = inner.info.class
		}
		if inner.reply && inner.status != 0 {
			// One service of a batch failing is the batch failing in part,
			// and the status of the first failure is the useful one.
			if ev.Exception == "" {
				ev.Exception = statusName(inner.status)
				setAttr(ev, "embedded_status", statusName(inner.status))
			}
		}
		for _, a := range inner.anomalies {
			addAnomaly(ev, a)
		}
	}
	setAttr(ev, "embedded_services", strings.Join(names, ","))
}

// describeConnection records the connection a Forward_Open asked for or
// confirmed.
func describeConnection(ev *model.Event, m *cipMessage) {
	c := m.conn
	if c == nil {
		return
	}
	setAttr(ev, "connection_o2t", "0x"+hex32be(c.o2t))
	setAttr(ev, "connection_t2o", "0x"+hex32be(c.t2o))
	setAttr(ev, "connection_serial", "0x"+hex16(c.serial))
	// The originator is the device asking for the connection, so its vendor
	// and serial number describe the client. They are kept as attributes and
	// not as identity, which is attributed to the server.
	setAttr(ev, "originator_vendor_id", strconv.Itoa(int(c.vendor)))
	setAttr(ev, "originator_serial", "0x"+hex32be(c.origSerial))
	if c.o2tInterval != 0 {
		setAttr(ev, "o2t_interval_us", strconv.FormatUint(uint64(c.o2tInterval), 10))
	}
	if c.t2oInterval != 0 {
		setAttr(ev, "t2o_interval_us", strconv.FormatUint(uint64(c.t2oInterval), 10))
	}
	if c.hasTransport {
		// The low four bits are the transport class: 0 and 1 are the cyclic
		// I/O classes, 3 the connected explicit messaging one.
		setAttr(ev, "transport_class", strconv.Itoa(int(c.transport&0x0f)))
	}
	if c.path != nil && len(c.path.text) > 0 {
		setAttr(ev, "connection_path", c.path.String())
		if c.path.key != "" {
			setAttr(ev, "connection_key", c.path.key)
		}
	}
}

// identityOf returns the identity a reply states, if it states one.
func identityOf(m *cipMessage) (*identity, bool) {
	if !m.reply || m.status != 0 || m.service != svcGetAttributesAll {
		return nil, false
	}
	return identityFromAttributes(m.data)
}

// classRank orders the classifications by how consequential they are, which
// is the same order the GUI sorts them by.
func classRank(c model.Classification) int {
	switch c {
	case model.ClassFirmware:
		return 7
	case model.ClassProgram:
		return 6
	case model.ClassControl:
		return 5
	case model.ClassWrite:
		return 4
	case model.ClassRead:
		return 3
	case model.ClassDiagnostic:
		return 2
	case model.ClassDiscovery:
		return 1
	default:
		return 0
	}
}

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
		ev.Identity = make(map[string]string, 8)
	}
	ev.Identity[key] = value
}

// addAnomaly records an anomaly, keeping any already there.
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

// malformed marks an event as undecodable, keeping whatever was read before
// the frame stopped making sense.
func malformed(ev model.Event, reason string) model.Event {
	if ev.Operation == "" {
		ev.Operation = "Encapsulation"
	}
	ev.Malformed = true
	ev.Error = reason
	return ev
}
