package enip

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/model"
)

// Decoding of the CIP message router request and reply that EtherNet/IP
// carries, and of the EPATH that says which object a request addresses
// (CIP Networks Library volume 1, chapters 2 and C-1.4).

const (
	// replyFlag is the high bit of the service octet, set in a reply.
	replyFlag = 0x80

	// minRequestLen is the service octet and the request path size.
	minRequestLen = 2

	// minReplyLen is the service octet, the reserved octet, the general
	// status and the size of the additional status.
	minReplyLen = 4

	// maxPathSegments caps how many segments of one EPATH are walked. A path
	// is attacker controlled and a route through several bridges is still
	// only a handful of segments.
	maxPathSegments = 16

	// maxEmbeddedServices caps how many services one Multiple_Service_Packet
	// is read out of. The count field is sixteen bits wide.
	maxEmbeddedServices = 16

	// maxEmbeddedDepth caps nesting. One level is an Unconnected_Send or a
	// Multiple_Service_Packet, two is a batch sent through a bridge, and
	// three is as deep as real traffic goes.
	maxEmbeddedDepth = 3

	// maxSymbolLen caps a symbolic segment, which carries a tag name. The
	// Logix limit is 40 characters per element of a name.
	maxSymbolLen = 128
)

// epath is a decoded CIP path. A request says what it addresses here, so this
// is where the analytically interesting part of a CIP request lives: the class
// is the kind of object, the instance which one of them, and a symbol the name
// an engineer gave a tag.
type epath struct {
	class     uint32
	hasClass  bool
	instance  uint32
	hasInst   bool
	attribute uint32
	hasAttr   bool
	symbol    string
	// route is the port and link address segments that send a request on
	// through a bridge, outermost first, e.g. "port1/link0" for slot 0 of a
	// backplane.
	route []string
	// key is the electronic key a connection path asserts the target must
	// match: the device the originator believes it is talking to.
	key string
	// text renders the whole path in order, which is what the GUI shows.
	text []string

	truncated bool
	unknown   bool
}

func (p *epath) String() string { return strings.Join(p.text, ",") }

// parsePath decodes an EPATH. It never fails: a segment it does not know
// stops the walk and is reported, because the segment types are variable
// length and there is no safe way to skip one whose length is unknown.
func parsePath(b []byte) epath {
	var p epath
	for i := 0; i < len(b); {
		if len(p.text) >= maxPathSegments {
			p.truncated = true
			return p
		}
		seg := b[i]
		rest := b[i+1:]
		switch {
		case seg < 0x20:
			// Port segment: the port to leave by and the link address to
			// leave towards, which together are a route through a chassis.
			n := p.port(seg, rest)
			if n == 0 {
				p.unknown = true
				return p
			}
			i += n

		case seg < 0x40:
			n := p.logical(seg, rest)
			if n == 0 {
				p.unknown = true
				return p
			}
			i += n

		case seg < 0x60:
			n := p.network(seg, rest)
			if n == 0 {
				p.unknown = true
				return p
			}
			i += n

		case seg < 0x80:
			// Symbolic segment: the low five bits are the length of an ASCII
			// name. Length zero means an extended format this does not read.
			ln := int(seg & 0x1f)
			if ln == 0 || len(rest) < ln {
				p.unknown = true
				return p
			}
			p.setSymbol(rest[:ln])
			i += 1 + ln + ln%2

		case seg == segANSISymbol:
			// ANSI extended symbol segment, which is how a Logix tag name is
			// addressed.
			if len(rest) < 1 {
				p.unknown = true
				return p
			}
			ln := int(rest[0])
			if ln == 0 || len(rest) < 1+ln {
				p.unknown = true
				return p
			}
			p.setSymbol(rest[1 : 1+ln])
			i += 2 + ln + ln%2

		case seg == segSimpleData:
			// Simple data segment: words of opaque data, which a connection
			// path uses to carry configuration.
			if len(rest) < 1 {
				p.unknown = true
				return p
			}
			words := int(rest[0])
			if len(rest) < 1+2*words {
				p.unknown = true
				return p
			}
			p.text = append(p.text, "data="+strconv.Itoa(2*words)+"B")
			i += 2 + 2*words

		default:
			p.unknown = true
			return p
		}
	}
	return p
}

// EPATH segment octets named individually (CIP volume 1, C-1.4).
const (
	segElectronicKey = 0x34
	segANSISymbol    = 0x91
	segSimpleData    = 0x80
)

// port decodes a port segment, returning the octets it used or zero when it
// cannot be read.
func (p *epath) port(seg uint8, rest []byte) int {
	portID := uint32(seg & 0x0f)
	used := 1
	if portID == 0x0f {
		// Extended port identifier: a sixteen bit port number follows.
		if len(rest) < 2 {
			return 0
		}
		portID = uint32(binary.LittleEndian.Uint16(rest[:2]))
		rest = rest[2:]
		used += 2
	}
	var link string
	switch {
	case seg&0x10 != 0:
		// Extended link address: a length and that many octets, padded to a
		// word boundary.
		if len(rest) < 1 {
			return 0
		}
		ln := int(rest[0])
		if ln == 0 || len(rest) < 1+ln {
			return 0
		}
		link = printable(rest[1 : 1+ln])
		used += 1 + ln + ln%2
	default:
		if len(rest) < 1 {
			return 0
		}
		link = strconv.Itoa(int(rest[0]))
		used++
	}
	hop := "port" + strconv.FormatUint(uint64(portID), 10) + "/link" + link
	p.route = append(p.route, hop)
	p.text = append(p.text, hop)
	return used
}

// logical decodes a logical segment: the class, instance, member, connection
// point or attribute number this path addresses.
func (p *epath) logical(seg uint8, rest []byte) int {
	if seg == segElectronicKey {
		return p.electronicKey(rest)
	}
	format := seg & 0x03
	var (
		value uint32
		used  int
	)
	switch format {
	case 0: // eight bit
		if len(rest) < 1 {
			return 0
		}
		value, used = uint32(rest[0]), 2
	case 1: // sixteen bit, preceded by a pad octet
		if len(rest) < 3 {
			return 0
		}
		value, used = uint32(binary.LittleEndian.Uint16(rest[1:3])), 4
	case 2: // thirty-two bit, preceded by a pad octet
		if len(rest) < 5 {
			return 0
		}
		value, used = binary.LittleEndian.Uint32(rest[1:5]), 6
	default:
		// Format 3 is reserved; a path using it is not one this can read.
		return 0
	}

	// A path may address an object through several, as a bridge to a chassis
	// to an object within it; the last class and instance it names are the
	// ones the service acts on, so a later segment replaces an earlier one.
	switch seg & 0xfc {
	case 0x20: // class
		p.class, p.hasClass = value, true
		p.text = append(p.text, "class="+className(value))
	case 0x24: // instance
		p.instance, p.hasInst = value, true
		p.text = append(p.text, "instance="+strconv.FormatUint(uint64(value), 10))
	case 0x28: // member, which for an array is the element index
		p.text = append(p.text, "member="+strconv.FormatUint(uint64(value), 10))
	case 0x2c: // connection point
		p.text = append(p.text, "connection_point="+strconv.FormatUint(uint64(value), 10))
	case 0x30: // attribute
		p.attribute, p.hasAttr = value, true
		p.text = append(p.text, "attribute="+strconv.FormatUint(uint64(value), 10))
	default:
		// Service id and reserved logical types.
		return 0
	}
	return used
}

// electronicKey decodes the key a connection path asserts: the vendor, device
// type, product code and revision the originator expects to find. A mismatch
// is what makes a device refuse a connection, so the assertion itself is
// evidence of what the originator was configured for.
func (p *epath) electronicKey(rest []byte) int {
	const keyFormat4 = 0x04
	if len(rest) < 1 || rest[0] != keyFormat4 || len(rest) < 9 {
		return 0
	}
	vendor := binary.LittleEndian.Uint16(rest[1:3])
	deviceType := binary.LittleEndian.Uint16(rest[3:5])
	product := binary.LittleEndian.Uint16(rest[5:7])
	major, minor := rest[7]&0x7f, rest[8]
	p.key = fmt.Sprintf("vendor=%d device_type=%d product_code=%d revision=%d.%d",
		vendor, deviceType, product, major, minor)
	p.text = append(p.text, "key")
	return 10
}

// network decodes a network segment, which carries a parameter of the
// connection being built rather than an address: the requested packet
// interval, a fixed tag, or a safety segment (CIP volume 1, C-1.4.3).
//
// Two shapes exist. The schedule, fixed tag and production inhibit time
// subtypes are a single octet of value; the safety and extended subtypes, and
// the microsecond form of the inhibit time, declare a length in words. A
// subtype outside those is not skipped: the length of a segment this does not
// know is not knowable, so the walk stops instead of resynchronising onto
// whatever follows.
func (p *epath) network(seg uint8, rest []byte) int {
	subtype := seg & 0x1f
	switch subtype {
	case 1, 2, 3:
		if len(rest) < 1 {
			return 0
		}
		p.text = append(p.text, "network="+strconv.Itoa(int(subtype))+"/"+strconv.Itoa(int(rest[0])))
		return 2
	case 4, 10, 16:
		if len(rest) < 1 {
			return 0
		}
		words := int(rest[0])
		if len(rest) < 1+2*words {
			return 0
		}
		p.text = append(p.text, "network="+strconv.Itoa(int(subtype)))
		return 2 + 2*words
	default:
		return 0
	}
}

func (p *epath) setSymbol(b []byte) {
	s := printable(b)
	if len(s) > maxSymbolLen {
		s = s[:maxSymbolLen]
	}
	if p.symbol == "" {
		p.symbol = s
	}
	p.text = append(p.text, "symbol="+s)
}

// cipMessage is one decoded message router request or reply.
type cipMessage struct {
	service uint8
	reply   bool
	info    serviceInfo
	// named is false when the service code is above the common range and
	// nothing in the request said which object it belongs to, so the code
	// could only be reported as the number it is.
	named bool

	path    *epath
	status  uint8
	addl    []uint16
	data    []byte
	element *uint32

	// embedded holds the messages this one carries: the services of a
	// Multiple_Service_Packet, or the single request an Unconnected_Send
	// routes onward.
	embedded []*cipMessage
	// conn is the connection a Forward_Open asks for or confirms.
	conn *connection

	// routing is set when this message only carries another one, in which
	// case the embedded message is the operation that actually happens.
	routing bool

	anomalies []string
}

func (m *cipMessage) anomaly(name string) {
	for _, have := range m.anomalies {
		if have == name {
			return
		}
	}
	m.anomalies = append(m.anomalies, name)
}

// decodeCIP decodes one message router request or reply.
func decodeCIP(b []byte, depth int) (*cipMessage, error) {
	if len(b) < minRequestLen {
		return nil, fmt.Errorf("%w: %d octets cannot hold a CIP message", dissect.ErrMalformed, len(b))
	}
	m := &cipMessage{service: b[0] & 0x7f, reply: b[0]&replyFlag != 0}
	if m.reply {
		if err := m.decodeReply(b); err != nil {
			return nil, err
		}
	} else if err := m.decodeRequest(b); err != nil {
		return nil, err
	}

	if m.reply {
		m.info, m.named = replyService(m.service)
	} else {
		class, hasClass := uint32(0), false
		if m.path != nil {
			class, hasClass = m.path.class, m.path.hasClass
		}
		symbolic := m.path != nil && m.path.symbol != ""
		m.info, m.named = service(m.service, class, hasClass, symbolic)
	}
	m.describeData(depth)
	return m, nil
}

func (m *cipMessage) decodeRequest(b []byte) error {
	words := int(b[1])
	end := minRequestLen + 2*words
	if end > len(b) {
		return fmt.Errorf("%w: request path declares %d octets, %d present",
			dissect.ErrMalformed, 2*words, len(b)-minRequestLen)
	}
	p := parsePath(b[minRequestLen:end])
	m.path = &p
	if p.unknown {
		m.anomaly("unreadable_path_segment")
	}
	if p.truncated {
		m.anomaly("path_segments_truncated")
	}
	m.data = b[end:]
	return nil
}

func (m *cipMessage) decodeReply(b []byte) error {
	if len(b) < minReplyLen {
		return fmt.Errorf("%w: %d octets cannot hold a CIP reply", dissect.ErrMalformed, len(b))
	}
	m.status = b[2]
	words := int(b[3])
	end := minReplyLen + 2*words
	if end > len(b) {
		return fmt.Errorf("%w: additional status declares %d octets, %d present",
			dissect.ErrMalformed, 2*words, len(b)-minReplyLen)
	}
	for i := minReplyLen; i+1 < end; i += 2 {
		m.addl = append(m.addl, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	m.data = b[end:]
	return nil
}

// describeData reads the part of a service that is defined per service rather
// than per object: the batch of a Multiple_Service_Packet, the request an
// Unconnected_Send routes onward, the connection a Forward_Open opens, and
// the element count of a tag access.
func (m *cipMessage) describeData(depth int) {
	switch {
	case m.service == svcMultipleServicePacket:
		m.decodeBatch(depth)

	case m.routesOnward():
		m.decodeRouted(depth)

	case m.opensConnection():
		m.decodeForwardOpen()

	case m.path != nil && m.path.symbol != "" && len(m.data) >= 2 && !m.reply:
		// A tag read or write states how many elements it covers.
		switch m.service {
		case svcReadTag, svcWriteTag, svcReadTagFragmented, svcWriteTagFragment:
			m.element = model.Ptr(uint32(binary.LittleEndian.Uint16(m.data[:2])))
		}
	}
}

// routesOnward reports a request that carries another request for a device
// further on. Unconnected_Send is the service a bridge takes to pass a
// message to the backplane behind it.
func (m *cipMessage) routesOnward() bool {
	return !m.reply && m.service == svcUnconnectedSend &&
		m.path != nil && m.path.hasClass && m.path.class == classConnectionManager
}

// opensConnection reports a Forward_Open. A request says so by its path; a
// reply carries no path, and the two Connection Manager codes are not used by
// any other object in these captures, so a reply is read on its code alone.
func (m *cipMessage) opensConnection() bool {
	if m.service != svcForwardOpen && m.service != svcLargeForwardOpen {
		return false
	}
	if m.reply {
		return true
	}
	return m.path != nil && m.path.hasClass && m.path.class == classConnectionManager
}

// decodeBatch reads a Multiple_Service_Packet: a count, an offset per service
// and the services themselves, each a complete message router message.
func (m *cipMessage) decodeBatch(depth int) {
	if len(m.data) < 2 {
		m.anomaly("empty_service_batch")
		return
	}
	count := int(binary.LittleEndian.Uint16(m.data[:2]))
	if count == 0 {
		m.anomaly("empty_service_batch")
		return
	}
	// Every offset must be present before any is trusted.
	if 2+2*count > len(m.data) {
		m.anomaly("service_batch_truncated")
		return
	}
	offsets := make([]int, 0, count)
	for i := 0; i < count; i++ {
		offsets = append(offsets, int(binary.LittleEndian.Uint16(m.data[2+2*i:4+2*i])))
	}
	for i, off := range offsets {
		if len(m.embedded) >= maxEmbeddedServices {
			m.anomaly("service_batch_truncated")
			return
		}
		// Offsets are counted from the start of the count field, and each
		// service runs to the next offset.
		end := len(m.data)
		if i+1 < len(offsets) {
			end = offsets[i+1]
		}
		if off < 2+2*count || off > end || end > len(m.data) {
			m.anomaly("service_batch_offset_out_of_range")
			return
		}
		m.embed(m.data[off:end], depth)
	}
}

// decodeRouted reads an Unconnected_Send: the embedded request and the route
// it is to take after this hop.
func (m *cipMessage) decodeRouted(depth int) {
	const header = 4 // tick time, timeout ticks and the embedded size
	if len(m.data) < header {
		m.anomaly("routed_request_truncated")
		return
	}
	size := int(binary.LittleEndian.Uint16(m.data[2:4]))
	if header+size > len(m.data) {
		m.anomaly("routed_request_truncated")
		return
	}
	m.routing = true
	m.embed(m.data[header:header+size], depth)

	// The route path follows the embedded request, after a size in words and
	// a reserved octet.
	rest := m.data[header+size:]
	if len(rest) < 2 {
		return
	}
	words := int(rest[0])
	if 2+2*words > len(rest) {
		m.anomaly("route_path_truncated")
		return
	}
	route := parsePath(rest[2 : 2+2*words])
	if len(route.route) == 0 {
		return
	}
	// The route belongs to the request that takes it, and the embedded
	// request is the one the event will describe, so it is recorded there.
	target := m.path
	if len(m.embedded) == 1 && m.embedded[0].path != nil {
		target = m.embedded[0].path
	}
	if target != nil {
		target.route = append(target.route, route.route...)
	}
}

// connection is what a Forward_Open asks for or confirms. The two connection
// identifiers are what the cyclic I/O frames on UDP 2222 carry, so they are
// how an implicit connection seen there can be traced back to the exchange
// that opened it.
type connection struct {
	o2t, t2o uint32
	serial   uint16
	// vendor and origSerial identify the originator — the device asking for
	// the connection — not the one being asked.
	vendor     uint16
	origSerial uint32
	// o2tInterval and t2oInterval are the requested packet intervals in
	// microseconds in a request, and the actual intervals in a reply.
	o2tInterval, t2oInterval uint32
	transport                uint8
	hasTransport             bool
	path                     *epath
}

// decodeForwardOpen reads the connection a Forward_Open asks for or confirms
// (CIP volume 1, 3-5.5.2 and 3-5.5.3). Large_Forward_Open differs only in the
// width of the two network connection parameter fields.
func (m *cipMessage) decodeForwardOpen() {
	if m.reply {
		m.decodeForwardOpenReply()
		return
	}
	params := 2
	if m.service == svcLargeForwardOpen {
		params = 4
	}
	// Tick time, timeout ticks, the two connection identifiers, the
	// connection serial, the originator's vendor and serial number, the
	// timeout multiplier and three reserved octets.
	const header = 1 + 1 + 4 + 4 + 2 + 2 + 4 + 1 + 3
	fixed := header + 2*(4+params) + 2
	if len(m.data) < fixed {
		m.anomaly("forward_open_truncated")
		return
	}
	c := &connection{
		o2t:        binary.LittleEndian.Uint32(m.data[2:6]),
		t2o:        binary.LittleEndian.Uint32(m.data[6:10]),
		serial:     binary.LittleEndian.Uint16(m.data[10:12]),
		vendor:     binary.LittleEndian.Uint16(m.data[12:14]),
		origSerial: binary.LittleEndian.Uint32(m.data[14:18]),
	}
	o := header
	c.o2tInterval = binary.LittleEndian.Uint32(m.data[o : o+4])
	o += 4 + params
	c.t2oInterval = binary.LittleEndian.Uint32(m.data[o : o+4])
	o += 4 + params
	c.transport, c.hasTransport = m.data[o], true
	words := int(m.data[o+1])
	o += 2
	if o+2*words > len(m.data) {
		m.anomaly("connection_path_truncated")
	} else {
		p := parsePath(m.data[o : o+2*words])
		c.path = &p
		if p.unknown {
			m.anomaly("unreadable_path_segment")
		}
	}
	m.conn = c
}

// decodeForwardOpenReply reads the confirmation: the identifiers the target
// assigned and the intervals it settled on.
func (m *cipMessage) decodeForwardOpenReply() {
	if m.status != 0 {
		// A refusal carries the failed connection's serial and vendor in its
		// additional status rather than a connection.
		return
	}
	const fixed = 4 + 4 + 2 + 2 + 4 + 4 + 4
	if len(m.data) < fixed {
		m.anomaly("forward_open_truncated")
		return
	}
	m.conn = &connection{
		o2t:         binary.LittleEndian.Uint32(m.data[0:4]),
		t2o:         binary.LittleEndian.Uint32(m.data[4:8]),
		serial:      binary.LittleEndian.Uint16(m.data[8:10]),
		vendor:      binary.LittleEndian.Uint16(m.data[10:12]),
		origSerial:  binary.LittleEndian.Uint32(m.data[12:16]),
		o2tInterval: binary.LittleEndian.Uint32(m.data[16:20]),
		t2oInterval: binary.LittleEndian.Uint32(m.data[20:24]),
	}
}

// embed decodes one message carried inside this one.
func (m *cipMessage) embed(b []byte, depth int) {
	if depth+1 >= maxEmbeddedDepth {
		m.anomaly("embedded_depth_exceeded")
		return
	}
	inner, err := decodeCIP(b, depth+1)
	if err != nil {
		m.anomaly("embedded_message_unreadable")
		return
	}
	m.embedded = append(m.embedded, inner)
}

// printable renders bytes that are meant to be a name. Packet bytes are
// hostile and are rendered in the GUI, so anything outside printable ASCII
// becomes a dot rather than travelling onwards as it is.
func printable(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			out = append(out, '.')
			continue
		}
		out = append(out, c)
	}
	return string(out)
}
