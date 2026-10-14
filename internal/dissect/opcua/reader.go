package opcua

import (
	"encoding/binary"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A bounded reader for the OPC UA binary encoding (OPC UA Part 6, clause 5.2).
//
// Everything here is read from attacker-controlled bytes: every length is
// checked against what is present, every array is capped, and a read past the
// end sets an error that every later read sees rather than panicking or
// silently returning zeroes. Strings are sanitised and truncated for display
// but the reader still advances by their declared length, so a long name
// cannot push the rest of the message out of alignment.
type reader struct {
	b   []byte
	off int
	bad bool
}

// Caps on what one message may ask the reader to do.
const (
	maxStringLen   = 256
	maxArrayLength = 1024
	maxEndpoints   = 8
	maxDepth       = 4
)

func newReader(b []byte) *reader { return &reader{b: b} }

func (r *reader) ok() bool        { return !r.bad }
func (r *reader) remaining() int  { return len(r.b) - r.off }
func (r *reader) fail()           { r.bad = true }
func (r *reader) have(n int) bool { return !r.bad && n >= 0 && r.remaining() >= n }

func (r *reader) skip(n int) {
	if !r.have(n) {
		r.fail()
		return
	}
	r.off += n
}

func (r *reader) u8() uint8 {
	if !r.have(1) {
		r.fail()
		return 0
	}
	v := r.b[r.off]
	r.off++
	return v
}

func (r *reader) u16() uint16 {
	if !r.have(2) {
		r.fail()
		return 0
	}
	v := binary.LittleEndian.Uint16(r.b[r.off:])
	r.off += 2
	return v
}

func (r *reader) u32() uint32 {
	if !r.have(4) {
		r.fail()
		return 0
	}
	v := binary.LittleEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v
}

func (r *reader) u64() uint64 {
	if !r.have(8) {
		r.fail()
		return 0
	}
	v := binary.LittleEndian.Uint64(r.b[r.off:])
	r.off += 8
	return v
}

func (r *reader) i32() int32 { return int32(r.u32()) }

func (r *reader) f64() float64 { return math.Float64frombits(r.u64()) }

// str reads a string: a signed length and that many UTF-8 octets, where a
// negative length is a null string rather than an error.
func (r *reader) str() string {
	n := r.i32()
	if r.bad {
		return ""
	}
	if n < 0 {
		return ""
	}
	if !r.have(int(n)) {
		r.fail()
		return ""
	}
	raw := r.b[r.off : r.off+int(n)]
	r.off += int(n)
	return sanitise(string(raw))
}

// byteString reads an opaque value, returning only its length: certificates
// and nonces are not things this tool stores.
func (r *reader) byteStringLen() int {
	n := r.i32()
	if r.bad {
		return 0
	}
	if n < 0 {
		return 0
	}
	if !r.have(int(n)) {
		r.fail()
		return 0
	}
	r.off += int(n)
	return int(n)
}

// arrayLen reads an array length, where a negative value is a null array.
// A length beyond what the message could hold fails the read rather than
// being trusted.
func (r *reader) arrayLen() int {
	n := r.i32()
	switch {
	case r.bad:
		return 0
	case n < 0:
		return 0
	case int(n) > maxArrayLength || int(n) > r.remaining():
		r.fail()
		return 0
	default:
		return int(n)
	}
}

// NodeId encodings (OPC UA Part 6, clause 5.2.2.9).
const (
	nodeTwoByte       = 0x00
	nodeFourByte      = 0x01
	nodeNumeric       = 0x02
	nodeString        = 0x03
	nodeGUID          = 0x04
	nodeOpaque        = 0x05
	nodeFlagNamespace = 0x80
	nodeFlagServer    = 0x40
)

// nodeID reads a node identifier and renders it the way OPC UA writes one:
// a namespace index and an identifier, with the identifier's own kind kept.
func (r *reader) nodeID() string {
	encoding := r.u8()
	if r.bad {
		return ""
	}
	// An ExpandedNodeId adds a namespace URI and a server index behind the
	// same encodings, which the two high bits mark.
	expanded := encoding & (nodeFlagNamespace | nodeFlagServer)
	var ns uint16
	var ident string
	switch encoding & 0x0F {
	case nodeTwoByte:
		ident = "i=" + strconv.FormatUint(uint64(r.u8()), 10)
	case nodeFourByte:
		ns = uint16(r.u8())
		ident = "i=" + strconv.FormatUint(uint64(r.u16()), 10)
	case nodeNumeric:
		ns = r.u16()
		ident = "i=" + strconv.FormatUint(uint64(r.u32()), 10)
	case nodeString:
		ns = r.u16()
		ident = "s=" + r.str()
	case nodeGUID:
		ns = r.u16()
		r.skip(16)
		ident = "g=guid"
	case nodeOpaque:
		ns = r.u16()
		ident = "b=" + strconv.Itoa(r.byteStringLen()) + "octets"
	default:
		r.fail()
		return ""
	}
	if expanded&nodeFlagNamespace != 0 {
		// The namespace URI, which replaces the index.
		if uri := r.str(); uri != "" {
			ident += ";nsu=" + uri
		}
	}
	if expanded&nodeFlagServer != 0 {
		r.u32()
	}
	if r.bad {
		return ""
	}
	if ns != 0 {
		return "ns=" + strconv.FormatUint(uint64(ns), 10) + ";" + ident
	}
	return ident
}

// numericNodeID reads a node identifier that must be numeric, which is how a
// message body names the service it carries.
func (r *reader) numericNodeID() (uint32, bool) {
	encoding := r.u8()
	if r.bad {
		return 0, false
	}
	switch encoding & 0x0F {
	case nodeTwoByte:
		return uint32(r.u8()), r.ok()
	case nodeFourByte:
		r.u8()
		return uint32(r.u16()), r.ok()
	case nodeNumeric:
		r.u16()
		return r.u32(), r.ok()
	default:
		return 0, false
	}
}

// localizedText reads a text with an optional locale, whose presence is a
// bitmask rather than a length (OPC UA Part 6, clause 5.2.2.14).
func (r *reader) localizedText() string {
	mask := r.u8()
	if r.bad {
		return ""
	}
	var locale, text string
	if mask&0x01 != 0 {
		locale = r.str()
	}
	if mask&0x02 != 0 {
		text = r.str()
	}
	if text == "" {
		return locale
	}
	return text
}

// qualifiedName reads a namespace index and a name.
func (r *reader) qualifiedName() string {
	ns := r.u16()
	name := r.str()
	if r.bad {
		return ""
	}
	if ns != 0 {
		return "ns=" + strconv.FormatUint(uint64(ns), 10) + ";" + name
	}
	return name
}

// extensionObject skips a value whose type is named by a node identifier.
// Its body is opaque here: what matters is that the reader lands after it.
func (r *reader) extensionObject() {
	r.nodeID()
	encoding := r.u8()
	if r.bad {
		return
	}
	switch encoding {
	case 0x00:
		// No body at all.
	case 0x01, 0x02:
		// A byte string or an XML element, both length prefixed.
		r.byteStringLen()
	default:
		r.fail()
	}
}

// diagnosticInfo skips the diagnostics a response header may carry, whose
// fields are each present only when their bit is set (OPC UA Part 6, clause
// 5.2.2.12).
func (r *reader) diagnosticInfo(depth int) {
	mask := r.u8()
	if r.bad {
		return
	}
	if mask&0x01 != 0 {
		r.i32() // symbolic id
	}
	if mask&0x02 != 0 {
		r.i32() // namespace uri
	}
	if mask&0x04 != 0 {
		r.i32() // localized text
	}
	if mask&0x08 != 0 {
		r.i32() // locale
	}
	if mask&0x10 != 0 {
		r.str() // additional info
	}
	if mask&0x20 != 0 {
		r.u32() // inner status code
	}
	if mask&0x40 != 0 {
		// Nested diagnostics, which a crafted message could nest without end.
		if depth >= maxDepth {
			r.fail()
			return
		}
		r.diagnosticInfo(depth + 1)
	}
}

// requestHeader skips the header every service request opens with, leaving
// the reader at the service's own first field (OPC UA Part 4, clause 7.28).
func (r *reader) requestHeader() {
	r.nodeID() // authentication token
	r.u64()    // timestamp
	r.u32()    // request handle
	r.u32()    // return diagnostics
	r.str()    // audit entry id
	r.u32()    // timeout hint
	r.extensionObject()
}

// responseHeader reads the header every service response opens with and
// returns the service result, which is how a server refuses a whole service
// rather than one item of it (OPC UA Part 4, clause 7.29).
func (r *reader) responseHeader() uint32 {
	r.u64() // timestamp
	r.u32() // request handle
	result := r.u32()
	r.diagnosticInfo(0)
	if n := r.arrayLen(); n > 0 {
		for i := 0; i < n && r.ok(); i++ {
			r.str()
		}
	}
	r.extensionObject()
	return result
}

// sanitise keeps a string printable and bounded. These strings are rendered
// in the GUI and come off the wire, so a control character becomes a dot
// here rather than travelling onwards.
func sanitise(s string) string {
	var sb strings.Builder
	for _, c := range s {
		switch {
		case c == utf8.RuneError, c < 0x20, c == 0x7f:
			sb.WriteByte('.')
		default:
			sb.WriteRune(c)
		}
		if sb.Len() >= maxStringLen {
			break
		}
	}
	return sb.String()
}
