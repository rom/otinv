package bacnet

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/rom/otinv/internal/dissect"
)

// The BACnet tag encoding (ASHRAE 135, clause 20.2): every value carries a
// tag number saying what it is, a class saying whether the number is an
// application data type or a position in the service's own structure, and a
// length that may be one of three widths or may mark the opening or closing
// of a constructed value.
//
// Everything here is read from attacker-controlled bytes, so each length is
// checked against what is present and the whole walk is capped.

const (
	// extendedTagNumber is the tag number that says the real one follows.
	extendedTagNumber = 0x0F

	// lvtExtendedLength says the length follows the tag rather than being
	// encoded in it.
	lvtExtendedLength = 5
	lvtOpening        = 6
	lvtClosing        = 7

	// Application data types (ASHRAE 135, clause 20.2.1.4).
	appNull            = 0
	appBoolean         = 1
	appUnsigned        = 2
	appSigned          = 3
	appReal            = 4
	appDouble          = 5
	appOctetString     = 6
	appCharacterString = 7
	appBitString       = 8
	appEnumerated      = 9
	appDate            = 10
	appTime            = 11
	appObjectID        = 12
)

// Budgets. A crafted APDU would otherwise walk as long as its length field
// claims and nest as deep as it likes.
const (
	maxTags      = 256
	maxTagDepth  = 8
	maxStringLen = 256
)

// tag is one decoded tag and its value.
type tag struct {
	number  uint8
	context bool
	opening bool
	closing bool
	value   []byte

	// boolean carries the value of an application boolean, which is encoded
	// in the length field rather than in a value octet.
	boolean bool
}

// budget bounds one walk.
type budget struct {
	tags  int
	depth int
}

// readTags decodes a flat list of tags, with the opening and closing markers
// of constructed values left in place so that a caller can walk structure
// without the reader having to understand every service.
func readTags(b []byte) ([]tag, error) {
	bud := &budget{}
	var out []tag
	for off := 0; off < len(b); {
		t, n, err := readTag(b[off:])
		if err != nil {
			return out, err
		}
		bud.tags++
		if bud.tags > maxTags {
			return out, fmt.Errorf("%w: more than %d tags", dissect.ErrMalformed, maxTags)
		}
		switch {
		case t.opening:
			bud.depth++
			if bud.depth > maxTagDepth {
				return out, fmt.Errorf("%w: tags nested deeper than %d",
					dissect.ErrMalformed, maxTagDepth)
			}
		case t.closing:
			bud.depth--
			if bud.depth < 0 {
				return out, fmt.Errorf("%w: a closing tag with nothing open", dissect.ErrMalformed)
			}
		}
		out = append(out, t)
		off += n
	}
	return out, nil
}

// readTag decodes one tag, returning how many octets it used.
func readTag(b []byte) (tag, int, error) {
	if len(b) == 0 {
		return tag{}, 0, fmt.Errorf("%w: a tag with no octets", dissect.ErrMalformed)
	}
	head := b[0]
	t := tag{number: head >> 4, context: head&0x08 != 0}
	lvt := head & 0x07
	off := 1

	if t.number == extendedTagNumber {
		if off >= len(b) {
			return tag{}, 0, fmt.Errorf("%w: an extended tag number with no octet", dissect.ErrMalformed)
		}
		t.number = b[off]
		off++
	}

	// An application boolean carries its value where the length would be.
	if !t.context && t.number == appBoolean {
		t.boolean = lvt != 0
		return t, off, nil
	}

	switch {
	case t.context && lvt == lvtOpening:
		t.opening = true
		return t, off, nil
	case t.context && lvt == lvtClosing:
		t.closing = true
		return t, off, nil
	}

	length := int(lvt)
	if lvt == lvtExtendedLength {
		if off >= len(b) {
			return tag{}, 0, fmt.Errorf("%w: an extended length with no octet", dissect.ErrMalformed)
		}
		switch first := b[off]; {
		case first < 254:
			length = int(first)
			off++
		case first == 254:
			if off+3 > len(b) {
				return tag{}, 0, fmt.Errorf("%w: a sixteen bit length with %d octets left",
					dissect.ErrMalformed, len(b)-off-1)
			}
			length = int(binary.BigEndian.Uint16(b[off+1 : off+3]))
			off += 3
		default:
			if off+5 > len(b) {
				return tag{}, 0, fmt.Errorf("%w: a thirty-two bit length with %d octets left",
					dissect.ErrMalformed, len(b)-off-1)
			}
			length = int(binary.BigEndian.Uint32(b[off+1 : off+5]))
			off += 5
		}
	}
	if length < 0 || off+length > len(b) {
		return tag{}, 0, fmt.Errorf("%w: a tag declaring %d octets with %d present",
			dissect.ErrMalformed, length, len(b)-off)
	}
	t.value = b[off : off+length]
	return t, off + length, nil
}

// contextValue returns the value of the first context tag with this number at
// the top level of the list, not descending into constructed values.
func contextValue(tags []tag, number uint8) ([]byte, bool) {
	depth := 0
	for _, t := range tags {
		switch {
		case t.opening:
			depth++
		case t.closing:
			depth--
		case depth == 0 && t.context && t.number == number:
			return t.value, true
		}
	}
	return nil, false
}

// group returns the tags inside the constructed value opened by this context
// tag number, with the opening and closing markers left out.
func group(tags []tag, number uint8) ([]tag, bool) {
	depth := 0
	for i, t := range tags {
		if depth == 0 && t.opening && t.context && t.number == number {
			inner := 0
			for j := i + 1; j < len(tags); j++ {
				switch {
				case tags[j].opening:
					inner++
				case tags[j].closing:
					if inner == 0 {
						return tags[i+1 : j], true
					}
					inner--
				}
			}
			return tags[i+1:], true
		}
		switch {
		case t.opening:
			depth++
		case t.closing:
			depth--
		}
	}
	return nil, false
}

// firstApplication returns the first application tag at the top level of the
// list, which is where a single value sits.
func firstApplication(tags []tag) (tag, bool) {
	for _, t := range tags {
		if !t.context && !t.opening && !t.closing {
			return t, true
		}
	}
	return tag{}, false
}

// unsigned reads an unsigned integer of one to four octets.
func unsigned(b []byte) (uint32, bool) {
	if len(b) == 0 || len(b) > 4 {
		return 0, false
	}
	var v uint32
	for _, c := range b {
		v = v<<8 | uint32(c)
	}
	return v, true
}

// signedValue reads a signed integer in two's complement.
func signedValue(b []byte) (int64, bool) {
	if len(b) == 0 || len(b) > 8 {
		return 0, false
	}
	v := int64(0)
	if b[0]&0x80 != 0 {
		v = -1
	}
	for _, c := range b {
		v = v<<8 | int64(c)
	}
	return v, true
}

// objectID splits an object identifier into its type and instance.
func objectID(b []byte) (objectType uint16, instance uint32, ok bool) {
	if len(b) != 4 {
		return 0, 0, false
	}
	v := binary.BigEndian.Uint32(b)
	return uint16(v >> 22), v & 0x003FFFFF, true
}

// characterString decodes a BACnet character string, whose first octet names
// the character set (ASHRAE 135, clause 20.2.9).
//
// Four of the five encodings are fixed width or ASCII compatible and are
// converted here; anything else is reported as the number it is rather than
// being read as if it were UTF-8. The result is sanitised either way, because
// these strings end up in the GUI and come off the wire.
func characterString(b []byte) (string, string, bool) {
	if len(b) == 0 {
		return "", "", false
	}
	encoding, body := b[0], b[1:]
	if len(body) > 4*maxStringLen {
		body = body[:4*maxStringLen]
	}
	switch encoding {
	case 0: // UTF-8, which ASHRAE 135 still calls ANSI X3.4
		return sanitise(string(body)), "utf8", true
	case 4: // UCS-2, read as UTF-16 big endian
		if len(body)%2 != 0 {
			return "", "ucs2", false
		}
		units := make([]uint16, 0, len(body)/2)
		for i := 0; i+1 < len(body); i += 2 {
			units = append(units, binary.BigEndian.Uint16(body[i:i+2]))
		}
		return sanitise(string(utf16.Decode(units))), "ucs2", true
	case 3: // UCS-4
		if len(body)%4 != 0 {
			return "", "ucs4", false
		}
		var sb strings.Builder
		for i := 0; i+3 < len(body); i += 4 {
			sb.WriteRune(rune(binary.BigEndian.Uint32(body[i : i+4])))
		}
		return sanitise(sb.String()), "ucs4", true
	case 5: // ISO 8859-1
		var sb strings.Builder
		for _, c := range body {
			sb.WriteRune(rune(c))
		}
		return sanitise(sb.String()), "latin1", true
	default:
		return "", "charset_" + strconv.Itoa(int(encoding)), false
	}
}

// sanitise keeps a string printable and bounded. Packet bytes are hostile and
// these strings are rendered, so a control character becomes a dot here
// rather than travelling onwards.
func sanitise(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r == utf8.RuneError, r < 0x20, r == 0x7f:
			sb.WriteByte('.')
		default:
			sb.WriteRune(r)
		}
		if sb.Len() >= maxStringLen {
			break
		}
	}
	return sb.String()
}

// renderValue describes an application tagged value in one short string,
// which is what the GUI shows for the value a property carries.
func renderValue(t tag) string {
	switch t.number {
	case appNull:
		return "null"
	case appBoolean:
		if t.boolean {
			return "true"
		}
		return "false"
	case appUnsigned:
		if v, ok := unsigned(t.value); ok {
			return strconv.FormatUint(uint64(v), 10)
		}
	case appSigned:
		if v, ok := signedValue(t.value); ok {
			return strconv.FormatInt(v, 10)
		}
	case appReal:
		if len(t.value) == 4 {
			return strconv.FormatFloat(
				float64(math.Float32frombits(binary.BigEndian.Uint32(t.value))), 'g', -1, 32)
		}
	case appDouble:
		if len(t.value) == 8 {
			return strconv.FormatFloat(
				math.Float64frombits(binary.BigEndian.Uint64(t.value)), 'g', -1, 64)
		}
	case appCharacterString:
		if s, _, ok := characterString(t.value); ok {
			return s
		}
	case appEnumerated:
		if v, ok := unsigned(t.value); ok {
			return "enum:" + strconv.FormatUint(uint64(v), 10)
		}
	case appObjectID:
		if ot, inst, ok := objectID(t.value); ok {
			return objectName(ot) + ":" + strconv.FormatUint(uint64(inst), 10)
		}
	case appBitString, appOctetString, appDate, appTime:
		return strconv.Itoa(len(t.value)) + " octets"
	}
	return "app" + strconv.Itoa(int(t.number)) + "/" + strconv.Itoa(len(t.value)) + "B"
}
