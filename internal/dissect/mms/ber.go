package mms

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// A minimal BER reader. Everything above the COTP layer of IEC 61850 is
// ASN.1 BER — the session layer's user data is a presentation PDU, which
// wraps an ACSE PDU, which wraps an MMS PDU — so reading any of it means
// reading tag-length-value triples.
//
// None of it may be trusted. Every length is checked against what is actually
// present before it is used, the forms that have no end in sight are refused
// outright, and every walk carries a depth and element budget so that a
// crafted blob cannot turn into unbounded recursion or work.

// BER tag classes.
const (
	classUniversal   = 0
	classApplication = 1
	classContext     = 2
	classPrivate     = 3
)

// Universal tag numbers this dissector names.
const (
	tagInteger       = 2
	tagBitString     = 3
	tagOctetString   = 4
	tagNull          = 5
	tagOID           = 6
	tagUTF8String    = 12
	tagSequence      = 16
	tagSet           = 17
	tagVisibleString = 26
)

// Limits on what a BER blob may ask of us.
const (
	// maxLengthOctets caps the long-form length. Four octets already allow a
	// length far beyond MaxPDUSize, so anything longer is a crafted header.
	maxLengthOctets = 4

	// maxTagOctets caps the high-tag-number form. MMS service tags reach 77,
	// which needs one octet; two is already generous.
	maxTagOctets = 2

	// maxDepth caps how deep a walk follows constructed elements. The deepest
	// nesting IEC 61850 reaches in practice is around ten: session, CP-type,
	// PDV list, ACSE, EXTERNAL, MMS PDU, service, access specification, list,
	// specification, name. Twenty leaves room without letting a crafted blob
	// recurse without end.
	maxDepth = 20

	// maxElements caps how many elements one walk visits, so a blob made of
	// thousands of empty elements cannot cost more than reading it.
	maxElements = 512
)

var errBER = errors.New("not valid BER")

// tlv is one BER element. value is a sub-slice of the buffer it came from and
// is never copied.
type tlv struct {
	class       uint8
	number      uint32
	constructed bool
	value       []byte
}

// tag renders the element's tag the way an ASN.1 definition names it, for
// reporting an element the dissector does not know.
func (t tlv) tag() string {
	switch t.class {
	case classUniversal:
		return "univ" + strconv.FormatUint(uint64(t.number), 10)
	case classApplication:
		return "app" + strconv.FormatUint(uint64(t.number), 10)
	case classPrivate:
		return "priv" + strconv.FormatUint(uint64(t.number), 10)
	default:
		return "ctx" + strconv.FormatUint(uint64(t.number), 10)
	}
}

// ctx reports whether this is the context-specific tag n, which is how every
// CHOICE in the MMS and ACSE definitions is encoded.
func (t tlv) ctx(n uint32) bool { return t.class == classContext && t.number == n }

// readTLV decodes the element at the start of b and returns it with whatever
// follows it.
func readTLV(b []byte) (tlv, []byte, error) {
	if len(b) < 2 {
		return tlv{}, nil, fmt.Errorf("%w: %d octets cannot hold a tag and a length", errBER, len(b))
	}
	first := b[0]
	out := tlv{
		class:       first >> 6,
		constructed: first&0x20 != 0,
		number:      uint32(first & 0x1f),
	}
	i := 1
	if out.number == 0x1f {
		// High tag number form: base 128, most significant octet first, each
		// but the last with the top bit set.
		out.number = 0
		for n := 0; ; n++ {
			if i >= len(b) {
				return tlv{}, nil, fmt.Errorf("%w: tag number runs past the end", errBER)
			}
			if n >= maxTagOctets {
				return tlv{}, nil, fmt.Errorf("%w: tag number longer than %d octets", errBER, maxTagOctets)
			}
			out.number = out.number<<7 | uint32(b[i]&0x7f)
			more := b[i]&0x80 != 0
			i++
			if !more {
				break
			}
		}
	}

	if i >= len(b) {
		return tlv{}, nil, fmt.Errorf("%w: no length octet", errBER)
	}
	length := int(b[i])
	i++
	switch {
	case length == 0x80:
		// The indefinite form ends with two zero octets somewhere later.
		// Nothing in IEC 61850 sends it, and honouring it would mean scanning
		// for a terminator a crafted frame can simply omit.
		return tlv{}, nil, fmt.Errorf("%w: indefinite length", errBER)
	case length&0x80 != 0:
		n := length & 0x7f
		if n > maxLengthOctets {
			return tlv{}, nil, fmt.Errorf("%w: length held in %d octets", errBER, n)
		}
		if i+n > len(b) {
			return tlv{}, nil, fmt.Errorf("%w: length octets run past the end", errBER)
		}
		length = 0
		for range n {
			length = length<<8 | int(b[i])
			i++
		}
	}
	if length < 0 || i+length > len(b) {
		return tlv{}, nil, fmt.Errorf("%w: element declares %d octets, %d present",
			errBER, length, len(b)-i)
	}
	out.value = b[i : i+length]
	return out, b[i+length:], nil
}

// readOne decodes exactly one element and requires it to account for the whole
// buffer, which is what every layer here expects of its payload.
func readOne(b []byte) (tlv, error) {
	t, rest, err := readTLV(b)
	if err != nil {
		return tlv{}, err
	}
	if len(rest) > 0 {
		return t, fmt.Errorf("%w: %d octets follow the element", errBER, len(rest))
	}
	return t, nil
}

// budget bounds one walk over a BER tree.
type budget struct {
	elements int
	depth    int
}

func newBudget() *budget { return &budget{elements: maxElements, depth: maxDepth} }

// children decodes the elements inside a constructed element. It reports
// whether it read all of them: a false means the rest were malformed or the
// budget ran out, and the caller must not treat what it got as complete.
func (t tlv) children(b *budget) ([]tlv, bool) {
	if !t.constructed || b.depth <= 0 {
		return nil, false
	}
	var out []tlv
	rest := t.value
	for len(rest) > 0 {
		if b.elements <= 0 {
			return out, false
		}
		b.elements--
		child, next, err := readTLV(rest)
		if err != nil {
			return out, false
		}
		out = append(out, child)
		rest = next
	}
	return out, true
}

// descend returns the children of t with one level of the depth budget spent.
func (t tlv) descend(b *budget) ([]tlv, bool) {
	kids, ok := t.children(b)
	b.depth--
	return kids, ok
}

// find returns the first child carrying the given context tag.
func (t tlv) find(b *budget, number uint32) (tlv, bool) {
	kids, _ := t.children(b)
	for _, k := range kids {
		if k.ctx(number) {
			return k, true
		}
	}
	return tlv{}, false
}

// integer reads an element's value as a signed integer. BER integers are
// arbitrary width; anything wider than eight octets is reported as not
// readable rather than silently truncated.
func (t tlv) integer() (int64, bool) {
	if len(t.value) == 0 || len(t.value) > 8 {
		return 0, false
	}
	v := int64(0)
	if t.value[0]&0x80 != 0 {
		v = -1 // sign extend
	}
	for _, b := range t.value {
		v = v<<8 | int64(b)
	}
	return v, true
}

// text reads an element's value as a printable string. MMS identifiers are
// VisibleString, so anything outside printable ASCII means this is not the
// field the layout said it was — or that someone is trying to get control
// characters or markup into a report.
func (t tlv) text() (string, bool) {
	if len(t.value) == 0 || len(t.value) > maxNameLen {
		return "", false
	}
	for _, c := range t.value {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return string(t.value), true
}

// oid renders an object identifier in dotted form. Object identifiers are how
// ACSE names the application context and the two application entities, which
// is the only addressing the association layer carries.
func (t tlv) oid() (string, bool) {
	if len(t.value) == 0 || len(t.value) > maxOIDLen {
		return "", false
	}
	first := t.value[0]
	arc1, arc2 := first/40, first%40
	if arc1 > 2 {
		arc1, arc2 = 2, first-80
	}
	parts := []string{strconv.FormatUint(uint64(arc1), 10), strconv.FormatUint(uint64(arc2), 10)}
	acc, started := uint64(0), false
	for _, b := range t.value[1:] {
		if acc > 1<<56 {
			return "", false
		}
		acc = acc<<7 | uint64(b&0x7f)
		started = true
		if b&0x80 == 0 {
			parts = append(parts, strconv.FormatUint(acc, 10))
			acc, started = 0, false
		}
	}
	if started {
		// A final octet with the continuation bit set is a truncated arc.
		return "", false
	}
	return strings.Join(parts, "."), true
}
