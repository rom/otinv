// Package ber is a minimal ASN.1 BER reader for the dissectors whose
// protocols are encoded in it.
//
// IEC 61850 needs it twice over: MMS carries its PDUs inside a presentation
// PDU inside a session PDU, all BER, and GOOSE publishes a BER encoded APDU
// straight on Ethernet. Sampled Values and ICCP will want the same reader.
// One reader with one set of tests and one fuzz corpus is a smaller place for
// a bug to hide than a copy per protocol, and a dissector that keeps its own
// decoding on top of it stays as independent of the others as before.
//
// None of it may be trusted. Every length is checked against what is actually
// present before it is used, the forms that have no end in sight are refused
// outright, and every walk carries a depth and element budget so that a
// crafted blob cannot turn into unbounded recursion or work.
package ber

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// BER tag classes.
const (
	ClassUniversal   = 0
	ClassApplication = 1
	ClassContext     = 2
	ClassPrivate     = 3
)

// Universal tag numbers worth naming.
const (
	TagInteger       = 2
	TagBitString     = 3
	TagOctetString   = 4
	TagNull          = 5
	TagOID           = 6
	TagUTF8String    = 12
	TagSequence      = 16
	TagSet           = 17
	TagVisibleString = 26
)

// Limits on what a BER blob may ask of us.
const (
	// maxLengthOctets caps the long-form length. Four octets already allow a
	// length far beyond any PDU a dissector will be handed, so anything
	// longer is a crafted header.
	maxLengthOctets = 4

	// maxTagOctets caps the high-tag-number form. MMS service tags reach 77,
	// which needs one octet; two is already generous.
	maxTagOctets = 2

	// MaxDepth caps how deep a walk follows constructed elements. The deepest
	// nesting IEC 61850 reaches in practice is around ten: session, CP-type,
	// PDV list, ACSE, EXTERNAL, MMS PDU, service, access specification, list,
	// specification, name. Twenty leaves room without letting a crafted blob
	// recurse without end.
	MaxDepth = 20

	// MaxElements caps how many elements one walk visits, so a blob made of
	// thousands of empty elements cannot cost more than reading it.
	MaxElements = 512

	// MaxTextLen caps a string read off the wire. An MMS Identifier may be 32
	// octets by the standard and IEC 61850 object references run longer; 128
	// covers the longest reference a substation configuration produces
	// without letting a crafted frame put a kilobyte of text into an event.
	MaxTextLen = 128

	// maxOIDLen caps an object identifier's encoded length.
	maxOIDLen = 32
)

// ErrBER is what every error from this package wraps, so that a dissector
// can tell a decoding failure from one of its own.
var ErrBER = errors.New("not valid BER")

// TLV is one BER element. Its value is a sub-slice of the buffer it came from
// and is never copied.
type TLV struct {
	Class       uint8
	Number      uint32
	Constructed bool
	Value       []byte
}

// Tag renders the element's tag the way an ASN.1 definition names it, for
// reporting an element a dissector does not know.
func (t TLV) Tag() string {
	switch t.Class {
	case ClassUniversal:
		return "univ" + strconv.FormatUint(uint64(t.Number), 10)
	case ClassApplication:
		return "app" + strconv.FormatUint(uint64(t.Number), 10)
	case ClassPrivate:
		return "priv" + strconv.FormatUint(uint64(t.Number), 10)
	default:
		return "ctx" + strconv.FormatUint(uint64(t.Number), 10)
	}
}

// Ctx reports whether this is the context-specific tag n, which is how every
// CHOICE in the MMS, ACSE and GOOSE definitions is encoded.
func (t TLV) Ctx(n uint32) bool { return t.Class == ClassContext && t.Number == n }

// ReadTLV decodes the element at the start of b and returns it with whatever
// follows it.
func ReadTLV(b []byte) (TLV, []byte, error) {
	if len(b) < 2 {
		return TLV{}, nil, fmt.Errorf("%w: %d octets cannot hold a Tag and a length", ErrBER, len(b))
	}
	first := b[0]
	out := TLV{
		Class:       first >> 6,
		Constructed: first&0x20 != 0,
		Number:      uint32(first & 0x1f),
	}
	i := 1
	if out.Number == 0x1f {
		// High tag number form: base 128, most significant octet first, each
		// but the last with the top bit set.
		out.Number = 0
		for n := 0; ; n++ {
			if i >= len(b) {
				return TLV{}, nil, fmt.Errorf("%w: tag number runs past the end", ErrBER)
			}
			if n >= maxTagOctets {
				return TLV{}, nil, fmt.Errorf("%w: tag number longer than %d octets", ErrBER, maxTagOctets)
			}
			out.Number = out.Number<<7 | uint32(b[i]&0x7f)
			more := b[i]&0x80 != 0
			i++
			if !more {
				break
			}
		}
	}

	if i >= len(b) {
		return TLV{}, nil, fmt.Errorf("%w: no length octet", ErrBER)
	}
	length := int(b[i])
	i++
	switch {
	case length == 0x80:
		// The indefinite form ends with two zero octets somewhere later.
		// Nothing in IEC 61850 sends it, and honouring it would mean scanning
		// for a terminator a crafted frame can simply omit.
		return TLV{}, nil, fmt.Errorf("%w: indefinite length", ErrBER)
	case length&0x80 != 0:
		n := length & 0x7f
		if n > maxLengthOctets {
			return TLV{}, nil, fmt.Errorf("%w: length held in %d octets", ErrBER, n)
		}
		if i+n > len(b) {
			return TLV{}, nil, fmt.Errorf("%w: length octets run past the end", ErrBER)
		}
		length = 0
		for range n {
			length = length<<8 | int(b[i])
			i++
		}
	}
	if length < 0 || i+length > len(b) {
		return TLV{}, nil, fmt.Errorf("%w: element declares %d octets, %d present",
			ErrBER, length, len(b)-i)
	}
	out.Value = b[i : i+length]
	return out, b[i+length:], nil
}

// ReadOne decodes exactly one element and requires it to account for the whole
// buffer, which is what every layer that uses this expects of its payload.
func ReadOne(b []byte) (TLV, error) {
	t, rest, err := ReadTLV(b)
	if err != nil {
		return TLV{}, err
	}
	if len(rest) > 0 {
		return t, fmt.Errorf("%w: %d octets follow the element", ErrBER, len(rest))
	}
	return t, nil
}

// Budget bounds one walk over a BER tree.
type Budget struct {
	elements int
	depth    int
}

// NewBudget returns a budget for one walk, with the package's limits.
func NewBudget() *Budget { return &Budget{elements: MaxElements, depth: MaxDepth} }

// Children decodes the elements inside a constructed element. It reports
// whether it read all of them: a false means the rest were malformed or the
// budget ran out, and the caller must not treat what it got as complete.
func (t TLV) Children(b *Budget) ([]TLV, bool) {
	if !t.Constructed || b.depth <= 0 {
		return nil, false
	}
	var out []TLV
	rest := t.Value
	for len(rest) > 0 {
		if b.elements <= 0 {
			return out, false
		}
		b.elements--
		child, next, err := ReadTLV(rest)
		if err != nil {
			return out, false
		}
		out = append(out, child)
		rest = next
	}
	return out, true
}

// Descend returns the children of t with one level of the depth budget spent.
func (t TLV) Descend(b *Budget) ([]TLV, bool) {
	kids, ok := t.Children(b)
	b.depth--
	return kids, ok
}

// Find returns the first child carrying the given context tag.
func (t TLV) Find(b *Budget, number uint32) (TLV, bool) {
	kids, _ := t.Children(b)
	for _, k := range kids {
		if k.Ctx(number) {
			return k, true
		}
	}
	return TLV{}, false
}

// Integer reads an element's value as a signed integer. BER integers are
// arbitrary width; anything wider than eight octets is reported as not
// readable rather than silently truncated.
func (t TLV) Integer() (int64, bool) {
	if len(t.Value) == 0 || len(t.Value) > 8 {
		return 0, false
	}
	v := int64(0)
	if t.Value[0]&0x80 != 0 {
		v = -1 // sign extend
	}
	for _, b := range t.Value {
		v = v<<8 | int64(b)
	}
	return v, true
}

// Text reads an element's value as a printable string. The identifiers these
// protocols carry are VisibleString, so anything outside printable ASCII means
// this is not the field the layout said it was — or that someone is trying to
// get control characters or markup into a report.
func (t TLV) Text() (string, bool) {
	if len(t.Value) == 0 || len(t.Value) > MaxTextLen {
		return "", false
	}
	for _, c := range t.Value {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return string(t.Value), true
}

// OID renders an object identifier in dotted form. Object identifiers are how
// ACSE names the application context and the two application entities, which
// is the only addressing the association layer carries.
func (t TLV) OID() (string, bool) {
	if len(t.Value) == 0 || len(t.Value) > maxOIDLen {
		return "", false
	}
	// Every subidentifier is a base 128 value, most significant octet first,
	// each but the last with the top bit set. The first one holds two arcs at
	// once: the top arc times forty plus the one below it, which is why an
	// identifier under the third top arc can need more than one octet for
	// what reads as its first two numbers.
	var parts []string
	acc, started := uint64(0), false
	for _, b := range t.Value {
		if acc > 1<<56 {
			return "", false
		}
		acc = acc<<7 | uint64(b&0x7f)
		started = true
		if b&0x80 != 0 {
			continue
		}
		if len(parts) == 0 {
			top := min(acc/40, 2)
			parts = append(parts,
				strconv.FormatUint(top, 10),
				strconv.FormatUint(acc-top*40, 10))
		} else {
			parts = append(parts, strconv.FormatUint(acc, 10))
		}
		acc, started = 0, false
	}
	if started {
		// A final octet with the continuation bit set is a truncated arc.
		return "", false
	}
	return strings.Join(parts, "."), true
}
