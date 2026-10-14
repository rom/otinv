package opcua_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/opcua"
	"github.com/rom/otinv/internal/model"
)

// seedCorpus holds messages taken verbatim from testdata/pcaps, plus the
// shapes the capture does not contain: a reverse hello, a chunked message, an
// abort, and bodies whose lengths lie.
var seedCorpus = []string{
	msgHello, msgAcknowledge, msgOpenChannel, msgGetEndpoints, msgActivateSession,
	msgTransportError,

	// A reverse hello, which is a server connecting outward.
	"52484546200000000500000073727669000000 0a0000006f70632e7463703a2f2f78",
	// A read, a write and a call.
	"4d5347463d000000010000000100000001000000010000000100770200000000000000000000000000" +
		"00000000ffffffff00000000000000",
	// An intermediate chunk and a continuation.
	"4d53474318000000010000000100000001000000010000000100770200",
	"4d534746140000000100000001000000020000000100000 0deadbeef",
	// An abort.
	"4d5347411800000001000000010000000100000001000000000085 80ffffffff",
	// A string node id whose length is absurd, which is what the sample
	// capture's method call does.
	"4d5347462000000001000000010000000100000001000000 0100c80203ff7f00000400",
	// A message whose size field is larger than the segment.
	"4d534746ff00000001000000010000000100000001000000",
	// A nested diagnostic info, which a crafted response could nest without
	// end.
	"4d53474628000000010000000100000001000000010000000100aa02" +
		"000000000000000000000000404040ffffffff000000",
}

// FuzzParse checks the invariants that hold for any byte sequence: no panic,
// errors always wrap ErrMalformed, exactly one event per message, and nothing
// taken off the wire reaching an attribute or an identity unchecked.
//
// Each input gets a fresh context, because the dissector remembers whether
// this direction of the stream is in the middle of a chunked message.
func FuzzParse(f *testing.F) {
	for _, s := range seedCorpus {
		b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
		if err != nil {
			f.Fatalf("bad seed %q: %v", s, err)
		}
		f.Add(b)
	}

	d := opcua.New()
	f.Fuzz(func(t *testing.T, payload []byte) {
		ctx := ctxFor(model.DirRequest)
		events, err := d.Parse(ctx, payload)
		if err != nil && !errors.Is(err, dissect.ErrMalformed) {
			t.Fatalf("Parse error must wrap ErrMalformed, got %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("one message must yield one event, got %d", len(events))
		}
		e := events[0]
		if !e.Class.Valid() {
			t.Fatalf("invalid classification %q", e.Class)
		}
		if e.Protocol != "opcua" {
			t.Fatalf("unexpected protocol %q", e.Protocol)
		}
		if e.Operation == "" {
			t.Fatal("event without an operation name")
		}
		if e.Malformed == (e.Error == "") {
			t.Fatalf("malformed=%v with error %q", e.Malformed, e.Error)
		}
		for k, v := range e.Attrs {
			if len(v) > 4096 {
				t.Fatalf("attribute %q is %d octets long", k, len(v))
			}
			if strings.ContainsAny(v, "\x00\n\r") {
				t.Fatalf("attribute %q carries control characters: %q", k, v)
			}
		}
		for k, v := range e.Identity {
			if len(v) > 512 {
				t.Fatalf("identity %q is %d octets long", k, len(v))
			}
			if strings.ContainsAny(v, "\x00\n\r") {
				t.Fatalf("identity %q carries control characters: %q", k, v)
			}
		}
		if c := d.Probe(ctx, payload); c < 0 || c > 100 {
			t.Fatalf("Probe returned %d, outside 0..100", c)
		}
	})
}

// FuzzPDULen checks the framer: it must never claim a length it cannot
// justify from the buffer, and never more than a stream may buffer.
func FuzzPDULen(f *testing.F) {
	for _, s := range seedCorpus {
		b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
		if err != nil {
			f.Fatalf("bad seed %q: %v", s, err)
		}
		f.Add(b)
	}

	d := opcua.New()
	f.Fuzz(func(t *testing.T, buf []byte) {
		n, err := d.PDULen(buf)
		switch {
		case err == nil:
			if n <= 0 || n > len(buf) || n > dissect.MaxPDUSize {
				t.Fatalf("PDULen returned %d for a %d octet buffer", n, len(buf))
			}
		case errors.Is(err, dissect.ErrNeedMore), errors.Is(err, dissect.ErrMalformed):
		default:
			t.Fatalf("PDULen error must wrap ErrNeedMore or ErrMalformed, got %v", err)
		}
	})
}
