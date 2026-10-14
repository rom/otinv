package profinet_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/profinet"
)

// seedCorpus holds frames taken verbatim from testdata/pcaps, plus the shapes
// the captures do not contain: the other three services, a refusal, a factory
// reset, and blocks whose lengths lie.
var seedCorpus = []string{
	frameIdentifyAll,
	frameIdentifyReply,
	frameSetIP,
	frameSetIPReply,
	frameCraftedName,
	frameIdentifyByName,
	// Get, its answer, and a station announcing itself.
	"fefd0300000000020000000c020200000203000001040000",
	"fefd030100000002000000140202000800 00706c632d30310204000400000200",
	"fefc060000000003000000140202000800 00706c632d30320204000400000200",
	// A factory reset and an LED signal.
	"fefd040000000004000000080505000400010000",
	"fefd04000000000500000008050300040001 0000",
	// A station refusing a Set.
	"fefd0401000000060000000805040003020206 00",
	// A block that declares more than the PDU holds, and a data length that
	// declares more than the frame holds.
	"fefd03000000000200000008" + "0202ff0000000000",
	"fefe050001000001000100ff0102",
	// A name of station of nothing but NULs, and one of the maximum length.
	"feff0501000000020000000c0202000800000000000000 00",
	"fefd04000000000200000008" + "0202ffff",
	// An alarm and a cyclic frame, which this dissector must not claim.
	"fc01010203040506070800000035",
	"8000010203040506070800000035",
}

// FuzzParse checks the invariants that hold for any byte sequence: no panic,
// errors always wrap ErrMalformed, exactly one event per frame, and nothing
// taken off the wire reaching an attribute or an identity unchecked.
func FuzzParse(f *testing.F) {
	for _, s := range seedCorpus {
		b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
		if err != nil {
			f.Fatalf("bad seed %q: %v", s, err)
		}
		f.Add(b)
	}

	d := profinet.New()
	f.Fuzz(func(t *testing.T, payload []byte) {
		ctx := ctxFor()
		events, err := d.Parse(ctx, payload)
		if err != nil && !errors.Is(err, dissect.ErrMalformed) {
			t.Fatalf("Parse error must wrap ErrMalformed, got %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("one frame must yield one event, got %d", len(events))
		}
		e := events[0]
		if !e.Class.Valid() {
			t.Fatalf("invalid classification %q", e.Class)
		}
		if e.Protocol != "profinet_dcp" {
			t.Fatalf("unexpected protocol %q", e.Protocol)
		}
		if e.Operation == "" {
			t.Fatal("event without an operation name")
		}
		if e.Malformed == (e.Error == "") {
			t.Fatalf("malformed=%v with error %q", e.Malformed, e.Error)
		}
		for k, v := range e.Attrs {
			if len(v) > 1024 {
				t.Fatalf("attribute %q is %d octets long", k, len(v))
			}
			if strings.ContainsAny(v, "\x00\n\r") {
				t.Fatalf("attribute %q carries control characters: %q", k, v)
			}
		}
		for k, v := range e.Identity {
			if len(v) > 256 {
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
