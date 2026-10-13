package enip_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/enip"
	"github.com/rom/otinv/internal/model"
)

// seedCorpus holds PDUs taken verbatim from testdata/pcaps, plus the shapes
// the captures do not contain: a refusal, an unknown command, a batch whose
// offsets lie, and the deepest nesting this decoder will follow.
var seedCorpus = []string{
	pduListIdentityRequest,
	pduListIdentityReply,
	pduStart,
	pduStop,
	pduSetAttributeReply,
	pduVendorService,
	pduBatchRequest,
	pduBatchReply,
	pduRoutedIdentityRead,
	pduRoutedIdentityReply,
	pduForwardOpen,
	pduForwardOpenReply,

	// A session the device does not know, answered with the header alone.
	"6f0000000001021264000000000000000000000000000000",
	// RegisterSession and its reply.
	"650004000000000000000000000000000000000000000000010000 00",
	"6500040000010212000000000000000000000000000000000100 0000",
	// A command this dissector does not know.
	"ff000000000102120000000000000000000000000000 0000",
	// An item list that declares more items than it carries.
	"6f0008000001021200000000000000000000000000000000000000000a00",
	// A batch whose offsets point outside it.
	"6f0014000001021200000000000000000000000000000000000000000200000000" +
		"00b2000a000a02200224010200ff00",
	// An Unconnected_Send carrying a Multiple_Service_Packet, which is as
	// deep as the nesting cap allows.
	"6f0026000001021200000000000000000000000000000000000000000200000000" +
		"00b2001c0052022006240107f90c000a0220022401010004000e0220012401" +
		"0100",
	// A cyclic I/O frame.
	"020002800800010000802a0000 00b1000a0004000102030405060708",
	// A ListServices reply.
	"040019000001021200000000000000000000000000000000010000012100" +
		"0100200143 6f6d6d756e69636174696f6e7300",
}

// FuzzParse checks the invariants that hold for any byte sequence: no panic,
// errors always wrap ErrMalformed, a bounded number of well formed events,
// and nothing taken off the wire reaching an attribute unchecked.
func FuzzParse(f *testing.F) {
	for _, s := range seedCorpus {
		b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
		if err != nil {
			f.Fatalf("bad seed %q: %v", s, err)
		}
		f.Add(b)
	}

	d := enip.New()
	f.Fuzz(func(t *testing.T, payload []byte) {
		for _, ctx := range []*dissect.FlowContext{tcpCtx(model.DirRequest), ioCtx()} {
			events, err := d.Parse(ctx, payload)
			if err != nil && !errors.Is(err, dissect.ErrMalformed) {
				t.Fatalf("Parse error must wrap ErrMalformed, got %v", err)
			}
			if len(events) == 0 {
				t.Fatal("Parse returned no events")
			}
			// One PDU carries at most one item list, which is capped, so the
			// event count cannot be driven up by a crafted frame.
			if len(events) > 8 {
				t.Fatalf("one PDU yielded %d events", len(events))
			}
			for _, e := range events {
				if !e.Class.Valid() {
					t.Fatalf("invalid classification %q", e.Class)
				}
				if e.Protocol != "enip" {
					t.Fatalf("unexpected protocol %q", e.Protocol)
				}
				if e.Operation == "" {
					t.Fatal("event without an operation name")
				}
				if e.FunctionCode < -1 {
					t.Fatalf("negative function code %d", e.FunctionCode)
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
					if len(v) > 256 {
						t.Fatalf("identity %q is %d octets long", k, len(v))
					}
					if strings.ContainsAny(v, "\x00\n\r") {
						t.Fatalf("identity %q carries control characters: %q", k, v)
					}
				}
			}

			if c := d.Probe(ctx, payload); c < 0 || c > 100 {
				t.Fatalf("Probe returned %d, outside 0..100", c)
			}
		}
	})
}

// FuzzPDULen checks the framer: it must never claim a length it cannot
// justify from the buffer, never zero with no error, and never more than a
// stream may buffer.
func FuzzPDULen(f *testing.F) {
	for _, s := range seedCorpus {
		b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
		if err != nil {
			f.Fatalf("bad seed %q: %v", s, err)
		}
		f.Add(b)
	}

	d := enip.New()
	f.Fuzz(func(t *testing.T, buf []byte) {
		n, err := d.PDULen(buf)
		switch {
		case err == nil:
			if n <= 0 {
				t.Fatalf("PDULen returned %d with no error", n)
			}
			if n > len(buf) {
				t.Fatalf("PDULen returned %d for a %d octet buffer", n, len(buf))
			}
			if n > dissect.MaxPDUSize {
				t.Fatalf("PDULen returned %d, beyond the %d octet cap", n, dissect.MaxPDUSize)
			}
		case errors.Is(err, dissect.ErrNeedMore), errors.Is(err, dissect.ErrMalformed):
		default:
			t.Fatalf("PDULen error must wrap ErrNeedMore or ErrMalformed, got %v", err)
		}
	})
}
