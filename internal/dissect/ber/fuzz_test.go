package ber_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/rom/otinv/internal/dissect/ber"
)

// FuzzRead checks the invariants every caller of this reader relies on: no
// panic on any byte sequence, an error that always says it is a BER error, a
// value that is always a slice of the input, and a walk that always stops.
//
// The dissectors that read MMS and GOOSE trust this with bytes straight off
// the wire, so the reader is the one place where getting the bounds wrong
// would cost every protocol at once.
func FuzzRead(f *testing.F) {
	seeds := []string{
		"020105",
		"800348454c",
		"a103020101",
		"6103020101",
		"bf2903020101",
		"bf8e3003020101",
		"0481050102030405",
		"0500",
		"300b800101810102a203020103",
		// An object identifier, a visible string and a long form length.
		"060528ca220203",
		"1a0e41413145315130314650324c4430",
		"3182010002010100",
		// The forms the reader refuses.
		"3080020105 0000",
		"04850100000000",
		"bfffffff020101",
		"0204ff",
		// Nesting, which the depth budget has to stop.
		strings.Repeat("a003", 60) + "020101",
	}
	for _, s := range seeds {
		b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
		if err != nil {
			f.Fatalf("bad seed %q: %v", s, err)
		}
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		tlv, rest, err := ber.ReadTLV(payload)
		if err != nil {
			if !errors.Is(err, ber.ErrBER) {
				t.Fatalf("ReadTLV error must wrap ErrBER, got %v", err)
			}
			return
		}
		if len(tlv.Value)+len(rest) > len(payload) {
			t.Fatalf("value %d and rest %d exceed the %d octet input",
				len(tlv.Value), len(rest), len(payload))
		}
		if tlv.Class > ber.ClassPrivate {
			t.Fatalf("class %d outside 0..3", tlv.Class)
		}
		if tlv.Tag() == "" {
			t.Fatalf("element without a tag name")
		}

		// Every accessor has to tolerate whatever the element turned out to
		// hold, not just the type its tag claims.
		if s, ok := tlv.Text(); ok {
			if len(s) == 0 || len(s) > ber.MaxTextLen {
				t.Fatalf("Text returned %d characters", len(s))
			}
			for _, c := range s {
				if c < 0x20 || c > 0x7e {
					t.Fatalf("Text returned %q, which is not printable ASCII", s)
				}
			}
		}
		if s, ok := tlv.OID(); ok && !strings.ContainsRune(s, '.') {
			t.Fatalf("OID returned %q, which names no arc", s)
		}
		tlv.Integer()

		// The walk must stop, and must never report a complete read of
		// children it could not read.
		bud := ber.NewBudget()
		visited := 0
		var walk func(ber.TLV)
		walk = func(node ber.TLV) {
			kids, _ := node.Descend(bud)
			for _, k := range kids {
				visited++
				if visited > ber.MaxElements {
					t.Fatalf("walk visited more than %d elements", ber.MaxElements)
				}
				walk(k)
			}
		}
		walk(tlv)
	})
}
