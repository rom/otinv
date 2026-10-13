package modbus_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/modbus"
	"github.com/rom/otinv/internal/model"
)

// seedCorpus holds ADUs taken verbatim from testdata/pcaps, plus the crafted
// frames in that capture (bogus length, non-zero protocol id, reserved
// function code) and identity replies.
var seedCorpus = []string{
	"0000 0000 0006 0a 08 0004 0000", // Force Listen Only Mode
	"0000 0000 0003 0a 88 0b",        // gateway exception
	"0000 0000 0002 0a 11",           // Report Server ID request
	"0000 0000 0015 0a 11 12 00 ff 57 69 6e 67 70 61 74 68 20 4c 69 6d 69 74 65 64",
	"0001 0000 0006 0a 2b 0e 03 01 00", // Read Device Identification
	"0001 0000 0006 0a 01 0000 0001",   // Read Coils
	"0001 0000 0004 0a 01 01 00",       // Read Coils reply
	"0001 0000 0007 0a 03 04 0009 0018",
	"0001 0000 0006 0a 05 0002 0000",
	"0001 0000 0006 0a 06 0005 000b",
	"0001 0010 0006 0a 01 0001 0003", // non-zero protocol id
	"0001 0000 8804 05 07 0809",      // bogus MBAP length
	"0001 0000 0005 0a 2a 0e 04 01",  // reserved function code
	"0001 0000 001d 0a 2b 0e 01 81 00 00 03 00 08 57 69 6e 67 70 61 74 68 01 04 50 4c 43 31 02 03 31 2e 30",
}

// FuzzParse checks the invariants that hold for any byte sequence: no panic,
// errors always wrap ErrMalformed, and a successful parse yields exactly one
// event with a valid classification.
func FuzzParse(f *testing.F) {
	for _, s := range seedCorpus {
		b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
		if err != nil {
			f.Fatalf("bad seed %q: %v", s, err)
		}
		f.Add(b)
	}

	d := modbus.New()
	f.Fuzz(func(t *testing.T, payload []byte) {
		ctx := &dissect.FlowContext{
			Flow: model.Flow{
				SrcIP: "10.0.0.9", DstIP: "10.0.0.3",
				SrcPort: 3082, DstPort: modbus.DefaultPort,
				Transport: model.TransportTCP,
			},
			Direction: model.DirRequest,
		}

		events, err := d.Parse(ctx, payload)
		if err != nil && !errors.Is(err, dissect.ErrMalformed) {
			t.Fatalf("Parse error must wrap ErrMalformed, got %v", err)
		}
		if err == nil && len(events) != 1 {
			t.Fatalf("a decoded PDU must yield exactly one event, got %d", len(events))
		}
		for _, e := range events {
			if !e.Class.Valid() {
				t.Fatalf("invalid classification %q", e.Class)
			}
			if e.Protocol != "modbus" {
				t.Fatalf("unexpected protocol %q", e.Protocol)
			}
			if err == nil && (e.FunctionCode < 1 || e.FunctionCode > 127) {
				t.Fatalf("function code %d outside 1..127", e.FunctionCode)
			}
			if e.Operation == "" {
				t.Fatalf("event without an operation name")
			}
		}

		// Framing must never claim bytes it cannot justify.
		if n, ferr := d.PDULen(payload); ferr == nil {
			if n <= 0 || n > len(payload) {
				t.Fatalf("PDULen returned %d for a %d byte buffer", n, len(payload))
			}
		} else if !errors.Is(ferr, dissect.ErrNeedMore) && !errors.Is(ferr, dissect.ErrMalformed) {
			t.Fatalf("PDULen error must wrap ErrNeedMore or ErrMalformed, got %v", ferr)
		}

		// Probe must stay in range and never panic.
		if c := d.Probe(ctx, payload); c < 0 || c > 100 {
			t.Fatalf("Probe returned %d, outside 0..100", c)
		}
	})
}
