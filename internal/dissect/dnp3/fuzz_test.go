package dnp3_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/dnp3"
	"github.com/rom/otinv/internal/model"
)

// seedCorpus holds frames taken verbatim from testdata/pcaps, including the
// crafted ones in those captures: a corrupted start octet and a read of an
// object group that does not exist.
var seedCorpus = []string{
	frameColdRestart,
	frameWriteTime,
	frameDisableUnsolicited,
	frameResponseTimeDelay,
	frameSelectCROB,
	frameSelectReject,
	frameReadUnknownGroup,
	frameResetLink,
	frameBadStart,
	// A fragment split by the transport function, first frame only.
	"05640e4403000400a5f045c1810000 1e020000 0129",
	// An object header whose count is larger than the frame can hold.
	"05640bc404000300e42bd701011effff07fb",
}

// FuzzParse checks the invariants that hold for any byte sequence: no panic,
// errors always wrap ErrMalformed, and a decoded fragment yields one event
// with a valid classification.
//
// Parse keeps reassembly state on the context, so each input gets a fresh one:
// a fuzzer must not have last iteration's half fragment decide this one.
func FuzzParse(f *testing.F) {
	for _, s := range seedCorpus {
		b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
		if err != nil {
			f.Fatalf("bad seed %q: %v", s, err)
		}
		f.Add(b)
	}

	d := dnp3.New()
	f.Fuzz(func(t *testing.T, payload []byte) {
		ctx := &dissect.FlowContext{
			Flow: model.Flow{
				SrcIP: "10.0.0.8", DstIP: "10.0.0.3",
				SrcPort: 2828, DstPort: dnp3.DefaultPort,
				Transport: model.TransportTCP,
			},
			Direction: model.DirRequest,
		}

		events, err := d.Parse(ctx, payload)
		if err != nil && !errors.Is(err, dissect.ErrMalformed) {
			t.Fatalf("Parse error must wrap ErrMalformed, got %v", err)
		}
		if len(events) > 1 {
			t.Fatalf("one frame must not yield %d events", len(events))
		}
		for _, e := range events {
			if !e.Class.Valid() {
				t.Fatalf("invalid classification %q", e.Class)
			}
			if e.Protocol != "dnp3" {
				t.Fatalf("unexpected protocol %q", e.Protocol)
			}
			if e.Operation == "" {
				t.Fatalf("event without an operation name")
			}
			if e.FunctionCode < -1 || e.FunctionCode > 255 {
				t.Fatalf("function code %d outside -1..255", e.FunctionCode)
			}
		}

		if n, ferr := d.PDULen(payload); ferr == nil {
			if n <= 0 || n > len(payload) {
				t.Fatalf("PDULen returned %d for a %d octet buffer", n, len(payload))
			}
		} else if !errors.Is(ferr, dissect.ErrNeedMore) && !errors.Is(ferr, dissect.ErrMalformed) {
			t.Fatalf("PDULen error must wrap ErrNeedMore or ErrMalformed, got %v", ferr)
		}

		if c := d.Probe(ctx, payload); c < 0 || c > 100 {
			t.Fatalf("Probe returned %d, outside 0..100", c)
		}
	})
}

// A fragment arriving across many frames must not let the dissector
// accumulate without bound, however the frames are ordered.
func FuzzTransportReassembly(f *testing.F) {
	f.Add([]byte{0x45, 0x01, 0x02}, []byte{0x86, 0x03})
	f.Add([]byte{0xc1, 0x81, 0x00}, []byte{0xc1, 0x01})

	d := dnp3.New()
	f.Fuzz(func(t *testing.T, first, second []byte) {
		ctx := &dissect.FlowContext{
			Flow:      model.Flow{SrcIP: "10.0.0.3", DstIP: "10.0.0.8", Transport: model.TransportTCP},
			Direction: model.DirResponse,
		}
		for _, body := range [][]byte{first, second} {
			if len(body) == 0 || len(body) > 250 {
				continue
			}
			frame := buildFuzzFrame(body)
			events, err := d.Parse(ctx, frame)
			if err != nil && !errors.Is(err, dissect.ErrMalformed) {
				t.Fatalf("Parse error must wrap ErrMalformed, got %v", err)
			}
			for _, e := range events {
				if !e.Class.Valid() {
					t.Fatalf("invalid classification %q", e.Class)
				}
			}
		}
	})
}

// buildFuzzFrame wraps a body in a link frame with correct CRCs, so that the
// fuzzer exercises the transport and application layers rather than stopping
// at the frame check.
func buildFuzzFrame(body []byte) []byte {
	header := []byte{0x05, 0x64, byte(len(body) + 5), 0x44, 0x03, 0x00, 0x04, 0x00}
	out := append([]byte{}, header...)
	crc := dnp3.CRC(header)
	out = append(out, byte(crc), byte(crc>>8))
	for len(body) > 0 {
		n := min(16, len(body))
		out = append(out, body[:n]...)
		c := dnp3.CRC(body[:n])
		out = append(out, byte(c), byte(c>>8))
		body = body[n:]
	}
	return out
}
