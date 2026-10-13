package goose_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/goose"
	"github.com/rom/otinv/internal/model"
)

// seedCorpus holds frames taken verbatim from testdata/pcaps, plus the shapes
// the captures do not contain: the simulated bit, a data set whose count does
// not match its contents, and the BER forms this reader refuses.
var seedCorpus = []string{
	frameInterlockingChange,
	frameInterlockingNext,
	frameInterlockingRepeat,
	frameGERelay,
	frameGERelayReplay,
	frameMinimal,
	// A frame marked as coming from a test set.
	"3001001a80000000610e8004744573748503000001860100",
	// A data set that declares more entries than it carries.
	"3001001d00000000611180047465737485030000018601008a0309",
	// An APDU with no fields at all.
	"3001000a0000000061 00",
	// The forms the BER reader refuses.
	"3001000a000000006180",
	"3001000e000000006185010000000000",
	"3001000d000000006103bfffff",
	// A length that counts less than the frame, which Ethernet padding does.
	"3001000c00000000610180047465737485030000018601 00",
	// A floating point value and a visible string in the data set.
	"3001001f0000000061138004746573748503000001860100ab0887053f80000000",
	"3001001e0000000061128004746573748503000001860100ab078a0568656c6c6f",
}

// FuzzParse checks the invariants that hold for any byte sequence: no panic,
// errors always wrap ErrMalformed, exactly one event per frame, and nothing
// taken off the wire reaching an attribute unchecked.
//
// Each input gets a fresh context, because the dissector tracks the counters
// of each control block it has seen on a flow.
func FuzzParse(f *testing.F) {
	for _, s := range seedCorpus {
		b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
		if err != nil {
			f.Fatalf("bad seed %q: %v", s, err)
		}
		f.Add(b)
	}

	d := goose.New()
	f.Fuzz(func(t *testing.T, payload []byte) {
		ctx := &dissect.FlowContext{
			Flow: model.Flow{
				SrcMAC:    "0a:bb:fe:10:c9:02",
				DstMAC:    "01:0c:cd:01:00:00",
				Transport: model.TransportEthernet,
			},
			Direction: model.DirUnknown,
		}

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
		if e.Protocol != "goose" {
			t.Fatalf("unexpected protocol %q", e.Protocol)
		}
		if e.Operation == "" {
			t.Fatalf("event without an operation name")
		}
		if e.FunctionCode != -1 {
			t.Fatalf("GOOSE has no function codes, got %d", e.FunctionCode)
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
			if strings.ContainsAny(v, "\x00\n\r") {
				t.Fatalf("identity %q carries control characters: %q", k, v)
			}
		}

		if c := d.Probe(ctx, payload); c < 0 || c > 100 {
			t.Fatalf("Probe returned %d, outside 0..100", c)
		}
	})
}

// A publisher that names a new control block on every frame must not be able
// to grow the state this dissector keeps without bound.
func FuzzControlBlockTracking(f *testing.F) {
	f.Add([]byte("LD/LLN0$GO$gcb"), uint32(1))

	d := goose.New()
	ctx := &dissect.FlowContext{
		Flow: model.Flow{
			SrcMAC: "0a:bb:fe:10:c9:02", DstMAC: "01:0c:cd:01:00:00",
			Transport: model.TransportEthernet,
		},
	}
	f.Fuzz(func(t *testing.T, ref []byte, state uint32) {
		if len(ref) > 100 {
			return
		}
		body := "80" + hex.EncodeToString([]byte{byte(len(ref))}) + hex.EncodeToString(ref) +
			"8504" + hex.EncodeToString([]byte{
			byte(state >> 24), byte(state >> 16), byte(state >> 8), byte(state),
		}) + "860100"
		pdu := "61" + hex.EncodeToString([]byte{byte(len(body) / 2)}) + body
		raw, err := hex.DecodeString("3001" +
			hex.EncodeToString([]byte{byte((8 + len(pdu)/2) >> 8), byte(8 + len(pdu)/2)}) +
			"00000000" + pdu)
		if err != nil {
			t.Fatalf("building the frame: %v", err)
		}
		if _, err := d.Parse(ctx, raw); err != nil && !errors.Is(err, dissect.ErrMalformed) {
			t.Fatalf("Parse error must wrap ErrMalformed, got %v", err)
		}
	})
}
