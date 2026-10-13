package iec104_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/iec104"
	"github.com/rom/otinv/internal/model"
)

// seedCorpus holds APDUs taken verbatim from testdata/pcaps, plus shapes the
// captures do not contain: the types with a variable or undefined element
// layout, a global address, a frame whose count overruns its own octets and
// the file transfer family.
var seedCorpus = []string{
	apduStartDTAct,
	apduStartDTCon,
	apduTestFRAct,
	apduTestFRCon,
	apduSupervisory,
	apduEndOfInit,
	apduInterrogationAct,
	apduInterrogationCon,
	apduInterrogationEnd,
	apduSinglePointSeq,
	apduDoublePointSeq,
	apduSingleCommandSelect,
	apduSingleCommandCon,
	apduSingleCommandNegCon,
	apduSingleCommandNegAct,
	apduDoubleCommandSelect,
	apduDoubleCommandNegCon,
	apduClockSync,
	apduSinglePointTime,
	apduSetPointFloatSelect,
	apduSetPointFloatEnd,
	apduSetPointFloatTime,
	apduSetPointNormTime,
	apduSingleCommandTime,
	apduDoubleCommandExec,
	apduMeasuredFloats,
	apduSinglePointList,
	apduMeasuredFloatSpont,
	// A STOPDT, which the captures never send.
	"680413000000",
	// An interrogation addressed to every station on the link.
	"680e0000020064010600ffff00000014",
	// A counter interrogation and a reset of the process.
	"680e0000020065010600030000000005",
	"680e0000020069010600030000000001",
	// A file segment, whose element declares its own length.
	"6811000002007d010d000300010000000103616263",
	// A reserved type identification, whose element layout is unknown.
	"680e000002005a0106000d9100000014",
	// A sequence claiming nine elements with four octets present.
	"680e04000200018914000d911a2700d0",
	// The maximum object count with nothing behind it.
	"680a000002000dff010003002a",
	// A binary counter reading and a step position, neither in the captures.
	"6813000002000f0101000300010000002a00000081",
	"6810000002000501010003000100000340",
}

// FuzzParse checks the invariants that hold for any byte sequence: no panic,
// errors always wrap ErrMalformed, and any event carries a name and a valid
// classification.
//
// Each input gets a fresh context, since the dissector keeps the send sequence
// number it expects next per stream.
func FuzzParse(f *testing.F) {
	for _, s := range seedCorpus {
		b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
		if err != nil {
			f.Fatalf("bad seed %q: %v", s, err)
		}
		f.Add(b)
	}

	d := iec104.New()
	f.Fuzz(func(t *testing.T, payload []byte) {
		ctx := &dissect.FlowContext{
			Flow: model.Flow{
				SrcIP: "172.27.248.109", DstIP: "172.27.248.79",
				SrcPort: 1578, DstPort: iec104.DefaultPort,
				Transport: model.TransportTCP,
			},
			Direction: model.DirRequest,
		}

		events, err := d.Parse(ctx, payload)
		if err != nil && !errors.Is(err, dissect.ErrMalformed) {
			t.Fatalf("Parse error must wrap ErrMalformed, got %v", err)
		}
		if len(events) > 1 {
			t.Fatalf("one APDU must not yield %d events", len(events))
		}
		for _, e := range events {
			if !e.Class.Valid() {
				t.Fatalf("invalid classification %q", e.Class)
			}
			if e.Protocol != "iec104" {
				t.Fatalf("unexpected protocol %q", e.Protocol)
			}
			if e.Operation == "" {
				t.Fatalf("event without an operation name")
			}
			if e.FunctionCode < -1 || e.FunctionCode > 255 {
				t.Fatalf("function code %d outside -1..255", e.FunctionCode)
			}
			if e.Malformed == (e.Error == "") {
				t.Fatalf("malformed=%v with error %q", e.Malformed, e.Error)
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
