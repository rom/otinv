package s7comm_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/s7comm"
	"github.com/rom/otinv/internal/model"
)

// seedCorpus holds frames taken verbatim from testdata/pcaps, plus shapes the
// captures do not contain: a CPU stop, an empty keep-alive and an S7comm-plus
// payload.
var seedCorpus = []string{
	frameConnectRequest,
	frameConnectConfirm,
	frameSetupComm,
	frameSetupCommAck,
	frameReadVar,
	frameReadVarAck,
	frameWriteVar,
	frameWriteVarAck,
	frameRequestDownload,
	frameDownloadBlock,
	frameDownloadEnded,
	framePLCControlInsert,
	frameReadSZLRequest,
	frameReadSZLModule,
	frameReadSZLComponent,
	// An empty COTP data frame, which STEP 7 uses as a keep-alive.
	"0300000702f000",
	// S7comm-plus, which shares the port but is a different protocol.
	"0300001b02f08072030000ffff000800000000f0000001000100f0",
	// An item specification whose declared length runs past the frame.
	"0300001f02f080320100000000000e00000401127f10020040000184000000",
	// An SZL reply claiming more records than it carries.
	"0300002102f080320700001100000c0008000112081284010200000000ff09000400110000ffff",
}

// FuzzParse checks the invariants that hold for any byte sequence: no panic,
// errors always wrap ErrMalformed, and any event carries a name and a valid
// classification.
//
// Each input gets a fresh context, since the dissector keeps per-stream state
// for reporting an unreadable payload once.
func FuzzParse(f *testing.F) {
	for _, s := range seedCorpus {
		b, err := hex.DecodeString(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "\n", ""))
		if err != nil {
			f.Fatalf("bad seed %q: %v", s, err)
		}
		f.Add(b)
	}

	d := s7comm.New()
	f.Fuzz(func(t *testing.T, payload []byte) {
		ctx := &dissect.FlowContext{
			Flow: model.Flow{
				SrcIP: "192.168.1.10", DstIP: "192.168.1.40",
				SrcPort: 4258, DstPort: s7comm.DefaultPort,
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
			if e.Protocol != "s7comm" {
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
		// Deferring shares the framing walk with Probe, so it has to tolerate
		// the same inputs.
		d.ProbeDefers(payload)
	})
}
