package mms_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/mms"
	"github.com/rom/otinv/internal/model"
)

// seedCorpus holds frames taken verbatim from testdata/pcaps, plus the shapes
// the captures do not contain: the BER forms this dissector refuses, a PDU
// whose declared length overruns its own frame, and an authentication value.
var seedCorpus = []string{
	frameConnectRequest,
	frameConnectConfirm,
	frameAssociateRequest,
	frameAssociateResponse,
	frameIdentifyRequest,
	frameIdentifyResponse,
	frameStatusRequest,
	frameInformationReport,
	frameGetVariableAccessAttributes,
	frameAccessDenied,
	frameRead,
	frameWrite,
	frameConcludeRequest,
	frameReleaseRequest,
	frameReleaseResponse,
	frameOffSpecAccept,
	frameTruncatedResponse,
	frameRawInitiate,
	frameRawStop,
	frameRawStart,
	frameRawTakeControl,
	frameRawDownload,
	frameRawConclude,
	frameBrokenServerReply,
	// An empty COTP data PDU, which a stack sends as a keep-alive.
	"0300000702f080",
	// An indefinite length, which BER allows and this dissector refuses.
	"0300000902f080a080",
	// A long form length held in more octets than any PDU could need.
	"0300000d02f080a0850100000000",
	// A high tag number running on without end.
	"0300000c02f080bfffffff020101",
	// A session PDU whose parameter field overruns the frame.
	"0300000b02f0800dff0506130100",
	// A presentation PDU with no data values in it.
	"0300000b02f080010001006100",
	// An MMS confirmed request with a service tag the standard leaves open.
	"0300001002f080a008020101bf7f020100",
}

// FuzzParse checks the invariants that hold for any byte sequence: no panic,
// errors always wrap ErrMalformed, and any event carries a name and a valid
// classification.
//
// It also holds the dissector to its own promise about secrets. An ACSE
// authentication value is a password sent in the clear, and no input may get
// one into an event, so no attribute may ever carry the bytes that follow an
// authentication value tag.
func FuzzParse(f *testing.F) {
	for _, s := range seedCorpus {
		b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
		if err != nil {
			f.Fatalf("bad seed %q: %v", s, err)
		}
		f.Add(b)
	}

	d := mms.New()
	f.Fuzz(func(t *testing.T, payload []byte) {
		ctx := &dissect.FlowContext{
			Flow: model.Flow{
				SrcIP: "172.16.0.101", DstIP: "172.16.202.5",
				SrcPort: 1345, DstPort: mms.DefaultPort,
				Transport: model.TransportTCP,
			},
			Direction: model.DirRequest,
		}

		events, err := d.Parse(ctx, payload)
		if err != nil && !errors.Is(err, dissect.ErrMalformed) {
			t.Fatalf("Parse error must wrap ErrMalformed, got %v", err)
		}
		if len(events) > 4 {
			t.Fatalf("one frame must not yield %d events", len(events))
		}
		for _, e := range events {
			if !e.Class.Valid() {
				t.Fatalf("invalid classification %q", e.Class)
			}
			if e.Protocol != "mms" {
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
		d.ProbeDefers(payload)
	})
}
