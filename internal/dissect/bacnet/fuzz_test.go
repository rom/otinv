package bacnet_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/bacnet"
)

// seedCorpus holds datagrams taken verbatim from testdata/pcaps, plus the
// shapes the captures do not contain: the discovery and control services, a
// forwarded broadcast, a router message, and tags whose lengths lie.
var seedCorpus = []string{
	dgReadVendorName, dgVendorNameReply, dgFirmwareReply, dgModelReply,
	dgReadBDT, dgReadBDTRefused, dgRegisterFDT, dgRegisterRefused,
	dgReadMultiple, dgReadMultipleReply,
	dgIAm, dgWhoIs, dgWriteProperty, dgWriteAck, dgReinitialize, dgCommControl,
	dgError, dgReject, dgForwarded, dgWhoIsRouter,

	// A segmented request and its segmented answer.
	"810a0013010400050c0c0e0001c4020001f4",
	"810a0012010038070e0c0c0e0001c40200",
	// An abort and a SegmentACK.
	"810a0009010070070b",
	"810a000a0100400701 01",
	// A tag that declares a thirty-two bit length, and one that declares
	// more than the APDU holds.
	"810a0010010400050c0c0dff00000010",
	"810a000c01040005010c0cff",
	// Tags nested as deep as the reader allows, and one deeper.
	"810a0014010400050e0e0e0e0e0e0e0e0f0f0f0f0f0f0f0f",
	// A character string in each of the four encodings BACnet allows.
	"810a0017010030010c0c023fffff19793e7503004142433f",
	"810a0019010030010c0c023fffff19793e75050441004243f03f",
	// A property value that is an object identifier rather than a string.
	"810a0017010030010c0c023fffff194b3e c4020001f43f",
}

// FuzzParse checks the invariants that hold for any byte sequence: no panic,
// errors always wrap ErrMalformed, exactly one event per datagram, and
// nothing taken off the wire reaching an attribute or an identity unchecked.
func FuzzParse(f *testing.F) {
	for _, s := range seedCorpus {
		b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
		if err != nil {
			f.Fatalf("bad seed %q: %v", s, err)
		}
		f.Add(b)
	}

	d := bacnet.New()
	f.Fuzz(func(t *testing.T, payload []byte) {
		ctx := ctxFor()
		events, err := d.Parse(ctx, payload)
		if err != nil && !errors.Is(err, dissect.ErrMalformed) {
			t.Fatalf("Parse error must wrap ErrMalformed, got %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("one datagram must yield one event, got %d", len(events))
		}
		e := events[0]
		if !e.Class.Valid() {
			t.Fatalf("invalid classification %q", e.Class)
		}
		if e.Protocol != "bacnet" {
			t.Fatalf("unexpected protocol %q", e.Protocol)
		}
		if e.Operation == "" {
			t.Fatal("event without an operation name")
		}
		if e.Malformed == (e.Error == "") {
			t.Fatalf("malformed=%v with error %q", e.Malformed, e.Error)
		}
		for k, v := range e.Attrs {
			if k == "argument_error" {
				// The reason the arguments did not decode, which is this
				// package's own prose rather than packet bytes.
				continue
			}
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
		// A password must never reach an attribute, whatever the service
		// carried: the fact of one is recorded and the value is not.
		if v, ok := e.Attrs["password"]; ok && v != "sent" {
			t.Fatalf("password attribute carries %q", v)
		}
		if c := d.Probe(ctx, payload); c < 0 || c > 100 {
			t.Fatalf("Probe returned %d, outside 0..100", c)
		}
	})
}

// FuzzPDULen checks the framer: it must never claim a length it cannot
// justify from the buffer, and never zero with no error.
func FuzzPDULen(f *testing.F) {
	for _, s := range seedCorpus {
		b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
		if err != nil {
			f.Fatalf("bad seed %q: %v", s, err)
		}
		f.Add(b)
	}

	d := bacnet.New()
	f.Fuzz(func(t *testing.T, buf []byte) {
		n, err := d.PDULen(buf)
		switch {
		case err == nil:
			if n <= 0 || n > len(buf) {
				t.Fatalf("PDULen returned %d for a %d octet buffer", n, len(buf))
			}
		case errors.Is(err, dissect.ErrNeedMore), errors.Is(err, dissect.ErrMalformed):
		default:
			t.Fatalf("PDULen error must wrap ErrNeedMore or ErrMalformed, got %v", err)
		}
	})
}
