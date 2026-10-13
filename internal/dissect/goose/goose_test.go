package goose_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/goose"
	"github.com/rom/otinv/internal/model"
)

// Frames taken verbatim from the public GOOSE sample captures in
// testdata/pcaps, from the EtherType onward; the comment names the file and
// packet each came from. Every capture was decoded independently before these
// expectations were written.
const (
	// interlocking #1, #2 and #3: a bay controller publishing an
	// interlocking data set. The first two are state changes, the third the
	// repeat that follows the second.
	frameInterlockingChange = "300100e3000000006181d8801b414131433151303141314c44302f4c4c4e3024474f246763" +
		"625f4181023a988220414131433151303141314c44302f4c4c4e3024496e7465726c6f636b696e6741830d496e74" +
		"65726c6f636b696e67418408488890c1240000278503008f618601008701008801018901008a0119ab6683010083" +
		"0100830100830100830100830100830100840206808403030000840206808403030000840206808403030000840206" +
		"008403030000840206408403030000840206408403030000840206408403030000840206408403030000840206408403030000"
	frameInterlockingNext = "300100e3000000006181d8801b414131433151303141314c44302f4c4c4e3024474f246763" +
		"625f4181023a988220414131433151303141314c44302f4c4c4e3024496e7465726c6f636b696e6741830d496e74" +
		"65726c6f636b696e67418408488890c1240000278503008f628601008701008801018901008a0119ab6683010083" +
		"0100830100830100830100830100830100840206808403030000840206808403030000840206808403030000840206" +
		"008403030000840206008403030000840206408403030000840206408403030000840206408403030000840206408403030000"
	frameInterlockingRepeat = "300100e3000000006181d8801b414131433151303141314c44302f4c4c4e3024474f2467" +
		"63625f4181023a988220414131433151303141314c44302f4c4c4e3024496e7465726c6f636b696e6741830d496e" +
		"7465726c6f636b696e67418408488890c1280000278503008f628601018701008801018901008a0119ab66830100" +
		"830100830100830100830100830100830100840206808403030000840206808403030000840206808403030000840206" +
		"008403030000840206008403030000840206408403030000840206408403030000840206408403030000840206408403030000"

	// ge_relay #1: a GE F650 relay, publishing to a vendor multicast address
	// of its own and with no VLAN tag.
	frameGERelay = "0001009100000000618186801a4745446576696365463635302f4c4c4e3024474f2467636230318103" +
		"009c4082184745446576696365463635302f4c4c4e3024474f4f534531830b463635305f474f4f53453184083" +
		"86ebbf34217280a85010186010a8701008801018901008a0108ab2083010084030300008301008403030000830" +
		"100840303000083010084030300 00"
	// ge_relay #4: the same relay a burst later, with the sequence number
	// back at one although the state number never moved.
	frameGERelayReplay = "0001009000000000618185801a4745446576696365463635302f4c4c4e3024474f246763623" +
		"031810203e882184745446576696365463635302f4c4c4e3024474f4f534531830b463635305f474f4f534531840" +
		"8386ebc41ed76ec0a8501018601018701008801018901008a0108ab208301008403030000830100840303000083" +
		"01008403030000830100840303 0000"

	// minimal #1: the smallest shape in the samples, VLAN tagged, with
	// references that are not object names at all.
	frameMinimal = "2000006c0000000061628003313131810500000027108203323232830333333384084ddda51adbe7" +
		"6d008505000000000186050000000001870100880500000000018901008a05000000000aab1e8301008301008301" +
		"00830100830100830100830100830100830100830100"
)

func frame(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
	require.NoError(t, err, "test fixture is not valid hex")
	return b
}

func ctxFor() *dissect.FlowContext {
	return &dissect.FlowContext{
		CaptureID: "test",
		Flow: model.Flow{
			SrcMAC:    "0a:bb:fe:10:c9:02",
			DstMAC:    "01:0c:cd:01:00:00",
			Transport: model.TransportEthernet,
		},
		PacketIndex: 1,
		Timestamp:   time.Unix(1216909505, 0).UTC(),
		Direction:   model.DirUnknown,
	}
}

func parseOne(t *testing.T, ctx *dissect.FlowContext, raw []byte) model.Event {
	t.Helper()
	events, err := goose.New().Parse(ctx, raw)
	require.NoError(t, err)
	require.Len(t, events, 1, "one frame is one PDU")
	return events[0]
}

func TestIdentity(t *testing.T) {
	d := goose.New()
	assert.Equal(t, "goose", d.Name())
	assert.Equal(t, 1, d.Tier())
}

// GOOSE has no port: it is bound by the EtherType IEEE assigned to it.
func TestRegisteredOnEtherType(t *testing.T) {
	reg := dissect.Default()
	d, ok := reg.Lookup("goose")
	require.True(t, ok, "goose must register itself in init()")
	require.NotNil(t, d)
	assert.True(t, reg.HasEtherType("goose", 0x88B8))
	assert.False(t, reg.HasPort("goose", model.TransportTCP, 102),
		"GOOSE runs on no port at all")
}

func TestProbe(t *testing.T) {
	d := goose.New()
	ctx := ctxFor()

	tests := []struct {
		name    string
		in      string
		wantMin int
		wantMax int
	}{
		{name: "interlocking publication", in: frameInterlockingChange, wantMin: 90, wantMax: 100},
		{name: "ge relay publication", in: frameGERelay, wantMin: 90, wantMax: 100},
		{name: "minimal publication", in: frameMinimal, wantMin: 90, wantMax: 100},

		{name: "empty", in: "", wantMax: 0},
		{name: "header only", in: "300100e300000000", wantMax: 0},
		{name: "length field longer than the frame", in: "3001ffff00000000610101", wantMax: 0},
		{name: "length field below the minimum", in: "300100030000000061", wantMax: 0},
		{name: "not a GOOSE PDU tag", in: "300100 0c 00000000 30020101", wantMax: 0},
		{name: "APDU that does not parse", in: "300100 0c 00000000 6182ff01", wantMax: 0},
		// A PDU that parses but carries none of the fields a publisher must
		// send is not something to act on.
		{name: "no required fields", in: "300100 0d 00000000 6103820100", wantMin: 50, wantMax: 50},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := d.Probe(ctx, frame(t, tc.in))
			assert.GreaterOrEqual(t, got, tc.wantMin)
			assert.LessOrEqual(t, got, tc.wantMax)
		})
	}
}

func TestParsePublication(t *testing.T) {
	ev := parseOne(t, ctxFor(), frame(t, frameInterlockingChange))

	assert.Equal(t, "goose", ev.Protocol)
	assert.Equal(t, "StateChange", ev.Operation,
		"a publisher restarts the sequence at zero when the state changes")
	assert.Equal(t, -1, ev.FunctionCode, "GOOSE has no function codes")
	assert.Equal(t, model.ClassRead, ev.Class)
	assert.Equal(t, model.DirResponse, ev.Direction, "a publication answers nothing")
	assert.False(t, ev.Malformed)

	assert.Equal(t, "0x3001", ev.Attrs["appid"])
	assert.Equal(t, "AA1C1Q01A1LD0/LLN0$GO$gcb_A", ev.Attrs["gocb_ref"])
	assert.Equal(t, "AA1C1Q01A1LD0/LLN0$InterlockingA", ev.Attrs["dat_set"])
	assert.Equal(t, "InterlockingA", ev.Attrs["go_id"])
	assert.Equal(t, "15000", ev.Attrs["time_allowed_to_live_ms"])
	assert.Equal(t, "36705", ev.Attrs["st_num"])
	assert.Equal(t, "0", ev.Attrs["sq_num"])
	assert.Equal(t, "1", ev.Attrs["conf_rev"])
	assert.Equal(t, "25", ev.Attrs["entries"])
	assert.Equal(t, "2008-07-24T14:25:05.140Z", ev.Attrs["t"])
	assert.Equal(t, "clock_not_synchronised,accuracy_7_bits", ev.Attrs["time_quality"])
	assert.Equal(t, "false,false,false,false,false,false,false,0x80,…", ev.Attrs["values"])
	require.NotNil(t, ev.Quantity)
	assert.Equal(t, uint32(25), *ev.Quantity)

	// A control block reference opens with the logical device, which is the
	// name the substation configuration gave the publisher.
	assert.Equal(t, map[string]string{"logical_device": "AA1C1Q01A1LD0"}, ev.Identity)

	// An unsynchronised clock is a standing condition of the installation,
	// not something wrong with this frame.
	assert.NotContains(t, ev.Attrs, "anomaly")
}

// The sequence number is what separates the message that reports a change
// from the repeats that keep subscribers alive, and the two mean different
// things to an analyst reading a bus.
func TestStateChangeAndRetransmission(t *testing.T) {
	ctx := ctxFor()

	first := parseOne(t, ctx, frame(t, frameInterlockingChange))
	assert.Equal(t, "StateChange", first.Operation)
	assert.Equal(t, "36705", first.Attrs["st_num"])

	next := parseOne(t, ctx, frame(t, frameInterlockingNext))
	assert.Equal(t, "StateChange", next.Operation)
	assert.Equal(t, "36706", next.Attrs["st_num"])
	assert.Equal(t, "0", next.Attrs["sq_num"])
	assert.NotContains(t, next.Attrs, "anomaly", "one state change follows the other")

	repeat := parseOne(t, ctx, frame(t, frameInterlockingRepeat))
	assert.Equal(t, "Retransmission", repeat.Operation)
	assert.Equal(t, "36706", repeat.Attrs["st_num"])
	assert.Equal(t, "1", repeat.Attrs["sq_num"])
	assert.NotContains(t, repeat.Attrs, "anomaly")
}

// A sequence number that goes backwards without the state changing is a
// repeat of something already published, which is the shape a replayed frame
// takes. This pair is from the sample capture, not crafted.
func TestSequenceRegressionIsReported(t *testing.T) {
	ctx := ctxFor()

	first := parseOne(t, ctx, frame(t, frameGERelay))
	assert.Equal(t, "1", first.Attrs["st_num"])
	assert.Equal(t, "10", first.Attrs["sq_num"])
	assert.NotContains(t, first.Attrs, "anomaly", "the first frame sets the expectation")
	assert.Equal(t, "GEDeviceF650", first.Identity["logical_device"])

	replay := parseOne(t, ctx, frame(t, frameGERelayReplay))
	assert.Equal(t, "1", replay.Attrs["st_num"])
	assert.Equal(t, "1", replay.Attrs["sq_num"])
	assert.Equal(t, "sq_num_regression", replay.Attrs["anomaly"])
	assert.Equal(t, "10", replay.Attrs["previous_sq_num"])
}

// CLAUDE.md names a state number that jumps as a built-in rule. The dissector
// supplies the finding; a jump is only visible against the frame before it.
func TestStateNumberJumpIsReported(t *testing.T) {
	ctx := ctxFor()
	parseOne(t, ctx, frame(t, frameInterlockingChange)) // state 36705

	// The same control block, eleven states later.
	jumped := parseOne(t, ctx, frame(t, publication(t, publicationFields{
		gocbRef: "AA1C1Q01A1LD0/LLN0$GO$gcb_A", stNum: 36716, sqNum: 0, entries: 1,
	})))
	assert.Equal(t, "st_num_jump", jumped.Attrs["anomaly"])
	assert.Equal(t, "36705", jumped.Attrs["previous_st_num"])
}

// A state change that does not restart the sequence is a publisher not
// following the standard, or a frame assembled without reading it.
func TestStateChangeWithoutSequenceResetIsReported(t *testing.T) {
	ctx := ctxFor()
	parseOne(t, ctx, frame(t, publication(t, publicationFields{
		gocbRef: "LD/LLN0$GO$gcb", stNum: 5, sqNum: 3, entries: 1,
	})))

	ev := parseOne(t, ctx, frame(t, publication(t, publicationFields{
		gocbRef: "LD/LLN0$GO$gcb", stNum: 6, sqNum: 4, entries: 1,
	})))
	assert.Equal(t, "sq_num_not_reset", ev.Attrs["anomaly"])
}

// A counter tracked per control block, because one publisher commonly serves
// several and their sequences are independent.
func TestCountersAreTrackedPerControlBlock(t *testing.T) {
	ctx := ctxFor()
	for _, ref := range []string{"LD/LLN0$GO$gcbA", "LD/LLN0$GO$gcbB"} {
		ev := parseOne(t, ctx, frame(t, publication(t, publicationFields{
			gocbRef: ref, stNum: 100, sqNum: 0, entries: 1,
		})))
		assert.NotContains(t, ev.Attrs, "anomaly", ref)
	}
	// Each block's own sequence continues without disturbing the other.
	for _, ref := range []string{"LD/LLN0$GO$gcbA", "LD/LLN0$GO$gcbB"} {
		ev := parseOne(t, ctx, frame(t, publication(t, publicationFields{
			gocbRef: ref, stNum: 100, sqNum: 1, entries: 1,
		})))
		assert.NotContains(t, ev.Attrs, "anomaly", ref)
	}
}

// A frame a test set put on the bus is marked as such in two places, and
// either one is worth reporting: a subscriber that ignores the mark will act
// on an injected message.
func TestSimulatedFramesAreFlagged(t *testing.T) {
	t.Run("the header bit", func(t *testing.T) {
		ev := parseOne(t, ctxFor(), frame(t, publication(t, publicationFields{
			gocbRef: "LD/LLN0$GO$gcb", stNum: 1, sqNum: 0, entries: 1, simulatedBit: true,
		})))
		assert.Equal(t, "true", ev.Attrs["simulated"])
		assert.Contains(t, ev.Attrs["anomaly"], "simulated_frame")
	})

	t.Run("the APDU field", func(t *testing.T) {
		ev := parseOne(t, ctxFor(), frame(t, publication(t, publicationFields{
			gocbRef: "LD/LLN0$GO$gcb", stNum: 1, sqNum: 0, entries: 1, simulation: true,
		})))
		assert.Equal(t, "true", ev.Attrs["simulation"])
		assert.Contains(t, ev.Attrs["anomaly"], "simulated_frame")
	})
}

// A publisher that says its configuration is incomplete is telling
// subscribers not to act on the data.
func TestNeedsCommissioningIsFlagged(t *testing.T) {
	ev := parseOne(t, ctxFor(), frame(t, publication(t, publicationFields{
		gocbRef: "LD/LLN0$GO$gcb", stNum: 1, sqNum: 0, entries: 1, ndsCom: true,
	})))
	assert.Equal(t, "true", ev.Attrs["nds_com"])
	assert.Contains(t, ev.Attrs["anomaly"], "needs_commissioning")
}

// The header says how many entries the data set holds and the data set says
// how many it carries. The two disagreeing is either a configuration mismatch
// between publisher and subscriber or a frame built by hand.
func TestEntryCountMismatchIsReported(t *testing.T) {
	ev := parseOne(t, ctxFor(), frame(t, publication(t, publicationFields{
		gocbRef: "LD/LLN0$GO$gcb", stNum: 1, sqNum: 0,
		entries: 9, values: 2,
	})))
	assert.Equal(t, "2", ev.Attrs["entries"])
	assert.Equal(t, "9", ev.Attrs["declared_entries"])
	assert.Equal(t, "entry_count_mismatch", ev.Attrs["anomaly"])
}

// Every field of a GOOSE PDU is optional on the wire, so a publisher that
// leaves out what it must send is reported rather than read as zero.
func TestMissingFieldsAreReported(t *testing.T) {
	// A PDU with nothing but a data set name.
	ev := parseOne(t, ctxFor(), frame(t, apdu(t, "820744532f6e616d65", false)))
	assert.Equal(t, "GOOSE", ev.Operation, "with no sequence number there is no state to name")
	assert.Equal(t, "DS/name", ev.Attrs["dat_set"])
	for _, want := range []string{"missing_gocbRef", "missing_stNum", "missing_sqNum"} {
		assert.Contains(t, ev.Attrs["anomaly"], want)
	}
	assert.Empty(t, ev.Identity)
}

// A reference that is not an object name carries no logical device, and
// inventing one from it would put a name on the asset that is not its own.
func TestReferenceWithoutADeviceNameYieldsNoIdentity(t *testing.T) {
	ev := parseOne(t, ctxFor(), frame(t, frameMinimal))
	assert.Equal(t, "111", ev.Attrs["gocb_ref"])
	assert.Equal(t, "222", ev.Attrs["dat_set"])
	assert.Equal(t, "10", ev.Attrs["entries"])
	assert.Empty(t, ev.Identity)
}

func TestParseMalformed(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		reason string
	}{
		{name: "empty", in: "", reason: "cannot hold a GOOSE header"},
		{name: "header only", in: "300100e300000000", reason: "cannot hold a GOOSE header"},
		{
			name: "length longer than the frame", in: "3001ffff00000000610101",
			reason: "length field is 65535",
		},
		{
			name: "length below the minimum", in: "3001000300000000610101",
			reason: "below the minimum",
		},
		{
			name: "APDU with an indefinite length", in: "3001000a000000006180",
			reason: "indefinite length",
		},
		{
			name: "APDU under the wrong tag", in: "300100 0d 00000000 30030201ff",
			reason: "not an application 1 tag",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events, err := goose.New().Parse(ctxFor(), frame(t, tc.in))
			require.Error(t, err)
			assert.True(t, errors.Is(err, dissect.ErrMalformed), "got %v", err)
			require.Len(t, events, 1, "a malformed frame is still evidence")
			assert.True(t, events[0].Malformed)
			assert.Equal(t, "GOOSE", events[0].Operation)
			assert.Contains(t, events[0].Error, tc.reason)
		})
	}
}

// Nothing in a frame may be trusted, so every prefix of every fixture has to
// come back as an event or an error, never a panic.
func TestParseNeverPanicsOnTruncation(t *testing.T) {
	d := goose.New()
	for _, fixture := range []string{
		frameInterlockingChange, frameGERelay, frameMinimal,
	} {
		raw := frame(t, fixture)
		for i := range len(raw) + 1 {
			ctx := ctxFor()
			assert.NotPanics(t, func() { _, _ = d.Parse(ctx, raw[:i]) }, "parse at %d", i)
			assert.NotPanics(t, func() { _ = d.Probe(ctx, raw[:i]) }, "probe at %d", i)
		}
	}
}

// publicationFields describes a GOOSE PDU to build for a test.
type publicationFields struct {
	gocbRef      string
	stNum        int
	sqNum        int
	entries      int
	values       int
	simulation   bool
	ndsCom       bool
	simulatedBit bool
}

// publication builds a frame carrying one publication, so that the shapes the
// public captures do not contain can still be exercised.
func publication(t *testing.T, f publicationFields) string {
	t.Helper()
	values := f.values
	if values == 0 {
		values = f.entries
	}

	body := ""
	if f.gocbRef != "" {
		body += "80" + hexByte(len(f.gocbRef)) + hex.EncodeToString([]byte(f.gocbRef))
	}
	body += "8102" + hexWord(15000) // timeAllowedtoLive
	// t: four octets of seconds, three of fraction and one of quality.
	body += "8408" + hexDWord(1216909505) + "240000" + "27"
	body += "8503" + hexTriple(f.stNum)
	body += "8603" + hexTriple(f.sqNum)
	if f.simulation {
		body += "870101"
	}
	body += "880101"
	if f.ndsCom {
		body += "890101"
	}
	body += "8a03" + hexTriple(f.entries)
	data := strings.Repeat("830100", values)
	body += "ab" + hexByte(len(data)/2) + data

	return apdu(t, body, f.simulatedBit)
}

// apdu wraps a PDU body in the GOOSE application tag and the Ethernet header.
func apdu(t *testing.T, body string, simulated bool) string {
	t.Helper()
	pdu := "61" + hexLen(len(body)/2) + body
	reserved1 := "0000"
	if simulated {
		reserved1 = "8000"
	}
	total := 8 + len(pdu)/2
	return "3001" + hexWord(total) + reserved1 + "0000" + pdu
}

func hexByte(n int) string { return hex.EncodeToString([]byte{byte(n)}) }
func hexWord(n int) string { return hex.EncodeToString([]byte{byte(n >> 8), byte(n)}) }
func hexTriple(n int) string {
	return hex.EncodeToString([]byte{byte(n >> 16), byte(n >> 8), byte(n)})
}

func hexDWord(n int) string {
	return hex.EncodeToString([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

func hexLen(n int) string {
	if n < 0x80 {
		return hexByte(n)
	}
	if n < 0x100 {
		return "81" + hexByte(n)
	}
	return "82" + hexWord(n)
}
