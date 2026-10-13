// Package goose dissects IEC 61850 GOOSE, the publish-subscribe protocol
// substation IEDs use to tell each other about state changes.
//
// GOOSE is the fast path in a substation: a protection relay publishes a trip
// or an interlocking state straight onto the Ethernet segment, with no IP, no
// transport and no handshake, and every subscriber acts on it within
// milliseconds. That makes it both the most time critical traffic on the bus
// and the easiest to forge, which is why the two counters it carries matter
// as much as the data. A publisher increments stNum when the state changes
// and restarts sqNum at zero; between changes it repeats the message with
// sqNum climbing. A state number that skips, a sequence number that goes
// backwards, or a frame marked simulated is the shape a replayed or injected
// message takes (CLAUDE.md, "GOOSE stNum jumps / unexpected publisher").
//
// There is nothing to reassemble and nothing to frame: one Ethernet frame is
// one PDU, with an eight octet header and a BER encoded APDU behind it.
package goose

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/ber"
	"github.com/rom/otinv/internal/model"
)

// EtherType is the value IEEE assigned to GOOSE (IEC 61850-8-1, clause A.3).
const EtherType = 0x88B8

// Header geometry (IEC 61850-8-1, clause A.3.2).
const (
	// headerLen is the application identifier, the length, and the two
	// reserved fields.
	headerLen = 8

	// minAPDULen is the smallest BER element that could be a GOOSE PDU.
	minAPDULen = 2

	// simulatedBit is the S bit of the first reserved field: the publisher
	// saying this frame comes from a test set rather than from the plant. A
	// subscriber that honours it is safe; one that ignores it will act on an
	// injected message, which is why the bit is worth reporting either way.
	simulatedBit = 0x8000
)

// APDU field tags, the context tags of IECGoosePdu (IEC 61850-8-1, clause
// A.2).
const (
	fieldGocbRef           = 0
	fieldTimeAllowedToLive = 1
	fieldDatSet            = 2
	fieldGoID              = 3
	fieldTime              = 4
	fieldStNum             = 5
	fieldSqNum             = 6
	fieldSimulation        = 7
	fieldConfRev           = 8
	fieldNdsCom            = 9
	fieldNumDatSetEntries  = 10
	fieldAllData           = 11
)

// maxTrackedControlBlocks caps how many control blocks one flow keeps state
// for. A publisher serves a handful; a crafted capture would otherwise name a
// new one per frame.
const maxTrackedControlBlocks = 64

// Dissector decodes IEC 61850 GOOSE. It holds no mutable state: the counters
// it tracks per control block live in the FlowContext the caller owns.
type Dissector struct{}

// New returns a GOOSE dissector.
func New() *Dissector { return &Dissector{} }

func init() {
	dissect.Register(New(), dissect.EtherTypes(EtherType))
}

// Name implements dissect.Dissector.
func (*Dissector) Name() string { return "goose" }

// Tier implements dissect.Dissector.
func (*Dissector) Tier() int { return 1 }

// Probe implements dissect.Dissector.
//
// GOOSE is bound by EtherType, which names one protocol, so this only has to
// separate a GOOSE frame from a corrupt one: a length that accounts for the
// frame, an APDU that parses, and the three fields no publisher may leave
// out.
func (*Dissector) Probe(_ *dissect.FlowContext, payload []byte) int {
	apdu, _, err := header(payload)
	if err != nil {
		return 0
	}
	top, err := ber.ReadOne(apdu)
	if err != nil || top.Class != ber.ClassApplication || top.Number != 1 {
		return 0
	}

	score := 50
	bud := ber.NewBudget()
	fields, complete := top.Children(bud)
	if !complete {
		return score
	}
	seen := map[uint32]bool{}
	for _, f := range fields {
		if f.Class == ber.ClassContext {
			seen[f.Number] = true
		}
	}
	if seen[fieldGocbRef] && seen[fieldStNum] && seen[fieldSqNum] {
		score += 40
	}
	if seen[fieldDatSet] && seen[fieldAllData] {
		score += 10
	}
	return min(score, 100)
}

// header splits a frame into its APDU and the fields in front of it.
func header(payload []byte) (apdu []byte, appid uint16, err error) {
	if len(payload) < headerLen+minAPDULen {
		return nil, 0, fmt.Errorf("%w: %d octets cannot hold a GOOSE header and a PDU",
			dissect.ErrMalformed, len(payload))
	}
	appid = binary.BigEndian.Uint16(payload[0:2])
	length := int(binary.BigEndian.Uint16(payload[2:4]))
	switch {
	case length < headerLen+minAPDULen:
		return nil, appid, fmt.Errorf("%w: GOOSE length field is %d, below the minimum %d",
			dissect.ErrMalformed, length, headerLen+minAPDULen)
	case length > len(payload):
		// The length counts from the application identifier, so it may be
		// shorter than the frame when the frame was padded to the Ethernet
		// minimum, but never longer.
		return nil, appid, fmt.Errorf("%w: GOOSE length field is %d, %d octets present",
			dissect.ErrMalformed, length, len(payload))
	}
	return payload[headerLen:length], appid, nil
}

// publication is the last state seen for one control block.
type publication struct {
	stNum, sqNum int64
	known        bool
}

// streamState tracks each control block a flow carries, so that a counter
// that skips is visible against the frame before it.
type streamState struct {
	blocks map[string]*publication
}

func state(ctx *dissect.FlowContext) *streamState {
	if s, ok := ctx.State.(*streamState); ok {
		return s
	}
	s := &streamState{blocks: map[string]*publication{}}
	ctx.State = s
	return s
}

// pdu is a decoded GOOSE APDU.
type pdu struct {
	gocbRef    string
	datSet     string
	goID       string
	ttl        int64
	stNum      int64
	sqNum      int64
	confRev    int64
	entries    int64
	simulation bool
	ndsCom     bool

	hasTTL, hasStNum, hasSqNum, hasConfRev, hasEntries bool

	time    ber.TLV
	hasTime bool
	allData ber.TLV
	hasData bool

	unknown []string
}

// Parse implements dissect.Dissector. One Ethernet frame carries one PDU.
func (d *Dissector) Parse(ctx *dissect.FlowContext, payload []byte) ([]model.Event, error) {
	ev := model.Event{
		CaptureID:   ctx.CaptureID,
		PacketIndex: ctx.PacketIndex,
		Timestamp:   ctx.Timestamp,
		Flow:        ctx.Flow,
		Protocol:    "goose",
		// A publication answers nothing: there is no request anywhere on the
		// segment, and the publisher is the device the message is evidence
		// about, so it is recorded as the serving side.
		Direction:    model.DirResponse,
		Operation:    "GOOSE",
		FunctionCode: -1,
		Class:        model.ClassRead,
	}

	apdu, appid, err := header(payload)
	if appid != 0 || err == nil {
		setAttr(&ev, "appid", fmt.Sprintf("0x%04x", appid))
	}
	if err != nil {
		return []model.Event{malformed(ev, err.Error())}, err
	}
	if binary.BigEndian.Uint16(payload[4:6])&simulatedBit != 0 {
		setAttr(&ev, "simulated", "true")
		addAnomaly(&ev, "simulated_frame")
	}

	top, err := ber.ReadOne(apdu)
	if err != nil {
		return []model.Event{malformed(ev, err.Error())},
			fmt.Errorf("%w: %s", dissect.ErrMalformed, err.Error())
	}
	if top.Class != ber.ClassApplication || top.Number != 1 {
		msg := fmt.Sprintf("GOOSE PDU opens with %s, not an application 1 tag", top.Tag())
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	bud := ber.NewBudget()
	p, complete := decode(top, bud)
	if !complete {
		addAnomaly(&ev, "truncated_pdu")
	}
	describe(&ev, p, bud)
	trackCounters(ctx, &ev, p)
	return []model.Event{ev}, nil
}

// decode reads the APDU's fields. Every one is optional on the wire, so what
// is missing is as much a finding as what is present.
func decode(top ber.TLV, bud *ber.Budget) (pdu, bool) {
	var p pdu
	fields, complete := top.Descend(bud)
	for _, f := range fields {
		if f.Class != ber.ClassContext {
			p.unknown = append(p.unknown, f.Tag())
			continue
		}
		switch f.Number {
		case fieldGocbRef:
			p.gocbRef, _ = f.Text()
		case fieldDatSet:
			p.datSet, _ = f.Text()
		case fieldGoID:
			p.goID, _ = f.Text()
		case fieldTimeAllowedToLive:
			p.ttl, p.hasTTL = f.Integer()
		case fieldTime:
			p.time, p.hasTime = f, true
		case fieldStNum:
			p.stNum, p.hasStNum = f.Integer()
		case fieldSqNum:
			p.sqNum, p.hasSqNum = f.Integer()
		case fieldSimulation:
			p.simulation = isTrue(f)
		case fieldConfRev:
			p.confRev, p.hasConfRev = f.Integer()
		case fieldNdsCom:
			p.ndsCom = isTrue(f)
		case fieldNumDatSetEntries:
			p.entries, p.hasEntries = f.Integer()
		case fieldAllData:
			p.allData, p.hasData = f, true
		default:
			p.unknown = append(p.unknown, f.Tag())
		}
	}
	return p, complete
}

// describe records what the PDU said.
func describe(ev *model.Event, p pdu, bud *ber.Budget) {
	setAttr(ev, "gocb_ref", p.gocbRef)
	setAttr(ev, "dat_set", p.datSet)
	setAttr(ev, "go_id", p.goID)
	if p.hasTTL {
		setAttr(ev, "time_allowed_to_live_ms", strconv.FormatInt(p.ttl, 10))
	}
	if p.hasConfRev {
		setAttr(ev, "conf_rev", strconv.FormatInt(p.confRev, 10))
	}
	if p.hasStNum {
		setAttr(ev, "st_num", strconv.FormatInt(p.stNum, 10))
	}
	if p.hasSqNum {
		setAttr(ev, "sq_num", strconv.FormatInt(p.sqNum, 10))
		// A publisher restarts the sequence at zero whenever the state
		// changes, so the first message of a burst is the state change itself
		// and the rest are the repeats that keep subscribers alive.
		if p.sqNum == 0 {
			ev.Operation = "StateChange"
		} else {
			ev.Operation = "Retransmission"
		}
	}
	if p.hasTime {
		setTime(ev, p.time)
	}

	if p.simulation {
		// The publisher's own claim that this is test traffic. In a live
		// substation it should not be there at all.
		setAttr(ev, "simulation", "true")
		addAnomaly(ev, "simulated_frame")
	}
	if p.ndsCom {
		// Needs commissioning: the publisher is telling subscribers its
		// configuration is incomplete, so the data is not to be acted on.
		setAttr(ev, "nds_com", "true")
		addAnomaly(ev, "needs_commissioning")
	}
	if len(p.unknown) > 0 {
		setAttr(ev, "unknown_fields", strings.Join(p.unknown, ","))
		addAnomaly(ev, "unknown_field")
	}
	for _, field := range []struct {
		name    string
		present bool
	}{
		{"gocbRef", p.gocbRef != ""},
		{"stNum", p.hasStNum},
		{"sqNum", p.hasSqNum},
	} {
		if !field.present {
			addAnomaly(ev, "missing_"+field.name)
		}
	}

	if p.gocbRef != "" {
		// A control block reference opens with the logical device, which is
		// the name the substation configuration gave this publisher.
		if device, _, found := strings.Cut(p.gocbRef, "/"); found && device != "" {
			setIdentity(ev, "logical_device", device)
		}
	}

	if !p.hasData {
		if p.hasEntries {
			setAttr(ev, "entries", strconv.FormatInt(p.entries, 10))
		}
		return
	}
	values, count, truncated := renderValues(p.allData, bud)
	setAttr(ev, "entries", strconv.Itoa(count))
	if p.hasEntries && p.entries != int64(count) {
		// The header says one thing and the data set another, which is either
		// a configuration mismatch between publisher and subscriber or a
		// frame built by hand.
		setAttr(ev, "declared_entries", strconv.FormatInt(p.entries, 10))
		addAnomaly(ev, "entry_count_mismatch")
	}
	if count > 0 {
		ev.Quantity = model.Ptr(uint32(count))
	}
	if values != "" {
		if truncated {
			values += ",…"
		}
		setAttr(ev, "values", values)
	}
}

// trackCounters compares this frame's counters with the last one from the same
// control block.
//
// The three ways they can disagree mean different things. A state number that
// skips means a state change was never seen, whether because the capture
// missed it or because it never travelled. A sequence number that goes
// backwards without the state changing is a repeat of something already sent,
// which is what a replayed frame looks like. A state change that does not
// restart the sequence is a publisher that is not following the standard, or
// a frame assembled without reading it.
func trackCounters(ctx *dissect.FlowContext, ev *model.Event, p pdu) {
	if p.gocbRef == "" || !p.hasStNum || !p.hasSqNum {
		return
	}
	st := state(ctx)
	last, known := st.blocks[p.gocbRef]
	if !known {
		if len(st.blocks) >= maxTrackedControlBlocks {
			addAnomaly(ev, "too_many_control_blocks")
			return
		}
		st.blocks[p.gocbRef] = &publication{stNum: p.stNum, sqNum: p.sqNum, known: true}
		return
	}

	switch p.stNum {
	case last.stNum:
		switch {
		case p.sqNum < last.sqNum:
			setAttr(ev, "previous_sq_num", strconv.FormatInt(last.sqNum, 10))
			addAnomaly(ev, "sq_num_regression")
		case p.sqNum > last.sqNum+1:
			setAttr(ev, "previous_sq_num", strconv.FormatInt(last.sqNum, 10))
			addAnomaly(ev, "sq_num_gap")
		}
	case last.stNum + 1:
		if p.sqNum != 0 {
			addAnomaly(ev, "sq_num_not_reset")
		}
	default:
		setAttr(ev, "previous_st_num", strconv.FormatInt(last.stNum, 10))
		addAnomaly(ev, "st_num_jump")
	}
	last.stNum, last.sqNum = p.stNum, p.sqNum
}

// isTrue reads a BER boolean. The standard encodes it in one octet, where any
// non-zero value is true.
func isTrue(t ber.TLV) bool {
	for _, b := range t.Value {
		if b != 0 {
			return true
		}
	}
	return false
}

func setAttr(ev *model.Event, key, value string) {
	if value == "" {
		return
	}
	if ev.Attrs == nil {
		ev.Attrs = make(map[string]string, 12)
	}
	ev.Attrs[key] = value
}

// addAnomaly records an anomaly, keeping any already there.
func addAnomaly(ev *model.Event, name string) {
	existing := ev.Attrs["anomaly"]
	switch {
	case existing == "":
		setAttr(ev, "anomaly", name)
	case strings.Contains(existing, name):
	default:
		setAttr(ev, "anomaly", existing+","+name)
	}
}

func setIdentity(ev *model.Event, key, value string) {
	if value == "" {
		return
	}
	if ev.Identity == nil {
		ev.Identity = make(map[string]string, 2)
	}
	ev.Identity[key] = value
}

func malformed(ev model.Event, reason string) model.Event {
	ev.Malformed = true
	ev.Error = reason
	return ev
}
