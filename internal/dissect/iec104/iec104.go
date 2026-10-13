// Package iec104 dissects IEC 60870-5-104, the TCP profile of the IEC
// 60870-5 telecontrol standard, spoken between control centres and
// substations on port 2404.
//
// IEC 104 carries the ASDUs of IEC 60870-5-101 inside a four-octet APCI that
// adds flow control: numbered information frames, supervisory acknowledgements
// and unnumbered control functions that start, stop and test data transfer.
// Behind that sits the part an analyst cares about — a type identification
// naming what kind of data or command this is, a cause of transmission saying
// why it was sent, the common address of the station and the information
// object addresses of the individual points.
//
// Everything in a frame is attacker-controlled, so the object count is checked
// against the element size the standard fixes for the type before any element
// is read, and a frame that does not add up becomes a malformed event rather
// than a panic.
package iec104

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/model"
)

// DefaultPort is the registered IEC 60870-5-104 port.
const DefaultPort = 2404

// APCI geometry (-104, clauses 5.1 and 5.3).
const (
	// startByte opens every APDU.
	startByte = 0x68

	// apciLen is the start octet, the length octet and four control octets.
	apciLen = 6

	// The length octet counts the control octets and the ASDU. Four is
	// therefore the smallest legal value, and 253 the largest the standard
	// allows, which caps an ASDU at 249 octets.
	minLengthField = 4
	maxLengthField = 253

	// asduHeaderLen is the type identification, the variable structure
	// qualifier, the two cause octets and the two common address octets.
	asduHeaderLen = 6

	// ioaLen is the information object address width -104 fixes.
	ioaLen = 3

	// seqModulus is the modulus of the send and receive sequence numbers,
	// which are 15 bit values held in the upper bits of two control octets.
	seqModulus = 1 << 15

	// globalAddress names every station on the link rather than one device.
	globalAddress = 0xFFFF

	// maxListedObjects caps how many information object addresses one event
	// lists. The count field is seven bits, so a frame may carry 127.
	maxListedObjects = 16
)

// apciFormat is which of the three APDU formats a frame uses.
type apciFormat int

// The three formats, distinguished by the low bits of the first control octet.
const (
	formatI apciFormat = iota // information transfer
	formatS                   // numbered supervisory function
	formatU                   // unnumbered control function
)

func (f apciFormat) String() string {
	switch f {
	case formatI:
		return "I"
	case formatS:
		return "S"
	default:
		return "U"
	}
}

// classify reads the format out of the first control octet.
func classify(c0 uint8) apciFormat {
	switch {
	case c0&0x01 == 0:
		return formatI
	case c0&0x03 == 0x01:
		return formatS
	default:
		return formatU
	}
}

// sequenceNumber reads a 15 bit sequence number from two control octets. The
// low bit of the first octet is the format marker, not part of the number.
func sequenceNumber(lo, hi uint8) uint16 {
	return (uint16(lo) | uint16(hi)<<8) >> 1
}

// Dissector decodes IEC 60870-5-104. It holds no mutable state: per-stream
// sequence tracking lives in the FlowContext the caller owns.
type Dissector struct{}

// New returns an IEC 60870-5-104 dissector.
func New() *Dissector { return &Dissector{} }

func init() {
	dissect.Register(New(), dissect.TCPPorts(DefaultPort))
}

// Name implements dissect.Dissector.
func (*Dissector) Name() string { return "iec104" }

// Tier implements dissect.Dissector.
func (*Dissector) Tier() int { return 1 }

// PDULen implements dissect.Framer. An APDU is delimited by its start octet
// and the length octet that follows it.
func (*Dissector) PDULen(buf []byte) (int, error) {
	if len(buf) < 1 {
		return 0, dissect.ErrNeedMore
	}
	if buf[0] != startByte {
		return 0, fmt.Errorf("%w: start octet is 0x%02x, not 0x68", dissect.ErrMalformed, buf[0])
	}
	if len(buf) < 2 {
		return 0, dissect.ErrNeedMore
	}
	length := buf[1]
	if length < minLengthField {
		return 0, fmt.Errorf("%w: APDU length %d is below the minimum %d",
			dissect.ErrMalformed, length, minLengthField)
	}
	if length > maxLengthField {
		return 0, fmt.Errorf("%w: APDU length %d exceeds the maximum %d",
			dissect.ErrMalformed, length, maxLengthField)
	}
	total := 2 + int(length)
	if len(buf) < total {
		return 0, dissect.ErrNeedMore
	}
	return total, nil
}

// Probe implements dissect.Dissector.
//
// A start octet and a length in range are weak on their own: 0x68 is a common
// byte. What makes IEC 104 recognisable is that all three formats constrain
// their control octets tightly — a supervisory or control frame is exactly six
// octets with fixed bits — and that a known type identification and cause of
// transmission follow in an information frame.
func (d *Dissector) Probe(_ *dissect.FlowContext, payload []byte) int {
	if len(payload) < apciLen || payload[0] != startByte {
		return 0
	}
	length := payload[1]
	if length < minLengthField || length > maxLengthField {
		return 0
	}
	total := 2 + int(length)
	control := payload[2:apciLen]
	score := 25

	switch classify(control[0]) {
	case formatU:
		// One function, nothing else set, and no ASDU.
		if _, ok := uFunctions[control[0]]; !ok {
			return 0
		}
		if control[1]|control[2]|control[3] != 0 || length != minLengthField {
			return 0
		}
		score += 45

	case formatS:
		if control[0] != 0x01 || control[1] != 0 || control[2]&0x01 != 0 {
			return 0
		}
		if length != minLengthField {
			return 0
		}
		score += 35

	case formatI:
		// The receive sequence number carries the same low-bit convention.
		if control[2]&0x01 != 0 {
			return 0
		}
		if total < apciLen+asduHeaderLen {
			return 0
		}
		score += 20
		if len(payload) >= apciLen+asduHeaderLen {
			asdu := payload[apciLen:]
			if _, known := types[asdu[0]]; known {
				score += 25
				if asdu[1]&0x7f != 0 {
					score += 5
				}
			}
			if _, known := causes[asdu[2]&0x3f]; known {
				score += 10
			}
		}
	}

	// Framing that accounts for the whole payload, or runs straight into
	// another APDU, is what separates a real stream from a lucky byte.
	switch {
	case total == len(payload):
		score += 20
	case total < len(payload):
		if _, err := d.PDULen(payload[total:]); err == nil {
			score += 20
		}
	}
	return min(score, 100)
}

// streamState tracks this direction's send sequence number so that a gap,
// which means APDUs were lost or injected, can be reported.
type streamState struct {
	expectSend uint16
	haveSend   bool
}

func state(ctx *dissect.FlowContext) *streamState {
	if s, ok := ctx.State.(*streamState); ok {
		return s
	}
	s := &streamState{}
	ctx.State = s
	return s
}

// Parse implements dissect.Dissector. It decodes one APDU.
func (d *Dissector) Parse(ctx *dissect.FlowContext, payload []byte) ([]model.Event, error) {
	ev := model.Event{
		CaptureID:    ctx.CaptureID,
		PacketIndex:  ctx.PacketIndex,
		Timestamp:    ctx.Timestamp,
		Flow:         ctx.Flow,
		Protocol:     "iec104",
		Direction:    ctx.Direction,
		FunctionCode: -1,
		Class:        model.ClassOther,
	}
	if ev.Direction == "" {
		ev.Direction = model.DirUnknown
	}

	if len(payload) < apciLen {
		msg := fmt.Sprintf("%d octets cannot hold an APCI", len(payload))
		return []model.Event{malformed(ev, "", msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}
	if payload[0] != startByte {
		msg := fmt.Sprintf("start octet is 0x%02x, not 0x68", payload[0])
		return []model.Event{malformed(ev, "", msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	length := payload[1]
	control := payload[2:apciLen]
	format := classify(control[0])
	setAttr(&ev, "apci_format", format.String())

	// The framer sized this slice from the length octet, so a mismatch here
	// means a caller handed over something else.
	if total := 2 + int(length); total != len(payload) {
		msg := fmt.Sprintf("APDU declares %d octets, %d present", total, len(payload))
		return []model.Event{malformed(ev, format.String(), msg)},
			fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	switch format {
	case formatU:
		return d.parseU(ev, control)
	case formatS:
		return d.parseS(ev, control)
	default:
		return d.parseI(ctx, ev, control, payload[apciLen:])
	}
}

// parseU decodes an unnumbered control function: starting, stopping and
// testing the data transfer of an established connection.
func (d *Dissector) parseU(ev model.Event, control []byte) ([]model.Event, error) {
	name, known := uFunctions[control[0]]
	if !known {
		// The three functions are single bit pairs; anything else is either a
		// combination the standard forbids or a reserved value.
		msg := fmt.Sprintf("control function 0x%02x is not one of STARTDT, STOPDT or TESTFR", control[0])
		ev.Operation = "U_FORMAT"
		return []model.Event{malformed(ev, "U", msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	ev.Operation = name
	ev.Class = uClass(control[0])
	setAttr(&ev, "u_function", name)
	// act is issued by the station that wants the transfer started, stopped or
	// tested; con comes back from the other one.
	if strings.HasSuffix(name, "_act") {
		ev.Direction = model.DirRequest
	} else {
		ev.Direction = model.DirResponse
	}
	if control[1]|control[2]|control[3] != 0 {
		addAnomaly(&ev, "reserved_control_octets_set")
	}
	return []model.Event{ev}, nil
}

// parseS decodes a numbered supervisory function: an acknowledgement of the
// information frames received so far, sent when there is no data to carry one.
func (d *Dissector) parseS(ev model.Event, control []byte) ([]model.Event, error) {
	ev.Operation = "SUPERVISORY"
	setAttr(&ev, "recv_seq", strconv.Itoa(int(sequenceNumber(control[2], control[3]))))
	if control[1] != 0 {
		addAnomaly(&ev, "reserved_control_octets_set")
	}
	return []model.Event{ev}, nil
}

// parseI decodes an information transfer frame: the sequence numbers of the
// APCI and the ASDU that follows it.
func (d *Dissector) parseI(ctx *dissect.FlowContext, ev model.Event, control, body []byte) ([]model.Event, error) {
	send := sequenceNumber(control[0], control[1])
	recv := sequenceNumber(control[2], control[3])
	setAttr(&ev, "send_seq", strconv.Itoa(int(send)))
	setAttr(&ev, "recv_seq", strconv.Itoa(int(recv)))
	ev.TransactionID = model.Ptr(uint32(send))

	// A send sequence number that skips means APDUs between the two were lost
	// from the capture or never sent, which is how an injected frame shows up.
	st := state(ctx)
	if st.haveSend && send != st.expectSend {
		setAttr(&ev, "expected_send_seq", strconv.Itoa(int(st.expectSend)))
		addAnomaly(&ev, "send_seq_gap")
	}
	st.expectSend = (send + 1) % seqModulus
	st.haveSend = true

	if len(body) < asduHeaderLen {
		msg := fmt.Sprintf("information frame carries %d ASDU octets, fewer than the %d octet header",
			len(body), asduHeaderLen)
		ev.Operation = "I_FORMAT"
		return []model.Event{malformed(ev, "I", msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	a := decodeASDU(body)
	describeASDU(&ev, a)

	objects, used, err := walkObjects(a)
	if err != nil {
		return []model.Event{malformed(ev, "I", err.Error())},
			fmt.Errorf("%w: %s", dissect.ErrMalformed, err.Error())
	}
	describeObjects(&ev, a, objects, used)
	return []model.Event{ev}, nil
}

// decodeASDU reads the six octet ASDU header. The caller has checked the
// length.
func decodeASDU(body []byte) asdu {
	vsq := body[1]
	cot := body[2]
	return asdu{
		typeID:   body[0],
		info:     typeID(body[0]),
		sequence: vsq&0x80 != 0,
		count:    vsq & 0x7f,
		cause:    cot & 0x3f,
		negative: cot&0x40 != 0,
		test:     cot&0x80 != 0,
		origin:   body[3],
		common:   binary.LittleEndian.Uint16(body[4:6]),
		elements: body[asduHeaderLen:],
	}
}

// describeASDU records the header fields: what this ASDU is, why it was sent
// and which station it concerns.
func describeASDU(ev *model.Event, a asdu) {
	ev.Operation = a.info.name
	ev.FunctionCode = int(a.typeID)
	ev.Class = a.info.class
	setAttr(ev, "type_id", strconv.Itoa(int(a.typeID)))
	setAttr(ev, "cause", causeName(a.cause))
	if a.origin != 0 {
		setAttr(ev, "originator", strconv.Itoa(int(a.origin)))
	}
	if _, known := types[a.typeID]; !known {
		addAnomaly(ev, "unknown_type_identification")
	}

	// A cause of transmission says more about who sent an ASDU than the ports
	// do: only a controlling station activates, only a controlled station
	// confirms.
	if dir, decided := causeDirection(a.cause); decided {
		ev.Direction = dir
	}

	if a.test {
		// Test ASDUs are for commissioning. One in service traffic is worth
		// seeing, so it is recorded rather than quietly dropped.
		setAttr(ev, "test", "true")
	}
	if a.negative {
		setAttr(ev, "negative", "true")
		switch a.cause {
		case cotActivationCon, cotDeactivateCon, cotActivationEnd:
			// The controlled station refusing a command is the protocol's own
			// error reply, so it belongs in the field rules count.
			ev.Exception = "negative_confirmation"
		case cotActivation, cotDeactivation:
			// The standard leaves P/N undefined in the control direction, so a
			// master setting it is either a bug or a crafted frame.
			addAnomaly(ev, "negative_bit_in_control_direction")
		}
	}

	switch a.cause {
	case cotUnknownType, cotUnknownCause, cotUnknownAddress, cotUnknownIOA:
		// The peer could not make sense of an ASDU it received. Which field it
		// named says whether the two ends disagree about addressing or about
		// what the device supports at all.
		ev.Exception = causeName(a.cause)
		addAnomaly(ev, "asdu_rejected")
	}

	switch a.common {
	case globalAddress:
		setAttr(ev, "address_kind", "global")
		setAttr(ev, "broadcast", "true")
	case 0:
		setAttr(ev, "address_kind", "not_used")
	default:
		ev.UnitID = model.Ptr(a.common)
	}
}

func setAttr(ev *model.Event, key, value string) {
	if ev.Attrs == nil {
		ev.Attrs = make(map[string]string, 8)
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

// malformed marks an event as undecodable. An operation is given so that a
// frame that failed before its type was readable still says which format it
// claimed to be.
func malformed(ev model.Event, format, reason string) model.Event {
	if ev.Operation == "" {
		if format == "" {
			ev.Operation = "APCI"
		} else {
			ev.Operation = format + "_FORMAT"
		}
	}
	ev.Malformed = true
	ev.Error = reason
	return ev
}
