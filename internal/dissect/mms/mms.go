// Package mms dissects IEC 61850 MMS, the client/server protocol a control
// centre reads substation data with and an engineer configures an IED over.
//
// MMS is ISO 9506 carried on the full OSI upper stack: TPKT on TCP port 102,
// then COTP, then the ISO 8327-1 session layer, the ISO 8823 presentation
// layer and the ISO 8650-1 association control service element, with
// everything above COTP encoded in ASN.1 BER. All of it has to be walked to
// reach the operation, and the walk is worth making: the association layer
// says which authentication the client offered and whether the server
// accepted it, and the service layer names the object being read or written
// as a full IEC 61850 reference — logical device, logical node, functional
// constraint, data object, attribute.
//
// Port 102 also carries S7comm and S7comm-plus, and the COTP connection
// request is the same for all three, so this dissector defers the binding
// decision until a PDU shows which protocol the stream speaks. See
// dissect.Deferring.
package mms

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/ber"
	"github.com/rom/otinv/internal/model"
)

// DefaultPort is ISO-on-TCP, which IEC 61850-8-1 uses for MMS.
const DefaultPort = 102

// TPKT framing (RFC 1006).
const (
	tpktVersion   = 0x03
	tpktHeaderLen = 4

	// minFrameLen is a TPKT header, a COTP length indicator and a PDU type.
	minFrameLen = tpktHeaderLen + 2

	// maxPDVs caps how many presentation data values one APDU may yield. One
	// is the rule; a handful is conceivable; hundreds is a crafted frame.
	maxPDVs = 4
)

// Errors for the layers between COTP and MMS.
var (
	errSession      = errors.New("not a valid session PDU")
	errPresentation = errors.New("not a valid presentation PDU")
)

// Dissector decodes IEC 61850 MMS. It holds no mutable state.
type Dissector struct{}

// New returns an MMS dissector.
func New() *Dissector { return &Dissector{} }

func init() {
	dissect.Register(New(), dissect.TCPPorts(DefaultPort))
}

// Name implements dissect.Dissector.
func (*Dissector) Name() string { return "mms" }

// Tier implements dissect.Dissector.
func (*Dissector) Tier() int { return 1 }

// PDULen implements dissect.Framer. A TPKT header carries the length of the
// whole frame, itself included.
func (*Dissector) PDULen(buf []byte) (int, error) {
	if len(buf) < 1 {
		return 0, dissect.ErrNeedMore
	}
	if buf[0] != tpktVersion {
		return 0, fmt.Errorf("%w: TPKT version is %d, not 3", dissect.ErrMalformed, buf[0])
	}
	if len(buf) < tpktHeaderLen {
		return 0, dissect.ErrNeedMore
	}
	if buf[1] != 0x00 {
		return 0, fmt.Errorf("%w: TPKT reserved octet is 0x%02x, not zero",
			dissect.ErrMalformed, buf[1])
	}
	// The length field is sixteen bits, so it cannot ask for more than
	// dissect.MaxPDUSize and needs no cap of its own.
	total := int(binary.BigEndian.Uint16(buf[2:4]))
	if total < minFrameLen {
		return 0, fmt.Errorf("%w: TPKT declares %d octets, below the minimum %d",
			dissect.ErrMalformed, total, minFrameLen)
	}
	if len(buf) < total {
		return 0, dissect.ErrNeedMore
	}
	return total, nil
}

// cotpPayload returns the COTP PDU type and user data of one TPKT frame.
func cotpPayload(frame []byte) (uint8, []byte, error) {
	if len(frame) < minFrameLen {
		return 0, nil, fmt.Errorf("%w: %d octets cannot hold a COTP header",
			dissect.ErrMalformed, len(frame))
	}
	li := int(frame[tpktHeaderLen])
	if li < 1 {
		return 0, nil, fmt.Errorf("%w: COTP length indicator is zero", dissect.ErrMalformed)
	}
	// The indicator counts the header after itself, so the user data starts
	// one octet past it.
	start := tpktHeaderLen + 1 + li
	if start > len(frame) {
		return 0, nil, fmt.Errorf("%w: COTP header of %d octets runs past the %d octet frame",
			dissect.ErrMalformed, li, len(frame))
	}
	return frame[tpktHeaderLen+1], frame[start:], nil
}

// Probe implements dissect.Dissector.
//
// The score comes from what sits above COTP, never from the COTP connection
// phase: on port 102 that phase is identical for MMS and for S7comm, so
// scoring it would be guessing. A frame carrying a session PDU whose user
// data is a presentation PDU, or an MMS PDU straight on top of COTP, is
// conclusive; anything else on the port is not ours.
func (d *Dissector) Probe(_ *dissect.FlowContext, payload []byte) int {
	best := 0
	frames := 0
	for rest := payload; len(rest) > 0; {
		n, err := d.PDULen(rest)
		if err != nil {
			if errors.Is(err, dissect.ErrNeedMore) && frames > 0 {
				break
			}
			return 0
		}
		frames++
		ptype, data, err := cotpPayload(rest[:n])
		rest = rest[n:]
		if err != nil {
			return 0
		}
		if ptype != cotpData || len(data) == 0 {
			continue
		}
		switch score := payloadScore(data); score {
		case 0:
			// Something else speaks above this COTP connection. S7comm is the
			// one that matters, and claiming its stream would be worse than
			// missing ours.
			return 0
		default:
			best = max(best, score)
		}
	}
	if frames == 0 {
		return 0
	}
	return min(best, 100)
}

// payloadScore rates what sits on top of a COTP data PDU, and returns zero
// when it belongs to another protocol.
//
// The ISO upper stack is recognisable from its first octet: a session PDU type
// the standard defines. Nothing S7comm sends can be mistaken for one, since
// its payloads open with a protocol identifier of 0x32 or 0x72 and neither is
// an SPDU type. A session PDU whose user data is also a presentation PDU is
// conclusive; one whose user data is missing or unreadable still says the ISO
// stack is spoken here, which is enough to tell this stream from an S7 one.
func payloadScore(data []byte) int {
	if isMMSPDUTag(data[0]) {
		// MMS with no session, presentation or association layer at all.
		if _, err := ber.ReadOne(data); err == nil {
			return 95
		}
		return 70
	}
	if _, known := spduNames[data[0]]; !known {
		return 0
	}
	s, err := decodeSession(data)
	if err != nil {
		return 0
	}
	if len(s.userData) > 0 {
		if _, pdvs, err := decodePresentation(s.userData); err == nil && len(pdvs) > 0 {
			return 95
		}
	}
	return 85
}

// ProbeDefers implements dissect.Deferring. A stream that has shown nothing
// but COTP connection management could still be any of the protocols on port
// 102, so the decision waits for the first frame that carries data.
func (d *Dissector) ProbeDefers(payload []byte) bool {
	frames := 0
	for rest := payload; len(rest) > 0; {
		n, err := d.PDULen(rest)
		if err != nil {
			// Not TPKT at all, or not enough of it yet: nothing to wait for
			// on our account.
			return false
		}
		frames++
		ptype, data, err := cotpPayload(rest[:n])
		if err != nil {
			return false
		}
		rest = rest[n:]
		switch ptype {
		case cotpData:
			if len(data) > 0 {
				// Something has shown itself; Probe can judge it.
				return false
			}
		case cotpConnectRequest, cotpConnectConfirm, cotpDisconnectReq,
			cotpDisconnectConf, cotpError, cotpDataAck, cotpReject:
		default:
			return false
		}
	}
	return frames > 0
}

// Parse implements dissect.Dissector. It decodes one TPKT frame, which carries
// one COTP PDU and, when that is a data PDU, the stack above it.
func (d *Dissector) Parse(ctx *dissect.FlowContext, payload []byte) ([]model.Event, error) {
	base := model.Event{
		CaptureID:    ctx.CaptureID,
		PacketIndex:  ctx.PacketIndex,
		Timestamp:    ctx.Timestamp,
		Flow:         ctx.Flow,
		Protocol:     "mms",
		Direction:    ctx.Direction,
		FunctionCode: -1,
		Class:        model.ClassOther,
	}
	if base.Direction == "" {
		base.Direction = model.DirUnknown
	}

	ptype, data, err := cotpPayload(payload)
	if err != nil {
		base.Operation = "COTP"
		return []model.Event{malformed(base, err.Error())}, err
	}

	name, known := cotpNames[ptype]
	if !known {
		msg := fmt.Sprintf("COTP PDU type 0x%02x is not defined", ptype)
		base.Operation = "COTP"
		return []model.Event{malformed(base, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	if ptype != cotpData {
		ev := base
		ev.Operation = name
		setAttr(&ev, "cotp", name)
		describeConnection(&ev, ptype, payload)
		return []model.Event{ev}, nil
	}
	if len(data) == 0 {
		// An empty data PDU is a keep-alive and carries no operation.
		return nil, nil
	}

	if isMMSPDUTag(data[0]) {
		// Some stacks put MMS straight on a COTP connection, with no session,
		// presentation or association layer.
		setAttr(&base, "stack", "cotp")
		return decodeMMS(base, data)
	}
	return d.parseStack(base, data)
}

// parseStack walks the session, presentation and association layers and
// decodes whatever they carry.
func (d *Dissector) parseStack(base model.Event, data []byte) ([]model.Event, error) {
	session, err := decodeSession(data)
	if err != nil {
		base.Operation = "Session"
		return []model.Event{malformed(base, err.Error())},
			fmt.Errorf("%w: %s", dissect.ErrMalformed, err.Error())
	}
	setAttr(&base, "session", session.name)
	for k, v := range session.attrs {
		setAttr(&base, k, v)
	}
	if session.anomaly != "" {
		addAnomaly(&base, session.anomaly)
	}

	if len(session.userData) == 0 {
		// A session PDU with nothing above it: a token grant, or a release
		// whose user data the peer left out. Still proof of the association.
		ev := base
		ev.Operation = session.name
		return []model.Event{ev}, nil
	}

	kind, pdvs, err := decodePresentation(session.userData)
	setAttr(&base, "presentation", kind)
	if err != nil {
		base.Operation = session.name
		return []model.Event{malformed(base, err.Error())},
			fmt.Errorf("%w: %s", dissect.ErrMalformed, err.Error())
	}
	if len(pdvs) == 0 {
		ev := base
		ev.Operation = session.name
		return []model.Event{ev}, nil
	}
	if len(pdvs) > maxPDVs {
		addAnomaly(&base, "presentation_data_value_flood")
		pdvs = pdvs[:maxPDVs]
	}

	var out []model.Event
	var firstErr error
	for _, p := range pdvs {
		ev := base
		if p.context >= 0 {
			setAttr(&ev, "presentation_context", strconv.FormatInt(p.context, 10))
		}
		events, err := decodePDV(ev, p.data)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		out = append(out, events...)
	}
	return out, firstErr
}

// decodePDV decodes one presentation data value: either an association
// control APDU, which may itself carry an MMS PDU, or an MMS PDU.
func decodePDV(ev model.Event, data []byte) ([]model.Event, error) {
	if assoc, ok := decodeACSE(data); ok {
		setAttr(&ev, "acse", assoc.name)
		for k, v := range assoc.attrs {
			setAttr(&ev, k, v)
		}
		if assoc.attrs["result"] != "" && assoc.attrs["result"] != "accepted" {
			// A server refusing an association is the association layer's
			// only verdict, and the reason a client never gets to the data.
			addAnomaly(&ev, "association_rejected")
		}
		if len(assoc.inner) == 0 {
			ev.Operation = assoc.name
			return []model.Event{ev}, nil
		}
		return decodeMMS(ev, assoc.inner)
	}
	return decodeMMS(ev, data)
}

// decodeMMS decodes one MMS PDU.
func decodeMMS(ev model.Event, data []byte) ([]model.Event, error) {
	top, err := ber.ReadOne(data)
	if err != nil {
		if ev.Operation == "" {
			ev.Operation = "MMS"
		}
		return []model.Event{malformed(ev, err.Error())},
			fmt.Errorf("%w: %s", dissect.ErrMalformed, err.Error())
	}
	if top.Class != ber.ClassContext {
		msg := fmt.Sprintf("MMS PDU opens with %s, not a context tag", top.Tag())
		if ev.Operation == "" {
			ev.Operation = "MMS"
		}
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	kind, known := pduNames[top.Number]
	if !known {
		kind = "pdu" + utoa(top.Number)
	}
	ev.Operation = kind
	setAttr(&ev, "pdu", kind)
	if !known {
		addAnomaly(&ev, "unknown_pdu_kind")
	}

	bud := ber.NewBudget()
	switch top.Number {
	case pduConfirmedRequest, pduConfirmedResponse, pduUnconfirmed:
		describeService(&ev, top, bud)
	case pduConfirmedError:
		describeError(&ev, top, bud)
	case pduInitiateRequest, pduInitiateResponse:
		initiateDetail(&ev, top, bud)
	case pduReject:
		describeReject(&ev, top, bud)
	case pduCancelRequest, pduCancelResponse:
		if v, ok := top.Integer(); ok {
			ev.TransactionID = model.Ptr(uint32(v))
			setAttr(&ev, "invoke_id", strconv.FormatInt(v, 10))
		}
	}
	return []model.Event{ev}, nil
}

// describeService names the service a confirmed or unconfirmed PDU carries and
// the objects it addresses.
func describeService(ev *model.Event, top ber.TLV, bud *ber.Budget) {
	kids, complete := top.Descend(bud)
	if !complete {
		addAnomaly(ev, "truncated_pdu")
	}
	for _, k := range kids {
		if k.Class == ber.ClassUniversal && k.Number == ber.TagInteger {
			if v, ok := k.Integer(); ok && v >= 0 {
				ev.TransactionID = model.Ptr(uint32(v))
				setAttr(ev, "invoke_id", strconv.FormatInt(v, 10))
			}
			continue
		}
		if k.Class != ber.ClassContext {
			continue
		}

		info := service(k.Number)
		if top.Number == pduUnconfirmed {
			info = unconfirmedService(k.Number)
		}
		ev.Operation = info.name
		ev.Class = info.class
		setAttr(ev, "service", info.name)
		if k.Number <= maxServiceTag {
			ev.FunctionCode = int(k.Number)
		} else {
			// BER lets a context tag run to five figures, and the function
			// code column is where every other protocol's single-octet code
			// is shown. A number that cannot be a service is reported as
			// what it is rather than presented as one.
			setAttr(ev, "service_tag", strconv.FormatUint(uint64(k.Number), 10))
			addAnomaly(ev, "service_tag_out_of_range")
		}

		names, domain, item := addressed(top.Number, k.Number, k, bud)
		if len(names) > 0 {
			setAttr(ev, "object", names[0])
			if len(names) > 1 {
				setAttr(ev, "objects", strings.Join(names, ","))
				ev.Quantity = model.Ptr(uint32(len(names)))
			}
		}
		// The item alone only means something next to its domain; for a
		// device-wide name the object is the whole of it.
		if domain != "" {
			setAttr(ev, "domain", domain)
			setAttr(ev, "item", item)
		}
		if domain != "" {
			// In IEC 61850 the MMS domain is the logical device, which is the
			// name the substation configuration gave this server.
			setIdentity(ev, "logical_device", domain)
		}

		switch {
		case k.Number == svcIdentify && top.Number == pduConfirmedResponse:
			for field, value := range identify(k, bud) {
				setIdentity(ev, field, value)
			}
		case top.Number == pduUnconfirmed && k.Number == 0:
			if id := reportID(k, bud); id != "" {
				setAttr(ev, "report_id", id)
				if device, _, found := strings.Cut(id, "/"); found && device != "" {
					setIdentity(ev, "logical_device", device)
				}
			}
		}
		return
	}
}

// describeError records the refusal a server answered with.
func describeError(ev *model.Event, top ber.TLV, bud *ber.Budget) {
	kids, _ := top.Descend(bud)
	for _, k := range kids {
		switch {
		case k.Ctx(0):
			// A confirmed error tags its invoke id, where a request and a
			// response leave theirs untagged.
			if v, ok := k.Integer(); ok && v >= 0 {
				ev.TransactionID = model.Ptr(uint32(v))
				setAttr(ev, "invoke_id", strconv.FormatInt(v, 10))
			}
		case k.Ctx(2):
			if msg := serviceError(k, bud); msg != "" {
				ev.Exception = msg
				setAttr(ev, "error", msg)
			}
		}
	}
}

// describeReject records a PDU the peer would not look at, which is a
// disagreement about the protocol rather than a refused request.
func describeReject(ev *model.Event, top ber.TLV, bud *ber.Budget) {
	kids, _ := top.Descend(bud)
	for _, k := range kids {
		if k.Class == ber.ClassUniversal && k.Number == ber.TagInteger {
			if v, ok := k.Integer(); ok && v >= 0 {
				ev.TransactionID = model.Ptr(uint32(v))
				setAttr(ev, "invoke_id", strconv.FormatInt(v, 10))
			}
			continue
		}
		if k.Class != ber.ClassContext {
			continue
		}
		name, known := rejectReasons[k.Number]
		if !known {
			name = "reason" + utoa(k.Number)
		}
		ev.Exception = "reject/" + name
		setAttr(ev, "error", ev.Exception)
		return
	}
}

// describeConnection records the transport selectors a COTP connection names.
// They are the only addressing the transport carries, and in a substation they
// come straight out of the configuration file.
func describeConnection(ev *model.Event, ptype uint8, frame []byte) {
	if ptype != cotpConnectRequest && ptype != cotpConnectConfirm {
		return
	}
	li := int(frame[tpktHeaderLen])
	// The fixed part is the type, destination and source reference and the
	// class option; the parameters follow it.
	const fixed = 6
	if li <= fixed || tpktHeaderLen+1+li > len(frame) {
		return
	}
	params := frame[tpktHeaderLen+1+fixed : tpktHeaderLen+1+li]
	for off := 0; off+2 <= len(params); {
		code, plen := params[off], int(params[off+1])
		if off+2+plen > len(params) {
			addAnomaly(ev, "cotp_parameter_overruns_header")
			return
		}
		value := params[off+2 : off+2+plen]
		switch code {
		case paramSrcTSAP:
			setAttr(ev, "calling_tsap", fmt.Sprintf("0x%x", value))
		case paramDstTSAP:
			setAttr(ev, "called_tsap", fmt.Sprintf("0x%x", value))
		case paramTPDUSize:
			if plen == 1 && value[0] <= 16 {
				setAttr(ev, "tpdu_size", strconv.Itoa(1<<value[0]))
			}
		}
		off += 2 + plen
	}
}

func malformed(ev model.Event, reason string) model.Event {
	if ev.Operation == "" {
		ev.Operation = "MMS"
	}
	ev.Malformed = true
	ev.Error = reason
	return ev
}
