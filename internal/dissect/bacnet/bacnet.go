// Package bacnet dissects BACnet/IP, the protocol of building automation:
// air handling, chillers, lighting, access control and fire panels, which in
// an industrial plant sit on the same cable as the process control network
// more often than anyone intends.
//
// Three layers stack inside one UDP datagram. The virtual link layer (BVLL)
// says whether this is an ordinary message, a broadcast, or one a BBMD
// forwarded on someone else's behalf — and when it forwarded one, which
// device it really came from. The network layer routes between BACnet
// networks and carries the router discovery messages. The application layer
// is where the meaning is: a service choice, the object it addresses and the
// property of it being read or written.
//
// What makes BACnet unusually good material for a passive inventory is that
// its answers are self-describing. A reply echoes the object identifier and
// the property identifier it is answering for, so a device reading as
// "vendor-name: Johnson Controls, model-name: MS-NAE4510-2" can be
// inventoried from the answers alone, with no request to pair them with. An
// i-Am gives the same for free, unasked, to the whole segment.
//
// Nothing in BACnet authenticates anything. The password on
// reinitializeDevice and deviceCommunicationControl travels in the clear, and
// those two services stop a device or silence it; this dissector records that
// a password was sent and never the value, the same restraint the MMS
// association layer gets.
package bacnet

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/model"
)

// DefaultPort is the registered BACnet/IP port. Devices are also configured
// on 47809 to 47823 when several BACnet networks share one IP subnet, which
// is what the extra ports in otinv.yaml are for.
const DefaultPort = 47808

const (
	// bvlcHeaderLen is the type, the function and the length.
	bvlcHeaderLen = 4

	// forwardedAddressLen is the B/IP address of the device a BBMD forwarded
	// for: four octets of address and two of port.
	forwardedAddressLen = 6

	// maxListedProperties caps how many properties one event names. A read
	// of a whole device asks for dozens; the operation is what the event is
	// for, and the flow view holds the detail.
	maxListedProperties = 8
)

// Dissector decodes BACnet/IP. It holds no mutable state.
type Dissector struct{}

// New returns a BACnet/IP dissector.
func New() *Dissector { return &Dissector{} }

func init() {
	dissect.Register(New(), dissect.UDPPorts(DefaultPort))
}

// Name implements dissect.Dissector.
func (*Dissector) Name() string { return "bacnet" }

// Tier implements dissect.Dissector.
func (*Dissector) Tier() int { return 1 }

// PDULen implements dissect.Framer. The virtual link layer declares the
// length of the whole message, header included.
func (*Dissector) PDULen(buf []byte) (int, error) {
	if len(buf) < 1 {
		return 0, dissect.ErrNeedMore
	}
	if buf[0] != bvlcTypeBACnetIP {
		return 0, fmt.Errorf("%w: BVLL type is 0x%s, not 0x81", dissect.ErrMalformed, hex8(buf[0]))
	}
	if len(buf) < bvlcHeaderLen {
		return 0, dissect.ErrNeedMore
	}
	total := int(binary.BigEndian.Uint16(buf[2:4]))
	if total < bvlcHeaderLen {
		return 0, fmt.Errorf("%w: BVLL length %d is shorter than its own header",
			dissect.ErrMalformed, total)
	}
	if len(buf) < total {
		return 0, dissect.ErrNeedMore
	}
	return total, nil
}

// Probe implements dissect.Dissector.
//
// The first octet is fixed at 0x81 for BACnet/IP, which is most of the
// evidence; beyond that there is a known function, a length that accounts for
// the datagram, and a network layer version of 1.
func (*Dissector) Probe(_ *dissect.FlowContext, payload []byte) int {
	if len(payload) < bvlcHeaderLen || payload[0] != bvlcTypeBACnetIP {
		return 0
	}
	fn := payload[1]
	if _, known := bvlcFunctions[fn]; !known {
		return 0
	}
	score := 55
	if total := int(binary.BigEndian.Uint16(payload[2:4])); total == len(payload) {
		score += 25
	} else if total < bvlcHeaderLen || total > len(payload) {
		return 0
	}
	if carriesNPDU(fn) {
		body := payload[bvlcHeaderLen:]
		if fn == bvlcForwardedNPDU && len(body) >= forwardedAddressLen {
			body = body[forwardedAddressLen:]
		}
		if len(body) >= 2 && body[0] == 1 {
			// The network layer version has been 1 since the standard was
			// published and is the one field a BACnet message cannot vary.
			score += 20
		} else {
			return 0
		}
	} else {
		score += 10
	}
	return min(score, 100)
}

// Parse implements dissect.Dissector. One datagram is one BVLL message.
func (d *Dissector) Parse(ctx *dissect.FlowContext, payload []byte) ([]model.Event, error) {
	ev := model.Event{
		CaptureID:    ctx.CaptureID,
		PacketIndex:  ctx.PacketIndex,
		Timestamp:    ctx.Timestamp,
		Flow:         ctx.Flow,
		Protocol:     "bacnet",
		Direction:    ctx.Direction,
		ServerPort:   ctx.ServerPort,
		Operation:    "BVLL",
		FunctionCode: -1,
		Class:        model.ClassOther,
	}
	if ev.Direction == "" {
		ev.Direction = model.DirUnknown
	}

	if len(payload) < bvlcHeaderLen {
		msg := fmt.Sprintf("%d octets cannot hold a BVLL header", len(payload))
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}
	if payload[0] != bvlcTypeBACnetIP {
		msg := fmt.Sprintf("BVLL type is 0x%s, not 0x81", hex8(payload[0]))
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	fn := payload[1]
	declared := int(binary.BigEndian.Uint16(payload[2:4]))
	name := bvlcName(fn)
	ev.Operation = name
	setAttr(&ev, "bvlc_function", name)
	if _, known := bvlcFunctions[fn]; !known {
		addAnomaly(&ev, "unknown_bvlc_function")
	}
	if declared != len(payload) {
		msg := fmt.Sprintf("BVLL declares %d octets, %d present", declared, len(payload))
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}
	body := payload[bvlcHeaderLen:]

	switch fn {
	case bvlcResult:
		if len(body) < 2 {
			msg := "a BVLC-Result with no result code"
			return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
		}
		code := binary.BigEndian.Uint16(body[:2])
		result := bvlcResultName(code)
		setAttr(&ev, "bvlc_result", result)
		ev.Direction = model.DirResponse
		if code != 0 {
			// The virtual link layer refusing: a device declining to be a
			// broadcast relay, or to register a foreign device.
			ev.Exception = result
		}
		return []model.Event{ev}, nil

	case bvlcRegisterForeign:
		// A device outside the broadcast domain asking a BBMD to forward
		// broadcasts to it, which is how a BACnet client reaches a plant
		// network from another subnet.
		if len(body) >= 2 {
			setAttr(&ev, "time_to_live", strconv.Itoa(int(binary.BigEndian.Uint16(body[:2]))))
		}
		ev.Class = model.ClassOther
		ev.Direction = model.DirRequest
		return []model.Event{ev}, nil

	case bvlcForwardedNPDU:
		if len(body) < forwardedAddressLen {
			msg := "a Forwarded-NPDU with no originating address"
			return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
		}
		// The address the message really came from, which the IP header no
		// longer carries: without this the inventory would credit the
		// forwarding device with everything behind it.
		origin := net.IP(body[0:4]).String()
		setAttr(&ev, "forwarded_from", origin+":"+
			strconv.Itoa(int(binary.BigEndian.Uint16(body[4:6]))))
		body = body[forwardedAddressLen:]
	}

	if !carriesNPDU(fn) {
		// A table read or write of the virtual link layer itself. The tables
		// say which devices relay broadcasts for which networks, which is
		// topology rather than an operation on a device.
		if len(body) > 0 {
			setAttr(&ev, "body_bytes", strconv.Itoa(len(body)))
		}
		return []model.Event{ev}, nil
	}

	apdu, err := d.describeNPDU(&ev, body)
	if err != nil {
		return []model.Event{malformed(ev, err.Error())}, fmt.Errorf("%w: %s", dissect.ErrMalformed, err.Error())
	}
	if apdu == nil {
		// A network layer message: router discovery rather than an
		// application service.
		return []model.Event{ev}, nil
	}
	if err := d.describeAPDU(&ev, apdu); err != nil {
		return []model.Event{malformed(ev, err.Error())}, fmt.Errorf("%w: %s", dissect.ErrMalformed, err.Error())
	}
	return []model.Event{ev}, nil
}

// describeNPDU reads the network layer and returns the application PDU, or
// nil when this message is a network layer one of its own
// (ASHRAE 135, clause 6.2).
func (d *Dissector) describeNPDU(ev *model.Event, b []byte) ([]byte, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("%d octets cannot hold an NPDU header", len(b))
	}
	if b[0] != 1 {
		return nil, fmt.Errorf("network layer version is %d, not 1", b[0])
	}
	control := b[1]
	off := 2

	if control&0x20 != 0 {
		// A destination on another BACnet network, which says this message
		// is routed rather than local.
		if off+3 > len(b) {
			return nil, fmt.Errorf("the destination address runs past the NPDU")
		}
		dnet := binary.BigEndian.Uint16(b[off : off+2])
		dlen := int(b[off+2])
		off += 3
		if off+dlen > len(b) {
			return nil, fmt.Errorf("the destination address declares %d octets, %d present",
				dlen, len(b)-off)
		}
		setAttr(ev, "destination_network", strconv.Itoa(int(dnet)))
		if dlen == 0 {
			// Length zero is a broadcast to every device on that network.
			setAttr(ev, "destination", "broadcast")
		} else {
			setAttr(ev, "destination_address", hexString(b[off:off+dlen]))
		}
		off += dlen
	}
	if control&0x08 != 0 {
		if off+3 > len(b) {
			return nil, fmt.Errorf("the source address runs past the NPDU")
		}
		snet := binary.BigEndian.Uint16(b[off : off+2])
		slen := int(b[off+2])
		off += 3
		if off+slen > len(b) {
			return nil, fmt.Errorf("the source address declares %d octets, %d present",
				slen, len(b)-off)
		}
		setAttr(ev, "source_network", strconv.Itoa(int(snet)))
		if slen > 0 {
			setAttr(ev, "source_address", hexString(b[off:off+slen]))
		}
		off += slen
	}
	if control&0x20 != 0 {
		if off >= len(b) {
			return nil, fmt.Errorf("a routed NPDU with no hop count")
		}
		setAttr(ev, "hop_count", strconv.Itoa(int(b[off])))
		off++
	}
	if control&0x04 != 0 {
		setAttr(ev, "expecting_reply", "true")
	}
	if priority := control & 0x03; priority != 0 {
		// Life safety and critical equipment messages are sent at a higher
		// priority, which says what the traffic is for.
		setAttr(ev, "network_priority", strconv.Itoa(int(priority)))
	}

	if control&0x80 == 0 {
		return b[off:], nil
	}

	// A network layer message: router discovery, or the security messages
	// added in the 2012 revision.
	if off >= len(b) {
		return nil, fmt.Errorf("a network layer message with no type")
	}
	msgType := b[off]
	off++
	ev.Operation = networkMessageName(msgType)
	ev.FunctionCode = int(msgType)
	setAttr(ev, "network_message", ev.Operation)
	if msgType >= 0x80 {
		// A vendor's own network layer message, which carries the vendor
		// identifier so that two of them cannot be confused.
		if off+2 <= len(b) {
			setAttr(ev, "vendor_id", strconv.Itoa(int(binary.BigEndian.Uint16(b[off:off+2]))))
			off += 2
		}
	}
	switch msgType {
	case 0x00, 0x01, 0x02, 0x05:
		// Each carries the list of networks it asks about or answers for.
		var nets []string
		for i := off; i+1 < len(b) && len(nets) < maxListedProperties; i += 2 {
			nets = append(nets, strconv.Itoa(int(binary.BigEndian.Uint16(b[i:i+2]))))
		}
		if len(nets) > 0 {
			setAttr(ev, "networks", strings.Join(nets, ","))
		}
	}
	ev.Class = model.ClassDiscovery
	return nil, nil
}

// describeAPDU reads the application layer: which service this is, which
// object it addresses and what it carries (ASHRAE 135, clause 20.1).
func (d *Dissector) describeAPDU(ev *model.Event, b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("an NPDU with no application PDU")
	}
	pduType := b[0] >> 4
	typeName, known := pduTypes[pduType]
	if !known {
		typeName = "PDU_" + strconv.Itoa(int(pduType))
		addAnomaly(ev, "unknown_pdu_type")
	}
	setAttr(ev, "apdu_type", typeName)

	switch pduType {
	case pduConfirmedRequest:
		return d.confirmedRequest(ev, b)
	case pduUnconfirmedRequest:
		return d.unconfirmedRequest(ev, b)
	case pduSimpleACK:
		if len(b) < 3 {
			return fmt.Errorf("a SimpleACK of %d octets", len(b))
		}
		ev.Direction = model.DirResponse
		ev.TransactionID = model.Ptr(uint32(b[1]))
		info, _ := confirmedService(b[2])
		ev.Operation = info.name
		ev.Class = info.class
		ev.FunctionCode = int(b[2])
		setAttr(ev, "service", info.name)
		return nil
	case pduComplexACK:
		return d.complexACK(ev, b)
	case pduSegmentACK:
		if len(b) < 4 {
			return fmt.Errorf("a SegmentACK of %d octets", len(b))
		}
		ev.Direction = model.DirResponse
		ev.Operation = "SegmentACK"
		ev.TransactionID = model.Ptr(uint32(b[2]))
		return nil
	case pduError:
		return d.errorPDU(ev, b)
	case pduReject, pduAbort:
		if len(b) < 3 {
			return fmt.Errorf("a %s of %d octets", typeName, len(b))
		}
		ev.Direction = model.DirResponse
		ev.Operation = typeName
		ev.TransactionID = model.Ptr(uint32(b[1]))
		table := rejectReasons
		if pduType == pduAbort {
			table = abortReasons
		}
		reason, ok := table[b[2]]
		if !ok {
			reason = "reason-" + strconv.Itoa(int(b[2]))
		}
		// A device refusing to look at a request at all, which separates a
		// client speaking a service the device does not have from one whose
		// request was malformed.
		ev.Exception = reason
		setAttr(ev, "reason", reason)
		return nil
	default:
		ev.Operation = typeName
		return nil
	}
}

// confirmedRequest reads a confirmed service request: the one APDU shape that
// carries segmentation, since a long request has to be split.
func (d *Dissector) confirmedRequest(ev *model.Event, b []byte) error {
	if len(b) < 4 {
		return fmt.Errorf("a Confirmed-Request of %d octets", len(b))
	}
	segmented := b[0]&0x08 != 0
	ev.Direction = model.DirRequest
	ev.TransactionID = model.Ptr(uint32(b[2]))
	off := 3
	if segmented {
		if len(b) < 6 {
			return fmt.Errorf("a segmented Confirmed-Request of %d octets", len(b))
		}
		setAttr(ev, "segment", strconv.Itoa(int(b[3])))
		setAttr(ev, "window_size", strconv.Itoa(int(b[4])))
		off = 5
	}
	if off >= len(b) {
		return fmt.Errorf("a Confirmed-Request with no service choice")
	}
	choice := b[off]
	info, named := confirmedService(choice)
	ev.Operation = info.name
	ev.Class = info.class
	ev.FunctionCode = int(choice)
	setAttr(ev, "service", info.name)
	if !named {
		addAnomaly(ev, "unknown_service")
	}
	if b[0]&0x02 != 0 {
		setAttr(ev, "segmented_response_accepted", "true")
	}
	return d.describeService(ev, choice, false, b[off+1:])
}

// unconfirmedRequest reads a service nobody answers: the discovery and
// notification traffic a BACnet segment is full of.
func (d *Dissector) unconfirmedRequest(ev *model.Event, b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("an Unconfirmed-Request of %d octets", len(b))
	}
	choice := b[1]
	info, named := unconfirmedService(choice)
	ev.Operation = info.name
	ev.Class = info.class
	ev.FunctionCode = int(choice)
	setAttr(ev, "service", info.name)
	if !named {
		addAnomaly(ev, "unknown_service")
	}
	// An i-Am or i-Have is a device describing itself unasked, which is an
	// answer in substance whatever the protocol calls it.
	switch choice {
	case svcIAm, svcIHave:
		ev.Direction = model.DirResponse
	default:
		ev.Direction = model.DirRequest
	}
	return d.describeService(ev, choice, true, b[2:])
}

// complexACK reads an answer that carries data. It echoes the object and the
// property it is answering for, which is what lets a passive observer read a
// device's own description without seeing the question.
func (d *Dissector) complexACK(ev *model.Event, b []byte) error {
	if len(b) < 3 {
		return fmt.Errorf("a ComplexACK of %d octets", len(b))
	}
	ev.Direction = model.DirResponse
	ev.TransactionID = model.Ptr(uint32(b[1]))
	off := 2
	if b[0]&0x08 != 0 {
		if len(b) < 5 {
			return fmt.Errorf("a segmented ComplexACK of %d octets", len(b))
		}
		setAttr(ev, "segment", strconv.Itoa(int(b[2])))
		setAttr(ev, "window_size", strconv.Itoa(int(b[3])))
		off = 4
	}
	if off >= len(b) {
		return fmt.Errorf("a ComplexACK with no service choice")
	}
	choice := b[off]
	info, named := confirmedService(choice)
	ev.Operation = info.name
	ev.Class = info.class
	ev.FunctionCode = int(choice)
	setAttr(ev, "service", info.name)
	if !named {
		addAnomaly(ev, "unknown_service")
	}
	return d.describeService(ev, choice, false, b[off+1:])
}

// errorPDU reads a device's refusal, whose class and code separate a client
// asking for something that does not exist from one asking for something it
// may not have.
func (d *Dissector) errorPDU(ev *model.Event, b []byte) error {
	if len(b) < 3 {
		return fmt.Errorf("an Error PDU of %d octets", len(b))
	}
	ev.Direction = model.DirResponse
	ev.TransactionID = model.Ptr(uint32(b[1]))
	choice := b[2]
	info, _ := confirmedService(choice)
	ev.Operation = info.name
	ev.Class = info.class
	ev.FunctionCode = int(choice)
	setAttr(ev, "service", info.name)

	tags, err := readTags(b[3:])
	if err != nil && len(tags) == 0 {
		return err
	}
	var class, code uint32
	var got int
	for _, t := range tags {
		if t.context || t.opening || t.closing || t.number != appEnumerated {
			continue
		}
		v, ok := unsigned(t.value)
		if !ok {
			continue
		}
		switch got {
		case 0:
			class = v
		case 1:
			code = v
		}
		got++
		if got == 2 {
			break
		}
	}
	if got == 2 {
		text := errorText(class, code)
		ev.Exception = text
		setAttr(ev, "error", text)
	}
	return nil
}

// describeService reads what a service names and carries. Only the services
// whose shape this project has use for are entered; the rest are left as the
// name and classification of the service itself.
func (d *Dissector) describeService(ev *model.Event, choice uint8, unconfirmed bool, body []byte) error {
	tags, err := readTags(body)
	if err != nil {
		// The tags are what the service carries, not what it is. A service
		// whose arguments do not decode is still a known service from a
		// known device, so the event keeps what it has and says what broke.
		addAnomaly(ev, "service_arguments_unreadable")
		setAttr(ev, "argument_error", err.Error())
		return nil
	}

	if unconfirmed {
		switch choice {
		case svcIAm:
			d.describeIAm(ev, tags)
		case svcIHave:
			d.describeIHave(ev, tags)
		case svcWhoIs, svcWhoHas:
			d.describeWho(ev, tags)
		case svcTimeSynchronization, svcUTCTimeSynchronization:
			setAttr(ev, "sets_clock", "true")
		case svcUnconfirmedCOVNotify, svcUnconfirmedEventNotify:
			d.describeNotification(ev, tags)
		}
		return nil
	}

	switch choice {
	case svcReadProperty, svcWriteProperty:
		d.describeProperty(ev, tags)
	case svcReadPropertyMultiple, svcWritePropertyMultiple:
		d.describePropertyMultiple(ev, tags)
	case svcSubscribeCOV, svcSubscribeCOVProperty:
		d.describeSubscribe(ev, tags)
	case svcReinitializeDevice:
		d.describeReinitialize(ev, tags)
	case svcDeviceCommControl:
		d.describeCommControl(ev, tags)
	case svcAtomicReadFile, svcAtomicWriteFile:
		if t, ok := firstApplication(tags); ok && t.number == appObjectID {
			setAttr(ev, "object", renderValue(t))
		}
	case svcCreateObject, svcDeleteObject:
		if v, ok := contextValue(tags, 0); ok {
			if ot, inst, ok := objectID(v); ok {
				setObject(ev, ot, inst)
			}
		}
	case svcConfirmedCOVNotify, svcConfirmedEventNotify:
		d.describeNotification(ev, tags)
	}
	return nil
}

// describeProperty reads a readProperty or writeProperty: the object, the
// property, and in an answer or a write the value itself.
func (d *Dissector) describeProperty(ev *model.Event, tags []tag) {
	if v, ok := contextValue(tags, 0); ok {
		if ot, inst, ok := objectID(v); ok {
			setObject(ev, ot, inst)
		}
	}
	var property uint32
	havePropery := false
	if v, ok := contextValue(tags, 1); ok {
		if id, ok := unsigned(v); ok {
			property, havePropery = id, true
			setAttr(ev, "property", propertyName(id))
			ev.Address = model.Ptr(id)
		}
	}
	if v, ok := contextValue(tags, 2); ok {
		if idx, ok := unsigned(v); ok {
			setAttr(ev, "array_index", strconv.FormatUint(uint64(idx), 10))
		}
	}
	// The value sits in the constructed tag 3 of both a write and an answer.
	if inner, ok := group(tags, 3); ok {
		if t, ok := firstApplication(inner); ok {
			value := renderValue(t)
			setAttr(ev, "value", value)
			if t.number == appCharacterString {
				// BACnet allows four character sets, and which one a device
				// uses is part of knowing the device: the Johnson Controls
				// engine in the sample captures answers in UCS-2 where most
				// answer in UTF-8.
				if _, charset, ok := characterString(t.value); ok && charset != "utf8" {
					setAttr(ev, "value_charset", charset)
				}
			}
			if havePropery {
				d.recordIdentity(ev, property, t, value)
			}
		}
	}
	if v, ok := contextValue(tags, 4); ok {
		if priority, ok := unsigned(v); ok {
			// The priority a write claims in the command array: 1 to 6 are
			// the life safety and manual operator levels, which an ordinary
			// supervisory write has no business using.
			setAttr(ev, "write_priority", strconv.FormatUint(uint64(priority), 10))
		}
	}
}

// describePropertyMultiple reads the list form, which is how a client reads a
// whole device in one exchange: a sequence of objects, each with its own list
// of properties and, in an answer, their values.
func (d *Dissector) describePropertyMultiple(ev *model.Event, tags []tag) {
	var (
		objects    []string
		properties []string
		count      int
		depth      int
		current    uint32
		haveProp   bool
	)
	for i, t := range tags {
		switch {
		case t.opening:
			depth++
			continue
		case t.closing:
			depth--
			continue
		}
		switch {
		case t.context && t.number == 0 && depth == 0:
			// The object this group of properties belongs to.
			if ot, inst, ok := objectID(t.value); ok {
				if len(objects) < maxListedProperties {
					objects = append(objects, objectName(ot)+":"+strconv.FormatUint(uint64(inst), 10))
				}
				if len(objects) == 1 {
					setObject(ev, ot, inst)
				}
			}
		case t.context && (t.number == 0 || t.number == 2) && depth > 0:
			// A property identifier: tag 0 in a request's list, tag 2 in an
			// answer's result.
			if id, ok := unsigned(t.value); ok {
				count++
				current, haveProp = id, true
				if len(properties) < maxListedProperties {
					properties = append(properties, propertyName(id))
				}
			}
		case !t.context && haveProp:
			// A value following the property it belongs to, which is where a
			// device's own description arrives in this service.
			d.recordIdentity(ev, current, t, renderValue(t))
			haveProp = false
		}
		_ = i
	}
	if len(objects) > 0 {
		setAttr(ev, "objects", strings.Join(objects, ","))
	}
	if len(properties) > 0 {
		setAttr(ev, "properties", strings.Join(properties, ","))
	}
	if count > 0 {
		setAttr(ev, "property_count", strconv.Itoa(count))
		ev.Quantity = model.Ptr(uint32(count))
	}
}

// describeIAm reads a device announcing itself: the one message that names a
// BACnet device, its vendor and how much of an answer it can take, sent to
// the whole segment without being asked.
func (d *Dissector) describeIAm(ev *model.Event, tags []tag) {
	var values []tag
	for _, t := range tags {
		if !t.context && !t.opening && !t.closing {
			values = append(values, t)
		}
	}
	if len(values) > 0 && values[0].number == appObjectID {
		if ot, inst, ok := objectID(values[0].value); ok {
			setObject(ev, ot, inst)
			if ot == objectTypeDevice {
				setIdentity(ev, "device_instance", strconv.FormatUint(uint64(inst), 10))
			}
		}
	}
	if len(values) > 1 && values[1].number == appUnsigned {
		if v, ok := unsigned(values[1].value); ok {
			setAttr(ev, "max_apdu", strconv.FormatUint(uint64(v), 10))
		}
	}
	if len(values) > 2 && values[2].number == appEnumerated {
		if v, ok := unsigned(values[2].value); ok {
			kind, named := segmentationKinds[v]
			if !named {
				kind = "segmentation-" + strconv.FormatUint(uint64(v), 10)
			}
			setAttr(ev, "segmentation", kind)
		}
	}
	if len(values) > 3 && values[3].number == appUnsigned {
		if v, ok := unsigned(values[3].value); ok {
			setIdentity(ev, "vendor_id", strconv.FormatUint(uint64(v), 10))
			if name, ok := vendors[v]; ok {
				setIdentity(ev, "vendor_name", name)
			}
		}
	}
}

// describeIHave reads a device announcing which object it holds, which is how
// a point is found by name rather than by address.
func (d *Dissector) describeIHave(ev *model.Event, tags []tag) {
	var values []tag
	for _, t := range tags {
		if !t.context && !t.opening && !t.closing {
			values = append(values, t)
		}
	}
	if len(values) > 0 && values[0].number == appObjectID {
		if ot, inst, ok := objectID(values[0].value); ok {
			if ot == objectTypeDevice {
				setIdentity(ev, "device_instance", strconv.FormatUint(uint64(inst), 10))
			}
		}
	}
	if len(values) > 1 && values[1].number == appObjectID {
		if ot, inst, ok := objectID(values[1].value); ok {
			setObject(ev, ot, inst)
		}
	}
	if len(values) > 2 && values[2].number == appCharacterString {
		if s, _, ok := characterString(values[2].value); ok {
			setAttr(ev, "object_name", s)
		}
	}
}

// describeWho reads the filters a who-Is or who-Has carries: the range of
// device instances being asked for, or the object being looked for by name.
func (d *Dissector) describeWho(ev *model.Event, tags []tag) {
	low, hasLow := contextValue(tags, 0)
	high, hasHigh := contextValue(tags, 1)
	if hasLow && hasHigh {
		l, okl := unsigned(low)
		h, okh := unsigned(high)
		if okl && okh {
			setAttr(ev, "instance_range",
				strconv.FormatUint(uint64(l), 10)+"-"+strconv.FormatUint(uint64(h), 10))
		}
	} else {
		// No range at all asks every device on the segment to answer, which
		// is what a discovery sweep looks like.
		setAttr(ev, "instance_range", "all")
	}
	if v, ok := contextValue(tags, 2); ok {
		if ot, inst, ok := objectID(v); ok {
			setObject(ev, ot, inst)
		}
	}
	if v, ok := contextValue(tags, 3); ok {
		if s, _, ok := characterString(v); ok {
			setAttr(ev, "object_name", s)
		}
	}
}

// describeSubscribe reads a subscription, which asks a device to report a
// value from now on rather than being polled for it.
func (d *Dissector) describeSubscribe(ev *model.Event, tags []tag) {
	if v, ok := contextValue(tags, 0); ok {
		if process, ok := unsigned(v); ok {
			setAttr(ev, "subscriber_process", strconv.FormatUint(uint64(process), 10))
		}
	}
	if v, ok := contextValue(tags, 1); ok {
		if ot, inst, ok := objectID(v); ok {
			setObject(ev, ot, inst)
		}
	}
	if v, ok := contextValue(tags, 3); ok {
		if lifetime, ok := unsigned(v); ok {
			setAttr(ev, "lifetime", strconv.FormatUint(uint64(lifetime), 10))
		}
	}
}

// describeNotification reads a change of value or event report: which object
// changed and which device is reporting it.
func (d *Dissector) describeNotification(ev *model.Event, tags []tag) {
	if v, ok := contextValue(tags, 1); ok {
		if ot, inst, ok := objectID(v); ok {
			if ot == objectTypeDevice {
				setAttr(ev, "initiating_device", strconv.FormatUint(uint64(inst), 10))
			}
		}
	}
	if v, ok := contextValue(tags, 2); ok {
		if ot, inst, ok := objectID(v); ok {
			setObject(ev, ot, inst)
		}
	}
}

// describeReinitialize reads a reinitializeDevice: which restart is being
// asked for, and whether a password came with it.
func (d *Dissector) describeReinitialize(ev *model.Event, tags []tag) {
	if v, ok := contextValue(tags, 0); ok {
		if state, ok := unsigned(v); ok {
			name, named := reinitStates[state]
			if !named {
				name = "state-" + strconv.FormatUint(uint64(state), 10)
			}
			setAttr(ev, "reinitialize_state", name)
			ev.Operation = "reinitializeDevice." + name
		}
	}
	d.notePassword(ev, tags, 1)
}

// describeCommControl reads a deviceCommunicationControl: how long the device
// is to stop talking, and whether a password came with it.
func (d *Dissector) describeCommControl(ev *model.Event, tags []tag) {
	if v, ok := contextValue(tags, 0); ok {
		if minutes, ok := unsigned(v); ok {
			setAttr(ev, "duration_minutes", strconv.FormatUint(uint64(minutes), 10))
		}
	}
	if v, ok := contextValue(tags, 1); ok {
		if state, ok := unsigned(v); ok {
			name, named := commControlStates[state]
			if !named {
				name = "state-" + strconv.FormatUint(uint64(state), 10)
			}
			setAttr(ev, "communication", name)
			ev.Operation = "deviceCommunicationControl." + name
		}
	}
	d.notePassword(ev, tags, 2)
}

// notePassword records that a service carried a password and never the value.
//
// BACnet sends it in the clear, so this tool must not become the place a
// captured password ends up stored and rendered — the same restraint the MMS
// association layer gets.
func (d *Dissector) notePassword(ev *model.Event, tags []tag, number uint8) {
	if _, ok := contextValue(tags, number); ok {
		setAttr(ev, "password", "sent")
	}
}

// recordIdentity keeps the value of a property that describes the device.
func (d *Dissector) recordIdentity(ev *model.Event, property uint32, t tag, value string) {
	if ev.Attrs["object_type"] != "device" {
		// Only the device object describes the device. A model name on an
		// air handler names the air handler.
		return
	}
	switch property {
	case propObjectIdentifier:
		if t.number == appObjectID {
			if ot, inst, ok := objectID(t.value); ok && ot == objectTypeDevice {
				setIdentity(ev, "device_instance", strconv.FormatUint(uint64(inst), 10))
			}
		}
		return
	case propVendorIdentifier:
		if v, ok := unsigned(t.value); ok && t.number == appUnsigned {
			setIdentity(ev, "vendor_id", strconv.FormatUint(uint64(v), 10))
			if name, ok := vendors[v]; ok {
				setIdentity(ev, "vendor_name", name)
			}
		}
		return
	}
	field, wanted := identityProperties[property]
	if !wanted || t.number != appCharacterString || value == "" {
		return
	}
	setIdentity(ev, field, value)
}

func setObject(ev *model.Event, objectType uint16, instance uint32) {
	setAttr(ev, "object", objectName(objectType)+":"+strconv.FormatUint(uint64(instance), 10))
	setAttr(ev, "object_type", objectName(objectType))
	setAttr(ev, "object_instance", strconv.FormatUint(uint64(instance), 10))
	if ev.UnitID == nil && objectType == objectTypeDevice && instance <= 0xffff {
		// The device instance is the nearest thing BACnet has to a unit
		// identifier: which of the devices behind this address the operation
		// was for. The instance of a point is not that, so an air handler's
		// analog input does not end up in the unit column.
		ev.UnitID = model.Ptr(uint16(instance))
	}
}

func hexString(b []byte) string {
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, hex8(c)...)
	}
	return string(out)
}

func setAttr(ev *model.Event, key, value string) {
	if value == "" {
		return
	}
	if ev.Attrs == nil {
		ev.Attrs = make(map[string]string, 8)
	}
	ev.Attrs[key] = value
}

func setIdentity(ev *model.Event, key, value string) {
	if value == "" {
		return
	}
	if ev.Identity == nil {
		ev.Identity = make(map[string]string, 8)
	}
	ev.Identity[key] = value
}

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

func malformed(ev model.Event, reason string) model.Event {
	ev.Malformed = true
	ev.Error = reason
	return ev
}
