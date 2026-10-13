// Package modbus dissects Modbus/TCP, the request/response protocol defined by
// the MODBUS Application Protocol Specification v1.1b3 and carried over TCP by
// the MODBUS Messaging on TCP/IP Implementation Guide v1.0b.
//
// It is a Tier 1 dissector: it pairs function codes with their addresses and
// quantities, decodes exceptions, and extracts device identity from Report
// Server ID and Read Device Identification replies.
//
// Every length field in a frame is attacker-controlled, so nothing here trusts
// one: each field is range-checked against both the protocol maximum and the
// bytes actually present, and an undecodable PDU becomes a malformed event
// rather than a panic.
package modbus

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/model"
)

// DefaultPort is the registered Modbus/TCP port.
const DefaultPort = 502

// Frame geometry.
const (
	// mbapLen is the MBAP header: transaction id (2), protocol id (2),
	// length (2), unit id (1).
	mbapLen = 7

	// headerLen is the MBAP header plus the function code, the smallest
	// decodable Modbus/TCP frame.
	headerLen = mbapLen + 1

	// The MBAP length field counts the unit id plus the PDU, so its legal
	// range is 2 (unit id + function code) to 254 (unit id + a 253 byte PDU).
	minLengthField = 2
	maxLengthField = 254

	// maxADU is the largest legal Modbus/TCP frame: 260 bytes.
	maxADU = 6 + maxLengthField

	// maxHexDump caps how many payload bytes are rendered into an attribute,
	// so that a large register read cannot bloat an event.
	maxHexDump = 32
)

// exceptionBit marks a response as an exception reply (v1.1b3, section 7).
const exceptionBit = 0x80

// Dissector decodes Modbus/TCP. It holds no mutable state, so one instance is
// shared by every worker; per-stream state lives in FlowContext.State.
type Dissector struct{}

// New returns a Modbus/TCP dissector.
func New() *Dissector { return &Dissector{} }

func init() {
	dissect.Register(New(), dissect.TCPPorts(DefaultPort))
}

// Name implements dissect.Dissector.
func (*Dissector) Name() string { return "modbus" }

// Tier implements dissect.Dissector.
func (*Dissector) Tier() int { return 1 }

// PDULen implements dissect.Framer. A Modbus/TCP frame is length-delimited by
// the MBAP length field, which makes the stream self-framing.
//
// A non-zero protocol identifier is deliberately not a framing error: the
// frame is still cut at its declared length so that Parse can report both the
// operation and the anomaly. Only a length outside the protocol's own range
// breaks framing, because then the next frame's offset is unknowable.
func (*Dissector) PDULen(buf []byte) (int, error) {
	if len(buf) < 6 {
		return 0, dissect.ErrNeedMore
	}
	length := binary.BigEndian.Uint16(buf[4:6])
	if length < minLengthField || length > maxLengthField {
		return 0, fmt.Errorf("%w: MBAP length field %d outside %d..%d",
			dissect.ErrMalformed, length, minLengthField, maxLengthField)
	}
	total := 6 + int(length)
	if len(buf) < total {
		return 0, dissect.ErrNeedMore
	}
	return total, nil
}

// Probe implements dissect.Dissector. It scores how much the payload looks
// like a Modbus/TCP frame, for streams whose ports give no answer and to break
// ties between protocols sharing a port.
//
// The protocol identifier is the one field the specification pins to a
// constant, so it carries the verdict: a frame whose identifier is zero is
// Modbus-shaped even when another field is crafted, and such frames are
// exactly the ones an OT inventory must not drop. A broken length or an
// undefined function code therefore lowers the score rather than zeroing it.
func (d *Dissector) Probe(_ *dissect.FlowContext, payload []byte) int {
	if len(payload) < headerLen {
		return 0
	}
	protocolID := binary.BigEndian.Uint16(payload[2:4])
	length := binary.BigEndian.Uint16(payload[4:6])
	unitID := payload[6]
	fc := payload[7] &^ exceptionBit

	if length < minLengthField || length > maxLengthField {
		if protocolID == 0 {
			// A Modbus/TCP header carrying an impossible length: most likely
			// crafted Modbus, never confidently anything else.
			return 15
		}
		return 0
	}

	score := 50
	total := 6 + int(length)
	switch {
	case total == len(payload):
		// Exactly one frame in the segment: the strongest signal there is.
		score += 30
	case total < len(payload):
		// Possibly pipelined frames. Worth more if the remainder frames too.
		if _, err := d.PDULen(payload[total:]); err == nil {
			score += 30
		} else {
			score += 5
		}
	default:
		// Declared longer than what is here. Either a frame split across
		// segments or not Modbus at all.
		score -= 10
	}
	if _, known := functions[fc]; known {
		score += 10
	} else if fc == 0 {
		// There is no function code 0, but a scan sweeping every code starts
		// there, so this still scores as Modbus.
		score -= 15
	}
	// Unit ids 1..247 address a device, 255 is the conventional "ignore" value
	// on TCP, and 0 is a broadcast.
	if unitID <= 247 || unitID == 255 {
		score += 5
	}
	if protocolID != 0 {
		// The protocol identifier must be zero for Modbus/TCP (Implementation
		// Guide v1.0b, section 4.1). Something claiming otherwise may still be
		// Modbus, but never confidently enough to bind on heuristics alone.
		if score > 30 {
			score = 30
		}
	}
	return score
}

// Parse implements dissect.Dissector. It decodes exactly one ADU and returns
// exactly one event.
func (d *Dissector) Parse(ctx *dissect.FlowContext, payload []byte) ([]model.Event, error) {
	if len(payload) < headerLen {
		return nil, fmt.Errorf("%w: %d bytes cannot hold an MBAP header and a function code",
			dissect.ErrMalformed, len(payload))
	}
	if len(payload) > maxADU {
		return nil, fmt.Errorf("%w: %d bytes exceed the %d byte maximum ADU",
			dissect.ErrMalformed, len(payload), maxADU)
	}

	transactionID := binary.BigEndian.Uint16(payload[0:2])
	protocolID := binary.BigEndian.Uint16(payload[2:4])
	length := binary.BigEndian.Uint16(payload[4:6])
	unitID := payload[6]
	rawFC := payload[7]
	fc := rawFC &^ exceptionBit
	isException := rawFC&exceptionBit != 0

	info := classify(fc)
	ev := model.Event{
		CaptureID:     ctx.CaptureID,
		PacketIndex:   ctx.PacketIndex,
		Timestamp:     ctx.Timestamp,
		Flow:          ctx.Flow,
		Protocol:      "modbus",
		Direction:     ctx.Direction,
		Operation:     info.name,
		FunctionCode:  int(fc),
		Class:         info.class,
		UnitID:        model.Ptr(uint16(unitID)),
		TransactionID: model.Ptr(uint32(transactionID)),
	}
	if ev.Direction == "" {
		ev.Direction = model.DirUnknown
	}
	// An exception reply is a response whatever the ports suggested.
	if isException {
		ev.Direction = model.DirResponse
	}
	if protocolID != 0 {
		setAttr(&ev, "protocol_id", strconv.FormatUint(uint64(protocolID), 10))
		setAttr(&ev, "anomaly", "non_zero_protocol_id")
	}

	if fc == 0 {
		return []model.Event{malformed(ev, "function code 0 is not defined")},
			fmt.Errorf("%w: function code 0 is not defined", dissect.ErrMalformed)
	}

	// The body is bounded by both the declared length and the bytes present.
	body := payload[headerLen:]
	declared := int(length) - 2 // length counts the unit id and function code
	if declared < 0 {
		return []model.Event{malformed(ev, "MBAP length field below minimum")},
			fmt.Errorf("%w: MBAP length field %d below minimum %d",
				dissect.ErrMalformed, length, minLengthField)
	}
	if declared > len(body) {
		msg := fmt.Sprintf("MBAP length declares %d body bytes, %d present", declared, len(body))
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}
	if declared < len(body) {
		// Trailing bytes inside the framed PDU: keep them as evidence.
		setAttr(&ev, "padding_bytes", strconv.Itoa(len(body)-declared))
		body = body[:declared]
	}

	var err error
	switch {
	case isException:
		err = parseException(&ev, body)
	case ev.Direction == model.DirResponse:
		err = parseResponse(&ev, fc, body)
	default:
		err = parseRequest(&ev, fc, body)
	}
	if err != nil {
		return []model.Event{malformed(ev, err.Error())},
			fmt.Errorf("%w: %s", dissect.ErrMalformed, err.Error())
	}
	return []model.Event{ev}, nil
}

func parseException(ev *model.Event, body []byte) error {
	if len(body) < 1 {
		return fmt.Errorf("exception reply without an exception code")
	}
	code := body[0]
	ev.Exception = exceptionName(code)
	setAttr(ev, "exception_code", strconv.FormatUint(uint64(code), 10))
	noteTrailing(ev, body[1:])
	return nil
}

func parseRequest(ev *model.Event, fc uint8, body []byte) error {
	switch fc {
	case fcReadCoils, fcReadDiscreteInputs, fcReadHoldingRegisters, fcReadInputRegisters:
		if len(body) < 4 {
			return fmt.Errorf("%s request needs 4 body bytes, got %d", ev.Operation, len(body))
		}
		ev.Address = model.Ptr(uint32(binary.BigEndian.Uint16(body[0:2])))
		ev.Quantity = model.Ptr(uint32(binary.BigEndian.Uint16(body[2:4])))
		noteTrailing(ev, body[4:])

	case fcWriteSingleCoil:
		if len(body) < 4 {
			return fmt.Errorf("WriteSingleCoil request needs 4 body bytes, got %d", len(body))
		}
		ev.Address = model.Ptr(uint32(binary.BigEndian.Uint16(body[0:2])))
		ev.Quantity = model.Ptr(uint32(1))
		value := binary.BigEndian.Uint16(body[2:4])
		setAttr(ev, "value", fmt.Sprintf("0x%04x", value))
		// 0xFF00 is on and 0x0000 is off; anything else is out of spec.
		switch value {
		case 0xFF00:
			setAttr(ev, "coil_state", "on")
		case 0x0000:
			setAttr(ev, "coil_state", "off")
		default:
			setAttr(ev, "coil_state", "invalid")
		}
		noteTrailing(ev, body[4:])

	case fcWriteSingleRegister:
		if len(body) < 4 {
			return fmt.Errorf("WriteSingleRegister request needs 4 body bytes, got %d", len(body))
		}
		ev.Address = model.Ptr(uint32(binary.BigEndian.Uint16(body[0:2])))
		ev.Quantity = model.Ptr(uint32(1))
		setAttr(ev, "value", strconv.FormatUint(uint64(binary.BigEndian.Uint16(body[2:4])), 10))
		noteTrailing(ev, body[4:])

	case fcWriteMultipleCoils, fcWriteMultipleRegisters:
		if len(body) < 5 {
			return fmt.Errorf("%s request needs at least 5 body bytes, got %d", ev.Operation, len(body))
		}
		ev.Address = model.Ptr(uint32(binary.BigEndian.Uint16(body[0:2])))
		ev.Quantity = model.Ptr(uint32(binary.BigEndian.Uint16(body[2:4])))
		byteCount := int(body[4])
		setAttr(ev, "byte_count", strconv.Itoa(byteCount))
		if len(body[5:]) < byteCount {
			return fmt.Errorf("%s request declares %d data bytes, %d present",
				ev.Operation, byteCount, len(body[5:]))
		}
		noteTrailing(ev, body[5+byteCount:])

	case fcReadExceptionStatus, fcGetCommEventCounter, fcGetCommEventLog, fcReportServerID:
		// No request body.
		noteTrailing(ev, body)

	case fcDiagnostics:
		return parseDiagnostics(ev, body)

	case fcMaskWriteRegister:
		if len(body) < 6 {
			return fmt.Errorf("MaskWriteRegister request needs 6 body bytes, got %d", len(body))
		}
		ev.Address = model.Ptr(uint32(binary.BigEndian.Uint16(body[0:2])))
		ev.Quantity = model.Ptr(uint32(1))
		setAttr(ev, "and_mask", fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(body[2:4])))
		setAttr(ev, "or_mask", fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(body[4:6])))
		noteTrailing(ev, body[6:])

	case fcReadWriteMultipleRegisters:
		if len(body) < 9 {
			return fmt.Errorf("ReadWriteMultipleRegisters request needs at least 9 body bytes, got %d", len(body))
		}
		ev.Address = model.Ptr(uint32(binary.BigEndian.Uint16(body[0:2])))
		ev.Quantity = model.Ptr(uint32(binary.BigEndian.Uint16(body[2:4])))
		setAttr(ev, "write_address", strconv.FormatUint(uint64(binary.BigEndian.Uint16(body[4:6])), 10))
		setAttr(ev, "write_quantity", strconv.FormatUint(uint64(binary.BigEndian.Uint16(body[6:8])), 10))
		byteCount := int(body[8])
		setAttr(ev, "byte_count", strconv.Itoa(byteCount))
		if len(body[9:]) < byteCount {
			return fmt.Errorf("ReadWriteMultipleRegisters declares %d data bytes, %d present",
				byteCount, len(body[9:]))
		}
		noteTrailing(ev, body[9+byteCount:])

	case fcReadFIFOQueue:
		if len(body) < 2 {
			return fmt.Errorf("ReadFIFOQueue request needs 2 body bytes, got %d", len(body))
		}
		ev.Address = model.Ptr(uint32(binary.BigEndian.Uint16(body[0:2])))
		noteTrailing(ev, body[2:])

	case fcReadFileRecord, fcWriteFileRecord:
		if len(body) < 1 {
			return fmt.Errorf("%s request needs a byte count", ev.Operation)
		}
		byteCount := int(body[0])
		setAttr(ev, "byte_count", strconv.Itoa(byteCount))
		if len(body[1:]) < byteCount {
			return fmt.Errorf("%s declares %d bytes of sub-requests, %d present",
				ev.Operation, byteCount, len(body[1:]))
		}
		noteTrailing(ev, body[1+byteCount:])

	case fcEncapsulatedInterface:
		return parseEncapsulatedRequest(ev, body)

	default:
		// Reserved, user-defined and unknown codes: keep the bytes as
		// evidence without pretending to understand them.
		dumpBody(ev, body)
	}
	return nil
}

func parseResponse(ev *model.Event, fc uint8, body []byte) error {
	switch fc {
	case fcReadCoils, fcReadDiscreteInputs:
		data, err := byteCountData(ev, body)
		if err != nil {
			return err
		}
		dumpValues(ev, data)

	case fcReadHoldingRegisters, fcReadInputRegisters, fcReadWriteMultipleRegisters:
		data, err := byteCountData(ev, body)
		if err != nil {
			return err
		}
		ev.Quantity = model.Ptr(uint32(len(data) / 2))
		dumpValues(ev, data)

	case fcWriteSingleCoil, fcWriteSingleRegister, fcMaskWriteRegister:
		// The response echoes the request.
		return parseRequest(ev, fc, body)

	case fcWriteMultipleCoils, fcWriteMultipleRegisters:
		if len(body) < 4 {
			return fmt.Errorf("%s response needs 4 body bytes, got %d", ev.Operation, len(body))
		}
		ev.Address = model.Ptr(uint32(binary.BigEndian.Uint16(body[0:2])))
		ev.Quantity = model.Ptr(uint32(binary.BigEndian.Uint16(body[2:4])))
		noteTrailing(ev, body[4:])

	case fcReadExceptionStatus:
		if len(body) < 1 {
			return fmt.Errorf("ReadExceptionStatus response needs an output status byte")
		}
		setAttr(ev, "output_status", fmt.Sprintf("0x%02x", body[0]))
		noteTrailing(ev, body[1:])

	case fcDiagnostics:
		return parseDiagnostics(ev, body)

	case fcGetCommEventCounter:
		if len(body) < 4 {
			return fmt.Errorf("GetCommEventCounter response needs 4 body bytes, got %d", len(body))
		}
		setAttr(ev, "status", fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(body[0:2])))
		setAttr(ev, "event_count", strconv.FormatUint(uint64(binary.BigEndian.Uint16(body[2:4])), 10))
		noteTrailing(ev, body[4:])

	case fcGetCommEventLog:
		data, err := byteCountData(ev, body)
		if err != nil {
			return err
		}
		dumpValues(ev, data)

	case fcReportServerID:
		return parseReportServerID(ev, body)

	case fcReadFIFOQueue:
		if len(body) < 4 {
			return fmt.Errorf("ReadFIFOQueue response needs 4 body bytes, got %d", len(body))
		}
		setAttr(ev, "byte_count", strconv.FormatUint(uint64(binary.BigEndian.Uint16(body[0:2])), 10))
		count := binary.BigEndian.Uint16(body[2:4])
		ev.Quantity = model.Ptr(uint32(count))
		setAttr(ev, "fifo_count", strconv.FormatUint(uint64(count), 10))
		noteTrailing(ev, body[4:])

	case fcReadFileRecord, fcWriteFileRecord:
		data, err := byteCountData(ev, body)
		if err != nil {
			return err
		}
		dumpValues(ev, data)

	case fcEncapsulatedInterface:
		return parseEncapsulatedResponse(ev, body)

	default:
		dumpBody(ev, body)
	}
	return nil
}

// parseDiagnostics decodes FC 8, whose sub-function decides both the name and
// the classification (v1.1b3, section 6.8).
func parseDiagnostics(ev *model.Event, body []byte) error {
	if len(body) < 4 {
		return fmt.Errorf("diagnostics needs a 2 byte sub-function and a 2 byte data field, got %d bytes", len(body))
	}
	sub := binary.BigEndian.Uint16(body[0:2])
	info := classifyDiagnostic(sub)
	ev.Class = info.class
	setAttr(ev, "sub_function", strconv.FormatUint(uint64(sub), 10))
	setAttr(ev, "sub_function_name", info.name)
	setAttr(ev, "data", fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(body[2:4])))
	noteTrailing(ev, body[4:])
	return nil
}

// parseReportServerID decodes FC 17. The specification says the server id
// content is device specific; in practice the first byte is the server id, the
// second a run indicator (0xFF on, 0x00 off) and the remainder printable
// vendor text, which is what makes this reply useful for asset enrichment.
func parseReportServerID(ev *model.Event, body []byte) error {
	data, err := byteCountData(ev, body)
	if err != nil {
		return err
	}
	if len(data) >= 1 {
		setAttr(ev, "server_id", strconv.FormatUint(uint64(data[0]), 10))
	}
	if len(data) >= 2 {
		switch data[1] {
		case 0xFF:
			setAttr(ev, "run_indicator", "on")
		case 0x00:
			setAttr(ev, "run_indicator", "off")
		default:
			setAttr(ev, "run_indicator", fmt.Sprintf("0x%02x", data[1]))
		}
	}
	if len(data) > 2 {
		if text := printable(data[2:]); text != "" {
			setIdentity(ev, "report_server_id", text)
		}
	}
	return nil
}

// parseEncapsulatedRequest decodes FC 43, which multiplexes on a MEI type
// (v1.1b3, section 6.19). MEI 14 is Read Device Identification.
func parseEncapsulatedRequest(ev *model.Event, body []byte) error {
	if len(body) < 1 {
		return fmt.Errorf("EncapsulatedInterfaceTransport needs a MEI type")
	}
	mei := body[0]
	setAttr(ev, "mei_type", strconv.FormatUint(uint64(mei), 10))
	switch mei {
	case meiReadDeviceIdent:
		if len(body) < 3 {
			return fmt.Errorf("ReadDeviceIdentification request needs a device id code and object id, got %d body bytes", len(body))
		}
		ev.Operation = "ReadDeviceIdentification"
		ev.Class = model.ClassDiscovery
		setAttr(ev, "read_device_id_code", strconv.FormatUint(uint64(body[1]), 10))
		setAttr(ev, "object_id", strconv.FormatUint(uint64(body[2]), 10))
		noteTrailing(ev, body[3:])
	case meiCANopen:
		ev.Operation = "CANopenGeneralReference"
		dumpBody(ev, body[1:])
	default:
		dumpBody(ev, body[1:])
	}
	return nil
}

// parseEncapsulatedResponse decodes the FC 43 / MEI 14 reply, whose identity
// objects are the richest device evidence Modbus offers (v1.1b3, section 6.21).
func parseEncapsulatedResponse(ev *model.Event, body []byte) error {
	if len(body) < 1 {
		return fmt.Errorf("EncapsulatedInterfaceTransport needs a MEI type")
	}
	mei := body[0]
	setAttr(ev, "mei_type", strconv.FormatUint(uint64(mei), 10))
	if mei != meiReadDeviceIdent {
		if mei == meiCANopen {
			ev.Operation = "CANopenGeneralReference"
		}
		dumpBody(ev, body[1:])
		return nil
	}

	if len(body) < 6 {
		return fmt.Errorf("ReadDeviceIdentification response needs 6 header bytes, got %d", len(body))
	}
	ev.Operation = "ReadDeviceIdentification"
	ev.Class = model.ClassDiscovery
	setAttr(ev, "read_device_id_code", strconv.FormatUint(uint64(body[1]), 10))
	setAttr(ev, "conformity_level", fmt.Sprintf("0x%02x", body[2]))
	moreFollows := body[3] != 0x00
	setAttr(ev, "more_follows", strconv.FormatBool(moreFollows))
	if moreFollows {
		// Only meaningful when the server has more objects to hand over.
		setAttr(ev, "next_object_id", strconv.FormatUint(uint64(body[4]), 10))
	}
	objectCount := int(body[5])
	setAttr(ev, "object_count", strconv.Itoa(objectCount))

	rest := body[6:]
	for i := 0; i < objectCount; i++ {
		if len(rest) < 2 {
			return fmt.Errorf("ReadDeviceIdentification declares %d objects, object %d has no header",
				objectCount, i)
		}
		id, objLen := rest[0], int(rest[1])
		if len(rest[2:]) < objLen {
			return fmt.Errorf("ReadDeviceIdentification object %d declares %d bytes, %d present",
				id, objLen, len(rest[2:]))
		}
		value := printable(rest[2 : 2+objLen])
		key, known := deviceIDObjects[id]
		if !known {
			key = "object_" + strconv.FormatUint(uint64(id), 10)
		}
		if value != "" {
			setIdentity(ev, key, value)
		}
		rest = rest[2+objLen:]
	}
	noteTrailing(ev, rest)
	return nil
}

// byteCountData reads a one byte count prefix and returns exactly that many
// bytes, recording the count and rejecting a count that overruns the body.
func byteCountData(ev *model.Event, body []byte) ([]byte, error) {
	if len(body) < 1 {
		return nil, fmt.Errorf("%s response needs a byte count", ev.Operation)
	}
	count := int(body[0])
	setAttr(ev, "byte_count", strconv.Itoa(count))
	if len(body[1:]) < count {
		return nil, fmt.Errorf("%s response declares %d data bytes, %d present",
			ev.Operation, count, len(body[1:]))
	}
	data := body[1 : 1+count]
	noteTrailing(ev, body[1+count:])
	return data, nil
}

func setAttr(ev *model.Event, key, value string) {
	if ev.Attrs == nil {
		ev.Attrs = make(map[string]string, 4)
	}
	ev.Attrs[key] = value
}

func setIdentity(ev *model.Event, key, value string) {
	if ev.Identity == nil {
		ev.Identity = make(map[string]string, 4)
	}
	ev.Identity[key] = value
}

// noteTrailing records bytes left over after a PDU was decoded. A well formed
// frame has none, so their presence is evidence of a crafted or padded frame.
func noteTrailing(ev *model.Event, rest []byte) {
	if len(rest) > 0 {
		setAttr(ev, "trailing_bytes", strconv.Itoa(len(rest)))
	}
}

func dumpValues(ev *model.Event, data []byte) {
	if len(data) == 0 {
		return
	}
	setAttr(ev, "values", hexDump(ev, data))
}

func dumpBody(ev *model.Event, body []byte) {
	if len(body) == 0 {
		return
	}
	setAttr(ev, "body", hexDump(ev, body))
}

// hexDump renders data as hex, capped so one event cannot carry an unbounded
// payload dump.
func hexDump(ev *model.Event, data []byte) string {
	if len(data) > maxHexDump {
		setAttr(ev, "values_truncated", "true")
		data = data[:maxHexDump]
	}
	return hex.EncodeToString(data)
}

// printable keeps the printable ASCII in b, which is how vendor strings arrive
// in identity replies. Non-printable bytes are dropped rather than escaped, so
// that a crafted string cannot smuggle control characters into the GUI.
func printable(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		if c >= 0x20 && c <= 0x7E {
			sb.WriteByte(c)
		}
	}
	return strings.TrimSpace(sb.String())
}

// malformed marks ev as undecodable, keeping whatever was decoded before the
// failure as evidence.
func malformed(ev model.Event, reason string) model.Event {
	ev.Malformed = true
	ev.Error = reason
	return ev
}
