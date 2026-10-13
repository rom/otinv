// Package s7comm dissects Siemens S7comm, the protocol STEP 7 and WinCC speak
// to S7-300 and S7-400 controllers over ISO-on-TCP (RFC 1006), port 102.
//
// Three layers stack up before an operation is readable: TPKT gives the frame
// its length, COTP carries a connection whose TSAPs name the rack and slot of
// the target CPU, and S7comm itself carries the function codes, the memory
// areas and the SZL lists that identify the device.
//
// S7comm is proprietary and has no published specification. Where behaviour is
// not obvious from the traffic, the layouts and names here follow the
// Wireshark s7comm dissector, which CLAUDE.md allows as the reference instead
// of guessing silently.
package s7comm

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/model"
)

// DefaultPort is the ISO-on-TCP port S7comm runs over.
const DefaultPort = 102

// Frame geometry.
const (
	tpktVersion = 0x03
	tpktLen     = 4

	// minFrameLen is a TPKT header plus the smallest COTP header.
	minFrameLen = tpktLen + 3

	// s7ProtocolID marks an S7comm payload; 0x72 is S7comm-plus, which the
	// S7-1200 and S7-1500 speak and which is a separate dissector.
	s7ProtocolID     = 0x32
	s7PlusProtocolID = 0x72

	// s7HeaderLen is protocol id, ROSCTR, redundancy id, PDU reference,
	// parameter length and data length.
	s7HeaderLen = 10

	// s7AckHeaderLen adds the error class and error code of a reply.
	s7AckHeaderLen = 12
)

// Dissector decodes S7comm. It holds no mutable state; what little it needs
// per stream lives in the FlowContext the caller owns.
type Dissector struct{}

// New returns an S7comm dissector.
func New() *Dissector { return &Dissector{} }

func init() {
	dissect.Register(New(), dissect.TCPPorts(DefaultPort))
}

// Name implements dissect.Dissector.
func (*Dissector) Name() string { return "s7comm" }

// Tier implements dissect.Dissector.
func (*Dissector) Tier() int { return 1 }

// PDULen implements dissect.Framer. TPKT exists precisely to give the frame a
// length, so framing is just its header.
func (*Dissector) PDULen(buf []byte) (int, error) {
	if len(buf) < tpktLen {
		return 0, dissect.ErrNeedMore
	}
	if buf[0] != tpktVersion {
		return 0, fmt.Errorf("%w: TPKT version is 0x%02x, not 0x03", dissect.ErrMalformed, buf[0])
	}
	if buf[1] != 0x00 {
		return 0, fmt.Errorf("%w: TPKT reserved octet is 0x%02x, not zero",
			dissect.ErrMalformed, buf[1])
	}

	length := int(binary.BigEndian.Uint16(buf[2:4]))
	if length < minFrameLen {
		return 0, fmt.Errorf("%w: TPKT length %d below the minimum %d",
			dissect.ErrMalformed, length, minFrameLen)
	}
	if len(buf) < length {
		return 0, dissect.ErrNeedMore
	}
	return length, nil
}

// Probe implements dissect.Dissector.
func (d *Dissector) Probe(_ *dissect.FlowContext, payload []byte) int {
	if len(payload) < minFrameLen {
		return 0
	}
	if payload[0] != tpktVersion || payload[1] != 0x00 {
		return 0
	}
	length := int(binary.BigEndian.Uint16(payload[2:4]))
	if length < minFrameLen {
		return 0
	}

	score := 30
	switch {
	case length == len(payload):
		score += 20
	case length < len(payload):
		if _, err := d.PDULen(payload[length:]); err == nil {
			score += 20
		}
	}

	li := payload[4]
	cotpType := payload[5]
	if _, known := cotpTypes[cotpType]; known {
		score += 20
	}
	switch cotpType {
	case cotpConnectRequest, cotpConnectConfirm:
		// The connection parameters carry TSAPs, which little else does.
		score += 20
	case cotpData:
		if start := 5 + int(li); start < length && start < len(payload) {
			if payload[start] == s7ProtocolID || payload[start] == s7PlusProtocolID {
				score += 30
			}
		}
	}
	return min(score, 100)
}

// streamState remembers what has already been reported for a stream, so that
// a payload this dissector cannot read is mentioned once instead of on every
// frame.
type streamState struct {
	reportedUnsupported bool
}

func state(ctx *dissect.FlowContext) *streamState {
	if s, ok := ctx.State.(*streamState); ok {
		return s
	}
	s := &streamState{}
	ctx.State = s
	return s
}

// Parse implements dissect.Dissector. It decodes one TPKT frame.
func (d *Dissector) Parse(ctx *dissect.FlowContext, payload []byte) ([]model.Event, error) {
	if len(payload) < minFrameLen {
		return nil, fmt.Errorf("%w: %d octets cannot hold a TPKT and COTP header",
			dissect.ErrMalformed, len(payload))
	}
	if payload[0] != tpktVersion {
		return nil, fmt.Errorf("%w: TPKT version is 0x%02x, not 0x03",
			dissect.ErrMalformed, payload[0])
	}

	length := int(binary.BigEndian.Uint16(payload[2:4]))
	if length < minFrameLen || length > len(payload) {
		return nil, fmt.Errorf("%w: TPKT declares %d octets, %d present",
			dissect.ErrMalformed, length, len(payload))
	}
	frame := payload[:length]

	li := int(frame[4])
	cotpType := frame[5]
	cotpName, known := cotpTypes[cotpType]
	if !known {
		cotpName = fmt.Sprintf("COTP_0x%02x", cotpType)
	}

	ev := model.Event{
		CaptureID:    ctx.CaptureID,
		PacketIndex:  ctx.PacketIndex,
		Timestamp:    ctx.Timestamp,
		Flow:         ctx.Flow,
		Protocol:     "s7comm",
		Direction:    ctx.Direction,
		Operation:    cotpName,
		FunctionCode: -1,
		Class:        model.ClassOther,
	}
	if ev.Direction == "" {
		ev.Direction = model.DirUnknown
	}

	// The length indicator counts the octets after itself, so the COTP header
	// ends there and anything beyond is user data.
	if li < 2 || 5+li > length {
		msg := fmt.Sprintf("COTP length indicator %d does not fit a %d octet frame", li, length)
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	switch cotpType {
	case cotpConnectRequest, cotpConnectConfirm:
		return d.parseConnect(ev, frame, li, cotpType)
	case cotpData:
		return d.parseData(ctx, ev, frame[5+li:])
	default:
		// Disconnects, rejects and acknowledgements carry no user data, but
		// they are still evidence that ISO-on-TCP is spoken here.
		setAttr(&ev, "layer", "cotp")
		return []model.Event{ev}, nil
	}
}

// parseConnect decodes a connection request or confirm, whose parameters name
// the rack and slot of the CPU the session is aimed at.
func (d *Dissector) parseConnect(ev model.Event, frame []byte, li int, cotpType uint8) ([]model.Event, error) {
	setAttr(&ev, "layer", "cotp")

	// Connection PDUs carry destination reference, source reference and a
	// class octet before the variable parameters.
	const fixed = 11
	if fixed > 5+li {
		msg := "connection PDU is too short for its fixed fields"
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	var dstTSAP []byte
	params := frame[fixed : 5+li]
	for len(params) >= 2 {
		code, plen := params[0], int(params[1])
		if 2+plen > len(params) {
			setAttr(&ev, "anomaly", "truncated_connection_parameter")
			break
		}
		value := params[2 : 2+plen]
		params = params[2+plen:]

		switch code {
		case paramSrcTSAP:
			setAttr(&ev, "src_tsap", tsapString(value))
		case paramDstTSAP:
			setAttr(&ev, "dst_tsap", tsapString(value))
			dstTSAP = value
		case paramTPDUSize:
			if plen == 1 {
				setAttr(&ev, "tpdu_size", strconv.Itoa(1<<value[0]))
			}
		}
	}

	// A two octet TSAP addresses a device: the first octet is the connection
	// type, the second holds the rack in its upper bits and the slot in its
	// lower five (Wireshark s7comm, "ISO-on-TCP" TSAP decoding).
	if len(dstTSAP) == 2 {
		rack := int(dstTSAP[1] >> 5)
		slot := int(dstTSAP[1] & 0x1f)
		setAttr(&ev, "rack", strconv.Itoa(rack))
		setAttr(&ev, "slot", strconv.Itoa(slot))
		if name, ok := connectionTypes[dstTSAP[0]]; ok {
			setAttr(&ev, "connection_type", name)
		}
		// A confirm means that rack and slot answered, so it is evidence
		// about the device. A request is only what the client asked for.
		if cotpType == cotpConnectConfirm {
			setIdentity(&ev, "rack", strconv.Itoa(rack))
			setIdentity(&ev, "slot", strconv.Itoa(slot))
		}
	}
	return []model.Event{ev}, nil
}

// connectionTypes names the first octet of an S7 TSAP.
var connectionTypes = map[uint8]string{
	0x01: "PG",
	0x02: "OP",
	0x03: "Basic",
}

func tsapString(b []byte) string {
	if len(b) == 2 {
		return fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(b))
	}
	return "0x" + hexString(b)
}

// parseData decodes the user data of a COTP data frame.
func (d *Dissector) parseData(ctx *dissect.FlowContext, ev model.Event, data []byte) ([]model.Event, error) {
	if len(data) == 0 {
		// STEP 7 sends empty data frames as keep-alives. They say nothing
		// about the device, so they produce no event; the frame still counts
		// as handled in parse health.
		return nil, nil
	}

	if data[0] != s7ProtocolID {
		st := state(ctx)
		if st.reportedUnsupported {
			return nil, nil
		}
		st.reportedUnsupported = true

		// Another protocol on the same port is not a broken frame. Reporting
		// it once per stream tells the analyst there is traffic here that
		// this dissector does not read, without flooding the timeline.
		ev.Operation = "UnsupportedPayload"
		setAttr(&ev, "protocol_id", fmt.Sprintf("0x%02x", data[0]))
		if data[0] == s7PlusProtocolID {
			setAttr(&ev, "protocol_hint", "s7comm-plus")
		}
		return []model.Event{ev}, nil
	}

	if len(data) < s7HeaderLen {
		msg := fmt.Sprintf("S7 header needs %d octets, %d present", s7HeaderLen, len(data))
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	rosctr := data[1]
	rosctrName, ok := rosctrNames[rosctr]
	if !ok {
		rosctrName = fmt.Sprintf("0x%02x", rosctr)
	}
	setAttr(&ev, "rosctr", rosctrName)
	setAttr(&ev, "pdu_reference", strconv.Itoa(int(binary.BigEndian.Uint16(data[4:6]))))

	paramLen := int(binary.BigEndian.Uint16(data[6:8]))
	dataLen := int(binary.BigEndian.Uint16(data[8:10]))

	header := s7HeaderLen
	if rosctr == rosctrAck || rosctr == rosctrAckData {
		if len(data) < s7AckHeaderLen {
			msg := "reply header has no error class"
			return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
		}
		errClass, errCode := data[10], data[11]
		header = s7AckHeaderLen
		if errClass != 0 || errCode != 0 {
			setAttr(&ev, "error_class", fmt.Sprintf("0x%02x", errClass))
			setAttr(&ev, "error_code", fmt.Sprintf("0x%02x", errCode))
			if name := errorClasses[errClass]; name != "" {
				ev.Exception = name
			} else {
				ev.Exception = fmt.Sprintf("Error0x%02x%02x", errClass, errCode)
			}
		}
	}

	// Declared lengths are attacker-controlled; check them against what is
	// actually here before slicing.
	if header+paramLen+dataLen > len(data) {
		msg := fmt.Sprintf("S7 PDU declares %d parameter and %d data octets, %d present",
			paramLen, dataLen, len(data)-header)
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}
	params := data[header : header+paramLen]
	payload := data[header+paramLen : header+paramLen+dataLen]

	// The message kind settles the direction, whatever the ports suggested.
	switch rosctr {
	case rosctrJob:
		ev.Direction = model.DirRequest
	case rosctrAck, rosctrAckData:
		ev.Direction = model.DirResponse
	}

	if rosctr == rosctrUserdata {
		return parseUserdata(&ev, params, payload)
	}
	return parseFunction(&ev, params, payload)
}

// parseFunction decodes the parameter block of a job or its reply.
func parseFunction(ev *model.Event, params, data []byte) ([]model.Event, error) {
	if len(params) < 1 {
		msg := "S7 PDU has no function code"
		return []model.Event{malformed(*ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	fc := params[0]
	info := appFunction(fc)
	ev.Operation = info.name
	ev.FunctionCode = int(fc)
	ev.Class = info.class

	switch fc {
	case fnSetupCommunication:
		parseSetupCommunication(ev, params)
	case fnReadVar, fnWriteVar:
		parseVarService(ev, params, data)
	case fnRequestDownload, fnDownloadBlock, fnDownloadEnded,
		fnStartUpload, fnUpload, fnEndUpload:
		parseBlockTransfer(ev, params)
	case fnPLCControl:
		parsePLCControl(ev, params)
	case fnPLCStop:
		parsePLCStop(ev, params)
	default:
		if len(params) > 1 {
			setAttr(ev, "parameters", hexString(capBytes(params[1:])))
		}
	}
	return []model.Event{*ev}, nil
}

// parseSetupCommunication reads the negotiated PDU size, which is the first
// thing a master and a CPU agree on.
func parseSetupCommunication(ev *model.Event, params []byte) {
	if len(params) < 8 {
		setAttr(ev, "anomaly", "truncated_setup_communication")
		return
	}
	setAttr(ev, "max_amq_calling", strconv.Itoa(int(binary.BigEndian.Uint16(params[2:4]))))
	setAttr(ev, "max_amq_called", strconv.Itoa(int(binary.BigEndian.Uint16(params[4:6]))))
	setAttr(ev, "pdu_length", strconv.Itoa(int(binary.BigEndian.Uint16(params[6:8]))))
}

// parsePLCControl decodes the program invocation service that PLC_CONTROL
// carries, which is what says whether a block was activated or deleted.
func parsePLCControl(ev *model.Event, params []byte) {
	// Function code, seven octets Wireshark marks unknown, then the parameter
	// block length, the block itself, and the service name.
	const fixed = 1 + 7
	if len(params) < fixed+2 {
		setAttr(ev, "anomaly", "truncated_plc_control")
		return
	}
	blockLen := int(binary.BigEndian.Uint16(params[fixed : fixed+2]))
	rest := params[fixed+2:]
	if blockLen > len(rest) {
		setAttr(ev, "anomaly", "truncated_plc_control")
		return
	}
	if blockLen > 0 {
		if text := printable(rest[:blockLen]); text != "" {
			setAttr(ev, "pi_parameter", text)
		}
	}
	rest = rest[blockLen:]

	if len(rest) < 1 {
		return
	}
	nameLen := int(rest[0])
	if nameLen > len(rest)-1 {
		setAttr(ev, "anomaly", "truncated_plc_control")
		return
	}
	service := printable(rest[1 : 1+nameLen])
	if service == "" {
		return
	}
	setAttr(ev, "pi_service", service)
	if piServicePrograms[service] {
		// Inserting or deleting a block changes the program.
		ev.Class = model.ClassProgram
	}
}

// parsePLCStop decodes the stop request, whose only payload is the service
// name of the program being stopped.
func parsePLCStop(ev *model.Event, params []byte) {
	const fixed = 1 + 5
	if len(params) < fixed+1 {
		return
	}
	nameLen := int(params[fixed])
	rest := params[fixed+1:]
	if nameLen > len(rest) {
		setAttr(ev, "anomaly", "truncated_plc_stop")
		return
	}
	if service := printable(rest[:nameLen]); service != "" {
		setAttr(ev, "pi_service", service)
	}
}

func setAttr(ev *model.Event, key, value string) {
	if ev.Attrs == nil {
		ev.Attrs = make(map[string]string, 8)
	}
	ev.Attrs[key] = value
}

func setIdentity(ev *model.Event, key, value string) {
	if ev.Identity == nil {
		ev.Identity = make(map[string]string, 4)
	}
	ev.Identity[key] = value
}

// printable keeps the printable ASCII of b. Device supplied strings reach the
// GUI, so control characters are dropped rather than escaped.
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

// maxHexDump caps how many octets are rendered into an attribute.
const maxHexDump = 32

func capBytes(b []byte) []byte {
	if len(b) > maxHexDump {
		return b[:maxHexDump]
	}
	return b
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

func malformed(ev model.Event, reason string) model.Event {
	ev.Malformed = true
	ev.Error = reason
	return ev
}
