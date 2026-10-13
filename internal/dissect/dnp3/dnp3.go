// Package dnp3 dissects DNP3, the SCADA protocol standardised as IEEE
// 1815-2012 and carried over TCP and UDP on port 20000.
//
// DNP3 has three layers to get through before an operation is readable: a data
// link frame with a CRC on every 16 byte block, a transport function that
// splits application fragments across frames, and the application layer that
// finally names the function and its objects. This dissector handles all
// three, including reassembling a fragment that spans frames, and decodes the
// control relay output blocks that carry the actual switching commands.
//
// Every length and count in a frame is attacker-controlled, so nothing here
// trusts one: object data is only walked where its size is known from the
// standard, a fragment under reassembly is capped, and anything undecodable
// becomes a malformed event rather than a panic.
package dnp3

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/model"
)

// DefaultPort is the registered DNP3 port, used for both TCP and UDP.
const DefaultPort = 20000

// Frame geometry (IEEE 1815, 9.2.4).
const (
	start1 = 0x05
	start2 = 0x64

	// headerLen is start octets (2), length (1), control (1), destination (2),
	// source (2) and the header CRC (2).
	headerLen = 10

	// The length octet counts the control and address fields plus the body,
	// so 5 is the smallest legal value and 255 the largest.
	minLengthField = 5
	maxLengthField = 255

	// blockSize is how many body octets share one CRC.
	blockSize = 16

	// maxFragment caps a reassembled application fragment. The standard's own
	// maximum is 2048 octets; this leaves room for an outstation that goes
	// further without letting a stream of continuations grow without bound.
	maxFragment = 4096

	// maxTransportSeq is the modulus of the transport sequence number.
	maxTransportSeq = 64
)

// Dissector decodes DNP3. It holds no mutable state: per-stream reassembly
// lives in the FlowContext the caller owns.
type Dissector struct{}

// New returns a DNP3 dissector.
func New() *Dissector { return &Dissector{} }

func init() {
	dissect.Register(New(),
		dissect.TCPPorts(DefaultPort),
		dissect.UDPPorts(DefaultPort))
}

// Name implements dissect.Dissector.
func (*Dissector) Name() string { return "dnp3" }

// Tier implements dissect.Dissector.
func (*Dissector) Tier() int { return 1 }

// PDULen implements dissect.Framer. A DNP3 frame is delimited by its start
// octets and its length field, and the CRC after every block has to be
// counted in to find where the next frame begins.
func (*Dissector) PDULen(buf []byte) (int, error) {
	if len(buf) < 1 {
		return 0, dissect.ErrNeedMore
	}
	if buf[0] != start1 {
		return 0, fmt.Errorf("%w: first start octet is 0x%02x, not 0x05", dissect.ErrMalformed, buf[0])
	}
	if len(buf) < 2 {
		return 0, dissect.ErrNeedMore
	}
	if buf[1] != start2 {
		return 0, fmt.Errorf("%w: second start octet is 0x%02x, not 0x64", dissect.ErrMalformed, buf[1])
	}
	if len(buf) < 3 {
		return 0, dissect.ErrNeedMore
	}

	length := buf[2]
	if length < minLengthField {
		return 0, fmt.Errorf("%w: length octet %d below the minimum %d",
			dissect.ErrMalformed, length, minLengthField)
	}
	total := frameLen(length)
	if len(buf) < total {
		return 0, dissect.ErrNeedMore
	}
	return total, nil
}

// frameLen is the whole frame size for a length octet, CRCs included.
func frameLen(length uint8) int {
	body := int(length) - minLengthField
	blocks := (body + blockSize - 1) / blockSize
	return headerLen + body + 2*blocks
}

// Probe implements dissect.Dissector. A matching header CRC is close to
// conclusive, which is what makes DNP3 cheap to detect on a stray port.
func (d *Dissector) Probe(_ *dissect.FlowContext, payload []byte) int {
	if len(payload) < headerLen {
		return 0
	}
	if payload[0] != start1 || payload[1] != start2 {
		return 0
	}
	length := payload[2]
	if length < minLengthField {
		return 0
	}

	score := 40
	if binary.LittleEndian.Uint16(payload[8:10]) == CRC(payload[0:8]) {
		score += 50
	}
	total := frameLen(length)
	switch {
	case total == len(payload):
		score += 10
	case total < len(payload):
		if _, err := d.PDULen(payload[total:]); err == nil {
			score += 10
		}
	}
	// A named link function adds a little; an unnamed one is not
	// disqualifying, since the standard reserves several.
	control := payload[3]
	if linkFunctionName(control&0x40 != 0, control&0x0f) != "Reserved" {
		score += 5
	}
	return min(score, 100)
}

// transportState is the per-direction reassembly buffer, kept in
// FlowContext.State.
type transportState struct {
	buf     []byte
	frames  int
	lastSeq int
	active  bool
}

func (s *transportState) reset() {
	s.buf = s.buf[:0]
	s.frames = 0
	s.active = false
}

// state returns this direction's reassembly state, creating it on first use.
// Ingest hands each direction of a stream its own FlowContext and never
// touches State, so this needs no locking.
func state(ctx *dissect.FlowContext) *transportState {
	if s, ok := ctx.State.(*transportState); ok {
		return s
	}
	s := &transportState{}
	ctx.State = s
	return s
}

// Parse implements dissect.Dissector. It decodes one link frame, and returns
// an event once a whole application fragment has arrived.
func (d *Dissector) Parse(ctx *dissect.FlowContext, payload []byte) ([]model.Event, error) {
	if len(payload) < headerLen {
		return nil, fmt.Errorf("%w: %d octets cannot hold a link header",
			dissect.ErrMalformed, len(payload))
	}
	if payload[0] != start1 || payload[1] != start2 {
		return nil, fmt.Errorf("%w: start octets are 0x%02x%02x, not 0x0564",
			dissect.ErrMalformed, payload[0], payload[1])
	}

	length := payload[2]
	control := payload[3]
	dest := binary.LittleEndian.Uint16(payload[4:6])
	source := binary.LittleEndian.Uint16(payload[6:8])
	headerCRC := binary.LittleEndian.Uint16(payload[8:10])

	fromMaster := control&0x80 != 0
	primary := control&0x40 != 0
	linkName := linkFunctionName(primary, control&0x0f)

	ev := model.Event{
		CaptureID:    ctx.CaptureID,
		PacketIndex:  ctx.PacketIndex,
		Timestamp:    ctx.Timestamp,
		Flow:         ctx.Flow,
		Protocol:     "dnp3",
		Direction:    ctx.Direction,
		Operation:    linkName,
		FunctionCode: -1,
		Class:        model.ClassOther,
	}
	if ev.Direction == "" {
		ev.Direction = model.DirUnknown
	}
	setAttr(&ev, "link_function", linkName)
	setAttr(&ev, "link_source", strconv.Itoa(int(source)))
	setAttr(&ev, "link_dest", strconv.Itoa(int(dest)))
	setAttr(&ev, "from_master", strconv.FormatBool(fromMaster))
	setUnit(&ev, ev.Direction, source, dest)

	if length < minLengthField {
		return []model.Event{malformed(ev, fmt.Sprintf("length octet %d below the minimum", length))},
			fmt.Errorf("%w: length octet %d below the minimum", dissect.ErrMalformed, length)
	}
	if binary.LittleEndian.Uint16(payload[8:10]) != CRC(payload[0:8]) {
		msg := fmt.Sprintf("link header CRC is 0x%04x, computed 0x%04x", headerCRC, CRC(payload[0:8]))
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	total := frameLen(length)
	if len(payload) < total {
		msg := fmt.Sprintf("frame declares %d octets, %d present", total, len(payload))
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	body, crcErrors := stripBlockCRCs(payload[headerLen:total], int(length)-minLengthField)
	if crcErrors > 0 {
		// The frame is still evidence; the analyst needs to know its contents
		// were not trustworthy.
		setAttr(&ev, "crc_errors", strconv.Itoa(crcErrors))
		addAnomaly(&ev, "crc_mismatch")
	}

	if len(body) == 0 {
		// A link layer frame with no user data: an acknowledgement, a link
		// reset or a status request. Still proof that DNP3 is spoken here.
		setAttr(&ev, "layer", "link")
		if linkName == "TEST_LINK_STATES" || linkName == "REQUEST_LINK_STATUS" || linkName == "LINK_STATUS" {
			ev.Class = model.ClassDiagnostic
		}
		return []model.Event{ev}, nil
	}

	return d.handleTransport(ctx, ev, body)
}

// handleTransport runs the transport function: a fragment may be split across
// frames, and only a complete one has an application header to read.
func (d *Dissector) handleTransport(ctx *dissect.FlowContext, ev model.Event, body []byte) ([]model.Event, error) {
	transport := body[0]
	fin := transport&0x80 != 0
	fir := transport&0x40 != 0
	seq := int(transport & 0x3f)
	segment := body[1:]

	setAttr(&ev, "transport_seq", strconv.Itoa(seq))
	st := state(ctx)

	switch {
	case fir && fin:
		// The whole fragment is in this frame, which is the common case.
		st.reset()
		setAttr(&ev, "transport_frames", "1")
		return d.parseApplication(ev, segment)

	case fir:
		st.reset()
		st.active = true
		st.lastSeq = seq
		st.frames = 1
		st.buf = append(st.buf, segment...)
		setAttr(&ev, "layer", "transport")
		return nil, nil

	default:
		if !st.active {
			// The capture started in the middle of a fragment. Report it
			// rather than inventing an application header for it.
			st.reset()
			setAttr(&ev, "layer", "transport")
			addAnomaly(&ev, "transport_continuation_without_start")
			return []model.Event{ev}, nil
		}
		if seq != (st.lastSeq+1)%maxTransportSeq {
			msg := fmt.Sprintf("transport sequence jumped from %d to %d, so a frame was lost",
				st.lastSeq, seq)
			st.reset()
			return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
		}
		if len(st.buf)+len(segment) > maxFragment {
			msg := fmt.Sprintf("application fragment exceeds the %d octet cap", maxFragment)
			st.reset()
			return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
		}

		st.lastSeq = seq
		st.frames++
		st.buf = append(st.buf, segment...)
		if !fin {
			setAttr(&ev, "layer", "transport")
			return nil, nil
		}

		frames := st.frames
		fragment := append([]byte(nil), st.buf...)
		st.reset()
		setAttr(&ev, "transport_frames", strconv.Itoa(frames))
		return d.parseApplication(ev, fragment)
	}
}

// parseApplication decodes the application header and its object headers.
func (d *Dissector) parseApplication(ev model.Event, app []byte) ([]model.Event, error) {
	if len(app) < 2 {
		msg := "application fragment has no function code"
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	appControl := app[0]
	fc := app[1]
	info := appFunction(fc)

	ev.Operation = info.name
	ev.FunctionCode = int(fc)
	ev.Class = info.class
	setAttr(&ev, "app_seq", strconv.Itoa(int(appControl&0x0f)))
	if appControl&0x20 != 0 {
		setAttr(&ev, "confirm_requested", "true")
	}
	if appControl&0x10 != 0 {
		setAttr(&ev, "unsolicited", "true")
	}
	// A reply is a reply whatever the ports said, and an unsolicited one
	// arrives with no request at all.
	if isResponse(fc) {
		ev.Direction = model.DirResponse
		setUnit(&ev, model.DirResponse, linkAddr(ev, "link_source"), linkAddr(ev, "link_dest"))
	} else if fc <= 33 {
		ev.Direction = model.DirRequest
		setUnit(&ev, model.DirRequest, linkAddr(ev, "link_source"), linkAddr(ev, "link_dest"))
	}

	offset := 2
	if isResponse(fc) {
		if len(app) < 4 {
			msg := "response has no internal indications"
			return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
		}
		iin1, iin2 := app[2], app[3]
		setAttr(&ev, "iin", fmt.Sprintf("0x%02x%02x", iin1, iin2))
		if flags := decodeIIN(iin1, iin2); len(flags) > 0 {
			setAttr(&ev, "iin_flags", strings.Join(flags, ","))
		}
		offset = 4
	}

	headers, complete := parseObjects(app[offset:])
	describeObjects(&ev, headers, complete)
	return []model.Event{ev}, nil
}

// describeObjects records what the object headers said, and pulls out the
// point and the command behind a control object.
func describeObjects(ev *model.Event, headers []objectHeader, complete bool) {
	if len(headers) == 0 {
		return
	}

	labels := make([]string, 0, len(headers))
	for _, h := range headers {
		labels = append(labels, h.label())
		if _, known := objectGroups[h.group]; !known {
			addAnomaly(ev, "unknown_object_group")
		}
	}
	setAttr(ev, "objects", strings.Join(labels, ","))
	if !complete {
		// Object data of an unknown size stops the walk. Saying so is better
		// than reporting the headers that were read as if they were all.
		setAttr(ev, "objects_truncated", "true")
	}

	first := headers[0]
	setAttr(ev, "group", strconv.Itoa(int(first.group)))
	setAttr(ev, "variation", strconv.Itoa(int(first.variation)))
	setAttr(ev, "qualifier", fmt.Sprintf("0x%02x", first.qualifier))
	if name, ok := objectGroups[first.group]; ok {
		setAttr(ev, "object_name", name)
	}

	switch {
	case len(first.indexes) > 0:
		ev.Address = model.Ptr(first.indexes[0])
	case first.hasRange:
		ev.Address = model.Ptr(first.start)
	}
	// An "all objects" request has no count worth reporting.
	if first.countKnown && first.rangeSpec != rangeAllObjects {
		ev.Quantity = model.Ptr(uint32(first.count))
	}

	describeControl(ev, first, ev.Direction == model.DirResponse)
}

// describeControl decodes a control relay output block, which is where a DNP3
// command says what it will actually do to the plant.
func describeControl(ev *model.Event, h objectHeader, isReply bool) {
	if h.group != 12 || (h.variation != 1 && h.variation != 2) {
		return
	}
	// The data holds count objects, each an index prefix plus 11 octets.
	const crobLen = 11
	data := h.data
	if len(data) < crobLen {
		return
	}
	// Skip the index prefix when there is one; the sizes are fixed, so the
	// block sits at the end of the first object's bytes.
	if h.prefix >= 1 && h.prefix <= 3 {
		indexLen := 1 << (h.prefix - 1)
		if len(data) < indexLen+crobLen {
			return
		}
		data = data[indexLen:]
	}

	controlCode := data[0]
	opType := controlCode & 0x0f
	name, known := crobOperations[opType]
	if !known {
		name = "Reserved"
	}
	setAttr(ev, "control_code", name)
	if tcc := (controlCode >> 6) & 0x03; tcc != 0 {
		if tccName, ok := crobTripClose[tcc]; ok {
			setAttr(ev, "trip_close", tccName)
		}
	}
	if controlCode&0x20 != 0 {
		setAttr(ev, "clear", "true")
	}
	setAttr(ev, "control_count", strconv.Itoa(int(data[1])))
	setAttr(ev, "on_time_ms", strconv.FormatUint(uint64(binary.LittleEndian.Uint32(data[2:6])), 10))
	setAttr(ev, "off_time_ms", strconv.FormatUint(uint64(binary.LittleEndian.Uint32(data[6:10])), 10))
	// The status octet is only meaningful in a reply; in a request the
	// standard leaves it unused, and reporting it there would read as though
	// the outstation had already answered.
	if isReply {
		if status, ok := commandStatus[data[10]&0x7f]; ok {
			setAttr(ev, "control_status", status)
		} else {
			setAttr(ev, "control_status", strconv.Itoa(int(data[10]&0x7f)))
		}
	}
}

// stripBlockCRCs removes the per-block CRCs from a frame body and reports how
// many did not match.
func stripBlockCRCs(buf []byte, bodyLen int) ([]byte, int) {
	out := make([]byte, 0, bodyLen)
	errors, offset, remaining := 0, 0, bodyLen

	for remaining > 0 {
		n := min(blockSize, remaining)
		if offset+n+2 > len(buf) {
			// The framer sized this buffer, so this means a truncated frame.
			if offset < len(buf) {
				out = append(out, buf[offset:]...)
			}
			return out, errors + 1
		}
		block := buf[offset : offset+n]
		if binary.LittleEndian.Uint16(buf[offset+n:offset+n+2]) != CRC(block) {
			errors++
		}
		out = append(out, block...)
		offset += n + 2
		remaining -= n
	}
	return out, errors
}

// outstation reports which link address belongs to the outstation: a request
// is addressed to it, a reply comes from it.
func outstation(dir model.Direction, source, dest uint16) uint16 {
	if dir == model.DirResponse {
		return source
	}
	return dest
}

// setUnit records the outstation this frame concerns.
//
// A broadcast address names every outstation on the link rather than one
// device, so it is reported as a broadcast and leaves the unit unset: an
// inventory that listed 65535 as a device would be inventing one. A broadcast
// write, control or program operation reaches every device at once, which is
// why it is called out for the rules to match on.
func setUnit(ev *model.Event, dir model.Direction, source, dest uint16) {
	addr := outstation(dir, source, dest)
	kind, special := linkAddressKind(addr)
	if !special {
		ev.UnitID = model.Ptr(addr)
		return
	}

	ev.UnitID = nil
	setAttr(ev, "address_kind", kind)
	if kind == "broadcast" {
		setAttr(ev, "broadcast", "true")
	}
}

// linkAddr reads back an address this dissector recorded, so the unit can be
// corrected once the function code has settled the direction.
func linkAddr(ev model.Event, key string) uint16 {
	v, err := strconv.ParseUint(ev.Attrs[key], 10, 16)
	if err != nil {
		return 0
	}
	return uint16(v)
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

func malformed(ev model.Event, reason string) model.Event {
	ev.Malformed = true
	ev.Error = reason
	return ev
}
