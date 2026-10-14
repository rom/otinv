// Package profinet dissects PROFINET DCP, the discovery and configuration
// protocol that finds PROFINET stations on a segment and sets the two things
// PROFINET addresses them by: the name of station and the IP configuration.
//
// DCP runs directly on Ethernet under EtherType 0x8892, which PROFINET shares
// between several protocols and tells apart by the first two octets of the
// frame. This dissector claims the four discovery frame identifiers and
// nothing else: the cyclic RT frames and the alarm frames under the same
// EtherType are PROFINET RT, which CLAUDE.md places in Tier 2, and until that
// exists those frames are counted as unrecognised rather than guessed at.
//
// What makes DCP worth deep parsing is that a station answering an Identify
// asks nothing of the observer and says almost everything: the name an
// engineer gave it, its vendor and device identifiers, the type string its
// manufacturer put in it, its IP configuration, and the part it plays in the
// system — IO device, IO controller or IO supervisor. That last one is a
// device stating its own role, which no amount of traffic watching can beat.
//
// The other half is that a Set writes those same fields. A station whose name
// or address is changed drops off the network as surely as if it had been
// unplugged, and nothing in DCP authenticates anything, so a Set from an
// unexpected source is exactly what CLAUDE.md's rule on writes from hosts
// outside the engineering allow-list is for.
package profinet

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/model"
)

// EtherType is the value PROFINET uses for its real time protocols
// (IEC 61158-6-10, clause 4.1).
const EtherType = 0x8892

const (
	// headerLen is the frame identifier, the service identifier and type,
	// the transaction identifier, the response delay and the data length.
	headerLen = 12

	// blockHeaderLen is an option, a suboption and a block length.
	blockHeaderLen = 4

	// maxBlocks caps how many blocks one PDU is read out of. A station
	// answering an Identify sends six or seven; the length field would allow
	// hundreds of empty ones.
	maxBlocks = 32

	// maxTextLen caps a name taken off the wire. The standard allows a name
	// of station of 240 octets; this is the length beyond which a name is
	// evidence of something other than a name.
	maxTextLen = 240
)

// Dissector decodes PROFINET DCP. It holds no mutable state.
type Dissector struct{}

// New returns a PROFINET DCP dissector.
func New() *Dissector { return &Dissector{} }

func init() {
	dissect.Register(New(), dissect.EtherTypes(EtherType))
}

// Name implements dissect.Dissector.
func (*Dissector) Name() string { return "profinet_dcp" }

// Tier implements dissect.Dissector.
func (*Dissector) Tier() int { return 1 }

// Probe implements dissect.Dissector.
//
// The EtherType is shared, so the frame identifier is what decides, and it is
// a fixed value rather than a range. Beyond that there is only the service
// identifier, the service type and a data length that fits the frame — which
// together are enough, because nothing else under this EtherType opens with
// 0xFEFC to 0xFEFF.
func (*Dissector) Probe(_ *dissect.FlowContext, payload []byte) int {
	if len(payload) < headerLen {
		return 0
	}
	frameID := binary.BigEndian.Uint16(payload[:2])
	if !isDCP(frameID) {
		return 0
	}
	score := 60
	if _, known := serviceName(payload[2]); known {
		score += 20
	}
	if _, known := serviceTypes[payload[3]]; known {
		score += 10
	}
	if headerLen+int(binary.BigEndian.Uint16(payload[10:12])) <= len(payload) {
		score += 10
	}
	return min(score, 100)
}

// Parse implements dissect.Dissector. One Ethernet frame is one PDU.
func (d *Dissector) Parse(ctx *dissect.FlowContext, payload []byte) ([]model.Event, error) {
	ev := model.Event{
		CaptureID:    ctx.CaptureID,
		PacketIndex:  ctx.PacketIndex,
		Timestamp:    ctx.Timestamp,
		Flow:         ctx.Flow,
		Protocol:     "profinet_dcp",
		Direction:    ctx.Direction,
		Operation:    "DCP",
		FunctionCode: -1,
		Class:        model.ClassOther,
	}
	if ev.Direction == "" {
		ev.Direction = model.DirUnknown
	}

	if len(payload) < headerLen {
		msg := fmt.Sprintf("%d octets cannot hold a DCP header", len(payload))
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	frameID := binary.BigEndian.Uint16(payload[:2])
	if !isDCP(frameID) {
		msg := fmt.Sprintf("frame identifier 0x%s is not a DCP one", hex16(frameID))
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	serviceID, serviceType := payload[2], payload[3]
	xid := binary.BigEndian.Uint32(payload[4:8])
	delay := binary.BigEndian.Uint16(payload[8:10])
	dataLen := int(binary.BigEndian.Uint16(payload[10:12]))

	info, known := serviceName(serviceID)
	ev.Operation = info.name
	ev.FunctionCode = int(serviceID)
	ev.Class = info.class
	ev.TransactionID = model.Ptr(xid)
	setAttr(&ev, "frame_id", "0x"+hex16(frameID))
	setAttr(&ev, "service", info.name)
	if !known {
		addAnomaly(&ev, "unknown_service")
	}

	kind, knownType := serviceTypes[serviceType]
	if !knownType {
		kind = "type_" + utoa(uint32(serviceType))
		addAnomaly(&ev, "unknown_service_type")
	}
	setAttr(&ev, "service_type", kind)
	switch serviceType {
	case typeRequest:
		ev.Direction = model.DirRequest
		if delay != 0 {
			// A request tells the stations how far to spread their answers,
			// so that a segment with hundreds of them is not flooded at once.
			setAttr(&ev, "response_delay", strconv.Itoa(int(delay)))
		}
	default:
		ev.Direction = model.DirResponse
		if serviceType == typeNotSupported {
			ev.Exception = "service_not_supported"
		}
	}
	// A Hello is a station announcing itself unasked, which is a request in
	// the protocol and an answer in substance.
	if serviceID == svcHello {
		ev.Direction = model.DirResponse
	}

	if headerLen+dataLen > len(payload) {
		msg := fmt.Sprintf("DCP data length %d exceeds the %d octets present",
			dataLen, len(payload)-headerLen)
		return []model.Event{malformed(ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}
	data := payload[headerLen : headerLen+dataLen]

	// Everything after the declared data is Ethernet padding. It should be
	// zero, and when it is not the frame is carrying whatever was in the
	// sender's buffer before it, which is worth seeing.
	if trailing := payload[headerLen+dataLen:]; len(trailing) > 0 && !allZero(trailing) {
		setAttr(&ev, "padding_bytes", strconv.Itoa(len(trailing)))
		addAnomaly(&ev, "padding_not_zero")
	}

	shape := blockShape(serviceID, serviceType)
	if err := d.walkBlocks(&ev, data, shape); err != nil {
		return []model.Event{malformed(ev, err.Error())}, fmt.Errorf("%w: %s", dissect.ErrMalformed, err.Error())
	}
	return []model.Event{ev}, nil
}

// blockLayout says what sits between a block's length and its value.
type blockLayout int

const (
	// layoutBare is a request naming an option it wants, or filtering on a
	// value: nothing between the length and the value.
	layoutBare blockLayout = iota
	// layoutQualifier is a Set request, which prefixes the value with a
	// block qualifier saying whether the setting is to be kept over a power
	// cycle.
	layoutQualifier
	// layoutInfo is a station's answer, which prefixes the value with block
	// info — for an IP block, whether the address is set at all.
	layoutInfo
)

// blockShape picks the layout the blocks of this PDU use
// (IEC 61158-6-10, clauses 4.3.1.4.2 to 4.3.1.4.4).
func blockShape(serviceID, serviceType uint8) blockLayout {
	switch {
	case serviceType != typeRequest:
		return layoutInfo
	case serviceID == svcSet:
		return layoutQualifier
	case serviceID == svcHello:
		// A Hello carries the station's own parameters, in the same shape as
		// an answer, although the service type says request.
		return layoutInfo
	default:
		return layoutBare
	}
}

// walkBlocks reads the blocks of a PDU. Each is padded to an even length,
// which is part of the encoding rather than something to discover.
//
// The service says what kind of operation this is and the blocks say what it
// was done to, so the classification is the most consequential thing any
// block contributes: a Set that writes a name of station is a write, one that
// only flashes the station's LED is a diagnostic, and one that resets it to
// factory state is a control — even though all three are the same service.
func (d *Dissector) walkBlocks(ev *model.Event, data []byte, shape blockLayout) error {
	var (
		names   []string
		roles   []string
		options int
		best    contribution
	)
	for off := 0; off < len(data); {
		if len(names) >= maxBlocks {
			addAnomaly(ev, "too_many_blocks")
			return nil
		}
		if off+blockHeaderLen > len(data) {
			return fmt.Errorf("block %d starts %d octets before the end of the data",
				len(names)+1, len(data)-off)
		}
		option, suboption := data[off], data[off+1]
		length := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		if off+blockHeaderLen+length > len(data) {
			return fmt.Errorf("block %s declares %d octets, %d present",
				blockName(option, suboption), length, len(data)-off-blockHeaderLen)
		}
		body := data[off+blockHeaderLen : off+blockHeaderLen+length]
		name := blockName(option, suboption)
		names = append(names, name)

		best = best.max(d.contributionOf(ev, option, suboption, name))

		// An option named with no value is a request asking for it.
		if length == 0 {
			options++
			off += blockHeaderLen
			continue
		}

		d.describeBlock(ev, option, suboption, name, body, shape, &roles)
		off += blockHeaderLen + length + length%2
	}

	if len(names) > 0 {
		setAttr(ev, "blocks", strings.Join(names, ","))
	}
	if best.named {
		ev.Class = best.class
		ev.Operation = best.operation
	}
	if len(roles) > 0 {
		setIdentity(ev, "device_role", strings.Join(roles, ","))
	}
	return nil
}

// describeBlock records one block. The value of a block is whatever the
// station put there, so each length is checked against the field it is read
// as rather than against what the standard says it should be.
func (d *Dissector) describeBlock(ev *model.Event, option, suboption uint8,
	name string, body []byte, shape blockLayout, roles *[]string) {

	// The Control/Response block is the one answer whose three octets are
	// not block info and a value but the option it acknowledges and how it
	// went, so it is read before the prefix is stripped.
	if option == optControl && suboption == subControlResponse {
		d.describeControlResponse(ev, body)
		return
	}

	var info uint16
	hasInfo := false
	switch shape {
	case layoutInfo, layoutQualifier:
		if len(body) < 2 {
			addAnomaly(ev, "block_shorter_than_its_prefix")
			return
		}
		info, hasInfo = binary.BigEndian.Uint16(body[:2]), true
		body = body[2:]
	}
	if shape == layoutQualifier && hasInfo {
		// Bit 0 of the qualifier says the value is to survive a power cycle,
		// which is the difference between a temporary change and a permanent
		// reconfiguration.
		if info&0x0001 != 0 {
			setAttr(ev, "set_permanent", "true")
		}
	}

	switch {
	case option == optIP && suboption == subIPParameter,
		option == optIP && suboption == subFullIPSuite:
		if hasInfo {
			if state, ok := ipBlockInfo[info]; ok {
				setAttr(ev, "ip_state", state)
				if info&0x0080 != 0 {
					// Two stations answering for one address is a fault an
					// engineer has to resolve and a sign of a cloned device.
					addAnomaly(ev, "ip_address_conflict")
				}
			}
		}
		if len(body) >= 12 {
			// Neutral names: in an answer these are the addresses the
			// station has, and in a Set they are the ones it is being given.
			setAttr(ev, "ip_address", ipString(body[0:4]))
			setAttr(ev, "netmask", ipString(body[4:8]))
			setAttr(ev, "gateway", ipString(body[8:12]))
			if ev.Direction == model.DirResponse {
				setIdentity(ev, "reported_address", ipString(body[0:4]))
				// A netmask cannot be read off an address, so a station
				// stating its own is the only way a passive observer learns
				// where one subnet ends: it is what the topology groups by
				// instead of assuming a prefix.
				setIdentity(ev, "reported_netmask", ipString(body[4:8]))
				setIdentity(ev, "reported_gateway", ipString(body[8:12]))
			}
		}

	case option == optIP && suboption == subMACAddress:
		if len(body) >= 6 {
			setAttr(ev, "mac_address", macString(body[:6]))
		}

	case option == optDeviceProps && suboption == subNameOfStatio:
		station, clean := text(body)
		setAttr(ev, "name_of_station", station)
		if !clean {
			// PROFINET names are a restricted character set, and this is the
			// field a device is addressed by. Anything else in it is either a
			// broken station or a crafted frame; the public sample captures
			// carry one with format specifiers and NUL padding in it.
			addAnomaly(ev, "name_of_station_not_printable")
		}
		if ev.Direction == model.DirResponse {
			setIdentity(ev, "station_name", station)
		}

	case option == optDeviceProps && suboption == subVendorValue:
		value, clean := text(body)
		setAttr(ev, "device_vendor_value", value)
		if !clean {
			addAnomaly(ev, "device_vendor_value_not_printable")
		}
		if ev.Direction == model.DirResponse {
			// The manufacturer's own type string for the hardware, which is
			// the closest thing DCP has to a model number.
			setIdentity(ev, "model", value)
		}

	case option == optDeviceProps && suboption == subDeviceID:
		if len(body) >= 4 {
			vendor := binary.BigEndian.Uint16(body[:2])
			device := binary.BigEndian.Uint16(body[2:4])
			setAttr(ev, "vendor_id", "0x"+hex16(vendor))
			setAttr(ev, "device_id", "0x"+hex16(device))
			if ev.Direction == model.DirResponse {
				setIdentity(ev, "vendor_id", strconv.Itoa(int(vendor)))
				setIdentity(ev, "device_id", "0x"+hex16(device))
				if vname, ok := vendors[vendor]; ok {
					setIdentity(ev, "vendor_name", vname)
				}
			}
		}

	case option == optDeviceProps && suboption == subDeviceRole:
		if len(body) >= 1 {
			for _, r := range deviceRoles {
				if body[0]&r.bit != 0 {
					*roles = append(*roles, r.name)
				}
			}
			setAttr(ev, "device_role", "0x"+hex8(body[0]))
		}

	case option == optDeviceProps && suboption == subDeviceInstan:
		if len(body) >= 2 {
			setAttr(ev, "device_instance", strconv.Itoa(int(binary.BigEndian.Uint16(body[:2]))))
		}

	case option == optDeviceProps && suboption == subAliasName:
		alias, _ := text(body)
		setAttr(ev, "alias_name", alias)

	case option == optDeviceProps && suboption == subDeviceOption:
		// The list of blocks the station supports, in option/suboption pairs.
		setAttr(ev, "supported_options", strconv.Itoa(len(body)/2))

	case option == optControl:
		// A control block is an operation rather than a value: ending a
		// transaction, flashing the station's LED so an engineer can find it
		// in a cabinet, or resetting it to factory state.
		d.describeControl(ev, suboption, name, body)

	case option == optDeviceInit:
		setAttr(ev, "device_initiative", "true")

	default:
		if len(body) > 0 {
			setAttr(ev, "block_"+strings.ToLower(name)+"_bytes", strconv.Itoa(len(body)))
		}
	}
}

// contribution is what one block says this PDU does.
type contribution struct {
	class     model.Classification
	operation string
	named     bool
}

// max keeps the more consequential of two contributions.
func (c contribution) max(o contribution) contribution {
	switch {
	case !o.named:
		return c
	case !c.named:
		return o
	case classRank(o.class) > classRank(c.class):
		return o
	default:
		return c
	}
}

// contributionOf says what a block makes of the PDU it is in. Everything but
// a control block is the service doing what the service does; a control block
// is its own operation.
func (d *Dissector) contributionOf(ev *model.Event, option, suboption uint8, name string) contribution {
	service := ev.Attrs["service"]
	if option != optControl {
		return contribution{class: serviceClassOf(service), operation: service, named: true}
	}
	switch suboption {
	case subControlSignal:
		// Flashing the LED is how an engineer identifies which cabinet a
		// station is in. It changes nothing, so it is a diagnostic.
		return contribution{class: model.ClassDiagnostic, operation: service + ".Signal", named: true}
	case subControlFactoryReset, subControlResetToFact:
		// A factory reset takes the name of station and the IP address with
		// it, so the device leaves the network and has to be recommissioned.
		// It acts on the device rather than writing a value to it, which is
		// the same reading the CIP Reset service gets.
		return contribution{class: model.ClassControl, operation: service + "." + name, named: true}
	case subControlResponse:
		// The acknowledgement of a block that was set, so it is the write
		// being confirmed rather than an operation of its own.
		return contribution{class: serviceClassOf(service), operation: service, named: true}
	default:
		// Start and End bracket a multi-block Set and are not themselves an
		// operation on anything.
		return contribution{class: model.ClassOther, operation: service, named: true}
	}
}

// serviceClassOf is the classification of a service by name, which is how a
// block says "whatever this service does".
func serviceClassOf(name string) model.Classification {
	for _, info := range services {
		if info.name == name {
			return info.class
		}
	}
	return model.ClassOther
}

// describeControl records which control block a PDU carried.
func (d *Dissector) describeControl(ev *model.Event, suboption uint8, name string, body []byte) {
	setAttr(ev, "control", name)
	if suboption == subControlFactoryReset || suboption == subControlResetToFact {
		if len(body) >= 2 {
			setAttr(ev, "reset_mode", "0x"+hex16(binary.BigEndian.Uint16(body[:2])))
		}
	}
}

// classRank orders the classifications by how consequential they are, the
// same order the GUI sorts them by.
func classRank(c model.Classification) int {
	switch c {
	case model.ClassFirmware:
		return 7
	case model.ClassProgram:
		return 6
	case model.ClassControl:
		return 5
	case model.ClassWrite:
		return 4
	case model.ClassRead:
		return 3
	case model.ClassDiagnostic:
		return 2
	case model.ClassDiscovery:
		return 1
	default:
		return 0
	}
}

// describeControlResponse records how a station answered each block of a Set:
// which option it is answering for, and whether it took it.
func (d *Dissector) describeControlResponse(ev *model.Event, body []byte) {
	if len(body) < 3 {
		addAnomaly(ev, "control_response_truncated")
		return
	}
	acked := blockName(body[0], body[1])
	result := blockErrorName(body[2])
	setAttr(ev, "acked_block", acked)
	setAttr(ev, "block_result", result)
	if body[2] != 0 {
		// A station refusing a Set is the protocol's own error reply, and
		// which refusal it is separates a device that does not support the
		// option from one that will not let this interface change it.
		ev.Exception = result
	}
}

// text renders a value that is meant to be a name, reporting whether every
// octet of it was printable. Packet bytes are hostile and these names are
// rendered in the GUI, so anything else becomes a dot here rather than
// travelling onwards as it is.
func text(b []byte) (string, bool) {
	if len(b) > maxTextLen {
		b = b[:maxTextLen]
	}
	// A station name is commonly padded with NULs to a fixed length, which is
	// not evidence of anything by itself.
	trimmed := b
	for len(trimmed) > 0 && trimmed[len(trimmed)-1] == 0 {
		trimmed = trimmed[:len(trimmed)-1]
	}
	out := make([]byte, 0, len(trimmed))
	clean := len(trimmed) == len(b) || len(b)-len(trimmed) <= 1
	for _, c := range trimmed {
		if c < 0x20 || c > 0x7e {
			out = append(out, '.')
			clean = false
			continue
		}
		out = append(out, c)
	}
	return string(out), clean
}

func ipString(b []byte) string {
	return net.IP(b[:4]).String()
}

func macString(b []byte) string {
	out := make([]byte, 0, 17)
	for i := 0; i < 6; i++ {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex8(b[i])...)
	}
	return string(out)
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
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
		ev.Identity = make(map[string]string, 6)
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
