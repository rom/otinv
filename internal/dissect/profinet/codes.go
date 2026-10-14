package profinet

import "github.com/rom/otinv/internal/model"

// The frame identifiers, services, options and errors of PROFINET DCP, as
// IEC 61158-6-10 defines them and the Wireshark pn_dcp dissector names them.

// Frame identifiers. PROFINET puts several protocols under one EtherType and
// tells them apart by the first two octets of the frame (IEC 61158-6-10,
// table 12).
const (
	frameHello          = 0xFEFC
	frameGetSet         = 0xFEFD
	frameIdentifyReq    = 0xFEFE
	frameIdentifyRes    = 0xFEFF
	frameAlarmHigh      = 0xFC01
	frameAlarmLow       = 0xFE01
	frameRTClass3First  = 0x0100
	frameRTClass3Last   = 0x0FFF
	frameRTClass1First  = 0x8000
	frameRTClass1Last   = 0xBFFF
	frameRTClassUDPLast = 0xFBFF
)

// isDCP reports whether a frame identifier belongs to the discovery and
// configuration protocol rather than to one of the other protocols sharing
// EtherType 0x8892.
func isDCP(frameID uint16) bool {
	switch frameID {
	case frameHello, frameGetSet, frameIdentifyReq, frameIdentifyRes:
		return true
	default:
		return false
	}
}

// Service identifiers and types (IEC 61158-6-10, clause 4.3.1.3).
const (
	svcGet      = 3
	svcSet      = 4
	svcIdentify = 5
	svcHello    = 6

	typeRequest      = 0
	typeSuccess      = 1
	typeNotSupported = 5
)

type serviceInfo struct {
	name  string
	class model.Classification
}

// services maps a service identifier to its name and classification.
//
// Identify and Hello are how a station is found and how it announces itself,
// so they are discovery. Get reads a station's parameters. Set writes them —
// the name of station and the IP address are what PROFINET addresses a device
// by, so changing them takes a device off the network as surely as unplugging
// it, which is why CLAUDE.md wants writes from unexpected sources flagged.
var services = map[uint8]serviceInfo{
	svcGet:      {"Get", model.ClassRead},
	svcSet:      {"Set", model.ClassWrite},
	svcIdentify: {"Identify", model.ClassDiscovery},
	svcHello:    {"Hello", model.ClassDiscovery},
}

func serviceName(id uint8) (serviceInfo, bool) {
	if info, ok := services[id]; ok {
		return info, true
	}
	return serviceInfo{"Service_" + utoa(uint32(id)), model.ClassOther}, false
}

var serviceTypes = map[uint8]string{
	typeRequest:      "request",
	typeSuccess:      "success",
	typeNotSupported: "not_supported",
}

// Options and suboptions (IEC 61158-6-10, table 17).
const (
	optIP            = 0x01
	optDeviceProps   = 0x02
	optDHCP          = 0x03
	optControl       = 0x05
	optDeviceInit    = 0x06
	optManufacturer0 = 0x80
	optAll           = 0xFF

	subMACAddress   = 0x01
	subIPParameter  = 0x02
	subFullIPSuite  = 0x03
	subVendorValue  = 0x01
	subNameOfStatio = 0x02
	subDeviceID     = 0x03
	subDeviceRole   = 0x04
	subDeviceOption = 0x05
	subAliasName    = 0x06
	subDeviceInstan = 0x07
	subOEMDeviceID  = 0x08
	subStdGateway   = 0x09

	subControlStart        = 0x01
	subControlEnd          = 0x02
	subControlSignal       = 0x03
	subControlResponse     = 0x04
	subControlFactoryReset = 0x05
	subControlResetToFact  = 0x06

	subAll = 0xFF
)

type optionKey struct{ option, suboption uint8 }

// optionNames names the blocks a DCP PDU carries.
var optionNames = map[optionKey]string{
	{optIP, subMACAddress}:  "MACAddress",
	{optIP, subIPParameter}: "IPParameter",
	{optIP, subFullIPSuite}: "FullIPSuite",

	{optDeviceProps, subVendorValue}:  "DeviceVendorValue",
	{optDeviceProps, subNameOfStatio}: "NameOfStation",
	{optDeviceProps, subDeviceID}:     "DeviceID",
	{optDeviceProps, subDeviceRole}:   "DeviceRole",
	{optDeviceProps, subDeviceOption}: "DeviceOptions",
	{optDeviceProps, subAliasName}:    "AliasName",
	{optDeviceProps, subDeviceInstan}: "DeviceInstance",
	{optDeviceProps, subOEMDeviceID}:  "OEMDeviceID",
	{optDeviceProps, subStdGateway}:   "StandardGateway",

	{optDHCP, 0x0c}: "DHCPClientID",
	{optDHCP, 0x3d}: "DHCPClientIdentifier",
	{optDHCP, 0x3f}: "DHCPControlParameter",

	{optControl, subControlStart}:        "Start",
	{optControl, subControlEnd}:          "End",
	{optControl, subControlSignal}:       "Signal",
	{optControl, subControlResponse}:     "Response",
	{optControl, subControlFactoryReset}: "FactoryReset",
	{optControl, subControlResetToFact}:  "ResetToFactory",

	{optDeviceInit, 0x01}: "DeviceInitiative",

	{optAll, subAll}: "AllSelector",
}

func blockName(option, suboption uint8) string {
	if name, ok := optionNames[optionKey{option, suboption}]; ok {
		return name
	}
	if option >= optManufacturer0 && option < optAll {
		return "ManufacturerOption_" + utoa(uint32(option)) + "/" + utoa(uint32(suboption))
	}
	return "Option_" + utoa(uint32(option)) + "/" + utoa(uint32(suboption))
}

// blockErrors name why a station refused a block (IEC 61158-6-10, table 23).
var blockErrors = map[uint8]string{
	0: "Ok",
	1: "OptionNotSupported",
	2: "SuboptionNotSupportedOrNoDataSet",
	3: "SuboptionNotSet",
	4: "ResourceError",
	5: "SetNotPossibleByLocalReason",
	6: "InUseByInterface",
}

func blockErrorName(code uint8) string {
	if name, ok := blockErrors[code]; ok {
		return name
	}
	return "BlockError_" + utoa(uint32(code))
}

// ipBlockInfo says what state a station's IP configuration is in, which is
// the difference between a device that has an address and one still waiting
// to be given one (IEC 61158-6-10, table 19).
var ipBlockInfo = map[uint16]string{
	0x0000: "ip_not_set",
	0x0001: "ip_set",
	0x0002: "ip_set_by_dhcp",
	0x0080: "ip_not_set_address_conflict",
	0x0081: "ip_set_address_conflict",
	0x0082: "ip_set_by_dhcp_address_conflict",
}

// deviceRoles are the bits of the device role block: what part a station
// plays in the PROFINET system. A controller is a PLC, a device is the field
// hardware it drives, and a supervisor is an engineering station — which the
// device itself states, rather than being inferred from its behaviour.
var deviceRoles = []struct {
	bit  uint8
	name string
}{
	{0x01, "io_device"},
	{0x02, "io_controller"},
	{0x04, "io_multidevice"},
	{0x08, "io_supervisor"},
}

// vendors names the PROFIBUS Nutzerorganisation vendor identifiers this
// project is sure of.
//
// PNO has assigned thousands and reproducing that list from memory would put
// wrong manufacturers on assets; the identifier itself is always recorded,
// and the embedded OUI table names a manufacturer from the MAC address.
var vendors = map[uint16]string{
	0x002a: "Siemens",
}

const hexDigits = "0123456789abcdef"

func hex8(v uint8) string {
	return string([]byte{hexDigits[v>>4], hexDigits[v&0xf]})
}

func hex16(v uint16) string {
	return string([]byte{
		hexDigits[v>>12&0xf], hexDigits[v>>8&0xf], hexDigits[v>>4&0xf], hexDigits[v&0xf],
	})
}

func utoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
