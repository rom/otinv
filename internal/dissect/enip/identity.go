package enip

import (
	"encoding/binary"
	"net"
	"strconv"
)

// What an EtherNet/IP device says about itself.
//
// There are two places to read it from without asking the device anything.
// A ListIdentity reply carries the whole Identity object in one item, which is
// how a device answers a broadcast that asks what is out there; and the
// Identity object can be read with an ordinary CIP service, which is the first
// thing most clients do after opening a session.

// identity is the Identity object (CIP volume 1, 5-2): what kind of device
// this is, who made it, which model and revision, and the name it carries.
type identity struct {
	vendor      uint16
	deviceType  uint16
	productCode uint16
	major       uint8
	minor       uint8
	status      uint16
	serial      uint32
	name        string
	state       *uint8

	// addr is the socket address a ListIdentity item carries, which is the
	// address the device believes it has.
	addr string
	// encapVersion is the encapsulation protocol revision the device speaks.
	encapVersion uint16
}

// Identity object attribute block geometry: the vendor, device type, product
// code, revision, status and serial number, then the length prefixed product
// name (CIP volume 1, 5-2.3).
const (
	identityFixedLen = 2 + 2 + 2 + 2 + 2 + 4
	identityNameLen  = identityFixedLen + 1

	// listIdentityPrefix is the encapsulation version and the sixteen octet
	// socket address that precede the attribute block in a ListIdentity item
	// (EtherNet/IP specification, 2-4.2.2).
	listIdentityPrefix = 2 + 16
)

// parseIdentityItem reads a ListIdentity response item.
func parseIdentityItem(b []byte) (*identity, bool) {
	if len(b) < listIdentityPrefix+identityNameLen {
		return nil, false
	}
	id, ok := parseIdentityBlock(b[listIdentityPrefix:], true)
	if !ok {
		return nil, false
	}
	id.encapVersion = binary.LittleEndian.Uint16(b[:2])
	// The socket address is sockaddr_in in network byte order: family, port,
	// address and eight unused octets.
	sin := b[2:listIdentityPrefix]
	ip := net.IP(sin[4:8])
	if !ip.Equal(net.IPv4zero) {
		id.addr = ip.String() + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(sin[2:4])))
	}
	return id, true
}

// parseIdentityBlock reads the Identity object's attributes. loose allows the
// trailing state octet to be absent, which is how some devices answer.
func parseIdentityBlock(b []byte, loose bool) (*identity, bool) {
	if len(b) < identityNameLen {
		return nil, false
	}
	nameLen := int(b[identityFixedLen])
	if identityNameLen+nameLen > len(b) {
		return nil, false
	}
	id := &identity{
		vendor:      binary.LittleEndian.Uint16(b[0:2]),
		deviceType:  binary.LittleEndian.Uint16(b[2:4]),
		productCode: binary.LittleEndian.Uint16(b[4:6]),
		major:       b[6],
		minor:       b[7],
		status:      binary.LittleEndian.Uint16(b[8:10]),
		serial:      binary.LittleEndian.Uint32(b[10:14]),
		name:        printable(b[identityNameLen : identityNameLen+nameLen]),
	}
	if rest := b[identityNameLen+nameLen:]; len(rest) > 0 {
		state := rest[0]
		id.state = &state
	} else if !loose {
		return nil, false
	}
	return id, true
}

// identityFromAttributes reads an Identity object out of the reply to a
// Get_Attributes_All, which is the one case where a device's own description
// of itself arrives with nothing to say which object it came from.
//
// A CIP reply carries no path, and this tool decodes each direction of a
// stream on its own, so the request that would name the Identity object is
// not available here. What is available is the shape of the answer, and the
// Identity object's is specific: six fixed fields, then a name whose length
// octet accounts for every remaining octet but at most one, then at most the
// state octet. A reply is read as an identity only when all of that holds,
// the device type is a profile ODVA has defined, and the vendor and revision
// are set — because putting a wrong vendor and model on an asset is worse
// than leaving it unknown. Measured against the public Rockwell captures in
// testdata that gate accepts every Identity read and no other reply; the
// reply to a Get_Attributes_All of any other object is left alone.
func identityFromAttributes(b []byte) (*identity, bool) {
	if len(b) < identityNameLen {
		return nil, false
	}
	nameLen := int(b[identityFixedLen])
	remaining := len(b) - identityNameLen
	if nameLen == 0 || (nameLen != remaining && nameLen != remaining-1) {
		return nil, false
	}
	for _, c := range b[identityNameLen : identityNameLen+nameLen] {
		if c < 0x20 || c > 0x7e {
			return nil, false
		}
	}
	id, ok := parseIdentityBlock(b, true)
	if !ok {
		return nil, false
	}
	if id.vendor == 0 || id.major == 0 {
		return nil, false
	}
	if _, known := deviceProfiles[id.deviceType]; !known {
		return nil, false
	}
	return id, true
}

// vendors names the CIP vendor identifiers this project is sure of.
//
// ODVA assigns several hundred and the full list is not something to
// reproduce from memory: a wrong vendor name is worse than none, and the
// embedded OUI table already names the manufacturer from the MAC address.
// The identifier itself is always recorded, so a device of an unnamed vendor
// still carries the evidence.
var vendors = map[uint16]string{
	1: "Rockwell Automation/Allen-Bradley",
}

// deviceTypeName names the ODVA device profile, or reports the number.
func deviceTypeName(t uint16) string {
	if name, ok := deviceProfiles[t]; ok {
		return name
	}
	return "DeviceType_0x" + hex16(t)
}

// fill records an identity on an event. Only the fields the device actually
// stated are set, so nothing is inferred from a zero.
func (id *identity) fill(set func(key, value string), attr func(key, value string)) {
	set("product_name", id.name)
	set("device_type", deviceTypeName(id.deviceType))
	set("product_code", strconv.Itoa(int(id.productCode)))
	set("major_minor_revision", strconv.Itoa(int(id.major))+"."+strconv.Itoa(int(id.minor)))
	// The serial number is unique only together with the vendor, and
	// Rockwell prints it as eight hexadecimal digits, which is how it is
	// written on the device.
	set("serial_number", "0x"+hex32be(id.serial))
	set("vendor_id", strconv.Itoa(int(id.vendor)))
	if name, ok := vendors[id.vendor]; ok {
		set("vendor_name", name)
	}

	attr("device_status", "0x"+hex16(id.status))
	if id.state != nil {
		attr("device_state", strconv.Itoa(int(*id.state)))
	}
	if id.addr != "" {
		attr("reported_address", id.addr)
	}
	if id.encapVersion != 0 {
		attr("encapsulation_version", strconv.Itoa(int(id.encapVersion)))
	}
}

// listServicesItem reads a ListServices reply item: the encapsulation
// version, what the device will carry, and the service's name.
func listServicesItem(b []byte) (version uint16, flags uint16, name string, ok bool) {
	const fixed = 2 + 2 + 16
	if len(b) < fixed {
		return 0, 0, "", false
	}
	version = binary.LittleEndian.Uint16(b[0:2])
	flags = binary.LittleEndian.Uint16(b[2:4])
	// The name is sixteen octets of ASCII padded with NULs.
	end := 4
	for end < fixed && b[end] != 0 {
		end++
	}
	return version, flags, printable(b[4:end]), true
}

// hex32be renders a serial number as eight hexadecimal digits.
func hex32be(v uint32) string {
	return hex16(uint16(v>>16)) + hex16(uint16(v))
}
