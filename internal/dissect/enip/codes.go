package enip

import "github.com/rom/otinv/internal/model"

// The command, item, service, class and status codes of EtherNet/IP and CIP,
// as ODVA's specifications and the Wireshark dissector name them.

// Encapsulation commands (EtherNet/IP specification, chapter 2).
const (
	cmdNOP               = 0x0000
	cmdListServices      = 0x0004
	cmdListIdentity      = 0x0063
	cmdListInterfaces    = 0x0064
	cmdRegisterSession   = 0x0065
	cmdUnRegisterSession = 0x0066
	cmdSendRRData        = 0x006F
	cmdSendUnitData      = 0x0070
	cmdIndicateStatus    = 0x0072
	cmdCancel            = 0x0073
)

type commandInfo struct {
	name  string
	class model.Classification
}

// commands maps an encapsulation command to its name and classification.
//
// The three list commands are how a device is found and made to describe
// itself, so they are discovery. The rest of the encapsulation layer manages
// the session and carries CIP; a message that carries CIP takes its
// classification from the service inside it instead.
var commands = map[uint16]commandInfo{
	cmdNOP:               {"NOP", model.ClassOther},
	cmdListServices:      {"ListServices", model.ClassDiscovery},
	cmdListIdentity:      {"ListIdentity", model.ClassDiscovery},
	cmdListInterfaces:    {"ListInterfaces", model.ClassDiscovery},
	cmdRegisterSession:   {"RegisterSession", model.ClassOther},
	cmdUnRegisterSession: {"UnRegisterSession", model.ClassOther},
	cmdSendRRData:        {"SendRRData", model.ClassOther},
	cmdSendUnitData:      {"SendUnitData", model.ClassOther},
	cmdIndicateStatus:    {"IndicateStatus", model.ClassOther},
	cmdCancel:            {"Cancel", model.ClassOther},
}

func command(code uint16) commandInfo {
	if info, ok := commands[code]; ok {
		return info
	}
	return commandInfo{"Command_0x" + hex16(code), model.ClassOther}
}

// Encapsulation status codes (EtherNet/IP specification, table 2-3.3).
var encapStatus = map[uint32]string{
	0x00: "Success",
	0x01: "InvalidCommand",
	0x02: "InsufficientMemory",
	0x03: "IncorrectData",
	0x64: "InvalidSessionHandle",
	0x65: "InvalidLength",
	0x69: "UnsupportedProtocolRevision",
}

// Common Packet Format item types (EtherNet/IP specification, table 2-6.1).
const (
	itemNullAddress          = 0x0000
	itemListIdentityResponse = 0x000C
	itemListServiceResponse  = 0x0100
	itemConnectedAddress     = 0x00A1
	itemConnectedData        = 0x00B1
	itemUnconnectedData      = 0x00B2
	itemSockaddrO2T          = 0x8000
	itemSockaddrT2O          = 0x8001
	itemSequencedAddress     = 0x8002
)

var items = map[uint16]string{
	itemNullAddress:          "NullAddress",
	itemListIdentityResponse: "ListIdentityResponse",
	itemListServiceResponse:  "ListServicesResponse",
	itemConnectedAddress:     "ConnectedAddress",
	itemConnectedData:        "ConnectedData",
	itemUnconnectedData:      "UnconnectedData",
	itemSockaddrO2T:          "SockaddrInfoO2T",
	itemSockaddrT2O:          "SockaddrInfoT2O",
	itemSequencedAddress:     "SequencedAddress",
}

func itemName(code uint16) string {
	if name, ok := items[code]; ok {
		return name
	}
	return "Item_0x" + hex16(code)
}

// CIP common services (CIP Networks Library volume 1, appendix A). These are
// the codes every object answers the same way, which is why they can be named
// without knowing what the device is.
const (
	svcGetAttributesAll      = 0x01
	svcSetAttributesAll      = 0x02
	svcGetAttributeList      = 0x03
	svcSetAttributeList      = 0x04
	svcReset                 = 0x05
	svcStart                 = 0x06
	svcStop                  = 0x07
	svcCreate                = 0x08
	svcDelete                = 0x09
	svcMultipleServicePacket = 0x0A
	svcApplyAttributes       = 0x0D
	svcGetAttributeSingle    = 0x0E
	svcSetAttributeSingle    = 0x10
	svcFindNextObject        = 0x11
	svcRestore               = 0x14
	svcSave                  = 0x15
	svcNoOperation           = 0x16
	svcGetMember             = 0x17
	svcSetMember             = 0x18
	svcInsertMember          = 0x19
	svcRemoveMember          = 0x1A
	svcGroupSync             = 0x1B

	// maxCommonService is the last code the specification defines for every
	// object. Above it a code means whatever the object's class, or the
	// device's vendor, says it means.
	maxCommonService = 0x31
)

type serviceInfo struct {
	name  string
	class model.Classification
}

// commonServices maps a CIP common service to its name and classification.
//
// Reading and writing attributes are the bulk of CIP and classify the obvious
// way. Reset, Start and Stop act on the device without changing what is in
// it, so they are control, which is what CLAUDE.md's rule on CIP stop and
// reset services matches. Creating and deleting instances, and saving and
// restoring them, change what the device holds, so they are program: that is
// how a configuration or a firmware image is put into a CIP device.
var commonServices = map[uint8]serviceInfo{
	svcGetAttributesAll:      {"Get_Attributes_All", model.ClassRead},
	svcSetAttributesAll:      {"Set_Attributes_All", model.ClassWrite},
	svcGetAttributeList:      {"Get_Attribute_List", model.ClassRead},
	svcSetAttributeList:      {"Set_Attribute_List", model.ClassWrite},
	svcReset:                 {"Reset", model.ClassControl},
	svcStart:                 {"Start", model.ClassControl},
	svcStop:                  {"Stop", model.ClassControl},
	svcCreate:                {"Create", model.ClassProgram},
	svcDelete:                {"Delete", model.ClassProgram},
	svcMultipleServicePacket: {"Multiple_Service_Packet", model.ClassOther},
	svcApplyAttributes:       {"Apply_Attributes", model.ClassWrite},
	svcGetAttributeSingle:    {"Get_Attribute_Single", model.ClassRead},
	svcSetAttributeSingle:    {"Set_Attribute_Single", model.ClassWrite},
	svcFindNextObject:        {"Find_Next_Object_Instance", model.ClassRead},
	svcRestore:               {"Restore", model.ClassProgram},
	svcSave:                  {"Save", model.ClassProgram},
	svcNoOperation:           {"No_Operation", model.ClassOther},
	svcGetMember:             {"Get_Member", model.ClassRead},
	svcSetMember:             {"Set_Member", model.ClassWrite},
	svcInsertMember:          {"Insert_Member", model.ClassWrite},
	svcRemoveMember:          {"Remove_Member", model.ClassWrite},
	svcGroupSync:             {"GroupSync", model.ClassOther},
}

// CIP object classes worth naming (CIP Networks Library volume 1, chapter 5,
// and volume 2 for the EtherNet/IP specific ones).
const (
	classIdentity          = 0x01
	classMessageRouter     = 0x02
	classAssembly          = 0x04
	classConnection        = 0x05
	classConnectionManager = 0x06
	classParameter         = 0x0F
	classFile              = 0x37
	classPCCC              = 0x67
	classSymbol            = 0x6B
	classTemplate          = 0x6C
	classPort              = 0xF4
	classTCPIPInterface    = 0xF5
	classEthernetLink      = 0xF6
)

var classes = map[uint32]string{
	classIdentity:          "Identity",
	classMessageRouter:     "MessageRouter",
	0x03:                   "DeviceNet",
	classAssembly:          "Assembly",
	classConnection:        "Connection",
	classConnectionManager: "ConnectionManager",
	0x07:                   "Register",
	0x08:                   "DiscreteInputPoint",
	0x09:                   "DiscreteOutputPoint",
	0x0A:                   "AnalogInputPoint",
	0x0B:                   "AnalogOutputPoint",
	0x0E:                   "PresenceSensing",
	classParameter:         "Parameter",
	0x10:                   "ParameterGroup",
	0x1D:                   "DiscreteInputGroup",
	0x1E:                   "DiscreteOutputGroup",
	0x28:                   "MotorData",
	0x29:                   "ControlSupervisor",
	0x2A:                   "ACDCDrive",
	0x2B:                   "AcknowledgeHandler",
	0x2C:                   "Overload",
	classFile:              "File",
	0x43:                   "TimeSync",
	0x44:                   "Modbus",
	0x47:                   "DeviceLevelRing",
	0x48:                   "QoS",
	0x4D:                   "BaseSwitch",
	0x4E:                   "SNMP",
	0x50:                   "RSTPBridge",
	0x51:                   "RSTPPort",
	0x59:                   "CIPSecurity",
	0x5A:                   "EtherNetIPSecurity",
	0x5B:                   "CertificateManagement",
	classPCCC:              "PCCC",
	classSymbol:            "Symbol",
	classTemplate:          "Template",
	0x6D:                   "ConnectionConfiguration",
	classPort:              "Port",
	classTCPIPInterface:    "TCPIPInterface",
	classEthernetLink:      "EthernetLink",
}

func className(id uint32) string {
	if name, ok := classes[id]; ok {
		return name
	}
	return "Class_0x" + hex32(id)
}

// Services above the common range, named only where the path says which
// object they belong to.
//
// A code above 0x31 means whatever the object's class says it means, and
// above 0x4A whatever the device's vendor says. The same code is therefore
// two different operations on two different objects: 0x52 is
// Read_Tag_Fragmented on a Logix symbol and Unconnected_Send on the
// Connection Manager, and these captures carry both. Naming one without
// knowing the class would be a guess, and naming a vendor service as a read
// when it might be a write is the one mistake that would hide something, so
// a code reached with no class to match is reported as the number it is.
const (
	svcReadTag           = 0x4C
	svcWriteTag          = 0x4D
	svcForwardClose      = 0x4E
	svcExecutePCCC       = 0x4B
	svcReadTagFragmented = 0x52
	svcUnconnectedSend   = 0x52
	svcWriteTagFragment  = 0x53
	svcForwardOpen       = 0x54
	svcInstanceAttrList  = 0x55
	svcLargeForwardOpen  = 0x5B
)

// classServices names a service by the class of the object it was sent to.
type classService struct {
	code  uint8
	class uint32
}

var classServices = map[classService]serviceInfo{
	{svcReadTag, classSymbol}:                     {"Read_Tag", model.ClassRead},
	{svcReadTag, classTemplate}:                   {"Read_Template", model.ClassRead},
	{svcWriteTag, classSymbol}:                    {"Write_Tag", model.ClassWrite},
	{svcReadTagFragmented, classSymbol}:           {"Read_Tag_Fragmented", model.ClassRead},
	{svcWriteTagFragment, classSymbol}:            {"Write_Tag_Fragmented", model.ClassWrite},
	{svcInstanceAttrList, classSymbol}:            {"Get_Instance_Attribute_List", model.ClassRead},
	{svcInstanceAttrList, classTemplate}:          {"Get_Instance_Attribute_List", model.ClassRead},
	{svcForwardClose, classConnectionManager}:     {"Forward_Close", model.ClassOther},
	{svcForwardOpen, classConnectionManager}:      {"Forward_Open", model.ClassOther},
	{svcLargeForwardOpen, classConnectionManager}: {"Large_Forward_Open", model.ClassOther},
	// Unconnected_Send is how a bridge is asked to pass a request to the
	// backplane behind it. What it routes is read as its own operation, so
	// the wrapper itself is not an operation on anything.
	{svcUnconnectedSend, classConnectionManager}: {"Unconnected_Send", model.ClassOther},
	// Execute_PCCC wraps a legacy DF1 command, which this does not decode,
	// so what the wrapped command does is not known from here.
	{svcExecutePCCC, classPCCC}: {"Execute_PCCC", model.ClassOther},
}

// symbolicServices names the services that address a tag by name. A request
// whose path carries a symbol is a Logix tag access whatever class segment it
// does or does not also carry.
var symbolicServices = map[uint8]serviceInfo{
	svcReadTag:           {"Read_Tag", model.ClassRead},
	svcWriteTag:          {"Write_Tag", model.ClassWrite},
	svcReadTagFragmented: {"Read_Tag_Fragmented", model.ClassRead},
	svcWriteTagFragment:  {"Write_Tag_Fragmented", model.ClassWrite},
	svcInstanceAttrList:  {"Get_Instance_Attribute_List", model.ClassRead},
}

// unambiguousServices maps a service code above the common range to the one
// meaning every object this project knows for it agrees on.
//
// It exists for replies. A CIP reply carries only the service code it is
// answering, never the path, and the two directions of a stream are decoded
// independently, so there is nothing in a reply that says which object
// answered. Where every meaning of a code agrees on both the operation and
// its classification, the reply can be named anyway: 0x54 is Forward_Open on
// the Connection Manager and nothing else here. Where they disagree — 0x52 is
// a fragmented tag read on a symbol and Unconnected_Send on the Connection
// Manager — the code is reported as the number it is, because a reply named
// as a read that was something else is exactly the mistake worth avoiding.
var unambiguousServices = buildUnambiguous()

func buildUnambiguous() map[uint8]serviceInfo {
	meanings := map[uint8][]serviceInfo{}
	for k, info := range classServices {
		meanings[k.code] = append(meanings[k.code], info)
	}
	for code, info := range symbolicServices {
		meanings[code] = append(meanings[code], info)
	}
	out := make(map[uint8]serviceInfo, len(meanings))
	for code, list := range meanings {
		agreed := true
		for _, info := range list[1:] {
			if info != list[0] {
				agreed = false
				break
			}
		}
		if agreed {
			out[code] = list[0]
		}
	}
	return out
}

// numbered reports a service code that could not be named.
func numbered(code uint8) serviceInfo {
	return serviceInfo{"Service_0x" + hex8(code), model.ClassOther}
}

func unambiguous(code uint8) (serviceInfo, bool) {
	if info, ok := unambiguousServices[code]; ok {
		return info, true
	}
	return numbered(code), false
}

// service names the service of a CIP request. symbolic says the request path
// addressed an object by name, which is how a tag is read on a Logix
// controller and is as good as the class at saying which object a vendor
// service belongs to.
//
// The second return value is false when the code could not be named with
// certainty, which the caller records so that the GUI does not present a
// guess as a fact.
func service(code uint8, class uint32, hasClass, symbolic bool) (serviceInfo, bool) {
	if info, ok := commonServices[code]; ok {
		return info, true
	}
	if code <= maxCommonService {
		return numbered(code), true
	}
	if hasClass {
		if info, ok := classServices[classService{code, class}]; ok {
			return info, true
		}
		// The path named a class this code is not defined for, so what it
		// means here is between the device and its vendor. These captures
		// carry such requests — 0x4C, a tag read on a symbol, sent to a
		// class that defines no such service — and a guess at one of them is
		// a guess about whether a controller was read or written.
		return numbered(code), false
	}
	if symbolic {
		if info, ok := symbolicServices[code]; ok {
			return info, true
		}
	}
	return unambiguous(code)
}

// replyService names the service of a CIP reply, which carries no path. See
// unambiguousServices.
func replyService(code uint8) (serviceInfo, bool) {
	if info, ok := commonServices[code]; ok {
		return info, true
	}
	if code <= maxCommonService {
		return numbered(code), true
	}
	return unambiguous(code)
}

// CIP general status codes (CIP Networks Library volume 1, appendix B). The
// status is how a device refuses, and which refusal it is separates a client
// asking for something that does not exist from one asking for something it
// may not have.
var generalStatus = map[uint8]string{
	0x00: "Success",
	0x01: "ConnectionFailure",
	0x02: "ResourceUnavailable",
	0x03: "InvalidParameterValue",
	0x04: "PathSegmentError",
	0x05: "PathDestinationUnknown",
	0x06: "PartialTransfer",
	0x07: "ConnectionLost",
	0x08: "ServiceNotSupported",
	0x09: "InvalidAttributeValue",
	0x0A: "AttributeListError",
	0x0B: "AlreadyInRequestedMode",
	0x0C: "ObjectStateConflict",
	0x0D: "ObjectAlreadyExists",
	0x0E: "AttributeNotSettable",
	0x0F: "PrivilegeViolation",
	0x10: "DeviceStateConflict",
	0x11: "ReplyDataTooLarge",
	0x12: "FragmentationOfPrimitiveValue",
	0x13: "NotEnoughData",
	0x14: "AttributeNotSupported",
	0x15: "TooMuchData",
	0x16: "ObjectDoesNotExist",
	0x17: "ServiceFragmentationSequenceNotInProgress",
	0x18: "NoStoredAttributeData",
	0x19: "StoreOperationFailure",
	0x1A: "RoutingFailureRequestTooLarge",
	0x1B: "RoutingFailureResponseTooLarge",
	0x1C: "MissingAttributeListEntryData",
	0x1D: "InvalidAttributeValueList",
	0x1E: "EmbeddedServiceError",
	0x1F: "VendorSpecificError",
	0x20: "InvalidParameter",
	0x21: "WriteOnceValueOrMediumAlreadyWritten",
	0x22: "InvalidReplyReceived",
	0x25: "KeyFailureInPath",
	0x26: "PathSizeInvalid",
	0x27: "UnexpectedAttributeInList",
	0x28: "InvalidMemberID",
	0x29: "MemberNotSettable",
	0x2A: "Group2OnlyServerGeneralFailure",
	0xFF: "GeneralError",
}

func statusName(code uint8) string {
	if name, ok := generalStatus[code]; ok {
		return name
	}
	return "Status_0x" + hex8(code)
}

// deviceProfiles names the device types of the ODVA device profiles, which is
// a device saying what kind of thing it is. That is better evidence for a
// role than behaviour, so the inventory takes it.
//
// The list is the profiles this project has use for rather than all of them;
// a type it does not name is reported as its number.
var deviceProfiles = map[uint16]string{
	0x00: "Generic Device",
	0x02: "AC Drive",
	0x03: "Motor Overload",
	0x04: "Limit Switch",
	0x05: "Inductive Proximity Switch",
	0x06: "Photoelectric Sensor",
	0x07: "General Purpose Discrete I/O",
	0x09: "Resolver",
	0x0C: "Communications Adapter",
	0x0E: "Programmable Logic Controller",
	0x10: "Position Controller",
	0x13: "DC Drive",
	0x15: "Contactor",
	0x16: "Motor Starter",
	0x17: "Soft Start",
	0x18: "Human Machine Interface",
	0x1B: "Pneumatic Valve",
	0x1D: "Process Control Valve",
	0x22: "Encoder",
	0x23: "Safety Discrete I/O Device",
	0x24: "Fluid Flow Controller",
	0x25: "CIP Motion Drive",
	0x28: "CIP Modbus Device",
	0x29: "CIP Modbus Translator",
	0x2A: "Safety Analog I/O Device",
	0x2C: "Managed Ethernet Switch",
	0x32: "ControlNet Physical Layer Component",
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

func hex32(v uint32) string {
	if v <= 0xffff {
		return hex16(uint16(v))
	}
	return hex16(uint16(v>>16)) + hex16(uint16(v))
}
