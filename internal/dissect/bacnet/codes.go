package bacnet

import (
	"strconv"

	"github.com/rom/otinv/internal/model"
)

// The virtual link, network and application layer codes of BACnet/IP, as
// ASHRAE 135 defines them and the Wireshark bacapp dissector names them.

// BVLL functions (ASHRAE 135, annex J.2.1).
const (
	bvlcResult                    = 0x00
	bvlcWriteBDT                  = 0x01
	bvlcReadBDT                   = 0x02
	bvlcReadBDTAck                = 0x03
	bvlcForwardedNPDU             = 0x04
	bvlcRegisterForeign           = 0x05
	bvlcReadFDT                   = 0x06
	bvlcReadFDTAck                = 0x07
	bvlcDeleteFDTEntry            = 0x08
	bvlcDistributeBroadcast       = 0x09
	bvlcOriginalUnicast           = 0x0A
	bvlcOriginalBroadcast         = 0x0B
	bvlcSecureBVLL                = 0x0C
	bvlcTypeBACnetIP        uint8 = 0x81
)

var bvlcFunctions = map[uint8]string{
	bvlcResult:              "BVLC-Result",
	bvlcWriteBDT:            "Write-Broadcast-Distribution-Table",
	bvlcReadBDT:             "Read-Broadcast-Distribution-Table",
	bvlcReadBDTAck:          "Read-Broadcast-Distribution-Table-Ack",
	bvlcForwardedNPDU:       "Forwarded-NPDU",
	bvlcRegisterForeign:     "Register-Foreign-Device",
	bvlcReadFDT:             "Read-Foreign-Device-Table",
	bvlcReadFDTAck:          "Read-Foreign-Device-Table-Ack",
	bvlcDeleteFDTEntry:      "Delete-Foreign-Device-Table-Entry",
	bvlcDistributeBroadcast: "Distribute-Broadcast-To-Network",
	bvlcOriginalUnicast:     "Original-Unicast-NPDU",
	bvlcOriginalBroadcast:   "Original-Broadcast-NPDU",
	bvlcSecureBVLL:          "Secure-BVLL",
}

func bvlcName(fn uint8) string {
	if name, ok := bvlcFunctions[fn]; ok {
		return name
	}
	return "BVLC_0x" + hex8(fn)
}

// carriesNPDU reports whether a BVLL function's body is a network layer PDU.
// The rest carry tables and results of the virtual link layer itself, and
// reading those as an NPDU would invent a message.
func carriesNPDU(fn uint8) bool {
	switch fn {
	case bvlcOriginalUnicast, bvlcOriginalBroadcast, bvlcForwardedNPDU, bvlcDistributeBroadcast:
		return true
	default:
		return false
	}
}

// bvlcResults name how the virtual link layer refused (ASHRAE 135, J.2.1.1).
var bvlcResults = map[uint16]string{
	0x0000: "Successful completion",
	0x0010: "Write-Broadcast-Distribution-Table NAK",
	0x0020: "Read-Broadcast-Distribution-Table NAK",
	0x0030: "Register-Foreign-Device NAK",
	0x0040: "Read-Foreign-Device-Table NAK",
	0x0050: "Delete-Foreign-Device-Table-Entry NAK",
	0x0060: "Distribute-Broadcast-To-Network NAK",
}

func bvlcResultName(code uint16) string {
	if name, ok := bvlcResults[code]; ok {
		return name
	}
	return "Result_0x" + hex16(code)
}

// Network layer message types (ASHRAE 135, clause 6.4). These are the router
// to router messages: how a BACnet internetwork discovers its own topology,
// which is also how a device can be told to send its traffic elsewhere.
var networkMessages = map[uint8]string{
	0x00: "Who-Is-Router-To-Network",
	0x01: "I-Am-Router-To-Network",
	0x02: "I-Could-Be-Router-To-Network",
	0x03: "Reject-Message-To-Network",
	0x04: "Router-Busy-To-Network",
	0x05: "Router-Available-To-Network",
	0x06: "Initialize-Routing-Table",
	0x07: "Initialize-Routing-Table-Ack",
	0x08: "Establish-Connection-To-Network",
	0x09: "Disconnect-Connection-To-Network",
	0x0A: "Challenge-Request",
	0x0B: "Security-Payload",
	0x0C: "Security-Response",
	0x0D: "Request-Key-Update",
	0x0E: "Update-Key-Set",
	0x0F: "Update-Distribution-Key",
	0x10: "Request-Master-Key",
	0x11: "Set-Master-Key",
	0x12: "What-Is-Network-Number",
	0x13: "Network-Number-Is",
}

func networkMessageName(t uint8) string {
	if name, ok := networkMessages[t]; ok {
		return name
	}
	return "NetworkMessage_0x" + hex8(t)
}

// APDU types (ASHRAE 135, clause 20.1.2).
const (
	pduConfirmedRequest   = 0
	pduUnconfirmedRequest = 1
	pduSimpleACK          = 2
	pduComplexACK         = 3
	pduSegmentACK         = 4
	pduError              = 5
	pduReject             = 6
	pduAbort              = 7
)

var pduTypes = map[uint8]string{
	pduConfirmedRequest:   "Confirmed-Request",
	pduUnconfirmedRequest: "Unconfirmed-Request",
	pduSimpleACK:          "SimpleACK",
	pduComplexACK:         "ComplexACK",
	pduSegmentACK:         "SegmentACK",
	pduError:              "Error",
	pduReject:             "Reject",
	pduAbort:              "Abort",
}

type serviceInfo struct {
	name  string
	class model.Classification
}

// Confirmed service choices (ASHRAE 135, clause 21).
const (
	svcAcknowledgeAlarm      = 0
	svcConfirmedCOVNotify    = 1
	svcConfirmedEventNotify  = 2
	svcGetAlarmSummary       = 3
	svcGetEnrollmentSummary  = 4
	svcSubscribeCOV          = 5
	svcAtomicReadFile        = 6
	svcAtomicWriteFile       = 7
	svcAddListElement        = 8
	svcRemoveListElement     = 9
	svcCreateObject          = 10
	svcDeleteObject          = 11
	svcReadProperty          = 12
	svcReadPropertyCondition = 13
	svcReadPropertyMultiple  = 14
	svcWriteProperty         = 15
	svcWritePropertyMultiple = 16
	svcDeviceCommControl     = 17
	svcConfirmedPrivateXfer  = 18
	svcConfirmedTextMessage  = 19
	svcReinitializeDevice    = 20
	svcVTOpen                = 21
	svcVTClose               = 22
	svcVTData                = 23
	svcAuthenticate          = 24
	svcRequestKey            = 25
	svcReadRange             = 26
	svcLifeSafetyOperation   = 27
	svcSubscribeCOVProperty  = 28
	svcGetEventInformation   = 29
)

// confirmedServices maps a confirmed service to its name and classification.
//
// Reads and writes of properties are the bulk of BACnet and classify the
// obvious way. Three are worth more thought. deviceCommunicationControl
// silences a device's traffic for a chosen number of minutes and
// reinitializeDevice cold or warm starts it, so both act on the device rather
// than on data: control, and the two services a building controller should
// never see from an unexpected source. atomicWriteFile is how a configuration
// or a firmware image gets into a BACnet device, which makes it program.
var confirmedServices = map[uint8]serviceInfo{
	svcAcknowledgeAlarm:      {"acknowledgeAlarm", model.ClassWrite},
	svcConfirmedCOVNotify:    {"confirmedCOVNotification", model.ClassRead},
	svcConfirmedEventNotify:  {"confirmedEventNotification", model.ClassRead},
	svcGetAlarmSummary:       {"getAlarmSummary", model.ClassRead},
	svcGetEnrollmentSummary:  {"getEnrollmentSummary", model.ClassRead},
	svcSubscribeCOV:          {"subscribeCOV", model.ClassRead},
	svcAtomicReadFile:        {"atomicReadFile", model.ClassRead},
	svcAtomicWriteFile:       {"atomicWriteFile", model.ClassProgram},
	svcAddListElement:        {"addListElement", model.ClassWrite},
	svcRemoveListElement:     {"removeListElement", model.ClassWrite},
	svcCreateObject:          {"createObject", model.ClassProgram},
	svcDeleteObject:          {"deleteObject", model.ClassProgram},
	svcReadProperty:          {"readProperty", model.ClassRead},
	svcReadPropertyCondition: {"readPropertyConditional", model.ClassRead},
	svcReadPropertyMultiple:  {"readPropertyMultiple", model.ClassRead},
	svcWriteProperty:         {"writeProperty", model.ClassWrite},
	svcWritePropertyMultiple: {"writePropertyMultiple", model.ClassWrite},
	svcDeviceCommControl:     {"deviceCommunicationControl", model.ClassControl},
	svcConfirmedPrivateXfer:  {"confirmedPrivateTransfer", model.ClassOther},
	svcConfirmedTextMessage:  {"confirmedTextMessage", model.ClassOther},
	svcReinitializeDevice:    {"reinitializeDevice", model.ClassControl},
	svcVTOpen:                {"vtOpen", model.ClassOther},
	svcVTClose:               {"vtClose", model.ClassOther},
	svcVTData:                {"vtData", model.ClassOther},
	svcAuthenticate:          {"authenticate", model.ClassOther},
	svcRequestKey:            {"requestKey", model.ClassOther},
	svcReadRange:             {"readRange", model.ClassRead},
	svcLifeSafetyOperation:   {"lifeSafetyOperation", model.ClassControl},
	svcSubscribeCOVProperty:  {"subscribeCOVProperty", model.ClassRead},
	svcGetEventInformation:   {"getEventInformation", model.ClassRead},
}

// Unconfirmed service choices (ASHRAE 135, clause 21).
const (
	svcIAm                    = 0
	svcIHave                  = 1
	svcUnconfirmedCOVNotify   = 2
	svcUnconfirmedEventNotify = 3
	svcUnconfirmedPrivateXfer = 4
	svcUnconfirmedTextMessage = 5
	svcTimeSynchronization    = 6
	svcWhoHas                 = 7
	svcWhoIs                  = 8
	svcUTCTimeSynchronization = 9
	svcWriteGroup             = 10
)

// unconfirmedServices maps an unconfirmed service to its name and class.
//
// who-Is and i-Am are how a BACnet device is found and how it answers, so
// they are discovery — and an i-Am is the richest identity the protocol
// gives away for free. The two time synchronisations write the device's clock,
// which is the same reading the IEC 104 clock sync gets.
var unconfirmedServices = map[uint8]serviceInfo{
	svcIAm:                    {"i-Am", model.ClassDiscovery},
	svcIHave:                  {"i-Have", model.ClassDiscovery},
	svcUnconfirmedCOVNotify:   {"unconfirmedCOVNotification", model.ClassRead},
	svcUnconfirmedEventNotify: {"unconfirmedEventNotification", model.ClassRead},
	svcUnconfirmedPrivateXfer: {"unconfirmedPrivateTransfer", model.ClassOther},
	svcUnconfirmedTextMessage: {"unconfirmedTextMessage", model.ClassOther},
	svcTimeSynchronization:    {"timeSynchronization", model.ClassWrite},
	svcWhoHas:                 {"who-Has", model.ClassDiscovery},
	svcWhoIs:                  {"who-Is", model.ClassDiscovery},
	svcUTCTimeSynchronization: {"utcTimeSynchronization", model.ClassWrite},
	svcWriteGroup:             {"writeGroup", model.ClassWrite},
}

func confirmedService(choice uint8) (serviceInfo, bool) {
	if info, ok := confirmedServices[choice]; ok {
		return info, true
	}
	return serviceInfo{"ConfirmedService_" + strconv.Itoa(int(choice)), model.ClassOther}, false
}

func unconfirmedService(choice uint8) (serviceInfo, bool) {
	if info, ok := unconfirmedServices[choice]; ok {
		return info, true
	}
	return serviceInfo{"UnconfirmedService_" + strconv.Itoa(int(choice)), model.ClassOther}, false
}

// Object types worth naming (ASHRAE 135, clause 12). The device object is the
// one every BACnet device has and the one that describes it.
const objectTypeDevice = 8

var objectTypes = map[uint16]string{
	0:  "analog-input",
	1:  "analog-output",
	2:  "analog-value",
	3:  "binary-input",
	4:  "binary-output",
	5:  "binary-value",
	6:  "calendar",
	7:  "command",
	8:  "device",
	9:  "event-enrollment",
	10: "file",
	11: "group",
	12: "loop",
	13: "multi-state-input",
	14: "multi-state-output",
	15: "notification-class",
	16: "program",
	17: "schedule",
	18: "averaging",
	19: "multi-state-value",
	20: "trend-log",
	21: "life-safety-point",
	22: "life-safety-zone",
	23: "accumulator",
	24: "pulse-converter",
	25: "event-log",
	27: "trend-log-multiple",
	28: "load-control",
	29: "structured-view",
	30: "access-door",
	56: "network-port",
}

func objectName(t uint16) string {
	if name, ok := objectTypes[t]; ok {
		return name
	}
	return "object-type-" + strconv.Itoa(int(t))
}

// Property identifiers (ASHRAE 135, clause 12). Only the ones this project
// has use for are named: the identity of a device, the value of a point, and
// the properties the detection rules care about.
const (
	propApplicationSoftware = 12
	propDescription         = 28
	propFirmwareRevision    = 44
	propLocation            = 58
	propModelName           = 70
	propObjectIdentifier    = 75
	propObjectList          = 76
	propObjectName          = 77
	propPresentValue        = 85
	propProtocolVersion     = 98
	propVendorIdentifier    = 120
	propVendorName          = 121
	propSerialNumber        = 372
)

var properties = map[uint32]string{
	0:                "acked-transitions",
	12:               "application-software-version",
	28:               "description",
	36:               "event-state",
	38:               "exception-schedule",
	44:               "firmware-revision",
	45:               "high-limit",
	52:               "inactive-text",
	58:               "location",
	62:               "low-limit",
	70:               "model-name",
	73:               "number-of-apdu-retries",
	81:               "out-of-service",
	88:               "priority-for-writing",
	75:               "object-identifier",
	76:               "object-list",
	77:               "object-name",
	79:               "object-type",
	85:               "present-value",
	87:               "priority-array",
	96:               "protocol-object-types-supported",
	97:               "protocol-services-supported",
	98:               "protocol-version",
	103:              "reliability",
	104:              "relinquish-default",
	107:              "segmentation-supported",
	111:              "status-flags",
	112:              "system-status",
	117:              "units",
	120:              "vendor-identifier",
	121:              "vendor-name",
	123:              "weekly-schedule",
	139:              "protocol-revision",
	155:              "database-revision",
	168:              "profile-name",
	174:              "schedule-default",
	propSerialNumber: "serial-number",
	8:                "all",
	371:              "property-list",
}

func propertyName(id uint32) string {
	if name, ok := properties[id]; ok {
		return name
	}
	return "property-" + strconv.FormatUint(uint64(id), 10)
}

// identityProperties maps the properties that describe a device to the
// identity field each supports. A BACnet reply echoes the object and property
// it answers for, so a device's own description can be read from the answer
// alone — no request needed, which is what makes BACnet such good material
// for a passive inventory.
var identityProperties = map[uint32]string{
	propVendorName:          "vendor_name",
	propModelName:           "model_name",
	propFirmwareRevision:    "firmware_revision",
	propApplicationSoftware: "application_software",
	propObjectName:          "device_name",
	propLocation:            "location",
	propDescription:         "description",
	propSerialNumber:        "serial_number",
}

// Error classes and the codes worth naming (ASHRAE 135, clause 18).
var errorClasses = map[uint32]string{
	0: "device",
	1: "object",
	2: "property",
	3: "resources",
	4: "security",
	5: "services",
	6: "vt",
	7: "communication",
}

var errorCodes = map[uint32]string{
	0:  "other",
	2:  "authentication-failed",
	9:  "device-busy",
	25: "inconsistent-parameters",
	26: "inconsistent-selection-criterion",
	27: "invalid-array-index",
	28: "invalid-configuration-data",
	30: "invalid-parameter-data-type",
	31: "invalid-time-stamp",
	32: "key-generation-error",
	35: "missing-required-parameter",
	36: "no-objects-of-specified-type",
	37: "no-space-for-object",
	38: "no-space-to-add-list-element",
	39: "no-space-to-write-property",
	40: "no-vt-sessions-available",
	41: "property-is-not-a-list",
	42: "object-deletion-not-permitted",
	43: "object-identifier-already-exists",
	44: "operational-problem",
	45: "password-failure",
	46: "read-access-denied",
	47: "security-not-supported",
	48: "service-request-denied",
	49: "timeout",
	50: "unknown-object",
	51: "unknown-property",
	53: "unknown-vt-class",
	54: "unknown-vt-session",
	55: "unsupported-object-type",
	56: "value-out-of-range",
	57: "vt-session-already-closed",
	58: "vt-session-termination-failure",
	59: "write-access-denied",
	60: "character-set-not-supported",
	61: "invalid-array-index",
	62: "cov-subscription-failed",
	63: "not-cov-property",
}

func errorText(class, code uint32) string {
	cname, ok := errorClasses[class]
	if !ok {
		cname = "class-" + strconv.FormatUint(uint64(class), 10)
	}
	ccode, ok := errorCodes[code]
	if !ok {
		ccode = "code-" + strconv.FormatUint(uint64(code), 10)
	}
	return cname + "/" + ccode
}

// rejectReasons and abortReasons say why a device would not even look at a
// request (ASHRAE 135, clauses 18.8 and 18.9).
var rejectReasons = map[uint8]string{
	0: "other", 1: "buffer-overflow", 2: "inconsistent-parameters",
	3: "invalid-parameter-data-type", 4: "invalid-tag", 5: "missing-required-parameter",
	6: "parameter-out-of-range", 7: "too-many-arguments", 8: "undefined-enumeration",
	9: "unrecognized-service",
}

var abortReasons = map[uint8]string{
	0: "other", 1: "buffer-overflow", 2: "invalid-apdu-in-this-state",
	3: "preempted-by-higher-priority-task", 4: "segmentation-not-supported",
	5: "security-error", 6: "insufficient-security", 7: "window-size-out-of-range",
	8: "application-exceeded-reply-time", 9: "out-of-resources", 10: "tsm-timeout",
	11: "apdu-too-long",
}

// reinitStates are what a reinitializeDevice asks for: a cold start wipes the
// device's state, a warm start restarts its application, and the backup and
// restore states take it out of service while a configuration is moved.
var reinitStates = map[uint32]string{
	0: "coldstart", 1: "warmstart", 2: "startbackup", 3: "endbackup",
	4: "startrestore", 5: "endrestore", 6: "abortrestore", 7: "activate-changes",
}

// commControlStates are what a deviceCommunicationControl asks for: silencing
// a device is how it disappears from an operator's screen while still
// running.
var commControlStates = map[uint32]string{
	0: "enable", 1: "disable", 2: "disable-initiation",
}

// segmentation says how much of a long answer a device can split, which is
// part of what an i-Am tells the network about itself.
var segmentationKinds = map[uint32]string{
	0: "both", 1: "transmit", 2: "receive", 3: "none",
}

// vendors names the BACnet vendor identifiers this project is sure of.
//
// ASHRAE has assigned thousands and reproducing that list from memory would
// put wrong manufacturers on assets. A BACnet device also carries its
// vendor's name as a property of its device object, so the name usually comes
// from the packets themselves; the identifier is always recorded.
var vendors = map[uint32]string{
	0: "ASHRAE",
	5: "Johnson Controls",
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
