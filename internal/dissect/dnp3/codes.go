package dnp3

import "github.com/rom/otinv/internal/model"

// Function codes, object groups, internal indications and control codes from
// IEEE 1815-2012 (DNP3).

// Data link layer function codes sent by a primary station (IEEE 1815, 9.2.4.1.3).
var linkPrimaryFunctions = map[uint8]string{
	0: "RESET_LINK_STATES",
	1: "RESET_USER_PROCESS",
	2: "TEST_LINK_STATES",
	3: "UNCONFIRMED_USER_DATA",
	4: "CONFIRMED_USER_DATA",
	9: "REQUEST_LINK_STATUS",
}

// Data link layer function codes sent by a secondary station.
var linkSecondaryFunctions = map[uint8]string{
	0:  "ACK",
	1:  "NACK",
	11: "LINK_STATUS",
	14: "LINK_SERVICE_NOT_FUNCTIONING",
	15: "LINK_SERVICE_NOT_USED",
}

// linkFunctionName names a link layer function. The primary/secondary bit
// decides which table applies, so the same number means different things in
// each direction.
func linkFunctionName(primary bool, fc uint8) string {
	table := linkSecondaryFunctions
	if primary {
		table = linkPrimaryFunctions
	}
	if name, ok := table[fc]; ok {
		return name
	}
	return "Reserved"
}

type funcInfo struct {
	name  string
	class model.Classification
}

// appFunctions maps an application layer function code to its name and the
// shared classification a rule matches on (IEEE 1815, table 4-1).
//
// The classifications follow what an operation does to the outstation rather
// than which layer it belongs to:
//
//   - Restarting, operating, freezing and switching unsolicited reporting on
//     or off all change how the device behaves, so they are control. CLAUDE.md
//     names cold and warm restart and disable unsolicited as built-in rules.
//   - Starting, stopping and configuring the application, and the file
//     transfers that carry configuration and firmware, are program.
//   - File info and reads are read; time measurement is diagnostic.
var appFunctions = map[uint8]funcInfo{
	0:  {"CONFIRM", model.ClassOther},
	1:  {"READ", model.ClassRead},
	2:  {"WRITE", model.ClassWrite},
	3:  {"SELECT", model.ClassControl},
	4:  {"OPERATE", model.ClassControl},
	5:  {"DIRECT_OPERATE", model.ClassControl},
	6:  {"DIRECT_OPERATE_NR", model.ClassControl},
	7:  {"IMMED_FREEZE", model.ClassControl},
	8:  {"IMMED_FREEZE_NR", model.ClassControl},
	9:  {"FREEZE_CLEAR", model.ClassControl},
	10: {"FREEZE_CLEAR_NR", model.ClassControl},
	11: {"FREEZE_AT_TIME", model.ClassControl},
	12: {"FREEZE_AT_TIME_NR", model.ClassControl},
	13: {"COLD_RESTART", model.ClassControl},
	14: {"WARM_RESTART", model.ClassControl},
	15: {"INITIALIZE_DATA", model.ClassProgram},
	16: {"INITIALIZE_APPL", model.ClassProgram},
	17: {"START_APPL", model.ClassProgram},
	18: {"STOP_APPL", model.ClassProgram},
	19: {"SAVE_CONFIG", model.ClassProgram},
	20: {"ENABLE_UNSOLICITED", model.ClassControl},
	21: {"DISABLE_UNSOLICITED", model.ClassControl},
	22: {"ASSIGN_CLASS", model.ClassProgram},
	23: {"DELAY_MEASURE", model.ClassDiagnostic},
	24: {"RECORD_CURRENT_TIME", model.ClassDiagnostic},
	25: {"OPEN_FILE", model.ClassProgram},
	26: {"CLOSE_FILE", model.ClassProgram},
	27: {"DELETE_FILE", model.ClassProgram},
	28: {"GET_FILE_INFO", model.ClassRead},
	29: {"AUTHENTICATE_FILE", model.ClassOther},
	30: {"ABORT_FILE", model.ClassProgram},
	31: {"ACTIVATE_CONFIG", model.ClassProgram},
	32: {"AUTHENTICATE_REQ", model.ClassOther},
	33: {"AUTH_REQ_NO_ACK", model.ClassOther},
	// Responses deliver measurement data, so they count as reads; the
	// direction field is what tells a reply from a request.
	129: {"RESPONSE", model.ClassRead},
	130: {"UNSOLICITED_RESPONSE", model.ClassRead},
	131: {"AUTHENTICATE_RESP", model.ClassOther},
}

func appFunction(fc uint8) funcInfo {
	if info, ok := appFunctions[fc]; ok {
		return info
	}
	// Everything else is reserved by the standard.
	return funcInfo{"Reserved", model.ClassOther}
}

// isResponse reports whether a function code is a reply. A reply carries two
// octets of internal indications that a request does not.
func isResponse(fc uint8) bool {
	switch fc {
	case 129, 130, 131:
		return true
	default:
		return false
	}
}

// iinFlags names the internal indication bits (IEEE 1815, 4.4.2). The first
// octet reports device state, the second reports what went wrong with the
// request, which is why a rejected command is readable at all.
var iinFlags = [2][8]string{
	{
		"broadcast", "class_1_events", "class_2_events", "class_3_events",
		"need_time", "local_control", "device_trouble", "device_restart",
	},
	{
		"function_not_supported", "object_unknown", "parameter_error",
		"event_buffer_overflow", "already_executing", "config_corrupt",
		"reserved_6", "reserved_7",
	},
}

// decodeIIN returns the names of the set internal indication bits.
func decodeIIN(octet1, octet2 uint8) []string {
	var out []string
	for bit := range 8 {
		if octet1&(1<<bit) != 0 {
			out = append(out, iinFlags[0][bit])
		}
	}
	for bit := range 8 {
		if octet2&(1<<bit) != 0 {
			out = append(out, iinFlags[1][bit])
		}
	}
	return out
}

// objectGroups names the object groups (IEEE 1815, table 11-1). An unnamed
// group is reported as an anomaly: it is either a vendor extension or, as in
// the sample capture, a scan probing for one.
var objectGroups = map[uint8]string{
	0:   "DeviceAttributes",
	1:   "BinaryInput",
	2:   "BinaryInputEvent",
	3:   "DoubleBitBinaryInput",
	4:   "DoubleBitBinaryInputEvent",
	10:  "BinaryOutput",
	11:  "BinaryOutputEvent",
	12:  "BinaryOutputCommand",
	13:  "BinaryOutputCommandEvent",
	20:  "Counter",
	21:  "FrozenCounter",
	22:  "CounterEvent",
	23:  "FrozenCounterEvent",
	30:  "AnalogInput",
	31:  "FrozenAnalogInput",
	32:  "AnalogInputEvent",
	33:  "FrozenAnalogInputEvent",
	34:  "AnalogInputDeadband",
	40:  "AnalogOutputStatus",
	41:  "AnalogOutputCommand",
	42:  "AnalogOutputEvent",
	43:  "AnalogOutputCommandEvent",
	50:  "TimeAndDate",
	51:  "TimeAndDateCTO",
	52:  "TimeDelay",
	60:  "ClassData",
	70:  "FileTransfer",
	80:  "InternalIndications",
	81:  "StorageObject",
	82:  "DeviceProfile",
	83:  "PrivateRegistration",
	85:  "DataSetPrototype",
	86:  "DataSetDescriptor",
	87:  "DataSetPresentValue",
	88:  "DataSetSnapshot",
	90:  "ApplicationIdentifier",
	100: "FloatingPoint",
	101: "BinaryCodedDecimal",
	102: "UnsignedInteger",
	110: "OctetString",
	111: "OctetStringEvent",
	112: "VirtualTerminalOutput",
	113: "VirtualTerminalEvent",
	120: "Authentication",
}

// Control relay output block operation types (IEEE 1815, table 11-13).
var crobOperations = map[uint8]string{
	0: "NUL",
	1: "PULSE_ON",
	2: "PULSE_OFF",
	3: "LATCH_ON",
	4: "LATCH_OFF",
}

// Trip/close codes, which ride in the upper bits of the control octet.
var crobTripClose = map[uint8]string{
	0: "NUL",
	1: "CLOSE",
	2: "TRIP",
}

// Command status codes returned in a control object (IEEE 1815, table 11-16).
var commandStatus = map[uint8]string{
	0:   "SUCCESS",
	1:   "TIMEOUT",
	2:   "NO_SELECT",
	3:   "FORMAT_ERROR",
	4:   "NOT_SUPPORTED",
	5:   "ALREADY_ACTIVE",
	6:   "HARDWARE_ERROR",
	7:   "LOCAL",
	8:   "TOO_MANY_OBJS",
	9:   "NOT_AUTHORIZED",
	10:  "AUTOMATION_INHIBIT",
	11:  "PROCESSING_LIMITED",
	12:  "OUT_OF_RANGE",
	126: "NON_PARTICIPATING",
	127: "UNDEFINED",
}

// Special data link addresses (IEEE 1815, 9.2.4.2). Addresses up to 0xFFEF
// identify a device; the rest are reserved or address many devices at once.
const (
	addrReservedFrom = 0xFFF0
	addrSelf         = 0xFFFC
	addrBroadcastMin = 0xFFFD
)

// linkAddressKind names an address that does not identify one device, so that
// a broadcast is never reported as though it were a single outstation.
func linkAddressKind(addr uint16) (string, bool) {
	switch {
	case addr >= addrBroadcastMin:
		return "broadcast", true
	case addr == addrSelf:
		return "self_address", true
	case addr >= addrReservedFrom:
		return "reserved", true
	default:
		return "", false
	}
}
