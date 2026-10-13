package iec104

import (
	"strconv"

	"github.com/rom/otinv/internal/model"
)

// Type identifications, causes of transmission and qualifiers of
// IEC 60870-5-101, as carried over TCP by IEC 60870-5-104.
//
// The ASDU is defined by -101 and reused unchanged by -104; what -104 fixes is
// the field widths, which -101 leaves configurable per link (-104 clause 7.2,
// table 1): cause of transmission is two octets including the originator
// address, the common address of the ASDU is two octets and the information
// object address is three. Nothing here is negotiable, so the header is always
// six octets and every information object address three.

// U-format control functions (-104, clause 5.3). The function sits in the
// upper six bits of the first control octet; only one may be set at a time.
const (
	uStartDTAct = 0x07
	uStartDTCon = 0x0B
	uStopDTAct  = 0x13
	uStopDTCon  = 0x23
	uTestFRAct  = 0x43
	uTestFRCon  = 0x83
)

// uFunctions names the legal U-format control functions. The names are the
// standard's own: STARTDT and STOPDT start and stop data transfer on an
// established connection, TESTFR tests that it is still alive.
var uFunctions = map[uint8]string{
	uStartDTAct: "STARTDT_act",
	uStartDTCon: "STARTDT_con",
	uStopDTAct:  "STOPDT_act",
	uStopDTCon:  "STOPDT_con",
	uTestFRAct:  "TESTFR_act",
	uTestFRCon:  "TESTFR_con",
}

// uClass classifies a U-format function.
//
// These control the connection, not the process: STARTDT and STOPDT switch the
// controlled station's data transfer on and off, and every normal connection
// starts with one. Classifying them as control would make CLAUDE.md's rule on
// control operations from unexpected sources fire on every session setup, so
// they stay other and carry a u_function attribute a custom rule can match on
// when the analyst does want to see who stopped a station's reporting.
func uClass(fn uint8) model.Classification {
	switch fn {
	case uTestFRAct, uTestFRCon:
		return model.ClassDiagnostic
	default:
		return model.ClassOther
	}
}

// typeInfo describes one ASDU type identification.
type typeInfo struct {
	name  string
	class model.Classification

	// size is the length in octets of one information element, excluding the
	// information object address. The standard fixes it for every type it
	// defines; it is 0 for the read command, whose objects are addresses and
	// nothing more, and -1 where the length cannot be known in advance, as for
	// the file segment that declares its own and for the types the standard
	// does not define.
	size int
}

// types maps a type identification to its name, classification and element
// size (-101, clause 7.3 and the type lists in 7.2.1).
//
// The classifications follow what the ASDU does rather than which direction it
// travels in:
//
//   - Process information in the monitor direction (1-40) delivers measured
//     and status data, so it is read, exactly as a DNP3 response is. The
//     direction field, not the class, says whether anyone asked for it.
//   - Commands in the control direction (45-64) operate the plant: switching,
//     stepping and set points. These are control, and are what CLAUDE.md's
//     built-in rule on "IEC 104 control commands (C_SC/C_DC/C_RC/C_SE*) from
//     unexpected sources" matches, so a rule needs no type numbers.
//   - Interrogation and read commands (100-102) ask for data, so they are
//     read; clock synchronisation (103) and parameter loading (110-112) change
//     the device, so they are write; resetting the process (105) and
//     activating parameters (113) change what it does, so they are control.
//   - File transfer (120-126) is how a station uploads configuration and
//     downloads disturbance records, so it is program, matching the DNP3 file
//     operations. The directory ASDU only lists what is there, so it is read.
var types = map[uint8]typeInfo{
	// Process information in the monitor direction.
	1:  {"M_SP_NA_1", model.ClassRead, 1},
	2:  {"M_SP_TA_1", model.ClassRead, 4},
	3:  {"M_DP_NA_1", model.ClassRead, 1},
	4:  {"M_DP_TA_1", model.ClassRead, 4},
	5:  {"M_ST_NA_1", model.ClassRead, 2},
	6:  {"M_ST_TA_1", model.ClassRead, 5},
	7:  {"M_BO_NA_1", model.ClassRead, 5},
	8:  {"M_BO_TA_1", model.ClassRead, 8},
	9:  {"M_ME_NA_1", model.ClassRead, 3},
	10: {"M_ME_TA_1", model.ClassRead, 6},
	11: {"M_ME_NB_1", model.ClassRead, 3},
	12: {"M_ME_TB_1", model.ClassRead, 6},
	13: {"M_ME_NC_1", model.ClassRead, 5},
	14: {"M_ME_TC_1", model.ClassRead, 8},
	15: {"M_IT_NA_1", model.ClassRead, 5},
	16: {"M_IT_TA_1", model.ClassRead, 8},
	17: {"M_EP_TA_1", model.ClassRead, 6},
	18: {"M_EP_TB_1", model.ClassRead, 7},
	19: {"M_EP_TC_1", model.ClassRead, 7},
	20: {"M_PS_NA_1", model.ClassRead, 5},
	21: {"M_ME_ND_1", model.ClassRead, 2},
	30: {"M_SP_TB_1", model.ClassRead, 8},
	31: {"M_DP_TB_1", model.ClassRead, 8},
	32: {"M_ST_TB_1", model.ClassRead, 9},
	33: {"M_BO_TB_1", model.ClassRead, 12},
	34: {"M_ME_TD_1", model.ClassRead, 10},
	35: {"M_ME_TE_1", model.ClassRead, 10},
	36: {"M_ME_TF_1", model.ClassRead, 12},
	37: {"M_IT_TB_1", model.ClassRead, 12},
	38: {"M_EP_TD_1", model.ClassRead, 10},
	39: {"M_EP_TE_1", model.ClassRead, 11},
	40: {"M_EP_TF_1", model.ClassRead, 11},

	// Process information in the control direction: the plant commands.
	45: {"C_SC_NA_1", model.ClassControl, 1},
	46: {"C_DC_NA_1", model.ClassControl, 1},
	47: {"C_RC_NA_1", model.ClassControl, 1},
	48: {"C_SE_NA_1", model.ClassControl, 3},
	49: {"C_SE_NB_1", model.ClassControl, 3},
	50: {"C_SE_NC_1", model.ClassControl, 5},
	51: {"C_BO_NA_1", model.ClassControl, 4},
	58: {"C_SC_TA_1", model.ClassControl, 8},
	59: {"C_DC_TA_1", model.ClassControl, 8},
	60: {"C_RC_TA_1", model.ClassControl, 8},
	61: {"C_SE_TA_1", model.ClassControl, 10},
	62: {"C_SE_TB_1", model.ClassControl, 10},
	63: {"C_SE_TC_1", model.ClassControl, 12},
	64: {"C_BO_TA_1", model.ClassControl, 11},

	// System information.
	70:  {"M_EI_NA_1", model.ClassDiagnostic, 1},
	100: {"C_IC_NA_1", model.ClassRead, 1},
	101: {"C_CI_NA_1", model.ClassRead, 1},
	102: {"C_RD_NA_1", model.ClassRead, 0},
	103: {"C_CS_NA_1", model.ClassWrite, 7},
	104: {"C_TS_NA_1", model.ClassDiagnostic, 2},
	105: {"C_RP_NA_1", model.ClassControl, 1},
	106: {"C_CD_NA_1", model.ClassDiagnostic, 2},
	107: {"C_TS_TA_1", model.ClassDiagnostic, 9},

	// Parameters in the control direction.
	110: {"P_ME_NA_1", model.ClassWrite, 3},
	111: {"P_ME_NB_1", model.ClassWrite, 3},
	112: {"P_ME_NC_1", model.ClassWrite, 5},
	113: {"P_AC_NA_1", model.ClassControl, 1},

	// File transfer.
	120: {"F_FR_NA_1", model.ClassProgram, 6},
	121: {"F_SR_NA_1", model.ClassProgram, 7},
	122: {"F_SC_NA_1", model.ClassProgram, 4},
	123: {"F_LS_NA_1", model.ClassProgram, 5},
	124: {"F_AF_NA_1", model.ClassProgram, 4},
	125: {"F_SG_NA_1", model.ClassProgram, -1},
	126: {"F_DR_TA_1", model.ClassRead, 13},
}

// typeID reports what a type identification means. The standard splits the
// unassigned numbers into three ranges, and saying which range an unknown type
// came from is more use to an analyst than one "unknown" for all of them
// (-101, clause 7.2.1.1).
func typeID(id uint8) typeInfo {
	if info, ok := types[id]; ok {
		return info
	}
	// An element size of -1 says the layout is unknown, which stops the walk
	// after the first object address rather than slicing the rest of the ASDU
	// on an assumption about how long an element is.
	switch {
	case id == 0:
		return typeInfo{"NotUsed", model.ClassOther, -1}
	case id <= 127:
		return typeInfo{"Reserved", model.ClassOther, -1}
	case id <= 135:
		return typeInfo{"RoutingReserved", model.ClassOther, -1}
	default:
		return typeInfo{"PrivateRange", model.ClassOther, -1}
	}
}

// Cause of transmission values (-101, clause 7.2.3). Groups 21-41 are the
// interrogation and counter request causes, named by causeName.
const (
	cotPeriodic       = 1
	cotBackground     = 2
	cotSpontaneous    = 3
	cotInitialized    = 4
	cotRequest        = 5
	cotActivation     = 6
	cotActivationCon  = 7
	cotDeactivation   = 8
	cotDeactivateCon  = 9
	cotActivationEnd  = 10
	cotRemoteCommand  = 11
	cotLocalCommand   = 12
	cotFileTransfer   = 13
	cotInterrogated   = 20
	cotGroup1         = 21
	cotGroup16        = 36
	cotCounterGeneral = 37
	cotCounterGroup1  = 38
	cotCounterGroup4  = 41
	cotUnknownType    = 44
	cotUnknownCause   = 45
	cotUnknownAddress = 46
	cotUnknownIOA     = 47
)

var causes = map[uint8]string{
	cotPeriodic:       "periodic",
	cotBackground:     "background_scan",
	cotSpontaneous:    "spontaneous",
	cotInitialized:    "initialized",
	cotRequest:        "request",
	cotActivation:     "activation",
	cotActivationCon:  "activation_confirmation",
	cotDeactivation:   "deactivation",
	cotDeactivateCon:  "deactivation_confirmation",
	cotActivationEnd:  "activation_termination",
	cotRemoteCommand:  "return_info_remote_command",
	cotLocalCommand:   "return_info_local_command",
	cotFileTransfer:   "file_transfer",
	cotInterrogated:   "interrogated_by_station",
	cotCounterGeneral: "requested_by_general_counter",
	cotUnknownType:    "unknown_type_identification",
	cotUnknownCause:   "unknown_cause_of_transmission",
	cotUnknownAddress: "unknown_common_address",
	cotUnknownIOA:     "unknown_information_object_address",
}

// causeName names a cause of transmission.
func causeName(cot uint8) string {
	if name, ok := causes[cot]; ok {
		return name
	}
	switch {
	case cot >= cotGroup1 && cot <= cotGroup16:
		return "interrogated_by_group_" + strconv.Itoa(int(cot-cotGroup1+1))
	case cot >= cotCounterGroup1 && cot <= cotCounterGroup4:
		return "requested_by_counter_group_" + strconv.Itoa(int(cot-cotCounterGroup1+1))
	case cot >= 48:
		return "private_range"
	default:
		return "reserved"
	}
}

// causeDirection reports the direction a cause of transmission implies, and
// whether it implies one at all.
//
// A cause is a stronger statement about who sent an ASDU than the TCP ports
// are: only a controlling station activates or deactivates, and only a
// controlled station confirms, terminates or reports. Two causes stay
// undecided — a read request and its reply share cause 5, and file transfer
// runs in both directions — so those keep whatever ingest concluded.
func causeDirection(cot uint8) (model.Direction, bool) {
	switch cot {
	case cotActivation, cotDeactivation:
		return model.DirRequest, true
	case cotRequest, cotFileTransfer:
		return model.DirUnknown, false
	case cotPeriodic, cotBackground, cotSpontaneous, cotInitialized,
		cotActivationCon, cotDeactivateCon, cotActivationEnd,
		cotRemoteCommand, cotLocalCommand:
		return model.DirResponse, true
	}
	if cot >= cotInterrogated && cot <= cotCounterGroup4 {
		return model.DirResponse, true
	}
	// 44-47 are returned by whichever side could not make sense of an ASDU it
	// received, so they say nothing about direction.
	return model.DirUnknown, false
}

// Qualifier of interrogation (-101, clause 7.2.6.22).
func interrogationName(qoi uint8) string {
	switch {
	case qoi == 0:
		return "not_used"
	case qoi == 20:
		return "station_interrogation"
	case qoi >= 21 && qoi <= 36:
		return "group_" + strconv.Itoa(int(qoi-20)) + "_interrogation"
	default:
		return "reserved"
	}
}

// Qualifier of counter interrogation request (-101, clause 7.2.6.23).
var counterRequests = map[uint8]string{
	0: "not_used",
	1: "counter_group_1",
	2: "counter_group_2",
	3: "counter_group_3",
	4: "counter_group_4",
	5: "general_counter",
}

var counterFreezes = map[uint8]string{
	0: "read",
	1: "freeze_without_reset",
	2: "freeze_with_reset",
	3: "counter_reset",
}

// Qualifier of reset process command (-101, clause 7.2.6.27).
var resetQualifiers = map[uint8]string{
	1: "general_reset",
	2: "reset_pending_time_tagged_information",
}

// Cause of initialisation (-101, clause 7.2.6.21).
var initCauses = map[uint8]string{
	0: "local_power_on",
	1: "local_manual_reset",
	2: "remote_reset",
}

// Qualifier of command, the output cycle of a switching command
// (-101, clause 7.2.6.26).
func commandQualifier(qu uint8) string {
	switch {
	case qu == 0:
		return "no_additional_definition"
	case qu == 1:
		return "short_pulse"
	case qu == 2:
		return "long_pulse"
	case qu == 3:
		return "persistent_output"
	case qu <= 15:
		return "reserved"
	default:
		return "private_range"
	}
}

// Single and double command states, and the regulating step command
// (-101, clauses 7.2.6.11, 7.2.6.12 and 7.2.6.13). The double point and step
// encodings reserve two of their four values, which is itself worth reporting:
// a command that asks for one is malformed by the standard's own definition.
var singleCommands = map[uint8]string{0: "off", 1: "on"}

var doubleCommands = map[uint8]string{
	0: "not_permitted",
	1: "off",
	2: "on",
	3: "not_permitted",
}

var stepCommands = map[uint8]string{
	0: "not_permitted",
	1: "next_step_lower",
	2: "next_step_higher",
	3: "not_permitted",
}

// Double point information, the two-bit status of a double point
// (-101, clause 7.2.6.3).
var doublePoints = map[uint8]string{
	0: "indeterminate",
	1: "off",
	2: "on",
	3: "indeterminate",
}

// Qualifier of parameter activation (-101, clause 7.2.6.25).
var parameterActivations = map[uint8]string{
	0: "not_used",
	1: "activate_loaded_parameters",
	2: "activate_parameters_of_addressed_object",
	3: "activate_persistent_cyclic_transmission",
}

// Kind of parameter (-101, clause 7.2.6.24).
var parameterKinds = map[uint8]string{
	0: "not_used",
	1: "threshold_value",
	2: "smoothing_factor",
	3: "low_limit",
	4: "high_limit",
}

// Select or execute, the bit that distinguishes a two-step command from a
// direct one (-101, clause 7.2.6.26). Select-before-operate is the normal way
// a control centre issues a command, so which one a frame carries is part of
// reading a command sequence.
func selectExecute(se bool) string {
	if se {
		return "select"
	}
	return "execute"
}
