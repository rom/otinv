package mms

import "github.com/rom/otinv/internal/model"

// The PDU kinds, services and errors of MMS (ISO 9506), and the SPDU types of
// the ISO 8327-1 session layer underneath it. Names are the standard's own, as
// a Wireshark trace or an SCL file spells them, so that what the GUI shows can
// be looked up.

// MMS PDU kinds, the context tags of the MMSpdu CHOICE.
const (
	pduConfirmedRequest  = 0
	pduConfirmedResponse = 1
	pduConfirmedError    = 2
	pduUnconfirmed       = 3
	pduReject            = 4
	pduCancelRequest     = 5
	pduCancelResponse    = 6
	pduCancelError       = 7
	pduInitiateRequest   = 8
	pduInitiateResponse  = 9
	pduInitiateError     = 10
	pduConcludeRequest   = 11
	pduConcludeResponse  = 12
	pduConcludeError     = 13
)

var pduNames = map[uint32]string{
	pduConfirmedRequest:  "confirmed-Request",
	pduConfirmedResponse: "confirmed-Response",
	pduConfirmedError:    "confirmed-Error",
	pduUnconfirmed:       "unconfirmed",
	pduReject:            "reject",
	pduCancelRequest:     "cancel-Request",
	pduCancelResponse:    "cancel-Response",
	pduCancelError:       "cancel-Error",
	pduInitiateRequest:   "initiate-Request",
	pduInitiateResponse:  "initiate-Response",
	pduInitiateError:     "initiate-Error",
	pduConcludeRequest:   "conclude-Request",
	pduConcludeResponse:  "conclude-Response",
	pduConcludeError:     "conclude-Error",
}

// Services this dissector names in its own right.
const (
	svcStatus                      = 0
	svcGetNameList                 = 1
	svcIdentify                    = 2
	svcRead                        = 4
	svcWrite                       = 5
	svcGetVariableAccessAttributes = 6
	svcInitiateDownloadSequence    = 26
	svcInitiateUploadSequence      = 29
	svcDeleteProgramInvocation     = 39
	svcStart                       = 40
	svcStop                        = 41
	svcResume                      = 42
	svcReset                       = 43
	svcKill                        = 44
)

// maxServiceTag is the largest service tag reported as a function code. The
// standard defines 0 to 77 and reserves the rest, and a vendor extension in
// the remaining single octet range is plausible; a tag beyond it is not a
// service at all.
const maxServiceTag = 255

type serviceInfo struct {
	name  string
	class model.Classification
}

// services maps a ConfirmedServiceRequest context tag to its name and the
// shared classification a rule matches on (ISO 9506-2, the MMS service list).
//
// The classifications follow the same reading as the other dissectors:
//
//   - Anything that fetches data or attributes is read. In IEC 61850 that is
//     most of the traffic: a client reads data objects, report control blocks
//     and the object dictionary itself.
//   - Anything that changes a value or the server's object dictionary is
//     write. CLAUDE.md's rule on "MMS writes to control objects" matches on
//     this, so a write needs no service numbers to be caught. A client
//     creating a data set to report on is a write, not a program operation:
//     it is routine for an HMI, and calling it program would make every HMI
//     look like an engineering workstation.
//   - Starting, stopping, resuming, resetting and killing a program
//     invocation, and taking or relinquishing control of a semaphore, change
//     what the device does without changing what is in it, so they are
//     control, exactly as an S7 CPU stop is.
//   - Loading and fetching domain contents, creating and deleting program
//     invocations, and the file services that carry them are program. This is
//     the MMS equivalent of an S7 block download, and only an engineer does
//     it.
//   - Identify is how a device names itself, so it is discovery.
var services = map[uint32]serviceInfo{
	svcStatus:                      {"status", model.ClassRead},
	svcGetNameList:                 {"getNameList", model.ClassRead},
	svcIdentify:                    {"identify", model.ClassDiscovery},
	3:                              {"rename", model.ClassWrite},
	svcRead:                        {"read", model.ClassRead},
	svcWrite:                       {"write", model.ClassWrite},
	svcGetVariableAccessAttributes: {"getVariableAccessAttributes", model.ClassRead},
	7:                              {"defineNamedVariable", model.ClassWrite},
	8:                              {"defineScatteredAccess", model.ClassWrite},
	9:                              {"getScatteredAccessAttributes", model.ClassRead},
	10:                             {"deleteVariableAccess", model.ClassWrite},
	11:                             {"defineNamedVariableList", model.ClassWrite},
	12:                             {"getNamedVariableListAttributes", model.ClassRead},
	13:                             {"deleteNamedVariableList", model.ClassWrite},
	14:                             {"defineNamedType", model.ClassWrite},
	15:                             {"getNamedTypeAttributes", model.ClassRead},
	16:                             {"deleteNamedType", model.ClassWrite},
	17:                             {"input", model.ClassWrite},
	18:                             {"output", model.ClassRead},
	19:                             {"takeControl", model.ClassControl},
	20:                             {"relinquishControl", model.ClassControl},
	21:                             {"defineSemaphore", model.ClassWrite},
	22:                             {"deleteSemaphore", model.ClassWrite},
	23:                             {"reportSemaphoreStatus", model.ClassRead},
	24:                             {"reportPoolSemaphoreStatus", model.ClassRead},
	25:                             {"reportSemaphoreEntryStatus", model.ClassRead},
	svcInitiateDownloadSequence:    {"initiateDownloadSequence", model.ClassProgram},
	27:                             {"downloadSegment", model.ClassProgram},
	28:                             {"terminateDownloadSequence", model.ClassProgram},
	svcInitiateUploadSequence:      {"initiateUploadSequence", model.ClassProgram},
	30:                             {"uploadSegment", model.ClassProgram},
	31:                             {"terminateUploadSequence", model.ClassProgram},
	32:                             {"requestDomainDownload", model.ClassProgram},
	33:                             {"requestDomainUpload", model.ClassProgram},
	34:                             {"loadDomainContent", model.ClassProgram},
	35:                             {"storeDomainContent", model.ClassProgram},
	36:                             {"deleteDomain", model.ClassProgram},
	37:                             {"getDomainAttributes", model.ClassRead},
	38:                             {"createProgramInvocation", model.ClassProgram},
	svcDeleteProgramInvocation:     {"deleteProgramInvocation", model.ClassProgram},
	svcStart:                       {"start", model.ClassControl},
	svcStop:                        {"stop", model.ClassControl},
	svcResume:                      {"resume", model.ClassControl},
	svcReset:                       {"reset", model.ClassControl},
	svcKill:                        {"kill", model.ClassControl},
	45:                             {"getProgramInvocationAttributes", model.ClassRead},
	46:                             {"obtainFile", model.ClassProgram},
	47:                             {"defineEventCondition", model.ClassWrite},
	48:                             {"deleteEventCondition", model.ClassWrite},
	49:                             {"getEventConditionAttributes", model.ClassRead},
	50:                             {"reportEventConditionStatus", model.ClassRead},
	51:                             {"alterEventConditionMonitoring", model.ClassWrite},
	52:                             {"triggerEvent", model.ClassControl},
	53:                             {"defineEventAction", model.ClassWrite},
	54:                             {"deleteEventAction", model.ClassWrite},
	55:                             {"getEventActionAttributes", model.ClassRead},
	56:                             {"reportEventActionStatus", model.ClassRead},
	57:                             {"defineEventEnrollment", model.ClassWrite},
	58:                             {"deleteEventEnrollment", model.ClassWrite},
	59:                             {"alterEventEnrollment", model.ClassWrite},
	60:                             {"reportEventEnrollmentStatus", model.ClassRead},
	61:                             {"getEventEnrollmentAttributes", model.ClassRead},
	62:                             {"acknowledgeEventNotification", model.ClassWrite},
	63:                             {"getAlarmSummary", model.ClassRead},
	64:                             {"getAlarmEnrollmentSummary", model.ClassRead},
	65:                             {"readJournal", model.ClassRead},
	66:                             {"writeJournal", model.ClassWrite},
	67:                             {"initializeJournal", model.ClassProgram},
	68:                             {"reportJournalStatus", model.ClassRead},
	69:                             {"createJournal", model.ClassProgram},
	70:                             {"deleteJournal", model.ClassProgram},
	71:                             {"getCapabilityList", model.ClassRead},
	72:                             {"fileOpen", model.ClassProgram},
	73:                             {"fileRead", model.ClassProgram},
	74:                             {"fileClose", model.ClassProgram},
	75:                             {"fileRename", model.ClassProgram},
	76:                             {"fileDelete", model.ClassProgram},
	77:                             {"fileDirectory", model.ClassRead},
}

// service names a confirmed service. The standard leaves no gaps below 78, so
// anything else is either a later addition or a crafted tag.
func service(tag uint32) serviceInfo {
	if info, ok := services[tag]; ok {
		return info
	}
	return serviceInfo{"service" + utoa(tag), model.ClassOther}
}

// unconfirmedServices maps an UnconfirmedService context tag.
//
// An information report is how IEC 61850 delivers data: a server pushes the
// contents of a report control block without being asked each time. It carries
// values, so it is a read, with the direction saying nobody asked for this one.
var unconfirmedServices = map[uint32]serviceInfo{
	0: {"informationReport", model.ClassRead},
	1: {"unsolicitedStatus", model.ClassRead},
	2: {"eventNotification", model.ClassRead},
}

func unconfirmedService(tag uint32) serviceInfo {
	if info, ok := unconfirmedServices[tag]; ok {
		return info
	}
	return serviceInfo{"unconfirmed" + utoa(tag), model.ClassOther}
}

// errorClasses names the ServiceError errorClass CHOICE (ISO 9506-2). The
// The class is the part worth reporting: it says whether the request was refused
// because the object does not exist, because the client may not have it, or
// because the device is in no state to answer.
var errorClasses = map[uint32]string{
	0:  "vmd-state",
	1:  "application-reference",
	2:  "definition",
	3:  "resource",
	4:  "service",
	5:  "service-preempt",
	6:  "time-resolution",
	7:  "access",
	8:  "initiate",
	9:  "conclude",
	10: "cancel",
	11: "file",
	12: "others",
}

// rejectReasons names the RejectPDU reason CHOICE. A reject means the peer
// would not even look at the PDU, which separates a protocol disagreement from
// a refused request.
var rejectReasons = map[uint32]string{
	1:  "confirmed-requestPDU",
	2:  "confirmed-responsePDU",
	3:  "confirmed-errorPDU",
	4:  "unconfirmedPDU",
	5:  "pdu-error",
	6:  "cancel-requestPDU",
	7:  "cancel-responsePDU",
	8:  "cancel-errorPDU",
	9:  "conclude-requestPDU",
	10: "conclude-responsePDU",
	11: "conclude-errorPDU",
}

// ACSE APDU tags, application class (ISO 8650-1). The association layer is
// where the two ends name each other and agree what they will speak.
var acseNames = map[uint32]string{
	0: "AARQ",
	1: "AARE",
	2: "RLRQ",
	3: "RLRE",
	4: "ABRT",
}

// Session layer SPDU types (ISO 8327-1). GIVE TOKENS and DATA TRANSFER share
// a code and are told apart by position: a data transfer is a GIVE TOKENS
// immediately followed by one.
const (
	spduDataTransfer = 1
	spduFinish       = 9
	spduDisconnect   = 10
	spduRefuse       = 12
	spduConnect      = 13
	spduAccept       = 14
	spduAbort        = 25
	spduAbortAccept  = 26
)

var spduNames = map[uint8]string{
	0:                "EXCEPTION_REPORT",
	spduDataTransfer: "DATA_TRANSFER",
	2:                "PLEASE_TOKENS",
	5:                "EXPEDITED",
	7:                "PREPARE",
	8:                "NOT_FINISHED",
	spduFinish:       "FINISH",
	spduDisconnect:   "DISCONNECT",
	spduRefuse:       "REFUSE",
	spduConnect:      "CONNECT",
	spduAccept:       "ACCEPT",
	spduAbort:        "ABORT",
	spduAbortAccept:  "ABORT_ACCEPT",
}

// Session parameter identifiers this dissector reads. The user data parameter
// is the one that matters: it holds the presentation PDU.
const (
	sesUserData         = 193
	sesExtendedUserData = 194
	sesConnectAccept    = 5
	sesConnectionID     = 1
)

// COTP PDU types (ISO 8073). MMS shares this transport with S7comm, which is
// why the connection phase cannot say which of them a stream carries.
const (
	cotpConnectRequest = 0xE0
	cotpConnectConfirm = 0xD0
	cotpDisconnectReq  = 0x80
	cotpDisconnectConf = 0xC0
	cotpData           = 0xF0
	cotpError          = 0x70
	cotpDataAck        = 0x10
	cotpReject         = 0x50
)

var cotpNames = map[uint8]string{
	cotpConnectRequest: "ConnectionRequest",
	cotpConnectConfirm: "ConnectionConfirm",
	cotpDisconnectReq:  "DisconnectRequest",
	cotpDisconnectConf: "DisconnectConfirm",
	cotpData:           "Data",
	cotpError:          "Error",
	cotpDataAck:        "DataAcknowledgement",
	cotpReject:         "Reject",
}

// COTP connection parameter codes.
const (
	paramTPDUSize = 0xC0
	paramSrcTSAP  = 0xC1
	paramDstTSAP  = 0xC2
)

// isMMSPDUTag reports whether a byte could open an MMS PDU.
//
// Some stacks put MMS straight on top of COTP with no session, presentation or
// association layer at all. Recognising that shape is what lets one dissector
// read both, and the tag set is narrow enough to be worth testing for: every
// MMSpdu alternative is a context tag below 14.
func isMMSPDUTag(b uint8) bool {
	if b&0xc0 != 0x80 {
		return false
	}
	return uint32(b&0x1f) <= pduConcludeError
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
