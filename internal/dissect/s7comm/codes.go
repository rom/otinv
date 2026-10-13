package s7comm

import "github.com/rom/otinv/internal/model"

// Function codes, memory areas and error classes of S7comm. The protocol is
// Siemens proprietary and has no public specification, so the names and
// layouts here follow the Wireshark s7comm dissector, which is the reference
// implementation the industry reads S7 traffic with.

// ISO 8073 / RFC 1006 COTP PDU types.
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

var cotpTypes = map[uint8]string{
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
	paramTPDUSize   = 0xC0
	paramSrcTSAP    = 0xC1
	paramDstTSAP    = 0xC2
	paramChecksum   = 0xC3
	paramAltClass   = 0xC5
	paramAddOptions = 0xC6
)

// ROSCTR values: which kind of S7 message this is.
const (
	rosctrJob      = 0x01
	rosctrAck      = 0x02
	rosctrAckData  = 0x03
	rosctrUserdata = 0x07
)

var rosctrNames = map[uint8]string{
	rosctrJob:      "Job",
	rosctrAck:      "Ack",
	rosctrAckData:  "AckData",
	rosctrUserdata: "Userdata",
}

// S7 application function codes.
const (
	fnCPUServices        = 0x00
	fnReadVar            = 0x04
	fnWriteVar           = 0x05
	fnRequestDownload    = 0x1A
	fnDownloadBlock      = 0x1B
	fnDownloadEnded      = 0x1C
	fnStartUpload        = 0x1D
	fnUpload             = 0x1E
	fnEndUpload          = 0x1F
	fnPLCControl         = 0x28
	fnPLCStop            = 0x29
	fnSetupCommunication = 0xF0
)

type funcInfo struct {
	name  string
	class model.Classification
}

// functions maps a function code to its name and the shared classification a
// rule matches on.
//
// Uploading and downloading blocks is how a PLC's program is changed, so the
// whole family classifies as program; CLAUDE.md names program upload and
// download as a built-in rule. Stopping the CPU is a control action on the
// plant, which it names as well.
var functions = map[uint8]funcInfo{
	fnCPUServices:        {"CPU_SERVICES", model.ClassOther},
	fnReadVar:            {"READ_VAR", model.ClassRead},
	fnWriteVar:           {"WRITE_VAR", model.ClassWrite},
	fnRequestDownload:    {"REQUEST_DOWNLOAD", model.ClassProgram},
	fnDownloadBlock:      {"DOWNLOAD_BLOCK", model.ClassProgram},
	fnDownloadEnded:      {"DOWNLOAD_ENDED", model.ClassProgram},
	fnStartUpload:        {"START_UPLOAD", model.ClassProgram},
	fnUpload:             {"UPLOAD", model.ClassProgram},
	fnEndUpload:          {"END_UPLOAD", model.ClassProgram},
	fnPLCControl:         {"PLC_CONTROL", model.ClassControl},
	fnPLCStop:            {"PLC_STOP", model.ClassControl},
	fnSetupCommunication: {"SETUP_COMMUNICATION", model.ClassOther},
}

func appFunction(fc uint8) funcInfo {
	if info, ok := functions[fc]; ok {
		return info
	}
	return funcInfo{"Unknown", model.ClassOther}
}

// piServices are the program invocation services carried by PLC_CONTROL.
// Inserting and deleting blocks changes the program, so those two outrank the
// control classification PLC_CONTROL otherwise carries.
var piServicePrograms = map[string]bool{
	"_INSE": true, // activate a block that was just downloaded
	"_DELE": true, // delete a block
}

// memoryAreas names the S7 memory areas a variable can live in.
var memoryAreas = map[uint8]string{
	0x03: "SystemInfo",
	0x05: "SystemFlags",
	0x06: "AnalogInputs",
	0x07: "AnalogOutputs",
	0x1C: "Counter",
	0x1D: "Timer",
	0x80: "DirectPeripheral",
	0x81: "Inputs",
	0x82: "Outputs",
	0x83: "Flags",
	0x84: "DB",
	0x85: "InstanceDB",
	0x86: "LocalData",
	0x87: "PreviousLocalData",
}

// transportSizes names the data type of a variable in a request.
var transportSizes = map[uint8]string{
	0x01: "BIT",
	0x02: "BYTE",
	0x03: "CHAR",
	0x04: "WORD",
	0x05: "INT",
	0x06: "DWORD",
	0x07: "DINT",
	0x08: "REAL",
	0x09: "DATE",
	0x0A: "TOD",
	0x0B: "TIME",
	0x0C: "S5TIME",
	0x0F: "DT",
	0x14: "COUNTER",
	0x1C: "TIMER",
	0x1D: "IEC_COUNTER",
	0x1E: "IEC_TIMER",
	0x1F: "HS_COUNTER",
}

// errorClasses are the header error classes of an Ack or Ack_Data.
var errorClasses = map[uint8]string{
	0x00: "",
	0x81: "ApplicationRelationshipError",
	0x82: "ObjectDefinitionError",
	0x83: "NoResourcesAvailable",
	0x84: "ServiceProcessingError",
	0x85: "SuppliesError",
	0x87: "AccessError",
}

// returnCodes are the per-item return codes in a read or write reply.
var returnCodes = map[uint8]string{
	0x00: "RESERVED",
	0x01: "HARDWARE_FAULT",
	0x03: "ACCESS_DENIED",
	0x05: "INVALID_ADDRESS",
	0x06: "DATA_TYPE_NOT_SUPPORTED",
	0x07: "DATA_TYPE_INCONSISTENT",
	0x0A: "OBJECT_DOES_NOT_EXIST",
	0xFF: "SUCCESS",
}

// blockTypes maps the two character block type in a download or upload
// filename to the block kind an engineer would name.
var blockTypes = map[string]string{
	"08": "OB",
	"0A": "DB",
	"0B": "SDB",
	"0C": "FC",
	"0D": "SFC",
	"0E": "FB",
	"0F": "SFB",
}

// Userdata function groups.
const (
	groupModeTransition = 0x0
	groupProgrammer     = 0x1
	groupCyclicData     = 0x2
	groupBlockFunctions = 0x3
	groupCPUFunctions   = 0x4
	groupSecurity       = 0x5
	groupPBC            = 0x6
	groupTimeFunctions  = 0x7
	groupNCProgramming  = 0xF
)

// userdataGroups names each group and the classification its operations
// default to.
var userdataGroups = map[uint8]funcInfo{
	groupModeTransition: {"ModeTransition", model.ClassControl},
	// Programmer commands are the online monitoring STEP 7 does: block
	// status, variable tables, diagnostic buffers.
	groupProgrammer:     {"ProgrammerCommand", model.ClassRead},
	groupCyclicData:     {"CyclicData", model.ClassRead},
	groupBlockFunctions: {"BlockFunction", model.ClassProgram},
	groupCPUFunctions:   {"CPUFunction", model.ClassDiagnostic},
	groupSecurity:       {"Security", model.ClassOther},
	groupPBC:            {"ProgrammableBlockCommunication", model.ClassOther},
	groupTimeFunctions:  {"TimeFunction", model.ClassDiagnostic},
	groupNCProgramming:  {"NCProgramming", model.ClassProgram},
}

// SZL partial lists that carry device identity (CLAUDE.md names the SZL reads
// as the S7 enrichment source for CPU model and firmware).
const (
	szlModuleIdentification    = 0x0011
	szlComponentIdentification = 0x001C
)

// szlComponentFields maps an index of SZL list 0x001C to the identity field it
// holds.
var szlComponentFields = map[uint16]string{
	0x0001: "plc_name",
	0x0002: "module_name",
	0x0003: "plant_designation",
	0x0004: "copyright",
	0x0005: "serial_number",
	0x0007: "model",
	0x0008: "memory_card_serial",
	0x0009: "manufacturer_profile",
	0x000A: "oem_id",
	0x000B: "location",
}
