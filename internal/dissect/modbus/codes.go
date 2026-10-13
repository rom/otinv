package modbus

import "github.com/rom/otinv/internal/model"

// Function codes, sub-functions, exception codes and device identification
// objects from the MODBUS Application Protocol Specification v1.1b3 and the
// MODBUS Messaging on TCP/IP Implementation Guide v1.0b.

// Function codes this dissector decodes (v1.1b3, section 6).
const (
	fcReadCoils                  = 1
	fcReadDiscreteInputs         = 2
	fcReadHoldingRegisters       = 3
	fcReadInputRegisters         = 4
	fcWriteSingleCoil            = 5
	fcWriteSingleRegister        = 6
	fcReadExceptionStatus        = 7
	fcDiagnostics                = 8
	fcGetCommEventCounter        = 11
	fcGetCommEventLog            = 12
	fcWriteMultipleCoils         = 15
	fcWriteMultipleRegisters     = 16
	fcReportServerID             = 17
	fcReadFileRecord             = 20
	fcWriteFileRecord            = 21
	fcMaskWriteRegister          = 22
	fcReadWriteMultipleRegisters = 23
	fcReadFIFOQueue              = 24
	fcEncapsulatedInterface      = 43
)

type funcInfo struct {
	name  string
	class model.Classification
}

// functions maps a function code to its name and shared classification.
// Rules match on the classification, never on the raw code.
var functions = map[uint8]funcInfo{
	fcReadCoils:              {"ReadCoils", model.ClassRead},
	fcReadDiscreteInputs:     {"ReadDiscreteInputs", model.ClassRead},
	fcReadHoldingRegisters:   {"ReadHoldingRegisters", model.ClassRead},
	fcReadInputRegisters:     {"ReadInputRegisters", model.ClassRead},
	fcWriteSingleCoil:        {"WriteSingleCoil", model.ClassWrite},
	fcWriteSingleRegister:    {"WriteSingleRegister", model.ClassWrite},
	fcReadExceptionStatus:    {"ReadExceptionStatus", model.ClassDiagnostic},
	fcDiagnostics:            {"Diagnostics", model.ClassDiagnostic},
	fcGetCommEventCounter:    {"GetCommEventCounter", model.ClassDiagnostic},
	fcGetCommEventLog:        {"GetCommEventLog", model.ClassDiagnostic},
	fcWriteMultipleCoils:     {"WriteMultipleCoils", model.ClassWrite},
	fcWriteMultipleRegisters: {"WriteMultipleRegisters", model.ClassWrite},
	// Report Server ID returns device identity, which is what makes it
	// interesting to an inventory: classified as discovery, not diagnostic.
	fcReportServerID: {"ReportServerID", model.ClassDiscovery},
	// File records hold device-specific data; on some controllers that is
	// configuration. Classified by the direction of the access.
	fcReadFileRecord:    {"ReadFileRecord", model.ClassRead},
	fcWriteFileRecord:   {"WriteFileRecord", model.ClassWrite},
	fcMaskWriteRegister: {"MaskWriteRegister", model.ClassWrite},
	// Read/Write Multiple Registers both reads and writes in one PDU. The
	// write is the security-relevant half, so it classifies as a write.
	fcReadWriteMultipleRegisters: {"ReadWriteMultipleRegisters", model.ClassWrite},
	fcReadFIFOQueue:              {"ReadFIFOQueue", model.ClassRead},
	// Refined to ReadDeviceIdentification once the MEI type is known.
	fcEncapsulatedInterface: {"EncapsulatedInterfaceTransport", model.ClassOther},
}

// reservedCodes are the codes the specification reserves for legacy use
// (v1.1b3, section 5).
var reservedCodes = map[uint8]bool{
	9: true, 10: true, 13: true, 14: true, 41: true,
	42: true, 90: true, 91: true, 125: true, 126: true, 127: true,
}

// classify names and classifies a function code, including the code ranges the
// specification leaves to the vendor (v1.1b3, section 5).
func classify(fc uint8) funcInfo {
	if info, ok := functions[fc]; ok {
		return info
	}
	switch {
	case reservedCodes[fc]:
		return funcInfo{"Reserved", model.ClassOther}
	case (fc >= 65 && fc <= 72) || (fc >= 100 && fc <= 110):
		return funcInfo{"UserDefined", model.ClassOther}
	default:
		return funcInfo{"Unknown", model.ClassOther}
	}
}

// Diagnostics sub-functions (v1.1b3, section 6.8).
const (
	diagReturnQueryData    = 0x0000
	diagRestartComms       = 0x0001
	diagForceListenOnly    = 0x0004
	diagClearCounters      = 0x000A
	diagClearOverrunCounts = 0x0014
)

// diagSubFunctions maps a diagnostics sub-function to its name and the
// classification of that specific sub-function.
//
// Most sub-functions only read counters, so FC 8 is a diagnostic by default.
// Two of them change how the device behaves on the bus — Restart
// Communications Option drops the session, Force Listen Only Mode stops the
// device answering anyone — so those classify as control, which is what the
// built-in detection rules key on.
var diagSubFunctions = map[uint16]funcInfo{
	diagReturnQueryData:    {"ReturnQueryData", model.ClassDiagnostic},
	diagRestartComms:       {"RestartCommunicationsOption", model.ClassControl},
	0x0002:                 {"ReturnDiagnosticRegister", model.ClassDiagnostic},
	0x0003:                 {"ChangeASCIIInputDelimiter", model.ClassDiagnostic},
	diagForceListenOnly:    {"ForceListenOnlyMode", model.ClassControl},
	diagClearCounters:      {"ClearCountersAndDiagnosticRegister", model.ClassDiagnostic},
	0x000B:                 {"ReturnBusMessageCount", model.ClassDiagnostic},
	0x000C:                 {"ReturnBusCommunicationErrorCount", model.ClassDiagnostic},
	0x000D:                 {"ReturnBusExceptionErrorCount", model.ClassDiagnostic},
	0x000E:                 {"ReturnServerMessageCount", model.ClassDiagnostic},
	0x000F:                 {"ReturnServerNoResponseCount", model.ClassDiagnostic},
	0x0010:                 {"ReturnServerNAKCount", model.ClassDiagnostic},
	0x0011:                 {"ReturnServerBusyCount", model.ClassDiagnostic},
	0x0012:                 {"ReturnBusCharacterOverrunCount", model.ClassDiagnostic},
	diagClearOverrunCounts: {"ClearOverrunCounterAndFlag", model.ClassDiagnostic},
}

func classifyDiagnostic(sub uint16) funcInfo {
	if info, ok := diagSubFunctions[sub]; ok {
		return info
	}
	return funcInfo{"Unknown", model.ClassDiagnostic}
}

// Exception codes (v1.1b3, section 7).
var exceptionNames = map[uint8]string{
	0x01: "IllegalFunction",
	0x02: "IllegalDataAddress",
	0x03: "IllegalDataValue",
	0x04: "ServerDeviceFailure",
	0x05: "Acknowledge",
	0x06: "ServerDeviceBusy",
	0x08: "MemoryParityError",
	0x0A: "GatewayPathUnavailable",
	0x0B: "GatewayTargetDeviceFailedToRespond",
}

func exceptionName(code uint8) string {
	if n, ok := exceptionNames[code]; ok {
		return n
	}
	return "Unknown"
}

// MEI types carried by FC 43 (v1.1b3, section 6.19).
const (
	meiCANopen          = 0x0D
	meiReadDeviceIdent  = 0x0E
	readDeviceIDObjects = 7
)

// deviceIDObjects maps a Read Device Identification object id to the identity
// key used on events (v1.1b3, section 6.21).
var deviceIDObjects = map[uint8]string{
	0x00: "vendor_name",
	0x01: "product_code",
	0x02: "major_minor_revision",
	0x03: "vendor_url",
	0x04: "product_name",
	0x05: "model_name",
	0x06: "user_application_name",
}
