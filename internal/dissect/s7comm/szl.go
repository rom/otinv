package s7comm

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/model"
)

// Userdata parameter block geometry.
const (
	// udParamHeadLen is the three octet head 0x000112 plus the parameter
	// length, method, type/group, subfunction and sequence number.
	udParamMinLen = 8

	// udParamResponseLen adds the data unit reference, the last data unit
	// flag and a two octet error code.
	udParamResponseLen = 12

	// udTypeRequest and udTypeResponse are the high nibble of the
	// type/function group octet.
	udTypeRequest  = 0x4
	udTypeResponse = 0x8

	// subReadSZL is the CPU function that reads a system status list.
	subReadSZL = 0x01
)

// parseUserdata decodes a Userdata PDU: the programmer and diagnostic
// services, among them the SZL reads that identify the CPU.
func parseUserdata(ev *model.Event, params, data []byte) ([]model.Event, error) {
	if len(params) < udParamMinLen {
		msg := fmt.Sprintf("userdata parameters need %d octets, %d present", udParamMinLen, len(params))
		return []model.Event{malformed(*ev, msg)}, fmt.Errorf("%w: %s", dissect.ErrMalformed, msg)
	}

	typeGroup := params[5]
	udType := typeGroup >> 4
	group := typeGroup & 0x0f
	subfunction := params[6]

	info, known := userdataGroups[group]
	if !known {
		info = funcInfo{fmt.Sprintf("Userdata0x%x", group), model.ClassOther}
	}
	ev.Operation = info.name
	ev.Class = info.class
	setAttr(ev, "function_group", fmt.Sprintf("0x%x", group))
	setAttr(ev, "subfunction", fmt.Sprintf("0x%02x", subfunction))
	setAttr(ev, "sequence_number", strconv.Itoa(int(params[7])))

	switch udType {
	case udTypeRequest:
		ev.Direction = model.DirRequest
		setAttr(ev, "userdata_type", "request")
	case udTypeResponse:
		ev.Direction = model.DirResponse
		setAttr(ev, "userdata_type", "response")
	}

	if len(params) >= udParamResponseLen {
		// A response says whether more data units follow. Wireshark reads
		// this flag as 0x00 meaning this was the last one.
		if params[9] != 0x00 {
			setAttr(ev, "more_follows", "true")
		}
		if code := binary.BigEndian.Uint16(params[10:12]); code != 0 {
			setAttr(ev, "error_code", fmt.Sprintf("0x%04x", code))
		}
	}

	// Setting the clock changes the device; reading it does not.
	if group == groupTimeFunctions {
		switch subfunction {
		case 0x02, 0x04:
			ev.Operation = "SetClock"
			ev.Class = model.ClassWrite
		case 0x01, 0x03:
			ev.Operation = "ReadClock"
			ev.Class = model.ClassDiagnostic
		}
	}

	if group == groupCPUFunctions && subfunction == subReadSZL {
		ev.Operation = "ReadSZL"
		// An SZL read enumerates what the device is, which is discovery
		// rather than plain diagnostics.
		ev.Class = model.ClassDiscovery
		parseSZL(ev, data)
	}
	return []model.Event{*ev}, nil
}

// szlHeaderLen is the return code, transport size and length that precede the
// list, plus the list id and index.
const szlHeaderLen = 8

// parseSZL decodes a system status list and lifts the device identity out of
// the lists that carry it.
//
// A partial list can span several data units; this decodes the records in the
// unit at hand and records that more follow, rather than stitching units
// together. The identity lists arrive in the first unit in practice.
func parseSZL(ev *model.Event, data []byte) {
	if len(data) < szlHeaderLen {
		if len(data) > 0 {
			setAttr(ev, "anomaly", "truncated_szl")
		}
		return
	}

	if name, ok := returnCodes[data[0]]; ok {
		setAttr(ev, "return_code", name)
	}
	szlID := binary.BigEndian.Uint16(data[4:6])
	index := binary.BigEndian.Uint16(data[6:8])
	setAttr(ev, "szl_id", fmt.Sprintf("0x%04x", szlID))
	setAttr(ev, "szl_index", fmt.Sprintf("0x%04x", index))

	// A request stops here: it only names the list it wants.
	if len(data) < szlHeaderLen+4 {
		return
	}
	recordLen := int(binary.BigEndian.Uint16(data[8:10]))
	recordCount := int(binary.BigEndian.Uint16(data[10:12]))
	setAttr(ev, "szl_records", strconv.Itoa(recordCount))
	if recordLen == 0 {
		return
	}

	records := data[12:]
	available := len(records) / recordLen
	if available < recordCount {
		// The list says more records than this data unit carries, which is
		// normal for a list split across units.
		setAttr(ev, "records_present", strconv.Itoa(available))
	}

	for i := range min(recordCount, available) {
		record := records[i*recordLen : (i+1)*recordLen]
		switch szlID {
		case szlModuleIdentification:
			readModuleRecord(ev, record)
		case szlComponentIdentification:
			readComponentRecord(ev, record)
		}
	}
}

// Module identification record geometry (SZL 0x0011): an index, the Siemens
// order number, and three version fields.
const (
	moduleRecordLen = 28
	mlfbLen         = 20

	moduleIndexModule        = 0x0001
	moduleIndexBasicHardware = 0x0006
	moduleIndexBasicFirmware = 0x0007
)

// readModuleRecord lifts the order number and the firmware version out of SZL
// list 0x0011.
func readModuleRecord(ev *model.Event, record []byte) {
	if len(record) < moduleRecordLen {
		return
	}
	index := binary.BigEndian.Uint16(record[0:2])
	mlfb := printable(record[2 : 2+mlfbLen])

	switch index {
	case moduleIndexModule:
		if mlfb != "" {
			setIdentity(ev, "order_number", mlfb)
		}
	case moduleIndexBasicHardware:
		if mlfb != "" {
			setAttr(ev, "hardware_order_number", mlfb)
		}
	case moduleIndexBasicFirmware:
		// For the firmware record the order number field is blank and the
		// version lives in the two version fields: the high octet of the
		// first is the letter V, and the remaining three octets are the
		// version digits. The sample capture reads V3.2.6 this way, from
		// 0x5603 and 0x0206.
		ausbg := binary.BigEndian.Uint16(record[24:26])
		ausbe := binary.BigEndian.Uint16(record[26:28])
		if byte(ausbg>>8) == 'V' {
			setIdentity(ev, "firmware_revision", fmt.Sprintf("V%d.%d.%d",
				ausbg&0xff, ausbe>>8, ausbe&0xff))
		}
	}
}

// Component identification record geometry (SZL 0x001C): an index and a fixed
// width name.
const componentRecordLen = 34

// readComponentRecord lifts the names out of SZL list 0x001C: the CPU model,
// its serial number and the name the engineer gave the station.
func readComponentRecord(ev *model.Event, record []byte) {
	if len(record) < componentRecordLen {
		return
	}
	index := binary.BigEndian.Uint16(record[0:2])
	value := printable(record[2:componentRecordLen])
	if value == "" {
		return
	}

	field, known := szlComponentFields[index]
	if !known {
		setAttr(ev, fmt.Sprintf("szl_1c_index_0x%04x", index), value)
		return
	}

	switch field {
	case "copyright":
		// The copyright string is the device naming its manufacturer, which
		// is evidence for the vendor rather than a field of its own.
		setAttr(ev, "copyright", value)
		if strings.Contains(strings.ToLower(value), "siemens") {
			setIdentity(ev, "vendor_name", "Siemens")
		}
	case "plant_designation", "location", "memory_card_serial",
		"manufacturer_profile", "oem_id":
		setAttr(ev, field, value)
	default:
		setIdentity(ev, field, value)
	}
}
