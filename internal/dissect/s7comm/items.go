package s7comm

import (
	"encoding/binary"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/model"
)

// Item specification constants of the variable services.
const (
	itemSpecVariable = 0x12 // every item specification starts with this
	syntaxS7ANY      = 0x10 // the addressing mode STEP 7 and WinCC use
	syntaxDBRead     = 0xb0
	syntaxSymbolic   = 0xb2

	// s7anyLen is syntax id, transport size, count, DB number, area and a
	// three octet address.
	s7anyLen = 10
)

// parseVarService decodes a read or write of variables: which area, which
// offset and how much.
//
// The first item gives the event its address and quantity, because that is
// what a rule and a GUI row need; every item's area is listed in an
// attribute, so a multi-item request is not misrepresented as a single one.
func parseVarService(ev *model.Event, params, data []byte) {
	if len(params) < 2 {
		setAttr(ev, "anomaly", "truncated_var_service")
		return
	}
	count := int(params[1])
	setAttr(ev, "item_count", strconv.Itoa(count))

	items, complete := parseItems(params[2:], count)
	if !complete {
		setAttr(ev, "items_truncated", "true")
	}

	areas := make([]string, 0, len(items))
	for i, it := range items {
		areas = append(areas, it.label())
		if i > 0 {
			continue
		}
		// The first item describes the event.
		ev.Address = model.Ptr(it.byteOffset)
		ev.Quantity = model.Ptr(uint32(it.count))
		setAttr(ev, "area", it.areaName())
		setAttr(ev, "db_number", strconv.Itoa(int(it.dbNumber)))
		if name, ok := transportSizes[it.transportSize]; ok {
			setAttr(ev, "transport_size", name)
		}
		if it.bitOffset != 0 {
			setAttr(ev, "bit_offset", strconv.Itoa(int(it.bitOffset)))
		}
	}
	if len(areas) > 0 {
		setAttr(ev, "items", strings.Join(areas, ","))
	}

	// A reply carries the outcome per item in the data block rather than in
	// the parameters.
	if ev.Direction == model.DirResponse && len(data) > 0 {
		if name, ok := returnCodes[data[0]]; ok {
			setAttr(ev, "return_code", name)
		} else {
			setAttr(ev, "return_code", "0x"+hexString(data[:1]))
		}
	}
	// A write request carries the value it is about to set.
	if ev.Direction == model.DirRequest && len(data) > 4 {
		setAttr(ev, "value", hexString(capBytes(data[4:])))
	}
}

// varItem is one decoded item specification.
type varItem struct {
	syntax        uint8
	transportSize uint8
	count         int
	dbNumber      uint16
	area          uint8
	byteOffset    uint32
	bitOffset     uint8
	raw           []byte
}

func (it varItem) areaName() string {
	if name, ok := memoryAreas[it.area]; ok {
		return name
	}
	return "0x" + hexString([]byte{it.area})
}

func (it varItem) label() string {
	if it.syntax != syntaxS7ANY {
		return "syntax0x" + hexString([]byte{it.syntax})
	}
	if it.area == 0x84 || it.area == 0x85 {
		return it.areaName() + strconv.Itoa(int(it.dbNumber)) + "." +
			strconv.FormatUint(uint64(it.byteOffset), 10)
	}
	return it.areaName() + "." + strconv.FormatUint(uint64(it.byteOffset), 10)
}

// parseItems walks the item specifications of a variable service.
func parseItems(buf []byte, count int) (items []varItem, complete bool) {
	for range count {
		if len(buf) < 2 {
			return items, false
		}
		if buf[0] != itemSpecVariable {
			// Not an item specification: stop rather than read the rest as
			// though it were one.
			return items, false
		}
		length := int(buf[1])
		if 2+length > len(buf) {
			return items, false
		}
		body := buf[2 : 2+length]
		buf = buf[2+length:]

		it := varItem{raw: body}
		if len(body) >= 1 {
			it.syntax = body[0]
		}
		if it.syntax == syntaxS7ANY && len(body) >= s7anyLen {
			it.transportSize = body[1]
			it.count = int(binary.BigEndian.Uint16(body[2:4]))
			it.dbNumber = binary.BigEndian.Uint16(body[4:6])
			it.area = body[6]
			// The address is 18 bits of byte offset and three of bit offset.
			addr := uint32(body[7])<<16 | uint32(body[8])<<8 | uint32(body[9])
			it.byteOffset = addr >> 3
			it.bitOffset = uint8(addr & 0x07)
		}
		items = append(items, it)
	}
	return items, true
}

// parseBlockTransfer decodes the upload and download requests, whose filename
// names the block whose code or data is moving.
func parseBlockTransfer(ev *model.Event, params []byte) {
	// Function code, function status, two reserved octets and a four octet
	// session id, then the filename.
	const fixed = 1 + 1 + 2 + 4
	if len(params) < fixed+1 {
		setAttr(ev, "anomaly", "truncated_block_transfer")
		return
	}
	nameLen := int(params[fixed])
	rest := params[fixed+1:]
	if nameLen > len(rest) {
		setAttr(ev, "anomaly", "truncated_block_transfer")
		return
	}

	filename := printable(rest[:nameLen])
	if filename == "" {
		return
	}
	setAttr(ev, "filename", filename)
	describeBlockFilename(ev, filename)
}

// describeBlockFilename reads a block filename of the form _0A00001P: an
// underscore, a two character block type, a five digit block number and the
// filesystem the block lives in.
func describeBlockFilename(ev *model.Event, filename string) {
	if len(filename) < 9 || filename[0] != '_' {
		return
	}
	if name, ok := blockTypes[filename[1:3]]; ok {
		setAttr(ev, "block_type", name)
	}
	if number, err := strconv.Atoi(filename[3:8]); err == nil {
		setAttr(ev, "block_number", strconv.Itoa(number))
	}
	setAttr(ev, "destination_filesystem", filename[8:9])
}
