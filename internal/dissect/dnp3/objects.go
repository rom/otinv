package dnp3

import (
	"encoding/binary"
	"fmt"
)

// Qualifier range specifier codes (IEEE 1815, table 4-5).
const (
	rangeStartStop8  = 0
	rangeStartStop16 = 1
	rangeStartStop32 = 2
	rangeAddr8       = 3
	rangeAddr16      = 4
	rangeAddr32      = 5
	rangeAllObjects  = 6
	rangeCount8      = 7
	rangeCount16     = 8
	rangeCount32     = 9
	rangeVariable    = 11
)

// objectHeader is one decoded object header and whatever could be read of the
// objects behind it.
type objectHeader struct {
	group     uint8
	variation uint8
	qualifier uint8
	prefix    uint8
	rangeSpec uint8

	// hasRange is set when the header carries a start/stop range rather than
	// a count, and count is set whenever the number of objects is knowable.
	hasRange   bool
	start      uint32
	stop       uint32
	count      int
	countKnown bool

	// indexes holds the index prefixes read from the objects, which is where
	// a command's point number comes from.
	indexes []uint32

	// data is the object data, when its size was known well enough to read.
	data []byte
}

func (h objectHeader) label() string {
	return fmt.Sprintf("g%dv%d", h.group, h.variation)
}

// parseObjects walks the object headers of an application fragment.
//
// Walking past a header needs the size of the objects behind it, and that is a
// per-variation property. The sizes of the common static, event and command
// variations are known here; anything else stops the walk, which is reported
// rather than guessed, because mis-skipping object data would turn the rest of
// the fragment into invented headers.
func parseObjects(buf []byte) (headers []objectHeader, complete bool) {
	for len(buf) > 0 {
		if len(buf) < 3 {
			return headers, false
		}
		h := objectHeader{group: buf[0], variation: buf[1], qualifier: buf[2]}
		h.prefix = (h.qualifier >> 4) & 0x07
		h.rangeSpec = h.qualifier & 0x0f
		buf = buf[3:]

		var ok bool
		if buf, ok = h.readRange(buf); !ok {
			headers = append(headers, h)
			return headers, false
		}

		rest, walked := h.readObjects(buf)
		headers = append(headers, h)
		if !walked {
			return headers, false
		}
		buf = rest
	}
	return headers, true
}

// readRange reads the range field that follows a qualifier.
func (h *objectHeader) readRange(buf []byte) ([]byte, bool) {
	switch h.rangeSpec {
	case rangeStartStop8, rangeAddr8:
		if len(buf) < 2 {
			return buf, false
		}
		h.start, h.stop = uint32(buf[0]), uint32(buf[1])
		buf = buf[2:]
	case rangeStartStop16, rangeAddr16:
		if len(buf) < 4 {
			return buf, false
		}
		h.start = uint32(binary.LittleEndian.Uint16(buf[0:2]))
		h.stop = uint32(binary.LittleEndian.Uint16(buf[2:4]))
		buf = buf[4:]
	case rangeStartStop32, rangeAddr32:
		if len(buf) < 8 {
			return buf, false
		}
		h.start = binary.LittleEndian.Uint32(buf[0:4])
		h.stop = binary.LittleEndian.Uint32(buf[4:8])
		buf = buf[8:]
	case rangeAllObjects:
		// No range field: the request means every object in the group.
		return buf, true
	case rangeCount8, rangeVariable:
		if len(buf) < 1 {
			return buf, false
		}
		h.count, h.countKnown = int(buf[0]), true
		return buf[1:], true
	case rangeCount16:
		if len(buf) < 2 {
			return buf, false
		}
		h.count, h.countKnown = int(binary.LittleEndian.Uint16(buf)), true
		return buf[2:], true
	case rangeCount32:
		if len(buf) < 4 {
			return buf, false
		}
		n := binary.LittleEndian.Uint32(buf)
		// A count this large cannot be backed by the bytes present; treat it
		// as unreadable rather than allocating for it.
		if n > uint32(len(buf)) {
			return buf, false
		}
		h.count, h.countKnown = int(n), true
		return buf[4:], true
	default:
		// Reserved range specifier: the rest of the fragment is unreadable.
		return buf, false
	}

	if h.stop < h.start {
		return buf, false
	}
	h.hasRange = true
	h.count, h.countKnown = int(h.stop-h.start)+1, true
	return buf, true
}

// readObjects reads the object data behind a header, when its size is known.
func (h *objectHeader) readObjects(buf []byte) ([]byte, bool) {
	if h.rangeSpec == rangeAllObjects || h.variation == 0 {
		// A request for every object, or for any variation, carries no data.
		return buf, true
	}
	if !h.countKnown || h.count == 0 {
		return buf, h.count == 0
	}

	switch h.prefix {
	case 0:
		// Objects are packed with no prefix.
		size, known := packedSize(h.group, h.variation, h.count)
		if !known || size > len(buf) {
			return buf, false
		}
		h.data = buf[:size]
		return buf[size:], true

	case 1, 2, 3:
		// Each object is preceded by an index.
		indexLen := 1 << (h.prefix - 1) // 1, 2 or 4 octets
		one, known := objectSize(h.group, h.variation)
		if !known {
			return buf, false
		}
		need := h.count * (indexLen + one)
		if need > len(buf) {
			return buf, false
		}
		h.data = buf[:need]
		for i := range h.count {
			at := i * (indexLen + one)
			h.indexes = append(h.indexes, readIndex(buf[at:], indexLen))
		}
		return buf[need:], true

	case 4, 5, 6:
		// Each object is preceded by its own size, so no table is needed.
		sizeLen := 1 << (h.prefix - 4) // 1, 2 or 4 octets
		consumed := 0
		for range h.count {
			if consumed+sizeLen > len(buf) {
				return buf, false
			}
			size := int(readIndex(buf[consumed:], sizeLen))
			consumed += sizeLen
			if size > len(buf)-consumed {
				return buf, false
			}
			consumed += size
		}
		h.data = buf[:consumed]
		return buf[consumed:], true

	default:
		return buf, false
	}
}

func readIndex(buf []byte, width int) uint32 {
	switch width {
	case 1:
		return uint32(buf[0])
	case 2:
		return uint32(binary.LittleEndian.Uint16(buf))
	case 4:
		return binary.LittleEndian.Uint32(buf)
	default:
		return 0
	}
}

// bitPacked lists the group/variation pairs whose objects are single bits, or
// two bits for the double-bit groups.
func bitPacked(group, variation uint8) (bits int, ok bool) {
	switch {
	case group == 1 && variation == 1,
		group == 10 && variation == 1,
		group == 12 && variation == 3,
		group == 80 && variation == 1:
		return 1, true
	case group == 3 && variation == 1:
		return 2, true
	default:
		return 0, false
	}
}

// packedSize returns the byte count of count objects stored without prefixes.
func packedSize(group, variation uint8, count int) (int, bool) {
	if bits, ok := bitPacked(group, variation); ok {
		return (count*bits + 7) / 8, true
	}
	one, known := objectSize(group, variation)
	if !known {
		return 0, false
	}
	return count * one, true
}

// objectSize returns the size in bytes of one object of a group and variation.
//
// Only the variations that appear in real traffic are listed; an unknown one
// stops the object walk instead of being guessed at.
func objectSize(group, variation uint8) (int, bool) {
	// Octet strings and their events encode their length in the variation.
	if group == 110 || group == 111 {
		if variation == 0 {
			return 0, false
		}
		return int(variation), true
	}

	sizes := map[[2]uint8]int{
		{1, 2}: 1,
		{2, 1}: 1, {2, 2}: 7, {2, 3}: 3,
		{3, 2}: 1,
		{4, 1}: 1, {4, 2}: 7, {4, 3}: 3,
		{10, 2}: 1,
		{11, 1}: 1, {11, 2}: 7,
		{12, 1}: 11, {12, 2}: 11,
		{13, 1}: 1, {13, 2}: 7,
		{20, 1}: 5, {20, 2}: 3, {20, 5}: 4, {20, 6}: 2,
		{21, 1}: 5, {21, 2}: 3, {21, 5}: 11, {21, 6}: 9, {21, 9}: 4, {21, 10}: 2,
		{22, 1}: 5, {22, 2}: 3, {22, 5}: 11, {22, 6}: 9,
		{23, 1}: 5, {23, 2}: 3, {23, 5}: 11, {23, 6}: 9,
		{30, 1}: 5, {30, 2}: 3, {30, 3}: 4, {30, 4}: 2, {30, 5}: 5, {30, 6}: 9,
		{31, 1}: 5, {31, 2}: 3, {31, 3}: 4, {31, 4}: 2, {31, 5}: 5, {31, 6}: 9,
		{32, 1}: 5, {32, 2}: 3, {32, 3}: 11, {32, 4}: 9, {32, 5}: 5, {32, 6}: 9,
		{32, 7}: 11, {32, 8}: 15,
		{33, 1}: 5, {33, 2}: 3, {33, 3}: 11, {33, 4}: 9, {33, 5}: 5, {33, 6}: 9,
		{34, 1}: 2, {34, 2}: 4, {34, 3}: 4,
		{40, 1}: 5, {40, 2}: 3, {40, 3}: 5, {40, 4}: 9,
		{41, 1}: 5, {41, 2}: 3, {41, 3}: 5, {41, 4}: 9,
		{42, 1}: 5, {42, 2}: 3, {42, 3}: 11, {42, 4}: 9, {42, 5}: 5, {42, 6}: 9,
		{42, 7}: 11, {42, 8}: 15,
		{43, 1}: 5, {43, 2}: 3, {43, 3}: 11, {43, 4}: 9, {43, 5}: 5, {43, 6}: 9,
		{43, 7}: 11, {43, 8}: 15,
		{50, 1}: 6, {50, 2}: 10, {50, 3}: 6, {50, 4}: 11,
		{51, 1}: 6, {51, 2}: 6,
		{52, 1}: 2, {52, 2}: 2,
		{102, 1}: 1,
	}
	size, ok := sizes[[2]uint8{group, variation}]
	return size, ok
}
