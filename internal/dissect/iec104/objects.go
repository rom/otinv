package iec104

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/model"
)

// asdu is a decoded ASDU header plus the information object octets that
// follow it.
type asdu struct {
	typeID uint8
	info   typeInfo

	// sequence is the SQ bit: set, the addresses of the count elements are
	// consecutive and only the first is transmitted (-101, clause 7.2.2).
	sequence bool
	count    uint8

	cause    uint8
	negative bool // P/N: the confirmation is a refusal
	test     bool // the ASDU was sent for testing, not for operation
	origin   uint8
	common   uint16

	elements []byte
}

// object is one information object: its address and its information element.
type object struct {
	ioa  uint32
	data []byte
}

// readIOA reads a three octet information object address, least significant
// octet first.
func readIOA(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
}

// walkObjects slices the information objects out of an ASDU.
//
// The count and the SQ bit come off the wire, so what they ask for is checked
// against the element size the standard fixes for this type before a single
// element is read. A frame that claims more objects than it carries is
// rejected rather than read past its end.
func walkObjects(a asdu) ([]object, int, error) {
	size := a.info.size
	count := int(a.count)
	if count == 0 {
		return nil, 0, nil
	}
	if size < 0 {
		// The element declares its own length, so only the address can be
		// read without following the type's own rules for the rest.
		if len(a.elements) < ioaLen {
			return nil, 0, fmt.Errorf("%s needs %d octets for an object address, %d present",
				a.info.name, ioaLen, len(a.elements))
		}
		return []object{{ioa: readIOA(a.elements)}}, ioaLen, nil
	}

	if a.sequence {
		need := ioaLen + count*size
		if len(a.elements) < need {
			return nil, 0, fmt.Errorf(
				"%s declares a sequence of %d elements of %d octets, needing %d octets, %d present",
				a.info.name, count, size, need, len(a.elements))
		}
		base := readIOA(a.elements)
		objects := make([]object, 0, count)
		for i := range count {
			off := ioaLen + i*size
			objects = append(objects, object{
				ioa:  base + uint32(i),
				data: a.elements[off : off+size],
			})
		}
		return objects, need, nil
	}

	need := count * (ioaLen + size)
	if len(a.elements) < need {
		return nil, 0, fmt.Errorf(
			"%s declares %d objects of %d octets, needing %d octets, %d present",
			a.info.name, count, ioaLen+size, need, len(a.elements))
	}
	objects := make([]object, 0, count)
	for i := range count {
		off := i * (ioaLen + size)
		objects = append(objects, object{
			ioa:  readIOA(a.elements[off:]),
			data: a.elements[off+ioaLen : off+ioaLen+size],
		})
	}
	return objects, need, nil
}

// describeObjects records the addresses the ASDU carries and decodes the first
// information element.
//
// Only the first element is decoded in full. An ASDU may hold 127 of them, and
// one event per point would bury the operation the analyst is looking for; the
// addresses are all listed, so a drill-down has what it needs.
func describeObjects(ev *model.Event, a asdu, objects []object, used int) {
	switch {
	case a.info.size < 0:
		// The walk stopped at the first address because the element layout is
		// not known, so the octets after it are not unaccounted for, they are
		// simply not read. Saying so is better than listing the addresses that
		// were read as if they were all of them.
		setAttr(ev, "objects_truncated", "true")
	case len(a.elements) > used:
		// Padding or a second ASDU smuggled behind the first. Either way the
		// frame carries octets its own header does not account for.
		setAttr(ev, "trailing_bytes", strconv.Itoa(len(a.elements)-used))
	}
	if len(objects) == 0 {
		// Legal for a read request, which addresses nothing, and meaningless
		// for everything else.
		if a.typeID != 102 {
			addAnomaly(ev, "no_information_objects")
		}
		return
	}

	if a.sequence {
		setAttr(ev, "sequence", "true")
	}
	first := objects[0]
	// An information object address of zero is defined as "not used", which is
	// what a station-wide command such as an interrogation carries.
	if first.ioa != 0 {
		ev.Address = model.Ptr(first.ioa)
	}
	if len(objects) > 1 {
		ev.Quantity = model.Ptr(uint32(len(objects)))
		setAttr(ev, "objects", listAddresses(a, objects))
	}
	describeElement(ev, a, first.data)
}

// listAddresses renders the object addresses. A sequence is a range by
// definition, and a long list is cut short: the event names the operation, the
// flow drill-down holds the detail.
func listAddresses(a asdu, objects []object) string {
	if a.sequence {
		return strconv.FormatUint(uint64(objects[0].ioa), 10) + "-" +
			strconv.FormatUint(uint64(objects[len(objects)-1].ioa), 10)
	}
	shown := min(len(objects), maxListedObjects)
	parts := make([]string, 0, shown+1)
	for _, o := range objects[:shown] {
		parts = append(parts, strconv.FormatUint(uint64(o.ioa), 10))
	}
	if rest := len(objects) - shown; rest > 0 {
		parts = append(parts, "+"+strconv.Itoa(rest)+" more")
	}
	return strings.Join(parts, ",")
}

// describeElement decodes one information element. The layouts are those of
// IEC 60870-5-101, clause 7.3, which -104 carries unchanged.
func describeElement(ev *model.Event, a asdu, data []byte) {
	if len(data) == 0 {
		return
	}
	// Every element with a time tag carries it last, so the value part is what
	// precedes it.
	stamp := timeTagLen(a.typeID)
	value := data
	if stamp > 0 && len(data) >= stamp {
		value = data[:len(data)-stamp]
		setTime(ev, timeAttr(a.typeID), data[len(data)-stamp:])
	}
	if len(value) == 0 {
		return
	}

	switch a.typeID {
	case 1, 2, 30: // single point information
		setAttr(ev, "value", singlePoint(value[0]))
		setQuality(ev, value[0], false)

	case 3, 4, 31: // double point information
		setAttr(ev, "value", doublePoints[value[0]&0x03])
		setQuality(ev, value[0], false)

	case 5, 6, 32: // step position
		setAttr(ev, "value", strconv.Itoa(int(stepPosition(value[0]))))
		if value[0]&0x80 != 0 {
			setAttr(ev, "transient", "true")
		}
		if len(value) > 1 {
			setQuality(ev, value[1], true)
		}

	case 7, 8, 33, 51, 64: // bit strings of 32 bit
		if len(value) >= 4 {
			setAttr(ev, "value", fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(value[:4])))
		}
		if len(value) > 4 {
			setQuality(ev, value[4], true)
		}

	case 9, 10, 34, 21: // normalised measured value
		setNormalised(ev, value)
		if a.typeID != 21 && len(value) > 2 {
			setQuality(ev, value[2], true)
		}

	case 11, 12, 35: // scaled measured value
		if len(value) >= 2 {
			setAttr(ev, "value", strconv.Itoa(int(int16(binary.LittleEndian.Uint16(value[:2])))))
		}
		if len(value) > 2 {
			setQuality(ev, value[2], true)
		}

	case 13, 14, 36: // short floating point measured value
		setFloat(ev, value)
		if len(value) > 4 {
			setQuality(ev, value[4], true)
		}

	case 15, 16, 37: // binary counter reading
		setCounter(ev, value)

	case 20: // packed single point with change detection
		if len(value) >= 4 {
			setAttr(ev, "value", fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(value[:4])))
		}
		if len(value) > 4 {
			setQuality(ev, value[4], true)
		}

	case 17, 18, 19, 38, 39, 40: // events of protection equipment
		setAttr(ev, "value", fmt.Sprintf("0x%02x", value[0]))
		setQuality(ev, value[0], false)

	case 45, 58: // single command
		setCommand(ev, value[0], singleCommands[value[0]&0x01])

	case 46, 59: // double command
		setCommand(ev, value[0], doubleCommands[value[0]&0x03])
		if doubleCommands[value[0]&0x03] == "not_permitted" {
			addAnomaly(ev, "reserved_command_state")
		}

	case 47, 60: // regulating step command
		setCommand(ev, value[0], stepCommands[value[0]&0x03])
		if stepCommands[value[0]&0x03] == "not_permitted" {
			addAnomaly(ev, "reserved_command_state")
		}

	case 48, 61: // set point command, normalised value
		setNormalised(ev, value)
		if len(value) > 2 {
			setSetPointQualifier(ev, value[2])
		}

	case 49, 62: // set point command, scaled value
		if len(value) >= 2 {
			setAttr(ev, "value", strconv.Itoa(int(int16(binary.LittleEndian.Uint16(value[:2])))))
		}
		if len(value) > 2 {
			setSetPointQualifier(ev, value[2])
		}

	case 50, 63: // set point command, short floating point value
		setFloat(ev, value)
		if len(value) > 4 {
			setSetPointQualifier(ev, value[4])
		}

	case 70: // end of initialisation
		setAttr(ev, "init_cause", lookup(initCauses, value[0]&0x7f))
		if value[0]&0x80 != 0 {
			setAttr(ev, "init_after_parameter_change", "true")
		}

	case 100: // interrogation command
		setAttr(ev, "interrogation", interrogationName(value[0]))

	case 101: // counter interrogation command
		setAttr(ev, "counter_request", lookup(counterRequests, value[0]&0x3f))
		setAttr(ev, "counter_freeze", lookup(counterFreezes, value[0]>>6))

	case 104, 107: // test command
		if len(value) >= 2 {
			setAttr(ev, "test_pattern", fmt.Sprintf("0x%04x", binary.LittleEndian.Uint16(value[:2])))
		}

	case 105: // reset process command
		setAttr(ev, "reset_qualifier", lookup(resetQualifiers, value[0]))

	case 106: // delay acquisition command
		if len(value) >= 2 {
			setAttr(ev, "delay_ms", strconv.Itoa(int(binary.LittleEndian.Uint16(value[:2]))))
		}

	case 110, 111: // parameter of measured value, normalised and scaled
		if a.typeID == 110 {
			setNormalised(ev, value)
		} else if len(value) >= 2 {
			setAttr(ev, "value", strconv.Itoa(int(int16(binary.LittleEndian.Uint16(value[:2])))))
		}
		if len(value) > 2 {
			setParameterQualifier(ev, value[2])
		}

	case 112: // parameter of measured value, short floating point
		setFloat(ev, value)
		if len(value) > 4 {
			setParameterQualifier(ev, value[4])
		}

	case 113: // parameter activation
		setAttr(ev, "parameter_activation", lookup(parameterActivations, value[0]&0x03))

	case 120, 121, 122, 123, 124, 125, 126: // file transfer
		setFile(ev, a.typeID, value)
	}
}

// singlePoint renders the single point information bit.
func singlePoint(siq uint8) string {
	return singleCommands[siq&0x01]
}

// stepPosition reads a value with transient state indication: a seven bit
// value in two's complement plus a transient flag (-101, clause 7.2.6.5).
func stepPosition(vti uint8) int8 {
	v := int(vti & 0x7f)
	if v >= 64 {
		v -= 128
	}
	return int8(v)
}

// setQuality records the quality descriptor bits that are not clean. A point
// marked invalid or substituted is a different statement from its value, and
// rules care about the difference.
func setQuality(ev *model.Event, b uint8, overflow bool) {
	var flags []string
	if overflow && b&0x01 != 0 {
		flags = append(flags, "overflow")
	}
	if b&0x10 != 0 {
		flags = append(flags, "blocked")
	}
	if b&0x20 != 0 {
		flags = append(flags, "substituted")
	}
	if b&0x40 != 0 {
		flags = append(flags, "not_topical")
	}
	if b&0x80 != 0 {
		flags = append(flags, "invalid")
	}
	if len(flags) > 0 {
		setAttr(ev, "quality", strings.Join(flags, ","))
	}
}

// setNormalised records a normalised value, a fraction of full scale held as a
// 16 bit two's complement number (-101, clause 7.2.6.6). The raw number is
// kept too: a threshold in a rule is easier to write against it.
func setNormalised(ev *model.Event, value []byte) {
	if len(value) < 2 {
		return
	}
	raw := int16(binary.LittleEndian.Uint16(value[:2]))
	setAttr(ev, "value", strconv.FormatFloat(float64(raw)/32768, 'f', 6, 64))
	setAttr(ev, "value_raw", strconv.Itoa(int(raw)))
}

// setFloat records an IEEE 754 single precision value.
func setFloat(ev *model.Event, value []byte) {
	if len(value) < 4 {
		return
	}
	f := math.Float32frombits(binary.LittleEndian.Uint32(value[:4]))
	if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
		// A set point of NaN is not a measurement, it is a frame worth a look.
		setAttr(ev, "value", "non_finite")
		addAnomaly(ev, "non_finite_value")
		return
	}
	setAttr(ev, "value", strconv.FormatFloat(float64(f), 'g', -1, 32))
}

// setCounter records a binary counter reading: the count, the sequence number
// that pairs a reading with its freeze, and the flags that say whether it can
// be trusted (-101, clause 7.2.6.9).
func setCounter(ev *model.Event, value []byte) {
	if len(value) < 5 {
		return
	}
	setAttr(ev, "value", strconv.FormatInt(int64(int32(binary.LittleEndian.Uint32(value[:4]))), 10))
	flags := value[4]
	setAttr(ev, "counter_seq", strconv.Itoa(int(flags&0x1f)))
	var notes []string
	if flags&0x20 != 0 {
		notes = append(notes, "carry")
	}
	if flags&0x40 != 0 {
		notes = append(notes, "adjusted")
	}
	if flags&0x80 != 0 {
		notes = append(notes, "invalid")
	}
	if len(notes) > 0 {
		setAttr(ev, "quality", strings.Join(notes, ","))
	}
}

// setCommand records a switching command: what it asks for, whether it is the
// select or the execute step, and the output cycle it asks the device to use.
func setCommand(ev *model.Event, b uint8, value string) {
	setAttr(ev, "value", value)
	setAttr(ev, "command_mode", selectExecute(b&0x80 != 0))
	setAttr(ev, "command_qualifier", commandQualifier((b>>2)&0x1f))
}

// setSetPointQualifier records the qualifier of a set point command: the
// select or execute step and the limits on the value.
func setSetPointQualifier(ev *model.Event, qos uint8) {
	setAttr(ev, "command_mode", selectExecute(qos&0x80 != 0))
	if ql := qos & 0x7f; ql != 0 {
		setAttr(ev, "command_qualifier", "ql_"+strconv.Itoa(int(ql)))
	}
}

// setParameterQualifier records the qualifier of a parameter: which parameter
// of the measured value is being loaded, and whether it takes effect
// (-101, clause 7.2.6.24).
func setParameterQualifier(ev *model.Event, qpm uint8) {
	setAttr(ev, "parameter_kind", lookup(parameterKinds, qpm&0x3f))
	if qpm&0x40 != 0 {
		setAttr(ev, "parameter_not_in_operation", "true")
	}
	if qpm&0x80 != 0 {
		setAttr(ev, "parameter_changed", "true")
	}
}

// setFile records the file and section a file transfer ASDU names. Every file
// transfer type opens with the file number; the section number follows it in
// all but the file ready and directory ASDUs (-101, clause 7.3.5).
func setFile(ev *model.Event, id uint8, value []byte) {
	if len(value) < 2 {
		return
	}
	setAttr(ev, "file_number", strconv.Itoa(int(binary.LittleEndian.Uint16(value[:2]))))
	switch id {
	case 121, 122, 123, 124, 125:
		if len(value) > 2 {
			setAttr(ev, "section_number", strconv.Itoa(int(value[2])))
		}
	case 120, 126:
		if len(value) >= 5 {
			setAttr(ev, "file_length", strconv.Itoa(int(readIOA(value[2:5]))))
		}
	}
}

// timeTagLen is the width of the time tag a type carries at the end of its
// information element: seven octets for CP56Time2a, three for CP24Time2a and
// none for the types without one.
func timeTagLen(id uint8) int {
	switch {
	case id >= 30 && id <= 40, id >= 58 && id <= 64, id == 103, id == 107, id == 126:
		return 7
	case id == 2, id == 4, id == 6, id == 8, id == 10, id == 12, id == 14, id == 16,
		id >= 17 && id <= 19:
		return 3
	default:
		return 0
	}
}

// timeAttr names the attribute a type's time tag belongs in. A clock
// synchronisation command's time tag is not when the frame was sent, it is the
// time the master is setting the station's clock to.
func timeAttr(id uint8) string {
	if id == 103 || id == 107 {
		return "clock_time"
	}
	return "object_time"
}

// setTime records a CP56Time2a or CP24Time2a time tag
// (-101, clauses 7.2.6.18 and 7.2.6.19).
//
// The time is always rendered, even when it does not add up, because a wrong
// time tag is evidence: it is reported alongside rather than instead of the
// value. Two things can be wrong with one, and they mean different things. The
// invalid bit is the sender saying its own clock is not to be trusted, which
// matters when time tags are what orders events. A field outside the range the
// standard allows is a sender that encodes time wrongly — a year above 99 is
// the common one, from an implementation writing the year less 1900 — and
// shows up as a date far in the future.
func setTime(ev *model.Event, key string, b []byte) {
	if len(b) < 3 {
		return
	}
	ms := binary.LittleEndian.Uint16(b[:2])
	minute := b[2] & 0x3f
	second, milli := ms/1000, ms%1000
	outOfRange := minute > 59 || second > 59

	if len(b) < 7 {
		// CP24Time2a carries only milliseconds and minutes, so it can only be
		// rendered as a time within an hour; the receiver supplies the rest
		// from its own clock.
		setAttr(ev, key, fmt.Sprintf("%02d:%02d.%03d", minute, second, milli))
	} else {
		hour := b[3] & 0x1f
		day := b[4] & 0x1f
		month := b[5] & 0x0f
		year := b[6] & 0x7f
		outOfRange = outOfRange || hour > 23 || day < 1 || day > 31 ||
			month < 1 || month > 12 || year > 99
		// The year is two digits and the standard leaves the century to the
		// receiver; every deployment of -104 postdates 2000.
		setAttr(ev, key, fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d.%03d",
			2000+int(year), month, day, hour, minute, second, milli))
	}

	if b[2]&0x80 != 0 {
		setAttr(ev, "time_invalid", "true")
	}
	if outOfRange {
		addAnomaly(ev, "time_tag_out_of_range")
	}
}

// lookup names a coded value, falling back to the number for the values the
// standard leaves reserved.
func lookup(table map[uint8]string, v uint8) string {
	if name, ok := table[v]; ok {
		return name
	}
	return "reserved_" + strconv.Itoa(int(v))
}
