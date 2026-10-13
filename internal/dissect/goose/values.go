package goose

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/rom/otinv/internal/dissect/ber"
	"github.com/rom/otinv/internal/model"
)

// Rendering of a GOOSE data set and of the timestamp that says when the state
// it reports last changed.

// Data CHOICE tags, shared with MMS (ISO 9506-2). A GOOSE data set is usually
// pairs of a value and its quality, so booleans and bit strings carry most of
// what a substation publishes.
const (
	dataArray         = 1
	dataStructure     = 2
	dataBoolean       = 3
	dataBitString     = 4
	dataInteger       = 5
	dataUnsigned      = 6
	dataFloatingPoint = 7
	dataOctetString   = 9
	dataVisibleString = 10
	dataBinaryTime    = 12
	dataBCD           = 13
	dataBooleanArray  = 14
	dataObjID         = 15
	dataMMSString     = 16
	dataUTCTime       = 17
)

var dataNames = map[uint32]string{
	dataArray:         "array",
	dataStructure:     "structure",
	dataBoolean:       "boolean",
	dataBitString:     "bit-string",
	dataInteger:       "integer",
	dataUnsigned:      "unsigned",
	dataFloatingPoint: "float",
	dataOctetString:   "octet-string",
	dataVisibleString: "visible-string",
	dataBinaryTime:    "binary-time",
	dataBCD:           "bcd",
	dataBooleanArray:  "boolean-array",
	dataObjID:         "objid",
	dataMMSString:     "mms-string",
	dataUTCTime:       "utc-time",
}

const (
	// maxRenderedValues caps how many data set entries one event spells out.
	// A substation interlocking data set holds dozens; the first few say what
	// kind of data this is, and the flow view holds the frame.
	maxRenderedValues = 8

	// maxRenderedLen caps the rendered string, so that a data set of long
	// strings cannot put a kilobyte of text into an event.
	maxRenderedLen = 160
)

// renderValues spells out the start of a data set and reports how many entries
// it actually holds.
func renderValues(allData ber.TLV, bud *ber.Budget) (rendered string, count int, truncated bool) {
	entries, complete := allData.Descend(bud)
	count = len(entries)

	var parts []string
	total := 0
	for i, e := range entries {
		if i >= maxRenderedValues || total >= maxRenderedLen {
			truncated = true
			break
		}
		s := renderValue(e, bud)
		total += len(s) + 1
		parts = append(parts, s)
	}
	if !complete {
		truncated = true
	}
	return strings.Join(parts, ","), count, truncated
}

// renderValue spells out one data set entry.
func renderValue(t ber.TLV, bud *ber.Budget) string {
	if t.Class != ber.ClassContext {
		return t.Tag()
	}
	switch t.Number {
	case dataBoolean:
		return strconv.FormatBool(isTrue(t))

	case dataBitString, dataBooleanArray:
		// The first octet counts the unused bits of the last one, which is
		// how IEC 61850 packs a quality descriptor into two octets.
		if len(t.Value) < 2 {
			return "0x"
		}
		return "0x" + fmt.Sprintf("%x", t.Value[1:])

	case dataInteger, dataUnsigned:
		if v, ok := t.Integer(); ok {
			return strconv.FormatInt(v, 10)
		}

	case dataFloatingPoint:
		if s, ok := floatValue(t.Value); ok {
			return s
		}

	case dataVisibleString, dataMMSString:
		if s, ok := t.Text(); ok {
			return s
		}

	case dataUTCTime:
		if s, _, ok := utcTime(t.Value); ok {
			return s
		}

	case dataStructure, dataArray:
		kids, _ := t.Descend(bud)
		return dataNames[t.Number] + "[" + strconv.Itoa(len(kids)) + "]"
	}

	if name, ok := dataNames[t.Number]; ok {
		return name
	}
	return t.Tag()
}

// floatValue reads an MMS floating point value, whose first octet is the width
// of the exponent and the rest the IEEE 754 number (ISO 9506-2).
func floatValue(v []byte) (string, bool) {
	if len(v) < 1 {
		return "", false
	}
	switch bits := v[1:]; len(bits) {
	case 4:
		f := math.Float32frombits(binary.BigEndian.Uint32(bits))
		if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
			return "non_finite", true
		}
		return strconv.FormatFloat(float64(f), 'g', -1, 32), true
	case 8:
		f := math.Float64frombits(binary.BigEndian.Uint64(bits))
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return "non_finite", true
		}
		return strconv.FormatFloat(f, 'g', -1, 64), true
	default:
		return "", false
	}
}

// Time quality bits of an MMS UtcTime (IEC 61850-8-1, clause 8.1.3.7).
const (
	qualityLeapSecondsKnown = 0x80
	qualityClockFailure     = 0x40
	qualityClockUnsynced    = 0x20
	qualityAccuracyMask     = 0x1f

	// accuracyUnspecified is the value a device sends when it will not say
	// how good its clock is.
	accuracyUnspecified = 31
)

// utcTime renders an eight octet UtcTime: four octets of seconds since the
// epoch, three of binary fraction and one of quality.
func utcTime(v []byte) (text string, quality uint8, ok bool) {
	if len(v) != 8 {
		return "", 0, false
	}
	secs := int64(binary.BigEndian.Uint32(v[0:4]))
	frac := uint32(v[4])<<16 | uint32(v[5])<<8 | uint32(v[6])
	// The fraction is a binary fraction of a second, so a nanosecond count is
	// the fraction over two to the twenty-fourth.
	nanos := int64(frac) * 1e9 >> 24
	t := time.Unix(secs, nanos).UTC()
	return t.Format("2006-01-02T15:04:05.000Z07:00"), v[7], true
}

// setTime records the timestamp of the last state change and what the
// publisher said about its own clock.
//
// A GOOSE timestamp is not when the frame was sent: it is when the state it
// reports changed, which is what orders protection events across a
// substation. A publisher that admits its clock is unsynchronised is saying
// that ordering cannot be trusted, which matters more than the time itself.
func setTime(ev *model.Event, t ber.TLV) {
	text, quality, ok := utcTime(t.Value)
	if !ok {
		setAttr(ev, "t", "invalid")
		addAnomaly(ev, "invalid_timestamp")
		return
	}
	setAttr(ev, "t", text)

	var flags []string
	if quality&qualityLeapSecondsKnown != 0 {
		flags = append(flags, "leap_seconds_known")
	}
	if quality&qualityClockFailure != 0 {
		flags = append(flags, "clock_failure")
	}
	if quality&qualityClockUnsynced != 0 {
		flags = append(flags, "clock_not_synchronised")
	}
	if accuracy := quality & qualityAccuracyMask; accuracy == accuracyUnspecified {
		flags = append(flags, "accuracy_unspecified")
	} else {
		flags = append(flags, "accuracy_"+strconv.Itoa(int(accuracy))+"_bits")
	}
	setAttr(ev, "time_quality", strings.Join(flags, ","))
	if quality&qualityClockFailure != 0 {
		// A clock that has failed is a fault in this frame's publisher. An
		// unsynchronised clock is a standing condition of the installation
		// rather than something wrong with the frame, and substations run
		// that way for weeks, so it stays in the attribute for a rule to
		// report once per asset instead of being flagged on every message.
		addAnomaly(ev, "publisher_clock_failure")
	}
}
