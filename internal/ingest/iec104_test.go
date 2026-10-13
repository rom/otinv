package ingest_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/model"
)

// The IEC 104 counts below were cross-checked against an independent decode of
// each capture, APDU by APDU.
func TestIec104CaptureFacts(t *testing.T) {
	root := repoRoot(t)

	tests := []struct {
		name          string
		file          string
		wantEvents    uint64
		wantMalformed uint64
		wantOps       map[string]int
		wantCauses    map[string]int
	}{
		{
			name: "dissector test traffic",
			file: "iec104_test_dissect",
			// 57 APDUs across six connections, plus one framing error for
			// each of the 17 payloads of filler the capture injects between
			// them.
			wantEvents:    74,
			wantMalformed: 17,
			wantOps: map[string]int{
				"STARTDT_act":  6,
				"STARTDT_con":  6,
				"TESTFR_act":   7,
				"TESTFR_con":   7,
				"SUPERVISORY":  12,
				"M_EI_NA_1":    2,
				"C_IC_NA_1":    3,
				"M_SP_NA_1":    1,
				"M_DP_NA_1":    1,
				"M_SP_TB_1":    1,
				"C_SC_NA_1":    7,
				"C_DC_NA_1":    2,
				"C_CS_NA_1":    2,
				"FramingError": 17,
			},
			wantCauses: map[string]int{
				"activation":              7,
				"activation_confirmation": 6,
				"activation_termination":  1,
				"initialized":             2,
				"interrogated_by_station": 2,
				"spontaneous":             1,
			},
		},
		{
			name:       "the command family",
			file:       "iec104_diverse_commands",
			wantEvents: 86,
			wantOps: map[string]int{
				"TESTFR_act":  2,
				"TESTFR_con":  2,
				"SUPERVISORY": 10,
				"C_SC_NA_1":   5,
				"C_SC_TA_1":   5,
				"C_DC_NA_1":   6,
				"C_DC_TA_1":   10,
				"C_SE_NC_1":   10,
				"C_SE_TA_1":   5,
				"C_SE_TC_1":   5,
				"C_IC_NA_1":   3,
				"M_ME_NC_1":   14,
				"M_SP_NA_1":   1,
				"M_SP_TB_1":   8,
			},
			wantCauses: map[string]int{
				"activation":              19,
				"activation_confirmation": 19,
				"activation_termination":  11,
				"interrogated_by_station": 2,
				"periodic":                3,
				"spontaneous":             18,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, events := run(t, filepath.Join(root, "testdata", "pcaps", tc.file+".pcap"))

			byOperation := map[string]int{}
			byCause := map[string]int{}
			for _, e := range events {
				assert.Equal(t, "iec104", e.Protocol)
				assert.True(t, e.Class.Valid(), "class %q", e.Class)
				assert.NotEmpty(t, e.Operation)
				byOperation[e.Operation]++
				if c := e.Attrs["cause"]; c != "" {
					byCause[c]++
				}
			}

			assert.Equal(t, tc.wantEvents, res.Events)
			assert.Equal(t, tc.wantMalformed, res.Malformed)
			assert.Equal(t, tc.wantOps, byOperation)
			assert.Equal(t, tc.wantCauses, byCause)
		})
	}
}

// CLAUDE.md's rule on IEC 104 control commands from unexpected sources needs
// two things from the dissector: the command family classified as control, and
// an unambiguous source. Both come out of this capture.
func TestIec104CommandsAreControlOperations(t *testing.T) {
	root := repoRoot(t)
	_, events := run(t, filepath.Join(root, "testdata", "pcaps", "iec104_diverse_commands.pcap"))

	commands := 0
	selects, executes := 0, 0
	for _, e := range events {
		if e.Class != model.ClassControl {
			continue
		}
		commands++
		require.NotNil(t, e.UnitID, "a command names the station it is for")
		assert.Equal(t, uint16(3), *e.UnitID)
		require.NotNil(t, e.Address, "a command names the point it operates")
		switch e.Attrs["command_mode"] {
		case "select":
			selects++
		case "execute":
			executes++
		default:
			t.Errorf("command %s at packet %d has no select or execute step",
				e.Operation, e.PacketIndex)
		}
	}

	assert.Equal(t, 46, commands)
	// Ten commands are issued. Eight of them are the two step kind: the
	// control centre selects the point, the station confirms the selection,
	// the centre executes, and the station confirms and then terminates the
	// execution. That is two selecting ASDUs and three executing ones each.
	// The other two are direct commands, which skip the selection and so
	// carry three executing ASDUs and none selecting.
	assert.Equal(t, 8*2, selects)
	assert.Equal(t, 8*3+2*3, executes)
}

// A command carries the address of the point it switches, which is the
// evidence a finding has to be able to link to.
func TestIec104CommandCarriesItsPoint(t *testing.T) {
	root := repoRoot(t)
	_, events := run(t, filepath.Join(root, "testdata", "pcaps", "iec104_test_dissect.pcap"))

	var found bool
	for _, e := range events {
		if e.Operation != "C_SC_NA_1" || e.Attrs["cause"] != "activation" {
			continue
		}
		found = true
		assert.Equal(t, model.ClassControl, e.Class)
		assert.Equal(t, model.DirRequest, e.Direction)
		require.NotNil(t, e.Address)
		assert.Contains(t, []uint32{10010, 22222, 33333}, *e.Address)
		assert.NotEmpty(t, e.Attrs["value"])
		assert.NotZero(t, e.PacketIndex, "a finding needs the packet it came from")
		assert.False(t, e.Timestamp.IsZero())
	}
	assert.True(t, found, "the capture issues single commands")
}

// The clock synchronisation command writes to the station, and the time it
// writes is the part worth seeing.
func TestIec104ClockSyncIsAWrite(t *testing.T) {
	root := repoRoot(t)
	_, events := run(t, filepath.Join(root, "testdata", "pcaps", "iec104_test_dissect.pcap"))

	times := []string{}
	for _, e := range events {
		if e.Operation == "C_CS_NA_1" {
			assert.Equal(t, model.ClassWrite, e.Class)
			times = append(times, e.Attrs["clock_time"])
		}
	}
	assert.Equal(t, []string{"2008-08-29T08:57:13.000", "2008-08-29T08:57:13.000"}, times,
		"the activation and its confirmation carry the same time")
}

// The capture pads its APDUs with filler bytes. Each payload of filler has to
// be reported once and then skipped, without taking the frames around it with
// it or inventing frames out of the filler.
func TestIec104FillerIsReportedAndSkipped(t *testing.T) {
	root := repoRoot(t)
	res, events := run(t, filepath.Join(root, "testdata", "pcaps", "iec104_test_dissect.pcap"))

	framingErrors := 0
	for _, e := range events {
		if e.Operation == "FramingError" {
			framingErrors++
			assert.True(t, e.Malformed)
			assert.NotEmpty(t, e.Error)
		}
	}
	assert.Equal(t, 17, framingErrors)
	assert.Equal(t, uint64(17), res.Resyncs)
	assert.Zero(t, res.AbandonedSides, "filler must not cost us the rest of a stream")
	assert.Equal(t, uint64(6), res.BoundStreams)
}
