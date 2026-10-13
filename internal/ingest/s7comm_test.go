package ingest_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/model"
)

// The S7comm counts below were cross-checked against an independent decode of
// each capture. Every COTP frame is accounted for: the difference between
// frames seen and events produced is the empty keep-alive frames, which carry
// no operation and so yield nothing.
func TestS7CommCaptureFacts(t *testing.T) {
	root := repoRoot(t)

	tests := []struct {
		name       string
		file       string
		wantEvents uint64
		wantOps    map[string]int
	}{
		{
			name:       "variable services",
			file:       "s7comm_varservice_libnodavedemo",
			wantEvents: 18, // 1 connection request, 1 confirm, 16 S7 PDUs
			wantOps: map[string]int{
				"ConnectionRequest":   1,
				"ConnectionConfirm":   1,
				"SETUP_COMMUNICATION": 2,
				"READ_VAR":            6,
				"WRITE_VAR":           8,
			},
		},
		{
			name:       "block download",
			file:       "s7comm_downloading_block_db1",
			wantEvents: 54, // 3 connects, 3 confirms, 48 S7 PDUs; 24 keep-alives yield nothing
			wantOps: map[string]int{
				"ConnectionRequest": 3,
				"ConnectionConfirm": 3,
				"REQUEST_DOWNLOAD":  2,
				"DOWNLOAD_BLOCK":    6,
				"DOWNLOAD_ENDED":    2,
				"PLC_CONTROL":       2,
			},
		},
		{
			name:       "plc status reads",
			file:       "s7comm_reading_plc_status",
			wantEvents: 146, // 1 connect, 1 confirm, 144 S7 PDUs; 72 keep-alives yield nothing
			wantOps: map[string]int{
				"ConnectionRequest":   1,
				"ConnectionConfirm":   1,
				"SETUP_COMMUNICATION": 2,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, events := run(t, filepath.Join(root, "testdata", "pcaps", tc.file+".pcap"))

			byOperation := map[string]int{}
			for _, e := range events {
				assert.Equal(t, "s7comm", e.Protocol)
				assert.True(t, e.Class.Valid(), "class %q", e.Class)
				assert.NotEmpty(t, e.Operation)
				byOperation[e.Operation]++
			}

			assert.Equal(t, tc.wantEvents, res.Events)
			for op, want := range tc.wantOps {
				assert.Equal(t, want, byOperation[op], "operation %q", op)
			}
			assert.Zero(t, res.Malformed, "these captures are clean")
		})
	}
}

// The SZL reads are what make an S7 CPU identify itself, which is why
// CLAUDE.md names them as the enrichment source for model and firmware.
func TestS7CommIdentifiesTheCPU(t *testing.T) {
	root := repoRoot(t)
	_, events := run(t, filepath.Join(root, "testdata", "pcaps", "s7comm_reading_plc_status.pcap"))

	identity := map[string]string{}
	szlReads := 0
	for _, e := range events {
		if e.Operation == "ReadSZL" {
			szlReads++
			assert.Equal(t, model.ClassDiscovery, e.Class)
		}
		for k, v := range e.Identity {
			identity[k] = v
		}
	}

	require.Positive(t, szlReads)
	assert.Equal(t, "IM151-8 PN/DP CPU", identity["model"])
	assert.Equal(t, "6ES7 151-8AB01-0AB0", identity["order_number"])
	assert.Equal(t, "S C-C6TW74882012", identity["serial_number"])
	assert.Equal(t, "V3.2.6", identity["firmware_revision"])
	assert.Equal(t, "IM151-8-CPU", identity["plc_name"])
	assert.Equal(t, "Siemens", identity["vendor_name"])
	// The ISO connection confirm says which rack and slot answered.
	assert.Equal(t, "0", identity["rack"])
	assert.Equal(t, "2", identity["slot"])
}

// Downloading a block is a program change, and the event says which block.
func TestS7CommBlockDownloadIsProgramClass(t *testing.T) {
	root := repoRoot(t)
	_, events := run(t, filepath.Join(root, "testdata", "pcaps", "s7comm_downloading_block_db1.pcap"))

	var program, named, activated int
	for _, e := range events {
		switch e.Operation {
		case "REQUEST_DOWNLOAD", "DOWNLOAD_BLOCK", "DOWNLOAD_ENDED":
			program++
			assert.Equal(t, model.ClassProgram, e.Class)
			// Only the request names the block; the reply is an
			// acknowledgement with a status and nothing else.
			if e.Direction == model.DirRequest {
				named++
				assert.Equal(t, "DB", e.Attrs["block_type"])
				assert.Equal(t, "1", e.Attrs["block_number"])
			} else {
				assert.Empty(t, e.Attrs["block_type"])
			}
		case "PLC_CONTROL":
			if e.Attrs["pi_service"] == "_INSE" {
				activated++
				assert.Equal(t, model.ClassProgram, e.Class,
					"activating a downloaded block changes the program")
			}
		}
	}

	assert.Equal(t, 10, program, "a request, six blocks and an end, request and reply each")
	assert.Equal(t, 5, named, "each request names DB1")
	assert.Equal(t, 1, activated)
}
