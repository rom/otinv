package ingest_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/model"
)

// The MMS counts below were cross-checked against an independent decode of
// each capture, PDU by PDU, through all five layers of the stack.
func TestMMSCaptureFacts(t *testing.T) {
	root := repoRoot(t)

	tests := []struct {
		name          string
		file          string
		wantEvents    uint64
		wantMalformed uint64
		wantStreams   uint64
		wantBound     uint64
		wantOps       map[string]int
	}{
		{
			name: "substation reports",
			file: "iec61850_mms_reports",
			// 36 MMS PDUs, two association release PDUs that carry no MMS of
			// their own, and the transport connection of the one association
			// the capture records in full.
			wantEvents:  40,
			wantStreams: 21,
			// The other sixteen streams are the file sharing traffic the
			// capture also holds, which nothing here claims.
			wantBound: 5,
			wantOps: map[string]int{
				"informationReport":           28,
				"read":                        2,
				"getVariableAccessAttributes": 1,
				"confirmed-Error":             1,
				"initiate-Request":            1,
				"initiate-Response":           1,
				"conclude-Request":            1,
				"conclude-Response":           1,
				"RLRQ":                        1,
				"RLRE":                        1,
				"ConnectionRequest":           1,
				"ConnectionConfirm":           1,
			},
		},
		{
			name:        "a device identifying itself",
			file:        "iec61850_mms_identify",
			wantEvents:  5,
			wantStreams: 1,
			wantBound:   1,
			wantOps: map[string]int{
				"initiate-Request":  1,
				"initiate-Response": 1,
				"identify":          2,
				"status":            1,
			},
		},
		{
			name:        "a write to a nameplate",
			file:        "iec61850_mms_write",
			wantEvents:  13,
			wantStreams: 4,
			wantBound:   2,
			wantOps: map[string]int{
				"write":              2,
				"initiate-Request":   1,
				"initiate-Response":  2,
				"conclude-Request":   2,
				"confirmed-Response": 4,
				"ConnectionRequest":  1,
				"ConnectionConfirm":  1,
			},
		},
		{
			name: "stopping and starting a program invocation",
			file: "iec61850_mms_program_control",
			// The client's frames are well formed; every one of the server's
			// declares a TPKT length that counts only its own header, so each
			// is reported as a framing failure and skipped.
			wantEvents:    10,
			wantMalformed: 5,
			wantStreams:   1,
			wantBound:     1,
			wantOps: map[string]int{
				"stop":              1,
				"start":             1,
				"initiate-Request":  1,
				"conclude-Request":  1,
				"ConnectionRequest": 1,
				"FramingError":      4,
				"COTP":              1,
			},
		},
		{
			name:          "opening a download into a domain",
			file:          "iec61850_mms_download",
			wantEvents:    10,
			wantMalformed: 5,
			wantStreams:   1,
			wantBound:     1,
			wantOps: map[string]int{
				"takeControl":              1,
				"initiateDownloadSequence": 1,
				"initiate-Request":         1,
				"conclude-Request":         1,
				"ConnectionRequest":        1,
				"FramingError":             4,
				"COTP":                     1,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, events := run(t, filepath.Join(root, "testdata", "pcaps", tc.file+".pcap"))

			byOperation := map[string]int{}
			for _, e := range events {
				assert.Equal(t, "mms", e.Protocol)
				assert.True(t, e.Class.Valid(), "class %q", e.Class)
				assert.NotEmpty(t, e.Operation)
				byOperation[e.Operation]++
			}

			assert.Equal(t, tc.wantEvents, res.Events)
			assert.Equal(t, tc.wantMalformed, res.Malformed)
			assert.Equal(t, tc.wantStreams, res.TCPStreams)
			assert.Equal(t, tc.wantBound, res.BoundStreams)
			assert.Equal(t, tc.wantOps, byOperation)
		})
	}
}

// Port 102 carries S7comm and MMS alike, and both open with the same COTP
// connection request. Binding a stream from that request would put a Siemens
// rack and slot on a substation IED, so neither dissector may claim a stream
// before something above the transport has shown itself.
func TestPort102IsNotClaimedFromTheConnectionRequest(t *testing.T) {
	root := repoRoot(t)

	for _, tc := range []struct {
		file string
		want string
	}{
		{"iec61850_mms_reports", "mms"},
		{"iec61850_mms_write", "mms"},
		{"s7comm_varservice_libnodavedemo", "s7comm"},
		{"s7comm_reading_plc_status", "s7comm"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			_, events := run(t, filepath.Join(root, "testdata", "pcaps", tc.file+".pcap"))
			require.NotEmpty(t, events)
			for _, e := range events {
				assert.Equal(t, tc.want, e.Protocol,
					"packet %d decoded as the wrong protocol on port 102", e.PacketIndex)
			}
		})
	}
}

// A frame held back while the stream's protocol was still undecided still
// belongs to the packet it travelled in. That packet is the evidence a
// finding points at, and it is not the one that happened to settle the
// binding.
func TestDeferredFramesKeepTheirOwnPacket(t *testing.T) {
	root := repoRoot(t)
	_, events := run(t, filepath.Join(root, "testdata", "pcaps", "iec61850_mms_reports.pcap"))

	byOperation := map[string]model.Event{}
	for _, e := range events {
		if _, seen := byOperation[e.Operation]; !seen {
			byOperation[e.Operation] = e
		}
	}

	request, ok := byOperation["ConnectionRequest"]
	require.True(t, ok)
	assert.Equal(t, uint64(107), request.PacketIndex,
		"the connection request was held until the association proved the protocol")
	confirm, ok := byOperation["ConnectionConfirm"]
	require.True(t, ok)
	assert.Equal(t, uint64(109), confirm.PacketIndex)
	assert.True(t, request.Timestamp.Before(confirm.Timestamp))
}

// A report is pushed without being asked for, and the reference it carries
// names the logical device the substation configuration gave the IED. That
// makes report traffic alone enough to inventory a substation.
func TestReportsNameTheirLogicalDevice(t *testing.T) {
	root := repoRoot(t)
	_, events := run(t, filepath.Join(root, "testdata", "pcaps", "iec61850_mms_reports.pcap"))

	devices := map[string]bool{}
	reports := 0
	for _, e := range events {
		if e.Operation != "informationReport" {
			continue
		}
		reports++
		assert.Equal(t, model.ClassRead, e.Class)
		assert.Equal(t, model.DirResponse, e.Direction, "nobody asked for this one")
		assert.NotEmpty(t, e.Attrs["report_id"])
		if d := e.Identity["logical_device"]; d != "" {
			devices[d] = true
		}
	}

	assert.Equal(t, 28, reports)
	assert.Equal(t, map[string]bool{
		"AA1C1Q01A1LD0":    true,
		"AA1C1Q01FP1LD0":   true,
		"AA1C1Q01FP2LD0":   true,
		"AA1QBQBBFP1ABB05": true,
	}, devices, "four logical devices push reports; a fifth is named by the read")
}

// Identify is the MMS enrichment source, the way Read Device Identification
// is for Modbus and an SZL read is for S7.
func TestMMSIdentifiesTheDevice(t *testing.T) {
	root := repoRoot(t)
	_, events := run(t, filepath.Join(root, "testdata", "pcaps", "iec61850_mms_identify.pcap"))

	identity := map[string]string{}
	for _, e := range events {
		for k, v := range e.Identity {
			identity[k] = v
		}
	}
	assert.Equal(t, map[string]string{
		"vendor_name": "INFO TECH",
		"model_name":  "S61850 for PC",
		"revision":    "0.0.1",
	}, identity)
}

// Program control and domain download are what CLAUDE.md's S7 rules name, and
// MMS has the same operations under different names.
func TestMMSProgramOperationsAreClassified(t *testing.T) {
	root := repoRoot(t)

	control, events := run(t, filepath.Join(root, "testdata", "pcaps", "iec61850_mms_program_control.pcap"))
	require.NotZero(t, control.Events)
	invocations := map[string]model.Classification{}
	for _, e := range events {
		if e.Operation == "start" || e.Operation == "stop" {
			invocations[e.Operation] = e.Class
			assert.Equal(t, "R395024397Application_1", e.Attrs["object"],
				"a control operation names the program invocation it acts on")
		}
	}
	assert.Equal(t, map[string]model.Classification{
		"start": model.ClassControl,
		"stop":  model.ClassControl,
	}, invocations)

	_, events = run(t, filepath.Join(root, "testdata", "pcaps", "iec61850_mms_download.pcap"))
	var found bool
	for _, e := range events {
		if e.Operation != "initiateDownloadSequence" {
			continue
		}
		found = true
		assert.Equal(t, model.ClassProgram, e.Class)
		assert.Equal(t, "DTLogFilesDomain", e.Attrs["object"])
		assert.Equal(t, "DTLogFilesDomain", e.Identity["logical_device"])
	}
	assert.True(t, found, "the capture opens a download")
}

// A server refusing a client is the association and service layers' only
// verdict, and it is what an analyst looks for first.
func TestMMSRefusalIsRecorded(t *testing.T) {
	root := repoRoot(t)
	_, events := run(t, filepath.Join(root, "testdata", "pcaps", "iec61850_mms_reports.pcap"))

	var denied *model.Event
	for i := range events {
		if events[i].Exception != "" {
			denied = &events[i]
		}
	}
	require.NotNil(t, denied, "the capture holds one refused request")
	assert.Equal(t, "confirmed-Error", denied.Operation)
	assert.Equal(t, "access/object-access-denied", denied.Exception)
	assert.NotZero(t, denied.PacketIndex)
	require.NotNil(t, denied.TransactionID)
	assert.Equal(t, uint32(303731), *denied.TransactionID)
}
