package ingest_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/model"
)

// The GOOSE counts below were cross-checked against an independent decode of
// each capture, frame by frame.
func TestGooseCaptureFacts(t *testing.T) {
	root := repoRoot(t)

	tests := []struct {
		name       string
		file       string
		wantFrames uint64
		wantOps    map[string]int
		wantDevice map[string]int
	}{
		{
			name: "bay interlocking",
			file: "iec61850_goose_interlocking",
			// Every frame in the capture is GOOSE, and every one decodes.
			wantFrames: 451,
			wantOps: map[string]int{
				"StateChange":    252,
				"Retransmission": 199,
			},
			wantDevice: map[string]int{
				"AA1C1Q01A1LD0": 120,
				"AA1C1Q05A1LD0": 167,
				"AA1C1Q07A1LD0": 164,
			},
		},
		{
			name:       "a GE relay",
			file:       "iec61850_goose_ge_relay",
			wantFrames: 8,
			// The capture holds two bursts of the same control block with the
			// state number unchanged, so none of its frames reports a change.
			wantOps:    map[string]int{"Retransmission": 8},
			wantDevice: map[string]int{"GEDeviceF650": 8},
		},
		{
			name:       "one frame, references that are not object names",
			file:       "iec61850_goose_minimal",
			wantFrames: 1,
			wantOps:    map[string]int{"Retransmission": 1},
			wantDevice: map[string]int{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, events := run(t, filepath.Join(root, "testdata", "pcaps", tc.file+".pcap"))

			byOperation := map[string]int{}
			byDevice := map[string]int{}
			for _, e := range events {
				assert.Equal(t, "goose", e.Protocol)
				assert.Equal(t, model.ClassRead, e.Class)
				assert.Equal(t, model.DirResponse, e.Direction)
				assert.Equal(t, -1, e.FunctionCode)
				assert.False(t, e.Malformed, "packet %d: %s", e.PacketIndex, e.Error)
				byOperation[e.Operation]++
				if d := e.Identity["logical_device"]; d != "" {
					byDevice[d]++
				}
			}

			assert.Equal(t, tc.wantFrames, res.L2Frames,
				"every frame is handed to a dissector by its EtherType")
			assert.Equal(t, tc.wantFrames, res.Events)
			assert.Zero(t, res.Malformed)
			assert.Zero(t, res.NonIP, "the captures hold nothing but GOOSE")
			assert.Zero(t, res.TCPStreams, "GOOSE has no transport layer at all")
			assert.Equal(t, tc.wantOps, byOperation)
			assert.Equal(t, tc.wantDevice, byDevice)
		})
	}
}

// A sequence number that goes backwards without the state changing is a
// repeat of something already published, which is the shape a replayed frame
// takes. The GE capture holds one, in real traffic rather than crafted.
func TestGooseSequenceRegressionInRealTraffic(t *testing.T) {
	root := repoRoot(t)
	_, events := run(t, filepath.Join(root, "testdata", "pcaps", "iec61850_goose_ge_relay.pcap"))

	var found []model.Event
	for _, e := range events {
		if e.Attrs["anomaly"] != "" {
			found = append(found, e)
		}
	}
	require.Len(t, found, 1, "exactly one frame in the capture goes backwards")
	assert.Equal(t, "sq_num_regression", found[0].Attrs["anomaly"])
	assert.Equal(t, "1", found[0].Attrs["st_num"])
	assert.Equal(t, "1", found[0].Attrs["sq_num"])
	assert.Equal(t, "12", found[0].Attrs["previous_sq_num"])
	assert.NotZero(t, found[0].PacketIndex, "a finding needs the packet it came from")
}

// The state numbers of each publisher are tracked separately, so one
// publisher's counter cannot make another's look like it jumped.
func TestGooseCountersAreTrackedPerPublisher(t *testing.T) {
	root := repoRoot(t)
	_, events := run(t, filepath.Join(root, "testdata", "pcaps", "iec61850_goose_interlocking.pcap"))

	require.NotEmpty(t, events)
	for _, e := range events {
		assert.NotContains(t, e.Attrs, "anomaly",
			"three publishers interleave on one segment and none of them skips")
	}
}

// A multicast destination names a subscription, not a machine. GOOSE and
// Sampled Values publish to one, and an inventory that listed those as assets
// would invent a device for every data set a substation publishes.
func TestGooseMulticastDestinationIsNotAnAsset(t *testing.T) {
	root := repoRoot(t)
	_, events := run(t, filepath.Join(root, "testdata", "pcaps", "iec61850_goose_interlocking.pcap"))

	require.NotEmpty(t, events)
	for _, e := range events {
		assert.Equal(t, "01:0c:cd:01:00:00", e.Flow.DstMAC,
			"the frame keeps the address it was sent to")
		assert.Empty(t, e.Flow.SrcIP, "GOOSE carries no IP layer")
		assert.Equal(t, model.TransportEthernet, e.Flow.Transport)
	}
}

// One capture holds both halves of IEC 61850, and they name the same devices:
// the MMS reports of a logical device and the GOOSE publications of the same
// one, from the same MAC address.
func TestGooseAndMMSAgreeOnTheDevice(t *testing.T) {
	root := repoRoot(t)
	res, events := run(t, filepath.Join(root, "testdata", "pcaps", "iec61850_mms_reports.pcap"))

	byProtocol := map[string]int{}
	devicesByMAC := map[string]map[string]bool{}
	for _, e := range events {
		byProtocol[e.Protocol]++
		device := e.Identity["logical_device"]
		if device == "" {
			continue
		}
		mac := e.Flow.SrcMAC
		if e.Protocol == "mms" && e.Direction == model.DirRequest {
			// A client naming a device is evidence about the server it is
			// addressing, not about itself.
			mac = e.Flow.DstMAC
		}
		if devicesByMAC[mac] == nil {
			devicesByMAC[mac] = map[string]bool{}
		}
		devicesByMAC[mac][device] = true
	}

	assert.Equal(t, map[string]int{"mms": 40, "goose": 34}, byProtocol)
	assert.Equal(t, uint64(34), res.L2Frames)
	assert.Equal(t, map[string]bool{"AA1C1Q01A1LD0": true}, devicesByMAC["00:00:23:06:30:fe"],
		"the IED's MMS reports and its GOOSE publications name the same logical device")
}
