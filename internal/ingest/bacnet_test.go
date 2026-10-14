package ingest_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/model"
)

// The BACnet counts below were cross-checked against an independent decode of
// each capture, datagram by datagram.
func TestBACnetCaptureFacts(t *testing.T) {
	root := repoRoot(t)

	t.Run("device_identity", func(t *testing.T) {
		res, events := run(t, filepath.Join(root, "testdata", "pcaps", "bacnet_device_identity.pcap"))
		assert.Equal(t, uint64(26), res.Capture.Packets)
		require.Len(t, events, 22, "22 BACnet datagrams among the 26 packets")

		byOp := map[string]int{}
		for _, e := range events {
			assert.Equal(t, "bacnet", e.Protocol)
			assert.False(t, e.Malformed, e.Error)
			assert.Equal(t, model.TransportUDP, e.Flow.Transport)
			byOp[e.Operation]++
		}
		assert.Equal(t, map[string]int{
			"readProperty":                      18,
			"BVLC-Result":                       2,
			"Read-Broadcast-Distribution-Table": 1,
			"Register-Foreign-Device":           1,
		}, byOp)

		// Nine properties of the device object read one at a time, which is
		// the whole identity of a Johnson Controls automation engine.
		identity := map[string]string{}
		for _, e := range events {
			for k, v := range e.Identity {
				identity[k] = v
			}
		}
		assert.Equal(t, "MS-NAE4510-2", identity["model_name"])
		assert.Equal(t, "5.1.0.4400", identity["firmware_revision"])
		assert.Equal(t, "KBRNAE", identity["device_name"])
		assert.Equal(t, "500", identity["device_instance"])
		assert.Equal(t, "5", identity["vendor_id"])

		// Both of the virtual link layer exchanges are refused, which is a
		// device that will not act as a broadcast relay.
		refusals := 0
		for _, e := range events {
			if e.Exception != "" {
				refusals++
				assert.Contains(t, e.Exception, "NAK")
			}
		}
		assert.Equal(t, 2, refusals)
	})

	t.Run("read_multiple", func(t *testing.T) {
		_, events := run(t, filepath.Join(root, "testdata", "pcaps", "bacnet_read_multiple.pcapng"))
		require.Len(t, events, 2)
		for _, e := range events {
			assert.Equal(t, "readPropertyMultiple", e.Operation)
			assert.Equal(t, model.ClassRead, e.Class)
			assert.Equal(t, "schedule:88", e.Attrs["object"])
			assert.Equal(t, "15", e.Attrs["property_count"])
			assert.False(t, e.Malformed, e.Error)
		}
		assert.Equal(t, model.DirRequest, events[0].Direction)
		assert.Equal(t, model.DirResponse, events[1].Direction,
			"both ports are 47808 in BACnet, so the APDU type is what says which is which")
	})

	t.Run("schedule_property", func(t *testing.T) {
		_, events := run(t, filepath.Join(root, "testdata", "pcaps", "bacnet_schedule_property.pcapng"))
		require.Len(t, events, 2)
		for _, e := range events {
			assert.Equal(t, "readPropertyMultiple", e.Operation)
			assert.Equal(t, model.DirResponse, e.Direction)
			assert.Contains(t, e.Attrs["properties"], "exception-schedule")
			assert.False(t, e.Malformed, e.Error)
		}
	})
}
