package ingest_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/model"
)

// The PROFINET DCP counts below were cross-checked against an independent
// decode of each capture, frame by frame.
func TestProfinetDCPCaptureFacts(t *testing.T) {
	root := repoRoot(t)

	t.Run("change_ip", func(t *testing.T) {
		res, events := run(t, filepath.Join(root, "testdata", "pcaps", "profinet_dcp_change_ip.pcap"))
		// Six packets: four DCP frames and the two ARP probes the station
		// sends to check its new address is free, which nothing claims.
		assert.Equal(t, uint64(6), res.Capture.Packets)
		require.Len(t, events, 4)

		byOp := map[string]int{}
		for _, e := range events {
			assert.Equal(t, "profinet_dcp", e.Protocol)
			assert.False(t, e.Malformed, e.Error)
			assert.Equal(t, model.TransportEthernet, e.Flow.Transport)
			byOp[e.Operation]++
		}
		assert.Equal(t, map[string]int{"Identify": 2, "Set": 2}, byOp)

		// The identify answer is the one frame that describes the station.
		identity := events[1].Identity
		assert.Equal(t, "X208-BORD", identity["station_name"])
		assert.Equal(t, "42", identity["vendor_id"])
		assert.Equal(t, "Siemens", identity["vendor_name"])
		assert.Equal(t, "io_device", identity["device_role"])
		assert.Equal(t, "192.168.0.6", identity["reported_address"])

		// The Set gives it a different address, and the station accepts.
		assert.Equal(t, model.ClassWrite, events[2].Class)
		assert.Equal(t, "192.168.0.10", events[2].Attrs["ip_address"])
		assert.Equal(t, "IPParameter", events[3].Attrs["acked_block"])
		assert.Equal(t, "Ok", events[3].Attrs["block_result"])
	})

	t.Run("crafted_name", func(t *testing.T) {
		_, events := run(t, filepath.Join(root, "testdata", "pcaps", "profinet_dcp_crafted_name.pcap"))
		require.Len(t, events, 4)
		assert.Equal(t, "%n%n%n ", events[1].Attrs["name_of_station"])
		assert.Contains(t, events[1].Attrs["anomaly"], "name_of_station_not_printable")
		assert.Equal(t, "io_controller", events[1].Identity["device_role"])
		assert.Equal(t, "S7-300EC", events[1].Identity["model"])
	})

	t.Run("identify_scan", func(t *testing.T) {
		_, events := run(t, filepath.Join(root, "testdata", "pcaps", "profinet_dcp_identify_scan.pcap"))
		require.Len(t, events, 14, "fourteen identify requests, despite the file's name")

		names := map[string]int{}
		padded, publishers := 0, map[string]bool{}
		for _, e := range events {
			assert.Equal(t, "Identify", e.Operation)
			assert.Equal(t, model.DirRequest, e.Direction)
			assert.Equal(t, model.ClassDiscovery, e.Class)
			// Every request is addressed to the PROFINET multicast group, so
			// nothing here is an asset of its own.
			assert.Equal(t, "01:0e:cf:00:00:00", e.Flow.DstMAC)
			publishers[e.Flow.SrcMAC] = true
			names[e.Attrs["name_of_station"]]++
			if e.Attrs["padding_bytes"] != "" {
				padded++
				assert.Contains(t, e.Attrs["anomaly"], "padding_not_zero")
			}
		}
		assert.Len(t, publishers, 11, "eleven interfaces doing the asking")
		assert.Equal(t, map[string]int{
			"switch1": 2, "switch2": 1, "switch3": 2, "switch4": 1, "switch5": 1,
			"switch6": 1, "switch7": 1, "swln3": 1, "swln4": 1, "pn-io": 3,
		}, names, "each request filters on the name of one station")
		assert.Equal(t, 11, padded,
			"eleven frames pad with whatever was in the sender's buffer")
	})
}
