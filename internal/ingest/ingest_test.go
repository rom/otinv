package ingest_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	_ "github.com/rom/otinv/internal/dissect/modbus" // register the dissector
	"github.com/rom/otinv/internal/ingest"
	"github.com/rom/otinv/internal/model"
)

var update = flag.Bool("update", false, "regenerate the golden files in testdata/golden")

// repoRoot walks up from the test's working directory to the module root, so
// that tests can reach the shared testdata/ tree.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "go.mod not found above the test directory")
		dir = parent
	}
}

func run(t *testing.T, path string) (*ingest.Result, []model.Event) {
	t.Helper()
	var events []model.Event
	res, err := ingest.File(path, ingest.Options{
		CaptureID: "test",
		Registry:  dissect.Default(),
		Sink:      func(e model.Event) { events = append(events, e) },
	})
	require.NoError(t, err)
	return res, events
}

// The golden files pin the full decode of the public sample captures. Review
// the diff before committing a regenerated file.
func TestGolden(t *testing.T) {
	root := repoRoot(t)
	for _, name := range []string{
		"modbus_test_data_part1",
		"modbus_test_data_part2",
	} {
		t.Run(name, func(t *testing.T) {
			_, events := run(t, filepath.Join(root, "testdata", "pcaps", name+".pcap"))
			require.NotEmpty(t, events)

			got, err := json.MarshalIndent(events, "", "  ")
			require.NoError(t, err)
			got = append(got, '\n')

			goldenPath := filepath.Join(root, "testdata", "golden", name+".json")
			if *update {
				require.NoError(t, os.WriteFile(goldenPath, got, 0o644))
				t.Logf("updated %s", goldenPath)
				return
			}
			want, err := os.ReadFile(goldenPath)
			require.NoError(t, err, "run `make test-update` to create the golden file")
			assert.JSONEq(t, string(want), string(got))
		})
	}
}

// The facts below were cross-checked against an independent decode of the
// capture and against the Zeek modbus.log shipped alongside it in the public
// dataset.
func TestPart1Facts(t *testing.T) {
	root := repoRoot(t)
	res, events := run(t, filepath.Join(root, "testdata", "pcaps", "modbus_test_data_part1.pcap"))

	assert.Equal(t, uint64(118), res.Packets, "the capture holds 118 packets")
	// Six distinct connections, all to or from port 502. The stream count is
	// higher because a connection that is seen again after it closed starts a
	// new reassembly stream; see Result.TCPStreams.
	assert.GreaterOrEqual(t, res.TCPStreams, uint64(6), "six TCP connections, all to or from port 502")
	assert.Equal(t, uint64(5), res.BoundStreams, "five streams carry Modbus payload")
	assert.Equal(t, "Ethernet", res.Capture.LinkType)
	assert.Equal(t, int64(10181), res.Capture.Bytes)
	assert.Equal(t,
		"94942b3d014810710f50836c95d3faf6df6e6370a6560bae541397c1df50213d",
		res.Capture.SHA256)

	byOperation := map[string]int{}
	byClass := map[model.Classification]int{}
	byException := map[string]int{}
	identities := map[string]int{}
	anomalies := 0
	malformed := 0
	units := map[uint16]int{}

	for _, e := range events {
		assert.Equal(t, "modbus", e.Protocol)
		assert.Equal(t, "test", e.CaptureID)
		assert.True(t, e.Class.Valid(), "class %q", e.Class)
		assert.NotZero(t, e.PacketIndex, "every event names the packet it came from")
		assert.False(t, e.Timestamp.IsZero())

		byOperation[e.Operation]++
		byClass[e.Class]++
		if e.Exception != "" {
			byException[e.Exception]++
		}
		for k, v := range e.Identity {
			identities[k+"="+v]++
		}
		if e.Attrs["anomaly"] != "" {
			anomalies++
		}
		if e.Malformed {
			malformed++
		}
		if e.UnitID != nil {
			units[*e.UnitID]++
		}
	}

	// Device identity evidence: the FC 17 reply names the vendor twice.
	assert.Equal(t, 2, identities["report_server_id=Wingpath Limited"],
		"Report Server ID carries the device identity for the inventory")

	// Operations the capture is known to contain.
	assert.Equal(t, 16, byOperation["Diagnostics"], "8 requests, 4 replies and 4 exception replies")
	assert.Equal(t, 4, byOperation["ReportServerID"])
	assert.Equal(t, 2, byOperation["ReadDeviceIdentification"])
	assert.Equal(t, 2, byOperation["ReadHoldingRegisters"])
	assert.Equal(t, 2, byOperation["WriteSingleRegister"], "one request and one reply")
	assert.Equal(t, 4, byOperation["WriteSingleCoil"], "two requests and two replies")

	// Exceptions, by name.
	assert.Equal(t, 4, byException["GatewayTargetDeviceFailedToRespond"])
	assert.Equal(t, 5, byException["ServerDeviceBusy"])
	assert.Equal(t, 5, byException["Acknowledge"])

	// The crafted frames in the capture.
	assert.Equal(t, 2, anomalies, "two frames carry a non-zero protocol identifier")
	assert.GreaterOrEqual(t, malformed, 2, "two frames declare a bogus MBAP length")
	assert.GreaterOrEqual(t, res.Malformed, uint64(2))

	// Force Listen Only Mode is a control action, not a read-only diagnostic.
	forceListenOnly := 0
	for _, e := range events {
		if e.Attrs["sub_function_name"] == "ForceListenOnlyMode" {
			forceListenOnly++
			assert.Equal(t, model.ClassControl, e.Class)
		}
	}
	assert.Equal(t, 3, forceListenOnly,
		"three requests force listen-only mode; the replies are exceptions, which carry no sub-function")

	assert.Positive(t, byClass[model.ClassWrite])
	assert.Positive(t, byClass[model.ClassRead])
	assert.Positive(t, byClass[model.ClassDiscovery])
	assert.Equal(t, 1, len(units), "every decodable frame addresses unit 10")
	assert.Positive(t, units[10])
}

func TestPart2SweepsFunctionCodes(t *testing.T) {
	root := repoRoot(t)
	_, events := run(t, filepath.Join(root, "testdata", "pcaps", "modbus_test_data_part2.pcap"))

	codes := map[int]bool{}
	for _, e := range events {
		codes[e.FunctionCode] = true
		assert.NotEmpty(t, e.Operation)
		assert.True(t, e.Class.Valid())
	}
	assert.Greater(t, len(codes), 100, "the capture sweeps function codes 1 through 127")
}

// writePcap serialises packets into a classic pcap file, which is how CLAUDE.md
// allows crafted test traffic: gopacket serialization rather than a committed
// capture.
func writePcap(t *testing.T, packets [][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "crafted.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	base := time.Unix(1700000000, 0).UTC()
	for i, p := range packets {
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     base.Add(time.Duration(i) * time.Millisecond),
			CaptureLength: len(p),
			Length:        len(p),
		}, p))
	}
	return path
}

// tcpSegment builds one Ethernet/IPv4/TCP packet, optionally VLAN tagged.
func tcpSegment(t *testing.T, srcPort, dstPort uint16, seq uint32, syn, ack bool, vlan uint16, payload []byte) []byte {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x1b, 0x1b, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x1b, 0x1b, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{10, 0, 0, 9},
		DstIP:    []byte{10, 0, 0, 3},
	}
	if srcPort == 502 {
		ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP
		eth.SrcMAC, eth.DstMAC = eth.DstMAC, eth.SrcMAC
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		SYN:     syn,
		ACK:     ack,
		PSH:     len(payload) > 0,
		Window:  65535,
	}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))

	stack := []gopacket.SerializableLayer{eth}
	if vlan != 0 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		stack = append(stack, &layers.Dot1Q{
			VLANIdentifier: vlan,
			Type:           layers.EthernetTypeIPv4,
		})
	}
	stack = append(stack, ip, tcp, gopacket.Payload(payload))

	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, stack...))
	return buf.Bytes()
}

// handshake returns the SYN and SYN-ACK that open a stream, so that reassembly
// knows which side is the client.
func handshake(t *testing.T) [][]byte {
	t.Helper()
	return [][]byte{
		tcpSegment(t, 3082, 502, 1000, true, false, 0, nil),
		tcpSegment(t, 502, 3082, 5000, true, true, 0, nil),
	}
}

// A single ADU split across two TCP segments must be reassembled and decoded
// once, not twice or never.
func TestSplitADUIsReassembled(t *testing.T) {
	full := []byte{
		0x00, 0x2a, 0x00, 0x00, 0x00, 0x06, 0x0a, // MBAP: tid 42, len 6, unit 10
		0x03, 0x00, 0x05, 0x00, 0x02, // FC 3, address 5, quantity 2
	}
	packets := append(handshake(t),
		tcpSegment(t, 3082, 502, 1001, false, true, 0, full[:5]),
		tcpSegment(t, 3082, 502, 1006, false, true, 0, full[5:]),
	)

	_, events := run(t, writePcap(t, packets))
	require.Len(t, events, 1, "one ADU yields one event however it is segmented")
	e := events[0]
	assert.Equal(t, "ReadHoldingRegisters", e.Operation)
	assert.Equal(t, model.DirRequest, e.Direction)
	assert.Equal(t, uint32(5), *e.Address)
	assert.Equal(t, uint32(2), *e.Quantity)
	assert.Equal(t, uint32(42), *e.TransactionID)
	assert.False(t, e.Malformed)
}

// Two ADUs inside one segment must both be decoded.
func TestPipelinedADUsInOneSegment(t *testing.T) {
	first := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x0a, 0x03, 0x00, 0x05, 0x00, 0x02}
	second := []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x0a, 0x01, 0x00, 0x07, 0x00, 0x03}
	packets := append(handshake(t),
		tcpSegment(t, 3082, 502, 1001, false, true, 0, append(append([]byte{}, first...), second...)),
	)

	_, events := run(t, writePcap(t, packets))
	require.Len(t, events, 2)
	assert.Equal(t, "ReadHoldingRegisters", events[0].Operation)
	assert.Equal(t, "ReadCoils", events[1].Operation)
	assert.Equal(t, uint32(1), *events[0].TransactionID)
	assert.Equal(t, uint32(2), *events[1].TransactionID)
}

// After a frame with an impossible length field, the stream must resynchronise
// and still decode the following good frame.
func TestResyncAfterBogusLength(t *testing.T) {
	bogus := []byte{0x00, 0x01, 0x00, 0x00, 0x88, 0x04, 0x05, 0x07, 0x08, 0x09}
	good := []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x0a, 0x03, 0x00, 0x05, 0x00, 0x02}
	packets := append(handshake(t),
		tcpSegment(t, 3082, 502, 1001, false, true, 0, append(append([]byte{}, bogus...), good...)),
	)

	res, events := run(t, writePcap(t, packets))
	require.GreaterOrEqual(t, len(events), 2)
	assert.True(t, events[0].Malformed, "the bogus frame is reported, not hidden")
	assert.Equal(t, -1, events[0].FunctionCode)
	assert.Positive(t, res.Resyncs)

	var decoded *model.Event
	for i := range events {
		if !events[i].Malformed {
			decoded = &events[i]
		}
	}
	require.NotNil(t, decoded, "the good frame after the bogus one must still be decoded")
	assert.Equal(t, "ReadHoldingRegisters", decoded.Operation)
	assert.Equal(t, uint32(2), *decoded.TransactionID)
}

func TestVLANTagIsRecorded(t *testing.T) {
	adu := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x0a, 0x03, 0x00, 0x05, 0x00, 0x02}
	packets := [][]byte{
		tcpSegment(t, 3082, 502, 1000, true, false, 100, nil),
		tcpSegment(t, 502, 3082, 5000, true, true, 100, nil),
		tcpSegment(t, 3082, 502, 1001, false, true, 100, adu),
	}

	_, events := run(t, writePcap(t, packets))
	require.Len(t, events, 1)
	assert.Equal(t, []uint16{100}, events[0].Flow.VLAN)
	assert.Equal(t, "00:1b:1b:00:00:01", events[0].Flow.SrcMAC)
	assert.Equal(t, "10.0.0.9", events[0].Flow.SrcIP)
	assert.Equal(t, uint16(502), events[0].Flow.DstPort)
}

// A reply arriving from the Modbus port is a response even when that side
// opened the connection, which is exactly what one stream in part1 does.
func TestDirectionFromServerPort(t *testing.T) {
	exception := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x0a, 0x81, 0x06}
	packets := [][]byte{
		tcpSegment(t, 502, 4446, 1000, true, false, 0, nil),
		tcpSegment(t, 4446, 502, 5000, true, true, 0, nil),
		tcpSegment(t, 502, 4446, 1001, false, true, 0, exception),
	}

	_, events := run(t, writePcap(t, packets))
	require.Len(t, events, 1)
	assert.Equal(t, model.DirResponse, events[0].Direction)
	assert.Equal(t, "ServerDeviceBusy", events[0].Exception)
}

func TestNonModbusStreamIsNotBound(t *testing.T) {
	packets := append(handshake(t),
		tcpSegment(t, 3082, 502, 1001, false, true, 0, []byte("GET / HTTP/1.1\r\nHost: plc\r\n\r\n")),
	)
	res, events := run(t, writePcap(t, packets))
	assert.Empty(t, events, "HTTP on port 502 must not be decoded as Modbus")
	assert.Positive(t, res.UnboundPayloads)
}

func TestFileErrors(t *testing.T) {
	_, err := ingest.File(filepath.Join(t.TempDir(), "missing.pcap"), ingest.Options{})
	require.Error(t, err)

	notACapture := filepath.Join(t.TempDir(), "notes.txt")
	require.NoError(t, os.WriteFile(notACapture, []byte("this is not a capture file"), 0o644))
	_, err = ingest.File(notACapture, ingest.Options{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a pcap")
}

func TestOptionsExtraPortsAreHonoured(t *testing.T) {
	adu := []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x0a, 0x03, 0x00, 0x05, 0x00, 0x02}
	packets := [][]byte{
		tcpSegment(t, 3082, 10502, 1000, true, false, 0, nil),
		tcpSegment(t, 10502, 3082, 5000, true, true, 0, nil),
		tcpSegment(t, 3082, 10502, 1001, false, true, 0, adu),
	}
	path := writePcap(t, packets)

	// A fresh registry keeps the extra port out of the process-wide one.
	reg := dissect.NewRegistry()
	reg.Register(newModbus(t), dissect.TCPPorts(502))
	require.NoError(t, reg.ExtraTCPPorts("modbus", 10502))

	var events []model.Event
	_, err := ingest.File(path, ingest.Options{
		Registry: reg,
		Sink:     func(e model.Event) { events = append(events, e) },
	})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, model.DirRequest, events[0].Direction,
		"a user-configured port tells request from response too")
}
