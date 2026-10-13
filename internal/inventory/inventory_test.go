package inventory_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	_ "github.com/rom/otinv/internal/dissect/modbus"
	"github.com/rom/otinv/internal/ingest"
	"github.com/rom/otinv/internal/inventory"
	"github.com/rom/otinv/internal/model"
)

var base = time.Unix(1093521694, 0).UTC()

func flow(srcMAC, srcIP string, srcPort uint16, dstMAC, dstIP string, dstPort uint16) model.Flow {
	return model.Flow{
		SrcMAC: srcMAC, DstMAC: dstMAC,
		SrcIP: srcIP, DstIP: dstIP,
		SrcPort: srcPort, DstPort: dstPort,
		Transport: model.TransportTCP,
	}
}

func request(f model.Flow, op string, fc int, class model.Classification, at time.Duration) model.Event {
	return model.Event{
		CaptureID: "cap", PacketIndex: 1, Timestamp: base.Add(at), Flow: f,
		Protocol: "modbus", Direction: model.DirRequest,
		Operation: op, FunctionCode: fc, Class: class,
		UnitID: model.Ptr(uint16(10)),
	}
}

func response(f model.Flow, op string, fc int, class model.Classification, at time.Duration) model.Event {
	e := request(f, op, fc, class, at)
	e.Flow = f
	e.Direction = model.DirResponse
	return e
}

func byKey(assets []model.Asset) map[string]model.Asset {
	m := make(map[string]model.Asset, len(assets))
	for _, a := range assets {
		m[a.Key] = a
	}
	return m
}

// The server of a control protocol is a controller; the host polling it is an
// operator station. Both are inferred from behaviour, with reasons.
func TestRolesFromBehaviour(t *testing.T) {
	client := flow("00:20:78:00:62:0d", "10.0.0.57", 2578, "00:02:b3:ce:70:51", "10.0.0.3", 502)
	server := client.Reverse()

	b := inventory.New()
	b.Add(request(client, "ReadHoldingRegisters", 3, model.ClassRead, 0))
	b.Add(response(server, "ReadHoldingRegisters", 3, model.ClassRead, time.Second))
	b.Add(request(client, "WriteSingleCoil", 5, model.ClassWrite, 2*time.Second))

	assets := byKey(b.Assets())
	require.Len(t, assets, 2)

	plc := assets["mac:00:02:b3:ce:70:51"]
	assert.Equal(t, model.RoleController, plc.Role.Name)
	assert.Positive(t, plc.Role.Confidence)
	assert.NotEmpty(t, plc.Role.Reasons, "an inferred role must say why")
	require.Len(t, plc.ServerProtocols(), 1)
	assert.Equal(t, "modbus", plc.ServerProtocols()[0].Protocol)
	assert.Equal(t, []uint16{10}, plc.ServerProtocols()[0].UnitIDs)

	hmi := assets["mac:00:20:78:00:62:0d"]
	assert.Equal(t, model.RoleOperator, hmi.Role.Name)
	require.Len(t, hmi.Protocols, 1)
	assert.Equal(t, "client", hmi.Protocols[0].Side)

	// Every event touches both endpoints, so both count it.
	assert.Equal(t, uint64(3), plc.Events)
	assert.Equal(t, uint64(3), hmi.Events)
	assert.True(t, base.Equal(plc.FirstSeen))
	assert.True(t, base.Add(2*time.Second).Equal(plc.LastSeen))
}

// A host issuing program or firmware operations is an engineering station,
// which outranks being a plain polling client.
func TestEngineeringWorkstationRole(t *testing.T) {
	client := flow("00:20:78:00:62:0d", "10.0.0.57", 2578, "00:02:b3:ce:70:51", "10.0.0.3", 502)

	b := inventory.New()
	b.Add(request(client, "ReadHoldingRegisters", 3, model.ClassRead, 0))
	b.Add(request(client, "DownloadBlock", 90, model.ClassProgram, time.Second))

	assets := byKey(b.Assets())
	ws := assets["mac:00:20:78:00:62:0d"]
	assert.Equal(t, model.RoleEngineering, ws.Role.Name)
	assert.Contains(t, ws.Role.Reasons[0]+ws.Role.Reasons[len(ws.Role.Reasons)-1], "program")
}

// Identity in a reply describes the device that sent it, and must carry the
// packet that proves it.
func TestIdentityEnrichment(t *testing.T) {
	server := flow("00:02:b3:ce:70:51", "10.0.0.3", 502, "00:20:78:00:62:0d", "10.0.0.57", 2578)

	idReply := response(server, "ReportServerID", 17, model.ClassDiscovery, time.Second)
	idReply.PacketIndex = 41
	idReply.Identity = map[string]string{"report_server_id": "Wingpath Limited"}

	devID := response(server, "ReadDeviceIdentification", 43, model.ClassDiscovery, 2*time.Second)
	devID.PacketIndex = 60
	devID.Identity = map[string]string{
		"vendor_name":          "Wingpath",
		"product_code":         "PLC1",
		"major_minor_revision": "1.0",
	}

	b := inventory.New()
	b.Add(idReply)
	b.Add(devID)

	assets := byKey(b.Assets())
	plc := assets["mac:00:02:b3:ce:70:51"]

	fields := map[string]model.Attribute{}
	for _, at := range plc.Attributes {
		fields[at.Field] = at
	}

	require.Contains(t, fields, "vendor")
	assert.Equal(t, "Wingpath", fields["vendor"].Value,
		"the structured FC 43 object outranks the free-text FC 17 string")
	require.Contains(t, fields, "report_server_id")
	assert.Equal(t, "Wingpath Limited", fields["report_server_id"].Value)
	assert.Equal(t, uint64(41), fields["report_server_id"].Evidence.PacketIndex)
	assert.Equal(t, "cap", fields["vendor"].Evidence.CaptureID)
	assert.Equal(t, uint64(60), fields["vendor"].Evidence.PacketIndex)
	assert.Equal(t, "modbus", fields["vendor"].Evidence.Protocol)
	assert.Equal(t, 43, fields["vendor"].Evidence.FunctionCode)
	assert.Greater(t, fields["vendor"].Confidence, fields["report_server_id"].Confidence)

	require.Contains(t, fields, "product_code")
	assert.Equal(t, "PLC1", fields["product_code"].Value)
	require.Contains(t, fields, "firmware_revision")
	assert.Equal(t, "1.0", fields["firmware_revision"].Value)

	// The client learns nothing about itself from the device's reply.
	hmi := assets["mac:00:20:78:00:62:0d"]
	assert.Empty(t, hmi.Attributes)
}

// A routed segment makes many IPs share the gateway's MAC. Those hosts must
// stay separate assets instead of merging into one device.
func TestGatewayIsNotMergedWithHostsBehindIt(t *testing.T) {
	const gatewayMAC = "00:50:04:93:70:67"
	b := inventory.New()
	for i, ip := range []string{"10.1.0.1", "10.1.0.2", "10.1.0.3", "10.1.0.4", "10.1.0.5"} {
		f := flow("00:20:78:00:62:0d", "10.0.0.57", 2578, gatewayMAC, ip, 502)
		b.Add(request(f, "ReadHoldingRegisters", 3, model.ClassRead, time.Duration(i)*time.Second))
	}

	assets := byKey(b.Assets())

	for _, ip := range []string{"10.1.0.1", "10.1.0.5"} {
		a, ok := assets["ip:"+ip]
		require.True(t, ok, "host %s behind the gateway must be its own asset", ip)
		assert.Equal(t, []string{ip}, a.IPs)
		assert.False(t, a.IsGateway)
		assert.Equal(t, model.RoleController, a.Role.Name)
	}
	assert.NotContains(t, assets, "mac:"+gatewayMAC+":merged")

	gw, ok := assets["mac:"+gatewayMAC]
	require.True(t, ok, "the gateway itself is an asset")
	assert.True(t, gw.IsGateway)
	assert.Equal(t, model.RoleGateway, gw.Role.Name)
	assert.Empty(t, gw.IPs, "a forwarding MAC does not own the addresses behind it")
}

// Below the threshold a MAC with a couple of IPs is one multi-homed device,
// not a gateway.
func TestFewIPsOnOneMACStayOneAsset(t *testing.T) {
	const mac = "00:02:b3:ce:70:51"
	b := inventory.New()
	for i, ip := range []string{"10.0.0.3", "10.0.0.4"} {
		f := flow("00:20:78:00:62:0d", "10.0.0.57", 2578, mac, ip, 502)
		b.Add(request(f, "ReadCoils", 1, model.ClassRead, time.Duration(i)*time.Second))
	}

	assets := byKey(b.Assets())
	a, ok := assets["mac:"+mac]
	require.True(t, ok)
	assert.False(t, a.IsGateway)
	assert.ElementsMatch(t, []string{"10.0.0.3", "10.0.0.4"}, a.IPs)
	assert.Len(t, a.Addresses, 2, "both tuples are kept")
}

func TestAddressTuplesKeepVLANAndTimeRange(t *testing.T) {
	vlan := uint16(100)
	f := flow("00:20:78:00:62:0d", "10.0.0.57", 2578, "00:02:b3:ce:70:51", "10.0.0.3", 502)
	f.VLAN = []uint16{vlan}

	b := inventory.New()
	b.Add(request(f, "ReadCoils", 1, model.ClassRead, 0))
	b.Add(request(f, "ReadCoils", 1, model.ClassRead, 10*time.Second))

	assets := byKey(b.Assets())
	plc := assets["mac:00:02:b3:ce:70:51"]
	require.Len(t, plc.Addresses, 1, "the same tuple seen twice is one address")
	addr := plc.Addresses[0]
	assert.Equal(t, "10.0.0.3", addr.IP)
	require.NotNil(t, addr.VLAN)
	assert.Equal(t, vlan, *addr.VLAN)
	assert.Equal(t, uint64(2), addr.Events)
	assert.True(t, base.Equal(addr.FirstSeen))
	assert.True(t, base.Add(10*time.Second).Equal(addr.LastSeen))
	assert.Equal(t, []uint16{vlan}, plc.VLANs)
}

func TestClassesAreCountedPerProtocol(t *testing.T) {
	client := flow("00:20:78:00:62:0d", "10.0.0.57", 2578, "00:02:b3:ce:70:51", "10.0.0.3", 502)
	b := inventory.New()
	b.Add(request(client, "ReadCoils", 1, model.ClassRead, 0))
	b.Add(request(client, "ReadCoils", 1, model.ClassRead, time.Second))
	b.Add(request(client, "Diagnostics", 8, model.ClassControl, 2*time.Second))

	assets := byKey(b.Assets())
	plc := assets["mac:00:02:b3:ce:70:51"]
	require.Len(t, plc.Protocols, 1)
	assert.Equal(t, uint64(2), plc.Protocols[0].Classes[model.ClassRead])
	assert.Equal(t, uint64(1), plc.Protocols[0].Classes[model.ClassControl])
}

// A malformed frame still proves two hosts talked, but says nothing about what
// either of them is.
func TestMalformedEventsStillYieldAssets(t *testing.T) {
	f := flow("00:20:78:00:62:0d", "10.0.0.57", 2585, "00:50:04:93:70:67", "10.0.0.8", 502)
	e := request(f, "FramingError", -1, model.ClassOther, 0)
	e.Malformed = true
	e.UnitID = nil

	b := inventory.New()
	b.Add(e)

	assets := b.Assets()
	require.Len(t, assets, 2)
	for _, a := range assets {
		assert.Equal(t, model.RoleUnknown, a.Role.Name)
		assert.Zero(t, a.Role.Confidence)
	}
}

func TestAssetsAreSortedDeterministically(t *testing.T) {
	busy := flow("00:20:78:00:62:0d", "10.0.0.57", 2578, "00:02:b3:ce:70:51", "10.0.0.3", 502)
	quiet := flow("00:20:78:00:62:0d", "10.0.0.57", 2579, "00:02:b3:ce:70:52", "10.0.0.4", 502)

	b := inventory.New()
	for i := range 5 {
		b.Add(request(busy, "ReadCoils", 1, model.ClassRead, time.Duration(i)*time.Second))
	}
	b.Add(request(quiet, "ReadCoils", 1, model.ClassRead, 0))

	first := b.Assets()
	second := b.Assets()
	assert.Equal(t, first, second, "repeated builds must be identical")
	assert.Equal(t, "mac:00:20:78:00:62:0d", first[0].Key, "busiest asset first")
	assert.GreaterOrEqual(t, first[0].Events, first[len(first)-1].Events)
}

// fakeSource and fakeSink stand in for the store so that Rebuild can be tested
// without a database.
type fakeSource struct{ events []model.Event }

func (f *fakeSource) EachEvent(_ context.Context, _ int64, fn func(model.Event) error) error {
	for _, e := range f.events {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

type fakeSink struct {
	projectID int64
	assets    []model.Asset
}

func (f *fakeSink) SaveAssets(_ context.Context, projectID int64, assets []model.Asset) error {
	f.projectID = projectID
	f.assets = assets
	return nil
}

func TestRebuildStreamsEventsIntoAssets(t *testing.T) {
	client := flow("00:20:78:00:62:0d", "10.0.0.57", 2578, "00:02:b3:ce:70:51", "10.0.0.3", 502)
	src := &fakeSource{events: []model.Event{
		request(client, "ReadCoils", 1, model.ClassRead, 0),
		response(client.Reverse(), "ReadCoils", 1, model.ClassRead, time.Second),
	}}
	dst := &fakeSink{}

	assets, err := inventory.Rebuild(context.Background(), src, dst, 7)
	require.NoError(t, err)
	assert.Len(t, assets, 2)
	assert.Equal(t, int64(7), dst.projectID)
	assert.Equal(t, assets, dst.assets, "what is returned is what is saved")
}

// End to end: the public sample capture through ingest and into an inventory.
func TestInventoryFromSampleCapture(t *testing.T) {
	root, err := os.Getwd()
	require.NoError(t, err)
	for filepath.Base(root) != "otinv" {
		parent := filepath.Dir(root)
		require.NotEqual(t, root, parent)
		root = parent
	}

	b := inventory.New()
	res, err := ingest.File(filepath.Join(root, "testdata", "pcaps", "modbus_test_data_part1.pcap"),
		ingest.Options{
			CaptureID: "part1",
			Registry:  dissect.Default(),
			Sink:      b.Add,
		})
	require.NoError(t, err)
	assert.Equal(t, uint64(118), res.Packets)

	assets := byKey(b.Assets())
	// Four (MAC, IP) endpoint tuples appear in this capture but only three
	// MACs: 00:50:04:93:70:67 fronts both 10.0.0.8 and 10.0.0.9. Two IPs is
	// below the gateway threshold, so they stay one multi-homed asset. That
	// is a real ambiguity in the data, not a decoding mistake: with this
	// capture alone there is no way to tell a dual-homed device from a small
	// router, and the address tuples keep the evidence either way.
	require.Len(t, assets, 3)
	multiHomed := assets["mac:00:50:04:93:70:67"]
	assert.ElementsMatch(t, []string{"10.0.0.8", "10.0.0.9"}, multiHomed.IPs)
	assert.False(t, multiHomed.IsGateway)
	assert.Len(t, multiHomed.Addresses, 2)

	// 10.0.0.3 answered the Report Server ID request, so it has a vendor.
	plc := assets["mac:00:02:b3:ce:70:51"]
	require.NotEmpty(t, plc.IPs)
	assert.Contains(t, plc.IPs, "10.0.0.3")
	assert.Equal(t, model.RoleController, plc.Role.Name)
	assert.Equal(t, "Wingpath Limited", plc.Vendor())
	require.Len(t, plc.ServerProtocols(), 1)
	assert.Equal(t, []uint16{10}, plc.ServerProtocols()[0].UnitIDs)
	assert.Positive(t, plc.ServerProtocols()[0].Classes[model.ClassControl],
		"this device was told to go listen-only")

	// 10.0.0.57 is the station that polled it.
	hmi := assets["mac:00:20:78:00:62:0d"]
	assert.Equal(t, model.RoleOperator, hmi.Role.Name)
	assert.Contains(t, hmi.IPs, "10.0.0.57")
}
