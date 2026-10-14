package topology_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/topology"
)

var seen = time.Date(2024, 5, 2, 9, 0, 0, 0, time.UTC)

// asset builds an asset with the fields the placement reads.
func asset(key, label string, role model.RoleName, protocols ...model.ProtocolUsage) model.Asset {
	return model.Asset{
		Key:       key,
		Label:     label,
		IPs:       []string{label},
		Role:      model.Role{Name: role, Confidence: 80},
		Level:     model.Level{Value: model.LevelUnknown},
		Protocols: protocols,
		Events:    10,
		FirstSeen: seen,
		LastSeen:  seen.Add(time.Minute),
	}
}

func served(protocol string, events uint64) model.ProtocolUsage {
	return model.ProtocolUsage{Protocol: protocol, Side: "server", Events: events}
}

func spoke(protocol string, events uint64, classes map[model.Classification]uint64) model.ProtocolUsage {
	return model.ProtocolUsage{Protocol: protocol, Side: "client", Events: events, Classes: classes}
}

func TestLevelFromBehaviour(t *testing.T) {
	tests := []struct {
		name       string
		asset      model.Asset
		level      int
		confidence int
		reason     string
	}{
		{
			name:       "a controller serves a control protocol",
			asset:      asset("a", "10.0.0.3", model.RoleController, served("modbus", 120)),
			level:      topology.LevelBasicCtrl,
			confidence: 80,
			reason:     "serves modbus (120 operations observed)",
		},
		{
			name: "a station that programs controllers supervises them",
			asset: asset("b", "10.0.0.9", model.RoleEngineering,
				spoke("s7comm", 200, map[model.Classification]uint64{model.ClassProgram: 12})),
			level:      topology.LevelSupervisory,
			confidence: 70,
			reason:     "programs s7comm devices (12 program, 0 firmware operations)",
		},
		{
			name:       "a polling client supervises",
			asset:      asset("c", "10.0.0.57", model.RoleOperator, spoke("modbus", 38, nil)),
			level:      topology.LevelSupervisory,
			confidence: 65,
			reason:     "polls modbus devices (38 operations observed)",
		},
		{
			name:       "an OPC UA server alone is placed above the control level, with a caveat",
			asset:      asset("d", "10.0.0.20", model.RoleController, served("opcua", 24)),
			level:      topology.LevelOperations,
			confidence: 45,
			reason:     "reference model places above the control level",
		},
		{
			name:  "an asset nothing was observed about is unplaced",
			asset: asset("e", "10.0.0.99", model.RoleUnknown),
			level: model.LevelUnknown,
		},
		{
			name: "a client of a protocol nobody controls with says nothing about a level",
			asset: asset("f", "10.0.0.98", model.RoleOperator,
				spoke("http", 40, nil)),
			level: model.LevelUnknown,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := topology.AssignLevels([]model.Asset{tc.asset})
			level := got[tc.asset.Key]
			assert.Equal(t, tc.level, level.Value)
			assert.Equal(t, tc.confidence, level.Confidence)
			if tc.reason != "" {
				require.NotEmpty(t, level.Reasons)
				assert.Contains(t, level.Reasons[0], tc.reason)
			}
		})
	}
}

// A forwarding device is on both sides of the boundary it forwards across.
func TestGatewayIsNotPlacedInOneLevel(t *testing.T) {
	gateway := asset("gw", "10.0.0.1", model.RoleGateway)
	gateway.IsGateway = true
	gateway.IPs = []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}

	assets := []model.Asset{
		gateway,
		asset("a", "10.0.0.5", model.RoleController, served("modbus", 10)),
		asset("b", "10.0.0.6", model.RoleController, served("modbus", 10)),
		asset("c", "10.0.0.7", model.RoleController, served("modbus", 10)),
	}

	levels := topology.AssignLevels(assets)
	level := levels["gw"]
	assert.Equal(t, model.LevelUnknown, level.Value,
		"a subnet full of controllers must not pull the gateway into level 1")
	require.Len(t, level.Reasons, 1)
	assert.Contains(t, level.Reasons[0], "spans levels")
}

func TestSubnetMajorityPlacesWhatBehaviourCannot(t *testing.T) {
	quiet := asset("quiet", "192.168.0.44", model.RoleUnknown)
	assets := []model.Asset{
		asset("a", "192.168.0.10", model.RoleController, served("modbus", 10)),
		asset("b", "192.168.0.11", model.RoleController, served("modbus", 10)),
		asset("c", "192.168.0.12", model.RoleOperator, spoke("modbus", 10, nil)),
		quiet,
	}

	levels := topology.AssignLevels(assets)
	level := levels["quiet"]
	assert.Equal(t, topology.LevelBasicCtrl, level.Value)
	assert.Equal(t, 40, level.Confidence, "the subnet is an argument, not evidence about the device")
	require.Len(t, level.Reasons, 1)
	assert.Contains(t, level.Reasons[0], "192.168.0.0/24")
	assert.Contains(t, level.Reasons[0], "nothing was observed about this one's own behaviour")

	// A different subnet is not an argument about this one.
	elsewhere := asset("elsewhere", "10.9.9.9", model.RoleUnknown)
	levels = topology.AssignLevels(append(assets, elsewhere))
	assert.Equal(t, model.LevelUnknown, levels["elsewhere"].Value)
}

func TestSubnetTieLeavesAnAssetUnplaced(t *testing.T) {
	assets := []model.Asset{
		asset("a", "192.168.0.10", model.RoleController, served("modbus", 10)),
		asset("b", "192.168.0.11", model.RoleOperator, spoke("modbus", 10, nil)),
		asset("quiet", "192.168.0.44", model.RoleUnknown),
	}

	levels := topology.AssignLevels(assets)
	assert.Equal(t, model.LevelUnknown, levels["quiet"].Value,
		"one controller and one HMI is not a majority")
}

// A netmask a device reported is better than the prefix otinv would assume.
func TestReportedNetmaskGroupsBeyondTheAssumedPrefix(t *testing.T) {
	far := asset("far", "192.168.9.44", model.RoleUnknown)
	far.Attributes = []model.Attribute{
		{Field: "netmask", Value: "255.255.0.0", Confidence: 60, Source: "profinet_dcp"},
	}

	controllers := []model.Asset{
		asset("a", "192.168.1.10", model.RoleController, served("profinet_dcp", 4)),
		asset("b", "192.168.2.11", model.RoleController, served("profinet_dcp", 4)),
		asset("c", "192.168.3.12", model.RoleController, served("profinet_dcp", 4)),
	}
	for i := range controllers {
		controllers[i].Attributes = []model.Attribute{
			{Field: "netmask", Value: "255.255.0.0", Confidence: 60, Source: "profinet_dcp"},
		}
	}

	levels := topology.AssignLevels(append(controllers, far))
	level := levels["far"]
	assert.Equal(t, topology.LevelBasicCtrl, level.Value,
		"a /16 the devices themselves reported puts them in one subnet")
	require.Len(t, level.Reasons, 1)
	assert.Contains(t, level.Reasons[0], "192.168.0.0/16")

	// Without the reported mask the same addresses are three /24s and
	// nothing is placed.
	far.Attributes = nil
	plain := make([]model.Asset, len(controllers))
	for i, c := range controllers {
		c.Attributes = nil
		plain[i] = c
	}
	levels = topology.AssignLevels(append(plain, far))
	assert.Equal(t, model.LevelUnknown, levels["far"].Value)
}

func TestNonsenseNetmaskIsIgnored(t *testing.T) {
	a := asset("a", "192.168.0.10", model.RoleController, served("modbus", 10))
	for _, value := range []string{"0.255.0.255", "not an address", "", "::1"} {
		a.Attributes = []model.Attribute{{Field: "netmask", Value: value}}
		levels := topology.AssignLevels([]model.Asset{a})
		assert.Equal(t, topology.LevelBasicCtrl, levels["a"].Value, value)
	}
}

// link is one aggregated conversation.
// link is one aggregated Modbus conversation; the protocol is fixed because
// what the graph does with a link does not depend on which protocol it is.
func link(src, dst string, events int64, classes map[model.Classification]int64) topology.Link {
	return topology.Link{
		Src: src, Dst: dst, Protocol: "modbus",
		Transport: model.TransportTCP, ServerPort: 502,
		Events: events, Classes: classes,
		FirstSeen: seen, LastSeen: seen.Add(time.Minute),
	}
}

func TestBuildOrientsEdgesFromClientToServer(t *testing.T) {
	assets := []model.Asset{
		asset("srv", "10.0.0.3", model.RoleController, served("modbus", 120)),
		asset("hmi", "10.0.0.57", model.RoleOperator, spoke("modbus", 120, nil)),
	}
	assets[0].Level = model.Level{Value: 1, Confidence: 80, Reasons: []string{"serves modbus"}}
	assets[1].Level = model.Level{Value: 2, Confidence: 65}

	// The server answers first in the aggregate, which must not decide the
	// direction of the edge.
	g := topology.Build(assets, []topology.Link{
		link("10.0.0.3", "10.0.0.57", 60, map[model.Classification]int64{model.ClassRead: 60}),
		link("10.0.0.57", "10.0.0.3", 60, map[model.Classification]int64{model.ClassRead: 60}),
	}, topology.Options{})

	require.Len(t, g.Nodes, 2)
	require.Len(t, g.Edges, 1, "both directions of one conversation are one edge")
	edge := g.Edges[0]
	assert.Equal(t, "hmi", edge.Src)
	assert.Equal(t, "srv", edge.Dst)
	assert.True(t, edge.Directed)
	assert.EqualValues(t, 120, edge.Events)
	assert.Equal(t, "read", edge.Class)
	assert.Equal(t, uint16(502), edge.ServerPort)
	assert.Contains(t, edge.Href, "protocol=modbus")

	byID := map[string]topology.Node{}
	for _, n := range g.Nodes {
		byID[n.ID] = n
	}
	assert.Equal(t, topology.KindDevice, byID["srv"].Kind)
	assert.Equal(t, 1, byID["srv"].Level)
	assert.Equal(t, "serves modbus", byID["srv"].LevelNote)
	assert.Equal(t, "/assets/srv", byID["srv"].Href)
	assert.Equal(t, "10.0.0.0/24", byID["srv"].Subnet)
	assert.Equal(t, []string{"modbus"}, byID["srv"].Protocols)
}

func TestEdgeTakesTheMostConsequentialClass(t *testing.T) {
	assets := []model.Asset{
		asset("srv", "10.0.0.3", model.RoleController, served("modbus", 1000)),
		asset("hmi", "10.0.0.57", model.RoleOperator, spoke("modbus", 1000, nil)),
	}

	g := topology.Build(assets, []topology.Link{
		link("10.0.0.57", "10.0.0.3", 1000, map[model.Classification]int64{
			model.ClassRead: 999, model.ClassWrite: 1,
		}),
	}, topology.Options{})

	require.Len(t, g.Edges, 1)
	assert.Equal(t, "write", g.Edges[0].Class,
		"one write among a thousand reads is what matters about the edge")
	assert.EqualValues(t, 999, g.Edges[0].Classes["read"])
	assert.EqualValues(t, 1, g.Edges[0].Classes["write"])
}

// GOOSE publishes to a multicast group and nothing answers from it.
func TestMulticastDestinationBecomesAGroupNode(t *testing.T) {
	publisher := asset("ied", "00:00:23:06:30:fe", model.RoleController,
		served("goose", 451))
	publisher.IPs = nil
	publisher.MACs = []string{"00:00:23:06:30:fe"}

	g := topology.Build([]model.Asset{publisher}, []topology.Link{{
		Src: "00:00:23:06:30:fe", Dst: "01:0c:cd:01:00:00", Protocol: "goose",
		Transport: model.TransportEthernet, Events: 451,
		Classes: map[model.Classification]int64{model.ClassRead: 451},
	}}, topology.Options{})

	require.Len(t, g.Nodes, 2)
	var group topology.Node
	for _, n := range g.Nodes {
		if n.Kind == topology.KindGroup {
			group = n
		}
	}
	assert.Equal(t, "01:0c:cd:01:00:00", group.ID)
	assert.Equal(t, model.LevelUnknown, group.Level)
	require.Len(t, g.Edges, 1)
	assert.Equal(t, "ied", g.Edges[0].Src, "a publication runs from the publisher outwards")
}

func TestOneAssetWithSeveralAddressesIsOneNode(t *testing.T) {
	multi := asset("multi", "10.0.0.5", model.RoleController, served("modbus", 10))
	multi.IPs = []string{"10.0.0.5", "10.0.1.5"}
	multi.MACs = []string{"00:0c:29:11:22:33"}

	g := topology.Build([]model.Asset{multi}, []topology.Link{
		// Traffic between two addresses of the same device is no edge.
		link("10.0.0.5", "10.0.1.5", 4, nil),
	}, topology.Options{})

	require.Len(t, g.Nodes, 1)
	assert.Empty(t, g.Edges)
	assert.Equal(t, []string{"10.0.0.5", "10.0.1.5", "00:0c:29:11:22:33"}, g.Nodes[0].Addresses)
}

func TestIsolatedAssetsAreStillDrawn(t *testing.T) {
	g := topology.Build([]model.Asset{
		asset("lonely", "10.0.0.8", model.RoleUnknown),
	}, nil, topology.Options{})

	require.Len(t, g.Nodes, 1)
	assert.Equal(t, "lonely", g.Nodes[0].ID)
	assert.Empty(t, g.Edges)
	assert.Empty(t, g.Truncated)
}

func TestCapsKeepTheBusiestTrafficAndSaySo(t *testing.T) {
	var (
		assets []model.Asset
		links  []topology.Link
	)
	for i := range 10 {
		label := "10.0.0." + string(rune('1'+i))
		assets = append(assets, asset("a"+label, label, model.RoleController,
			served("modbus", 10)))
	}
	// The last pair is the busiest, so a cap of one edge has to keep it.
	for i := range 9 {
		links = append(links, link(assets[i].Label, assets[i+1].Label, int64(i+1), nil))
	}

	g := topology.Build(assets, links, topology.Options{MaxNodes: 4, MaxEdges: 1})
	assert.Len(t, g.Edges, 1)
	assert.EqualValues(t, 9, g.Edges[0].Events, "the busiest link survives the cap")
	assert.LessOrEqual(t, len(g.Nodes), 4)
	assert.Contains(t, g.Truncated, "left out by the graph cap")
}

func TestLevelAndSubnetGroups(t *testing.T) {
	assets := []model.Asset{
		asset("plc1", "192.168.0.10", model.RoleController, served("modbus", 10)),
		asset("plc2", "192.168.0.11", model.RoleController, served("modbus", 10)),
		asset("hmi", "10.0.0.57", model.RoleOperator, spoke("modbus", 10, nil)),
	}
	for i := range assets {
		assets[i].Level = topology.AssignLevels(assets)[assets[i].Key]
	}

	g := topology.Build(assets, []topology.Link{
		link("10.0.0.57", "192.168.0.10", 10, nil),
	}, topology.Options{})

	require.Len(t, g.Levels, 2)
	assert.Equal(t, 1, g.Levels[0].Level)
	assert.ElementsMatch(t, []string{"plc1", "plc2"}, g.Levels[0].Nodes)
	assert.Equal(t, 2, g.Levels[1].Level)
	assert.Equal(t, []string{"hmi"}, g.Levels[1].Nodes)

	require.Len(t, g.Subnets, 2)
	assert.Equal(t, "10.0.0.0/24", g.Subnets[0].CIDR)
	assert.Equal(t, "192.168.0.0/24", g.Subnets[1].CIDR)
	assert.ElementsMatch(t, []string{"plc1", "plc2"}, g.Subnets[1].Nodes)
	assert.False(t, g.Subnets[1].Observed, "no device reported a mask, so the prefix is assumed")
}

func TestCrossLevelReportsFlowsThatSkipALevel(t *testing.T) {
	assets := []model.Asset{
		asset("plc", "10.0.1.10", model.RoleController, served("modbus", 10)),
		asset("hmi", "10.0.2.10", model.RoleOperator, spoke("modbus", 10, nil)),
		asset("erp", "10.0.4.10", model.RoleUnknown),
		asset("quiet", "10.0.9.9", model.RoleUnknown),
	}
	assets[0].Level = model.Level{Value: 1, Confidence: 80}
	assets[1].Level = model.Level{Value: 2, Confidence: 65}
	assets[2].Level = model.Level{Value: 4, Confidence: 50}
	assets[3].Level = model.Level{Value: model.LevelUnknown}

	g := topology.Build(assets, []topology.Link{
		link("10.0.2.10", "10.0.1.10", 10, nil), // level 2 to 1: adjacent
		link("10.0.4.10", "10.0.1.10", 5, nil),  // level 4 to 1: three levels
		link("10.0.9.9", "10.0.1.10", 5, nil),   // unplaced: no claim
	}, topology.Options{})

	crossing := g.CrossLevel()
	require.Len(t, crossing, 1)
	assert.Equal(t, "erp", crossing[0].Src)
	assert.Equal(t, "plc", crossing[0].Dst)
}

// A PROFINET station states its address in a frame that has no IP layer, so
// the inventory holds it as an attribute. It still places the device.
func TestAnAddressADeviceStatedPlacesIt(t *testing.T) {
	stated := func(key, ip, mask string, protocols ...model.ProtocolUsage) model.Asset {
		a := asset(key, key, model.RoleUnknown, protocols...)
		a.IPs = nil
		a.MACs = []string{key}
		a.Attributes = []model.Attribute{
			{Field: "reported_address", Value: ip, Confidence: 60, Source: "profinet_dcp"},
			{Field: "netmask", Value: mask, Confidence: 60, Source: "profinet_dcp"},
		}
		return a
	}

	assets := []model.Asset{
		stated("00:11:22:33:44:01", "192.168.0.10", "255.255.0.0", served("profinet_dcp", 4)),
		stated("00:11:22:33:44:02", "192.168.1.11", "255.255.0.0", served("profinet_dcp", 4)),
		stated("00:11:22:33:44:03", "192.168.2.12", "255.255.0.0", served("profinet_dcp", 4)),
		stated("00:11:22:33:44:04", "192.168.3.13", "255.255.0.0"),
	}

	levels := topology.AssignLevels(assets)
	quiet := levels["00:11:22:33:44:04"]
	assert.Equal(t, topology.LevelBasicCtrl, quiet.Value)
	require.Len(t, quiet.Reasons, 1)
	assert.Contains(t, quiet.Reasons[0], "192.168.0.0/16",
		"the mask the devices reported decides the group, not the assumed prefix")

	// And the graph groups them in that subnet rather than leaving them out.
	for i := range assets {
		assets[i].Level = levels[assets[i].Key]
	}
	g := topology.Build(assets, nil, topology.Options{})
	require.Len(t, g.Subnets, 1)
	assert.Equal(t, "192.168.0.0/16", g.Subnets[0].CIDR)
	assert.True(t, g.Subnets[0].Observed, "a device reported this mask")
	assert.Len(t, g.Subnets[0].Nodes, 4)
}
