// Package topology turns an asset inventory and the flows between its assets
// into the graph the GUI draws, and places each asset in a Purdue level.
//
// Both are inferences and both carry their reasons. A level an analyst cannot
// argue with is a level they cannot correct, and `CLAUDE.md` wants every
// inferred attribute overridable — which starts with it being readable.
//
// Nothing here looks at a packet: it works from the inventory and the flow
// aggregate, so the topology of a project is recomputed from stored evidence
// and never from a live network.
package topology

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/rom/otinv/internal/model"
)

// Confidence levels for the placements this package makes. They rank
// evidence; they are not probabilities.
const (
	// A device serving a control protocol is the strongest evidence there is:
	// it is the thing being controlled.
	confidenceServesControl = 80
	// A station that programs controllers acts from the engineering level.
	confidencePrograms = 70
	// A station that polls controllers supervises them.
	confidencePolls = 65
	// One protocol whose level the reference model leaves open.
	confidenceSupervisory = 45
	// Everyone else in the subnet agrees, which is an argument but not
	// evidence about this device.
	confidenceSubnet = 40
)

// The levels of the Purdue reference model this package assigns.
const (
	LevelProcess     = 0 // field instrumentation, not visible in IP traffic
	LevelBasicCtrl   = 1 // PLC, RTU, IED
	LevelSupervisory = 2 // HMI, SCADA, engineering stations
	LevelOperations  = 3 // historians, MES, aggregation servers
	LevelEnterprise  = 4 // enterprise IT
)

// controlProtocols are the protocols whose *server* is the device being
// controlled, so serving one places an asset at level 1.
//
// A protocol is listed here because the server side of it is a controller,
// not because the protocol is industrial: OPC UA is deliberately absent,
// since its server is as often an aggregation server at level 3 as it is an
// embedded one in a PLC.
var controlProtocols = map[string]bool{
	"modbus":       true,
	"dnp3":         true,
	"s7comm":       true,
	"iec104":       true,
	"mms":          true,
	"goose":        true,
	"enip":         true,
	"profinet_dcp": true,
	"bacnet":       true,
}

// supervisoryProtocols are protocols whose server sits above the control
// level in the reference model. The placement is weaker than a control
// protocol's, and its reason says so.
var supervisoryProtocols = map[string]int{
	"opcua": LevelOperations,
}

// AssignLevels places every asset in a Purdue level, returning the placement
// by asset key.
//
// Placement follows CLAUDE.md: the role first, then the subnet. The role is
// what the asset was observed doing, so it decides where it can be decided;
// the subnet only places assets nothing else placed, and says so.
func AssignLevels(assets []model.Asset) map[string]model.Level {
	out := make(map[string]model.Level, len(assets))
	for _, a := range assets {
		out[a.Key] = levelFromBehaviour(a)
	}
	applySubnetMajority(assets, out)
	return out
}

// levelFromBehaviour places one asset from what it did.
func levelFromBehaviour(a model.Asset) model.Level {
	unknown := model.Level{Value: model.LevelUnknown}

	if a.IsGateway {
		// A forwarding device is on both sides of the boundary it forwards
		// across, so putting it in one level would be a claim about traffic
		// rather than about the device.
		return model.Level{
			Value:      model.LevelUnknown,
			Confidence: 0,
			Reasons: []string{fmt.Sprintf(
				"forwards for %d addresses, so it spans levels rather than sitting in one",
				len(a.IPs))},
		}
	}

	var (
		control     []string
		supervisory []string
		highest     = model.LevelUnknown
	)
	for _, p := range a.ServerProtocols() {
		level, above := supervisoryProtocols[p.Protocol]
		switch {
		case controlProtocols[p.Protocol]:
			control = append(control, fmt.Sprintf("serves %s (%d operations observed)",
				p.Protocol, p.Events))
		case above:
			supervisory = append(supervisory, p.Protocol)
			if level > highest {
				highest = level
			}
		}
	}
	if len(control) > 0 {
		return model.Level{
			Value:      LevelBasicCtrl,
			Confidence: confidenceServesControl,
			Reasons:    control,
		}
	}
	if len(supervisory) > 0 {
		return model.Level{
			Value:      highest,
			Confidence: confidenceSupervisory,
			Reasons: []string{fmt.Sprintf(
				"serves %s, which the reference model places above the control level; "+
					"an embedded server in a controller would belong at level %d instead",
				strings.Join(supervisory, ", "), LevelBasicCtrl)},
		}
	}

	// Nothing served, so the asset is placed by what it asks of others.
	var (
		programs []string
		polls    []string
	)
	for _, p := range a.Protocols {
		if p.Side != "client" {
			continue
		}
		if _, above := supervisoryProtocols[p.Protocol]; !controlProtocols[p.Protocol] && !above {
			continue
		}
		if p.Classes[model.ClassProgram] > 0 || p.Classes[model.ClassFirmware] > 0 {
			programs = append(programs, fmt.Sprintf(
				"programs %s devices (%d program, %d firmware operations)",
				p.Protocol, p.Classes[model.ClassProgram], p.Classes[model.ClassFirmware]))
			continue
		}
		polls = append(polls, fmt.Sprintf("polls %s devices (%d operations observed)",
			p.Protocol, p.Events))
	}
	switch {
	case len(programs) > 0:
		return model.Level{
			Value:      LevelSupervisory,
			Confidence: confidencePrograms,
			Reasons:    append(programs, polls...),
		}
	case len(polls) > 0:
		return model.Level{
			Value:      LevelSupervisory,
			Confidence: confidencePolls,
			Reasons:    polls,
		}
	}
	return unknown
}

// applySubnetMajority places the assets behaviour could not place, from the
// level their neighbours were placed in.
//
// This is the weakest inference here and the one most worth having: a device
// that only answered an ARP sits in a subnet full of controllers, and saying
// so is more useful than saying nothing — as long as the reason makes clear
// that the evidence is about the subnet and not about the device.
func applySubnetMajority(assets []model.Asset, levels map[string]model.Level) {
	type tally struct {
		counts map[int]int
		total  int
	}
	bySubnet := map[string]*tally{}

	for _, a := range assets {
		level, ok := levels[a.Key]
		if !ok || !level.Known() {
			continue
		}
		for _, net := range subnetsOf(a) {
			t := bySubnet[net.CIDR]
			if t == nil {
				t = &tally{counts: map[int]int{}}
				bySubnet[net.CIDR] = t
			}
			t.counts[level.Value]++
			t.total++
		}
	}

	for _, a := range assets {
		if level := levels[a.Key]; level.Known() || len(level.Reasons) > 0 {
			// Already placed, or deliberately left unplaced with a reason.
			continue
		}
		for _, net := range subnetsOf(a) {
			t := bySubnet[net.CIDR]
			if t == nil || t.total == 0 {
				continue
			}
			best, count := majority(t.counts)
			if count*2 <= t.total {
				continue // no majority: guessing from a tie says nothing
			}
			levels[a.Key] = model.Level{
				Value:      best,
				Confidence: confidenceSubnet,
				Reasons: []string{fmt.Sprintf(
					"%d of the %d placed devices in %s are level %d, and nothing was "+
						"observed about this one's own behaviour",
					count, t.total, net.CIDR, best)},
			}
			break
		}
	}
}

func majority(counts map[int]int) (level, count int) {
	levels := make([]int, 0, len(counts))
	for l := range counts {
		levels = append(levels, l)
	}
	sort.Ints(levels)
	for _, l := range levels {
		if counts[l] > count {
			level, count = l, counts[l]
		}
	}
	return level, count
}

// Subnet is an address group a node belongs to.
type Subnet struct {
	// CIDR is the group in prefix form, e.g. "192.168.0.0/24".
	CIDR string
	// Observed is true when a device told the network its own netmask — a
	// PROFINET DCP IP parameter block, for example. Otherwise the prefix is
	// the assumed one below, because a mask cannot be observed from an
	// address alone.
	Observed bool
}

// AssumedPrefix is the prefix length used for an IPv4 address whose netmask
// was never observed, and AssumedPrefix6 the same for IPv6.
//
// A netmask is not in a packet's addresses, so grouping has to assume one.
// A /24 is the convention these networks are built on; where a capture
// carries a device's own mask the observed one is used instead, and
// CLAUDE.md's zone settings will let the analyst define the real ones.
const (
	AssumedPrefix  = 24
	AssumedPrefix6 = 64
)

// subnetsOf returns the address groups an asset belongs to, most trustworthy
// first: a netmask the device reported, then the assumed prefix.
func subnetsOf(a model.Asset) []Subnet {
	var out []Subnet
	seen := map[string]bool{}

	mask := reportedNetmask(a)
	for _, raw := range addressesOf(a) {
		ip := net.ParseIP(raw)
		if ip == nil {
			continue
		}
		for _, s := range groupsFor(ip, mask) {
			if !seen[s.CIDR] {
				seen[s.CIDR] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// addressesOf returns the addresses an asset can be grouped by: the ones it
// was seen using, and the one it stated as its own.
//
// A PROFINET station answers a DCP Identify with its IP configuration over a
// frame that has no IP layer at all, so the address is in the inventory as an
// attribute rather than as traffic. It is still the device saying where it
// lives, which is exactly what a subnet grouping needs.
func addressesOf(a model.Asset) []string {
	out := append([]string(nil), a.IPs...)
	for _, at := range a.Attributes {
		if at.Field == "reported_address" && at.Value != "" {
			out = append(out, at.Value)
		}
	}
	return out
}

// groupsFor renders the groups one address belongs to.
func groupsFor(ip net.IP, mask net.IPMask) []Subnet {
	var out []Subnet
	if v4 := ip.To4(); v4 != nil {
		if mask != nil {
			if ones, bits := mask.Size(); bits == 32 && ones > 0 && ones < 32 {
				out = append(out, Subnet{
					CIDR:     (&net.IPNet{IP: v4.Mask(mask), Mask: mask}).String(),
					Observed: true,
				})
			}
		}
		assumed := net.CIDRMask(AssumedPrefix, 32)
		out = append(out, Subnet{
			CIDR: (&net.IPNet{IP: v4.Mask(assumed), Mask: assumed}).String(),
		})
		return out
	}
	assumed := net.CIDRMask(AssumedPrefix6, 128)
	return append(out, Subnet{
		CIDR: (&net.IPNet{IP: ip.Mask(assumed), Mask: assumed}).String(),
	})
}

// reportedNetmask returns the netmask an asset told the network about, if a
// dissector recorded one.
func reportedNetmask(a model.Asset) net.IPMask {
	for _, at := range a.Attributes {
		if at.Field != "netmask" {
			continue
		}
		ip := net.ParseIP(at.Value)
		if ip == nil {
			return nil
		}
		v4 := ip.To4()
		if v4 == nil {
			return nil
		}
		mask := net.IPMask(v4)
		if ones, bits := mask.Size(); ones == 0 || bits != 32 {
			// A value that is not a contiguous mask is not one; Size reports
			// zero for those.
			return nil
		}
		return mask
	}
	return nil
}
