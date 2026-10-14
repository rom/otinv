package model

import "time"

// Project is one analysis workspace, backed by its own database file.
type Project struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// RoleName is a device role inferred from observed behaviour.
type RoleName string

// The roles otinv infers. More arrive with the remaining Tier 1 protocols.
const (
	RoleUnknown     RoleName = "unknown"
	RoleController  RoleName = "plc_rtu_ied"
	RoleOperator    RoleName = "hmi_scada"
	RoleEngineering RoleName = "engineering_workstation"
	RoleGateway     RoleName = "gateway"
)

// Role is an inferred role with the confidence and the reasons behind it.
// Nothing is inferred without a reason the analyst can read.
type Role struct {
	Name       RoleName `json:"name"`
	Confidence int      `json:"confidence"`
	Reasons    []string `json:"reasons,omitempty"`
}

// LevelUnknown marks an asset no Purdue level could be inferred for. A
// forwarding device spans levels rather than sitting in one, and an asset
// nothing was observed about sits nowhere until the analyst says otherwise.
const LevelUnknown = -1

// Level is an inferred Purdue level with the confidence and the reasons
// behind it. The reference model's levels are 0 (process), 1 (basic control),
// 2 (area supervisory), 3 (site operations) and 4 (enterprise).
//
// A level is an inference like any other, so it carries why: an analyst who
// cannot see the reasoning cannot correct it (CLAUDE.md, "Purdue level
// assignment: inferred from role + subnet, overridable by the user").
type Level struct {
	Value      int      `json:"value"`
	Confidence int      `json:"confidence"`
	Reasons    []string `json:"reasons,omitempty"`
}

// Known reports whether a level was inferred at all.
//
// A zero Level is an absence rather than level 0: the lowest level of the
// reference model is a claim like any other, so it counts as one only when it
// arrives with the confidence or the reasons that make it one. Without that
// rule an asset nobody placed would read as a field device.
func (l Level) Known() bool {
	return l.Value != LevelUnknown && (l.Confidence > 0 || len(l.Reasons) > 0)
}

// Evidence points at the single observation that produced an inference, so
// that every inferred field can be traced back to a packet.
type Evidence struct {
	CaptureID    string    `json:"capture_id"`
	PacketIndex  uint64    `json:"packet_index"`
	Timestamp    time.Time `json:"ts"`
	Protocol     string    `json:"protocol"`
	Operation    string    `json:"operation,omitempty"`
	FunctionCode int       `json:"function_code,omitempty"`
	SrcIP        string    `json:"src_ip,omitempty"`
	DstIP        string    `json:"dst_ip,omitempty"`
}

// Attribute is one inferred property of an asset: what it is, how sure otinv
// is, where the value came from and which packet proves it.
type Attribute struct {
	Field      string   `json:"field"`
	Value      string   `json:"value"`
	Confidence int      `json:"confidence"`
	Source     string   `json:"source"`
	Evidence   Evidence `json:"evidence"`
}

// Address is one observed (MAC, IP, VLAN) tuple with the window it was seen
// in. An asset keeps every tuple rather than collapsing them, because that
// history is what makes a routed segment or a re-addressed device readable.
type Address struct {
	MAC       string    `json:"mac,omitempty"`
	IP        string    `json:"ip,omitempty"`
	VLAN      *uint16   `json:"vlan,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Events    uint64    `json:"events"`
}

// ProtocolUsage is how an asset used one protocol, as client or as server.
type ProtocolUsage struct {
	Protocol  string                    `json:"protocol"`
	Side      string                    `json:"side"` // "server" or "client"
	Events    uint64                    `json:"events"`
	Classes   map[Classification]uint64 `json:"classes,omitempty"`
	UnitIDs   []uint16                  `json:"unit_ids,omitempty"`
	FirstSeen time.Time                 `json:"first_seen"`
	LastSeen  time.Time                 `json:"last_seen"`
}

// Asset is one device observed in the captures.
//
// Identity is keyed on the MAC when one was observed and on the IP otherwise
// (CLAUDE.md, "Inventory and topology"). Key is that identity in string form
// and is stable across re-ingests, so the GUI can deep-link to an asset.
type Asset struct {
	Key       string    `json:"key"`
	Label     string    `json:"label"`
	MACs      []string  `json:"macs,omitempty"`
	IPs       []string  `json:"ips,omitempty"`
	VLANs     []uint16  `json:"vlans,omitempty"`
	Addresses []Address `json:"addresses,omitempty"`

	Role       Role            `json:"role"`
	Level      Level           `json:"level"`
	Attributes []Attribute     `json:"attributes,omitempty"`
	Protocols  []ProtocolUsage `json:"protocols,omitempty"`

	// IsGateway marks a MAC seen fronting many IPs, such as a router. Assets
	// behind it are kept apart instead of being merged into one device.
	IsGateway bool `json:"is_gateway"`

	Events    uint64    `json:"events"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Vendor returns the asset's vendor attribute, if one was inferred.
func (a *Asset) Vendor() string {
	for _, at := range a.Attributes {
		if at.Field == "vendor" {
			return at.Value
		}
	}
	return ""
}

// ServerProtocols returns the protocols the asset served, which is what makes
// it interesting as a control device.
func (a *Asset) ServerProtocols() []ProtocolUsage {
	var out []ProtocolUsage
	for _, p := range a.Protocols {
		if p.Side == "server" {
			out = append(out, p)
		}
	}
	return out
}
