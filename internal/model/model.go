// Package model holds the core domain types shared by ingest, dissectors,
// inventory, topology, rules, store and the web layer.
package model

import "time"

// Classification is the protocol-independent meaning of an observed operation.
// Detection rules operate on the classification rather than on raw protocol
// function codes, so that one rule covers every protocol (CLAUDE.md,
// "Dissector contract").
type Classification string

// The closed set of classifications. Dissectors must map every function code
// they know to one of these.
const (
	ClassRead       Classification = "read"
	ClassWrite      Classification = "write"
	ClassControl    Classification = "control"
	ClassProgram    Classification = "program"
	ClassFirmware   Classification = "firmware"
	ClassDiagnostic Classification = "diagnostic"
	ClassDiscovery  Classification = "discovery"
	ClassOther      Classification = "other"
)

// Valid reports whether c is one of the defined classifications.
func (c Classification) Valid() bool {
	switch c {
	case ClassRead, ClassWrite, ClassControl, ClassProgram,
		ClassFirmware, ClassDiagnostic, ClassDiscovery, ClassOther:
		return true
	default:
		return false
	}
}

// Direction says whether a PDU travelled from client to server or back.
type Direction string

// Directions of a single PDU.
const (
	DirRequest  Direction = "request"
	DirResponse Direction = "response"
	DirUnknown  Direction = "unknown"
)

// Transport is the L4 protocol carrying a flow.
type Transport string

// Supported transports.
const (
	TransportTCP Transport = "tcp"
	TransportUDP Transport = "udp"
)

// Flow identifies one unidirectional conversation between two endpoints. It is
// the key of the communication matrix; aggregated counters live on the
// inventory side, not here.
type Flow struct {
	SrcMAC    string    `json:"src_mac,omitempty"`
	DstMAC    string    `json:"dst_mac,omitempty"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Transport Transport `json:"transport"`
	VLAN      []uint16  `json:"vlan,omitempty"` // outermost first, for QinQ
}

// Reverse returns the flow with source and destination swapped.
func (f Flow) Reverse() Flow {
	f.SrcMAC, f.DstMAC = f.DstMAC, f.SrcMAC
	f.SrcIP, f.DstIP = f.DstIP, f.SrcIP
	f.SrcPort, f.DstPort = f.DstPort, f.SrcPort
	return f
}

// Event is one decoded protocol operation. Every finding must be traceable to
// the event that produced it, so an event always carries its capture, packet
// index and timestamp.
type Event struct {
	CaptureID   string    `json:"capture_id,omitempty"`
	PacketIndex uint64    `json:"packet_index"`
	Timestamp   time.Time `json:"ts"`
	Flow        Flow      `json:"flow"`

	Protocol  string    `json:"protocol"`
	Direction Direction `json:"direction"`

	// Operation is the protocol's own name for the operation, e.g.
	// "ReadHoldingRegisters". FunctionCode is its numeric form; -1 when the
	// protocol has no such concept or the PDU could not be decoded.
	Operation    string         `json:"operation"`
	FunctionCode int            `json:"function_code"`
	Class        Classification `json:"class"`

	// Addressing. Nil when the operation carries no such field, which keeps
	// golden files free of meaningless zeroes.
	UnitID        *uint16 `json:"unit_id,omitempty"`
	TransactionID *uint32 `json:"transaction_id,omitempty"`
	Address       *uint32 `json:"address,omitempty"`
	Quantity      *uint32 `json:"quantity,omitempty"`

	// Exception is the protocol's error name when the PDU is an error reply.
	Exception string `json:"exception,omitempty"`

	// Identity holds device identity evidence for inventory enrichment, e.g.
	// {"vendor_name": "Wingpath Limited"}.
	Identity map[string]string `json:"identity,omitempty"`

	// Attrs holds protocol-specific detail that has no common field, e.g. a
	// Modbus diagnostics sub-function. Keys are snake_case.
	Attrs map[string]string `json:"attrs,omitempty"`

	// Malformed marks a PDU that could not be decoded. Error says why. Such
	// events are counted as parse errors and shown as "parse health"; they are
	// kept because crafted frames are themselves security-relevant evidence.
	Malformed bool   `json:"malformed,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Capture is one ingested capture file.
type Capture struct {
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	SHA256    string    `json:"sha256"`
	Bytes     int64     `json:"bytes"`
	Packets   uint64    `json:"packets"`
	LinkType  string    `json:"link_type"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Ptr returns a pointer to v. It keeps optional Event fields readable at the
// call site: model.Ptr(uint16(10)).
func Ptr[T any](v T) *T { return &v }
