// Package inventory turns decoded events into an asset inventory.
//
// Identity follows CLAUDE.md: the MAC is the primary key when one was
// observed and the IP is the fallback. Every observed (MAC, IP, VLAN) tuple is
// kept with its time range, because a MAC fronting many IPs is a router rather
// than one device, and collapsing those addresses would invent a device that
// does not exist.
//
// Nothing is inferred without a reason the analyst can read and a packet that
// proves it.
package inventory

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/oui"
	"github.com/rom/otinv/internal/topology"
)

// DefaultGatewayIPThreshold is how many distinct IP addresses behind one MAC
// make it a forwarding device rather than a multi-homed host. Two or three
// addresses on one MAC is an ordinary dual-homed controller.
const DefaultGatewayIPThreshold = 4

// Confidence levels for the inferences this package makes. They are
// deliberately coarse: they rank evidence, they are not probabilities.
const (
	confidenceServedProtocol = 80
	confidencePolledServer   = 60
	confidenceProgrammed     = 70
	confidenceGateway        = 75
	// The IEEE register names the maker of the network card with certainty,
	// so that is held high; what the card says about the device it is fitted
	// in is held below every protocol identity, because an OEM commonly
	// builds somebody else's network chip into its controller.
	confidenceNICVendor     = 85
	confidenceVendorFromMAC = 55
)

// Builder accumulates events and produces assets. It is not safe for
// concurrent use; ingest feeds one builder from its sink.
type Builder struct {
	gatewayIPThreshold int
	tuples             map[tupleKey]*tupleStats
	order              []tupleKey // first-seen order, for deterministic output
	macIPs             map[string]map[string]bool
}

// Option configures a Builder.
type Option func(*Builder)

// WithGatewayIPThreshold overrides how many IPs behind one MAC make it a
// gateway.
func WithGatewayIPThreshold(n int) Option {
	return func(b *Builder) {
		if n > 0 {
			b.gatewayIPThreshold = n
		}
	}
}

// New returns an empty Builder.
func New(opts ...Option) *Builder {
	b := &Builder{
		gatewayIPThreshold: DefaultGatewayIPThreshold,
		tuples:             map[tupleKey]*tupleStats{},
		macIPs:             map[string]map[string]bool{},
	}
	for _, o := range opts {
		o(b)
	}
	return b
}

// tupleKey is one observed address tuple.
type tupleKey struct {
	mac     string
	ip      string
	vlan    uint16
	hasVLAN bool
}

// protoKey identifies one protocol used from one side.
type protoKey struct {
	protocol string
	side     string
}

type protoStats struct {
	events      uint64
	classes     map[model.Classification]uint64
	units       map[uint16]bool
	first, last time.Time
}

type attrCandidate struct {
	field      string
	value      string
	confidence int
	source     string
	evidence   model.Evidence
}

type tupleStats struct {
	events      uint64
	first, last time.Time
	protocols   map[protoKey]*protoStats
	attrs       []attrCandidate
	// macAttrs is what the MAC itself says. It is kept apart from attrs
	// because it describes the card the frames carried, which for a tuple
	// reached through a router is the router's card and not the host's.
	macAttrs []attrCandidate
}

// Add folds one event into the inventory. Both endpoints of the event are
// recorded, because an event is evidence about both of them.
func (b *Builder) Add(e model.Event) {
	var vlan uint16
	hasVLAN := false
	if len(e.Flow.VLAN) > 0 {
		vlan, hasVLAN = e.Flow.VLAN[0], true
	}

	src := tupleKey{
		mac: unicastMAC(e.Flow.SrcMAC), ip: unicastIP(e.Flow.SrcIP),
		vlan: vlan, hasVLAN: hasVLAN,
	}
	dst := tupleKey{
		mac: unicastMAC(e.Flow.DstMAC), ip: unicastIP(e.Flow.DstIP),
		vlan: vlan, hasVLAN: hasVLAN,
	}

	// A frame that could not be decoded still proves these two hosts
	// exchanged bytes, but says nothing about what either of them is: no
	// protocol usage, no identity, and so no role.
	srcSide, dstSide := "", ""
	if !e.Malformed {
		srcSide, dstSide = sides(e)
	}

	b.observe(src, e, srcSide)
	b.observe(dst, e, dstSide)

	// Identity in a PDU describes the device acting as the server.
	if !e.Malformed && len(e.Identity) > 0 {
		switch {
		case srcSide == "server":
			b.enrich(src, e)
		case dstSide == "server":
			b.enrich(dst, e)
		}
	}
}

// sides reports which endpoint of an event is the server and which the
// client.
//
// The port the session is served on decides it, because a PDU's direction can
// invert mid-session: during an S7 block download the CPU sends the jobs that
// fetch each block, so the device would otherwise look like a client of
// itself. Only when the port says nothing — both ends on the same port, or
// none known — does the direction of this PDU decide.
func sides(e model.Event) (src, dst string) {
	port := e.ServerPort
	switch {
	case port != 0 && e.Flow.SrcPort == port && e.Flow.DstPort != port:
		return "server", "client"
	case port != 0 && e.Flow.DstPort == port && e.Flow.SrcPort != port:
		return "client", "server"
	}

	switch e.Direction {
	case model.DirRequest:
		return "client", "server"
	case model.DirResponse:
		return "server", "client"
	default:
		return "", ""
	}
}

func (b *Builder) observe(k tupleKey, e model.Event, side string) {
	if k.mac == "" && k.ip == "" {
		return
	}

	st := b.tuples[k]
	if st == nil {
		st = &tupleStats{
			first:     e.Timestamp,
			last:      e.Timestamp,
			protocols: map[protoKey]*protoStats{},
		}
		b.tuples[k] = st
		b.order = append(b.order, k)
		st.macAttrs = macVendor(k.mac, e)
	}
	st.events++
	if e.Timestamp.Before(st.first) {
		st.first = e.Timestamp
	}
	if e.Timestamp.After(st.last) {
		st.last = e.Timestamp
	}

	if k.mac != "" && k.ip != "" {
		if b.macIPs[k.mac] == nil {
			b.macIPs[k.mac] = map[string]bool{}
		}
		b.macIPs[k.mac][k.ip] = true
	}

	if side == "" {
		return
	}
	pk := protoKey{protocol: e.Protocol, side: side}
	ps := st.protocols[pk]
	if ps == nil {
		ps = &protoStats{
			classes: map[model.Classification]uint64{},
			units:   map[uint16]bool{},
			first:   e.Timestamp,
			last:    e.Timestamp,
		}
		st.protocols[pk] = ps
	}
	ps.events++
	if e.Class != "" {
		ps.classes[e.Class]++
	}
	if e.Timestamp.Before(ps.first) {
		ps.first = e.Timestamp
	}
	if e.Timestamp.After(ps.last) {
		ps.last = e.Timestamp
	}
	// A unit id addresses a device behind the server, so it belongs to the
	// server's view of the protocol.
	if side == "server" && e.UnitID != nil {
		ps.units[*e.UnitID] = true
	}
}

// identityTarget maps a dissector's identity key to the asset fields it
// supports, with the confidence that source deserves.
//
// Structured objects, such as the Read Device Identification objects, outrank
// free-text fields whose layout the specification leaves to the vendor.
var identityTargets = map[string][]struct {
	field      string
	confidence int
}{
	"vendor_name":           {{"vendor", 90}},
	"product_code":          {{"product_code", 90}},
	"product_name":          {{"product_name", 90}},
	"model_name":            {{"model", 90}},
	"major_minor_revision":  {{"firmware_revision", 90}},
	"user_application_name": {{"application", 85}},
	"vendor_url":            {{"vendor_url", 85}},
	// Report Server ID is device specific free text that in practice carries
	// the vendor, so it supports both fields at a lower confidence.
	"report_server_id": {{"report_server_id", 75}, {"vendor", 70}},

	// S7 CPUs answer an SZL read with their own type name, order number,
	// serial number and firmware version. A device naming itself from a
	// structured list is the best evidence there is, short of asking it
	// actively, which this tool never does.
	"model":             {{"model", 95}},
	"serial_number":     {{"serial_number", 95}},
	"firmware_revision": {{"firmware_revision", 95}},
	"order_number":      {{"order_number", 95}},
	// The station name and module name are what an engineer typed into the
	// project, so they describe the installation rather than the hardware.
	"plc_name":    {{"name", 85}},
	"module_name": {{"module_name", 85}},
	// Rack and slot come from the connection the CPU confirmed, so they say
	// where in the chassis it answered.
	"rack": {{"rack", 80}},
	"slot": {{"slot", 80}},

	// An MMS device answers Identify with its vendor, model and revision,
	// which is the same kind of structured self-description as an SZL read.
	"revision": {{"firmware_revision", 90}},
	// An OPC UA server describes itself in every endpoint description it
	// returns: the URI that identifies the application, the product it is
	// and the name it goes by. The endpoint URL a client connects to names
	// the host and port the server is known by.
	"application_uri":  {{"application_uri", 90}},
	"application_name": {{"name", 85}},
	"product_uri":      {{"product_uri", 85}},
	"endpoint_url":     {{"endpoint_url", 80}},
	// A PROFINET station answering a DCP Identify states the name an
	// engineer gave it, which is the name PROFINET itself addresses it by,
	// the part it plays in the system — IO device, IO controller or IO
	// supervisor — and its vendor and device identifiers. A device stating
	// its own role is better evidence than any amount of traffic watching.
	"station_name": {{"name", 90}},
	// The netmask and default gateway a station states are facts about the
	// network it is on rather than about the device, which is exactly what
	// the topology needs to group a subnet without assuming a prefix.
	"reported_netmask": {{"netmask", 60}},
	"reported_gateway": {{"gateway_address", 60}},
	"device_role":      {{"device_role", 90}},
	"device_id":        {{"device_id", 85}},
	// A BACnet device answers a read of its device object with the name an
	// engineer gave it, where it is installed, and what software it runs.
	// The answer echoes the property it is for, so this arrives without any
	// request to pair it with.
	"device_name":          {{"name", 85}},
	"application_software": {{"application", 85}},
	"location":             {{"location", 80}},
	"device_instance":      {{"device_instance", 85}},
	// A CIP device states its ODVA device profile — what kind of thing it
	// is — and the vendor identifier ODVA assigned its manufacturer. Both
	// are the device's own answer about itself, which is the strongest
	// evidence available without asking it anything.
	"device_type": {{"device_type", 90}},
	"vendor_id":   {{"vendor_id", 90}},
	// In IEC 61850 the MMS domain is the logical device, which is the name
	// the substation configuration gave this server. It is kept as its own
	// field rather than as the asset's name, because one device commonly
	// hosts several logical devices and none of them is the device.
	"logical_device": {{"logical_device", 85}},
}

func (b *Builder) enrich(k tupleKey, e model.Event) {
	st := b.tuples[k]
	if st == nil {
		return
	}
	evidence := model.Evidence{
		CaptureID:    e.CaptureID,
		PacketIndex:  e.PacketIndex,
		Timestamp:    e.Timestamp,
		Protocol:     e.Protocol,
		Operation:    e.Operation,
		FunctionCode: e.FunctionCode,
		SrcIP:        e.Flow.SrcIP,
		DstIP:        e.Flow.DstIP,
	}

	keys := make([]string, 0, len(e.Identity))
	for key := range e.Identity {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := e.Identity[key]
		if value == "" {
			continue
		}
		targets, known := identityTargets[key]
		if !known {
			// An identity field no mapping knows about is still evidence;
			// keep it under its own name rather than dropping it.
			targets = []struct {
				field      string
				confidence int
			}{{key, 60}}
		}
		for _, t := range targets {
			st.attrs = append(st.attrs, attrCandidate{
				field:      t.field,
				value:      value,
				confidence: t.confidence,
				source:     e.Protocol + "_" + e.Operation,
				evidence:   evidence,
			})
		}
	}
}

// Assets builds the inventory. Calling it twice gives the same answer.
func (b *Builder) Assets() []model.Asset {
	gateways := b.gatewayMACs()

	assets := map[string]*model.Asset{}
	accs := map[string]*assetAcc{}
	var keyOrder []string

	get := func(key string) (*model.Asset, *assetAcc) {
		if a, ok := assets[key]; ok {
			return a, accs[key]
		}
		a := &model.Asset{Key: key}
		assets[key] = a
		accs[key] = &assetAcc{
			protocols: map[protoKey]*protoStats{},
			macs:      map[string]bool{},
			ips:       map[string]bool{},
			vlans:     map[uint16]bool{},
		}
		keyOrder = append(keyOrder, key)
		return a, accs[key]
	}

	for _, tk := range b.order {
		st := b.tuples[tk]
		isGateway := tk.mac != "" && gateways[tk.mac]

		key := assetKey(tk, isGateway)
		if key == "" {
			continue
		}
		a, ac := get(key)
		mergeTuple(a, ac, tk, st, isGateway)

		// The forwarding device itself is an asset too, separate from the
		// hosts behind it. It gets the addresses it was seen with but not the
		// addresses it merely forwarded for, and none of their operations.
		if isGateway {
			gw, gwAcc := get("mac:" + tk.mac)
			gw.IsGateway = true
			gwAcc.macs[tk.mac] = true
			addAddress(gw, model.Address{
				MAC:       tk.mac,
				Events:    st.events,
				FirstSeen: st.first,
				LastSeen:  st.last,
			})
			gwAcc.attrs = append(gwAcc.attrs, st.macAttrs...)
			gw.Events += st.events
			widenSeen(gw, st.first, st.last)
		}
	}

	out := make([]model.Asset, 0, len(assets))
	for _, key := range keyOrder {
		a := assets[key]
		ac := accs[key]

		a.MACs = sortedKeys(ac.macs)
		a.IPs = sortedKeys(ac.ips)
		a.VLANs = sortedVLANs(ac.vlans)
		a.Label = label(a)
		a.Protocols = buildProtocols(ac.protocols)
		a.Attributes = buildAttributes(ac.attrs)
		a.Role = b.inferRole(a, len(b.macIPs[firstOf(a.MACs)]))
		// A level needs the whole inventory, so Rebuild places the assets
		// once they are all built. Until then nothing is placed, which is
		// not the same as being placed at level 0.
		a.Level = model.Level{Value: model.LevelUnknown}
		out = append(out, *a)
	}

	// Busiest first, then by key: a stable order the GUI and the golden files
	// can rely on.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Events != out[j].Events {
			return out[i].Events > out[j].Events
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// gatewayMACs returns the MACs seen fronting enough distinct IPs to be
// forwarding for them.
func (b *Builder) gatewayMACs() map[string]bool {
	out := map[string]bool{}
	for mac, ips := range b.macIPs {
		if len(ips) >= b.gatewayIPThreshold {
			out[mac] = true
		}
	}
	return out
}

// unicastMAC drops a group address, which is never one device.
//
// A multicast or broadcast destination names a subscription, not a machine:
// GOOSE and Sampled Values publish to 01:0c:cd:01:00:00 and its neighbours,
// and ARP and the discovery protocols broadcast. An inventory that listed
// those as assets would invent a device for every data set a substation
// publishes.
func unicastMAC(mac string) string {
	// The group bit is the least significant bit of the first octet, which in
	// the usual notation is the low bit of the second hex digit.
	if len(mac) < 2 {
		return mac
	}
	first, err := strconv.ParseUint(mac[:2], 16, 8)
	if err != nil || first&0x01 == 0 {
		return mac
	}
	return ""
}

// macVendor reads what the IEEE register says about an address.
//
// It is the one piece of identity that costs nothing but the frame header:
// the block a MAC was handed out from belongs to whoever made the card, which
// otinv embeds rather than asking anybody. Two attributes come out of it,
// because they are two different claims. The card's maker is a fact about the
// hardware and is recorded as such; what that implies about the device is a
// guess, and ranks below every identity a device states about itself, so that
// a Siemens CPU with a third-party network chip is still a Siemens CPU — and
// so that the difference between the two stays visible in the GUI.
//
// A locally administered address, a group address, a block whose holder the
// IEEE does not publish and a block the IEEE subdivides beyond what the
// embedded register lists all name nobody, and yield nothing.
func macVendor(mac string, e model.Event) []attrCandidate {
	if mac == "" {
		return nil
	}
	v, ok := oui.Lookup(mac)
	if !ok {
		return nil
	}

	evidence := model.Evidence{
		CaptureID:   e.CaptureID,
		PacketIndex: e.PacketIndex,
		Timestamp:   e.Timestamp,
		Protocol:    e.Protocol,
		Operation:   e.Operation,
		SrcIP:       e.Flow.SrcIP,
		DstIP:       e.Flow.DstIP,
	}
	source := fmt.Sprintf("ieee_oui_%s", strings.ReplaceAll(v.Prefix, ":", ""))
	return []attrCandidate{{
		field:      "nic_vendor",
		value:      v.Name,
		confidence: confidenceNICVendor,
		source:     source,
		evidence:   evidence,
	}, {
		field:      "vendor",
		value:      v.Name,
		confidence: confidenceVendorFromMAC,
		source:     source,
		evidence:   evidence,
	}}
}

// unicastIP drops an address that names a group of machines rather than one.
//
// The discovery protocols ask a whole segment at once: a CIP client finds
// controllers by broadcasting ListIdentity to 255.255.255.255 on UDP 44818,
// and mDNS and NTP use multicast the same way. The reply comes from one
// device and is evidence about it; the question was addressed to nobody in
// particular, and an asset for 255.255.255.255 would be an invention.
//
// A subnet directed broadcast cannot be recognised without knowing the mask,
// so it is left alone: inventing a mask would be the worse guess.
func unicastIP(addr string) string {
	if addr == "" {
		return ""
	}
	ip := net.ParseIP(addr)
	switch {
	case ip == nil:
		return addr
	case ip.IsMulticast(), ip.Equal(net.IPv4bcast), ip.IsUnspecified():
		return ""
	default:
		return addr
	}
}

// assetKey is the identity of an observed tuple: the MAC when it belongs to
// one device, the IP when the MAC is forwarding for many.
func assetKey(tk tupleKey, isGateway bool) string {
	switch {
	case tk.mac != "" && !isGateway:
		return "mac:" + tk.mac
	case tk.ip != "":
		return "ip:" + tk.ip
	case tk.mac != "":
		return "mac:" + tk.mac
	default:
		return ""
	}
}

// assetAcc is the per-asset accumulation that the model type does not carry.
type assetAcc struct {
	protocols map[protoKey]*protoStats
	attrs     []attrCandidate
	macs      map[string]bool
	ips       map[string]bool
	vlans     map[uint16]bool
}

func mergeTuple(a *model.Asset, ac *assetAcc, tk tupleKey, st *tupleStats, viaGateway bool) {
	addr := model.Address{
		MAC:       tk.mac,
		IP:        tk.ip,
		Events:    st.events,
		FirstSeen: st.first,
		LastSeen:  st.last,
	}
	if tk.hasVLAN {
		addr.VLAN = model.Ptr(tk.vlan)
	}
	addAddress(a, addr)

	// A MAC that forwards for many IPs is not this host's own MAC, so it stays
	// in the address tuple as evidence of how the host was reached without
	// being claimed as the host's address.
	if tk.mac != "" && !viaGateway {
		ac.macs[tk.mac] = true
	}
	if tk.ip != "" {
		ac.ips[tk.ip] = true
	}
	if tk.hasVLAN {
		ac.vlans[tk.vlan] = true
	}

	a.Events += st.events
	widenSeen(a, st.first, st.last)

	for pk, ps := range st.protocols {
		dst := ac.protocols[pk]
		if dst == nil {
			dst = &protoStats{
				classes: map[model.Classification]uint64{},
				units:   map[uint16]bool{},
				first:   ps.first,
				last:    ps.last,
			}
			ac.protocols[pk] = dst
		}
		dst.events += ps.events
		for c, n := range ps.classes {
			dst.classes[c] += n
		}
		for u := range ps.units {
			dst.units[u] = true
		}
		if ps.first.Before(dst.first) {
			dst.first = ps.first
		}
		if ps.last.After(dst.last) {
			dst.last = ps.last
		}
	}
	ac.attrs = append(ac.attrs, st.attrs...)
	if !viaGateway {
		ac.attrs = append(ac.attrs, st.macAttrs...)
	}
}

func addAddress(a *model.Asset, addr model.Address) {
	for i := range a.Addresses {
		existing := &a.Addresses[i]
		if existing.MAC == addr.MAC && existing.IP == addr.IP && sameVLAN(existing.VLAN, addr.VLAN) {
			existing.Events += addr.Events
			if addr.FirstSeen.Before(existing.FirstSeen) {
				existing.FirstSeen = addr.FirstSeen
			}
			if addr.LastSeen.After(existing.LastSeen) {
				existing.LastSeen = addr.LastSeen
			}
			return
		}
	}
	a.Addresses = append(a.Addresses, addr)
}

func sameVLAN(a, b *uint16) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}

func widenSeen(a *model.Asset, first, last time.Time) {
	if a.FirstSeen.IsZero() || first.Before(a.FirstSeen) {
		a.FirstSeen = first
	}
	if last.After(a.LastSeen) {
		a.LastSeen = last
	}
}

// label is what the GUI shows: the most recognisable address the asset has.
func label(a *model.Asset) string {
	if len(a.IPs) > 0 {
		return a.IPs[0]
	}
	if len(a.MACs) > 0 {
		return a.MACs[0]
	}
	return a.Key
}

func buildProtocols(in map[protoKey]*protoStats) []model.ProtocolUsage {
	if len(in) == 0 {
		return nil
	}
	out := make([]model.ProtocolUsage, 0, len(in))
	for pk, ps := range in {
		usage := model.ProtocolUsage{
			Protocol:  pk.protocol,
			Side:      pk.side,
			Events:    ps.events,
			FirstSeen: ps.first,
			LastSeen:  ps.last,
		}
		if len(ps.classes) > 0 {
			usage.Classes = make(map[model.Classification]uint64, len(ps.classes))
			for c, n := range ps.classes {
				usage.Classes[c] = n
			}
		}
		usage.UnitIDs = sortedVLANs(ps.units)
		out = append(out, usage)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Side < out[j].Side
	})
	return out
}

// buildAttributes keeps one value per field: the highest confidence source
// wins, and the earliest packet that supports it is the evidence.
func buildAttributes(candidates []attrCandidate) []model.Attribute {
	if len(candidates) == 0 {
		return nil
	}
	best := map[string]attrCandidate{}
	for _, c := range candidates {
		cur, seen := best[c.field]
		switch {
		case !seen:
			best[c.field] = c
		case c.confidence > cur.confidence:
			best[c.field] = c
		case c.confidence == cur.confidence && c.value == cur.value &&
			c.evidence.PacketIndex < cur.evidence.PacketIndex:
			best[c.field] = c
		}
	}

	out := make([]model.Attribute, 0, len(best))
	for _, c := range best {
		out = append(out, model.Attribute{
			Field:      c.field,
			Value:      c.value,
			Confidence: c.confidence,
			Source:     c.source,
			Evidence:   c.evidence,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

// inferRole decides what a device is from how it behaved, and records why.
func (b *Builder) inferRole(a *model.Asset, ipsBehindMAC int) model.Role {
	if a.IsGateway {
		return model.Role{
			Name:       model.RoleGateway,
			Confidence: confidenceGateway,
			Reasons: []string{fmt.Sprintf(
				"one MAC seen fronting %d IP addresses, so it forwards for them", ipsBehindMAC)},
		}
	}

	serves := map[string]bool{}
	for _, p := range a.Protocols {
		if p.Side == "server" {
			serves[p.Protocol] = true
		}
	}

	var (
		served      []model.ProtocolUsage
		polled      []model.ProtocolUsage
		programmed  []model.ProtocolUsage
		reasonsSrv  []string
		reasonsClnt []string
		reasonsProg []string
	)
	for _, p := range a.Protocols {
		switch p.Side {
		case "server":
			served = append(served, p)
			reasonsSrv = append(reasonsSrv, fmt.Sprintf(
				"serves %s (%d operations observed)", p.Protocol, p.Events))
		case "client":
			polled = append(polled, p)
			if p.Classes[model.ClassProgram] > 0 || p.Classes[model.ClassFirmware] > 0 {
				reasonsProg = append(reasonsProg, fmt.Sprintf(
					"issues %s program or firmware operations (%d program, %d firmware)",
					p.Protocol, p.Classes[model.ClassProgram], p.Classes[model.ClassFirmware]))
				// Program operations only mark an engineering station when
				// the device does not itself serve that protocol. During an
				// S7 block download the CPU sends the jobs that fetch each
				// block, so a controller issues program requests too; what
				// distinguishes it is that it also answers them.
				if !serves[p.Protocol] {
					programmed = append(programmed, p)
				}
			}
			reasonsClnt = append(reasonsClnt, fmt.Sprintf(
				"issues %s requests (%d observed)", p.Protocol, p.Events))
		}
	}

	switch {
	case len(served) > 0:
		// CLAUDE.md defines a controller as the server of a control
		// protocol, which is the most concrete thing an asset can be.
		reasons := append([]string{}, reasonsSrv...)
		reasons = append(reasons, reasonsProg...)
		reasons = append(reasons, reasonsClnt...)
		return model.Role{
			Name:       model.RoleController,
			Confidence: confidenceServedProtocol,
			Reasons:    reasons,
		}

	case len(programmed) > 0:
		reasons := append([]string{}, reasonsProg...)
		reasons = append(reasons, reasonsClnt...)
		return model.Role{Name: model.RoleEngineering, Confidence: confidenceProgrammed, Reasons: reasons}

	case len(polled) > 0:
		return model.Role{
			Name:       model.RoleOperator,
			Confidence: confidencePolledServer,
			Reasons:    reasonsClnt,
		}

	default:
		return model.Role{Name: model.RoleUnknown}
	}
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedVLANs(m map[uint16]bool) []uint16 {
	if len(m) == 0 {
		return nil
	}
	out := make([]uint16, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func firstOf(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[0]
}

// EventSource streams a project's events. The store implements it.
type EventSource interface {
	EachEvent(ctx context.Context, projectID int64, fn func(model.Event) error) error
}

// AssetSink persists a rebuilt inventory. The store implements it.
type AssetSink interface {
	SaveAssets(ctx context.Context, projectID int64, assets []model.Asset) error
}

// Rebuild recomputes a project's inventory from its stored events and saves
// it.
//
// The inventory is derived data, so it is rebuilt rather than merged: that
// keeps one code path for a first ingest and for the tenth, and no incremental
// merge can drift from what the events actually say. Events are streamed, so
// memory stays bounded however large the project is.
func Rebuild(ctx context.Context, src EventSource, dst AssetSink, projectID int64, opts ...Option) ([]model.Asset, error) {
	b := New(opts...)
	if err := src.EachEvent(ctx, projectID, func(e model.Event) error {
		b.Add(e)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("inventory: reading events: %w", err)
	}

	assets := b.Assets()
	// The Purdue placement reads the finished inventory: an asset nothing was
	// observed about is placed by the subnet its neighbours are in, which
	// cannot be decided one asset at a time (CLAUDE.md, "inferred from role +
	// subnet").
	index := make(map[string]int, len(assets))
	for i := range assets {
		index[assets[i].Key] = i
	}
	for key, level := range topology.AssignLevels(assets) {
		if i, ok := index[key]; ok {
			assets[i].Level = level
		}
	}

	if err := dst.SaveAssets(ctx, projectID, assets); err != nil {
		return nil, fmt.Errorf("inventory: saving assets: %w", err)
	}
	return assets, nil
}
