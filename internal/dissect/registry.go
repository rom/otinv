package dissect

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/rom/otinv/internal/model"
)

// DefaultMinConfidence is the Probe score a dissector must reach to be bound to
// a stream whose ports match no known default. Overridable via otinv.yaml.
const DefaultMinConfidence = 70

// Health is the per-protocol parse health shown in the GUI.
type Health struct {
	PDUs   uint64 `json:"pdus"`   // PDUs handed to Parse
	Events uint64 `json:"events"` // events produced
	Errors uint64 `json:"errors"` // PDUs rejected as malformed
	Panics uint64 `json:"panics"` // recovered panics: always a bug
}

type registration struct {
	d          Dissector
	tcpPorts   []uint16
	udpPorts   []uint16
	etherTypes []uint16
}

// Registry holds the registered dissectors and tracks their parse health. A
// Registry is safe for concurrent use by the dissection worker pool.
type Registry struct {
	mu     sync.RWMutex
	byName map[string]*registration
	order  []string // registration order, for stable iteration
	health map[string]*Health
}

// NewRegistry returns an empty registry. Most callers want Default.
func NewRegistry() *Registry {
	return &Registry{
		byName: make(map[string]*registration),
		health: make(map[string]*Health),
	}
}

var defaultRegistry = NewRegistry()

// Default returns the process-wide registry that init-time Register calls
// populate.
func Default() *Registry { return defaultRegistry }

// RegisterOption configures a registration.
type RegisterOption func(*registration)

// TCPPorts declares the default TCP ports for a protocol. Ports are defaults
// only: a dissector is still offered streams on other ports via Probe.
func TCPPorts(ports ...uint16) RegisterOption {
	return func(r *registration) { r.tcpPorts = append(r.tcpPorts, ports...) }
}

// UDPPorts declares the default UDP ports for a protocol.
func UDPPorts(ports ...uint16) RegisterOption {
	return func(r *registration) { r.udpPorts = append(r.udpPorts, ports...) }
}

// EtherTypes declares the EtherTypes a layer 2 protocol is carried under.
//
// Several industrial protocols have no port at all because they have no IP
// layer: GOOSE, Sampled Values, PROFINET RT, EtherCAT, LLDP. An EtherType is
// a stronger claim than a port — IEEE assigns each to one protocol, where a
// port is only a convention several protocols share — so a dissector
// registered for one is not asked to compete with heuristics.
func EtherTypes(types ...uint16) RegisterOption {
	return func(r *registration) { r.etherTypes = append(r.etherTypes, types...) }
}

// Register adds d to the default registry. It is meant for init() and panics on
// a duplicate name or an invalid tier, both of which are programming errors.
func Register(d Dissector, opts ...RegisterOption) {
	defaultRegistry.Register(d, opts...)
}

// Register adds d to this registry.
func (r *Registry) Register(d Dissector, opts ...RegisterOption) {
	if d == nil {
		panic("dissect: Register called with nil dissector")
	}
	name := d.Name()
	if name == "" {
		panic("dissect: dissector with empty name")
	}
	if t := d.Tier(); t < 1 || t > 3 {
		panic(fmt.Sprintf("dissect: dissector %q declares invalid tier %d", name, t))
	}

	reg := &registration{d: d}
	for _, o := range opts {
		o(reg)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byName[name]; dup {
		panic(fmt.Sprintf("dissect: dissector %q registered twice", name))
	}
	r.byName[name] = reg
	r.order = append(r.order, name)
	r.health[name] = &Health{}
}

// Names returns the registered protocol names in registration order.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]string(nil), r.order...)
}

// Lookup returns the dissector registered under name.
func (r *Registry) Lookup(name string) (Dissector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.byName[name]
	if !ok {
		return nil, false
	}
	return reg.d, true
}

// ExtraTCPPorts adds user-configured ports for an already registered protocol
// (otinv.yaml, protocols.<name>.extra_ports).
func (r *Registry) ExtraTCPPorts(name string, ports ...uint16) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	reg, ok := r.byName[name]
	if !ok {
		return fmt.Errorf("dissect: no such dissector %q", name)
	}
	reg.tcpPorts = append(reg.tcpPorts, ports...)
	return nil
}

// Candidates returns the dissectors to try for a flow, port-matched ones first.
func (r *Registry) Candidates(transport model.Transport, srcPort, dstPort uint16) (matched, others []Dissector) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, name := range r.order {
		reg := r.byName[name]
		ports := reg.tcpPorts
		if transport == model.TransportUDP {
			ports = reg.udpPorts
		}
		if containsPort(ports, srcPort) || containsPort(ports, dstPort) {
			matched = append(matched, reg.d)
		} else {
			others = append(others, reg.d)
		}
	}
	return matched, others
}

// EtherTypeCandidates returns the dissectors registered for an EtherType, in
// registration order.
func (r *Registry) EtherTypeCandidates(etherType uint16) []Dissector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Dissector
	for _, name := range r.order {
		if containsPort(r.byName[name].etherTypes, etherType) {
			out = append(out, r.byName[name].d)
		}
	}
	return out
}

// SelectEtherType picks the dissector for a layer 2 frame.
//
// Unlike a port, an EtherType names one protocol, so a registered dissector
// is accepted on any non-zero confidence and nothing unregistered is tried:
// a frame under an EtherType nobody claims is not ours, however it looks.
func (r *Registry) SelectEtherType(ctx *FlowContext, etherType uint16, payload []byte) (Dissector, int) {
	if len(payload) == 0 {
		return nil, 0
	}
	var best Dissector
	bestScore := 0
	for _, d := range r.EtherTypeCandidates(etherType) {
		if s := r.Probe(d, ctx, payload); s > bestScore {
			best, bestScore = d, s
		}
	}
	return best, bestScore
}

// HasEtherType reports whether a protocol is registered for an EtherType.
func (r *Registry) HasEtherType(name string, etherType uint16) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.byName[name]
	return ok && containsPort(reg.etherTypes, etherType)
}

func containsPort(ports []uint16, p uint16) bool {
	for _, q := range ports {
		if q == p {
			return true
		}
	}
	return false
}

// Select picks the dissector for a stream from its first bytes.
//
// A port-matched dissector is accepted on any non-zero confidence, because the
// port is already evidence. A dissector reached only by heuristics must score
// at least minConfidence. Highest score wins; on a tie the port match wins.
//
// The third return value asks the caller to wait. A port-matched dissector
// that implements Deferring and says it cannot yet tell its protocol from the
// others on its port is left out of the comparison; if that leaves no winner,
// deferred is true and the caller should keep the bytes and try again rather
// than treat the stream as unrecognised. See Deferring.
func (r *Registry) Select(ctx *FlowContext, payload []byte, minConfidence int) (d Dissector, confidence int, deferred bool) {
	if len(payload) == 0 {
		return nil, 0, false
	}
	if minConfidence <= 0 {
		minConfidence = DefaultMinConfidence
	}
	matched, others := r.Candidates(ctx.Flow.Transport, ctx.Flow.SrcPort, ctx.Flow.DstPort)

	var best Dissector
	bestScore := 0
	for _, cand := range matched {
		if r.defers(cand, payload) {
			deferred = true
			continue
		}
		if s := r.Probe(cand, ctx, payload); s > bestScore {
			best, bestScore = cand, s
		}
	}
	if best != nil {
		return best, bestScore, false
	}
	if deferred {
		return nil, 0, true
	}
	for _, cand := range others {
		if s := r.Probe(cand, ctx, payload); s > bestScore && s >= minConfidence {
			best, bestScore = cand, s
		}
	}
	return best, bestScore, false
}

// defers asks a Deferring dissector whether it wants to wait, recovering from
// a panic the same way Probe does. A dissector that panics here is a bug and
// is taken not to defer, so the stream is decided on the scores at hand.
func (r *Registry) defers(d Dissector, payload []byte) (wait bool) {
	dd, ok := d.(Deferring)
	if !ok {
		return false
	}
	defer func() {
		if v := recover(); v != nil {
			r.recordPanic(d.Name(), "ProbeDefers", v)
			wait = false
		}
	}()
	return dd.ProbeDefers(payload)
}

// Probe calls d.Probe, recovering from a panic and clamping the result to
// 0-100. A panic here is a bug in the dissector and is counted as such.
func (r *Registry) Probe(d Dissector, ctx *FlowContext, payload []byte) (confidence int) {
	defer func() {
		if v := recover(); v != nil {
			r.recordPanic(d.Name(), "Probe", v)
			confidence = 0
		}
	}()
	c := d.Probe(ctx, payload)
	switch {
	case c < 0:
		return 0
	case c > 100:
		return 100
	default:
		return c
	}
}

// PDULen calls d's Framer implementation, recovering from a panic. A dissector
// that does not implement Framer is a programming error for stream transports.
func (r *Registry) PDULen(d Dissector, buf []byte) (n int, err error) {
	f, ok := d.(Framer)
	if !ok {
		return 0, fmt.Errorf("dissect: %s does not implement Framer", d.Name())
	}
	defer func() {
		if v := recover(); v != nil {
			r.recordPanic(d.Name(), "PDULen", v)
			n, err = 0, fmt.Errorf("%w: panic in %s framer", ErrMalformed, d.Name())
		}
	}()
	n, err = f.PDULen(buf)
	if err == nil {
		if n <= 0 {
			return 0, fmt.Errorf("%w: %s framer returned length %d", ErrMalformed, d.Name(), n)
		}
		if n > MaxPDUSize {
			return 0, fmt.Errorf("%w: %s framer returned length %d above cap %d",
				ErrMalformed, d.Name(), n, MaxPDUSize)
		}
		if n > len(buf) {
			return 0, fmt.Errorf("%w: %s framer claimed %d bytes from a %d byte buffer",
				ErrMalformed, d.Name(), n, len(buf))
		}
	}
	return n, err
}

// Parse calls d.Parse, recovering from a panic, and records parse health.
func (r *Registry) Parse(d Dissector, ctx *FlowContext, payload []byte) (events []model.Event, err error) {
	name := d.Name()
	defer func() {
		if v := recover(); v != nil {
			r.recordPanic(name, "Parse", v)
			events, err = nil, fmt.Errorf("%w: panic in %s dissector", ErrMalformed, name)
		}
	}()

	r.bump(name, func(h *Health) { h.PDUs++ })
	events, err = d.Parse(ctx, payload)
	r.bump(name, func(h *Health) {
		h.Events += uint64(len(events))
		if err != nil {
			h.Errors++
		}
	})
	return events, err
}

// RecordError counts a parse error that ingest detected outside Parse, such as
// a framing error or a stream that had to be abandoned.
func (r *Registry) RecordError(name string) {
	r.bump(name, func(h *Health) { h.Errors++ })
}

func (r *Registry) recordPanic(name, op string, v any) {
	r.bump(name, func(h *Health) { h.Panics++ })
	// A panic is a bug: the recover keeps the ingest running, the log makes
	// sure it is not silently swallowed.
	slog.Error("recovered panic in dissector",
		"protocol", name, "op", op, "panic", fmt.Sprint(v))
}

func (r *Registry) bump(name string, f func(*Health)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.health[name]
	if !ok {
		h = &Health{}
		r.health[name] = h
	}
	f(h)
}

// Health returns a snapshot of parse health per protocol.
func (r *Registry) Health() map[string]Health {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]Health, len(r.health))
	for name, h := range r.health {
		out[name] = *h
	}
	return out
}

// HealthNames returns the protocol names that have health records, sorted.
func (r *Registry) HealthNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.health))
	for n := range r.health {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// HasPort reports whether the named protocol has port registered as a default
// or user-configured port for the transport.
func (r *Registry) HasPort(name string, transport model.Transport, port uint16) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.byName[name]
	if !ok {
		return false
	}
	if transport == model.TransportUDP {
		return containsPort(reg.udpPorts, port)
	}
	return containsPort(reg.tcpPorts, port)
}
