// Package ingest reads capture files, decodes the link, network and transport
// layers, reassembles TCP streams and hands the payload to the dissector
// registry.
//
// Ingest is strictly passive: it reads files and never touches a network.
package ingest

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/gopacket/gopacket/reassembly"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/model"
)

// Defaults for stream handling.
const (
	// defaultFlushTimeout is how much capture time may pass without new data
	// before a stream is closed and its buffers released. It bounds memory on
	// captures with many short-lived connections.
	defaultFlushTimeout = 5 * time.Minute

	// defaultFlushEvery is how many packets to read between flush sweeps.
	defaultFlushEvery = 4096

	// maxVLANTags caps the VLAN stack depth, so a crafted packet cannot make
	// the decoder loop.
	maxVLANTags = 4

	// maxResyncScan caps how far into a desynchronised stream to look for the
	// next frame boundary.
	maxResyncScan = 2048

	// resyncMinConfidence is how much the dissector must like a candidate
	// boundary before a desynchronised stream is restarted there.
	resyncMinConfidence = dissect.DefaultMinConfidence

	// maxFramingErrors is how many framing failures one direction of a stream
	// may produce before it is abandoned.
	maxFramingErrors = 32

	// maxBindAttempts is how many reassembled chunks a stream may offer before
	// ingest gives up identifying its protocol.
	maxBindAttempts = 4

	// bindDecisionBytes is how many bytes make a Probe verdict trustworthy.
	// Below this a stream gets another chance as more data arrives.
	bindDecisionBytes = 16
)

// Options configures a capture ingest.
type Options struct {
	// CaptureID is stamped on every event. Defaults to the first 12 hex
	// characters of the file's SHA-256.
	CaptureID string

	// Registry supplies the dissectors. Defaults to dissect.Default().
	Registry *dissect.Registry

	// MinConfidence is the Probe score needed to bind a dissector to a stream
	// whose ports match no default. Defaults to dissect.DefaultMinConfidence.
	MinConfidence int

	// ExtraTCPPorts adds user-configured ports per protocol, as read from
	// otinv.yaml.
	ExtraTCPPorts map[string][]uint16

	// Sink receives every event. Required to get any output.
	Sink func(model.Event)

	// Logger defaults to slog.Default().
	Logger *slog.Logger

	// FlushTimeout and FlushEvery tune stream expiry; zero means the default.
	FlushTimeout time.Duration
	FlushEvery   uint64
}

// Result summarises one ingested capture.
type Result struct {
	Capture model.Capture `json:"capture"`

	Packets      uint64 `json:"packets"`
	DecodeErrors uint64 `json:"decode_errors"`
	NonIP        uint64 `json:"non_ip_packets"`
	// TCPStreams counts the reassembly streams created. A connection that is
	// seen again after it was closed, for example by the FIN-ACK that follows
	// its FIN, starts a new stream, so this can exceed the number of distinct
	// connections. Each connection getting its own stream is deliberate: it
	// keeps a reused port from inheriting the previous session's framing.
	TCPStreams      uint64 `json:"tcp_streams"`
	BoundStreams    uint64 `json:"bound_streams"`
	UnboundPayloads uint64 `json:"unbound_payloads"`
	UDPDatagrams    uint64 `json:"udp_datagrams"`
	Events          uint64 `json:"events"`
	Malformed       uint64 `json:"malformed"`
	Resyncs         uint64 `json:"resyncs"`
	MissingBytes    uint64 `json:"missing_bytes"`
	AbandonedSides  uint64 `json:"abandoned_stream_sides"`

	// Health is the registry's parse health. The registry is process-wide by
	// default, so these counters cover every capture it has seen.
	Health map[string]dissect.Health `json:"health"`
}

// packetReader is the part of pcapgo's readers that ingest needs.
type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

// File ingests one capture file.
func File(path string, opts Options) (*Result, error) {
	if opts.Registry == nil {
		opts.Registry = dissect.Default()
	}
	if opts.MinConfidence <= 0 {
		opts.MinConfidence = dissect.DefaultMinConfidence
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.FlushTimeout <= 0 {
		opts.FlushTimeout = defaultFlushTimeout
	}
	if opts.FlushEvery == 0 {
		opts.FlushEvery = defaultFlushEvery
	}
	for name, ports := range opts.ExtraTCPPorts {
		if err := opts.Registry.ExtraTCPPorts(name, ports...); err != nil {
			return nil, fmt.Errorf("ingest: extra ports for %q: %w", name, err)
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("ingest: %w", err)
	}

	// Hash first, in its own pass: the digest identifies the capture in the
	// store and stamps every event, so it has to be known before dissection
	// starts rather than after.
	digest, err := hashFile(path)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ingest: %w", err)
	}
	defer func() { _ = f.Close() }()

	reader, err := openCapture(bufio.NewReaderSize(f, 1<<16))
	if err != nil {
		return nil, err
	}

	captureID := opts.CaptureID
	if captureID == "" {
		captureID = digest[:12]
	}
	res := &Result{
		Capture: model.Capture{
			ID:       captureID,
			Path:     path,
			SHA256:   digest,
			Bytes:    info.Size(),
			LinkType: reader.LinkType().String(),
		},
	}
	linkType := reader.LinkType()
	if linkType != layers.LinkTypeEthernet {
		// Other link types (raw IP, Linux cooked) are a small addition to
		// decodePacket, but nothing in this project needs them yet.
		return nil, fmt.Errorf("ingest: unsupported link type %s", linkType)
	}

	sink := opts.Sink
	if sink == nil {
		sink = func(model.Event) {}
	}
	counted := func(e model.Event) {
		res.Events++
		if e.Malformed {
			res.Malformed++
		}
		sink(e)
	}

	fac := &factory{opts: &opts, res: res, sink: counted}
	pool := reassembly.NewStreamPool(fac)
	asm := reassembly.NewAssembler(pool)

	var dec decoder
	for {
		data, ci, err := reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// A truncated final packet is common in real captures; stop
			// rather than lose everything decoded so far.
			opts.Logger.Warn("stopping ingest on read error",
				"path", path, "packet", res.Packets+1, "err", err)
			res.DecodeErrors++
			break
		}
		res.Packets++
		if res.Packets == 1 || ci.Timestamp.Before(res.Capture.FirstSeen) {
			res.Capture.FirstSeen = ci.Timestamp
		}
		if ci.Timestamp.After(res.Capture.LastSeen) {
			res.Capture.LastSeen = ci.Timestamp
		}

		pkt, err := dec.decode(data)
		if err != nil {
			res.DecodeErrors++
			continue
		}
		if pkt == nil {
			res.NonIP++
			continue
		}

		actx := &assemblerCtx{
			ci:     ci,
			index:  res.Packets,
			srcMAC: pkt.srcMAC,
			dstMAC: pkt.dstMAC,
			vlans:  pkt.vlans,
		}
		switch pkt.transport {
		case layers.IPProtocolTCP:
			asm.AssembleWithContext(pkt.netFlow, &dec.tcp, actx)
		case layers.IPProtocolUDP:
			res.UDPDatagrams++
			fac.handleDatagram(pkt, &dec.udp, actx)
		default:
			// Not a transport this project dissects.
		}

		if res.Packets%opts.FlushEvery == 0 {
			asm.FlushCloseOlderThan(ci.Timestamp.Add(-opts.FlushTimeout))
		}
	}
	asm.FlushAll()

	res.Capture.Packets = res.Packets
	res.Health = opts.Registry.Health()
	return res, nil
}

// Fingerprint returns a capture's digest and size without decoding it.
//
// The store needs a capture row before its events can reference it, but the
// packet counts and time range are only known once the file has been read, so
// ingest is asked for the identity first and the counts afterwards.
func Fingerprint(path string) (digest string, size int64, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, fmt.Errorf("ingest: %w", err)
	}
	digest, err = hashFile(path)
	if err != nil {
		return "", 0, err
	}
	return digest, info.Size(), nil
}

// hashFile returns the hex SHA-256 of a file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("ingest: %w", err)
	}
	defer func() { _ = f.Close() }()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, bufio.NewReaderSize(f, 1<<16)); err != nil {
		return "", fmt.Errorf("ingest: hashing %s: %w", path, err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// openCapture sniffs the file magic and returns a reader for classic pcap or
// pcapng.
func openCapture(r *bufio.Reader) (packetReader, error) {
	magic, err := r.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("ingest: reading file magic: %w", err)
	}
	switch binary.BigEndian.Uint32(magic) {
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1:
		rd, err := pcapgo.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("ingest: reading pcap: %w", err)
		}
		return rd, nil
	case 0x0a0d0d0a:
		rd, err := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, fmt.Errorf("ingest: reading pcapng: %w", err)
		}
		return rd, nil
	default:
		return nil, fmt.Errorf("ingest: not a pcap or pcapng file (magic %x)", magic)
	}
}

// packetInfo is what one decoded packet contributes to a flow.
type packetInfo struct {
	netFlow        gopacket.Flow
	transport      layers.IPProtocol
	srcMAC, dstMAC string
	vlans          []uint16
}

// decoder decodes Ethernet through TCP/UDP into reused layer structs, so that
// per-packet work does not allocate.
type decoder struct {
	eth   layers.Ethernet
	dot1q layers.Dot1Q
	ip4   layers.IPv4
	ip6   layers.IPv6
	tcp   layers.TCP
	udp   layers.UDP
	vlans []uint16
}

// decode returns nil without an error for packets this project does not
// dissect, and an error only for malformed headers.
func (d *decoder) decode(data []byte) (*packetInfo, error) {
	if err := d.eth.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return nil, err
	}

	etherType := d.eth.EthernetType
	payload := d.eth.Payload
	d.vlans = d.vlans[:0]
	for range maxVLANTags {
		if etherType != layers.EthernetTypeDot1Q && etherType != layers.EthernetTypeQinQ {
			break
		}
		if err := d.dot1q.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
			return nil, err
		}
		d.vlans = append(d.vlans, d.dot1q.VLANIdentifier)
		etherType = d.dot1q.Type
		payload = d.dot1q.Payload
	}

	pkt := &packetInfo{
		srcMAC: d.eth.SrcMAC.String(),
		dstMAC: d.eth.DstMAC.String(),
	}
	if len(d.vlans) > 0 {
		pkt.vlans = append([]uint16(nil), d.vlans...)
	}

	switch etherType {
	case layers.EthernetTypeIPv4:
		if err := d.ip4.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
			return nil, err
		}
		pkt.netFlow = d.ip4.NetworkFlow()
		pkt.transport = d.ip4.Protocol
		payload = d.ip4.Payload
	case layers.EthernetTypeIPv6:
		if err := d.ip6.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
			return nil, err
		}
		pkt.netFlow = d.ip6.NetworkFlow()
		// Extension headers are not walked yet; such packets fall through to
		// the default branch below and are counted as non-IP.
		pkt.transport = d.ip6.NextHeader
		payload = d.ip6.Payload
	default:
		// Industrial layer 2 protocols (GOOSE, EtherCAT, PROFINET RT) arrive
		// here; they get their own dissectors in a later milestone.
		return nil, nil
	}

	switch pkt.transport {
	case layers.IPProtocolTCP:
		if err := d.tcp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
			return nil, err
		}
	case layers.IPProtocolUDP:
		if err := d.udp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
			return nil, err
		}
	default:
		return nil, nil
	}
	return pkt, nil
}

// assemblerCtx carries the packet metadata that reassembly does not, so that
// an event can name the packet it came from.
type assemblerCtx struct {
	ci             gopacket.CaptureInfo
	index          uint64
	srcMAC, dstMAC string
	vlans          []uint16
}

// GetCaptureInfo implements reassembly.AssemblerContext.
func (c *assemblerCtx) GetCaptureInfo() gopacket.CaptureInfo { return c.ci }

// factory creates one tcpStream per TCP connection.
type factory struct {
	opts *Options
	res  *Result
	sink func(model.Event)
}

// New implements reassembly.StreamFactory.
func (f *factory) New(netFlow, tcpFlow gopacket.Flow, _ *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	f.res.TCPStreams++
	src, dst := tcpFlow.Endpoints()
	return &tcpStream{
		f: f,
		base: model.Flow{
			SrcIP:     netFlow.Src().String(),
			DstIP:     netFlow.Dst().String(),
			SrcPort:   portOf(src),
			DstPort:   portOf(dst),
			Transport: model.TransportTCP,
		},
	}
}

func portOf(e gopacket.Endpoint) uint16 {
	raw := e.Raw()
	if len(raw) != 2 {
		return 0
	}
	return binary.BigEndian.Uint16(raw)
}

// side is one direction of a stream.
type side struct {
	direction     model.Direction
	ctx           *dissect.FlowContext
	framingErrors int
	abandoned     bool
}

// tcpStream decodes both directions of one TCP connection.
type tcpStream struct {
	f       *factory
	base    model.Flow
	bound   dissect.Dissector
	tries   int
	unbound bool
	started bool
	sides   [2]side
}

// Accept implements reassembly.Stream. Everything is accepted: captures from
// the field routinely start in the middle of a session, and a capture is all
// the evidence there is.
func (s *tcpStream) Accept(tcp *layers.TCP, _ gopacket.CaptureInfo, _ reassembly.TCPFlowDirection,
	_ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext,
) bool {
	if !s.started {
		s.started = true
		if !tcp.SYN && len(tcp.Payload) > 0 {
			// No handshake in the capture: force the stream to start here
			// rather than wait for bytes that were never recorded.
			*start = true
		}
	}
	return true
}

// ReassembledSG implements reassembly.Stream. It frames the reassembled bytes
// into PDUs and hands each one to the bound dissector.
func (s *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, skip := sg.Info()
	idx := 0
	if dir == reassembly.TCPDirServerToClient {
		idx = 1
	}
	sd := &s.sides[idx]

	available, _ := sg.Lengths()
	if skip > 0 {
		// Bytes the capture never recorded: the frame boundary is lost.
		s.f.res.MissingBytes += uint64(skip)
	}
	if available == 0 || sd.abandoned || s.unbound {
		if available > 0 {
			s.f.res.UnboundPayloads++
			sg.KeepFrom(available) // drop: nothing will decode these bytes
		}
		return
	}

	actx, _ := ac.(*assemblerCtx)
	flow := s.base
	if idx == 1 {
		flow = flow.Reverse()
	}
	if actx != nil {
		flow.SrcMAC, flow.DstMAC = actx.srcMAC, actx.dstMAC
		flow.VLAN = actx.vlans
	}

	data := sg.Fetch(available)

	if s.bound == nil {
		if !s.bind(flow, data, actx) {
			// A verdict on a handful of bytes is not worth much, so a short
			// first chunk gets another look once more data arrives. Enough
			// bytes with no match means this stream is not ours.
			if s.tries < maxBindAttempts && len(data) < bindDecisionBytes {
				sg.KeepFrom(0)
				return
			}
			s.unbound = true
			s.f.res.UnboundPayloads++
			sg.KeepFrom(available)
			return
		}
	}

	if sd.ctx == nil {
		sd.direction = s.directionFor(flow)
		sd.ctx = &dissect.FlowContext{
			CaptureID:  s.f.res.Capture.ID,
			Direction:  sd.direction,
			ServerPort: s.serverPort(flow),
		}
	}
	sd.ctx.Flow = flow
	if actx != nil {
		sd.ctx.PacketIndex = actx.index
		sd.ctx.Timestamp = actx.ci.Timestamp
	}

	consumed := s.frame(sd, data)
	if consumed < len(data) {
		kept := len(data) - consumed
		if kept > dissect.MaxPDUSize {
			// A stream that never produces a frame must not grow without
			// bound; drop what is held and resynchronise later.
			s.f.res.Resyncs++
			s.f.opts.Registry.RecordError(s.bound.Name())
			consumed = len(data)
		}
	}
	sg.KeepFrom(consumed)
}

// frame cuts data into PDUs, dissects each one and returns how many bytes were
// consumed. Whatever is left is an incomplete PDU to be kept for later.
func (s *tcpStream) frame(sd *side, data []byte) int {
	reg := s.f.opts.Registry
	consumed := 0
	for consumed < len(data) {
		rest := data[consumed:]
		n, err := reg.PDULen(s.bound, rest)
		switch {
		case errors.Is(err, dissect.ErrNeedMore):
			return consumed
		case err != nil:
			// Framing is broken. Report it, then look for the next plausible
			// frame boundary rather than discarding the whole buffer.
			s.f.sink(s.framingErrorEvent(sd, err))
			reg.RecordError(s.bound.Name())
			sd.framingErrors++
			if sd.framingErrors >= maxFramingErrors {
				sd.abandoned = true
				s.f.res.AbandonedSides++
				return len(data)
			}
			skip := s.resync(rest, sd.ctx)
			s.f.res.Resyncs++
			if skip <= 0 {
				return len(data)
			}
			consumed += skip
			continue
		}

		events, perr := reg.Parse(s.bound, sd.ctx, rest[:n])
		if perr != nil {
			sd.framingErrors = 0 // the framing held; only the body was bad
		}
		for _, e := range events {
			s.f.sink(e)
		}
		consumed += n
	}
	return consumed
}

// resync returns the offset of the next byte at which a convincing PDU starts,
// or 0 when there is none within maxResyncScan bytes.
//
// Framing alone is not enough to resynchronise: inside a garbage payload some
// offset almost always has a plausible length field, and locking on to it
// turns one broken frame into a stream of invented ones. A candidate must also
// look like the protocol, so each one is put through Probe. Every resync is
// counted and surfaced as parse health, because even a convincing boundary can
// be the wrong one.
func (s *tcpStream) resync(buf []byte, ctx *dissect.FlowContext) int {
	limit := min(len(buf), maxResyncScan)
	reg := s.f.opts.Registry
	for i := 1; i < limit; i++ {
		candidate := buf[i:]
		if _, err := reg.PDULen(s.bound, candidate); err != nil {
			continue
		}
		if reg.Probe(s.bound, ctx, candidate) < resyncMinConfidence {
			continue
		}
		return i
	}
	return 0
}

// bind picks the dissector for this stream from its first bytes.
func (s *tcpStream) bind(flow model.Flow, data []byte, actx *assemblerCtx) bool {
	s.tries++
	probeCtx := &dissect.FlowContext{
		CaptureID:  s.f.res.Capture.ID,
		Flow:       flow,
		Direction:  model.DirUnknown,
		ServerPort: s.serverPort(flow),
	}
	if actx != nil {
		probeCtx.PacketIndex = actx.index
		probeCtx.Timestamp = actx.ci.Timestamp
	}
	d, score := s.f.opts.Registry.Select(probeCtx, data, s.f.opts.MinConfidence)
	if d == nil {
		return false
	}
	s.bound = d
	s.f.res.BoundStreams++
	s.f.opts.Logger.Debug("bound dissector to stream",
		"protocol", d.Name(), "confidence", score,
		"src", flow.SrcIP, "src_port", flow.SrcPort,
		"dst", flow.DstIP, "dst_port", flow.DstPort)
	return true
}

// serverPort reports which side of the flow looks like the listening one.
func (s *tcpStream) serverPort(flow model.Flow) uint16 {
	if s.bound == nil {
		return 0
	}
	reg := s.f.opts.Registry
	switch {
	case reg.HasPort(s.bound.Name(), model.TransportTCP, flow.DstPort):
		return flow.DstPort
	case reg.HasPort(s.bound.Name(), model.TransportTCP, flow.SrcPort):
		return flow.SrcPort
	default:
		return s.base.DstPort // the side that was connected to
	}
}

// directionFor decides whether this side carries requests or responses. The
// protocol's own port wins; failing that, whoever opened the connection is the
// client.
func (s *tcpStream) directionFor(flow model.Flow) model.Direction {
	reg := s.f.opts.Registry
	name := s.bound.Name()
	dstIsProto := reg.HasPort(name, model.TransportTCP, flow.DstPort)
	srcIsProto := reg.HasPort(name, model.TransportTCP, flow.SrcPort)
	switch {
	case dstIsProto && !srcIsProto:
		return model.DirRequest
	case srcIsProto && !dstIsProto:
		return model.DirResponse
	case flow.SrcPort == s.base.SrcPort && flow.DstPort == s.base.DstPort:
		return model.DirRequest // the side that opened the connection
	default:
		return model.DirResponse
	}
}

// framingErrorEvent reports a frame that could not be cut from the stream. It
// has no function code, so the field is -1 rather than a misleading zero.
func (s *tcpStream) framingErrorEvent(sd *side, err error) model.Event {
	return model.Event{
		CaptureID:    sd.ctx.CaptureID,
		PacketIndex:  sd.ctx.PacketIndex,
		Timestamp:    sd.ctx.Timestamp,
		Flow:         sd.ctx.Flow,
		Protocol:     s.bound.Name(),
		Direction:    sd.direction,
		Operation:    "FramingError",
		FunctionCode: -1,
		Class:        model.ClassOther,
		Malformed:    true,
		Error:        err.Error(),
	}
}

// ReassemblyComplete implements reassembly.Stream.
func (s *tcpStream) ReassemblyComplete(_ reassembly.AssemblerContext) bool {
	return true
}

// handleDatagram dissects one UDP datagram. Datagram protocols are
// self-delimiting, so there is no framing step.
func (f *factory) handleDatagram(pkt *packetInfo, udp *layers.UDP, actx *assemblerCtx) {
	if len(udp.Payload) == 0 {
		return
	}
	flow := model.Flow{
		SrcMAC:    pkt.srcMAC,
		DstMAC:    pkt.dstMAC,
		SrcIP:     pkt.netFlow.Src().String(),
		DstIP:     pkt.netFlow.Dst().String(),
		SrcPort:   uint16(udp.SrcPort),
		DstPort:   uint16(udp.DstPort),
		Transport: model.TransportUDP,
		VLAN:      pkt.vlans,
	}
	ctx := &dissect.FlowContext{
		CaptureID:   f.res.Capture.ID,
		Flow:        flow,
		PacketIndex: actx.index,
		Timestamp:   actx.ci.Timestamp,
		Direction:   model.DirUnknown,
	}
	d, _ := f.opts.Registry.Select(ctx, udp.Payload, f.opts.MinConfidence)
	if d == nil {
		f.res.UnboundPayloads++
		return
	}
	if f.opts.Registry.HasPort(d.Name(), model.TransportUDP, flow.DstPort) {
		ctx.Direction = model.DirRequest
		ctx.ServerPort = flow.DstPort
	} else if f.opts.Registry.HasPort(d.Name(), model.TransportUDP, flow.SrcPort) {
		ctx.Direction = model.DirResponse
		ctx.ServerPort = flow.SrcPort
	}

	// A datagram can hold several PDUs of a length-delimited protocol, DNP3
	// over UDP among them, so a framer is used here too. Nothing is carried
	// between datagrams: a datagram boundary is a message boundary, which is
	// why a partial PDU at the end is an error rather than something to keep.
	if _, framed := d.(dissect.Framer); !framed {
		events, _ := f.opts.Registry.Parse(d, ctx, udp.Payload)
		for _, e := range events {
			f.sink(e)
		}
		return
	}

	reg := f.opts.Registry
	for consumed := 0; consumed < len(udp.Payload); {
		rest := udp.Payload[consumed:]
		n, err := reg.PDULen(d, rest)
		if err != nil {
			reason := err
			if errors.Is(err, dissect.ErrNeedMore) {
				reason = fmt.Errorf("%w: datagram ends inside a PDU", dissect.ErrMalformed)
			}
			f.sink(datagramErrorEvent(d.Name(), ctx, reason))
			reg.RecordError(d.Name())
			return
		}
		events, _ := reg.Parse(d, ctx, rest[:n])
		for _, e := range events {
			f.sink(e)
		}
		consumed += n
	}
}

// datagramErrorEvent reports a datagram that could not be cut into PDUs.
func datagramErrorEvent(protocol string, ctx *dissect.FlowContext, err error) model.Event {
	return model.Event{
		CaptureID:    ctx.CaptureID,
		PacketIndex:  ctx.PacketIndex,
		Timestamp:    ctx.Timestamp,
		Flow:         ctx.Flow,
		Protocol:     protocol,
		Direction:    ctx.Direction,
		Operation:    "FramingError",
		FunctionCode: -1,
		Class:        model.ClassOther,
		Malformed:    true,
		Error:        err.Error(),
	}
}
