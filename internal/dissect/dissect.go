// Package dissect holds the protocol dissector contract and the registry that
// binds dissectors to flows.
//
// A dissector decodes one PDU at a time and must never panic on hostile input;
// the registry wraps every call with a recover as a last line of defence and
// counts the result as parse health (CLAUDE.md, "Dissector contract").
package dissect

import (
	"errors"
	"time"

	"github.com/rom/otinv/internal/model"
)

// Framing and parse errors. Dissectors wrap ErrMalformed so that callers can
// distinguish "this is not decodable" from "I need more bytes".
var (
	// ErrNeedMore reports that the buffer holds less than one complete PDU.
	// The caller must keep the bytes and retry when more data arrives.
	ErrNeedMore = errors.New("incomplete PDU")

	// ErrMalformed reports that the bytes cannot be a valid PDU of this
	// protocol. The caller should count a parse error and resynchronise.
	ErrMalformed = errors.New("malformed PDU")
)

// FlowContext describes the flow a PDU belongs to and the packet it arrived in.
// Ingest owns it and updates PacketIndex, Timestamp and Direction before each
// Parse call. Dissectors must treat it as read-only apart from State.
type FlowContext struct {
	CaptureID   string
	Flow        model.Flow
	PacketIndex uint64
	Timestamp   time.Time

	// Direction is how ingest classified this PDU, from the server port or,
	// failing that, from which side opened the connection. A dissector may
	// override it when the PDU itself says more (a Modbus exception reply, for
	// example, is always a response).
	Direction model.Direction

	// ServerPort is the port ingest believes is the listening side, or 0 when
	// it could not tell.
	ServerPort uint16

	// State is per-stream scratch space owned by the bound dissector, for
	// request/response pairing and similar. Ingest creates one FlowContext per
	// direction of a stream and never touches State.
	State any
}

// Dissector decodes one industrial protocol. Implementations register
// themselves in init() via Register.
type Dissector interface {
	// Name is the stable protocol identifier used in events, config and the
	// GUI, e.g. "modbus".
	Name() string

	// Tier is the parsing depth tier declared in CLAUDE.md: 1 deep parsing,
	// 2 function-level, 3 identification only.
	Tier() int

	// Probe returns a confidence 0-100 that payload belongs to this protocol.
	// It must not modify ctx and must tolerate any byte sequence.
	Probe(ctx *FlowContext, payload []byte) int

	// Parse decodes one PDU and returns the events it produced. It must never
	// panic. A PDU it cannot decode yields an error wrapping ErrMalformed, and
	// may also yield an event marked Malformed carrying the evidence.
	Parse(ctx *FlowContext, payload []byte) ([]model.Event, error)
}

// Framer is implemented by dissectors whose protocol runs over a byte stream
// with length-delimited PDUs.
//
// The Dissector contract is deliberately one PDU per Parse call, so something
// has to cut the reassembled stream into PDUs. A dissector knows its own
// framing, so it reports the length and ingest does the slicing.
type Framer interface {
	// PDULen reports the total byte length of the first PDU in buf.
	//
	// It returns ErrNeedMore when buf is shorter than one PDU, and an error
	// wrapping ErrMalformed when the framing itself is broken. It must never
	// return a length larger than it can justify from buf's header bytes, and
	// never a length of zero with a nil error.
	PDULen(buf []byte) (int, error)
}

// Deferring is implemented by a dissector that shares its transport with other
// protocols on the same port, where the connection phase does not say which of
// them the stream will carry.
//
// ISO-on-TCP port 102 is the case this exists for: S7comm, S7comm-plus and
// IEC 61850 MMS all open with the same COTP connection request, and only the
// first data PDU tells them apart. Binding a stream from its connection
// request alone would attribute MMS traffic to S7comm roughly as often as not,
// and a wrong protocol on an asset is worse than a late one: it changes the
// role inferred for the device.
//
// A dissector that defers is left out of the selection entirely, whatever its
// Probe score, until it stops deferring.
type Deferring interface {
	// ProbeDefers reports that payload is framed the way this dissector
	// expects but carries nothing yet that separates its protocol from the
	// others sharing the port. The caller keeps the bytes and asks again when
	// more arrive.
	ProbeDefers(payload []byte) bool
}

// MaxPDUSize is the largest PDU any stream dissector may claim, and therefore
// the cap on per-stream reassembly buffers. It bounds memory regardless of
// capture size and of what a crafted length field asks for.
const MaxPDUSize = 64 * 1024
