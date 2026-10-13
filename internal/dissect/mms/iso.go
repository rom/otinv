package mms

import (
	"fmt"
	"strconv"
)

// The layers between COTP and MMS: the ISO 8327-1 session layer, the ISO 8823
// presentation layer and the ISO 8650-1 association control service element.
//
// IEC 61850 inherits the whole OSI upper stack, so getting to the operation an
// analyst cares about means walking all three. They are worth walking rather
// than skipping past: the association layer is where the two ends name each
// other, say which authentication they will use and accept or refuse the
// association, and a refused association is exactly the kind of evidence this
// tool exists to keep.

// sessionPDU is one decoded session layer PDU.
type sessionPDU struct {
	name     string
	attrs    map[string]string
	anomaly  string
	userData []byte
}

// decodeSession reads the session layer. A data transfer is a GIVE TOKENS
// SPDU immediately followed by a DATA TRANSFER SPDU, both empty, and the user
// data is whatever follows; every other SPDU carries its user data as a
// parameter (ISO 8327-1, clause 8).
func decodeSession(data []byte) (sessionPDU, error) {
	if len(data) < 2 {
		return sessionPDU{}, fmt.Errorf("%w: %d octets cannot hold an SPDU header",
			errSession, len(data))
	}

	// The common case first: the token-giving pair that opens every data
	// transfer.
	if data[0] == spduDataTransfer && data[1] == 0 {
		rest := data[2:]
		if len(rest) >= 2 && rest[0] == spduDataTransfer && rest[1] == 0 {
			return sessionPDU{name: "DATA_TRANSFER", userData: rest[2:]}, nil
		}
		// A lone DATA TRANSFER without the token grant. Legal when the token
		// is already held, and what some stacks always send.
		return sessionPDU{name: "DATA_TRANSFER", userData: rest}, nil
	}

	out := sessionPDU{name: spduName(data[0]), attrs: map[string]string{}}
	length := int(data[1])
	end := 2 + length
	if end > len(data) {
		// The parameter field is shorter than its own header claims. Stacks
		// in the field get this off by an octet, and refusing the PDU over it
		// would lose the association setup it carries, so what is there is
		// read and the discrepancy is reported rather than passed off as
		// normal.
		out.anomaly = "session_length_overruns_frame"
		end = len(data)
	}
	params := data[2:end]

	for off := 0; off+2 <= len(params); {
		code, plen := params[off], int(params[off+1])
		if off+2+plen > len(params) {
			out.anomaly = "session_parameter_overruns_spdu"
			break
		}
		value := params[off+2 : off+2+plen]
		switch code {
		case sesUserData, sesExtendedUserData:
			if plen > 0 {
				out.userData = value
			}
		case 50: // reason code, on a REFUSE or a DISCONNECT
			if plen > 0 {
				out.attrs["session_reason"] = strconv.Itoa(int(value[0]))
			}
		case 51:
			out.attrs["calling_session_selector"] = fmt.Sprintf("0x%x", value)
		case 52:
			out.attrs["called_session_selector"] = fmt.Sprintf("0x%x", value)
		}
		off += 2 + plen
	}

	if len(out.userData) == 0 {
		// Some stacks declare the user data parameter empty and then append
		// the presentation PDU anyway. Reading it is better than losing the
		// association setup, but the encoding is off-spec and is reported as
		// such rather than passed off as normal.
		if rest, ok := undeclaredUserData(params); ok {
			out.userData = rest
			out.anomaly = "session_user_data_not_declared"
		}
	}
	return out, nil
}

// undeclaredUserData looks for a presentation PDU sitting in the parameter
// field without a parameter header of its own.
func undeclaredUserData(params []byte) ([]byte, bool) {
	for off := 0; off+2 <= len(params); {
		code, plen := params[off], int(params[off+1])
		if looksLikePresentation(params[off:]) {
			return params[off:], true
		}
		if off+2+plen > len(params) {
			return nil, false
		}
		_ = code
		off += 2 + plen
	}
	return nil, false
}

// looksLikePresentation reports whether b opens with a presentation PDU that
// accounts for everything after it: either the SET of a connect PDU or the
// fully-encoded-data of a transfer.
func looksLikePresentation(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	if b[0] != 0x31 && b[0] != 0x61 {
		return false
	}
	_, err := readOne(b)
	return err == nil
}

func spduName(si uint8) string {
	if name, ok := spduNames[si]; ok {
		return name
	}
	return "SPDU_" + strconv.Itoa(int(si))
}

// pdv is one presentation data value: the context it was sent under and the
// bytes it carries.
type pdv struct {
	context int64
	data    []byte
}

// decodePresentation reads the presentation layer and returns the data values
// it carries. The connect PDUs wrap theirs in a SET of negotiation
// parameters; a transfer sends them on their own (ISO 8823, clause 8).
func decodePresentation(b []byte) (string, []pdv, error) {
	top, err := readOne(b)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %s", errPresentation, err.Error())
	}
	bud := newBudget()

	switch {
	case top.class == classApplication && top.number == 1:
		return "user-data", collectPDVs(top, bud), nil

	case top.class == classUniversal && top.number == tagSet:
		// CP-type, CPA-type or CPR-type: the connect, accept and reject PDUs.
		params, _ := top.descend(bud)
		for _, p := range params {
			if !p.ctx(2) {
				continue
			}
			kids, _ := p.descend(bud)
			for _, k := range kids {
				if k.class == classApplication && k.number == 1 {
					return "connect", collectPDVs(k, bud), nil
				}
			}
		}
		return "connect", nil, nil

	default:
		return top.tag(), nil, fmt.Errorf("%w: unexpected element %s", errPresentation, top.tag())
	}
}

// collectPDVs walks a fully-encoded-data element.
func collectPDVs(fed tlv, bud *budget) []pdv {
	lists, _ := fed.descend(bud)
	out := make([]pdv, 0, len(lists))
	for _, list := range lists {
		kids, _ := list.descend(bud)
		entry := pdv{context: -1}
		for _, k := range kids {
			switch {
			case k.class == classUniversal && k.number == tagInteger:
				if v, ok := k.integer(); ok {
					entry.context = v
				}
			case k.class == classContext && k.number <= 2:
				entry.data = k.value
			}
		}
		if entry.data != nil {
			out = append(out, entry)
		}
	}
	return out
}

// association is a decoded ACSE APDU: what it is, what the two ends said
// about themselves, and the MMS PDU it carries.
type association struct {
	name  string
	attrs map[string]string
	inner []byte
}

// acseResults names the AARE result field: whether the association was
// accepted, and if not whether trying again could help (ISO 8650-1).
var acseResults = map[int64]string{
	0: "accepted",
	1: "rejected_permanent",
	2: "rejected_transient",
}

// decodeACSE reads an association control APDU, if that is what b holds.
func decodeACSE(b []byte) (association, bool) {
	top, err := readOne(b)
	if err != nil || top.class != classApplication {
		return association{}, false
	}
	name, ok := acseNames[top.number]
	if !ok {
		return association{}, false
	}

	out := association{name: name, attrs: map[string]string{}}
	bud := newBudget()
	fields, _ := top.descend(bud)
	for _, f := range fields {
		if f.class != classContext {
			continue
		}
		switch {
		case f.number == 1:
			// The application context names what will be spoken over the
			// association, which for IEC 61850 is always the MMS context.
			setOID(out.attrs, "application_context", f, bud)

		case f.number == 2 && (top.number == 0 || top.number == 2 || top.number == 3):
			// AARQ names the called application process here; the release
			// PDUs have no field 2, so only an AARQ reaches this.
			setOID(out.attrs, "called_ap_title", f, bud)
		case f.number == 2 && top.number == 1:
			if v, ok := innerInt(f, bud); ok {
				out.attrs["result"] = resultName(v)
			}

		case f.number == 3 && top.number == 0:
			if v, ok := innerInt(f, bud); ok {
				out.attrs["called_ae_qualifier"] = strconv.FormatInt(v, 10)
			}
		case f.number == 4 && top.number == 1:
			setOID(out.attrs, "responding_ap_title", f, bud)
		case f.number == 5 && top.number == 1:
			if v, ok := innerInt(f, bud); ok {
				out.attrs["responding_ae_qualifier"] = strconv.FormatInt(v, 10)
			}

		case f.number == 6 && top.number == 0:
			setOID(out.attrs, "calling_ap_title", f, bud)
		case f.number == 7 && top.number == 0:
			if v, ok := innerInt(f, bud); ok {
				out.attrs["calling_ae_qualifier"] = strconv.FormatInt(v, 10)
			}

		case f.number == 11:
			// The authentication mechanism the client chose.
			if s, ok := f.oid(); ok {
				out.attrs["authentication_mechanism"] = s
			}
		case f.number == 12:
			// The authentication value itself. IEC 61850 sends a password
			// here in the clear, so the fact that one was sent is recorded
			// and the value deliberately is not: this tool must not become
			// the place a captured password ends up stored and rendered.
			out.attrs["authentication"] = "password"

		case f.number == 29:
			if s, ok := f.text(); ok {
				out.attrs["implementation"] = s
			}

		case f.number == 30:
			out.inner = userInformation(f, bud)
		}
	}
	return out, true
}

func resultName(v int64) string {
	if name, ok := acseResults[v]; ok {
		return name
	}
	return "result_" + strconv.FormatInt(v, 10)
}

// userInformation pulls the embedded PDU out of an ACSE user-information
// field, which is a sequence of EXTERNALs.
func userInformation(f tlv, bud *budget) []byte {
	externals, _ := f.descend(bud)
	for _, ext := range externals {
		kids, _ := ext.descend(bud)
		for _, k := range kids {
			if k.class == classContext && k.number <= 2 {
				return k.value
			}
		}
	}
	return nil
}

// setOID records an object identifier held inside a CHOICE wrapper.
func setOID(attrs map[string]string, key string, f tlv, bud *budget) {
	if s, ok := f.oid(); ok && !f.constructed {
		attrs[key] = s
		return
	}
	kids, _ := f.descend(bud)
	for _, k := range kids {
		if k.class == classUniversal && k.number == tagOID {
			if s, ok := k.oid(); ok {
				attrs[key] = s
				return
			}
		}
	}
}

// innerInt reads an integer held inside a CHOICE wrapper.
func innerInt(f tlv, bud *budget) (int64, bool) {
	if !f.constructed {
		return f.integer()
	}
	kids, _ := f.descend(bud)
	for _, k := range kids {
		if v, ok := k.integer(); ok {
			return v, true
		}
	}
	return 0, false
}
