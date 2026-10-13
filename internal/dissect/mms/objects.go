package mms

import (
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/model"
)

// Decoding of what an MMS service names and reports: the objects it addresses,
// the identity a device gives of itself, and the error a server answers with.

// Limits on the strings taken off the wire.
const (
	// maxNameLen caps an MMS Identifier. The standard allows 32 octets and
	// IEC 61850 object references run longer; 128 covers the longest
	// reference a substation configuration produces without letting a
	// crafted frame put a kilobyte of text into an event.
	maxNameLen = 128

	// maxOIDLen caps an object identifier's encoded length.
	maxOIDLen = 32

	// maxListedNames caps how many object names one event lists. A read of a
	// whole data set addresses dozens; the operation is what the event is
	// for, and the flow view holds the detail.
	maxListedNames = 8
)

// objectName renders an MMS ObjectName (ISO 9506-2). The three forms say where
// the object lives: in the device as a whole, inside one of its domains, or
// only within this association.
//
// In IEC 61850 the domain is the logical device, which is the name an engineer
// gave the device in the substation configuration, and the item is the rest of
// the reference — logical node, functional constraint, data object, attribute.
func objectName(t tlv, bud *budget) (name, domain, item string, ok bool) {
	switch {
	case t.ctx(0) && !t.constructed:
		// vmd-specific: one identifier, scoped to the whole device.
		if s, good := t.text(); good {
			return s, "", s, true
		}
	case t.ctx(1) && t.constructed:
		// domain-specific: the domain and the item within it.
		kids, _ := t.descend(bud)
		if len(kids) != 2 || kids[0].constructed || kids[1].constructed {
			return "", "", "", false
		}
		d, okd := kids[0].text()
		i, oki := kids[1].text()
		if !okd || !oki {
			return "", "", "", false
		}
		return d + "/" + i, d, i, true
	case t.ctx(2) && !t.constructed:
		// aa-specific: scoped to this association only.
		if s, good := t.text(); good {
			return s, "", s, true
		}
	}
	return "", "", "", false
}

// addressed collects the objects a service names.
//
// The walk is structured rather than a search for anything that looks like
// text, because a write carries the value it writes right next to the name it
// writes to, and a visible string in a data value is not an object name. Each
// service is entered only where its definition puts names.
func addressed(pdu uint32, svc uint32, body tlv, bud *budget) (names []string, domain, item string) {
	// Only a request and an unsolicited report name what they act on. A
	// response carries results, and reading its first element as a name turns
	// a vendor string in an Identify reply into an object that does not exist.
	if pdu != pduConfirmedRequest && pdu != pduUnconfirmed {
		return nil, "", ""
	}
	add := func(t tlv) {
		n, d, i, ok := objectName(t, bud)
		if !ok {
			return
		}
		if len(names) < maxListedNames {
			names = append(names, n)
		}
		if domain == "" {
			domain, item = d, i
		}
	}

	switch {
	case pdu == pduUnconfirmed:
		// InformationReport and friends open with the access specification.
		kids, _ := body.descend(bud)
		if len(kids) > 0 {
			walkAccessSpec(kids[0], bud, add)
		}

	case svc == svcRead:
		// Read-Request tags its access specification, so the alternative the
		// client chose sits one level further in than in a write, where the
		// specification is untagged.
		if spec, ok := body.find(bud, 1); ok {
			alts, _ := spec.descend(bud)
			for _, alt := range alts {
				walkAccessSpec(alt, bud, add)
			}
		}

	case svc == svcWrite:
		// Write-Request leaves its access specification untagged, so it is
		// the first element; everything after it is the data being written.
		kids, _ := body.descend(bud)
		if len(kids) > 0 {
			walkAccessSpec(kids[0], bud, add)
		}

	case svc == svcGetVariableAccessAttributes:
		// A CHOICE of a name or an address.
		if n, ok := body.find(bud, 0); ok {
			walkObjectName(n, bud, add)
		}

	default:
		// Every other service that names something puts a single identifier
		// or object name first: a program invocation, a domain, a semaphore,
		// a file. Some put it in the service element itself.
		if !body.constructed {
			add(tlv{class: classContext, number: 0, value: body.value})
			break
		}
		kids, _ := body.descend(bud)
		if len(kids) > 0 {
			walkObjectName(kids[0], bud, add)
		}
	}

	// A bare identifier says nothing about what kind of name it is, so only
	// the services whose definition puts a domain there are read as naming
	// one. Calling a program invocation or a semaphore a logical device would
	// put a name on the asset that is not its own.
	if domain == "" && domainServices[svc] && len(names) > 0 {
		domain = names[0]
	}
	return names, domain, item
}

// domainServices are the services whose first identifier is a domain name,
// which in IEC 61850 is the logical device (ISO 9506-2, the domain
// management and domain upload and download services).
var domainServices = map[uint32]bool{
	26: true, // initiateDownloadSequence
	27: true, // downloadSegment
	28: true, // terminateDownloadSequence
	29: true, // initiateUploadSequence
	31: true, // terminateUploadSequence
	32: true, // requestDomainDownload
	33: true, // requestDomainUpload
	34: true, // loadDomainContent
	35: true, // storeDomainContent
	36: true, // deleteDomain
	37: true, // getDomainAttributes
}

// walkAccessSpec enters a VariableAccessSpecification, which is either a list
// of variable specifications or the name of a stored list.
func walkAccessSpec(spec tlv, bud *budget, add func(tlv)) {
	switch {
	case spec.ctx(0) && spec.constructed:
		// listOfVariable: a sequence of specifications, each wrapping a name.
		entries, _ := spec.descend(bud)
		for _, e := range entries {
			kids, _ := e.descend(bud)
			for _, k := range kids {
				if k.ctx(0) {
					walkObjectName(k, bud, add)
				}
			}
		}
	case spec.ctx(1):
		// variableListName: the name of a list the server holds.
		walkObjectName(spec, bud, add)
	}
}

// walkObjectName accepts either an ObjectName or the VariableSpecification
// CHOICE that wraps one.
func walkObjectName(t tlv, bud *budget, add func(tlv)) {
	if _, _, _, ok := objectName(t, bud); ok {
		add(t)
		return
	}
	// A variableSpecification [0] holding a name [0], or a variableListName
	// [1] holding the ObjectName CHOICE.
	kids, _ := t.descend(bud)
	for _, k := range kids {
		if _, _, _, ok := objectName(k, bud); ok {
			add(k)
			return
		}
	}
}

// identify reads an Identify-Response, which is how an MMS device names
// itself: the one place in the protocol where it says what it is without
// being asked anything beyond "what are you".
func identify(body tlv, bud *budget) map[string]string {
	kids, _ := body.descend(bud)
	out := map[string]string{}
	for _, k := range kids {
		s, ok := k.text()
		if !ok {
			continue
		}
		switch {
		case k.ctx(0):
			out["vendor_name"] = s
		case k.ctx(1):
			out["model_name"] = s
		case k.ctx(2):
			out["revision"] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// reportID reads the report reference out of an information report.
//
// IEC 61850 carries it as the first access result of a report whose variable
// list is the device-wide "RPT" (IEC 61850-8-1): the report control block's
// own reference, which names the logical device and the report. It is the
// most useful thing a passive observer gets from report traffic, since a
// server pushing reports never has to be asked anything.
func reportID(body tlv, bud *budget) string {
	kids, _ := body.descend(bud)
	for _, k := range kids {
		if !k.ctx(0) || !k.constructed {
			continue
		}
		results, _ := k.descend(bud)
		if len(results) == 0 {
			return ""
		}
		// visible-string [10] of the Data CHOICE.
		if first := results[0]; first.ctx(10) {
			if s, ok := first.text(); ok {
				return s
			}
		}
		return ""
	}
	return ""
}

// errorCodes names the code within each ServiceError class that carries one
// (ISO 9506-2). The classes left out use codes whose meaning is specific to
// the service that failed, so their numbers are reported as they are.
var errorCodes = map[uint32]map[int64]string{
	0: { // vmd-state
		0: "other", 1: "vmd-state-conflict", 2: "vmd-operational-problem",
		3: "domain-transfer-problem", 4: "state-machine-id-invalid",
	},
	1: { // application-reference
		0: "other", 1: "application-unreachable", 2: "connection-lost",
		3: "application-reference-invalid", 4: "context-unsupported",
	},
	2: { // definition
		0: "object-undefined", 1: "invalid-address", 2: "type-unsupported",
		3: "type-inconsistent", 4: "object-exists", 5: "object-attribute-inconsistent",
	},
	3: { // resource
		0: "memory-unavailable", 1: "processor-resource-unavailable",
		2: "mass-storage-unavailable", 3: "capability-unavailable",
		4: "capability-unknown",
	},
	4: { // service
		0: "other", 1: "object-state-conflict", 3: "continuation-invalid",
		4: "object-constraint-conflict",
	},
	7: { // access
		0: "object-access-unsupported", 1: "object-non-existent",
		2: "object-access-denied", 3: "object-invalidated",
	},
}

// serviceError renders the error a server answered with. The class says what
// kind of refusal it was, and within the access class the code separates "no
// such object" from "you may not have it", which is the difference between a
// misconfigured client and one reaching for what it should not.
func serviceError(body tlv, bud *budget) string {
	class, ok := body.find(bud, 0)
	if !ok {
		return ""
	}
	alt := class
	if class.constructed {
		kids, _ := class.descend(bud)
		if len(kids) == 0 {
			return ""
		}
		alt = kids[0]
	}
	if alt.class != classContext {
		return ""
	}
	name, known := errorClasses[alt.number]
	if !known {
		name = "errorClass" + utoa(alt.number)
	}
	code, hasCode := alt.integer()
	if !hasCode {
		return name
	}
	if table, ok := errorCodes[alt.number]; ok {
		if label, ok := table[code]; ok {
			return name + "/" + label
		}
	}
	return name + "/" + strconv.FormatInt(code, 10)
}

// initiateDetail records what the two ends agreed the association may carry.
// The negotiated PDU size is the one number that bounds everything above it.
func initiateDetail(ev *model.Event, body tlv, bud *budget) {
	kids, _ := body.descend(bud)
	for _, k := range kids {
		switch {
		case k.ctx(0):
			if v, ok := k.integer(); ok {
				setAttr(ev, "max_pdu_size", strconv.FormatInt(v, 10))
			}
		case k.ctx(4) && k.constructed:
			detail, _ := k.descend(bud)
			for _, d := range detail {
				if d.ctx(0) {
					if v, ok := d.integer(); ok {
						setAttr(ev, "mms_version", strconv.FormatInt(v, 10))
					}
				}
			}
		}
	}
}

func setAttr(ev *model.Event, key, value string) {
	if value == "" {
		return
	}
	if ev.Attrs == nil {
		ev.Attrs = make(map[string]string, 8)
	}
	ev.Attrs[key] = value
}

// addAnomaly records an anomaly, keeping any already there.
func addAnomaly(ev *model.Event, name string) {
	existing := ev.Attrs["anomaly"]
	switch {
	case existing == "":
		setAttr(ev, "anomaly", name)
	case strings.Contains(existing, name):
	default:
		setAttr(ev, "anomaly", existing+","+name)
	}
}

func setIdentity(ev *model.Event, key, value string) {
	if value == "" {
		return
	}
	if ev.Identity == nil {
		ev.Identity = make(map[string]string, 4)
	}
	ev.Identity[key] = value
}
