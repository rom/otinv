package mms

import (
	"strconv"
	"strings"

	"github.com/rom/otinv/internal/dissect/ber"
	"github.com/rom/otinv/internal/model"
)

// Decoding of what an MMS service names and reports: the objects it addresses,
// the identity a device gives of itself, and the error a server answers with.

// maxListedNames caps how many object names one event lists. A read of a
// whole data set addresses dozens; the operation is what the event is for,
// and the flow view holds the detail.
const maxListedNames = 8

// objectName renders an MMS ObjectName (ISO 9506-2). The three forms say where
// the object lives: in the device as a whole, inside one of its domains, or
// only within this association.
//
// In IEC 61850 the domain is the logical device, which is the name an engineer
// gave the device in the substation configuration, and the item is the rest of
// the reference — logical node, functional constraint, data object, attribute.
func objectName(t ber.TLV, bud *ber.Budget) (name, domain, item string, ok bool) {
	switch {
	case t.Ctx(0) && !t.Constructed:
		// vmd-specific: one identifier, scoped to the whole device.
		if s, good := t.Text(); good {
			return s, "", s, true
		}
	case t.Ctx(1) && t.Constructed:
		// domain-specific: the domain and the item within it.
		kids, _ := t.Descend(bud)
		if len(kids) != 2 || kids[0].Constructed || kids[1].Constructed {
			return "", "", "", false
		}
		d, okd := kids[0].Text()
		i, oki := kids[1].Text()
		if !okd || !oki {
			return "", "", "", false
		}
		return d + "/" + i, d, i, true
	case t.Ctx(2) && !t.Constructed:
		// aa-specific: scoped to this association only.
		if s, good := t.Text(); good {
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
func addressed(pdu uint32, svc uint32, body ber.TLV, bud *ber.Budget) (names []string, domain, item string) {
	// Only a request and an unsolicited report name what they act on. A
	// response carries results, and reading its first element as a name turns
	// a vendor string in an Identify reply into an object that does not exist.
	if pdu != pduConfirmedRequest && pdu != pduUnconfirmed {
		return nil, "", ""
	}
	add := func(t ber.TLV) {
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
		kids, _ := body.Descend(bud)
		if len(kids) > 0 {
			walkAccessSpec(kids[0], bud, add)
		}

	case svc == svcRead:
		// Read-Request tags its access specification, so the alternative the
		// client chose sits one level further in than in a write, where the
		// specification is untagged.
		if spec, ok := body.Find(bud, 1); ok {
			alts, _ := spec.Descend(bud)
			for _, alt := range alts {
				walkAccessSpec(alt, bud, add)
			}
		}

	case svc == svcWrite:
		// Write-Request leaves its access specification untagged, so it is
		// the first element; everything after it is the data being written.
		kids, _ := body.Descend(bud)
		if len(kids) > 0 {
			walkAccessSpec(kids[0], bud, add)
		}

	case svc == svcGetVariableAccessAttributes:
		// A CHOICE of a name or an address.
		if n, ok := body.Find(bud, 0); ok {
			walkObjectName(n, bud, add)
		}

	default:
		// Every other service that names something puts a single identifier
		// or object name first: a program invocation, a domain, a semaphore,
		// a file. Some put it in the service element itself.
		if !body.Constructed {
			add(ber.TLV{Class: ber.ClassContext, Number: 0, Value: body.Value})
			break
		}
		kids, _ := body.Descend(bud)
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
func walkAccessSpec(spec ber.TLV, bud *ber.Budget, add func(ber.TLV)) {
	switch {
	case spec.Ctx(0) && spec.Constructed:
		// listOfVariable: a sequence of specifications, each wrapping a name.
		entries, _ := spec.Descend(bud)
		for _, e := range entries {
			kids, _ := e.Descend(bud)
			for _, k := range kids {
				if k.Ctx(0) {
					walkObjectName(k, bud, add)
				}
			}
		}
	case spec.Ctx(1):
		// variableListName: the name of a list the server holds.
		walkObjectName(spec, bud, add)
	}
}

// walkObjectName accepts either an ObjectName or the VariableSpecification
// CHOICE that wraps one.
func walkObjectName(t ber.TLV, bud *ber.Budget, add func(ber.TLV)) {
	if _, _, _, ok := objectName(t, bud); ok {
		add(t)
		return
	}
	// A variableSpecification [0] holding a name [0], or a variableListName
	// [1] holding the ObjectName CHOICE.
	kids, _ := t.Descend(bud)
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
func identify(body ber.TLV, bud *ber.Budget) map[string]string {
	kids, _ := body.Descend(bud)
	out := map[string]string{}
	for _, k := range kids {
		s, ok := k.Text()
		if !ok {
			continue
		}
		switch {
		case k.Ctx(0):
			out["vendor_name"] = s
		case k.Ctx(1):
			out["model_name"] = s
		case k.Ctx(2):
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
func reportID(body ber.TLV, bud *ber.Budget) string {
	kids, _ := body.Descend(bud)
	for _, k := range kids {
		if !k.Ctx(0) || !k.Constructed {
			continue
		}
		results, _ := k.Descend(bud)
		if len(results) == 0 {
			return ""
		}
		// visible-string [10] of the Data CHOICE.
		if first := results[0]; first.Ctx(10) {
			if s, ok := first.Text(); ok {
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
func serviceError(body ber.TLV, bud *ber.Budget) string {
	class, ok := body.Find(bud, 0)
	if !ok {
		return ""
	}
	alt := class
	if class.Constructed {
		kids, _ := class.Descend(bud)
		if len(kids) == 0 {
			return ""
		}
		alt = kids[0]
	}
	if alt.Class != ber.ClassContext {
		return ""
	}
	name, known := errorClasses[alt.Number]
	if !known {
		name = "errorClass" + utoa(alt.Number)
	}
	code, hasCode := alt.Integer()
	if !hasCode {
		return name
	}
	if table, ok := errorCodes[alt.Number]; ok {
		if label, ok := table[code]; ok {
			return name + "/" + label
		}
	}
	return name + "/" + strconv.FormatInt(code, 10)
}

// initiateDetail records what the two ends agreed the association may carry.
// The negotiated PDU size is the one number that bounds everything above it.
func initiateDetail(ev *model.Event, body ber.TLV, bud *ber.Budget) {
	kids, _ := body.Descend(bud)
	for _, k := range kids {
		switch {
		case k.Ctx(0):
			if v, ok := k.Integer(); ok {
				setAttr(ev, "max_pdu_size", strconv.FormatInt(v, 10))
			}
		case k.Ctx(4) && k.Constructed:
			detail, _ := k.Descend(bud)
			for _, d := range detail {
				if d.Ctx(0) {
					if v, ok := d.Integer(); ok {
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
