package rules

import (
	"fmt"
	"strings"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/topology"
)

// The built-in rules. Each is one of the rules CLAUDE.md names, with the
// MITRE ATT&CK for ICS technique it belongs to taken from the published
// matrix rather than from memory (see mitre.go).
//
// Two of CLAUDE.md's rules are not here yet and are not pretended to be: a
// new talker compared with a baseline needs the baseline package, and
// cleartext IT protocols on an OT segment need the Tier 3 dissectors that
// recognise them.
func builtins() []Rule {
	return []Rule{
		&unauthorisedCommand{},
		&s7ProgramControl{},
		&modbusBehaviourChange{},
		&dnp3OutstationControl{},
		&iec104Command{},
		&mmsControlWrite{},
		&gooseIntegrity{},
		&cipDeviceControl{},
		&opcuaInsecure{},
		&nonStandardPort{},
		&crossLevelFlow{},
		&exceptionStorm{seen: map[string]*pairCount{}},
		&malformedFrames{seen: map[string]*pairCount{}},
	}
}

// clientOf returns the endpoint that asked, which is the one a rule about
// "who did this" cares about.
//
// The direction of a single PDU inverts mid-session — during an S7 download
// the CPU sends the jobs that fetch each block — so the listening port
// decides, exactly as the inventory decides which side is the device.
func clientOf(ev model.Event) (client, server string) {
	src, dst := endpoints(ev)
	switch p := ev.ServerPort; {
	case p != 0 && ev.Flow.SrcPort == p && ev.Flow.DstPort != p:
		return dst, src
	case p != 0 && ev.Flow.DstPort == p && ev.Flow.SrcPort != p:
		return src, dst
	}
	if ev.Direction == model.DirResponse {
		return dst, src
	}
	return src, dst
}

// requestOnly reports whether an event is the asking half of an exchange. A
// rule about commands should not fire twice because the device answered.
func requestOnly(ev model.Event) bool { return ev.Direction != model.DirResponse }

// -----------------------------------------------------------------------
// OT-001: a command from a host that is not allowed to send one.

type unauthorisedCommand struct{}

func (*unauthorisedCommand) Describe() Description {
	return Description{
		ID:    "OT-001",
		Title: "Write, control or program operation from a host outside the engineering allow-list",
		Description: "An operation that changes a device came from an address that is not on the " +
			"engineering allow-list. In a plant where only named stations are allowed to write, " +
			"anything else writing is either an undocumented tool or an intruder.",
		Severity:  model.SeverityHigh,
		Technique: "T1692.001",
	}
}

// InactiveReason says why the rule cannot fire: without an allow-list it has
// nothing to compare against, and flagging every write in the plant would be
// worse than saying so.
func (*unauthorisedCommand) InactiveReason(ctx *Context) string {
	if ctx.HasAllowList() {
		return ""
	}
	return "no engineering allow-list is configured (rules.engineering_stations in otinv.yaml)"
}

func (r *unauthorisedCommand) Check(ctx *Context, ev model.Event) []Finding {
	if !ctx.HasAllowList() || !requestOnly(ev) {
		return nil
	}
	switch ev.Class {
	case model.ClassWrite, model.ClassControl, model.ClassProgram, model.ClassFirmware:
	default:
		return nil
	}

	client, server := clientOf(ev)
	if client == "" || ctx.IsEngineering(client) {
		return nil
	}

	severity := model.SeverityHigh
	if ev.Class == model.ClassWrite {
		severity = model.SeverityMedium
	}
	return []Finding{{
		Key: ctx.Identity(client) + "|" + ctx.Identity(server) + "|" + ev.Protocol + "|" + string(ev.Class),
		Summary: fmt.Sprintf("%s %s on %s from %s, which is not an engineering station",
			ev.Protocol, ev.Operation, ctx.Label(server), ctx.Label(client)),
		Severity: severity,
		Src:      client,
		Dst:      server,
		Protocol: ev.Protocol,
		Details: map[string]string{
			"classification": string(ev.Class),
			"operation":      ev.Operation,
		},
		Evidence: evidenceOf(ev),
	}}
}

// -----------------------------------------------------------------------
// OT-002: the S7 operations that change what a CPU runs.

type s7ProgramControl struct{}

func (*s7ProgramControl) Describe() Description {
	return Description{
		ID:    "OT-002",
		Title: "Siemens S7 CPU stopped, started or reprogrammed",
		Description: "A CPU was stopped or started, or a block was uploaded, downloaded, activated " +
			"or deleted. Outside a planned engineering window, each of these changes what the " +
			"plant does.",
		Severity:  model.SeverityHigh,
		Technique: "T0858",
	}
}

func (r *s7ProgramControl) Check(ctx *Context, ev model.Event) []Finding {
	if ev.Protocol != "s7comm" || !requestOnly(ev) {
		return nil
	}

	var (
		what      string
		technique string
		severity  = model.SeverityHigh
	)
	switch ev.Operation {
	case "PLC_STOP":
		what, technique = "stopped the CPU", "T0858"
	case "PLC_CONTROL":
		what, technique = "sent a CPU control service", "T0858"
		if service := ev.Attrs["pi_service"]; service != "" {
			switch service {
			case "_INSE":
				what, technique = "activated a downloaded block", "T0889"
			case "_DELE":
				what, technique = "deleted a block", "T0889"
			default:
				what = "ran the program invocation service " + service
			}
		}
	case "REQUEST_DOWNLOAD", "DOWNLOAD_BLOCK", "DOWNLOAD_ENDED":
		what, technique = "downloaded a block into the CPU", "T0843"
	case "START_UPLOAD", "UPLOAD", "END_UPLOAD":
		what, technique = "uploaded a block from the CPU", "T0845"
		severity = model.SeverityMedium
	default:
		return nil
	}

	client, server := clientOf(ev)
	details := map[string]string{"operation": ev.Operation}
	if block := ev.Attrs["block_name"]; block != "" {
		details["block"] = block
	}
	if service := ev.Attrs["pi_service"]; service != "" {
		details["pi_service"] = service
	}
	return []Finding{{
		// Keyed on what was done rather than on which step of it: a block
		// download is three services, and an analyst wants one finding
		// about the download, not three about its steps.
		Key:       ctx.Identity(client) + "|" + ctx.Identity(server) + "|" + what,
		Summary:   fmt.Sprintf("%s %s on %s", ctx.Label(client), what, ctx.Label(server)),
		Severity:  severity,
		Technique: technique,
		Src:       client,
		Dst:       server,
		Protocol:  ev.Protocol,
		Details:   details,
		Evidence:  evidenceOf(ev),
	}}
}

// -----------------------------------------------------------------------
// OT-003: the Modbus diagnostics that change how a device behaves.

type modbusBehaviourChange struct{}

func (*modbusBehaviourChange) Describe() Description {
	return Description{
		ID:    "OT-003",
		Title: "Modbus diagnostic that changes how a device answers",
		Description: "Function code 8 is mostly harmless counters, but two of its sub-functions are " +
			"not: Force Listen Only Mode silences a device on the bus, and Restart Communications " +
			"Option restarts its port. Both stop the device answering its master.",
		Severity:  model.SeverityHigh,
		Technique: "T0813",
	}
}

func (r *modbusBehaviourChange) Check(ctx *Context, ev model.Event) []Finding {
	if ev.Protocol != "modbus" || ev.Operation != "Diagnostics" || !requestOnly(ev) {
		return nil
	}
	sub := ev.Attrs["sub_function_name"]
	switch sub {
	case "ForceListenOnlyMode", "RestartCommunicationsOption":
	default:
		return nil
	}

	client, server := clientOf(ev)
	return []Finding{{
		Key:      ctx.Identity(client) + "|" + ctx.Identity(server) + "|" + sub,
		Summary:  fmt.Sprintf("%s sent %s to %s", ctx.Label(client), sub, ctx.Label(server)),
		Src:      client,
		Dst:      server,
		Protocol: ev.Protocol,
		Details:  map[string]string{"sub_function": sub},
		Evidence: evidenceOf(ev),
	}}
}

// -----------------------------------------------------------------------
// OT-004: the DNP3 functions that restart, silence or reprogram an outstation.

type dnp3OutstationControl struct{}

func (*dnp3OutstationControl) Describe() Description {
	return Description{
		ID:    "OT-004",
		Title: "DNP3 restart, application stop, unsolicited reporting disabled or file transfer",
		Description: "A master restarted an outstation, stopped its application, told it to stop " +
			"reporting on its own, or moved a file into it. A device that no longer reports is a " +
			"device nobody is watching.",
		Severity:  model.SeverityHigh,
		Technique: "T0816",
	}
}

func (r *dnp3OutstationControl) Check(ctx *Context, ev model.Event) []Finding {
	if ev.Protocol != "dnp3" || !requestOnly(ev) {
		return nil
	}

	var (
		what      string
		technique string
		severity  = model.SeverityHigh
	)
	switch ev.Operation {
	case "COLD_RESTART", "WARM_RESTART":
		what, technique = "restarted the outstation", "T0816"
	case "STOP_APPL":
		what, technique = "stopped the outstation's application", "T0881"
	case "START_APPL":
		what, technique = "started the outstation's application", "T0881"
		severity = model.SeverityMedium
	case "DISABLE_UNSOLICITED":
		what, technique = "disabled unsolicited reporting", "T1691.002"
	case "OPEN_FILE", "DELETE_FILE", "ABORT_FILE":
		what, technique = "moved or deleted a file on the outstation", "T0843"
	case "INITIALIZE_DATA", "INITIALIZE_APPL", "ACTIVATE_CONFIG":
		what, technique = "reinitialised or activated a configuration", "T0889"
	default:
		return nil
	}

	client, server := clientOf(ev)
	details := map[string]string{"operation": ev.Operation}
	if name := ev.Attrs["file_name"]; name != "" {
		details["file"] = name
	}
	// A broadcast address reaches every outstation on the link at once, which
	// is worth saying rather than naming one device.
	if broadcast := ev.Attrs["broadcast"]; broadcast != "" {
		details["broadcast"] = broadcast
	}
	return []Finding{{
		// As with S7, the key is what was done: a cold restart and a warm
		// restart are one finding about a restarted outstation.
		Key:       ctx.Identity(client) + "|" + ctx.Identity(server) + "|" + what,
		Summary:   fmt.Sprintf("%s %s at %s", ctx.Label(client), what, ctx.Label(server)),
		Severity:  severity,
		Technique: technique,
		Src:       client,
		Dst:       server,
		Protocol:  ev.Protocol,
		Details:   details,
		Evidence:  evidenceOf(ev),
	}}
}

// -----------------------------------------------------------------------
// OT-005: IEC 104 control commands.

type iec104Command struct{}

func (*iec104Command) Describe() Description {
	return Description{
		ID:    "OT-005",
		Title: "IEC 60870-5-104 control command",
		Description: "A single, double, regulating-step or set-point command was sent to a station. " +
			"These are the commands that open breakers and move set points; CLAUDE.md asks for " +
			"them to be visible, and an execute without a preceding select is worth a second look.",
		Severity:  model.SeverityMedium,
		Technique: "T1692.001",
	}
}

func (r *iec104Command) Check(ctx *Context, ev model.Event) []Finding {
	if ev.Protocol != "iec104" || ev.Class != model.ClassControl || !requestOnly(ev) {
		return nil
	}
	if !strings.HasPrefix(ev.Operation, "C_") {
		return nil
	}

	client, server := clientOf(ev)
	severity := model.SeverityMedium
	mode := ev.Attrs["command_mode"]
	if mode == "execute" {
		// Select arms a command; execute is the one that moves the plant.
		severity = model.SeverityHigh
	}
	details := map[string]string{"type_id": ev.Operation}
	if mode != "" {
		details["command_mode"] = mode
	}
	if ev.Address != nil {
		details["information_object"] = fmt.Sprint(*ev.Address)
	}
	return []Finding{{
		Key:      ctx.Identity(client) + "|" + ctx.Identity(server) + "|" + ev.Operation + "|" + mode,
		Summary:  fmt.Sprintf("%s sent %s to %s", ctx.Label(client), ev.Operation, ctx.Label(server)),
		Severity: severity,
		Src:      client,
		Dst:      server,
		Protocol: ev.Protocol,
		Details:  details,
		Evidence: evidenceOf(ev),
	}}
}

// -----------------------------------------------------------------------
// OT-006: an MMS write to a control object.

type mmsControlWrite struct{}

func (*mmsControlWrite) Describe() Description {
	return Description{
		ID:    "OT-006",
		Title: "IEC 61850 MMS write to a control object",
		Description: "A write reached an object under the control functional constraint — the Oper, " +
			"SBO or Cancel attribute of a switch or a breaker — which is how a substation is " +
			"operated over MMS rather than merely read.",
		Severity:  model.SeverityHigh,
		Technique: "T1692.001",
	}
}

func (r *mmsControlWrite) Check(ctx *Context, ev model.Event) []Finding {
	if ev.Protocol != "mms" || ev.Class != model.ClassWrite || !requestOnly(ev) {
		return nil
	}
	object := ev.Attrs["object"]
	if object == "" {
		object = ev.Attrs["objects"]
	}
	if !isControlObject(object) {
		return nil
	}

	client, server := clientOf(ev)
	return []Finding{{
		Key:      ctx.Identity(client) + "|" + ctx.Identity(server) + "|" + object,
		Summary:  fmt.Sprintf("%s wrote the control object %s on %s", ctx.Label(client), object, ctx.Label(server)),
		Src:      client,
		Dst:      server,
		Protocol: ev.Protocol,
		Details:  map[string]string{"object": object},
		Evidence: evidenceOf(ev),
	}}
}

// isControlObject reports whether an IEC 61850 reference names a control
// attribute: the CO functional constraint, or one of the control attributes
// a client writes to operate a device (IEC 61850-7-2, clause 20).
func isControlObject(reference string) bool {
	if reference == "" {
		return false
	}
	if strings.Contains(reference, "$CO$") || strings.Contains(reference, ".CO.") {
		return true
	}
	for _, attribute := range []string{"Oper", "SBO", "SBOw", "Cancel"} {
		if strings.HasSuffix(reference, "$"+attribute) || strings.HasSuffix(reference, "."+attribute) {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------
// OT-007: GOOSE counters that do not add up.

type gooseIntegrity struct{}

func (*gooseIntegrity) Describe() Description {
	return Description{
		ID:    "OT-007",
		Title: "GOOSE state or sequence counters inconsistent, or a simulated frame",
		Description: "GOOSE has no handshake and no authentication, so the counters are what a " +
			"subscriber has to trust. A state number that jumps, a sequence that goes backwards, " +
			"or a frame marked as coming from a test set is what an injected publication looks like.",
		Severity:  model.SeverityHigh,
		Technique: "T0848",
	}
}

func (r *gooseIntegrity) Check(ctx *Context, ev model.Event) []Finding {
	if ev.Protocol != "goose" {
		return nil
	}
	anomaly := ev.Attrs["anomaly"]
	if anomaly == "" {
		return nil
	}

	severity := model.SeverityMedium
	for _, serious := range []string{"st_num_jump", "sq_num_regression", "simulated_frame"} {
		if strings.Contains(anomaly, serious) {
			severity = model.SeverityHigh
		}
	}
	// A frame the publisher itself marks as test traffic is not an attack;
	// it is a test set on a live bus, which is its own kind of problem.
	src, dst := endpoints(ev)
	control := ev.Attrs["gocb_ref"]
	return []Finding{{
		Key:      ctx.Identity(src) + "|" + control + "|" + anomaly,
		Summary:  fmt.Sprintf("GOOSE publication from %s: %s", ctx.Label(src), anomaly),
		Severity: severity,
		Src:      src,
		Dst:      dst,
		Protocol: ev.Protocol,
		Details: map[string]string{
			"anomaly":  anomaly,
			"gocb_ref": control,
			"st_num":   ev.Attrs["st_num"],
			"sq_num":   ev.Attrs["sq_num"],
		},
		Evidence: evidenceOf(ev),
	}}
}

// -----------------------------------------------------------------------
// OT-008: CIP services that stop, reset or reflash a controller.

type cipDeviceControl struct{}

func (*cipDeviceControl) Describe() Description {
	return Description{
		ID:    "OT-008",
		Title: "EtherNet/IP service that stops, resets or reflashes a controller",
		Description: "A CIP Stop, Start, Reset or firmware service reached a controller. Stop and " +
			"Reset take a controller out of run; the firmware services replace what it runs.",
		Severity:  model.SeverityHigh,
		Technique: "T0858",
	}
}

func (r *cipDeviceControl) Check(ctx *Context, ev model.Event) []Finding {
	if ev.Protocol != "enip" || !requestOnly(ev) {
		return nil
	}

	var (
		what      string
		technique string
	)
	switch {
	case ev.Class == model.ClassFirmware:
		what, technique = "a firmware service", "T1693.001"
	case ev.Operation == "Stop":
		what, technique = "Stop", "T0858"
	case ev.Operation == "Start":
		what, technique = "Start", "T0858"
	case ev.Operation == "Reset":
		what, technique = "Reset", "T0816"
	default:
		return nil
	}

	client, server := clientOf(ev)
	details := map[string]string{"service": ev.Operation}
	if class := ev.Attrs["cip_class"]; class != "" {
		details["cip_class"] = class
	}
	if route := ev.Attrs["cip_route"]; route != "" {
		// An Unconnected_Send carries the request onward to a controller on
		// the backplane, which is the device that was actually stopped.
		details["routed_through"] = route
	}
	return []Finding{{
		Key:       ctx.Identity(client) + "|" + ctx.Identity(server) + "|" + ev.Operation,
		Summary:   fmt.Sprintf("%s sent %s to %s", ctx.Label(client), what, ctx.Label(server)),
		Technique: technique,
		Src:       client,
		Dst:       server,
		Protocol:  ev.Protocol,
		Details:   details,
		Evidence:  evidenceOf(ev),
	}}
}

// -----------------------------------------------------------------------
// OT-009: OPC UA with its security switched off.

type opcuaInsecure struct{}

func (*opcuaInsecure) Describe() Description {
	return Description{
		ID:    "OT-009",
		Title: "OPC UA channel or endpoint with security mode None",
		Description: "OPC UA is the one industrial protocol designed with security in it, which is " +
			"why it is worth checking whether it is switched on. A channel with message security " +
			"mode None is neither signed nor encrypted: anyone on the segment can read it and " +
			"forge it.",
		Severity:  model.SeverityHigh,
		Technique: "T0830",
	}
}

func (r *opcuaInsecure) Check(ctx *Context, ev model.Event) []Finding {
	if ev.Protocol != "opcua" {
		return nil
	}

	client, server := clientOf(ev)
	switch {
	case ev.Attrs["insecure_channel"] == "true":
		return []Finding{{
			Key: ctx.Identity(client) + "|" + ctx.Identity(server) + "|channel",
			Summary: fmt.Sprintf("OPC UA channel between %s and %s runs with security mode None",
				ctx.Label(client), ctx.Label(server)),
			Src:      client,
			Dst:      server,
			Protocol: ev.Protocol,
			Details: map[string]string{
				"security_mode":   ev.Attrs["security_mode"],
				"security_policy": ev.Attrs["security_policy"],
			},
			Evidence: evidenceOf(ev),
		}}
	case ev.Attrs["offers_insecure_endpoint"] == "true":
		return []Finding{{
			Key:      ctx.Identity(server) + "|endpoints",
			Summary:  fmt.Sprintf("OPC UA server %s offers an endpoint with security mode None", ctx.Label(server)),
			Severity: model.SeverityMedium,
			Src:      client,
			Dst:      server,
			Protocol: ev.Protocol,
			Details: map[string]string{
				"security_modes":    ev.Attrs["security_modes"],
				"security_policies": ev.Attrs["security_policies"],
			},
			Evidence: evidenceOf(ev),
		}}
	}
	return nil
}

// -----------------------------------------------------------------------
// OT-010: a protocol somewhere other than its own port.

type nonStandardPort struct{}

func (*nonStandardPort) Describe() Description {
	return Description{
		ID:    "OT-010",
		Title: "Industrial protocol on a non-standard port",
		Description: "A protocol was recognised by its own shape on a port that is not one of its " +
			"registered ones. That is often a deliberate configuration, and worth recording either " +
			"way: a firewall rule written against the standard port does not cover this traffic.",
		Severity:  model.SeverityLow,
		Technique: "T0885",
	}
}

func (r *nonStandardPort) Check(ctx *Context, ev model.Event) []Finding {
	port := ev.ServerPort
	if port == 0 || !ctx.KnownPorts(ev.Protocol) || ctx.StandardPort(ev.Protocol, port) {
		return nil
	}

	_, server := clientOf(ev)
	return []Finding{{
		Key: ctx.Identity(server) + "|" + ev.Protocol + "|" + fmt.Sprint(port),
		Summary: fmt.Sprintf("%s served on port %d by %s, which is not one of its registered ports",
			ev.Protocol, port, ctx.Label(server)),
		Dst:      server,
		Protocol: ev.Protocol,
		Details:  map[string]string{"server_port": fmt.Sprint(port)},
		Evidence: evidenceOf(ev),
	}}
}

// -----------------------------------------------------------------------
// OT-011: a flow that skips a level of the reference model.

type crossLevelFlow struct{}

func (*crossLevelFlow) Describe() Description {
	return Description{
		ID:    "OT-011",
		Title: "Flow between Purdue levels that are not neighbours",
		Description: "A conversation ran between two levels with at least one level between them — " +
			"the shape of traffic that bypasses whatever sits in the middle, a DMZ most of all. " +
			"The levels are inferred, so the asset pages are where to check the reasoning before " +
			"acting on this.",
		Severity:  model.SeverityMedium,
		Technique: "T0886",
	}
}

func (r *crossLevelFlow) CheckGraph(ctx *Context, g topology.Graph) []Finding {
	level := make(map[string]int, len(g.Nodes))
	label := make(map[string]string, len(g.Nodes))
	for _, n := range g.Nodes {
		level[n.ID] = n.Level
		label[n.ID] = n.Label
	}

	var out []Finding
	for _, edge := range g.CrossLevel() {
		evidence, ok := ctx.edgeEvidence(edge.Src, edge.Dst, edge.Protocol)
		if !ok {
			// No stored event backs this edge, so there is nothing an
			// analyst could check. CLAUDE.md: no finding without evidence.
			continue
		}
		out = append(out, Finding{
			Key: edge.ID,
			Summary: fmt.Sprintf("%s (level %d) talks %s to %s (level %d)",
				label[edge.Src], level[edge.Src], edge.Protocol, label[edge.Dst], level[edge.Dst]),
			Src:      label[edge.Src],
			Dst:      label[edge.Dst],
			Protocol: edge.Protocol,
			Details: map[string]string{
				"source_level":      fmt.Sprint(level[edge.Src]),
				"destination_level": fmt.Sprint(level[edge.Dst]),
				"events":            fmt.Sprint(edge.Events),
			},
			Evidence: evidence,
		})
	}
	return out
}

// -----------------------------------------------------------------------
// OT-012: a burst of exception replies.

type pairCount struct {
	count    int64
	total    int64
	evidence model.Evidence
	src, dst string
	protocol string
	detail   string
}

type exceptionStorm struct {
	seen map[string]*pairCount
}

// exceptionThreshold is how many exception replies between one pair make a
// finding, and the share of their traffic they have to be. A handful of
// exceptions is ordinary; a stream of them is a client asking for things that
// are not there, which is what enumerating a device looks like.
const (
	exceptionThreshold = 10
	exceptionShare     = 0.25
)

func (*exceptionStorm) Describe() Description {
	return Description{
		ID:    "OT-012",
		Title: "Burst of protocol exceptions between two devices",
		Description: "One endpoint answered another with exceptions for a large share of their " +
			"traffic. A misconfigured client does this, and so does an inventory of a device's " +
			"registers or points: the exceptions are the addresses that do not exist.",
		Severity:  model.SeverityLow,
		Technique: "T0861",
	}
}

func (r *exceptionStorm) Check(_ *Context, ev model.Event) []Finding {
	if ev.Protocol == "" {
		return nil
	}
	src, dst := endpoints(ev)
	key := src + "|" + dst + "|" + ev.Protocol
	stat := r.seen[key]
	if stat == nil {
		stat = &pairCount{src: src, dst: dst, protocol: ev.Protocol}
		r.seen[key] = stat
	}
	stat.total++
	if ev.Exception == "" {
		return nil
	}
	stat.count++
	if stat.evidence.Protocol == "" {
		stat.evidence = evidenceOf(ev)
		stat.detail = ev.Exception
	}
	return nil
}

// CheckGraph reports the pairs that crossed the threshold. It takes no notice
// of the graph: the counting happened per event, and this is where a rule
// that has to see everything first gets to speak.
func (r *exceptionStorm) CheckGraph(ctx *Context, _ topology.Graph) []Finding {
	var out []Finding
	for key, stat := range r.seen {
		if stat.count < exceptionThreshold || float64(stat.count) < exceptionShare*float64(stat.total) {
			continue
		}
		out = append(out, Finding{
			Key: key,
			Summary: fmt.Sprintf("%s answered %s with %d exceptions out of %d %s messages",
				ctx.Label(stat.src), ctx.Label(stat.dst), stat.count, stat.total, stat.protocol),
			Src:      stat.src,
			Dst:      stat.dst,
			Protocol: stat.protocol,
			Details: map[string]string{
				"exceptions": fmt.Sprint(stat.count),
				"messages":   fmt.Sprint(stat.total),
				"first":      stat.detail,
			},
			Evidence: stat.evidence,
		})
	}
	return out
}

// -----------------------------------------------------------------------
// OT-013: frames that do not decode.

type malformedFrames struct {
	seen map[string]*pairCount
}

// malformedThreshold is how many undecodable frames from one source make a
// finding. One is a truncated capture; a stream of them is a device that is
// broken or a frame that was crafted.
const malformedThreshold = 5

func (*malformedFrames) Describe() Description {
	return Description{
		ID:    "OT-013",
		Title: "Repeated undecodable frames from one source",
		Description: "A source sent frames that could not be decoded as the protocol they claim. " +
			"A broken stack does this; so does a crafted frame aimed at whatever parses it, which " +
			"is why otinv keeps them as evidence rather than dropping them.",
		Severity:  model.SeverityLow,
		Technique: "T0814",
	}
}

func (r *malformedFrames) Check(_ *Context, ev model.Event) []Finding {
	if !ev.Malformed {
		return nil
	}
	src, dst := endpoints(ev)
	key := src + "|" + ev.Protocol
	stat := r.seen[key]
	if stat == nil {
		stat = &pairCount{src: src, dst: dst, protocol: ev.Protocol}
		r.seen[key] = stat
	}
	stat.count++
	if stat.evidence.Protocol == "" {
		stat.evidence = evidenceOf(ev)
		stat.detail = ev.Error
	}
	return nil
}

func (r *malformedFrames) CheckGraph(ctx *Context, _ topology.Graph) []Finding {
	var out []Finding
	for key, stat := range r.seen {
		if stat.count < malformedThreshold {
			continue
		}
		out = append(out, Finding{
			Key: key,
			Summary: fmt.Sprintf("%s sent %d %s frames that could not be decoded",
				ctx.Label(stat.src), stat.count, stat.protocol),
			Src:      stat.src,
			Dst:      stat.dst,
			Protocol: stat.protocol,
			Details: map[string]string{
				"frames": fmt.Sprint(stat.count),
				"first":  stat.detail,
			},
			Evidence: stat.evidence,
		})
	}
	return out
}
