package rules_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/rules"
	"github.com/rom/otinv/internal/topology"
)

var at = time.Date(2024, 6, 3, 9, 30, 0, 0, time.UTC)

// plant is the inventory the rules read the project through.
func plant() []model.Asset {
	return []model.Asset{
		{
			Key: "mac:00:02:b3:ce:70:51", Label: "10.0.0.3",
			IPs: []string{"10.0.0.3"}, MACs: []string{"00:02:b3:ce:70:51"},
			Role:  model.Role{Name: model.RoleController, Confidence: 80},
			Level: model.Level{Value: 1, Confidence: 80},
		},
		{
			Key: "mac:00:20:78:00:62:0d", Label: "10.0.0.57",
			IPs: []string{"10.0.0.57"}, MACs: []string{"00:20:78:00:62:0d"},
			Role:  model.Role{Name: model.RoleOperator, Confidence: 60},
			Level: model.Level{Value: 2, Confidence: 65},
		},
		{
			Key: "mac:00:50:56:aa:bb:cc", Label: "10.9.9.9",
			IPs:   []string{"10.9.9.9"},
			Role:  model.Role{Name: model.RoleUnknown},
			Level: model.Level{Value: 4, Confidence: 50},
		},
	}
}

// event builds a request from the HMI to the controller.
func event(protocol, operation string, class model.Classification, i int) model.Event {
	return model.Event{
		CaptureID: "aa11", PacketIndex: uint64(i), Timestamp: at.Add(time.Duration(i) * time.Second),
		Flow: model.Flow{
			SrcIP: "10.0.0.57", DstIP: "10.0.0.3", SrcPort: 45000, DstPort: 502,
			Transport: model.TransportTCP,
		},
		ServerPort: 502,
		Protocol:   protocol, Direction: model.DirRequest,
		Operation: operation, Class: class, FunctionCode: 1,
	}
}

func run(t *testing.T, cfg rules.Config, events ...model.Event) []model.Finding {
	t.Helper()
	if cfg.Assets == nil {
		cfg.Assets = plant()
	}
	engine, err := rules.New(cfg)
	require.NoError(t, err)
	for _, ev := range events {
		engine.Add(ev)
	}
	engine.AddTopology(topology.Graph{})
	return engine.Findings()
}

// byRule indexes findings by the rule that raised them.
func byRule(findings []model.Finding) map[string]model.Finding {
	out := map[string]model.Finding{}
	for _, f := range findings {
		if _, seen := out[f.RuleID]; !seen {
			out[f.RuleID] = f
		}
	}
	return out
}

// Every finding has to be traceable to a packet, whatever raised it.
func TestEveryFindingCarriesItsEvidence(t *testing.T) {
	stop := event("s7comm", "PLC_STOP", model.ClassControl, 7)
	diag := event("modbus", "Diagnostics", model.ClassControl, 9)
	diag.Attrs = map[string]string{"sub_function_name": "ForceListenOnlyMode"}

	findings := run(t, rules.Config{}, stop, diag)
	require.NotEmpty(t, findings)
	for _, f := range findings {
		assert.NotEmpty(t, f.ID, f.RuleID)
		assert.NotEmpty(t, f.Title, f.RuleID)
		assert.NotEmpty(t, f.Summary, f.RuleID)
		assert.True(t, f.Severity.Valid(), f.RuleID)
		assert.Equal(t, model.StatusNew, f.Status, f.RuleID)
		assert.NotEmpty(t, f.Evidence.CaptureID, f.RuleID)
		assert.NotZero(t, f.Evidence.PacketIndex, f.RuleID)
		assert.NotEmpty(t, f.Evidence.Protocol, f.RuleID)
		assert.False(t, f.Evidence.Timestamp.IsZero(), f.RuleID)
		assert.NotEmpty(t, f.Technique, f.RuleID)
		assert.NotEmpty(t, f.TechniqueName, "%s cites a technique this build cannot name", f.RuleID)
	}
}

// The same observation twice is one finding with a count, not two rows.
func TestRepeatedObservationsMerge(t *testing.T) {
	var events []model.Event
	for i := range 5 {
		events = append(events, event("s7comm", "PLC_STOP", model.ClassControl, i+1))
	}

	findings := byRule(run(t, rules.Config{}, events...))
	stop := findings["OT-002"]
	assert.EqualValues(t, 5, stop.Count)
	assert.Equal(t, at.Add(time.Second), stop.FirstSeen)
	assert.Equal(t, at.Add(5*time.Second), stop.LastSeen)
	assert.EqualValues(t, 1, stop.Evidence.PacketIndex, "the evidence is the first one seen")
}

// A finding's id is derived from the rule and what it is about, so a re-run
// over the same project produces the same id — which is what lets triage
// survive a re-run.
func TestFindingIDsAreStableAcrossRuns(t *testing.T) {
	stop := event("s7comm", "PLC_STOP", model.ClassControl, 3)
	first := run(t, rules.Config{}, stop)
	second := run(t, rules.Config{}, stop)
	require.Len(t, first, len(second))
	for i := range first {
		assert.Equal(t, first[i].ID, second[i].ID)
	}

	// A different device is a different finding.
	elsewhere := stop
	elsewhere.Flow.DstIP = "10.0.0.8"
	third := run(t, rules.Config{}, elsewhere)
	require.NotEmpty(t, third)
	assert.NotEqual(t, first[0].ID, third[0].ID)
}

func TestEngineeringAllowList(t *testing.T) {
	write := event("modbus", "WriteSingleCoil", model.ClassWrite, 4)

	// With no allow-list the rule cannot fire, and says why.
	findings := run(t, rules.Config{}, write)
	assert.NotContains(t, byRule(findings), "OT-001")

	engine, err := rules.New(rules.Config{Assets: plant()})
	require.NoError(t, err)
	var inactive string
	for _, d := range engine.Rules() {
		if d.ID == "OT-001" {
			inactive = d.Inactive
		}
	}
	assert.Contains(t, inactive, "engineering allow-list")

	// With one, a write from a host outside it is a finding.
	findings = run(t, rules.Config{EngineeringStations: []string{"10.0.0.9"}}, write)
	f := byRule(findings)["OT-001"]
	require.NotEmpty(t, f.ID)
	assert.Equal(t, model.SeverityMedium, f.Severity, "a write is one step below a command")
	assert.Equal(t, "10.0.0.57", f.Src)
	assert.Equal(t, "10.0.0.3", f.Dst)
	assert.Contains(t, f.Summary, "not an engineering station")

	// And from a host inside it, it is not.
	findings = run(t, rules.Config{EngineeringStations: []string{"10.0.0.0/24"}}, write)
	assert.NotContains(t, byRule(findings), "OT-001")

	// A program operation outranks a write.
	program := event("s7comm", "DOWNLOAD_BLOCK", model.ClassProgram, 5)
	findings = run(t, rules.Config{EngineeringStations: []string{"10.0.0.9"}}, program)
	assert.Equal(t, model.SeverityHigh, byRule(findings)["OT-001"].Severity)
}

// The listening port decides who asked, because the direction of one PDU
// inverts mid-session: during a download the CPU sends the jobs.
func TestTheClientIsTheOneWhoAsked(t *testing.T) {
	download := event("s7comm", "DOWNLOAD_BLOCK", model.ClassProgram, 6)
	download.Flow = model.Flow{
		SrcIP: "10.0.0.3", DstIP: "10.0.0.57", SrcPort: 102, DstPort: 45000,
		Transport: model.TransportTCP,
	}
	download.ServerPort = 102

	f := byRule(run(t, rules.Config{EngineeringStations: []string{"10.0.0.9"}}, download))["OT-001"]
	require.NotEmpty(t, f.ID)
	assert.Equal(t, "10.0.0.57", f.Src, "the station that opened the session is the one programming")
	assert.Equal(t, "10.0.0.3", f.Dst)
}

func TestS7ProgramAndControlOperations(t *testing.T) {
	tests := []struct {
		operation string
		pi        string
		severity  model.Severity
		technique string
		summary   string
	}{
		{operation: "PLC_STOP", severity: model.SeverityHigh, technique: "T0858", summary: "stopped the CPU"},
		{operation: "DOWNLOAD_BLOCK", severity: model.SeverityHigh, technique: "T0843", summary: "downloaded a block"},
		{operation: "START_UPLOAD", severity: model.SeverityMedium, technique: "T0845", summary: "uploaded a block"},
		{operation: "PLC_CONTROL", pi: "_DELE", severity: model.SeverityHigh, technique: "T0889", summary: "deleted a block"},
		{operation: "PLC_CONTROL", pi: "_INSE", severity: model.SeverityHigh, technique: "T0889", summary: "activated a downloaded block"},
	}

	for _, tc := range tests {
		t.Run(tc.operation+tc.pi, func(t *testing.T) {
			ev := event("s7comm", tc.operation, model.ClassProgram, 2)
			if tc.pi != "" {
				ev.Attrs = map[string]string{"pi_service": tc.pi}
			}
			f := byRule(run(t, rules.Config{}, ev))["OT-002"]
			require.NotEmpty(t, f.ID)
			assert.Equal(t, tc.severity, f.Severity)
			assert.Equal(t, tc.technique, f.Technique)
			assert.Contains(t, f.Summary, tc.summary)
		})
	}

	// A read is not a program operation.
	read := event("s7comm", "READ_VAR", model.ClassRead, 3)
	assert.NotContains(t, byRule(run(t, rules.Config{}, read)), "OT-002")
}

func TestModbusDiagnosticsThatChangeBehaviour(t *testing.T) {
	force := event("modbus", "Diagnostics", model.ClassControl, 4)
	force.Attrs = map[string]string{"sub_function_name": "ForceListenOnlyMode"}
	f := byRule(run(t, rules.Config{}, force))["OT-003"]
	require.NotEmpty(t, f.ID)
	assert.Equal(t, model.SeverityHigh, f.Severity)
	assert.Equal(t, "T0813", f.Technique)

	// The counter sub-functions are not behaviour changes.
	counters := event("modbus", "Diagnostics", model.ClassDiagnostic, 5)
	counters.Attrs = map[string]string{"sub_function_name": "ClearCountersAndDiagnosticRegister"}
	assert.NotContains(t, byRule(run(t, rules.Config{}, counters)), "OT-003")
}

func TestDNP3OutstationControl(t *testing.T) {
	tests := []struct {
		operation string
		technique string
		severity  model.Severity
	}{
		{operation: "COLD_RESTART", technique: "T0816", severity: model.SeverityHigh},
		{operation: "STOP_APPL", technique: "T0881", severity: model.SeverityHigh},
		{operation: "DISABLE_UNSOLICITED", technique: "T1691.002", severity: model.SeverityHigh},
		{operation: "DELETE_FILE", technique: "T0843", severity: model.SeverityHigh},
		{operation: "START_APPL", technique: "T0881", severity: model.SeverityMedium},
	}
	for _, tc := range tests {
		t.Run(tc.operation, func(t *testing.T) {
			f := byRule(run(t, rules.Config{}, event("dnp3", tc.operation, model.ClassControl, 1)))["OT-004"]
			require.NotEmpty(t, f.ID)
			assert.Equal(t, tc.technique, f.Technique)
			assert.Equal(t, tc.severity, f.Severity)
		})
	}

	assert.NotContains(t, byRule(run(t, rules.Config{}, event("dnp3", "READ", model.ClassRead, 1))), "OT-004")
}

func TestIEC104CommandsAndTheirMode(t *testing.T) {
	selectCmd := event("iec104", "C_SC_NA_1", model.ClassControl, 1)
	selectCmd.Attrs = map[string]string{"command_mode": "select"}
	f := byRule(run(t, rules.Config{}, selectCmd))["OT-005"]
	require.NotEmpty(t, f.ID)
	assert.Equal(t, model.SeverityMedium, f.Severity, "select arms a command")

	execute := event("iec104", "C_SC_NA_1", model.ClassControl, 2)
	execute.Attrs = map[string]string{"command_mode": "execute"}
	f = byRule(run(t, rules.Config{}, execute))["OT-005"]
	assert.Equal(t, model.SeverityHigh, f.Severity, "execute moves the plant")

	// An interrogation is not a command.
	assert.NotContains(t, byRule(run(t, rules.Config{},
		event("iec104", "C_IC_NA_1", model.ClassRead, 3))), "OT-005")
}

func TestMMSWritesToControlObjects(t *testing.T) {
	control := event("mms", "write", model.ClassWrite, 1)
	control.Attrs = map[string]string{"object": "AA1C1Q01A1LD0/CSWI1$CO$Pos$Oper"}
	f := byRule(run(t, rules.Config{}, control))["OT-006"]
	require.NotEmpty(t, f.ID)
	assert.Equal(t, model.SeverityHigh, f.Severity)
	assert.Contains(t, f.Summary, "control object")

	// A write to a setting is not a control write.
	setting := event("mms", "write", model.ClassWrite, 2)
	setting.Attrs = map[string]string{"object": "AA1C1Q01A1LD0/MMXU1$SP$A$setMag"}
	assert.NotContains(t, byRule(run(t, rules.Config{}, setting)), "OT-006")
}

func TestGOOSEIntegrityAnomalies(t *testing.T) {
	publication := model.Event{
		CaptureID: "bb22", PacketIndex: 4, Timestamp: at,
		Flow: model.Flow{
			SrcMAC: "0a:bb:fe:10:c9:02", DstMAC: "01:0c:cd:01:00:00",
			Transport: model.TransportEthernet,
		},
		Protocol: "goose", Direction: model.DirResponse, Operation: "StateChange",
		Class: model.ClassRead,
		Attrs: map[string]string{"anomaly": "st_num_jump", "gocb_ref": "AA1/LLN0$GO$gcb01"},
	}
	f := byRule(run(t, rules.Config{}, publication))["OT-007"]
	require.NotEmpty(t, f.ID)
	assert.Equal(t, model.SeverityHigh, f.Severity)
	assert.Equal(t, "T0848", f.Technique)
	assert.Equal(t, "0a:bb:fe:10:c9:02", f.Src, "a publisher is named by its MAC")

	// A less serious anomaly is reported, lower.
	minor := publication
	minor.Attrs = map[string]string{"anomaly": "unknown_field"}
	f = byRule(run(t, rules.Config{}, minor))["OT-007"]
	assert.Equal(t, model.SeverityMedium, f.Severity)
}

func TestCIPDeviceControl(t *testing.T) {
	for _, tc := range []struct {
		operation string
		class     model.Classification
		technique string
	}{
		{operation: "Stop", class: model.ClassControl, technique: "T0858"},
		{operation: "Reset", class: model.ClassControl, technique: "T0816"},
		{operation: "Update_Firmware", class: model.ClassFirmware, technique: "T1693.001"},
	} {
		t.Run(tc.operation, func(t *testing.T) {
			f := byRule(run(t, rules.Config{}, event("enip", tc.operation, tc.class, 1)))["OT-008"]
			require.NotEmpty(t, f.ID)
			assert.Equal(t, tc.technique, f.Technique)
		})
	}

	assert.NotContains(t, byRule(run(t, rules.Config{},
		event("enip", "Get_Attribute_All", model.ClassRead, 1))), "OT-008")
}

func TestOPCUASecurity(t *testing.T) {
	channel := event("opcua", "OpenSecureChannel", model.ClassOther, 1)
	channel.Attrs = map[string]string{
		"insecure_channel": "true", "security_mode": "None",
		"security_policy": "http://opcfoundation.org/UA/SecurityPolicy#None",
	}
	f := byRule(run(t, rules.Config{}, channel))["OT-009"]
	require.NotEmpty(t, f.ID)
	assert.Equal(t, model.SeverityHigh, f.Severity)
	assert.Equal(t, "T0830", f.Technique)

	endpoints := event("opcua", "GetEndpoints", model.ClassDiscovery, 2)
	endpoints.Attrs = map[string]string{"offers_insecure_endpoint": "true"}
	f = byRule(run(t, rules.Config{}, endpoints))["OT-009"]
	assert.Equal(t, model.SeverityMedium, f.Severity, "offering is not the same as using")
}

// portRegistry is a registry with one protocol on its own port. The rules
// package deliberately does not import the dissectors, so the ports a rule
// compares against come from whatever registry the caller passes — the CLI
// passes the real one.
func portRegistry(t *testing.T) *dissect.Registry {
	t.Helper()
	r := dissect.NewRegistry()
	r.Register(&portOnly{name: "modbus"}, dissect.TCPPorts(502))
	r.Register(&portOnly{name: "goose"}, dissect.EtherTypes(0x88b8))
	return r
}

type portOnly struct{ name string }

func (p *portOnly) Name() string { return p.name }
func (*portOnly) Tier() int      { return 1 }
func (*portOnly) Probe(*dissect.FlowContext, []byte) int {
	return 0
}
func (*portOnly) Parse(*dissect.FlowContext, []byte) ([]model.Event, error) {
	return nil, nil
}

func TestProtocolOnANonStandardPort(t *testing.T) {
	registry := portRegistry(t)
	odd := event("modbus", "ReadCoils", model.ClassRead, 1)
	odd.ServerPort = 1502
	odd.Flow.DstPort = 1502
	f := byRule(run(t, rules.Config{Registry: registry}, odd))["OT-010"]
	require.NotEmpty(t, f.ID)
	assert.Equal(t, model.SeverityLow, f.Severity)
	assert.Contains(t, f.Summary, "1502")

	// The registered port is not a finding.
	assert.NotContains(t, byRule(run(t, rules.Config{Registry: registry},
		event("modbus", "ReadCoils", model.ClassRead, 2))), "OT-010")

	// A protocol with no port at all cannot be on the wrong one.
	goose := model.Event{
		CaptureID: "bb22", PacketIndex: 3, Timestamp: at,
		Flow:     model.Flow{SrcMAC: "0a:bb:fe:10:c9:02", DstMAC: "01:0c:cd:01:00:00", Transport: model.TransportEthernet},
		Protocol: "goose", Operation: "StateChange", Class: model.ClassRead,
	}
	assert.NotContains(t, byRule(run(t, rules.Config{Registry: registry}, goose)), "OT-010")
}

func TestCrossLevelFlowsNeedEvidence(t *testing.T) {
	// An event between the enterprise host and the controller, three levels
	// apart, gives the graph rule its packet.
	ev := event("modbus", "ReadCoils", model.ClassRead, 11)
	ev.Flow.SrcIP = "10.9.9.9"

	assets := plant()
	engine, err := rules.New(rules.Config{Assets: assets})
	require.NoError(t, err)
	engine.Add(ev)

	g := topology.Build(assets, []topology.Link{{
		Src: "10.9.9.9", Dst: "10.0.0.3", Protocol: "modbus", Events: 1,
		Transport: model.TransportTCP, ServerPort: 502,
		FirstSeen: at, LastSeen: at,
	}}, topology.Options{})
	engine.AddTopology(g)

	f := byRule(engine.Findings())["OT-011"]
	require.NotEmpty(t, f.ID)
	assert.Equal(t, "T0886", f.Technique)
	assert.Contains(t, f.Summary, "level 4")
	assert.Contains(t, f.Summary, "level 1")
	assert.EqualValues(t, 11, f.Evidence.PacketIndex)

	// Without an event behind the edge there is nothing to check, so there is
	// no finding either.
	bare, err := rules.New(rules.Config{Assets: assets})
	require.NoError(t, err)
	bare.AddTopology(g)
	assert.NotContains(t, byRule(bare.Findings()), "OT-011")
}

func TestExceptionStorm(t *testing.T) {
	var events []model.Event
	for i := range 12 {
		ev := event("modbus", "ReadHoldingRegisters", model.ClassRead, i+1)
		ev.Direction = model.DirResponse
		ev.Exception = "IllegalDataAddress"
		ev.Flow = ev.Flow.Reverse()
		events = append(events, ev)
	}

	f := byRule(run(t, rules.Config{}, events...))["OT-012"]
	require.NotEmpty(t, f.ID)
	assert.Equal(t, "T0861", f.Technique)
	assert.Contains(t, f.Summary, "12 exceptions")

	// Below the threshold nothing is said.
	assert.NotContains(t, byRule(run(t, rules.Config{}, events[:5]...)), "OT-012")
}

func TestMalformedFrameBurst(t *testing.T) {
	var events []model.Event
	for i := range 6 {
		ev := event("modbus", "FramingError", model.ClassOther, i+1)
		ev.Malformed = true
		ev.Error = "MBAP length 34820 exceeds the segment"
		events = append(events, ev)
	}

	f := byRule(run(t, rules.Config{}, events...))["OT-013"]
	require.NotEmpty(t, f.ID)
	assert.Equal(t, "T0814", f.Technique)
	assert.Contains(t, f.Details["first"], "MBAP length")

	assert.NotContains(t, byRule(run(t, rules.Config{}, events[:3]...)), "OT-013")
}

func TestDisabledRulesDoNotRun(t *testing.T) {
	stop := event("s7comm", "PLC_STOP", model.ClassControl, 1)

	findings := run(t, rules.Config{Disabled: []string{"OT-002"}}, stop)
	assert.NotContains(t, byRule(findings), "OT-002")

	engine, err := rules.New(rules.Config{Assets: plant(), Disabled: []string{"OT-002"}})
	require.NoError(t, err)
	for _, d := range engine.Rules() {
		assert.NotEqual(t, "OT-002", d.ID)
	}
}

func TestRulesDescribeThemselves(t *testing.T) {
	engine, err := rules.New(rules.Config{Assets: plant()})
	require.NoError(t, err)

	seen := map[string]bool{}
	for _, d := range engine.Rules() {
		assert.NotEmpty(t, d.ID)
		assert.NotEmpty(t, d.Title)
		assert.NotEmpty(t, d.Description, d.ID)
		assert.True(t, d.Severity.Valid(), d.ID)
		assert.NotEmpty(t, d.Technique, d.ID)
		assert.NotEmpty(t, d.TechniqueName(), "%s cites %s, which this build cannot name", d.ID, d.Technique)
		assert.False(t, seen[d.ID], "duplicate rule id %s", d.ID)
		seen[d.ID] = true
	}
	assert.GreaterOrEqual(t, len(seen), 13)
}

func TestTechniqueLinks(t *testing.T) {
	assert.Equal(t, "https://attack.mitre.org/techniques/T0858", rules.TechniqueURL("T0858"))
	assert.Equal(t, "https://attack.mitre.org/techniques/T1692/001", rules.TechniqueURL("T1692.001"),
		"a sub-technique is written with a dot and linked with a slash")
	assert.Empty(t, rules.TechniqueURL("T9999"), "a technique this build cannot name gets no link")
}

func TestEngineRefusesANonsenseAllowList(t *testing.T) {
	_, err := rules.New(rules.Config{EngineeringStations: []string{"not an address"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an address")
}
