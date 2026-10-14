package rules_test

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/rules"
)

func load(t *testing.T, yaml string) []*rules.CustomRule {
	t.Helper()
	loaded, err := rules.ParseRules([]byte(yaml))
	require.NoError(t, err)
	return loaded
}

func TestCustomRuleMatchesWhatItNames(t *testing.T) {
	custom := load(t, `
rules:
  - id: PLANT-001
    title: Writes to the turbine controller
    description: Only the engineering station may write to this controller.
    severity: critical
    technique: T0836
    match:
      protocol: [modbus]
      classification: [write, control]
      dst: [10.0.0.3]
      not_src: [10.0.0.9]
`)
	require.Len(t, custom, 1)

	write := event("modbus", "WriteSingleCoil", model.ClassWrite, 1)
	findings := run(t, rules.Config{Custom: custom}, write)
	f := byRule(findings)["PLANT-001"]
	require.NotEmpty(t, f.ID)
	assert.Equal(t, model.SeverityCritical, f.Severity)
	assert.Equal(t, "T0836", f.Technique)
	assert.Equal(t, "Modify Parameter", f.TechniqueName)
	assert.Contains(t, f.Summary, "Writes to the turbine controller")
	assert.Equal(t, "Only the engineering station may write to this controller.", f.Description)

	// A read is not a write.
	assert.NotContains(t, byRule(run(t, rules.Config{Custom: custom},
		event("modbus", "ReadCoils", model.ClassRead, 2))), "PLANT-001")

	// Nor is a write from the station the rule excuses.
	excused := write
	excused.Flow.SrcIP = "10.0.0.9"
	assert.NotContains(t, byRule(run(t, rules.Config{Custom: custom}, excused)), "PLANT-001")

	// Nor is one to another device.
	elsewhere := write
	elsewhere.Flow.DstIP = "10.0.0.8"
	assert.NotContains(t, byRule(run(t, rules.Config{Custom: custom}, elsewhere)), "PLANT-001")
}

func TestCustomRuleSelectors(t *testing.T) {
	custom := load(t, `
rules:
  - id: PLANT-002
    title: Function code 6 on unit 10 from the wrong subnet
    match:
      function_codes: [6]
      unit_ids: [10]
      src: [10.0.0.0/24]
`)

	match := event("modbus", "WriteSingleRegister", model.ClassWrite, 1)
	match.FunctionCode = 6
	match.UnitID = model.Ptr(uint16(10))
	assert.Contains(t, byRule(run(t, rules.Config{Custom: custom}, match)), "PLANT-002")

	otherCode := match
	otherCode.FunctionCode = 5
	assert.NotContains(t, byRule(run(t, rules.Config{Custom: custom}, otherCode)), "PLANT-002")

	otherUnit := match
	otherUnit.UnitID = model.Ptr(uint16(11))
	assert.NotContains(t, byRule(run(t, rules.Config{Custom: custom}, otherUnit)), "PLANT-002")

	otherSubnet := match
	otherSubnet.Flow.SrcIP = "192.0.2.5"
	assert.NotContains(t, byRule(run(t, rules.Config{Custom: custom}, otherSubnet)), "PLANT-002")
}

func TestCustomRuleMatchesAnomaliesAndMalformedFrames(t *testing.T) {
	custom := load(t, `
rules:
  - id: PLANT-003
    title: Crafted frames
    severity: high
    match:
      malformed: true
  - id: PLANT-004
    title: Station names that are not printable
    match:
      anomaly: name_of_station_not_printable
`)

	bad := event("modbus", "FramingError", model.ClassOther, 1)
	bad.Malformed = true
	findings := byRule(run(t, rules.Config{Custom: custom}, bad))
	assert.Contains(t, findings, "PLANT-003")
	assert.NotContains(t, findings, "PLANT-004")

	crafted := event("profinet_dcp", "Identify", model.ClassDiscovery, 2)
	crafted.Attrs = map[string]string{"anomaly": "name_of_station_not_printable"}
	findings = byRule(run(t, rules.Config{Custom: custom}, crafted))
	assert.Contains(t, findings, "PLANT-004")
	assert.NotContains(t, findings, "PLANT-003")
}

func TestCustomRuleWindow(t *testing.T) {
	// Writes are expected during the weekday maintenance window and are a
	// finding outside it, which is how an operations window is written.
	custom := load(t, `
rules:
  - id: PLANT-005
    title: Write outside the maintenance window
    match:
      classification: [write]
    window:
      days: [mon, tue, wed, thu, fri]
      from: "06:00"
      to: "18:00"
      outside: true
`)

	inside := event("modbus", "WriteSingleCoil", model.ClassWrite, 1) // Monday 09:30 UTC
	assert.NotContains(t, byRule(run(t, rules.Config{Custom: custom}, inside)), "PLANT-005")

	evening := inside
	evening.Timestamp = time.Date(2024, 6, 3, 22, 0, 0, 0, time.UTC)
	assert.Contains(t, byRule(run(t, rules.Config{Custom: custom}, evening)), "PLANT-005")

	weekend := inside
	weekend.Timestamp = time.Date(2024, 6, 2, 9, 30, 0, 0, time.UTC) // Sunday
	assert.Contains(t, byRule(run(t, rules.Config{Custom: custom}, weekend)), "PLANT-005")
}

func TestCustomRuleWindowAcrossMidnight(t *testing.T) {
	custom := load(t, `
rules:
  - id: PLANT-006
    title: Night-time control commands
    match:
      classification: [control]
    window:
      from: "22:00"
      to: "05:00"
`)

	night := event("iec104", "C_SC_NA_1", model.ClassControl, 1)
	night.Timestamp = time.Date(2024, 6, 3, 23, 30, 0, 0, time.UTC)
	assert.Contains(t, byRule(run(t, rules.Config{Custom: custom}, night)), "PLANT-006")

	earlyMorning := night
	earlyMorning.Timestamp = time.Date(2024, 6, 3, 4, 59, 0, 0, time.UTC)
	assert.Contains(t, byRule(run(t, rules.Config{Custom: custom}, earlyMorning)), "PLANT-006")

	daytime := night
	daytime.Timestamp = time.Date(2024, 6, 3, 12, 0, 0, 0, time.UTC)
	assert.NotContains(t, byRule(run(t, rules.Config{Custom: custom}, daytime)), "PLANT-006")
}

func TestCustomRuleThreshold(t *testing.T) {
	custom := load(t, `
rules:
  - id: PLANT-007
    title: A burst of writes
    match:
      classification: [write]
    threshold:
      count: 5
      within: 1m
`)

	var burst []model.Event
	for i := range 4 {
		burst = append(burst, event("modbus", "WriteSingleCoil", model.ClassWrite, i+1))
	}
	assert.NotContains(t, byRule(run(t, rules.Config{Custom: custom}, burst...)), "PLANT-007",
		"four writes is below the threshold")

	burst = append(burst, event("modbus", "WriteSingleCoil", model.ClassWrite, 5))
	f := byRule(run(t, rules.Config{Custom: custom}, burst...))["PLANT-007"]
	require.NotEmpty(t, f.ID)
	assert.Contains(t, f.Summary, "5 matches within 1m0s")
	assert.Equal(t, "5", f.Details["matches"])
	assert.EqualValues(t, 1, f.Evidence.PacketIndex, "the evidence is where the burst started")

	// Spread out beyond the window, the same writes are not a burst.
	var slow []model.Event
	for i := range 5 {
		ev := event("modbus", "WriteSingleCoil", model.ClassWrite, i+1)
		ev.Timestamp = at.Add(time.Duration(i) * 30 * time.Second)
		slow = append(slow, ev)
	}
	assert.NotContains(t, byRule(run(t, rules.Config{Custom: custom}, slow...)), "PLANT-007")
}

func TestCustomRuleValidation(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		err  string
	}{
		{
			name: "no rules at all",
			yaml: "rules: []",
			err:  "defines no rules",
		},
		{
			name: "a key nobody knows",
			yaml: "rules:\n  - id: A\n    titel: typo\n",
			err:  "field titel not found",
		},
		{
			name: "no id",
			yaml: "rules:\n  - title: Nameless\n    match:\n      protocol: [modbus]\n",
			err:  "id is required",
		},
		{
			name: "no title",
			yaml: "rules:\n  - id: A\n    match:\n      protocol: [modbus]\n",
			err:  "title is required",
		},
		{
			name: "severity nobody defined",
			yaml: "rules:\n  - id: A\n    title: T\n    severity: catastrophic\n    match:\n      protocol: [modbus]\n",
			err:  "is not one of info, low, medium, high or critical",
		},
		{
			name: "classification nobody defined",
			yaml: "rules:\n  - id: A\n    title: T\n    match:\n      classification: [destroy]\n",
			err:  "is not a classification",
		},
		{
			name: "an address that is not one",
			yaml: "rules:\n  - id: A\n    title: T\n    match:\n      src: [over there]\n",
			err:  "is not an address, a MAC or a CIDR block",
		},
		{
			name: "a match that selects everything",
			yaml: "rules:\n  - id: A\n    title: T\n    match: {}\n",
			err:  "selects every event",
		},
		{
			name: "half a window",
			yaml: "rules:\n  - id: A\n    title: T\n    match:\n      protocol: [modbus]\n    window:\n      from: \"06:00\"\n",
			err:  "from and to come as a pair",
		},
		{
			name: "a time that is not one",
			yaml: "rules:\n  - id: A\n    title: T\n    match:\n      protocol: [modbus]\n    window:\n      from: \"half six\"\n      to: \"18:00\"\n",
			err:  "is not a time of day",
		},
		{
			name: "an empty window",
			yaml: "rules:\n  - id: A\n    title: T\n    match:\n      protocol: [modbus]\n    window: {}\n",
			err:  "name days, or a from and to time",
		},
		{
			name: "a day that is not one",
			yaml: "rules:\n  - id: A\n    title: T\n    match:\n      protocol: [modbus]\n    window:\n      days: [caturday]\n",
			err:  "is not a weekday",
		},
		{
			name: "a threshold of one",
			yaml: "rules:\n  - id: A\n    title: T\n    match:\n      protocol: [modbus]\n    threshold:\n      count: 1\n      within: 1m\n",
			err:  "must be at least 2",
		},
		{
			name: "a threshold with no window",
			yaml: "rules:\n  - id: A\n    title: T\n    match:\n      protocol: [modbus]\n    threshold:\n      count: 5\n",
			err:  "threshold.within is required",
		},
		{
			name: "a duration that is not one",
			yaml: "rules:\n  - id: A\n    title: T\n    match:\n      protocol: [modbus]\n    threshold:\n      count: 5\n      within: soon\n",
			err:  "threshold.within",
		},
		{
			name: "two rules with one id",
			yaml: "rules:\n  - id: A\n    title: T\n    match:\n      protocol: [modbus]\n  - id: A\n    title: U\n    match:\n      protocol: [dnp3]\n",
			err:  "already defined",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rules.ParseRules([]byte(tc.yaml))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.err)
		})
	}
}

func TestCustomRulesAreListedAfterTheBuiltIns(t *testing.T) {
	custom := load(t, `
rules:
  - id: PLANT-100
    title: Anything modbus
    match:
      protocol: [modbus]
`)
	engine, err := rules.New(rules.Config{Assets: plant(), Custom: custom})
	require.NoError(t, err)

	listed := engine.Rules()
	require.NotEmpty(t, listed)
	last := listed[len(listed)-1]
	assert.Equal(t, "PLANT-100", last.ID)
	assert.True(t, last.Custom)
	for _, d := range listed[:len(listed)-1] {
		assert.False(t, d.Custom, d.ID)
	}
}

func TestLoadRuleFiles(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/plant.yaml"
	require.NoError(t, writeFile(path, `
rules:
  - id: FILE-001
    title: From a file
    match:
      protocol: [modbus]
`))

	loaded, err := rules.LoadRuleFiles(path)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "FILE-001", loaded[0].Describe().ID)

	_, err = rules.LoadRuleFiles(dir + "/missing.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading")

	// A file that does not parse names itself in the error.
	bad := dir + "/bad.yaml"
	require.NoError(t, writeFile(bad, "rules:\n  - id: A\n"))
	_, err = rules.LoadRuleFiles(bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad.yaml")
	assert.Contains(t, err.Error(), "title is required")
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
