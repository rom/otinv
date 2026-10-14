package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/export"
)

// modbusPCAP is a capture with both reads and writes in it, which makes it
// enough to exercise every table an export can hold.
const modbusPCAP = "../../testdata/pcaps/modbus_test_data_part1.pcap"

// run executes the CLI the way a shell would and returns everything it wrote.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := run(t, args...)
	require.NoError(t, err, out)
	return out
}

func TestVersionCommand(t *testing.T) {
	out := mustRun(t, "version")
	assert.Contains(t, out, "otinv "+version)
	assert.Contains(t, out, "commit")

	short := mustRun(t, "version", "--short")
	assert.Equal(t, version+"\n", short, "--short is for scripts, so it is the version alone")
}

func TestProtocolsCommandListsEveryDissector(t *testing.T) {
	out := mustRun(t, "protocols")

	for _, name := range dissect.Default().Names() {
		assert.Contains(t, out, name)
	}
	assert.Contains(t, out, "502", "the Modbus default port")
	assert.Contains(t, out, "0x88b8", "the GOOSE EtherType")
	assert.Contains(t, out, "at tier 1")
	assert.Contains(t, out, "Ports are defaults",
		"the listing has to say that a port is not the only way a protocol is found")
}

func TestProtocolsCommandJSON(t *testing.T) {
	out := mustRun(t, "protocols", "--json")

	var list protocolList
	require.NoError(t, json.Unmarshal([]byte(out), &list))
	assert.Equal(t, len(dissect.Default().Names()), list.Total)
	assert.Equal(t, list.Total, list.ByTier[1]+list.ByTier[2]+list.ByTier[3])

	byName := map[string]dissect.Registered{}
	for _, p := range list.Protocols {
		byName[p.Name] = p
	}
	modbus, ok := byName["modbus"]
	require.True(t, ok)
	assert.Equal(t, 1, modbus.Tier)
	assert.Equal(t, []uint16{502}, modbus.TCPPorts)
	assert.True(t, modbus.Framed, "a TCP dissector has to frame its stream")

	goose, ok := byName["goose"]
	require.True(t, ok)
	assert.Equal(t, []uint16{0x88b8}, goose.EtherTypes)
	assert.Empty(t, goose.TCPPorts, "GOOSE has no IP layer, so it has no port")
}

func TestProtocolsCommandTierFilter(t *testing.T) {
	tier1 := mustRun(t, "protocols", "--tier", "1", "--json")
	var list protocolList
	require.NoError(t, json.Unmarshal([]byte(tier1), &list))
	assert.Positive(t, list.Total)
	for _, p := range list.Protocols {
		assert.Equal(t, 1, p.Tier)
	}

	// Tier 2 and 3 are later milestones; an empty tier says so rather than
	// printing a bare header.
	out := mustRun(t, "protocols", "--tier", "3")
	assert.Contains(t, out, "no dissector at tier 3")

	_, err := run(t, "protocols", "--tier", "4")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--tier must be 1, 2 or 3")
}

func TestAnalyzeWritesItsReportToAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	out := mustRun(t, "analyze", modbusPCAP, "--json", "--out", path)
	assert.Empty(t, out, "the report went to the file")

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var rep report
	require.NoError(t, json.Unmarshal(data, &rep))
	assert.NotEmpty(t, rep.Servers)
	assert.Positive(t, rep.Result.Events)
}

func TestAnalyzeMaxEventsCapsTheJSONReport(t *testing.T) {
	out := mustRun(t, "analyze", modbusPCAP, "--json", "--max-events", "5")
	var rep report
	require.NoError(t, json.Unmarshal([]byte(out), &rep))
	assert.Len(t, rep.Events, 5, "--max-events implies --events and caps it")
	assert.Greater(t, rep.Result.Events, uint64(5), "the capture holds more than the report shows")

	_, err := run(t, "analyze", modbusPCAP, "--max-events", "-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be negative")
}

func TestAnalyzeOnlyRestrictsTheDissectors(t *testing.T) {
	// Restricted to a protocol the capture does not carry, nothing is
	// decoded, which is how the flag is observable without a second capture.
	out := mustRun(t, "analyze", modbusPCAP, "--json", "--only", "dnp3")
	var rep report
	require.NoError(t, json.Unmarshal([]byte(out), &rep))
	assert.Empty(t, rep.Servers)
	assert.Zero(t, rep.Result.Events)

	with := mustRun(t, "analyze", modbusPCAP, "--json", "--only", "modbus,dnp3")
	require.NoError(t, json.Unmarshal([]byte(with), &rep))
	assert.NotEmpty(t, rep.Servers)

	_, err := run(t, "analyze", modbusPCAP, "--only", "mqtt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `no such dissector "mqtt"`)
}

func TestAnalyzeRejectsAnImpossibleConfidence(t *testing.T) {
	for _, value := range []string{"0", "101"} {
		_, err := run(t, "analyze", modbusPCAP, "--min-confidence", value)
		require.Error(t, err, value)
		assert.Contains(t, err.Error(), "between 1 and 100")
	}
}

func TestAnalyzeQuietPrintsOnlyTheProjectSummary(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "demo.db")

	out := mustRun(t, "analyze", modbusPCAP, "--project", "demo", "--db", db, "--quiet")
	assert.NotContains(t, out, "parse health")
	assert.NotContains(t, out, "endpoints")
	assert.Contains(t, out, `project "demo"`)
	assert.Contains(t, out, "browse with: otinv serve --project demo")
}

func TestAnalyzeSkipInventorySaysSo(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "demo.db")

	out := mustRun(t, "analyze", modbusPCAP, "--project", "demo", "--db", db,
		"--quiet", "--skip-inventory")
	assert.Contains(t, out, "inventory not rebuilt")

	// Nothing was inferred, so the project holds events and no assets; the
	// next analyze without the flag fills the inventory in.
	out = mustRun(t, "export", "--project", "demo", "--db", db, "--what", "summary", "--compact")
	var doc export.Document
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	require.NotNil(t, doc.Summary)
	assert.Zero(t, doc.Summary.Assets)
	assert.Positive(t, doc.Summary.Events)
}

// project ingests the sample capture and returns the database path.
func project(t *testing.T) string {
	t.Helper()
	db := filepath.Join(t.TempDir(), "demo.db")
	mustRun(t, "analyze", modbusPCAP, "--project", "demo", "--db", db, "--quiet")
	return db
}

func TestExportJSONHoldsTheRequestedTables(t *testing.T) {
	db := project(t)

	out := mustRun(t, "export", "--project", "demo", "--db", db, "--what", "all")
	var doc export.Document
	require.NoError(t, json.Unmarshal([]byte(out), &doc))

	assert.Equal(t, "otinv", doc.Tool)
	assert.Equal(t, "demo", doc.Project)
	assert.Equal(t, db, doc.Database)
	require.NotNil(t, doc.Summary)
	assert.Positive(t, doc.Summary.Events)
	assert.NotEmpty(t, doc.Assets)
	assert.NotEmpty(t, doc.Flows)
	assert.NotEmpty(t, doc.Protocols)
	require.Len(t, doc.Captures, 1)
	assert.Contains(t, doc.Captures[0].Path, "modbus")
	assert.Empty(t, doc.Events, "all leaves the events out; they are asked for by name")
	require.NotNil(t, doc.Filter)
	assert.Equal(t, export.Overview, doc.Filter.Tables)
}

func TestExportStreamsEventsAsOneJSONObject(t *testing.T) {
	db := project(t)

	out := mustRun(t, "export", "--project", "demo", "--db", db,
		"--what", "summary,events", "--limit", "20")
	var doc export.Document
	require.NoError(t, json.Unmarshal([]byte(out), &doc))

	require.NotNil(t, doc.Summary)
	require.Len(t, doc.Events, 20)
	assert.Equal(t, "modbus", doc.Events[0].Protocol)
	assert.NotEmpty(t, doc.Events[0].Operation)
}

func TestExportFiltersByProtocolAndClass(t *testing.T) {
	db := project(t)

	out := mustRun(t, "export", "--project", "demo", "--db", db,
		"--what", "events", "--class", "write", "--compact")
	var doc export.Document
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	require.NotEmpty(t, doc.Events)
	for _, e := range doc.Events {
		assert.EqualValues(t, "write", e.Class)
	}

	out = mustRun(t, "export", "--project", "demo", "--db", db,
		"--what", "events", "--protocol", "dnp3")
	require.NoError(t, json.Unmarshal([]byte(out), &doc))
	assert.Empty(t, doc.Events, "the capture carries no DNP3")
}

func TestExportCSVHoldsOneTable(t *testing.T) {
	db := project(t)

	out := mustRun(t, "export", "--project", "demo", "--db", db,
		"--what", "assets", "--format", "csv")
	records, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	require.NoError(t, err)
	require.Greater(t, len(records), 1)
	assert.Equal(t, export.AssetColumns, records[0])

	_, err = run(t, "export", "--project", "demo", "--db", db,
		"--what", "assets,flows", "--format", "csv")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "a CSV file holds one table")
}

func TestExportCSVStreamsEvents(t *testing.T) {
	db := project(t)
	path := filepath.Join(t.TempDir(), "events.csv")

	out := mustRun(t, "export", "--project", "demo", "--db", db,
		"--what", "events", "--format", "csv", "--out", path, "--limit", "12")
	assert.Contains(t, out, "wrote "+path)
	assert.Contains(t, out, "12 events")

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	records, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	require.NoError(t, err)
	require.Len(t, records, 13, "a header and twelve events")
	assert.Equal(t, export.EventColumns, records[0])
}

func TestExportRefusesWhatItCannotFind(t *testing.T) {
	db := project(t)

	_, err := run(t, "export", "--db", db, "--what", "assets")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project is required")

	_, err = run(t, "export", "--project", "demo", "--db", filepath.Join(t.TempDir(), "missing.db"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no project database at")

	_, err = run(t, "export", "--project", "other", "--db", db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `holds no project "other"`)
	assert.Contains(t, err.Error(), `"demo"`, "the error names what the file does hold")

	_, err = run(t, "export", "--project", "demo", "--db", db, "--what", "findings")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no table named")

	_, err = run(t, "export", "--project", "demo", "--db", db, "--format", "xlsx")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pick json or csv")

	_, err = run(t, "export", "--project", "demo", "--db", db, "--limit", "-3")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be negative")
}

func TestServeRefusesWhatItCannotServe(t *testing.T) {
	db := project(t)

	_, err := run(t, "serve", "--db", db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project is required")

	_, err = run(t, "serve", "--project", "demo", "--db", db, "--lang", "de")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--lang \"de\" is not one of en, sv")

	_, err = run(t, "serve", "--project", "demo", "--db", db, "--shutdown-timeout", "0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--shutdown-timeout must be positive")

	// Binding beyond loopback stays refused: there is no authentication yet.
	_, err = run(t, "serve", "--project", "demo", "--db", db, "--listen", "0.0.0.0:8080")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication")
}

func TestExtraTCPPorts(t *testing.T) {
	registry := dissect.Default()

	tests := []struct {
		name  string
		cfg   *Config
		specs []string
		want  map[string][]uint16
		err   string
	}{
		{name: "nothing", cfg: &Config{}},
		{
			name:  "one port",
			cfg:   &Config{},
			specs: []string{"modbus=1502"},
			want:  map[string][]uint16{"modbus": {1502}},
		},
		{
			name:  "a list and a repeat",
			cfg:   &Config{},
			specs: []string{"modbus=1502,1503", "s7comm=10102"},
			want:  map[string][]uint16{"modbus": {1502, 1503}, "s7comm": {10102}},
		},
		{
			name: "the config file contributes too",
			cfg: &Config{Protocols: map[string]ProtocolConfig{
				"modbus": {ExtraPorts: []uint16{1502}},
			}},
			specs: []string{"modbus=1502,1600"},
			want:  map[string][]uint16{"modbus": {1502, 1600}},
		},
		{
			name: "a protocol no dissector answers to is dropped from the config",
			cfg: &Config{Protocols: map[string]ProtocolConfig{
				"mqtt": {ExtraPorts: []uint16{1883}},
			}},
		},
		{name: "not a pair", cfg: &Config{}, specs: []string{"modbus"}, err: "is not name=port"},
		{name: "no name", cfg: &Config{}, specs: []string{"=502"}, err: "is not name=port"},
		{name: "unknown protocol", cfg: &Config{}, specs: []string{"mqtt=1883"}, err: "no dissector named"},
		{name: "not a port", cfg: &Config{}, specs: []string{"modbus=http"}, err: "is not a port"},
		{name: "port zero", cfg: &Config{}, specs: []string{"modbus=0"}, err: "is not a port"},
		{name: "port too high", cfg: &Config{}, specs: []string{"modbus=70000"}, err: "is not a port"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extraTCPPorts(tc.cfg, tc.specs, registry)
			if tc.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSplitList(t *testing.T) {
	assert.Equal(t, []string{"modbus", "dnp3", "s7comm"},
		splitList([]string{"modbus, dnp3", "s7comm"}))
	assert.Nil(t, splitList([]string{" ", ","}))
}

func TestLoggerFormatsAndLevels(t *testing.T) {
	for _, format := range []string{"", "auto", "text", "json"} {
		logger, err := newLogger(os.Stderr, "info", format)
		require.NoError(t, err, format)
		assert.NotNil(t, logger)
	}
	_, err := newLogger(os.Stderr, "info", "logfmt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not auto, text or json")

	for name, want := range map[string]slog.Level{
		"debug": slog.LevelDebug,
		"":      slog.LevelInfo,
		"INFO":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	} {
		level, err := parseLevel(name)
		require.NoError(t, err, name)
		assert.Equal(t, want, level, name)
	}
	_, err = parseLevel("trace")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not debug, info, warn or error")
}

func TestVerboseIsOverriddenByAnExplicitLevel(t *testing.T) {
	ctx := context.Background()

	// -v means debug, but a level the user spelled out wins over it.
	mustRun(t, "-v", "version")
	assert.True(t, slog.Default().Enabled(ctx, slog.LevelDebug))

	mustRun(t, "-v", "--log-level", "error", "version")
	assert.False(t, slog.Default().Enabled(ctx, slog.LevelDebug))
	assert.True(t, slog.Default().Enabled(ctx, slog.LevelError))
}

func TestProjectDBPathSanitisesTheName(t *testing.T) {
	assert.Equal(t, "demo.otinv.db", projectDBPath("demo", ""))
	assert.Equal(t, "my-plant_2.otinv.db", projectDBPath("my-plant_2", ""))
	assert.Equal(t, "---etc-passwd.otinv.db", projectDBPath("../etc/passwd", ""),
		"a project name cannot walk out of the working directory")
	assert.Equal(t, "/tmp/given.db", projectDBPath("demo", "/tmp/given.db"))
}
