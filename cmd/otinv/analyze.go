package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/rom/otinv/internal/dissect"
	_ "github.com/rom/otinv/internal/dissect/bacnet"   // register the BACnet/IP dissector
	_ "github.com/rom/otinv/internal/dissect/dnp3"     // register the DNP3 dissector
	_ "github.com/rom/otinv/internal/dissect/enip"     // register the EtherNet/IP and CIP dissector
	_ "github.com/rom/otinv/internal/dissect/goose"    // register the IEC 61850 GOOSE dissector
	_ "github.com/rom/otinv/internal/dissect/iec104"   // register the IEC 60870-5-104 dissector
	_ "github.com/rom/otinv/internal/dissect/mms"      // register the IEC 61850 MMS dissector
	_ "github.com/rom/otinv/internal/dissect/modbus"   // register the Modbus dissector
	_ "github.com/rom/otinv/internal/dissect/opcua"    // register the OPC UA dissector
	_ "github.com/rom/otinv/internal/dissect/profinet" // register the PROFINET DCP dissector
	_ "github.com/rom/otinv/internal/dissect/s7comm"   // register the S7comm dissector
	"github.com/rom/otinv/internal/ingest"
	"github.com/rom/otinv/internal/inventory"
	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/rules"
	"github.com/rom/otinv/internal/store"
	"github.com/rom/otinv/internal/topology"
)

func newAnalyzeCommand() *cobra.Command {
	var (
		configPath    string
		asJSON        bool
		withEvents    bool
		maxEvents     int
		project       string
		dbPath        string
		reingest      bool
		minConfidence int
		extraPorts    []string
		only          []string
		outPath       string
		quiet         bool
		skipInventory bool
		skipRules     bool
	)

	cmd := &cobra.Command{
		Use:   "analyze <capture.pcap> [capture.pcap ...]",
		Short: "Decode captures and report what was found",
		Long: "analyze reads one or more pcap/pcapng files, dissects the industrial\n" +
			"protocols it recognises and reports the devices, operations and anomalies\n" +
			"it observed.\n\n" +
			"With --project the events and the asset inventory are stored, and\n" +
			"`otinv serve --project <name>` then browses them. Without it, analyze\n" +
			"prints its findings and keeps nothing.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig(configPath)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("min-confidence") {
				if minConfidence < 1 || minConfidence > 100 {
					return fmt.Errorf("analyze: --min-confidence must be between 1 and 100, not %d",
						minConfidence)
				}
				cfg.Probe.MinConfidence = minConfidence
			}
			if maxEvents < 0 {
				return fmt.Errorf("analyze: --max-events cannot be negative (%d); 0 means every event",
					maxEvents)
			}

			opts := analyzeOptions{
				cfg:        cfg,
				registry:   dissect.Default(),
				asJSON:     asJSON,
				withEvents: withEvents || maxEvents > 0,
				maxEvents:  maxEvents,
				quiet:      quiet,
			}
			if len(only) > 0 {
				if opts.registry, err = opts.registry.Subset(splitList(only)...); err != nil {
					return fmt.Errorf("analyze: --only: %w", err)
				}
			}
			if opts.extraPorts, err = extraTCPPorts(cfg, extraPorts, opts.registry); err != nil {
				return err
			}

			out, closeOut, err := openOutput(outPath, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			defer func() { _ = closeOut() }()

			if project == "" {
				for i, path := range args {
					if i > 0 && !quiet {
						if _, err := fmt.Fprintln(out); err != nil {
							return err
						}
					}
					if err := analyze(out, path, opts); err != nil {
						return err
					}
				}
				return closeOut()
			}
			if err := analyzeIntoProject(cmd.Context(), out, args, opts,
				project, dbPath, reingest, skipInventory, skipRules); err != nil {
				return err
			}
			return closeOut()
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "",
		"configuration file (default "+DefaultConfigPath+" when present)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the report as JSON")
	cmd.Flags().BoolVar(&withEvents, "events", false, "include every decoded event in the JSON report")
	cmd.Flags().IntVar(&maxEvents, "max-events", 0,
		"include at most this many events in the JSON report (implies --events; 0 means every event)")
	cmd.Flags().StringVarP(&project, "project", "p", "",
		"store the results in this project instead of only printing them")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"project database file (default <project>.otinv.db)")
	cmd.Flags().BoolVar(&reingest, "reingest", false,
		"replace a capture that was already ingested into this project")
	cmd.Flags().IntVar(&minConfidence, "min-confidence", dissect.DefaultMinConfidence,
		"confidence a heuristic must reach to claim a stream on an unknown port (1-100)")
	cmd.Flags().StringArrayVar(&extraPorts, "extra-port", nil,
		"extra port for a protocol, as name=port; repeatable, and name=port,port is allowed")
	cmd.Flags().StringArrayVar(&only, "only", nil,
		"dissect with these protocols alone; repeatable, and a comma separated list is allowed")
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "write the report to this file instead of stdout")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false,
		"leave out the per-capture report; with --project, print its summary alone")
	cmd.Flags().BoolVar(&skipInventory, "skip-inventory", false,
		"store the events without rebuilding the asset inventory")
	cmd.Flags().BoolVar(&skipRules, "skip-rules", false,
		"store the events without running the detection rules over them")
	return cmd
}

// analyzeOptions is what the flags and the configuration file agree on for
// one run.
type analyzeOptions struct {
	cfg        *Config
	registry   *dissect.Registry
	extraPorts map[string][]uint16
	asJSON     bool
	withEvents bool
	maxEvents  int
	quiet      bool
}

// ingestOptions renders the parts of a run that ingest needs.
func (o analyzeOptions) ingestOptions(captureID string, sink func(model.Event)) ingest.Options {
	return ingest.Options{
		CaptureID:     captureID,
		Registry:      o.registry,
		MinConfidence: o.cfg.Probe.MinConfidence,
		ExtraTCPPorts: o.extraPorts,
		Sink:          sink,
	}
}

// keepEvent reports whether one more event belongs in the JSON report.
func (o analyzeOptions) keepEvent(have int) bool {
	return o.withEvents && (o.maxEvents == 0 || have < o.maxEvents)
}

// extraTCPPorts merges the configuration file's extra ports with the ones
// --extra-port added. A name no dissector answers to is an error rather than
// a silently ignored flag, and so is a name left out by --only.
func extraTCPPorts(cfg *Config, specs []string, registry *dissect.Registry) (map[string][]uint16, error) {
	merged := map[string][]uint16{}
	for name, ports := range cfg.ExtraTCPPorts() {
		if _, ok := registry.Lookup(name); !ok {
			continue // another protocol's section, or one --only left out
		}
		merged[name] = append(merged[name], ports...)
	}

	for _, spec := range specs {
		name, portList, ok := strings.Cut(spec, "=")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("analyze: --extra-port %q is not name=port", spec)
		}
		if _, known := registry.Lookup(name); !known {
			return nil, fmt.Errorf("analyze: --extra-port %q: no dissector named %q "+
				"(otinv protocols lists them)", spec, name)
		}
		for _, raw := range strings.Split(portList, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			port, err := strconv.ParseUint(raw, 10, 16)
			if err != nil || port == 0 {
				return nil, fmt.Errorf("analyze: --extra-port %q: %q is not a port between 1 and 65535",
					spec, raw)
			}
			if !containsUint16(merged[name], uint16(port)) {
				merged[name] = append(merged[name], uint16(port))
			}
		}
	}

	if len(merged) == 0 {
		return nil, nil
	}
	return merged, nil
}

// splitList flattens repeated flags that also accept a comma separated list,
// so --only modbus,dnp3 and --only modbus --only dnp3 mean the same thing.
func splitList(values []string) []string {
	var out []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// analyzeIntoProject ingests captures into a project database and rebuilds its
// inventory from everything the project holds.
func analyzeIntoProject(ctx context.Context, out io.Writer, paths []string, opts analyzeOptions,
	project, dbPath string, reingest, skipInventory, skipRules bool,
) error {
	db, err := store.Open(ctx, projectDBPath(project, dbPath))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	p, err := db.EnsureProject(ctx, project)
	if err != nil {
		return err
	}

	for i, path := range paths {
		if i > 0 && !opts.quiet {
			if _, err := fmt.Fprintln(out); err != nil {
				return err
			}
		}
		if err := ingestCapture(ctx, out, db, p, path, opts, reingest); err != nil {
			return err
		}
	}

	var inventoryAssets []model.Asset
	assets := 0
	if skipInventory {
		// The events are stored; the inventory is whatever the last rebuild
		// left behind, and saying so is better than reporting a count that
		// this run did not produce.
		slog.Info("skipping the inventory rebuild", "project", p.Name)
	} else {
		rebuilt, err := inventory.Rebuild(ctx, db, db, p.ID)
		if err != nil {
			return err
		}
		inventoryAssets = rebuilt
		assets = len(rebuilt)
	}

	// The rules run over everything the project holds, not only what this
	// command just ingested: a finding about a flow is about the project.
	var findings []model.Finding
	if !skipRules {
		if inventoryAssets == nil {
			stored, _, err := db.Assets(ctx, store.AssetQuery{ProjectID: p.ID, Limit: maxRuleAssets})
			if err != nil {
				return err
			}
			inventoryAssets = stored
		}
		if findings, err = runRules(ctx, db, p.ID, inventoryAssets, opts.cfg); err != nil {
			return err
		}
	}
	events, err := db.CountEvents(ctx, p.ID)
	if err != nil {
		return err
	}

	p2 := &printer{w: out}
	if skipInventory {
		p2.printf("\nproject %q: %d stored events in %s (inventory not rebuilt)\n",
			p.Name, events, db.Path())
	} else {
		p2.printf("\nproject %q: %d assets from %d stored events in %s\n",
			p.Name, assets, events, db.Path())
	}
	if !skipRules {
		p2.printf("findings: %s\n", describeFindings(findings))
	}
	p2.printf("browse with: otinv serve --project %s\n", p.Name)
	return p2.err
}

// maxRuleAssets bounds how much of the inventory a rule run reads when it did
// not just rebuild it itself.
const maxRuleAssets = 5000

// runRules builds the engine from the configuration, streams the project's
// events through it, shows it the topology and stores what it found.
func runRules(ctx context.Context, db *store.Store, projectID int64,
	assets []model.Asset, cfg *Config,
) ([]model.Finding, error) {
	custom, err := rules.LoadRuleFiles(cfg.Rules.Files...)
	if err != nil {
		return nil, err
	}
	engine, err := rules.New(rules.Config{
		Assets:              assets,
		EngineeringStations: cfg.Rules.EngineeringStations,
		Registry:            dissect.Default(),
		Custom:              custom,
		Disabled:            cfg.Rules.Disabled,
	})
	if err != nil {
		return nil, err
	}

	if err := db.EachEvent(ctx, projectID, func(e model.Event) error {
		engine.Add(e)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("rules: reading events: %w", err)
	}

	// The rules that look at the network as a whole — a flow that skips a
	// Purdue level — need the graph the topology view draws.
	links, err := projectLinks(ctx, db, projectID)
	if err != nil {
		return nil, err
	}
	engine.AddTopology(topology.Build(assets, links, topology.Options{}))

	findings := engine.Findings()
	if err := db.SaveFindings(ctx, projectID, findings); err != nil {
		return nil, err
	}
	return findings, nil
}

// projectLinks reads the flow aggregate as the topology wants it.
func projectLinks(ctx context.Context, db *store.Store, projectID int64) ([]topology.Link, error) {
	var out []topology.Link
	for offset := 0; ; offset += flowPage {
		page, total, err := db.Flows(ctx, store.FlowQuery{
			ProjectID: projectID, Limit: flowPage, Offset: offset,
		})
		if err != nil {
			return nil, err
		}
		for _, f := range page {
			out = append(out, topology.Link{
				Src: f.Src, Dst: f.Dst, Protocol: f.Protocol, Transport: f.Transport,
				ServerPort: f.ServerPort, Events: f.Events, Malformed: f.Malformed,
				Classes: f.Classes, FirstSeen: f.FirstSeen, LastSeen: f.LastSeen,
			})
		}
		if len(page) == 0 || offset+len(page) >= total {
			return out, nil
		}
	}
}

// describeFindings summarises a run for the terminal: how many, and how
// serious the worst of them are.
func describeFindings(findings []model.Finding) string {
	if len(findings) == 0 {
		return "none"
	}
	counts := map[model.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	parts := make([]string, 0, len(model.Severities))
	for _, severity := range model.Severities {
		if counts[severity] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[severity], severity))
		}
	}
	return fmt.Sprintf("%d (%s)", len(findings), strings.Join(parts, ", "))
}

func ingestCapture(ctx context.Context, out io.Writer, db *store.Store, p model.Project,
	path string, opts analyzeOptions, reingest bool,
) error {
	digest, size, err := ingest.Fingerprint(path)
	if err != nil {
		return err
	}
	row := model.Capture{ID: digest[:12], Path: path, SHA256: digest, Bytes: size}

	capturePK, inserted, err := db.SaveCapture(ctx, p.ID, row)
	if err != nil {
		return err
	}
	if !inserted {
		if !reingest {
			_, err := fmt.Fprintf(out,
				"capture %s is already in project %q (sha256 %s); pass --reingest to replace it\n",
				path, p.Name, digest[:12])
			return err
		}
		// Dropping the capture takes its events with it, so a replacement
		// cannot leave the project holding two copies of the same traffic.
		if err := db.DeleteCapture(ctx, capturePK); err != nil {
			return err
		}
		if capturePK, _, err = db.SaveCapture(ctx, p.ID, row); err != nil {
			return err
		}
	}

	w := db.NewEventWriter(p.ID, capturePK)
	servers := map[string]*serverReport{}
	var (
		events   []model.Event
		writeErr error
	)

	res, err := ingest.File(path, opts.ingestOptions(digest[:12], func(e model.Event) {
		if writeErr != nil {
			return
		}
		if err := w.Add(ctx, e); err != nil {
			writeErr = err
			return
		}
		if opts.keepEvent(len(events)) {
			events = append(events, e)
		}
		record(servers, e)
	}))
	if err != nil {
		return err
	}
	if writeErr != nil {
		return writeErr
	}
	if err := w.Close(ctx); err != nil {
		return err
	}
	if err := db.UpdateCapture(ctx, capturePK, res.Capture); err != nil {
		return err
	}

	rep := report{Result: res, Servers: sortedServers(servers), Events: events}
	return writeReport(out, &rep, opts)
}

// writeReport writes one capture's report, unless --quiet asked for silence.
func writeReport(out io.Writer, rep *report, opts analyzeOptions) error {
	if opts.quiet {
		return nil
	}
	if opts.asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return fmt.Errorf("writing the report: %w", err)
		}
		return nil
	}
	return writeText(out, rep)
}

// projectDBPath keeps one database file per project unless told otherwise.
func projectDBPath(project, override string) string {
	if override != "" {
		return override
	}
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, project)
	return safe + ".otinv.db"
}

// report is the JSON shape of an analysis.
type report struct {
	Result  *ingest.Result `json:"result"`
	Servers []serverReport `json:"servers"`
	Events  []model.Event  `json:"events,omitempty"`
}

// serverReport is one observed protocol endpoint: the raw material the
// inventory milestone turns into an asset.
type serverReport struct {
	Address    string            `json:"address"`
	Protocol   string            `json:"protocol"`
	Units      []uint16          `json:"unit_ids,omitempty"`
	Clients    []string          `json:"clients"`
	Identity   map[string]string `json:"identity,omitempty"`
	Operations map[string]int    `json:"operations"`
	Classes    map[string]int    `json:"classes"`
	Exceptions map[string]int    `json:"exceptions,omitempty"`
	Anomalies  int               `json:"anomalies"`
	Malformed  int               `json:"malformed"`
	Events     int               `json:"events"`
}

func analyze(out io.Writer, path string, opts analyzeOptions) error {
	servers := map[string]*serverReport{}
	var events []model.Event

	res, err := ingest.File(path, opts.ingestOptions("", func(e model.Event) {
		if opts.keepEvent(len(events)) {
			events = append(events, e)
		}
		record(servers, e)
	}))
	if err != nil {
		return err
	}

	rep := report{Result: res, Servers: sortedServers(servers), Events: events}
	return writeReport(out, &rep, opts)
}

// record folds one event into the per-endpoint view.
func record(servers map[string]*serverReport, e model.Event) {
	server, client, port := endpointsOf(e)
	addr := server
	if port != 0 {
		addr += ":" + strconv.Itoa(int(port))
	}

	s := servers[addr]
	if s == nil {
		s = &serverReport{
			Address:    addr,
			Protocol:   e.Protocol,
			Operations: map[string]int{},
			Classes:    map[string]int{},
		}
		servers[addr] = s
	}
	s.Events++
	s.Operations[e.Operation]++
	s.Classes[string(e.Class)]++
	if e.Exception != "" {
		if s.Exceptions == nil {
			s.Exceptions = map[string]int{}
		}
		s.Exceptions[e.Exception]++
	}
	if e.Attrs["anomaly"] != "" {
		s.Anomalies++
	}
	if e.Malformed {
		s.Malformed++
	}
	if e.UnitID != nil && !containsUint16(s.Units, *e.UnitID) {
		s.Units = append(s.Units, *e.UnitID)
	}
	// A group address names a subscription, not a client: GOOSE publishes to
	// one and nothing answers from it.
	if !isGroupAddress(client) && !containsString(s.Clients, client) {
		s.Clients = append(s.Clients, client)
	}
	for k, v := range e.Identity {
		if s.Identity == nil {
			s.Identity = map[string]string{}
		}
		s.Identity[k] = v
	}
}

// endpointsOf reports which side of an event is the listening one.
//
// The port ingest identified as the server's is what decides it, because the
// direction of a single PDU can run against the session: an IEC 104 station
// sends the keep-alive its master answers, and during an S7 block download the
// CPU sends the jobs that fetch each block. Direction is only consulted when
// ingest could not tell which port was listening. This matches how the
// inventory assigns an asset its side, so the two agree on what is a device.
func endpointsOf(e model.Event) (server, client string, port uint16) {
	if e.Flow.Transport == model.TransportEthernet {
		// A protocol with no IP layer has no port either, and its publisher
		// is named by its MAC address alone.
		if e.Direction == model.DirRequest {
			return e.Flow.DstMAC, e.Flow.SrcMAC, 0
		}
		return e.Flow.SrcMAC, e.Flow.DstMAC, 0
	}

	switch p := e.ServerPort; {
	case p != 0 && e.Flow.SrcPort == p && e.Flow.DstPort != p:
		return e.Flow.SrcIP, e.Flow.DstIP, e.Flow.SrcPort
	case p != 0 && e.Flow.DstPort == p && e.Flow.SrcPort != p:
		return e.Flow.DstIP, e.Flow.SrcIP, e.Flow.DstPort
	}
	if e.Direction == model.DirResponse {
		return e.Flow.SrcIP, e.Flow.DstIP, e.Flow.SrcPort
	}
	return e.Flow.DstIP, e.Flow.SrcIP, e.Flow.DstPort
}

// isGroupAddress reports whether a MAC address is multicast or broadcast,
// which is the low bit of its first octet.
func isGroupAddress(addr string) bool {
	if len(addr) != len("01:0c:cd:01:00:00") {
		return false
	}
	first, err := strconv.ParseUint(addr[:2], 16, 8)
	return err == nil && first&0x01 != 0
}

func containsUint16(xs []uint16, x uint16) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func sortedServers(m map[string]*serverReport) []serverReport {
	out := make([]serverReport, 0, len(m))
	for _, s := range m {
		sort.Slice(s.Units, func(i, j int) bool { return s.Units[i] < s.Units[j] })
		sort.Strings(s.Clients)
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

// printer writes a report and remembers the first write error, so that a
// closed pipe stops the output instead of being ignored line by line.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) printf(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format, args...)
}

func writeText(out io.Writer, rep *report) error {
	p := &printer{w: out}
	r := rep.Result

	p.printf("capture %s\n", r.Capture.Path)
	p.printf("  sha256       %s\n", r.Capture.SHA256)
	p.printf("  link type    %s\n", r.Capture.LinkType)
	p.printf("  packets      %d (%d non-IP, %d undecodable)\n", r.Packets, r.NonIP, r.DecodeErrors)
	if r.Packets > 0 {
		p.printf("  time range   %s .. %s\n",
			r.Capture.FirstSeen.UTC().Format("2006-01-02T15:04:05Z"),
			r.Capture.LastSeen.UTC().Format("2006-01-02T15:04:05Z"))
	}
	p.printf("  tcp streams  %d (%d dissected, %d not recognised)\n",
		r.TCPStreams, r.BoundStreams, r.UnboundPayloads)
	p.printf("  events       %d (%d malformed, %d stream resynchronisations)\n",
		r.Events, r.Malformed, r.Resyncs)

	if len(r.Health) > 0 {
		p.printf("\nparse health\n")
		tw := tabwriter.NewWriter(out, 2, 8, 2, ' ', 0)
		twp := &printer{w: tw}
		twp.printf("  PROTOCOL\tPDUS\tEVENTS\tERRORS\tPANICS\n")
		names := make([]string, 0, len(r.Health))
		for name := range r.Health {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			h := r.Health[name]
			twp.printf("  %s\t%d\t%d\t%d\t%d\n", name, h.PDUs, h.Events, h.Errors, h.Panics)
		}
		if twp.err != nil {
			return twp.err
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	if len(rep.Servers) == 0 {
		p.printf("\nno industrial protocol endpoints found\n")
		return p.err
	}

	p.printf("\nendpoints\n")
	for _, s := range rep.Servers {
		p.printf("  %s  %s\n", s.Address, s.Protocol)
		if len(s.Units) > 0 {
			p.printf("    unit ids    %s\n", joinUint16(s.Units))
		}
		p.printf("    clients     %s\n", strings.Join(s.Clients, ", "))
		for _, kv := range sortedPairs(s.Identity) {
			p.printf("    identity    %s = %s\n", kv[0], kv[1])
		}
		p.printf("    operations  %s\n", joinCounts(s.Operations))
		p.printf("    classes     %s\n", joinCounts(s.Classes))
		if len(s.Exceptions) > 0 {
			p.printf("    exceptions  %s\n", joinCounts(s.Exceptions))
		}
		if s.Anomalies > 0 || s.Malformed > 0 {
			p.printf("    suspect     %d anomalous, %d malformed frames\n", s.Anomalies, s.Malformed)
		}
	}
	return p.err
}

// sortedPairs returns identity entries in a stable order.
func sortedPairs(m map[string]string) [][2]string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][2]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, [2]string{k, m[k]})
	}
	return out
}

func joinCounts(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, " ")
}

func joinUint16(xs []uint16) string {
	parts := make([]string, 0, len(xs))
	for _, x := range xs {
		parts = append(parts, strconv.Itoa(int(x)))
	}
	return strings.Join(parts, ", ")
}
