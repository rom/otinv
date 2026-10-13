package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/rom/otinv/internal/dissect"
	_ "github.com/rom/otinv/internal/dissect/dnp3"   // register the DNP3 dissector
	_ "github.com/rom/otinv/internal/dissect/enip"   // register the EtherNet/IP and CIP dissector
	_ "github.com/rom/otinv/internal/dissect/goose"  // register the IEC 61850 GOOSE dissector
	_ "github.com/rom/otinv/internal/dissect/iec104" // register the IEC 60870-5-104 dissector
	_ "github.com/rom/otinv/internal/dissect/mms"    // register the IEC 61850 MMS dissector
	_ "github.com/rom/otinv/internal/dissect/modbus" // register the Modbus dissector
	_ "github.com/rom/otinv/internal/dissect/s7comm" // register the S7comm dissector
	"github.com/rom/otinv/internal/ingest"
	"github.com/rom/otinv/internal/inventory"
	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/store"
)

func newAnalyzeCommand() *cobra.Command {
	var (
		configPath string
		asJSON     bool
		withEvents bool
		project    string
		dbPath     string
		reingest   bool
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

			if project == "" {
				for i, path := range args {
					if i > 0 {
						if _, err := fmt.Fprintln(cmd.OutOrStdout()); err != nil {
							return err
						}
					}
					if err := analyze(cmd.OutOrStdout(), path, cfg, asJSON, withEvents); err != nil {
						return err
					}
				}
				return nil
			}
			return analyzeIntoProject(cmd.Context(), cmd.OutOrStdout(), args, cfg,
				project, dbPath, reingest, asJSON, withEvents)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "",
		"configuration file (default "+DefaultConfigPath+" when present)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the report as JSON")
	cmd.Flags().BoolVar(&withEvents, "events", false, "include every decoded event in the JSON report")
	cmd.Flags().StringVarP(&project, "project", "p", "",
		"store the results in this project instead of only printing them")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"project database file (default <project>.otinv.db)")
	cmd.Flags().BoolVar(&reingest, "reingest", false,
		"replace a capture that was already ingested into this project")
	return cmd
}

// analyzeIntoProject ingests captures into a project database and rebuilds its
// inventory from everything the project holds.
func analyzeIntoProject(ctx context.Context, out io.Writer, paths []string, cfg *Config,
	project, dbPath string, reingest, asJSON, withEvents bool,
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
		if i > 0 {
			if _, err := fmt.Fprintln(out); err != nil {
				return err
			}
		}
		if err := ingestCapture(ctx, out, db, p, path, cfg, reingest, asJSON, withEvents); err != nil {
			return err
		}
	}

	assets, err := inventory.Rebuild(ctx, db, db, p.ID)
	if err != nil {
		return err
	}
	events, err := db.CountEvents(ctx, p.ID)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(out,
		"\nproject %q: %d assets from %d stored events in %s\nbrowse with: otinv serve --project %s\n",
		p.Name, len(assets), events, db.Path(), p.Name)
	return err
}

func ingestCapture(ctx context.Context, out io.Writer, db *store.Store, p model.Project,
	path string, cfg *Config, reingest, asJSON, withEvents bool,
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

	res, err := ingest.File(path, ingest.Options{
		CaptureID:     digest[:12],
		Registry:      dissect.Default(),
		MinConfidence: cfg.Probe.MinConfidence,
		ExtraTCPPorts: cfg.ExtraTCPPorts(),
		Sink: func(e model.Event) {
			if writeErr != nil {
				return
			}
			if err := w.Add(ctx, e); err != nil {
				writeErr = err
				return
			}
			if withEvents {
				events = append(events, e)
			}
			record(servers, e)
		},
	})
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
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	return writeText(out, &rep)
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

func analyze(out io.Writer, path string, cfg *Config, asJSON, withEvents bool) error {
	servers := map[string]*serverReport{}
	var events []model.Event

	res, err := ingest.File(path, ingest.Options{
		Registry:      dissect.Default(),
		MinConfidence: cfg.Probe.MinConfidence,
		ExtraTCPPorts: cfg.ExtraTCPPorts(),
		Sink: func(e model.Event) {
			if withEvents {
				events = append(events, e)
			}
			record(servers, e)
		},
	})
	if err != nil {
		return err
	}

	rep := report{Result: res, Servers: sortedServers(servers), Events: events}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	return writeText(out, &rep)
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
