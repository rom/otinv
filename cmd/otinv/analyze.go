package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/rom/otinv/internal/dissect"
	_ "github.com/rom/otinv/internal/dissect/modbus" // register the Modbus dissector
	"github.com/rom/otinv/internal/ingest"
	"github.com/rom/otinv/internal/model"
)

func newAnalyzeCommand() *cobra.Command {
	var (
		configPath string
		asJSON     bool
		withEvents bool
	)

	cmd := &cobra.Command{
		Use:   "analyze <capture.pcap> [capture.pcap ...]",
		Short: "Decode captures and report what was found",
		Long: "analyze reads one or more pcap/pcapng files, dissects the industrial\n" +
			"protocols it recognises and reports the devices, operations and anomalies\n" +
			"it observed.\n\n" +
			"Results are not yet persisted: the SQLite store and the web GUI are\n" +
			"separate milestones, so for now analyze prints its findings.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := LoadConfig(configPath)
			if err != nil {
				return err
			}
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
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "",
		"configuration file (default "+DefaultConfigPath+" when present)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the report as JSON")
	cmd.Flags().BoolVar(&withEvents, "events", false, "include every decoded event in the JSON report")
	return cmd
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

// record folds one event into the per-endpoint view. The server side of a
// request is its destination, and of a response its source.
func record(servers map[string]*serverReport, e model.Event) {
	server, client := e.Flow.DstIP, e.Flow.SrcIP
	port := e.Flow.DstPort
	if e.Direction == model.DirResponse {
		server, client = e.Flow.SrcIP, e.Flow.DstIP
		port = e.Flow.SrcPort
	}
	addr := server + ":" + strconv.Itoa(int(port))

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
	if !containsString(s.Clients, client) {
		s.Clients = append(s.Clients, client)
	}
	for k, v := range e.Identity {
		if s.Identity == nil {
			s.Identity = map[string]string{}
		}
		s.Identity[k] = v
	}
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
