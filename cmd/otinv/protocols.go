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
)

func newProtocolsCommand() *cobra.Command {
	var (
		asJSON     bool
		tier       int
		configPath string
	)

	cmd := &cobra.Command{
		Use:   "protocols",
		Short: "List the protocol dissectors built into this binary",
		Long: "protocols lists every dissector, the depth tier it parses at and the ports\n" +
			"or EtherTypes it is offered traffic on by default.\n\n" +
			"Ports are defaults only: every TCP and UDP dissector is also offered traffic\n" +
			"on other ports through its heuristic probe, and otinv.yaml can add ports per\n" +
			"protocol. Listing them never touches a network.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if tier < 0 || tier > 3 {
				return fmt.Errorf("protocols: --tier must be 1, 2 or 3 (or 0 for all), not %d", tier)
			}
			cfg, err := LoadConfig(configPath)
			if err != nil {
				return err
			}

			rows := dissect.Default().Registered()
			rows = withConfiguredPorts(rows, cfg.ExtraTCPPorts())
			if tier > 0 {
				rows = keepTier(rows, tier)
			}
			// Registration order is an implementation detail; a listing reads
			// better by depth and then by name.
			sort.Slice(rows, func(i, j int) bool {
				if rows[i].Tier != rows[j].Tier {
					return rows[i].Tier < rows[j].Tier
				}
				return rows[i].Name < rows[j].Name
			})

			if asJSON {
				return writeProtocolsJSON(cmd.OutOrStdout(), rows)
			}
			return writeProtocolsText(cmd.OutOrStdout(), rows, tier)
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the list as JSON")
	cmd.Flags().IntVar(&tier, "tier", 0, "list one depth tier only (1, 2 or 3)")
	cmd.Flags().StringVarP(&configPath, "config", "c", "",
		"configuration file whose extra ports to include (default "+DefaultConfigPath+" when present)")
	return cmd
}

// withConfiguredPorts folds otinv.yaml's extra ports into the listing, so that
// what the command shows is what this run would actually match on.
func withConfiguredPorts(rows []dissect.Registered, extra map[string][]uint16) []dissect.Registered {
	if len(extra) == 0 {
		return rows
	}
	for i := range rows {
		for _, port := range extra[rows[i].Name] {
			if !containsUint16(rows[i].TCPPorts, port) {
				rows[i].TCPPorts = append(rows[i].TCPPorts, port)
			}
		}
	}
	return rows
}

func keepTier(rows []dissect.Registered, tier int) []dissect.Registered {
	out := make([]dissect.Registered, 0, len(rows))
	for _, r := range rows {
		if r.Tier == tier {
			out = append(out, r)
		}
	}
	return out
}

// protocolList is the JSON shape of the listing.
type protocolList struct {
	Total     int                  `json:"total"`
	ByTier    map[int]int          `json:"by_tier"`
	Protocols []dissect.Registered `json:"protocols"`
}

func writeProtocolsJSON(out io.Writer, rows []dissect.Registered) error {
	list := protocolList{Total: len(rows), ByTier: tierCounts(rows), Protocols: rows}
	if list.Protocols == nil {
		list.Protocols = []dissect.Registered{}
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(list)
}

func writeProtocolsText(out io.Writer, rows []dissect.Registered, tier int) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintf(out, "no dissector at tier %d\n", tier)
		return err
	}

	tw := tabwriter.NewWriter(out, 2, 8, 2, ' ', 0)
	p := &printer{w: tw}
	p.printf("PROTOCOL\tTIER\tTCP\tUDP\tETHERTYPE\tFRAMING\n")
	for _, r := range rows {
		p.printf("%s\t%d\t%s\t%s\t%s\t%s\n",
			r.Name, r.Tier,
			portList(r.TCPPorts), portList(r.UDPPorts),
			etherTypeList(r.EtherTypes), framingNote(r))
	}
	if p.err != nil {
		return p.err
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	p = &printer{w: out}
	p.printf("\n%d dissectors: %s\n", len(rows), tierSummary(rows))
	p.printf("Ports are defaults. Traffic on any other port is still offered to every\n" +
		"dissector's heuristic probe, and otinv.yaml adds ports per protocol under\n" +
		"protocols.<name>.extra_ports.\n")
	return p.err
}

// framingNote says how a dissector finds its PDU boundaries. One that reads a
// length can be handed a TCP stream; one that cannot only ever sees a whole
// frame. "defers" marks a dissector that waits for more bytes before claiming
// a stream on a port it shares with another protocol.
func framingNote(r dissect.Registered) string {
	switch {
	case r.Framed && r.Defers:
		return "length, defers"
	case r.Framed:
		return "length"
	default:
		return "whole frame"
	}
}

func tierCounts(rows []dissect.Registered) map[int]int {
	counts := map[int]int{}
	for _, r := range rows {
		counts[r.Tier]++
	}
	return counts
}

func tierSummary(rows []dissect.Registered) string {
	counts := tierCounts(rows)
	tiers := make([]int, 0, len(counts))
	for t := range counts {
		tiers = append(tiers, t)
	}
	sort.Ints(tiers)
	parts := make([]string, 0, len(tiers))
	for _, t := range tiers {
		parts = append(parts, fmt.Sprintf("%d at tier %d", counts[t], t))
	}
	return strings.Join(parts, ", ")
}

func portList(ports []uint16) string {
	if len(ports) == 0 {
		return "-"
	}
	sorted := append([]uint16(nil), ports...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	parts := make([]string, 0, len(sorted))
	for _, p := range sorted {
		parts = append(parts, strconv.Itoa(int(p)))
	}
	return strings.Join(parts, ",")
}

func etherTypeList(types []uint16) string {
	if len(types) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(types))
	for _, t := range types {
		parts = append(parts, fmt.Sprintf("0x%04x", t))
	}
	return strings.Join(parts, ",")
}
