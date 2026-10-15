package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/rom/otinv/internal/oui"
)

func newOUICommand() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "oui [mac...]",
		Short: "Name the maker of a network card from a MAC address",
		Long: "oui looks a MAC address up in the IEEE registry of address blocks and says\n" +
			"who holds the block the address came from — in practice, who made the network\n" +
			"interface.\n\n" +
			"The registry is embedded in this binary, so the lookup is a table read: no\n" +
			"packet is sent and no host is contacted, on an air-gapped laptop as anywhere\n" +
			"else. Addresses may be written with colons, hyphens, dots or none of them, and\n" +
			"a block on its own (00:1b:1b) is a valid question. With no arguments the\n" +
			"addresses are read from standard input, one per line, so that a column from a\n" +
			"report can be piped in.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			macs := args
			if len(macs) == 0 {
				// Nothing to look up and nothing piped in: asking a
				// terminal for a list would just hang.
				in := cmd.InOrStdin()
				if f, ok := in.(*os.File); ok && isTerminal(f) {
					return fmt.Errorf("oui: give one or more MAC addresses, or pipe them in one per line")
				}
				var err error
				if macs, err = readMACs(in); err != nil {
					return err
				}
			}
			if len(macs) == 0 {
				return fmt.Errorf("oui: no MAC address to look up")
			}

			rows := make([]ouiRow, 0, len(macs))
			for _, mac := range macs {
				row, err := lookupMAC(mac)
				if err != nil {
					return err
				}
				rows = append(rows, row)
			}

			bits24, bits36, err := oui.Size()
			if err != nil {
				return fmt.Errorf("oui: %w", err)
			}
			reg := ouiRegister{Bits24: bits24, Bits36: bits36}

			if asJSON {
				return writeOUIJSON(cmd.OutOrStdout(), rows, reg)
			}
			return writeOUIText(cmd.OutOrStdout(), rows, reg)
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the answers as JSON")
	return cmd
}

// ouiRow is one answer: what was asked, and what the registry said.
type ouiRow struct {
	MAC string `json:"mac"`
	// Vendor is the holder of the block, empty when the registry names none.
	Vendor string `json:"vendor,omitempty"`
	Block  string `json:"block,omitempty"`
	Bits   int    `json:"bits,omitempty"`
	// Manufacturer reports whether Vendor can be read as the maker of the
	// card that holds this address.
	Manufacturer bool   `json:"manufacturer"`
	Shared       bool   `json:"shared_block,omitempty"`
	Withheld     bool   `json:"holder_withheld,omitempty"`
	Local        bool   `json:"locally_administered,omitempty"`
	Group        bool   `json:"group_address,omitempty"`
	Note         string `json:"note"`
}

// ouiRegister says how much of the IEEE registry this binary carries, so that
// an answer of "nothing" can be told apart from a lost table.
type ouiRegister struct {
	Bits24 int `json:"bits_24"`
	Bits36 int `json:"bits_36"`
}

type ouiAnswer struct {
	Addresses []ouiRow    `json:"addresses"`
	Register  ouiRegister `json:"register"`
}

func lookupMAC(mac string) (ouiRow, error) {
	digits, err := oui.Normalize(mac)
	if err != nil {
		return ouiRow{}, fmt.Errorf("oui: %w", err)
	}
	v, ok := oui.Lookup(mac)
	return ouiRow{
		MAC:          oui.Format(digits),
		Vendor:       v.Name,
		Block:        v.Prefix,
		Bits:         v.Bits,
		Manufacturer: ok,
		Shared:       v.Shared,
		Withheld:     v.Withheld,
		Local:        v.Local,
		Group:        v.Group,
		Note:         v.Explain(),
	}, nil
}

// readMACs takes one address per line, ignoring blank lines and comments so
// that a saved list stays readable.
func readMACs(in io.Reader) ([]string, error) {
	var out []string
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("oui: reading addresses: %w", err)
	}
	return out, nil
}

func writeOUIJSON(out io.Writer, rows []ouiRow, reg ouiRegister) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(ouiAnswer{Addresses: rows, Register: reg})
}

func writeOUIText(out io.Writer, rows []ouiRow, reg ouiRegister) error {
	tw := tabwriter.NewWriter(out, 2, 8, 2, ' ', 0)
	p := &printer{w: tw}
	p.printf("ADDRESS\tVENDOR\tBLOCK\tNOTE\n")
	named := 0
	for _, r := range rows {
		vendor, note := r.Vendor, ""
		if vendor == "" {
			vendor = "-"
		}
		if r.Manufacturer {
			named++
		} else {
			// Only the cases that need explaining get a sentence; a plain
			// assignment says everything in the two columns before it.
			note = r.Note
		}
		p.printf("%s\t%s\t%s\t%s\n", r.MAC, vendor, blockLabel(r), note)
	}
	if p.err != nil {
		return p.err
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	p = &printer{w: out}
	p.printf("\n%d of %s named, from a registry of %d 24-bit and %d 36-bit assignments.\n",
		named, plural(len(rows), "address", "addresses"), reg.Bits24, reg.Bits36)
	return p.err
}

func blockLabel(r ouiRow) string {
	if r.Block == "" {
		return "-"
	}
	return fmt.Sprintf("%s/%d", r.Block, r.Bits)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
