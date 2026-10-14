package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/rules"
)

func newRulesCommand() *cobra.Command {
	var (
		asJSON     bool
		configPath string
		check      []string
	)

	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List the detection rules, or validate a custom rule file",
		Long: "rules lists the built-in rules and the custom ones the configuration loads,\n" +
			"with the severity and the MITRE ATT&CK for ICS technique each belongs to.\n\n" +
			"A rule that cannot fire in this configuration says so rather than quietly\n" +
			"doing nothing: the engineering allow-list is the usual reason.\n\n" +
			"--check validates rule files and prints what they define, which is the fast\n" +
			"way to find out why a rule file will not load.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := LoadConfig(configPath)
			if err != nil {
				return err
			}

			files := cfg.Rules.Files
			onlyCheck := len(check) > 0
			if onlyCheck {
				files = check
			}
			custom, err := rules.LoadRuleFiles(files...)
			if err != nil {
				return err
			}

			engine, err := rules.New(rules.Config{
				EngineeringStations: cfg.Rules.EngineeringStations,
				Registry:            dissect.Default(),
				Custom:              custom,
				Disabled:            cfg.Rules.Disabled,
			})
			if err != nil {
				return err
			}

			listed := engine.Rules()
			if onlyCheck {
				kept := listed[:0]
				for _, d := range listed {
					if d.Custom {
						kept = append(kept, d)
					}
				}
				listed = kept
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s: %s\n",
					strings.Join(check, ", "), pluralRules(len(listed))); err != nil {
					return err
				}
			}

			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(ruleList(listed))
			}
			return writeRulesText(cmd.OutOrStdout(), listed)
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the list as JSON")
	cmd.Flags().StringVarP(&configPath, "config", "c", "",
		"configuration file (default "+DefaultConfigPath+" when present)")
	cmd.Flags().StringArrayVar(&check, "check", nil,
		"validate these custom rule files and list what they define; repeatable")
	return cmd
}

// ruleEntry is the JSON shape of a listed rule.
type ruleEntry struct {
	rules.Description
	TechniqueName string `json:"technique_name,omitempty"`
	TechniqueURL  string `json:"technique_url,omitempty"`
}

type ruleListing struct {
	Total int         `json:"total"`
	Rules []ruleEntry `json:"rules"`
}

func ruleList(in []rules.Description) ruleListing {
	out := ruleListing{Total: len(in), Rules: make([]ruleEntry, 0, len(in))}
	for _, d := range in {
		out.Rules = append(out.Rules, ruleEntry{
			Description:   d,
			TechniqueName: d.TechniqueName(),
			TechniqueURL:  rules.TechniqueURL(d.Technique),
		})
	}
	return out
}

func writeRulesText(out io.Writer, listed []rules.Description) error {
	if len(listed) == 0 {
		_, err := fmt.Fprintln(out, "no rules")
		return err
	}

	tw := tabwriter.NewWriter(out, 2, 8, 2, ' ', 0)
	p := &printer{w: tw}
	p.printf("ID\tSEVERITY\tTECHNIQUE\tKIND\tTITLE\n")
	for _, d := range listed {
		kind := "built-in"
		if d.Custom {
			kind = "custom"
		}
		technique := d.Technique
		if name := d.TechniqueName(); name != "" {
			technique += " " + name
		}
		p.printf("%s\t%s\t%s\t%s\t%s\n", d.ID, d.Severity, technique, kind, d.Title)
	}
	if p.err != nil {
		return p.err
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	p = &printer{w: out}
	inactive := make([]rules.Description, 0, len(listed))
	for _, d := range listed {
		if d.Inactive != "" {
			inactive = append(inactive, d)
		}
	}
	sort.SliceStable(inactive, func(i, j int) bool { return inactive[i].ID < inactive[j].ID })
	if len(inactive) > 0 {
		p.printf("\ninactive in this configuration\n")
		for _, d := range inactive {
			p.printf("  %s  %s\n", d.ID, d.Inactive)
		}
	}
	p.printf("\n%s. Findings carry the packet that produced them; see `otinv export --what findings`.\n",
		pluralRules(len(listed)))
	return p.err
}

func pluralRules(n int) string {
	if n == 1 {
		return "1 rule"
	}
	return fmt.Sprintf("%d rules", n)
}
