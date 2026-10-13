// Command otinv builds an asset inventory for OT/ICS environments from packet
// captures. It is strictly passive: it reads capture files and never sends a
// packet or opens a connection toward an analysed host.
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// Set via -ldflags at build time; see the Makefile.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		// Cobra has already printed the error.
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	var verbose bool

	root := &cobra.Command{
		Use:   "otinv",
		Short: "Passive OT/ICS asset inventory from packet captures",
		Long: "otinv builds an asset inventory, communication matrix and network topology\n" +
			"for OT/ICS environments from packet captures only.\n\n" +
			"It is strictly passive: it never sends packets, never connects to analysed\n" +
			"hosts and never fingerprints them actively.",
		SilenceUsage:  true,
		SilenceErrors: false,
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			slog.SetDefault(newLogger(verbose))
		},
	}
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "log at debug level")

	root.AddCommand(newAnalyzeCommand(), newVersionCommand())
	return root
}

// newLogger logs text to a terminal and JSON everywhere else, so that piped
// output stays machine readable.
func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}

	if info, err := os.Stderr.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "otinv %s (commit %s, built %s)\n",
				version, commit, buildDate)
			return err
		},
	}
}
