// Command otinv builds an asset inventory for OT/ICS environments from packet
// captures. It is strictly passive: it reads capture files and never sends a
// packet or opens a connection toward an analysed host.
package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"

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
	var (
		verbose   bool
		logLevel  string
		logFormat string
	)

	root := &cobra.Command{
		Use:   "otinv",
		Short: "Passive OT/ICS asset inventory from packet captures",
		Long: "otinv builds an asset inventory, communication matrix and network topology\n" +
			"for OT/ICS environments from packet captures only.\n\n" +
			"It is strictly passive: it never sends packets, never connects to analysed\n" +
			"hosts and never fingerprints them actively.",
		SilenceUsage:  true,
		SilenceErrors: false,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// -v is the short way to say --log-level debug; an explicit level
			// wins, so --log-level warn is not overridden by a stray -v.
			if verbose && !cmd.Flags().Changed("log-level") {
				logLevel = "debug"
			}
			logger, err := newLogger(os.Stderr, logLevel, logFormat)
			if err != nil {
				return err
			}
			slog.SetDefault(logger)
			return nil
		},
	}

	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false,
		"log at debug level (same as --log-level debug)")
	root.PersistentFlags().StringVar(&logLevel, "log-level", "info",
		"log level: debug, info, warn or error")
	root.PersistentFlags().StringVar(&logFormat, "log-format", "auto",
		"log format: auto, text or json (auto is text on a terminal, JSON when redirected)")

	root.AddCommand(
		newAnalyzeCommand(),
		newServeCommand(),
		newExportCommand(),
		newProtocolsCommand(),
		newRulesCommand(),
		newVersionCommand(),
	)
	return root
}

// newLogger builds the process logger. The default format logs text to a
// terminal and JSON everywhere else, so that redirected output stays machine
// readable (CLAUDE.md, "Logging").
func newLogger(w *os.File, levelName, formatName string) (*slog.Logger, error) {
	level, err := parseLevel(levelName)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: level}

	switch strings.ToLower(strings.TrimSpace(formatName)) {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "", "auto":
		if isTerminal(w) {
			return slog.New(slog.NewTextHandler(w, opts)), nil
		}
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("--log-format %q is not auto, text or json", formatName)
	}
}

func parseLevel(name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("--log-level %q is not debug, info, warn or error", name)
	}
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func newVersionCommand() *cobra.Command {
	var short bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return writeVersion(cmd.OutOrStdout(), short)
		},
	}
	cmd.Flags().BoolVar(&short, "short", false, "print the version alone, for scripts")
	return cmd
}

func writeVersion(out io.Writer, short bool) error {
	if short {
		_, err := fmt.Fprintln(out, version)
		return err
	}
	p := &printer{w: out}
	p.printf("otinv %s (commit %s, built %s)\n", version, commit, buildDate)
	p.printf("%s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return p.err
}
