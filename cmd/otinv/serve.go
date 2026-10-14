package main

import (
	"errors"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/rom/otinv/internal/store"
	"github.com/rom/otinv/internal/web"
	"github.com/rom/otinv/internal/web/templates"
)

func newServeCommand() *cobra.Command {
	var (
		project  string
		dbPath   string
		listen   string
		readOnly bool
		lang     string
		shutdown time.Duration
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Browse a project's inventory in the web GUI",
		Long: "serve starts the self-hosted GUI for a project that analyze has already\n" +
			"ingested.\n\n" +
			"It binds to loopback. Binding anywhere else requires authentication, which\n" +
			"is a later milestone, so other addresses are refused rather than exposing\n" +
			"OT data unprotected. The GUI only reads the project database; it never\n" +
			"touches a network other than this listener.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if project == "" {
				return errors.New("serve: --project is required; analyze a capture into one first")
			}
			if lang != "" {
				if _, ok := templates.ValidLang(lang); !ok {
					return fmt.Errorf("serve: --lang %q is not one of %s", lang, templates.LangList())
				}
			}
			if shutdown <= 0 {
				return fmt.Errorf("serve: --shutdown-timeout must be positive, not %s", shutdown)
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			db, err := store.Open(ctx, projectDBPath(project, dbPath))
			if err != nil {
				return err
			}
			defer func() { _ = db.Close() }()

			p, err := db.EnsureProject(ctx, project)
			if err != nil {
				return err
			}

			srv, err := web.New(web.Options{
				Store:           db,
				Project:         p,
				Addr:            listen,
				ReadOnly:        readOnly,
				Lang:            lang,
				ShutdownTimeout: shutdown,
			})
			if err != nil {
				return err
			}

			mode := ""
			if srv.ReadOnly() {
				mode = " (read-only)"
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(),
				"otinv serving project %q on http://%s%s\n", p.Name, srv.Addr(), mode); err != nil {
				return err
			}
			return srv.ListenAndServe(ctx)
		},
	}

	cmd.Flags().StringVarP(&project, "project", "p", "", "project to serve (required)")
	cmd.Flags().StringVar(&dbPath, "db", "", "project database file (default <project>.otinv.db)")
	cmd.Flags().StringVar(&listen, "listen", web.DefaultAddr, "address to bind (loopback only)")
	cmd.Flags().BoolVar(&readOnly, "read-only", false,
		"refuse every state-changing request, so the GUI can only be read")
	cmd.Flags().StringVar(&lang, "lang", "",
		"UI language when the project has none stored: "+templates.LangList())
	cmd.Flags().DurationVar(&shutdown, "shutdown-timeout", web.DefaultShutdownTimeout,
		"how long to wait for requests in flight when shutting down")
	return cmd
}
