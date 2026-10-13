package main

import (
	"fmt"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/rom/otinv/internal/store"
	"github.com/rom/otinv/internal/web"
)

func newServeCommand() *cobra.Command {
	var (
		project string
		dbPath  string
		listen  string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Browse a project's inventory in the web GUI",
		Long: "serve starts the self-hosted GUI for a project that analyze has already\n" +
			"ingested.\n\n" +
			"It binds to loopback. Binding anywhere else requires authentication, which\n" +
			"is a later milestone, so other addresses are refused rather than exposing\n" +
			"OT data unprotected.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if project == "" {
				return fmt.Errorf("serve: --project is required; analyze a capture into one first")
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

			srv, err := web.New(web.Options{Store: db, Project: p, Addr: listen})
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(),
				"otinv serving project %q on http://%s\n", p.Name, srv.Addr()); err != nil {
				return err
			}
			return srv.ListenAndServe(ctx)
		},
	}

	cmd.Flags().StringVarP(&project, "project", "p", "", "project to serve (required)")
	cmd.Flags().StringVar(&dbPath, "db", "", "project database file (default <project>.otinv.db)")
	cmd.Flags().StringVar(&listen, "listen", web.DefaultAddr, "address to bind (loopback only)")
	return cmd
}
