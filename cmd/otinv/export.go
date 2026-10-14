package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rom/otinv/internal/export"
	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/store"
)

// assetPage and flowPage are how many rows one query asks the store for. The
// store caps a page for the GUI's sake, so an export walks the list a page at
// a time rather than asking for a number it would not get.
const (
	assetPage = 500
	flowPage  = 1000
)

func newExportCommand() *cobra.Command {
	var (
		project  string
		dbPath   string
		what     string
		format   string
		outPath  string
		protocol string
		class    string
		limit    int
		compact  bool
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write a project's inventory out as JSON or CSV",
		Long: "export reads a project that analyze has already ingested and writes it out\n" +
			"for other tools: JSON for programs, CSV for spreadsheets.\n\n" +
			"--what picks the tables: " + export.KindList() + ", or all for everything\n" +
			"except the events, which a project can hold millions of. A CSV file holds\n" +
			"one table, so --format csv takes one table at a time; JSON takes any mix.\n\n" +
			"Nothing is decoded again and nothing is sent anywhere: an export is a read\n" +
			"of the project database.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if project == "" {
				return errors.New("export: --project is required; analyze a capture into one first")
			}
			if limit < 0 {
				return fmt.Errorf("export: --limit cannot be negative (%d); 0 means every row", limit)
			}
			kinds, err := export.ParseKinds(what)
			if err != nil {
				return err
			}
			encoding, err := export.ParseFormat(format)
			if err != nil {
				return err
			}
			if encoding == export.FormatCSV && len(kinds) != 1 {
				return fmt.Errorf("export: a CSV file holds one table, but %d were asked for; "+
					"pass one --what (e.g. --what assets) or --format json", len(kinds))
			}

			ctx := cmd.Context()
			db, p, err := openExistingProject(ctx, project, dbPath)
			if err != nil {
				return err
			}
			defer func() { _ = db.Close() }()

			doc := export.NewDocument(p.Name, db.Path(), version, kinds)
			doc.Filter.Protocol = protocol
			doc.Filter.Class = class
			doc.Filter.Limit = limit

			counts, err := fillDocument(ctx, db, p.ID, doc, kinds, protocol, class, limit)
			if err != nil {
				return err
			}

			out, closeOut, err := openOutput(outPath, cmd.OutOrStdout())
			if err != nil {
				return err
			}
			written, err := writeExport(ctx, db, p.ID, out, doc, kinds, encoding,
				!compact, protocol, class, limit)
			if closeErr := closeOut(); err == nil {
				err = closeErr
			}
			if err != nil {
				return err
			}

			if outPath == "" {
				return nil
			}
			// Writing to a file leaves the terminal empty, so say what landed
			// in it. Writing to stdout says nothing: the data is the output.
			counts[export.KindEvents] = written
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s: %s\n",
				outPath, describeCounts(kinds, counts))
			return err
		},
	}

	cmd.Flags().StringVarP(&project, "project", "p", "", "project to export (required)")
	cmd.Flags().StringVar(&dbPath, "db", "", "project database file (default <project>.otinv.db)")
	cmd.Flags().StringVar(&what, "what", string(export.KindAssets),
		"tables to export, comma separated: "+export.KindList()+", all")
	cmd.Flags().StringVarP(&format, "format", "f", string(export.FormatJSON), "output format: json or csv")
	cmd.Flags().StringVarP(&outPath, "out", "o", "", "write to this file instead of stdout")
	cmd.Flags().StringVar(&protocol, "protocol", "", "only this protocol's flows and events")
	cmd.Flags().StringVar(&class, "class", "",
		"only this classification's flows and events: read, write, control, program, "+
			"firmware, diagnostic, discovery, other")
	cmd.Flags().IntVar(&limit, "limit", 0, "at most this many rows per table (0 means every row)")
	cmd.Flags().BoolVar(&compact, "compact", false, "write JSON without indentation")
	return cmd
}

// openExistingProject opens a project without creating anything. An export of
// a project that does not exist is a typo, and answering it with an empty file
// would hide the mistake.
func openExistingProject(ctx context.Context, project, dbPath string) (*store.Store, model.Project, error) {
	path := projectDBPath(project, dbPath)
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, model.Project{}, fmt.Errorf(
				"no project database at %s; analyze a capture into project %q first", path, project)
		}
		return nil, model.Project{}, fmt.Errorf("opening %s: %w", path, err)
	}

	db, err := store.Open(ctx, path)
	if err != nil {
		return nil, model.Project{}, err
	}
	projects, err := db.Projects(ctx)
	if err != nil {
		_ = db.Close()
		return nil, model.Project{}, err
	}
	for _, p := range projects {
		if p.Name == project {
			return db, p, nil
		}
	}

	names := make([]string, 0, len(projects))
	for _, p := range projects {
		names = append(names, strconv.Quote(p.Name))
	}
	_ = db.Close()
	if len(names) == 0 {
		return nil, model.Project{}, fmt.Errorf("%s holds no project yet", path)
	}
	return nil, model.Project{}, fmt.Errorf("%s holds no project %q; it holds %s",
		path, project, strings.Join(names, ", "))
}

// fillDocument loads every requested table but the events, which are streamed
// later rather than collected.
func fillDocument(ctx context.Context, db *store.Store, projectID int64, doc *export.Document,
	kinds []export.Kind, protocol, class string, limit int,
) (map[export.Kind]int, error) {
	counts := map[export.Kind]int{}
	for _, kind := range kinds {
		switch kind {
		case export.KindSummary:
			summary, err := db.Summary(ctx, projectID)
			if err != nil {
				return nil, err
			}
			doc.Summary = export.FromSummary(summary)
			counts[kind] = 1
		case export.KindCaptures:
			captures, err := db.Captures(ctx, projectID)
			if err != nil {
				return nil, err
			}
			doc.Captures = export.FromCaptures(captures)
			counts[kind] = len(doc.Captures)
		case export.KindProtocols:
			stats, err := db.ProtocolStats(ctx, projectID)
			if err != nil {
				return nil, err
			}
			doc.Protocols = export.FromProtocolStats(stats)
			counts[kind] = len(doc.Protocols)
		case export.KindAssets:
			assets, err := allAssets(ctx, db, projectID, protocol, limit)
			if err != nil {
				return nil, err
			}
			doc.Assets = assets
			counts[kind] = len(assets)
		case export.KindFlows:
			flows, err := allFlows(ctx, db, projectID, protocol, class, limit)
			if err != nil {
				return nil, err
			}
			doc.Flows = export.FromFlows(flows)
			counts[kind] = len(doc.Flows)
		case export.KindEvents:
			// Streamed in writeExport.
		}
	}
	return counts, nil
}

// allAssets walks the whole inventory, page by page.
func allAssets(ctx context.Context, db *store.Store, projectID int64,
	protocol string, limit int,
) ([]model.Asset, error) {
	var out []model.Asset
	for offset := 0; ; offset += assetPage {
		page, total, err := db.Assets(ctx, store.AssetQuery{
			ProjectID: projectID,
			Protocol:  protocol,
			Limit:     assetPage,
			Offset:    offset,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if limit > 0 && len(out) >= limit {
			return out[:limit], nil
		}
		if len(page) == 0 || len(out) >= total {
			return out, nil
		}
	}
}

// allFlows walks every flow, page by page.
func allFlows(ctx context.Context, db *store.Store, projectID int64,
	protocol, class string, limit int,
) ([]store.Flow, error) {
	var out []store.Flow
	for offset := 0; ; offset += flowPage {
		page, total, err := db.Flows(ctx, store.FlowQuery{
			ProjectID: projectID,
			Protocol:  protocol,
			Class:     class,
			Limit:     flowPage,
			Offset:    offset,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if limit > 0 && len(out) >= limit {
			return out[:limit], nil
		}
		if len(page) == 0 || len(out) >= total {
			return out, nil
		}
	}
}

// writeExport writes the document, streaming the events when they were asked
// for. It returns how many events it wrote.
func writeExport(ctx context.Context, db *store.Store, projectID int64, out io.Writer,
	doc *export.Document, kinds []export.Kind, encoding export.Format, indent bool,
	protocol, class string, limit int,
) (int, error) {
	if !wants(kinds, export.KindEvents) {
		if encoding == export.FormatCSV {
			table, err := doc.Table(kinds[0])
			if err != nil {
				return 0, err
			}
			return len(table.Rows), export.WriteCSV(out, table)
		}
		return 0, export.WriteJSON(out, doc, indent)
	}

	stream, err := export.NewEventStream(out, encoding, doc, indent)
	if err != nil {
		return 0, err
	}
	written := 0
	err = db.EachEventMatching(ctx, store.EventQuery{
		ProjectID: projectID,
		Protocol:  protocol,
		Class:     class,
		Limit:     limit,
	}, func(e model.Event) error {
		written++
		return stream.Add(e)
	})
	if err != nil {
		return written, err
	}
	return written, stream.Close()
}

func wants(kinds []export.Kind, kind export.Kind) bool {
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// openOutput returns where to write and how to finish. A file is created
// fresh; stdout is left open, since the command did not open it.
func openOutput(path string, stdout io.Writer) (io.Writer, func() error, error) {
	if path == "" {
		return stdout, func() error { return nil }, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("creating %s: %w", path, err)
	}
	return f, f.Close, nil
}

// describeCounts says what a file holds, in the order the tables were written.
func describeCounts(kinds []export.Kind, counts map[export.Kind]int) string {
	parts := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		if kind == export.KindSummary {
			parts = append(parts, "the summary")
			continue
		}
		parts = append(parts, fmt.Sprintf("%d %s", counts[kind], kind))
	}
	return strings.Join(parts, ", ")
}
