// Package web serves the otinv GUI: server-rendered pages with htmx for
// filtering, and no external origins at all.
//
// The GUI shows sensitive OT data, so it binds to loopback by default and the
// security headers are set on every response.
package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/rules"
	"github.com/rom/otinv/internal/store"
	"github.com/rom/otinv/internal/web/templates"
)

//go:embed static
var staticFS embed.FS

// DefaultAddr is the address the GUI binds to unless told otherwise.
const DefaultAddr = "127.0.0.1:8080"

// maxAssetEvents is how many of an asset's events the detail page shows.
const maxAssetEvents = 100

// DefaultShutdownTimeout is how long a shutdown waits for requests in flight.
const DefaultShutdownTimeout = 5 * time.Second

// Options configures the server.
type Options struct {
	Store   *store.Store
	Project model.Project
	Addr    string
	Logger  *slog.Logger

	// ReadOnly refuses every state-changing request. The GUI has no accounts
	// yet, so anyone who can reach it can change a project's settings; this
	// is what `serve --read-only` offers when a project is being shown
	// rather than worked on.
	ReadOnly bool

	// Lang is the UI language to use when the project has no stored language
	// setting. It is a fallback, not an override: a stored setting and an
	// explicit ?lang= both still win. An empty value leaves the choice to the
	// browser's Accept-Language header.
	Lang string

	// ShutdownTimeout bounds how long a shutdown waits for requests in
	// flight. Zero means DefaultShutdownTimeout.
	ShutdownTimeout time.Duration

	// Rules is the detection rule configuration, as otinv.yaml defines it:
	// the GUI runs exactly the rules the command line would. Assets is
	// filled per run, since the inventory changes under it.
	Rules rules.Config

	// RuleFiles are the custom rule files the configuration loaded, which
	// the rules view names so that a reader knows where a rule is edited.
	RuleFiles []string
}

// Server serves the GUI for one project.
type Server struct {
	store     *store.Store
	project   model.Project
	addr      string
	log       *slog.Logger
	mux       *http.ServeMux
	readOnly  bool
	lang      templates.Lang
	shutdown  time.Duration
	rules     rules.Config
	ruleFiles []string
}

// New builds a server.
//
// Binding anywhere but loopback is refused: CLAUDE.md requires mandatory
// authentication for that, and authentication is not implemented yet. Failing
// to start is the safe answer, rather than exposing OT data to the network.
func New(opts Options) (*Server, error) {
	if opts.Store == nil {
		return nil, errors.New("web: a store is required")
	}
	if opts.Addr == "" {
		opts.Addr = DefaultAddr
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.ShutdownTimeout <= 0 {
		opts.ShutdownTimeout = DefaultShutdownTimeout
	}
	if err := checkAddr(opts.Addr); err != nil {
		return nil, err
	}

	var lang templates.Lang
	if opts.Lang != "" {
		valid, ok := templates.ValidLang(opts.Lang)
		if !ok {
			return nil, fmt.Errorf("web: no UI language %q; the GUI ships with %s",
				opts.Lang, templates.LangList())
		}
		lang = valid
	}

	// Building the engine once here turns a bad rule configuration into a
	// server that refuses to start, rather than into a page that fails.
	if _, err := rules.New(opts.Rules); err != nil {
		return nil, err
	}

	s := &Server{
		store:     opts.Store,
		project:   opts.Project,
		addr:      opts.Addr,
		log:       opts.Logger,
		readOnly:  opts.ReadOnly,
		lang:      lang,
		shutdown:  opts.ShutdownTimeout,
		rules:     opts.Rules,
		ruleFiles: opts.RuleFiles,
	}
	s.routes()
	return s, nil
}

// checkAddr refuses a listen address that would expose the GUI beyond this
// machine while there is no authentication to protect it.
func checkAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("web: listen address %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("web: listen address %q binds every interface, which needs authentication; "+
			"authentication is not implemented yet, so use a loopback address", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if host == "localhost" {
			return nil
		}
		return fmt.Errorf("web: listen address %q is not a loopback address; binding elsewhere needs "+
			"authentication, which is not implemented yet", addr)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("web: listen address %q is not a loopback address; binding elsewhere needs "+
			"authentication, which is not implemented yet", addr)
	}
	return nil
}

// Addr is the address the server binds to.
func (s *Server) Addr() string { return s.addr }

// ReadOnly reports whether state-changing requests are refused.
func (s *Server) ReadOnly() bool { return s.readOnly }

// Handler returns the routed, wrapped handler.
func (s *Server) Handler() http.Handler { return secureHeaders(s.mux) }

func (s *Server) routes() {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	})
	mux.HandleFunc("GET /dashboard", s.handleDashboard)
	mux.HandleFunc("GET /assets", s.handleAssets)
	mux.HandleFunc("GET /assets/{key}", s.handleAsset)
	mux.HandleFunc("GET /topology", s.handleTopology)
	// The island fetches the graph as JSON and the export link takes the same
	// filter as a standalone picture.
	mux.HandleFunc("GET /topology.json", s.handleTopologyJSON)
	mux.HandleFunc("GET /topology.svg", s.handleTopologySVG)
	mux.HandleFunc("GET /flows", s.handleFlows)
	mux.HandleFunc("GET /matrix", s.handleMatrix)
	mux.HandleFunc("GET /events", s.handleEvents)
	mux.HandleFunc("GET /protocols", s.handleProtocols)
	mux.HandleFunc("GET /captures", s.handleCaptures)
	mux.HandleFunc("GET /findings", s.handleFindings)
	mux.HandleFunc("POST /findings", s.handleBulkTriage)
	mux.HandleFunc("GET /findings/{id}", s.handleFinding)
	mux.HandleFunc("POST /findings/{id}", s.handleTriage)
	mux.HandleFunc("GET /rules", s.handleRules)
	mux.HandleFunc("POST /rules", s.handleRerunRules)
	mux.HandleFunc("GET /settings", s.handleSettings)
	mux.HandleFunc("POST /settings", s.handleSaveSettings)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})

	static, err := fs.Sub(staticFS, "static")
	if err != nil {
		// The embed is compiled in, so this cannot fail at runtime.
		panic("web: embedded static assets missing: " + err.Error())
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(static))))

	s.mux = mux
}

// ListenAndServe serves until the context is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	errCh := make(chan error, 1)
	go func() {
		s.log.Info("serving GUI", "addr", s.addr, "project", s.project.Name)
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdown)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// secureHeaders sets the policy for every response. The content security
// policy allows this origin only and no inline scripts, which is why the
// templates carry none.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
				"form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// same-origin rather than no-referrer: a referrer never leaves this
		// origin either way, but no-referrer also makes a browser post forms
		// with an opaque "null" origin, which is one signal fewer for the
		// CSRF check to work with.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// cacheStatic lets the vendored assets be cached; they change only when the
// binary does.
func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}

// page builds the shared chrome: the UI language and the appearance settings.
// The caller sets the title afterwards, because a translated title needs the
// language this returns.
//
// The settings are read per request rather than cached, so that saving them
// takes effect on the next page rather than on the next restart. The table
// holds a handful of rows and the read is a local SQLite query.
func (s *Server) page(r *http.Request, nav string) templates.PageView {
	stored, err := s.store.Settings(r.Context(), s.project.ID)
	if err != nil {
		// A page is more useful with default settings than not at all.
		s.log.Warn("reading settings failed", "err", err)
		stored = nil
	}
	theme := templates.NewTheme(stored)

	// An explicit ?lang= wins, then the stored setting, then what the browser
	// asks for: a link someone sends should arrive in the language it was
	// written in.
	lang := theme.Lang()
	if explicit := r.URL.Query().Get("lang"); explicit != "" {
		lang = templates.ParseLang(explicit, "")
	} else if _, ok := stored[templates.SettingLang]; !ok {
		// Nothing is stored, so the command line decides, and the browser
		// only when it did not: `serve --lang sv` means this project is read
		// in Swedish whoever opens it.
		if s.lang != "" {
			lang = s.lang
		} else {
			lang = templates.ParseLang("", r.Header.Get("Accept-Language"))
		}
	}

	return templates.PageView{
		Lang:    lang,
		Project: s.project.Name,
		Nav:     nav,
		Theme:   theme,
	}
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := s.page(r, "assets")
	page.Title = templates.T(page.Lang, "assets.title")
	filter := templates.AssetsFilter{
		Search:   q.Get("q"),
		Role:     q.Get("role"),
		Protocol: q.Get("protocol"),
		Level:    q.Get("level"),
	}
	limit := clampInt(q.Get("limit"), page.Theme.PageSize(), 1, 500)
	offset := clampInt(q.Get("offset"), 0, 0, 1<<30)
	// A column the store does not know how to order by is dropped rather than
	// refused, so a stale or hand-edited link still shows the list.
	order := parseSort(q.Get("sort"), q.Get("dir"))
	if _, ok := store.AssetSortColumns[order.Column]; !ok {
		order.Column = ""
	}

	ctx := r.Context()
	assets, total, err := s.store.Assets(ctx, store.AssetQuery{
		ProjectID: s.project.ID,
		Role:      filter.Role,
		Protocol:  filter.Protocol,
		Level:     filter.Level,
		Search:    filter.Search,
		Limit:     limit,
		Offset:    offset,
		Sort:      order.Column,
		Desc:      order.Desc,
	})
	if err != nil {
		s.fail(w, r, "listing assets", err)
		return
	}
	roles, err := s.store.AssetRoles(ctx, s.project.ID)
	if err != nil {
		s.fail(w, r, "listing roles", err)
		return
	}
	protocols, err := s.store.AssetProtocols(ctx, s.project.ID)
	if err != nil {
		s.fail(w, r, "listing protocols", err)
		return
	}
	levels, err := s.store.AssetLevels(ctx, s.project.ID)
	if err != nil {
		s.fail(w, r, "listing levels", err)
		return
	}

	view := templates.AssetsView{
		Page:      page,
		Rows:      assetRows(assets),
		Total:     total,
		Offset:    offset,
		Limit:     limit,
		Filter:    filter,
		Sort:      order,
		Roles:     roles,
		Protocols: protocols,
		Levels:    levels,
	}

	// htmx asks for the table alone, so filtering and paging stay on the
	// server and only the table is replaced.
	if r.Header.Get("HX-Request") == "true" {
		s.render(w, r, templates.AssetTable(view))
		return
	}
	s.render(w, r, templates.AssetsPage(view))
}

func assetRows(assets []model.Asset) []templates.AssetRow {
	rows := make([]templates.AssetRow, 0, len(assets))
	for _, a := range assets {
		row := templates.AssetRow{
			Key:       a.Key,
			Label:     a.Label,
			Vendor:    a.Vendor(),
			Role:      a.Role.Name,
			Level:     a.Level,
			Events:    a.Events,
			LastSeen:  a.LastSeen,
			IsGateway: a.IsGateway,
		}
		row.Addresses = append(row.Addresses, a.MACs...)
		for _, ip := range a.IPs {
			if ip != a.Label {
				row.Addresses = append(row.Addresses, ip)
			}
		}
		for _, p := range a.Protocols {
			row.Protocols = append(row.Protocols, p.Protocol+" ("+p.Side+")")
		}
		rows = append(rows, row)
	}
	return rows
}

func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	ctx := r.Context()

	asset, err := s.store.Asset(ctx, s.project.ID, key)
	if err != nil {
		s.fail(w, r, "reading asset", err)
		return
	}
	if asset == nil {
		http.NotFound(w, r)
		return
	}

	addresses := append(append([]string{}, asset.IPs...), asset.MACs...)
	events, err := s.store.Events(ctx, store.EventQuery{
		ProjectID: s.project.ID,
		Addresses: addresses,
		Limit:     maxAssetEvents,
	})
	if err != nil {
		s.fail(w, r, "reading asset events", err)
		return
	}

	page := s.page(r, "assets")
	page.Title = asset.Label
	view := templates.AssetView{
		Page:   page,
		Asset:  *asset,
		Events: eventRows(*asset, events),
		Sort:   parseSort(r.URL.Query().Get("sort"), r.URL.Query().Get("dir")),
	}
	// Each of the page's tables orders only by a column of its own, so one
	// sort state can serve all four.
	sortAttributes(view.Asset.Attributes, view.Sort)
	sortAddresses(view.Asset.Addresses, view.Sort)
	sortProtocols(view.Asset.Protocols, view.Sort)
	sortEvents(view.Events, view.Sort)
	s.render(w, r, templates.AssetPage(view))
}

// eventRows renders an asset's events from its own point of view: the peer is
// whichever endpoint is not this asset.
func eventRows(asset model.Asset, events []model.Event) []templates.EventRow {
	own := map[string]bool{}
	for _, ip := range asset.IPs {
		own[ip] = true
	}
	for _, mac := range asset.MACs {
		own[mac] = true
	}

	rows := make([]templates.EventRow, 0, len(events))
	for _, e := range events {
		peer := e.Flow.DstIP
		if !own[e.Flow.SrcIP] && own[e.Flow.DstIP] {
			peer = e.Flow.SrcIP
		}
		unit := "—"
		if e.UnitID != nil {
			unit = strconv.Itoa(int(*e.UnitID))
		}
		rows = append(rows, templates.EventRow{
			Time:      e.Timestamp,
			Operation: e.Operation,
			Detail:    eventDetail(e),
			Class:     string(e.Class),
			Direction: string(e.Direction),
			Peer:      peer,
			Packet:    e.PacketIndex,
			Unit:      unit,
			Exception: e.Exception,
			Malformed: e.Malformed,
		})
	}
	return rows
}

// eventDetail summarises what an operation did, from the fields the dissector
// decoded. It is deliberately short: the full attribute set belongs to the
// flow view, but a page about a device has to show the operation that matters.
func eventDetail(e model.Event) string {
	var parts []string
	if name := e.Attrs["sub_function_name"]; name != "" {
		parts = append(parts, name)
	}
	if e.Address != nil {
		addr := "addr " + strconv.FormatUint(uint64(*e.Address), 10)
		if e.Quantity != nil && *e.Quantity > 1 {
			addr += " ×" + strconv.FormatUint(uint64(*e.Quantity), 10)
		}
		parts = append(parts, addr)
	}
	// Protocols that address objects by name rather than by number: an MMS
	// object reference says more about what happened than any other field.
	if v := e.Attrs["report_id"]; v != "" {
		parts = append(parts, v)
	} else if v := e.Attrs["object"]; v != "" {
		obj := v
		if e.Quantity != nil && *e.Quantity > 1 {
			obj += " ×" + strconv.FormatUint(uint64(*e.Quantity), 10)
		}
		parts = append(parts, obj)
	}
	if v := e.Attrs["coil_state"]; v != "" {
		parts = append(parts, v)
	} else if v := e.Attrs["value"]; v != "" {
		parts = append(parts, "value "+v)
	}
	// Select or execute is the difference between arming a command and
	// issuing it, so a command sequence is unreadable without it.
	if v := e.Attrs["command_mode"]; v != "" {
		parts = append(parts, v)
	}
	if v := e.Attrs["anomaly"]; v != "" {
		parts = append(parts, v)
	}
	if e.Error != "" {
		parts = append(parts, e.Error)
	}
	return strings.Join(parts, " · ")
}

func (s *Server) handleCaptures(w http.ResponseWriter, r *http.Request) {
	captures, err := s.store.Captures(r.Context(), s.project.ID)
	if err != nil {
		s.fail(w, r, "listing captures", err)
		return
	}

	rows := make([]templates.CaptureRow, 0, len(captures))
	for _, c := range captures {
		rows = append(rows, templates.CaptureRow{
			Path:      c.Path,
			SHA256:    c.SHA256,
			Packets:   c.Packets,
			LinkType:  c.LinkType,
			FirstSeen: c.FirstSeen,
			LastSeen:  c.LastSeen,
		})
	}

	page := s.page(r, "captures")
	page.Title = templates.T(page.Lang, "captures.title")
	order := parseSort(r.URL.Query().Get("sort"), r.URL.Query().Get("dir"))
	sortCaptures(rows, order)
	s.render(w, r, templates.CapturesPage(templates.CapturesView{
		Page:     page,
		Captures: rows,
		Sort:     order,
	}))
}

// render writes a page. Sensitive OT data must not linger in any cache, so
// every rendered page is marked no-store.
//
// A render that fails midway has already written part of the body, so the
// status cannot be changed any more; the error is logged instead.
func (s *Server) render(w http.ResponseWriter, r *http.Request, c templ.Component) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := c.Render(r.Context(), w); err != nil {
		s.log.Error("rendering page failed", "path", r.URL.Path, "err", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.Error("request failed", "what", what, "path", r.URL.Path, "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func clampInt(raw string, def, minValue, maxValue int) int {
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return min(max(v, minValue), maxValue)
}
