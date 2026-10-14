package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/rules"
	"github.com/rom/otinv/internal/store"
	"github.com/rom/otinv/internal/topology"
	"github.com/rom/otinv/internal/web/templates"
)

// The findings views: the triage queue, one finding with its evidence, and
// the rules that produce them.
//
// Triage is the one thing in this GUI an analyst writes, so it goes through
// the same CSRF check as the settings and is refused outright on a read-only
// server.

// maxRuleAssets bounds how much of the inventory a re-run reads.
const maxRuleAssets = 5000

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	page := s.page(r, "findings")
	page.Title = templates.T(page.Lang, "findings.title")
	theme := page.Theme

	filter := templates.FindingsFilter{
		Severity: q.Get("severity"),
		Status:   q.Get("status"),
		Rule:     q.Get("rule"),
		Protocol: q.Get("protocol"),
		Search:   strings.TrimSpace(q.Get("q")),
		Open:     q.Get("open") == "1",
	}
	// A severity or status nobody defined is dropped rather than sent to the
	// store, the same as every other filter in this GUI.
	if filter.Severity != "" && !model.Severity(filter.Severity).Valid() {
		filter.Severity = ""
	}
	if filter.Status != "" && !model.FindingStatus(filter.Status).Valid() {
		filter.Status = ""
	}

	limit := clampInt(q.Get("limit"), theme.PageSize(), 1, 500)
	offset := clampInt(q.Get("offset"), 0, 0, 1<<30)
	order := parseSort(q.Get("sort"), q.Get("dir"))
	if _, ok := store.FindingSortColumns[order.Column]; !ok {
		order.Column = ""
	}

	findings, total, err := s.store.Findings(ctx, store.FindingQuery{
		ProjectID: s.project.ID,
		Severity:  filter.Severity,
		Status:    filter.Status,
		RuleID:    filter.Rule,
		Protocol:  filter.Protocol,
		Open:      filter.Open,
		Search:    filter.Search,
		Limit:     limit,
		Offset:    offset,
		Sort:      order.Column,
		Desc:      order.Desc,
	})
	if err != nil {
		s.fail(w, r, "listing findings", err)
		return
	}
	open, err := s.store.CountOpenFindings(ctx, s.project.ID)
	if err != nil {
		s.fail(w, r, "counting open findings", err)
		return
	}
	ruleIDs, err := s.store.FindingRules(ctx, s.project.ID)
	if err != nil {
		s.fail(w, r, "listing the rules with findings", err)
		return
	}
	token, err := s.csrfToken(w, r)
	if err != nil {
		s.fail(w, r, "issuing a CSRF token", err)
		return
	}

	view := templates.FindingsView{
		Page:       page,
		Theme:      theme,
		Rows:       findingRows(findings),
		Total:      total,
		Open:       open,
		Offset:     offset,
		Limit:      limit,
		Filter:     filter,
		Sort:       order,
		Severities: templates.SeverityNames(),
		Statuses:   templates.StatusNames(),
		Rules:      ruleIDs,
		CSRF:       token,
	}
	if n := q.Get("saved"); n != "" {
		view.Saved = templates.T(page.Lang, "findings.saved")
	}
	s.render(w, r, templates.FindingsPage(view))
}

func findingRows(findings []model.Finding) []templates.FindingRow {
	rows := make([]templates.FindingRow, 0, len(findings))
	for _, f := range findings {
		row := templates.FindingRow{
			ID:        f.ID,
			RuleID:    f.RuleID,
			Title:     f.Title,
			Summary:   f.Summary,
			Severity:  string(f.Severity),
			Status:    string(f.Status),
			Src:       f.Src,
			Dst:       f.Dst,
			Protocol:  f.Protocol,
			Count:     f.Count,
			LastSeen:  f.LastSeen,
			Href:      templates.FindingURL(f.ID),
			Technique: f.Technique,
		}
		if f.Src != "" {
			row.SrcHref = templates.AssetURLByAddress(f.Src)
		}
		if f.Dst != "" {
			row.DstHref = templates.AssetURLByAddress(f.Dst)
		}
		rows = append(rows, row)
	}
	return rows
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	finding, err := s.store.Finding(r.Context(), s.project.ID, id)
	if err != nil {
		s.fail(w, r, "reading a finding", err)
		return
	}
	if finding == nil {
		http.NotFound(w, r)
		return
	}

	page := s.page(r, "findings")
	page.Title = finding.Title
	token, err := s.csrfToken(w, r)
	if err != nil {
		s.fail(w, r, "issuing a CSRF token", err)
		return
	}

	view := templates.FindingView{
		Page:         page,
		Theme:        page.Theme,
		Finding:      *finding,
		CSRF:         token,
		Saved:        r.URL.Query().Get("saved") == "1",
		EventsHref:   templates.EvidenceHref(*finding),
		TechniqueURL: rules.TechniqueURL(finding.Technique),
		Details:      templates.DetailRows(finding.Details),
		Back:         "/findings",
	}
	if finding.Src != "" {
		view.SrcHref = templates.AssetURLByAddress(finding.Src)
	}
	if finding.Dst != "" {
		view.DstHref = templates.AssetURLByAddress(finding.Dst)
	}
	for _, status := range templates.StatusNames() {
		view.Statuses = append(view.Statuses, templates.StatusOption{
			Value:    status,
			Label:    templates.StatusLabel(page.Lang, status),
			Selected: status == string(finding.Status),
		})
	}
	s.render(w, r, templates.FindingPage(view))
}

// handleTriage stores where one finding sits in the workflow.
func (s *Server) handleTriage(w http.ResponseWriter, r *http.Request) {
	if !s.allowWrite(w, r) {
		return
	}
	id := r.PathValue("id")

	status := model.FindingStatus(r.PostFormValue("status"))
	if !status.Valid() {
		http.Error(w, "unknown status", http.StatusBadRequest)
		return
	}
	// The note and the assignee are free text an analyst typed, so they are
	// bounded here and escaped on the way out, like every other value.
	triage := store.Triage{
		Status:   status,
		Assignee: trimTo(r.PostFormValue("assignee"), 64),
		Note:     trimTo(r.PostFormValue("note"), 500),
	}
	if err := s.store.SetTriage(r.Context(), s.project.ID, id, triage); err != nil {
		s.log.Warn("triage failed", "finding", id, "err", err)
		http.Error(w, "no such finding", http.StatusNotFound)
		return
	}
	// The redirect is built from a fixed path and an escaped id, so nothing
	// a request carries can send a browser anywhere but back to this page.
	http.Redirect(w, r, "/findings/"+url.PathEscape(id)+"?saved=1", http.StatusSeeOther)
}

// handleBulkTriage applies one state to the findings that were ticked.
func (s *Server) handleBulkTriage(w http.ResponseWriter, r *http.Request) {
	if !s.allowWrite(w, r) {
		return
	}

	status := model.FindingStatus(r.PostFormValue("status"))
	if !status.Valid() {
		http.Error(w, "unknown status", http.StatusBadRequest)
		return
	}
	ids := r.PostForm["id"]
	if len(ids) > 0 {
		if _, err := s.store.SetTriageMany(r.Context(), s.project.ID, ids,
			store.Triage{Status: status}); err != nil {
			s.fail(w, r, "triaging findings", err)
			return
		}
	}

	// Back to the list the analyst was looking at. Only the query of the
	// posted address is kept and the path is always this view's own, so a
	// return address cannot send a browser somewhere else.
	query := url.Values{}
	if u, err := url.Parse(r.PostFormValue("return")); err == nil && u.Path == "/findings" {
		query = u.Query()
	}
	query.Set("saved", "1")
	//nolint:gosec // G710: the path is this view's own and the query is
	// percent-encoded by Values.Encode, so the target cannot leave this origin
	http.Redirect(w, r, "/findings?"+query.Encode(), http.StatusSeeOther)
}

// allowWrite parses a form and checks that this request may change anything.
func (s *Server) allowWrite(w http.ResponseWriter, r *http.Request) bool {
	if s.readOnly {
		s.log.Warn("refused a write on a read-only server", "path", r.URL.Path, "remote", r.RemoteAddr)
		http.Error(w, "this GUI is read-only", http.StatusForbidden)
		return false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return false
	}
	if err := s.checkCSRF(r); err != nil {
		s.log.Warn("rejected a post", "path", r.URL.Path, "err", err, "remote", r.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func trimTo(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

// handleRules lists the rules this server runs and what each has found.
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	page := s.page(r, "rules")
	page.Title = templates.T(page.Lang, "rules.title")

	engine, err := s.ruleEngine(nil)
	if err != nil {
		s.fail(w, r, "building the rule engine", err)
		return
	}
	counts, err := s.store.CountFindingsBy(r.Context(), s.project.ID, "rule")
	if err != nil {
		s.fail(w, r, "counting findings by rule", err)
		return
	}
	byRule := make(map[string]int64, len(counts))
	for _, bucket := range counts {
		byRule[bucket.Label] = bucket.Count
	}
	token, err := s.csrfToken(w, r)
	if err != nil {
		s.fail(w, r, "issuing a CSRF token", err)
		return
	}

	view := templates.RulesView{
		Page:        page,
		Theme:       page.Theme,
		Rows:        templates.NewRuleRows(engine.Rules(), byRule),
		CSRF:        token,
		ReadOnly:    s.readOnly,
		CustomFiles: s.ruleFiles,
	}
	if n := r.URL.Query().Get("ran"); n != "" {
		view.Reran = templates.T(page.Lang, "findings.saved")
		if count := clampInt(n, -1, 0, 1<<30); count >= 0 {
			view.Reran = fmt.Sprintf("%s %d %s",
				templates.T(page.Lang, "rules.rerun"),
				count, templates.T(page.Lang, "findings.total"))
		}
	}
	s.render(w, r, templates.RulesPage(view))
}

// handleRerunRules runs every rule over the events the project already holds.
//
// It is the one action in this GUI that recomputes anything. It writes
// findings and nothing else: the triage states are the analyst's and are left
// exactly as they were, and no packet is ever sent anywhere.
func (s *Server) handleRerunRules(w http.ResponseWriter, r *http.Request) {
	if !s.allowWrite(w, r) {
		return
	}

	findings, err := s.runRules(r.Context())
	if err != nil {
		s.fail(w, r, "running the rules", err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/rules?ran=%d", len(findings)), http.StatusSeeOther)
}

// ruleEngine builds an engine from the configuration this server was started
// with, which is the same configuration the command line uses.
func (s *Server) ruleEngine(assets []model.Asset) (*rules.Engine, error) {
	cfg := s.rules
	cfg.Assets = assets
	return rules.New(cfg)
}

// runRules streams the project's events through the rules and stores what
// they find.
func (s *Server) runRules(ctx context.Context) ([]model.Finding, error) {
	assets, _, err := s.store.Assets(ctx, store.AssetQuery{
		ProjectID: s.project.ID, Limit: maxRuleAssets,
	})
	if err != nil {
		return nil, err
	}
	engine, err := s.ruleEngine(assets)
	if err != nil {
		return nil, err
	}

	if err := s.store.EachEvent(ctx, s.project.ID, func(e model.Event) error {
		engine.Add(e)
		return nil
	}); err != nil {
		return nil, err
	}

	links, _, err := s.topologyLinks(ctx, templates.TopologyFilter{})
	if err != nil {
		return nil, err
	}
	engine.AddTopology(topology.Build(assets, links, topology.Options{}))

	findings := engine.Findings()
	if err := s.store.SaveFindings(ctx, s.project.ID, findings); err != nil {
		return nil, err
	}
	s.log.Info("rules run from the GUI", "project", s.project.Name, "findings", len(findings))
	return findings, nil
}
