package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/rom/otinv/internal/model"
)

// AssetQuery selects and pages the asset list.
type AssetQuery struct {
	ProjectID int64
	Role      string
	Protocol  string
	// Search matches the label, the inferred vendor and any observed address.
	Search string
	Limit  int
	Offset int

	// Sort names the column to order by, as AssetSortColumns spells it, and
	// Desc the direction. An empty Sort keeps the default, which is the
	// busiest assets first.
	//
	// The ordering belongs here rather than in the handler because the list
	// is paged: sorting a page after it has been read would sort the wrong
	// fifty assets.
	Sort string
	Desc bool
}

// AssetSortColumns maps a sortable column of the asset list to the SQL that
// orders by it. Nothing outside this map can reach a query, which is what
// keeps a column name taken from a URL out of the statement.
//
// Two of the six are not columns of the assets table. The vendor is
// denormalised onto it already; the protocols are not, so they are summarised
// per asset in the same order the list renders them, which keeps what the
// sort does and what the reader sees in step.
var AssetSortColumns = map[string]string{
	"address":   "a.label",
	"role":      "a.role",
	"vendor":    "a.vendor",
	"protocols": protocolSummary,
	"events":    "a.events",
	"seen":      "a.last_seen",
}

// protocolSummary is the sort key for the protocols column, built to match
// what the list view shows. It is an expression rather than a stored column,
// so it appears in the order clause only and the row scan is unchanged.
const protocolSummary = `(SELECT group_concat(p.protocol || ' (' || p.side || ')')
	FROM asset_protocols p WHERE p.asset_pk = a.id)`

// assetOrder renders the ORDER BY clause for a query.
//
// A null vendor sorts last whichever way the column is read, because an
// unknown value is not the smallest one, and the asset key breaks ties so
// that paging is stable: without it two assets with the same event count
// could swap places between pages and one of them would never be seen.
func assetOrder(q AssetQuery) string {
	expr, ok := AssetSortColumns[q.Sort]
	if !ok {
		return "a.events DESC, a.asset_key"
	}
	direction := "ASC"
	if q.Desc {
		direction = "DESC"
	}
	return "(" + expr + " IS NULL), " + expr + " " + direction + ", a.asset_key"
}

// SaveAssets replaces a project's inventory.
//
// Assets are derived from events and recomputed on every ingest, so a full
// replace is both correct and cheaper than merging: there is no state here to
// lose. User overrides will live in their own table and survive this.
func (s *Store) SaveAssets(ctx context.Context, projectID int64, assets []model.Asset) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: saving assets: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The child tables cascade from assets.
	if _, err := tx.ExecContext(ctx, `DELETE FROM assets WHERE project_id = ?`, projectID); err != nil {
		return fmt.Errorf("store: clearing assets: %w", err)
	}

	for _, a := range assets {
		if err := insertAsset(ctx, tx, projectID, a); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: committing assets: %w", err)
	}
	return nil
}

func insertAsset(ctx context.Context, tx *sql.Tx, projectID int64, a model.Asset) error {
	reasons, err := marshalJSON(a.Role.Reasons)
	if err != nil {
		return fmt.Errorf("store: encoding role reasons: %w", err)
	}
	macs, err := marshalJSON(a.MACs)
	if err != nil {
		return fmt.Errorf("store: encoding asset macs: %w", err)
	}
	ips, err := marshalJSON(a.IPs)
	if err != nil {
		return fmt.Errorf("store: encoding asset ips: %w", err)
	}
	vlans, err := marshalJSON(a.VLANs)
	if err != nil {
		return fmt.Errorf("store: encoding asset vlans: %w", err)
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO assets
			(project_id, asset_key, label, is_gateway, role, role_confidence,
			 role_reasons, vendor, macs, ips, vlans, events, first_seen, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		projectID, a.Key, a.Label, a.IsGateway, string(a.Role.Name), a.Role.Confidence,
		reasons, nullString(a.Vendor()), macs, ips, vlans, a.Events,
		a.FirstSeen.UTC().UnixNano(), a.LastSeen.UTC().UnixNano())
	if err != nil {
		return fmt.Errorf("store: inserting asset %s: %w", a.Key, err)
	}
	pk, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("store: inserting asset %s: %w", a.Key, err)
	}

	for _, ad := range a.Addresses {
		var vlan any
		if ad.VLAN != nil {
			vlan = int64(*ad.VLAN)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO asset_addresses (asset_pk, mac, ip, vlan, events, first_seen, last_seen)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			pk, nullString(ad.MAC), nullString(ad.IP), vlan, ad.Events,
			ad.FirstSeen.UTC().UnixNano(), ad.LastSeen.UTC().UnixNano()); err != nil {
			return fmt.Errorf("store: inserting asset address: %w", err)
		}
	}

	for _, at := range a.Attributes {
		evidence, err := marshalJSON(at.Evidence)
		if err != nil {
			return fmt.Errorf("store: encoding attribute evidence: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO asset_attributes (asset_pk, field, value, confidence, source, evidence)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			pk, at.Field, at.Value, at.Confidence, at.Source, evidence); err != nil {
			return fmt.Errorf("store: inserting asset attribute: %w", err)
		}
	}

	for _, pr := range a.Protocols {
		classes, err := marshalJSON(pr.Classes)
		if err != nil {
			return fmt.Errorf("store: encoding protocol classes: %w", err)
		}
		units, err := marshalJSON(pr.UnitIDs)
		if err != nil {
			return fmt.Errorf("store: encoding protocol unit ids: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO asset_protocols
				(asset_pk, protocol, side, events, classes, unit_ids, first_seen, last_seen)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			pk, pr.Protocol, pr.Side, pr.Events, classes, units,
			pr.FirstSeen.UTC().UnixNano(), pr.LastSeen.UTC().UnixNano()); err != nil {
			return fmt.Errorf("store: inserting asset protocol: %w", err)
		}
	}
	return nil
}

// assetFilter builds the shared WHERE clause. Only placeholders are
// concatenated; every value travels as a bound parameter.
func assetFilter(q AssetQuery) (string, []any) {
	where := []string{"a.project_id = ?"}
	args := []any{q.ProjectID}

	if q.Role != "" {
		where = append(where, "a.role = ?")
		args = append(args, q.Role)
	}
	if q.Protocol != "" {
		where = append(where,
			"EXISTS (SELECT 1 FROM asset_protocols p WHERE p.asset_pk = a.id AND p.protocol = ?)")
		args = append(args, q.Protocol)
	}
	if q.Search != "" {
		like := "%" + q.Search + "%"
		where = append(where, `(
			a.label LIKE ?
			OR IFNULL(a.vendor, '') LIKE ?
			OR IFNULL(a.macs, '') LIKE ?
			OR IFNULL(a.ips, '') LIKE ?
			OR EXISTS (
				SELECT 1 FROM asset_addresses ad
				WHERE ad.asset_pk = a.id
				  AND (IFNULL(ad.ip, '') LIKE ? OR IFNULL(ad.mac, '') LIKE ?)
			))`)
		args = append(args, like, like, like, like, like, like)
	}
	return joinAnd(where), args
}

// Assets returns one page of the inventory, busiest asset first, with the
// total number of matches for the pager.
func (s *Store) Assets(ctx context.Context, q AssetQuery) ([]model.Asset, int, error) {
	filter, args := assetFilter(q)

	var total int
	// The concatenated text is the clause assetFilter built from fixed
	// fragments and placeholders; every value travels as a bound parameter.
	//nolint:gosec // G202: no value is ever concatenated into this statement
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM assets a WHERE `+filter, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: counting assets: %w", err)
	}

	limit := q.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	pageArgs := append(append([]any{}, args...), limit, max(q.Offset, 0))

	// The order clause comes from AssetSortColumns, so only SQL this package
	// wrote can appear in it.
	//nolint:gosec // G202: only the filter clause, the order clause and placeholders are concatenated
	rows, err := s.db.QueryContext(ctx,
		`SELECT a.id, a.asset_key, a.label, a.is_gateway, a.role, a.role_confidence,
		        a.role_reasons, a.macs, a.ips, a.vlans, a.events, a.first_seen, a.last_seen
		 FROM assets a WHERE `+filter+`
		 ORDER BY `+assetOrder(q)+`
		 LIMIT ? OFFSET ?`, pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: listing assets: %w", err)
	}

	assets, byPK, err := scanAssets(rows)
	if err != nil {
		return nil, 0, err
	}
	if len(assets) == 0 {
		return nil, total, nil
	}
	if err := s.loadAssetChildren(ctx, byPK); err != nil {
		return nil, 0, err
	}
	return assets, total, nil
}

// Asset returns one asset by its identity key, or nil when the project has no
// such asset.
func (s *Store) Asset(ctx context.Context, projectID int64, key string) (*model.Asset, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT a.id, a.asset_key, a.label, a.is_gateway, a.role, a.role_confidence,
		        a.role_reasons, a.macs, a.ips, a.vlans, a.events, a.first_seen, a.last_seen
		 FROM assets a WHERE a.project_id = ? AND a.asset_key = ?`,
		projectID, key)
	if err != nil {
		return nil, fmt.Errorf("store: reading asset %s: %w", key, err)
	}
	assets, byPK, err := scanAssets(rows)
	if err != nil {
		return nil, err
	}
	if len(assets) == 0 {
		return nil, nil
	}
	if err := s.loadAssetChildren(ctx, byPK); err != nil {
		return nil, err
	}
	return &assets[0], nil
}

// scanAssets reads asset rows and returns them along with a map from row id to
// the asset, so the child tables can be filled in afterwards.
func scanAssets(rows *sql.Rows) ([]model.Asset, map[int64]*model.Asset, error) {
	var assets []model.Asset
	var pks []int64
	for rows.Next() {
		var (
			pk               int64
			a                model.Asset
			role             string
			reasons          []byte
			macs, ips, vlans []byte
			first, last      int64
		)
		if err := rows.Scan(&pk, &a.Key, &a.Label, &a.IsGateway, &role, &a.Role.Confidence,
			&reasons, &macs, &ips, &vlans, &a.Events, &first, &last); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("store: scanning asset: %w", err)
		}
		a.Role.Name = model.RoleName(role)
		a.FirstSeen = time.Unix(0, first).UTC()
		a.LastSeen = time.Unix(0, last).UTC()
		if err := unmarshalJSON(reasons, &a.Role.Reasons); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("store: decoding role reasons: %w", err)
		}
		if err := unmarshalJSON(macs, &a.MACs); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("store: decoding asset macs: %w", err)
		}
		if err := unmarshalJSON(ips, &a.IPs); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("store: decoding asset ips: %w", err)
		}
		if err := unmarshalJSON(vlans, &a.VLANs); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("store: decoding asset vlans: %w", err)
		}
		assets = append(assets, a)
		pks = append(pks, pk)
	}
	if err := closeRows(rows); err != nil {
		return nil, nil, fmt.Errorf("store: scanning assets: %w", err)
	}

	byPK := make(map[int64]*model.Asset, len(assets))
	for i := range assets {
		byPK[pks[i]] = &assets[i]
	}
	return assets, byPK, nil
}

// loadAssetChildren fills in addresses, attributes and protocols for a page of
// assets with one query each, rather than one query per asset.
func (s *Store) loadAssetChildren(ctx context.Context, byPK map[int64]*model.Asset) error {
	pks := make([]any, 0, len(byPK))
	for pk := range byPK {
		pks = append(pks, pk)
	}
	// inPlaceholders returns only "?" separators, so the statements below
	// concatenate placeholders and never a value.
	placeholders := inPlaceholders(len(pks))

	//nolint:gosec // G202: placeholders only
	rows, err := s.db.QueryContext(ctx,
		`SELECT asset_pk, mac, ip, vlan, events, first_seen, last_seen
		 FROM asset_addresses WHERE asset_pk IN (`+placeholders+`) ORDER BY rowid`, pks...)
	if err != nil {
		return fmt.Errorf("store: reading asset addresses: %w", err)
	}
	for rows.Next() {
		var (
			pk          int64
			mac, ip     sql.NullString
			vlan        sql.NullInt64
			ad          model.Address
			first, last int64
		)
		if err := rows.Scan(&pk, &mac, &ip, &vlan, &ad.Events, &first, &last); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: reading asset addresses: %w", err)
		}
		ad.MAC, ad.IP = mac.String, ip.String
		if vlan.Valid {
			ad.VLAN = model.Ptr(uint16(vlan.Int64))
		}
		ad.FirstSeen = time.Unix(0, first).UTC()
		ad.LastSeen = time.Unix(0, last).UTC()
		if a := byPK[pk]; a != nil {
			a.Addresses = append(a.Addresses, ad)
		}
	}
	if err := closeRows(rows); err != nil {
		return fmt.Errorf("store: reading asset addresses: %w", err)
	}

	//nolint:gosec // G202: placeholders only
	rows, err = s.db.QueryContext(ctx,
		`SELECT asset_pk, field, value, confidence, source, evidence
		 FROM asset_attributes WHERE asset_pk IN (`+placeholders+`) ORDER BY rowid`, pks...)
	if err != nil {
		return fmt.Errorf("store: reading asset attributes: %w", err)
	}
	for rows.Next() {
		var (
			pk       int64
			at       model.Attribute
			evidence []byte
		)
		if err := rows.Scan(&pk, &at.Field, &at.Value, &at.Confidence, &at.Source, &evidence); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: reading asset attributes: %w", err)
		}
		if err := unmarshalJSON(evidence, &at.Evidence); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: decoding attribute evidence: %w", err)
		}
		if a := byPK[pk]; a != nil {
			a.Attributes = append(a.Attributes, at)
		}
	}
	if err := closeRows(rows); err != nil {
		return fmt.Errorf("store: reading asset attributes: %w", err)
	}

	//nolint:gosec // G202: placeholders only
	rows, err = s.db.QueryContext(ctx,
		`SELECT asset_pk, protocol, side, events, classes, unit_ids, first_seen, last_seen
		 FROM asset_protocols WHERE asset_pk IN (`+placeholders+`) ORDER BY rowid`, pks...)
	if err != nil {
		return fmt.Errorf("store: reading asset protocols: %w", err)
	}
	for rows.Next() {
		var (
			pk             int64
			pr             model.ProtocolUsage
			classes, units []byte
			first, last    int64
		)
		if err := rows.Scan(&pk, &pr.Protocol, &pr.Side, &pr.Events, &classes, &units,
			&first, &last); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: reading asset protocols: %w", err)
		}
		if err := unmarshalJSON(classes, &pr.Classes); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: decoding protocol classes: %w", err)
		}
		if err := unmarshalJSON(units, &pr.UnitIDs); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: decoding protocol unit ids: %w", err)
		}
		pr.FirstSeen = time.Unix(0, first).UTC()
		pr.LastSeen = time.Unix(0, last).UTC()
		if a := byPK[pk]; a != nil {
			a.Protocols = append(a.Protocols, pr)
		}
	}
	if err := closeRows(rows); err != nil {
		return fmt.Errorf("store: reading asset protocols: %w", err)
	}
	return nil
}

// AssetProtocols lists the protocols present in a project, for the filter
// panel.
func (s *Store) AssetProtocols(ctx context.Context, projectID int64) ([]string, error) {
	return s.distinct(ctx,
		`SELECT DISTINCT p.protocol FROM asset_protocols p
		 JOIN assets a ON a.id = p.asset_pk
		 WHERE a.project_id = ? ORDER BY p.protocol`, projectID)
}

// AssetRoles lists the roles present in a project, for the filter panel.
func (s *Store) AssetRoles(ctx context.Context, projectID int64) ([]string, error) {
	return s.distinct(ctx,
		`SELECT DISTINCT role FROM assets WHERE project_id = ? ORDER BY role`, projectID)
}

func (s *Store) distinct(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: reading facets: %w", err)
	}
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("store: reading facets: %w", err)
		}
		out = append(out, v)
	}
	if err := closeRows(rows); err != nil {
		return nil, fmt.Errorf("store: reading facets: %w", err)
	}
	sort.Strings(out)
	return out, nil
}

// inPlaceholders returns "?, ?, ..." for an IN clause.
func inPlaceholders(n int) string {
	if n == 0 {
		return "NULL"
	}
	b := make([]byte, 0, n*3)
	for i := range n {
		if i > 0 {
			b = append(b, ',', ' ')
		}
		b = append(b, '?')
	}
	return string(b)
}
