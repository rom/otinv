package web

import (
	"sort"
	"strings"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/web/templates"
)

// Sorting of the tables that are read whole rather than paged.
//
// The asset list is paged in the store, so its order has to be decided in SQL
// or a sorted page would hold the wrong fifty assets. These tables are a
// single asset's own, or the project's handful of captures, so they are read
// in full and ordered here. Each leaves the slice as it is when the column is
// not one of its own, which is what keeps one table's sort from disturbing
// another's on a page that shares the state.

// parseSort reads the sort state out of a query string.
func parseSort(column, direction string) templates.Sort {
	return templates.Sort{Column: column, Desc: direction == "desc"}
}

// comparison is how one column is ordered: whether a row has nothing to
// compare, and how two rows that do compare.
type comparison struct {
	// missing reports that a row's value in this column is absent — no VLAN
	// tag, no unit id, no address. Nil when the column is always present.
	missing func(i int) bool
	less    func(i, j int) bool
}

// orderBy sorts rows by a comparison, reversing it for a descending sort.
//
// A row with nothing to compare stays at the end whichever way the column is
// read, because a missing value is neither the smallest nor the largest one:
// reversing the whole comparison would promote the untagged addresses to the
// top of a descending VLAN sort, where they say nothing.
//
// The sort is stable, so rows a column cannot tell apart keep the order they
// arrived in rather than shuffling between requests.
func orderBy[T any](rows []T, desc bool, c comparison) {
	missing := c.missing
	if missing == nil {
		missing = func(int) bool { return false }
	}
	sort.SliceStable(rows, func(i, j int) bool {
		mi, mj := missing(i), missing(j)
		if mi != mj {
			// A row that has a value comes before one that does not.
			return mj
		}
		if mi {
			return false
		}
		if desc {
			return c.less(j, i)
		}
		return c.less(i, j)
	})
}

// sortAttributes orders the inferred identity table.
func sortAttributes(attrs []model.Attribute, s templates.Sort) {
	var c comparison
	switch s.Column {
	case "identity.field":
		c.less = func(i, j int) bool { return attrs[i].Field < attrs[j].Field }
	case "identity.value":
		c.less = func(i, j int) bool { return attrs[i].Value < attrs[j].Value }
	case "identity.confidence":
		c.less = func(i, j int) bool { return attrs[i].Confidence < attrs[j].Confidence }
	case "identity.source":
		c.less = func(i, j int) bool { return attrs[i].Source < attrs[j].Source }
	case "identity.evidence":
		// The evidence cell names a packet and the moment it arrived, so the
		// order a reader means by it is the order the evidence was captured.
		c.less = func(i, j int) bool {
			if !attrs[i].Evidence.Timestamp.Equal(attrs[j].Evidence.Timestamp) {
				return attrs[i].Evidence.Timestamp.Before(attrs[j].Evidence.Timestamp)
			}
			return attrs[i].Evidence.PacketIndex < attrs[j].Evidence.PacketIndex
		}
	default:
		return
	}
	orderBy(attrs, s.Desc, c)
}

// sortAddresses orders the observed address table.
func sortAddresses(addrs []model.Address, s templates.Sort) {
	var c comparison
	switch s.Column {
	case "addresses.mac":
		c.missing = func(i int) bool { return addrs[i].MAC == "" }
		c.less = func(i, j int) bool { return addrs[i].MAC < addrs[j].MAC }
	case "addresses.ip":
		c.missing = func(i int) bool { return addrs[i].IP == "" }
		c.less = func(i, j int) bool { return lessIP(addrs[i].IP, addrs[j].IP) }
	case "addresses.vlan":
		c.missing = func(i int) bool { return addrs[i].VLAN == nil }
		c.less = func(i, j int) bool { return *addrs[i].VLAN < *addrs[j].VLAN }
	case "addresses.events":
		c.less = func(i, j int) bool { return addrs[i].Events < addrs[j].Events }
	case "addresses.time":
		c.less = func(i, j int) bool { return addrs[i].FirstSeen.Before(addrs[j].FirstSeen) }
	default:
		return
	}
	orderBy(addrs, s.Desc, c)
}

// sortProtocols orders the protocol usage table.
func sortProtocols(usage []model.ProtocolUsage, s templates.Sort) {
	var c comparison
	switch s.Column {
	case "protocols.protocol":
		c.less = func(i, j int) bool { return usage[i].Protocol < usage[j].Protocol }
	case "protocols.side":
		c.less = func(i, j int) bool { return usage[i].Side < usage[j].Side }
	case "protocols.events":
		c.less = func(i, j int) bool { return usage[i].Events < usage[j].Events }
	case "protocols.class":
		c.less = func(i, j int) bool { return classWeight(usage[i]) < classWeight(usage[j]) }
	case "protocols.unit":
		c.missing = func(i int) bool { return len(usage[i].UnitIDs) == 0 }
		c.less = func(i, j int) bool { return usage[i].UnitIDs[0] < usage[j].UnitIDs[0] }
	default:
		return
	}
	orderBy(usage, s.Desc, c)
}

// sortEvents orders an asset's event table.
func sortEvents(rows []templates.EventRow, s templates.Sort) {
	var c comparison
	switch s.Column {
	case "events.time":
		c.less = func(i, j int) bool {
			if !rows[i].Time.Equal(rows[j].Time) {
				return rows[i].Time.Before(rows[j].Time)
			}
			return rows[i].Packet < rows[j].Packet
		}
	case "events.operation":
		c.less = func(i, j int) bool { return rows[i].Operation < rows[j].Operation }
	case "events.class":
		c.less = func(i, j int) bool { return rows[i].Class < rows[j].Class }
	case "events.peer":
		c.missing = func(i int) bool { return rows[i].Peer == "" }
		c.less = func(i, j int) bool { return lessIP(rows[i].Peer, rows[j].Peer) }
	case "events.unit":
		// The cell holds a unit id as text, or an em dash for no unit at all.
		c.missing = func(i int) bool { return numericText(rows[i].Unit) < 0 }
		c.less = func(i, j int) bool { return numericText(rows[i].Unit) < numericText(rows[j].Unit) }
	case "events.packet":
		c.less = func(i, j int) bool { return rows[i].Packet < rows[j].Packet }
	default:
		return
	}
	orderBy(rows, s.Desc, c)
}

// sortCaptures orders the capture list.
func sortCaptures(rows []templates.CaptureRow, s templates.Sort) {
	var c comparison
	switch s.Column {
	case "path":
		c.less = func(i, j int) bool { return rows[i].Path < rows[j].Path }
	case "digest":
		c.less = func(i, j int) bool { return rows[i].SHA256 < rows[j].SHA256 }
	case "packets":
		c.less = func(i, j int) bool { return rows[i].Packets < rows[j].Packets }
	case "range":
		c.less = func(i, j int) bool { return rows[i].FirstSeen.Before(rows[j].FirstSeen) }
	default:
		return
	}
	orderBy(rows, s.Desc, c)
}

// classWeight ranks a protocol usage by the most consequential class it was
// seen doing, so that ordering by the class column brings the devices being
// programmed and controlled to one end.
func classWeight(u model.ProtocolUsage) int {
	order := []model.Classification{
		model.ClassOther, model.ClassDiscovery, model.ClassDiagnostic,
		model.ClassRead, model.ClassWrite, model.ClassControl,
		model.ClassProgram, model.ClassFirmware,
	}
	weight := 0
	for i, c := range order {
		if u.Classes[c] > 0 {
			weight = i
		}
	}
	return weight
}

// lessIP compares two addresses as addresses: 10.0.0.9 comes before
// 10.0.0.10, which is not what comparing the text would say.
func lessIP(a, b string) bool {
	ap, bp := strings.Split(a, "."), strings.Split(b, ".")
	if len(ap) != 4 || len(bp) != 4 {
		// Not a dotted quad — a MAC address, or a name — so compare it as the
		// text it is.
		return a < b
	}
	for i := range ap {
		x, y := numericText(ap[i]), numericText(bp[i])
		if x != y {
			return x < y
		}
	}
	return false
}

// numericText reads a cell that holds a number, and returns -1 for anything
// that is not one, including the em dash that stands for "none".
func numericText(s string) int {
	if s == "" {
		return -1
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return -1
		}
	}
	return n
}
