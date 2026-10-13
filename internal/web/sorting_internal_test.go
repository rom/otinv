package web

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/model"
	"github.com/rom/otinv/internal/web/templates"
)

func asc(column string) templates.Sort  { return templates.Sort{Column: column} }
func desc(column string) templates.Sort { return templates.Sort{Column: column, Desc: true} }

func TestSortAttributes(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	fixture := func() []model.Attribute {
		return []model.Attribute{
			{Field: "vendor", Value: "Siemens", Confidence: 70, Source: "oui",
				Evidence: model.Evidence{Timestamp: base.Add(2 * time.Minute), PacketIndex: 20}},
			{Field: "model", Value: "IM151", Confidence: 95, Source: "s7comm_szl",
				Evidence: model.Evidence{Timestamp: base, PacketIndex: 3}},
			{Field: "name", Value: "bay01", Confidence: 85, Source: "mms_identify",
				Evidence: model.Evidence{Timestamp: base.Add(time.Minute), PacketIndex: 11}},
		}
	}

	tests := []struct {
		sort templates.Sort
		want []string // the field names, in order
	}{
		{sort: asc("identity.field"), want: []string{"model", "name", "vendor"}},
		{sort: desc("identity.field"), want: []string{"vendor", "name", "model"}},
		{sort: asc("identity.value"), want: []string{"model", "vendor", "name"}},
		{sort: asc("identity.confidence"), want: []string{"vendor", "name", "model"}},
		{sort: desc("identity.confidence"), want: []string{"model", "name", "vendor"}},
		{sort: asc("identity.source"), want: []string{"name", "vendor", "model"}},
		// The evidence cell names a packet and when it arrived, so that is
		// what ordering by it means.
		{sort: asc("identity.evidence"), want: []string{"model", "name", "vendor"}},
		// A column of another table leaves this one in the order it came in.
		{sort: asc("events.time"), want: []string{"vendor", "model", "name"}},
		{sort: templates.Sort{}, want: []string{"vendor", "model", "name"}},
	}

	for _, tc := range tests {
		name := tc.sort.Column + dirSuffix(tc.sort)
		t.Run(name, func(t *testing.T) {
			attrs := fixture()
			sortAttributes(attrs, tc.sort)
			got := make([]string, 0, len(attrs))
			for _, a := range attrs {
				got = append(got, a.Field)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSortAddresses(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	vlan100, vlan20 := uint16(100), uint16(20)
	fixture := func() []model.Address {
		return []model.Address{
			{MAC: "00:0b:ff:00:00:01", IP: "10.0.0.10", VLAN: &vlan100, Events: 5,
				FirstSeen: base.Add(2 * time.Hour)},
			{MAC: "00:0a:ff:00:00:02", IP: "10.0.0.9", Events: 90, FirstSeen: base},
			{MAC: "00:0c:ff:00:00:03", IP: "10.0.0.100", VLAN: &vlan20, Events: 40,
				FirstSeen: base.Add(time.Hour)},
		}
	}

	tests := []struct {
		sort templates.Sort
		want []string // the IPs, in order
	}{
		{sort: asc("addresses.mac"), want: []string{"10.0.0.9", "10.0.0.10", "10.0.0.100"}},
		// An address is a number, not a string: .9 comes before .10, which is
		// not what comparing the text would say.
		{sort: asc("addresses.ip"), want: []string{"10.0.0.9", "10.0.0.10", "10.0.0.100"}},
		{sort: desc("addresses.ip"), want: []string{"10.0.0.100", "10.0.0.10", "10.0.0.9"}},
		// Untagged sorts last either way: no VLAN is not VLAN zero.
		{sort: asc("addresses.vlan"), want: []string{"10.0.0.100", "10.0.0.10", "10.0.0.9"}},
		{sort: desc("addresses.vlan"), want: []string{"10.0.0.10", "10.0.0.100", "10.0.0.9"}},
		{sort: asc("addresses.events"), want: []string{"10.0.0.10", "10.0.0.100", "10.0.0.9"}},
		{sort: asc("addresses.time"), want: []string{"10.0.0.9", "10.0.0.100", "10.0.0.10"}},
		{sort: asc("protocols.protocol"), want: []string{"10.0.0.10", "10.0.0.9", "10.0.0.100"}},
	}

	for _, tc := range tests {
		t.Run(tc.sort.Column+dirSuffix(tc.sort), func(t *testing.T) {
			addrs := fixture()
			sortAddresses(addrs, tc.sort)
			got := make([]string, 0, len(addrs))
			for _, a := range addrs {
				got = append(got, a.IP)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSortProtocols(t *testing.T) {
	fixture := func() []model.ProtocolUsage {
		return []model.ProtocolUsage{
			{Protocol: "s7comm", Side: "server", Events: 10,
				Classes: map[model.Classification]uint64{model.ClassRead: 10},
				UnitIDs: []uint16{7}},
			{Protocol: "modbus", Side: "client", Events: 90,
				Classes: map[model.Classification]uint64{model.ClassProgram: 1}},
			{Protocol: "goose", Side: "server", Events: 40,
				Classes: map[model.Classification]uint64{model.ClassWrite: 4},
				UnitIDs: []uint16{3}},
		}
	}

	tests := []struct {
		sort templates.Sort
		want []string
	}{
		{sort: asc("protocols.protocol"), want: []string{"goose", "modbus", "s7comm"}},
		{sort: asc("protocols.side"), want: []string{"modbus", "s7comm", "goose"}},
		{sort: asc("protocols.events"), want: []string{"s7comm", "goose", "modbus"}},
		// Ordering by the class column brings the devices being programmed to
		// one end, which is the reason to sort by it at all.
		{sort: desc("protocols.class"), want: []string{"modbus", "goose", "s7comm"}},
		// A protocol with no unit ids sorts last.
		{sort: asc("protocols.unit"), want: []string{"goose", "s7comm", "modbus"}},
	}

	for _, tc := range tests {
		t.Run(tc.sort.Column+dirSuffix(tc.sort), func(t *testing.T) {
			usage := fixture()
			sortProtocols(usage, tc.sort)
			got := make([]string, 0, len(usage))
			for _, u := range usage {
				got = append(got, u.Protocol)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSortEvents(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	fixture := func() []templates.EventRow {
		return []templates.EventRow{
			{Operation: "write", Time: base.Add(2 * time.Second), Class: "write",
				Peer: "10.0.0.100", Unit: "10", Packet: 20},
			{Operation: "ReadCoils", Time: base, Class: "read",
				Peer: "10.0.0.9", Unit: "—", Packet: 3},
			{Operation: "stop", Time: base.Add(time.Second), Class: "control",
				Peer: "10.0.0.10", Unit: "2", Packet: 11},
		}
	}

	tests := []struct {
		sort templates.Sort
		want []string
	}{
		{sort: asc("events.time"), want: []string{"ReadCoils", "stop", "write"}},
		{sort: desc("events.time"), want: []string{"write", "stop", "ReadCoils"}},
		{sort: asc("events.operation"), want: []string{"ReadCoils", "stop", "write"}},
		{sort: asc("events.class"), want: []string{"stop", "ReadCoils", "write"}},
		{sort: asc("events.peer"), want: []string{"ReadCoils", "stop", "write"}},
		// The em dash stands for no unit at all, so it sorts last.
		{sort: asc("events.unit"), want: []string{"stop", "write", "ReadCoils"}},
		{sort: asc("events.packet"), want: []string{"ReadCoils", "stop", "write"}},
	}

	for _, tc := range tests {
		t.Run(tc.sort.Column+dirSuffix(tc.sort), func(t *testing.T) {
			rows := fixture()
			sortEvents(rows, tc.sort)
			got := make([]string, 0, len(rows))
			for _, r := range rows {
				got = append(got, r.Operation)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSortCaptures(t *testing.T) {
	base := time.Unix(1700000000, 0).UTC()
	fixture := func() []templates.CaptureRow {
		return []templates.CaptureRow{
			{Path: "b.pcap", SHA256: "ccc", Packets: 10, FirstSeen: base.Add(time.Hour)},
			{Path: "a.pcap", SHA256: "bbb", Packets: 90, FirstSeen: base},
			{Path: "c.pcap", SHA256: "aaa", Packets: 40, FirstSeen: base.Add(2 * time.Hour)},
		}
	}

	tests := []struct {
		sort templates.Sort
		want []string
	}{
		{sort: asc("path"), want: []string{"a.pcap", "b.pcap", "c.pcap"}},
		{sort: asc("digest"), want: []string{"c.pcap", "a.pcap", "b.pcap"}},
		{sort: desc("packets"), want: []string{"a.pcap", "c.pcap", "b.pcap"}},
		{sort: asc("range"), want: []string{"a.pcap", "b.pcap", "c.pcap"}},
		{sort: templates.Sort{}, want: []string{"b.pcap", "a.pcap", "c.pcap"}},
	}

	for _, tc := range tests {
		t.Run(tc.sort.Column+dirSuffix(tc.sort), func(t *testing.T) {
			rows := fixture()
			sortCaptures(rows, tc.sort)
			got := make([]string, 0, len(rows))
			for _, r := range rows {
				got = append(got, r.Path)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

// Sorting is stable, so the rows a column cannot tell apart keep the order
// they arrived in rather than shuffling on every request.
func TestSortingIsStable(t *testing.T) {
	rows := []templates.CaptureRow{
		{Path: "first.pcap", Packets: 5},
		{Path: "second.pcap", Packets: 5},
		{Path: "third.pcap", Packets: 5},
	}
	sortCaptures(rows, asc("packets"))
	require.Len(t, rows, 3)
	assert.Equal(t, "first.pcap", rows[0].Path)
	assert.Equal(t, "second.pcap", rows[1].Path)
	assert.Equal(t, "third.pcap", rows[2].Path)
}

func TestParseSort(t *testing.T) {
	assert.Equal(t, templates.Sort{}, parseSort("", ""))
	assert.Equal(t, templates.Sort{Column: "events"}, parseSort("events", ""))
	assert.Equal(t, templates.Sort{Column: "events"}, parseSort("events", "asc"))
	assert.Equal(t, templates.Sort{Column: "events"}, parseSort("events", "nonsense"))
	assert.Equal(t, templates.Sort{Column: "events", Desc: true}, parseSort("events", "desc"))
}

func dirSuffix(s templates.Sort) string {
	if s.Desc {
		return "/desc"
	}
	return "/asc"
}
