package oui

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"colons", "00:1b:1b:0a:0b:0c", "001b1b0a0b0c"},
		{"hyphens and upper case", "00-1B-1B-0A-0B-0C", "001b1b0a0b0c"},
		{"cisco dotted quads", "001b.1b0a.0b0c", "001b1b0a0b0c"},
		{"bare hex", "001B1B0A0B0C", "001b1b0a0b0c"},
		{"spaced", "00 1b 1b 0a 0b 0c", "001b1b0a0b0c"},
		{"underscores", "001b_1b0a_0b0c", "001b1b0a0b0c"},
		{"a 24-bit block on its own", "00:1b:1b", "001b1b"},
		{"a 36-bit block on its own", "00:50:c2:00:0", "0050c2000"},
		{"an encapsulated MAC-48 comes back out of an EUI-64", "00:1b:1b:ff:fe:0a:0b:0c", "001b1b0a0b0c"},
		{"a native EUI-64 keeps its leading six octets", "00:1b:1b:0a:0b:0c:0d:0e", "001b1b0a0b0c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Normalize(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNormalizeRejects(t *testing.T) {
	cases := []struct {
		name string
		in   string
		msg  string
	}{
		{"empty", "", "too short"},
		{"two octets", "00:1b", "too short"},
		{"seven octets", "00:1b:1b:0a:0b:0c:0d", "too long"},
		{"not hex", "00:1b:1b:0a:0b:zz", "neither a hex digit nor a separator"},
		{"a host name", "plc1.example.org", "neither a hex digit nor a separator"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Normalize(tc.in)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.msg)
		})
	}
}

func TestLookup(t *testing.T) {
	cases := []struct {
		name    string
		mac     string
		want    Vendor
		wantOK  bool
		explain string
	}{{
		name:    "a 24-bit assignment names the card's maker",
		mac:     "00:1b:1b:0a:0b:0c",
		want:    Vendor{Name: "Siemens AG", Prefix: "00:1b:1b", Bits: 24},
		wantOK:  true,
		explain: "Siemens AG, from the block 00:1b:1b/24",
	}, {
		name:   "another, to show the table is not one entry deep",
		mac:    "00:1d:9c:ff:00:01",
		want:   Vendor{Name: "Rockwell Automation", Prefix: "00:1d:9c", Bits: 24},
		wantOK: true,
	}, {
		// 00-50-C2 is a block the IEEE divides into 36-bit assignments, so
		// the long match has to win: the 24-bit holder is the IEEE itself.
		name:    "a 36-bit assignment wins over the shared block it sits in",
		mac:     "00:50:c2:00:0a:bb",
		want:    Vendor{Name: "T.L.S. Corp.", Prefix: "00:50:c2:00:0", Bits: 36},
		wantOK:  true,
		explain: "T.L.S. Corp., from the block 00:50:c2:00:0/36",
	}, {
		name:   "and in the other shared block",
		mac:    "40:d8:55:0d:7f:ff",
		want:   Vendor{Name: "Avant Technologies", Prefix: "40:d8:55:0d:7", Bits: 36},
		wantOK: true,
	}, {
		name:    "a shared block asked about on its own names nobody",
		mac:     "00:50:c2",
		want:    Vendor{Prefix: "00:50:c2", Bits: 24, Shared: true},
		wantOK:  false,
		explain: "00:50:c2/24 is a shared IEEE block",
	}, {
		name:    "a block whose holder is not published",
		mac:     "00:00:6c:11:22:33",
		want:    Vendor{Prefix: "00:00:6c", Bits: 24, Withheld: true},
		wantOK:  false,
		explain: "asked the IEEE not to publish",
	}, {
		// What a container runtime or a hypervisor makes up for itself.
		name:    "a locally administered address has no maker",
		mac:     "02:42:ac:11:00:02",
		want:    Vendor{Local: true},
		wantOK:  false,
		explain: "locally administered",
	}, {
		// AA-00-04 is DECnet, registered before the U/L bit meant what it
		// means now: the entry exists, but the address was still built from
		// a node number rather than handed out with a card.
		name:    "a locally administered address that a legacy entry covers",
		mac:     "aa:00:04:00:01:02",
		want:    Vendor{Name: "DIGITAL EQUIPMENT CORPORATION", Prefix: "aa:00:04", Bits: 24, Local: true},
		wantOK:  false,
		explain: "locally administered",
	}, {
		// Where GOOSE publishes. It is a subscription, not a device.
		name:    "a multicast group address",
		mac:     "01:0c:cd:01:00:00",
		want:    Vendor{Group: true},
		wantOK:  false,
		explain: "a group address",
	}, {
		name:   "broadcast",
		mac:    "ff:ff:ff:ff:ff:ff",
		want:   Vendor{Local: true, Group: true},
		wantOK: false,
	}, {
		name:    "an unassigned block",
		mac:     "fc:ff:ff:00:00:01",
		want:    Vendor{},
		wantOK:  false,
		explain: "no entry in the IEEE register",
	}, {
		name:   "not an address at all",
		mac:    "plc1",
		want:   Vendor{},
		wantOK: false,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Lookup(tc.mac)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.want.Name != "", got.Known())
			if tc.explain != "" {
				assert.Contains(t, got.Explain(), tc.explain)
			}
			assert.NotEmpty(t, got.Explain(), "every outcome explains itself")
		})
	}
}

// TestLookupSharedBlockGap covers an address inside a block the IEEE
// subdivides, in a range it has not assigned in this build's register. The
// holder of the 24-bit block is the IEEE, which never made a network card,
// so the lookup must report a shared block rather than naming it.
func TestLookupSharedBlockGap(t *testing.T) {
	load()
	require.NoError(t, loadErr)

	var parents []string
	for prefix, org := range bits24 {
		if org == sharedHolder {
			parents = append(parents, prefix)
		}
	}
	require.NotEmpty(t, parents, "the register should list shared blocks")

	var gap string
	for _, parent := range parents {
		for i := range 0x1000 {
			candidate := fmt.Sprintf("%s%03x", parent, i)
			if _, assigned := bits36[candidate]; !assigned {
				gap = candidate
				break
			}
		}
		if gap != "" {
			break
		}
	}
	require.NotEmpty(t, gap, "every shared block is fully assigned, which cannot be")

	got, ok := Lookup(gap + "000")
	assert.False(t, ok)
	assert.Empty(t, got.Name)
	assert.True(t, got.Shared)
	assert.Equal(t, 24, got.Bits)
	assert.Equal(t, Format(gap[:6]), got.Prefix)
}

func TestLookupIgnoresNotation(t *testing.T) {
	want, ok := Lookup("00:1b:1b:0a:0b:0c")
	require.True(t, ok)

	for _, form := range []string{
		"00-1B-1B-0A-0B-0C",
		"001b.1b0a.0b0c",
		"001B1B0A0B0C",
		"00 1b 1b 0a 0b 0c",
		"00:1b:1b:ff:fe:0a:0b:0c", // the same block, as an EUI-64
	} {
		got, ok := Lookup(form)
		assert.True(t, ok, form)
		assert.Equal(t, want, got, form)
	}
}

// TestSize guards the embedded table: a build that lost it, or truncated it,
// has to fail a test rather than quietly stop naming anything.
func TestSize(t *testing.T) {
	bits24Count, bits36Count, err := Size()
	require.NoError(t, err)
	assert.Greater(t, bits24Count, 30000, "the 24-bit register holds tens of thousands of blocks")
	assert.Greater(t, bits36Count, 4000, "the 36-bit register holds thousands of blocks")
}

// TestTableWellFormed checks what the generator promised: prefixes are hex,
// of one of two lengths, and every one of them has a holder.
func TestTableWellFormed(t *testing.T) {
	load()
	require.NoError(t, loadErr)

	for prefix, org := range bits24 {
		requireHexPrefix(t, prefix, 6, org)
	}
	for prefix, org := range bits36 {
		requireHexPrefix(t, prefix, 9, org)
		if _, ok := bits24[prefix[:6]]; !ok {
			t.Fatalf("the 36-bit block %q sits in no 24-bit block", prefix)
		}
	}
}

func requireHexPrefix(t *testing.T, prefix string, length int, org string) {
	t.Helper()
	if len(prefix) != length {
		t.Fatalf("prefix %q is %d hex digits, want %d", prefix, len(prefix), length)
	}
	if strings.ToLower(prefix) != prefix {
		t.Fatalf("prefix %q is not lower case", prefix)
	}
	if _, err := hex.DecodeString(prefix + strings.Repeat("0", len(prefix)%2)); err != nil {
		t.Fatalf("prefix %q is not hex: %v", prefix, err)
	}
	if strings.TrimSpace(org) != org || org == "" {
		t.Fatalf("prefix %q has holder %q, which is empty or padded", prefix, org)
	}
}

// FuzzLookup feeds the parser whatever a user, a report column or a pasted
// table might hold. Nothing here comes off the wire, but the rule in
// CLAUDE.md — a parser never panics — is the same.
func FuzzLookup(f *testing.F) {
	for _, seed := range []string{
		"00:1b:1b:0a:0b:0c", "001b1b", "00-50-C2-00-0A-BB", "001b.1b0a.0b0c",
		"02:42:ac:11:00:02", "ff:ff:ff:ff:ff:ff", "", "::::::", "0x001b1b",
		"00:1b:1b:ff:fe:0a:0b:0c", "plc1.example.org",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		digits, err := Normalize(in)
		v, ok := Lookup(in)
		if err != nil {
			if ok || v != (Vendor{}) {
				t.Fatalf("Lookup(%q) answered %+v for an address that does not parse", in, v)
			}
			return
		}
		if n := len(digits); n < 6 || n > 12 {
			t.Fatalf("Normalize(%q) returned %d hex digits", in, n)
		}
		if _, err := hex.DecodeString(digits + strings.Repeat("0", len(digits)%2)); err != nil {
			t.Fatalf("Normalize(%q) returned %q, which is not hex", in, digits)
		}
		if ok != (v.Name != "" && !v.Local && !v.Group) {
			t.Fatalf("Lookup(%q) reported ok=%v for %+v", in, ok, v)
		}
		if v.Name != "" && v.Prefix == "" {
			t.Fatalf("Lookup(%q) named %q without the block it came from", in, v.Name)
		}
		if v.Explain() == "" {
			t.Fatalf("Lookup(%q) gave %+v, which explains nothing", in, v)
		}
	})
}
