package main

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A short stand-in for oui.txt, in the registry's own layout: the assignment
// twice, once in each notation, then the holder's address.
const ouiSample = `OUI/MA-L                                                    Organization
company_id                                                  Organization
                                                            Address

00-1B-1B   (hex)		Siemens AG
001B1B     (base 16)		Siemens AG
				Gleiwitzer Str. 555
				Nuernberg  90475
				DE

08-00-30   (hex)		NETWORK RESEARCH CORPORATION
080030     (base 16)		NETWORK RESEARCH CORPORATION
				2380 NORTH ROSE AVENUE
				OXNARD  CA  93010
				US

08-00-30   (hex)		CERN
080030     (base 16)		CERN
				CH-1211 GENEVE
				SWITZERLAND  CH-1211
				CH

00-50-C2   (hex)		IEEE Registration Authority
0050C2     (base 16)		IEEE Registration Authority
				445 Hoes Lane
				Piscataway  NJ  08554
				US

AC-DE-48   (hex)		Private

FF-FF-00   (hex)		Padded   Name,
FFFF00     (base 16)		Padded   Name,
`

const iabSample = `IAB                                                             Organization
company_id                                                      Organization
                                                                Address

00-50-C2   (hex)		T.L.S. Corp.
000000-000FFF     (base 16)		T.L.S. Corp.
				6815 Shiloh Road East
				Alpharetta  GA  30005
				US

40-D8-55   (hex)		Avant Technologies
0D7000-0D7FFF     (base 16)		Avant Technologies
				Cambridge  MA  02142
				US
`

func TestBuild(t *testing.T) {
	dir := t.TempDir()
	ouiPath := filepath.Join(dir, "oui.txt")
	iabPath := filepath.Join(dir, "iab.txt")
	require.NoError(t, os.WriteFile(ouiPath, []byte(ouiSample), 0o600))
	require.NoError(t, os.WriteFile(iabPath, []byte(iabSample), 0o600))

	entries, notes, err := build(ouiPath, iabPath)
	require.NoError(t, err)

	got := map[string]entry{}
	for _, e := range entries {
		require.NotContains(t, got, e.prefix, "a prefix is listed once")
		got[e.prefix] = e
	}

	assert.Equal(t, entry{prefix: "001b1b", bits: 24, org: "Siemens AG"}, got["001b1b"])
	assert.Equal(t, entry{prefix: "0050c2", bits: 24, org: "IEEE Registration Authority"}, got["0050c2"])
	assert.Equal(t, entry{prefix: "acde48", bits: 24, org: "Private"}, got["acde48"])

	// The range in an IAB line is the low 12 bits, so the assignment is the
	// OUI plus the first three digits of the range.
	assert.Equal(t, entry{prefix: "0050c2000", bits: 36, org: "T.L.S. Corp."}, got["0050c2000"])
	assert.Equal(t, entry{prefix: "40d8550d7", bits: 36, org: "Avant Technologies"}, got["40d8550d7"])

	// A prefix with two holders keeps both, in the registry's order.
	assert.Equal(t, "NETWORK RESEARCH CORPORATION / CERN", got["080030"].org)

	// The registry pads with tabs and a few holders left a trailing comma.
	assert.Equal(t, "Padded Name", got["ffff00"].org)

	// Entries come out sorted by prefix length and then by prefix, so the
	// generated file is the same for the same input.
	assert.True(t, isSorted(entries), "entries are sorted: %v", entries)

	require.Len(t, notes, 2)
	assert.Equal(t, "oui.txt", notes[0].path)
	assert.Equal(t, 6, notes[0].entries, "the holder lines, before duplicates are merged")
	assert.Len(t, notes[0].sha256, 64)
	assert.Equal(t, "iab.txt", notes[1].path)
	assert.Equal(t, 2, notes[1].entries)
}

func TestBuildWithoutIAB(t *testing.T) {
	dir := t.TempDir()
	ouiPath := filepath.Join(dir, "oui.txt")
	require.NoError(t, os.WriteFile(ouiPath, []byte(ouiSample), 0o600))

	entries, notes, err := build(ouiPath, "")
	require.NoError(t, err)
	require.Len(t, notes, 1)
	for _, e := range entries {
		assert.Equal(t, 24, e.bits)
	}
}

func TestBuildRejectsSomethingElse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oui.txt")
	require.NoError(t, os.WriteFile(path, []byte("this is not the IEEE registry\n"), 0o600))

	_, _, err := build(path, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "holds no assignments")

	_, _, err = build(filepath.Join(dir, "absent.txt"), "")
	require.Error(t, err)
}

func TestWrite(t *testing.T) {
	entries := []entry{
		{prefix: "001b1b", bits: 24, org: "Siemens AG"},
		{prefix: "0050c2000", bits: 36, org: "T.L.S. Corp."},
	}
	notes := []sourceNote{{path: "oui.txt", entries: 2, sha256: strings.Repeat("a", 64)}}

	dir := t.TempDir()
	require.NoError(t, write(dir, entries, notes, "a test"))

	f, err := os.Open(filepath.Join(dir, tableFile))
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	require.NoError(t, err)
	body, err := io.ReadAll(zr)
	require.NoError(t, err)
	assert.Equal(t, "001b1b\tSiemens AG\n0050c2000\tT.L.S. Corp.\n", string(body))

	provenance, err := os.ReadFile(filepath.Join(dir, "PROVENANCE.md"))
	require.NoError(t, err)
	text := string(provenance)
	assert.Contains(t, text, "a test")
	assert.Contains(t, text, "| 24-bit assignments (MA-L) | 1 |")
	assert.Contains(t, text, "| 36-bit assignments (IAB) | 1 |")
	assert.Contains(t, text, strings.Repeat("a", 64))
	assert.NotContains(t, text, "lines repeat a prefix", "nothing was merged here")
}

func TestCleanOrg(t *testing.T) {
	cases := map[string]string{
		"\t\tSiemens AG\t\t":   "Siemens AG",
		"A & B  Co.,":          "A & B Co.",
		"Name\x07with\x00junk": "Name with junk",
		"Ltd.":                 "Ltd.",
		"":                     "",
		"   ":                  "",
	}
	for in, want := range cases {
		assert.Equal(t, want, cleanOrg(in), "cleanOrg(%q)", in)
	}
}

func isSorted(entries []entry) bool {
	for i := 1; i < len(entries); i++ {
		switch {
		case entries[i-1].bits > entries[i].bits:
			return false
		case entries[i-1].bits == entries[i].bits && entries[i-1].prefix >= entries[i].prefix:
			return false
		}
	}
	return true
}
