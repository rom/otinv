// Command ouigen builds the embedded MAC vendor table from the IEEE registry.
//
// It is not part of the otinv binary and never runs at build time: the table
// it writes is committed, so a build — and an air-gapped laptop — needs
// nothing but the Go toolchain. Run it when the registry is worth refreshing:
//
//	make oui OUI_DIR=/path/to/ieee
//
// The registry files are IEEE's own, published at
// https://standards-oui.ieee.org/ (oui.txt, the 24-bit MA-L assignments, and
// iab.txt, the 36-bit IAB assignments under the IEEE's shared blocks).
package main

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func main() {
	var (
		ouiPath = flag.String("oui", "", "IEEE oui.txt (the 24-bit MA-L registry)")
		iabPath = flag.String("iab", "", "IEEE iab.txt (the 36-bit IAB registry)")
		outDir  = flag.String("out", "internal/oui", "directory to write the table into")
		source  = flag.String("source", "https://standards-oui.ieee.org/",
			"where the registry files came from, for the provenance note")
	)
	flag.Parse()

	if *ouiPath == "" {
		fmt.Fprintln(os.Stderr, "ouigen: -oui is required; see the Makefile's oui target")
		os.Exit(2)
	}

	entries, notes, err := build(*ouiPath, *iabPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ouigen:", err)
		os.Exit(1)
	}
	if err := write(*outDir, entries, notes, *source); err != nil {
		fmt.Fprintln(os.Stderr, "ouigen:", err)
		os.Exit(1)
	}
}

// entry is one assignment: a prefix in hex, its length in bits, and who holds
// it.
type entry struct {
	prefix string // lower-case hex, 6 characters for 24 bits, 9 for 36
	bits   int
	org    string
}

// sourceNote records what one input file contributed.
type sourceNote struct {
	path    string
	entries int
	sha256  string
}

func build(ouiPath, iabPath string) ([]entry, []sourceNote, error) {
	var (
		out   []entry
		notes []sourceNote
	)

	ouiEntries, note, err := parseOUI(ouiPath)
	if err != nil {
		return nil, nil, err
	}
	out = append(out, ouiEntries...)
	notes = append(notes, note)

	if iabPath != "" {
		iabEntries, note, err := parseIAB(iabPath)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, iabEntries...)
		notes = append(notes, note)
	}

	out = merge(out)
	sort.Slice(out, func(i, j int) bool {
		if out[i].bits != out[j].bits {
			return out[i].bits < out[j].bits
		}
		return out[i].prefix < out[j].prefix
	})
	return out, notes, nil
}

// merge collapses the handful of prefixes the registry lists more than once.
//
// A few of the oldest OUIs were shared, and some holders have been renamed
// without the old line being withdrawn: 08-00-30 is listed for Network
// Research Corporation, the Royal Melbourne Institute of Technology and CERN
// all three. Dropping any of them would make the answer depend on the order
// the file happened to be read in, so the names are kept together, in the
// order the registry lists them, and the lookup reports all of them.
func merge(in []entry) []entry {
	type key struct {
		prefix string
		bits   int
	}
	at := map[key]int{}
	out := make([]entry, 0, len(in))
	for _, e := range in {
		k := key{e.prefix, e.bits}
		i, seen := at[k]
		if !seen {
			at[k] = len(out)
			out = append(out, e)
			continue
		}
		for _, name := range strings.Split(out[i].org, orgSeparator) {
			if strings.EqualFold(name, e.org) {
				e.org = ""
				break
			}
		}
		if e.org != "" {
			out[i].org += orgSeparator + e.org
		}
	}
	return out
}

// orgSeparator joins the holders of a prefix that has more than one.
const orgSeparator = " / "

// parseOUI reads the MA-L registry. Each assignment has a line in the form
//
//	00-00-00   (hex)		XEROX CORPORATION
//
// followed by the same assignment in base 16 and the holder's address, which
// this table does not keep: otinv wants the manufacturer of a network card,
// not its postal address.
func parseOUI(path string) ([]entry, sourceNote, error) {
	lines, note, err := read(path)
	if err != nil {
		return nil, note, err
	}

	var out []entry
	for _, line := range lines {
		prefix, org, ok := hexLine(line)
		if !ok {
			continue
		}
		out = append(out, entry{prefix: prefix, bits: 24, org: org})
	}
	if len(out) == 0 {
		return nil, note, fmt.Errorf("%s holds no assignments; is it the IEEE oui.txt?", path)
	}
	note.entries = len(out)
	return out, note, nil
}

// parseIAB reads the IAB registry, whose assignments are 36 bits: a shared
// OUI and a range of the next 24.
//
//	40-D8-55                      (hex)                         Avant Technologies
//	0D7000-0D7FFF                 (base 16)                     Avant Technologies
//
// The range always covers the low 12 bits, so the assignment is the OUI plus
// the first three hex digits of the range.
func parseIAB(path string) ([]entry, sourceNote, error) {
	lines, note, err := read(path)
	if err != nil {
		return nil, note, err
	}

	var (
		out           []entry
		pendingPrefix string
	)
	for _, line := range lines {
		if prefix, _, ok := hexLine(line); ok {
			pendingPrefix = prefix
			continue
		}
		rangeStart, org, ok := base16Line(line)
		if !ok || pendingPrefix == "" {
			continue
		}
		if len(rangeStart) < 3 {
			continue
		}
		out = append(out, entry{prefix: pendingPrefix + rangeStart[:3], bits: 36, org: org})
		pendingPrefix = ""
	}
	if len(out) == 0 {
		return nil, note, fmt.Errorf("%s holds no assignments; is it the IEEE iab.txt?", path)
	}
	note.entries = len(out)
	return out, note, nil
}

// hexLine reads a "XX-XX-XX   (hex)   Organization" line.
func hexLine(line string) (prefix, org string, ok bool) {
	before, after, found := strings.Cut(line, "(hex)")
	if !found {
		return "", "", false
	}
	prefix = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(before), "-", ""))
	if len(prefix) != 6 || !isHex(prefix) {
		return "", "", false
	}
	org = cleanOrg(after)
	if org == "" {
		return "", "", false
	}
	return prefix, org, true
}

// base16Line reads a "ABC000-ABCFFF   (base 16)   Organization" line, which
// in the IAB registry carries the range of an assignment.
func base16Line(line string) (rangeStart, org string, ok bool) {
	before, after, found := strings.Cut(line, "(base 16)")
	if !found {
		return "", "", false
	}
	start, _, _ := strings.Cut(strings.TrimSpace(before), "-")
	start = strings.ToLower(strings.TrimSpace(start))
	if len(start) != 6 || !isHex(start) {
		return "", "", false
	}
	org = cleanOrg(after)
	if org == "" {
		return "", "", false
	}
	return start, org, true
}

// cleanOrg tidies an organisation name: the registry pads with tabs, and a
// few holders have entered control characters.
func cleanOrg(raw string) string {
	org := strings.TrimSpace(raw)
	org = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, org)
	org = strings.Join(strings.Fields(org), " ")
	// A few holders ended their name with the separator of the form they
	// filled in. A full stop can belong to the name ("Ltd."), a trailing
	// comma never does.
	return strings.TrimRight(org, " ,;")
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

func read(path string) ([]string, sourceNote, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, sourceNote{}, fmt.Errorf("reading %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	note := sourceNote{path: filepath.Base(path), sha256: hex.EncodeToString(sum[:])}

	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, note, fmt.Errorf("reading %s: %w", path, err)
	}
	return lines, note, nil
}

// write emits the compressed table and the note that says where it came from.
func write(dir string, entries []entry, notes []sourceNote, source string) error {
	tablePath := filepath.Join(dir, tableFile)
	f, err := os.Create(tablePath)
	if err != nil {
		return fmt.Errorf("creating %s: %w", tablePath, err)
	}
	defer func() { _ = f.Close() }()

	zw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(zw)
	for _, e := range entries {
		// prefix<TAB>organisation, one per line. The prefix's length says
		// how many bits it covers, so nothing else has to be stored.
		if _, err := fmt.Fprintf(w, "%s\t%s\n", e.prefix, e.org); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	info, err := os.Stat(tablePath)
	if err != nil {
		return err
	}
	return writeProvenance(dir, entries, notes, source, info.Size())
}

const tableFile = "table.txt.gz"

func writeProvenance(dir string, entries []entry, notes []sourceNote, source string, size int64) error {
	counts := map[int]int{}
	for _, e := range entries {
		counts[e.bits]++
	}

	var b strings.Builder
	b.WriteString("# Embedded IEEE MAC address registry\n\n")
	b.WriteString("`table.txt.gz` maps a MAC address prefix to the organisation that\n")
	b.WriteString("registered it, so that otinv can name the maker of a network card from an\n")
	b.WriteString("address it observed. It is generated — do not edit it by hand:\n\n")
	b.WriteString("```\nmake oui OUI_DIR=/path/to/ieee\n```\n\n")
	b.WriteString("| What | Value |\n|------|-------|\n")
	fmt.Fprintf(&b, "| Generated | %s |\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "| Source | %s |\n", source)
	fmt.Fprintf(&b, "| 24-bit assignments (MA-L) | %d |\n", counts[24])
	fmt.Fprintf(&b, "| 36-bit assignments (IAB) | %d |\n", counts[36])
	fmt.Fprintf(&b, "| Compressed size | %d bytes |\n", size)
	b.WriteString("\nInput files, as read by `ouigen`:\n\n")
	b.WriteString("| File | Assignments | SHA-256 |\n|------|-------------|---------|\n")
	for _, n := range notes {
		fmt.Fprintf(&b, "| `%s` | %d | `%s` |\n", n.path, n.entries, n.sha256)
	}
	raw := 0
	for _, n := range notes {
		raw += n.entries
	}
	if merged := raw - len(entries); merged > 0 {
		fmt.Fprintf(&b, `
%d lines repeat a prefix the registry already lists under another holder: the
oldest OUIs were occasionally shared, and a renamed holder is listed again
without the old line being withdrawn. The table keeps every name, joined
with " / ".
`, merged)
	}

	b.WriteString(`
The registry is IEEE's own public listing. The 28-bit (MA-M) and 36-bit (MA-S)
registries are **not** included here: this build's source carries the MA-L and
IAB files only. A MAC from one of the shared blocks those registries are
carved out of therefore resolves to the block's holder — the IEEE Registration
Authority — rather than to a manufacturer, and the lookup reports it as a
shared block with no vendor instead of naming the IEEE.
`)
	// Created the same way as the table, so that both come out with the
	// ordinary mode a committed file wants.
	f, err := os.Create(filepath.Join(dir, "PROVENANCE.md"))
	if err != nil {
		return err
	}
	if _, err := f.WriteString(b.String()); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
