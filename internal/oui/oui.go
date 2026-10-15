// Package oui names the maker of a network card from a MAC address.
//
// The IEEE assigns a manufacturer a block of addresses and publishes the
// register of who holds which block; the leading bits of an address are the
// block. Reading a name out of that register is passive — the table is
// embedded in the binary and nothing is asked of any device — which is what
// otinv requires of every source of evidence.
//
// The embedded table is generated from the IEEE files by
// internal/oui/ouigen; PROVENANCE.md records which files, when, and what
// they contained.
package oui

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

//go:embed table.txt.gz
var tableGz []byte

// sharedHolder is the name the register gives the blocks it carves the
// smaller MA-M (28-bit) and MA-S (36-bit) assignments out of. A match on one
// of those says only that the real holder is in a register this build does
// not carry, so it must not be reported as a manufacturer.
const sharedHolder = "IEEE Registration Authority"

// withheldHolder is what the register prints where the holder asked the IEEE
// not to publish its name. The block is assigned to a manufacturer all the
// same, which is worth saying: the address is a card's, the maker is simply
// not on record.
const withheldHolder = "Private"

// Vendor is what the register says about one MAC address.
//
// Name is empty when nothing can be named. The remaining flags say why a
// name is missing, or why a name that was found is not the maker of the card
// that sent the frame.
type Vendor struct {
	Name     string // the organisation the matched block is registered to
	Prefix   string // the block that matched, e.g. "00:1b:1b" or "00:50:c2:0a:f"
	Bits     int    // how much of the address the block covers: 24 or 36
	Shared   bool   // the block is one the IEEE subdivides further
	Withheld bool   // the block is assigned, but its holder is not published
	Local    bool   // the address is locally administered (the U/L bit is set)
	Group    bool   // the address names a group of receivers (the I/G bit is set)
}

// Known reports whether the register named an organisation at all, including
// one that cannot be the maker of the card.
func (v Vendor) Known() bool { return v.Name != "" }

// madeTheCard reports whether Name can be read as the manufacturer of the
// network interface the address belongs to.
func (v Vendor) madeTheCard() bool { return v.Name != "" && !v.Local && !v.Group }

// Explain states in one clause what the register had to say, for the command
// line and for the evidence shown in the GUI.
func (v Vendor) Explain() string {
	switch {
	case v.Group && v.Name != "":
		return fmt.Sprintf("a group address, which names a set of receivers rather than a card; "+
			"the register's entry for %s/%d is %s", v.Prefix, v.Bits, v.Name)
	case v.Group:
		return "a group address, which names a set of receivers rather than a card"
	case v.Local && v.Name != "":
		return fmt.Sprintf("locally administered, so the address was chosen where the device runs "+
			"and not by a manufacturer; the register's entry for %s/%d is %s",
			v.Prefix, v.Bits, v.Name)
	case v.Local:
		return "locally administered, so the address was chosen where the device runs " +
			"and not by a manufacturer"
	case v.Withheld:
		return fmt.Sprintf("%s/%d is assigned, but its holder asked the IEEE not to publish "+
			"the name", v.Prefix, v.Bits)
	case v.Shared:
		return fmt.Sprintf("%s/%d is a shared IEEE block, divided into smaller assignments "+
			"that this build's register does not list", v.Prefix, v.Bits)
	case v.Name != "":
		return fmt.Sprintf("%s, from the block %s/%d", v.Name, v.Prefix, v.Bits)
	default:
		return "no entry in the IEEE register covers this address"
	}
}

// Lookup names the maker of the network card that holds the given address.
//
// The bool reports whether Name is that maker: it is false when no block
// matched, when the block is one the IEEE subdivides, when its holder is not
// published, and when the address
// was not handed out by a manufacturer at all — locally administered or a
// group address — even where one of the register's oldest entries happens to
// cover its leading bits. The returned Vendor explains itself in every one of
// those cases, so a caller that wants to show the near miss can.
//
// A 36-bit assignment wins over the 24-bit block it sits inside, which is
// what makes the shared blocks resolve to their real holders where this
// build's register lists them.
func Lookup(mac string) (Vendor, bool) {
	digits, err := Normalize(mac)
	if err != nil {
		return Vendor{}, false
	}
	load()

	// Normalize guarantees two leading hex digits.
	first, err := strconv.ParseUint(digits[:2], 16, 8)
	if err != nil {
		return Vendor{}, false
	}
	v := Vendor{
		Group: first&0x01 != 0,
		Local: first&0x02 != 0,
	}

	if len(digits) >= 9 {
		if org, ok := bits36[digits[:9]]; ok {
			v.Name, v.Prefix, v.Bits = org, Format(digits[:9]), 36
			return v, v.madeTheCard()
		}
	}
	if org, ok := bits24[digits[:6]]; ok {
		v.Prefix, v.Bits = Format(digits[:6]), 24
		switch {
		case strings.EqualFold(org, sharedHolder):
			v.Shared = true
			return v, false
		case strings.EqualFold(org, withheldHolder):
			v.Withheld = true
			return v, false
		}
		v.Name = org
		return v, v.madeTheCard()
	}
	return v, false
}

// Normalize reads a MAC address, or the leading part of one, in any of the
// notations the field uses — 00:1b:1b:0a:0b:0c, 00-1B-1B-0A-0B-0C,
// 001b.1b0a.0b0c, 001b1b0a0b0c — and returns its hex digits in lower case.
//
// A prefix is accepted because the register is a register of prefixes: three
// octets look up a 24-bit assignment and nine hex digits a 36-bit one, so an
// analyst can ask about a block without inventing the rest of an address. An
// EUI-64, which PTP and the field buses carry, is read as the MAC-48 it
// encapsulates, or cut back to its leading six octets when it is an address
// in its own right.
func Normalize(mac string) (string, error) {
	var b strings.Builder
	b.Grow(len(mac))
	for _, r := range mac {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			b.WriteRune(r)
		case r >= 'A' && r <= 'F':
			b.WriteRune(r + ('a' - 'A'))
		case r == ':', r == '-', r == '.', r == ' ', r == '\t', r == '_':
			// Separator. Which one is used says nothing about the address.
		default:
			return "", fmt.Errorf("%q is not a MAC address: %q is neither a hex digit nor a separator", mac, r)
		}
	}

	digits := b.String()
	switch {
	case len(digits) == 16:
		// An EUI-64. Where one encapsulates a MAC-48 — which is how PTP
		// writes a clock identity — the standard inserts ff-fe after the
		// block, so taking those four digits out gives the address back. An
		// EUI-64 assigned as such keeps its own bits, whose leading 36 are
		// still the assignment.
		if digits[6:10] == "fffe" {
			digits = digits[:6] + digits[10:]
		} else {
			digits = digits[:12]
		}
	case len(digits) < 6:
		return "", fmt.Errorf("%q is too short for a MAC address: %d hex digits, and a block takes 6", mac, len(digits))
	case len(digits) > 12:
		return "", fmt.Errorf("%q is too long for a MAC address: %d hex digits, and an address has 12", mac, len(digits))
	}
	return digits, nil
}

// Size reports how many 24-bit and 36-bit assignments the embedded register
// holds. A damaged embedded table is a build problem rather than a runtime
// one, and shows up here as an error and in every lookup finding nothing.
func Size() (bits24Count, bits36Count int, err error) {
	load()
	return len(bits24), len(bits36), loadErr
}

var (
	once    sync.Once
	loadErr error
	bits24  map[string]string
	bits36  map[string]string
)

// load unpacks the embedded table on first use. A run that never asks about
// a MAC address — exporting a report, say — does not pay for it.
func load() {
	once.Do(func() {
		bits24 = map[string]string{}
		bits36 = map[string]string{}

		zr, err := gzip.NewReader(bytes.NewReader(tableGz))
		if err != nil {
			loadErr = fmt.Errorf("reading the embedded MAC register: %w", err)
			return
		}
		defer func() { _ = zr.Close() }()

		scanner := bufio.NewScanner(zr)
		for scanner.Scan() {
			prefix, org, ok := strings.Cut(scanner.Text(), "\t")
			if !ok || org == "" {
				continue
			}
			switch len(prefix) {
			case 6:
				bits24[prefix] = org
			case 9:
				bits36[prefix] = org
			}
		}
		if err := scanner.Err(); err != nil {
			loadErr = fmt.Errorf("reading the embedded MAC register: %w", err)
			return
		}
		if len(bits24) == 0 {
			loadErr = fmt.Errorf("the embedded MAC register holds no assignments")
		}
	})
}

// Format writes hex digits the way an address is written, in colon-separated
// pairs, with the odd digit of a 36-bit block left on its own:
// 00:50:c2:0a:f. It is how this package prints a block, and how a caller
// prints an address it normalized.
func Format(digits string) string {
	var b strings.Builder
	b.Grow(len(digits) + len(digits)/2)
	for i := 0; i < len(digits); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		end := min(i+2, len(digits))
		b.WriteString(digits[i:end])
	}
	return b.String()
}
