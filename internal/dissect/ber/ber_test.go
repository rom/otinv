package ber_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect/ber"
)

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	require.NoError(t, err, "test fixture is not valid hex")
	return b
}

func TestReadTLV(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		class       uint8
		number      uint32
		constructed bool
		value       string
		rest        string
		wantErr     bool
	}{
		{
			name: "universal integer", in: "020105",
			class: ber.ClassUniversal, number: ber.TagInteger, value: "05",
		},
		{
			name: "context primitive", in: "800348454c",
			class: ber.ClassContext, number: 0, value: "48454c",
		},
		{
			name: "context constructed", in: "a103020101",
			class: ber.ClassContext, number: 1, constructed: true, value: "020101",
		},
		{
			name: "application class, constructed", in: "6103020101",
			class: ber.ClassApplication, number: 1, constructed: true, value: "020101",
		},
		{
			name: "private class", in: "c10100",
			class: ber.ClassPrivate, number: 1, value: "00",
		},
		{
			// MMS numbers its later services above 30, which BER can only
			// encode in the high tag number form.
			name: "high tag number", in: "bf2903020101",
			class: ber.ClassContext, number: 41, constructed: true, value: "020101",
		},
		{
			name: "high tag number over two octets", in: "bf8e3003020101",
			class: ber.ClassContext, number: 1840, constructed: true, value: "020101",
		},
		{
			name: "long form length", in: "0481050102030405" + "ff",
			class: ber.ClassUniversal, number: ber.TagOctetString,
			value: "0102030405", rest: "ff",
		},
		{
			name: "zero length", in: "0500", class: ber.ClassUniversal, number: ber.TagNull,
		},
		{
			name: "trailing bytes are returned", in: "020105" + "020106",
			class: ber.ClassUniversal, number: ber.TagInteger, value: "05", rest: "020106",
		},

		{name: "empty", in: "", wantErr: true},
		{name: "tag without length", in: "02", wantErr: true},
		{name: "length past the end", in: "020405", wantErr: true},
		{name: "indefinite length", in: "308002010500 00", wantErr: true},
		{name: "length octets past the end", in: "0484010203", wantErr: true},
		{name: "length in more octets than any PDU needs", in: "04850100000000", wantErr: true},
		{name: "high tag number running on", in: "bfffffff020101", wantErr: true},
		{name: "high tag number without a terminator", in: "bfff", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, rest, err := ber.ReadTLV(decode(t, tc.in))
			if tc.wantErr {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ber.ErrBER), "got %v", err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.class, got.Class)
			assert.Equal(t, tc.number, got.Number)
			assert.Equal(t, tc.constructed, got.Constructed)
			assert.Equal(t, decode(t, tc.value), got.Value)
			assert.Equal(t, decode(t, tc.rest), rest)
		})
	}
}

// Every layer that uses this reader hands it a payload it expects one element
// to account for, so a trailing octet is a defect rather than the next
// element.
func TestReadOneRejectsTrailingBytes(t *testing.T) {
	_, err := ber.ReadOne(decode(t, "020105"))
	assert.NoError(t, err)

	_, err = ber.ReadOne(decode(t, "020105ff"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ber.ErrBER))
	assert.Contains(t, err.Error(), "1 octets follow")
}

func TestChildren(t *testing.T) {
	top, err := ber.ReadOne(decode(t, "3009 020101 020102 020103"))
	require.NoError(t, err)

	kids, complete := top.Children(ber.NewBudget())
	require.True(t, complete)
	require.Len(t, kids, 3)
	for i, k := range kids {
		v, ok := k.Integer()
		require.True(t, ok)
		assert.Equal(t, int64(i+1), v)
	}

	// A primitive element has no children, and saying so is not the same as
	// saying it had none left.
	leaf := kids[0]
	kids, complete = leaf.Children(ber.NewBudget())
	assert.Empty(t, kids)
	assert.False(t, complete)
}

// A constructed element whose contents stop making sense partway must report
// that what it returned is not all of them, so a caller cannot read a
// truncated list as a complete one.
func TestChildrenReportsAnIncompleteWalk(t *testing.T) {
	top, err := ber.ReadOne(decode(t, "3006 020101 0204ff"))
	require.NoError(t, err)

	kids, complete := top.Children(ber.NewBudget())
	assert.False(t, complete, "the second element declares more than it carries")
	require.Len(t, kids, 1)
}

func TestFind(t *testing.T) {
	top, err := ber.ReadOne(decode(t, "300b 800101 810102 a203020103"))
	require.NoError(t, err)
	bud := ber.NewBudget()

	got, ok := top.Find(bud, 1)
	require.True(t, ok)
	assert.Equal(t, decode(t, "02"), got.Value)

	got, ok = top.Find(bud, 2)
	require.True(t, ok)
	assert.True(t, got.Constructed)

	_, ok = top.Find(bud, 7)
	assert.False(t, ok)
}

// The budget is what keeps a crafted blob from turning into unbounded work,
// so both halves of it have to bite.
func TestBudgetBoundsTheWalk(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		// One more level than the budget allows.
		body := "020101"
		for range ber.MaxDepth + 1 {
			body = "a0" + hex.EncodeToString([]byte{byte(len(body) / 2)}) + body
		}
		top, err := ber.ReadOne(decode(t, body))
		require.NoError(t, err)

		bud := ber.NewBudget()
		node, depth := top, 0
		for {
			kids, _ := node.Descend(bud)
			if len(kids) == 0 {
				break
			}
			node = kids[0]
			depth++
		}
		assert.LessOrEqual(t, depth, ber.MaxDepth,
			"the walk must stop at the depth budget, not at the end of the blob")
	})

	t.Run("elements", func(t *testing.T) {
		// A sequence of more empty elements than the budget allows.
		body := strings.Repeat("0500", ber.MaxElements+10)
		top, err := ber.ReadOne(decode(t, "3082"+hex.EncodeToString([]byte{
			byte(len(body) / 2 >> 8), byte(len(body) / 2),
		})+body))
		require.NoError(t, err)

		kids, complete := top.Children(ber.NewBudget())
		assert.False(t, complete, "the budget ran out before the elements did")
		assert.LessOrEqual(t, len(kids), ber.MaxElements)
	})
}

func TestInteger(t *testing.T) {
	tests := []struct {
		in   string
		want int64
		ok   bool
	}{
		{in: "00", want: 0, ok: true},
		{in: "05", want: 5, ok: true},
		{in: "7f", want: 127, ok: true},
		{in: "ff", want: -1, ok: true},
		{in: "80", want: -128, ok: true},
		{in: "0100", want: 256, ok: true},
		{in: "04a273", want: 303731, ok: true},
		{in: "7fffffffffffffff", want: 1<<63 - 1, ok: true},
		// Nothing to read, and more than an int64 can hold.
		{in: ""},
		{in: "000000000000000000"},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			tlv := ber.TLV{Class: ber.ClassUniversal, Number: ber.TagInteger, Value: decode(t, tc.in)}
			got, ok := tlv.Integer()
			assert.Equal(t, tc.ok, ok)
			if tc.ok {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

// Text is what puts a device's own strings into an event and from there into
// the GUI, so anything that is not printable ASCII is refused: either the
// field is not what the layout said, or someone is trying to get control
// characters into a report.
func TestText(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "identifier", in: hex.EncodeToString([]byte("LLN0$GO$gcb01")), want: "LLN0$GO$gcb01", ok: true},
		{name: "space and tilde are printable", in: "207e", want: " ~", ok: true},
		{name: "empty", in: ""},
		{name: "null byte", in: "410042"},
		{name: "newline", in: "410a42"},
		{name: "tab", in: "410942"},
		{name: "escape", in: "411b42"},
		{name: "high bit set", in: "41ff42"},
		{name: "longer than the cap", in: strings.Repeat("41", ber.MaxTextLen+1)},
		{name: "exactly the cap", in: strings.Repeat("41", ber.MaxTextLen),
			want: strings.Repeat("A", ber.MaxTextLen), ok: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tlv := ber.TLV{Value: decode(t, tc.in)}
			got, ok := tlv.Text()
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestOID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "MMS application context", in: "28ca220203", want: "1.0.9506.2.3", ok: true},
		{name: "BER transfer syntax", in: "5101", want: "2.1.1", ok: true},
		{name: "ACSE apdus", in: "52010001", want: "2.2.1.0.1", ok: true},
		{name: "arc above 79 belongs to the third top arc", in: "81340102", want: "2.100.1.2", ok: true},
		{name: "single octet", in: "2a", want: "1.2", ok: true},
		{name: "empty"},
		{name: "arc without a terminator", in: "2aff"},
		{name: "longer than the cap", in: strings.Repeat("01", 33)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tlv := ber.TLV{Class: ber.ClassUniversal, Number: ber.TagOID, Value: decode(t, tc.in)}
			got, ok := tlv.OID()
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTagAndCtx(t *testing.T) {
	assert.Equal(t, "univ16", ber.TLV{Class: ber.ClassUniversal, Number: 16}.Tag())
	assert.Equal(t, "app1", ber.TLV{Class: ber.ClassApplication, Number: 1}.Tag())
	assert.Equal(t, "ctx11", ber.TLV{Class: ber.ClassContext, Number: 11}.Tag())
	assert.Equal(t, "priv3", ber.TLV{Class: ber.ClassPrivate, Number: 3}.Tag())

	ctx := ber.TLV{Class: ber.ClassContext, Number: 4}
	assert.True(t, ctx.Ctx(4))
	assert.False(t, ctx.Ctx(5))
	assert.False(t, ber.TLV{Class: ber.ClassUniversal, Number: 4}.Ctx(4))
}
