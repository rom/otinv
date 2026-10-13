package dissect_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/model"
)

// panicker is a deliberately broken dissector: the registry must contain it.
type panicker struct{ name string }

func (p *panicker) Name() string { return p.name }
func (*panicker) Tier() int      { return 1 }
func (*panicker) Probe(*dissect.FlowContext, []byte) int {
	panic("probe exploded")
}
func (*panicker) Parse(*dissect.FlowContext, []byte) ([]model.Event, error) {
	panic("parse exploded")
}
func (*panicker) PDULen([]byte) (int, error) {
	panic("framer exploded")
}

// greedy claims more bytes than the buffer holds.
type greedy struct{}

func (*greedy) Name() string { return "greedy" }
func (*greedy) Tier() int    { return 2 }
func (*greedy) Probe(*dissect.FlowContext, []byte) int {
	return 1000 // out of range on purpose: the registry must clamp it
}
func (*greedy) Parse(*dissect.FlowContext, []byte) ([]model.Event, error) {
	return nil, nil
}
func (*greedy) PDULen(buf []byte) (int, error) { return len(buf) + 1, nil }
func testCtx() *dissect.FlowContext {
	return &dissect.FlowContext{
		Flow: model.Flow{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 1234, DstPort: 502,
			Transport: model.TransportTCP,
		},
		Direction: model.DirRequest,
	}
}

// A panic in a dissector must not take the ingest down; it is recovered,
// counted and surfaced as a parse error.
func TestRegistryRecoversPanics(t *testing.T) {
	r := dissect.NewRegistry()
	d := &panicker{name: "panicker"}
	r.Register(d)
	assert.Equal(t, 0, r.Probe(d, testCtx(), []byte{1, 2, 3}))
	events, err := r.Parse(d, testCtx(), []byte{1, 2, 3})
	require.Error(t, err)
	assert.ErrorIs(t, err, dissect.ErrMalformed)
	assert.Empty(t, events)
	n, err := r.PDULen(d, []byte{1, 2, 3})
	require.Error(t, err)
	assert.ErrorIs(t, err, dissect.ErrMalformed)
	assert.Zero(t, n)
	health := r.Health()["panicker"]
	assert.Equal(t, uint64(3), health.Panics, "every recovered panic is counted")
}
func TestRegistryClampsProbeAndFramer(t *testing.T) {
	r := dissect.NewRegistry()
	d := &greedy{}
	r.Register(d, dissect.TCPPorts(9999))
	assert.Equal(t, 100, r.Probe(d, testCtx(), []byte{1, 2, 3}), "confidence is clamped to 100")
	_, err := r.PDULen(d, []byte{1, 2, 3})
	require.Error(t, err)
	assert.ErrorIs(t, err, dissect.ErrMalformed,
		"a framer may never claim more bytes than the buffer holds")
}
func TestRegistryHealthCountsParses(t *testing.T) {
	r := dissect.NewRegistry()
	d := &greedy{}
	r.Register(d)
	_, err := r.Parse(d, testCtx(), []byte{1})
	require.NoError(t, err)
	r.RecordError("greedy")
	h := r.Health()["greedy"]
	assert.Equal(t, uint64(1), h.PDUs)
	assert.Equal(t, uint64(1), h.Errors)
	assert.Zero(t, h.Panics)
}
func TestRegisterRejectsDuplicatesAndBadTiers(t *testing.T) {
	r := dissect.NewRegistry()
	r.Register(&panicker{name: "dup"})
	assert.Panics(t, func() { r.Register(&panicker{name: "dup"}) },
		"registering the same name twice is a programming error")
	assert.Panics(t, func() { r.Register(nil) })
}
func TestSelectPrefersPortMatch(t *testing.T) {
	r := dissect.NewRegistry()
	onPort := &stub{name: "onport", score: 40}
	heuristic := &stub{name: "heuristic", score: 95}
	r.Register(onPort, dissect.TCPPorts(502))
	r.Register(heuristic)
	got, score, wait := r.Select(testCtx(), []byte{1, 2, 3}, dissect.DefaultMinConfidence)
	require.NotNil(t, got)
	assert.Equal(t, "onport", got.Name(), "the port is evidence in its own right")
	assert.Equal(t, 40, score)
	assert.False(t, wait)
}
func TestSelectRequiresConfidenceWithoutPortMatch(t *testing.T) {
	r := dissect.NewRegistry()
	weak := &stub{name: "weak", score: 69}
	r.Register(weak)
	got, _, _ := r.Select(testCtx(), []byte{1, 2, 3}, 70)
	assert.Nil(t, got, "below the threshold and no port match: no binding")
	r2 := dissect.NewRegistry()
	strong := &stub{name: "strong", score: 70}
	r2.Register(strong)
	got, score, _ := r2.Select(testCtx(), []byte{1, 2, 3}, 70)
	require.NotNil(t, got)
	assert.Equal(t, "strong", got.Name())
	assert.Equal(t, 70, score)
}
func TestSelectIgnoresEmptyPayload(t *testing.T) {
	r := dissect.NewRegistry()
	r.Register(&stub{name: "any", score: 100}, dissect.TCPPorts(502))
	got, _, _ := r.Select(testCtx(), nil, 70)
	assert.Nil(t, got)
}
func TestLookupAndExtraPorts(t *testing.T) {
	r := dissect.NewRegistry()
	r.Register(&stub{name: "proto", score: 50}, dissect.TCPPorts(502))
	_, ok := r.Lookup("proto")
	assert.True(t, ok)
	_, ok = r.Lookup("absent")
	assert.False(t, ok)
	require.NoError(t, r.ExtraTCPPorts("proto", 5020))
	matched, _ := r.Candidates(model.TransportTCP, 1234, 5020)
	require.Len(t, matched, 1, "a user-configured extra port must bind too")
	err := r.ExtraTCPPorts("absent", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no such dissector")
}

// stub is a well behaved dissector with a fixed Probe score.
type stub struct {
	name  string
	score int
}

func (s *stub) Name() string { return s.name }
func (*stub) Tier() int      { return 1 }
func (s *stub) Probe(*dissect.FlowContext, []byte) int {
	return s.score
}
func (s *stub) Parse(ctx *dissect.FlowContext, _ []byte) ([]model.Event, error) {
	return []model.Event{{Protocol: s.name, Flow: ctx.Flow}}, nil
}

// deferStub is a dissector that shares a port and can say it is not yet able
// to tell its protocol from the others on it.
type deferStub struct {
	stub
	wait bool
}

func (d *deferStub) ProbeDefers([]byte) bool { return d.wait }

// A dissector that defers is left out of the comparison whatever it would
// score, because on a shared port a confident guess from the connection phase
// is still a guess, and a wrong protocol on an asset changes the role inferred
// for the device.
func TestSelectHonoursDeferral(t *testing.T) {
	waiting := &deferStub{stub: stub{name: "waiting", score: 90}, wait: true}
	other := &stub{name: "other", score: 40}

	r := dissect.NewRegistry()
	r.Register(waiting, dissect.TCPPorts(102))
	got, score, wait := r.Select(testCtx102(), []byte{3, 0, 0, 7}, 70)
	assert.Nil(t, got, "the only candidate is waiting for more bytes")
	assert.Zero(t, score)
	assert.True(t, wait, "the caller must keep the bytes rather than give up")

	// Another candidate on the same port that does not defer wins outright.
	r2 := dissect.NewRegistry()
	r2.Register(waiting, dissect.TCPPorts(102))
	r2.Register(other, dissect.TCPPorts(102))
	got, score, wait = r2.Select(testCtx102(), []byte{3, 0, 0, 7}, 70)
	require.NotNil(t, got)
	assert.Equal(t, "other", got.Name())
	assert.Equal(t, 40, score)
	assert.False(t, wait)

	// Once it stops deferring its own score decides.
	waiting.wait = false
	got, score, wait = r2.Select(testCtx102(), []byte{3, 0, 0, 7}, 70)
	require.NotNil(t, got)
	assert.Equal(t, "waiting", got.Name())
	assert.Equal(t, 90, score)
	assert.False(t, wait)
}

// A heuristic candidate must not pick up a stream that a port-matched
// dissector has asked to wait for: that is how MMS traffic would end up
// labelled as something else entirely.
func TestDeferralOutranksHeuristics(t *testing.T) {
	r := dissect.NewRegistry()
	r.Register(&deferStub{stub: stub{name: "waiting", score: 0}, wait: true}, dissect.TCPPorts(102))
	r.Register(&stub{name: "guesser", score: 100})

	got, _, wait := r.Select(testCtx102(), []byte{3, 0, 0, 7}, 70)
	assert.Nil(t, got)
	assert.True(t, wait)
}

// A dissector that panics when asked is a bug, not a reason to stall the
// stream, so the selection goes ahead on the scores at hand.
func TestDeferralPanicIsRecovered(t *testing.T) {
	r := dissect.NewRegistry()
	r.Register(&panicDeferStub{stub{name: "boom", score: 80}}, dissect.TCPPorts(102))

	got, score, wait := r.Select(testCtx102(), []byte{3, 0, 0, 7}, 70)
	require.NotNil(t, got)
	assert.Equal(t, 80, score)
	assert.False(t, wait)
	assert.Equal(t, uint64(1), r.Health()["boom"].Panics)
}

type panicDeferStub struct{ stub }

func (p *panicDeferStub) ProbeDefers([]byte) bool { panic("probe defers panicked") }

func testCtx102() *dissect.FlowContext {
	ctx := testCtx()
	ctx.Flow.DstPort = 102
	return ctx
}
