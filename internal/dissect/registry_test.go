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

// Several industrial protocols have no port because they have no IP layer, so
// they are bound by the EtherType IEEE assigned them. An EtherType names one
// protocol, unlike a port, so a registered dissector is accepted outright and
// nothing unregistered is offered the frame.
func TestSelectEtherType(t *testing.T) {
	const gooseEtherType = 0x88B8

	r := dissect.NewRegistry()
	layer2 := &stub{name: "layer2", score: 40}
	onPort := &stub{name: "onport", score: 100}
	r.Register(layer2, dissect.EtherTypes(gooseEtherType))
	r.Register(onPort, dissect.TCPPorts(502))

	got, score := r.SelectEtherType(testCtx(), gooseEtherType, []byte{1, 2, 3})
	require.NotNil(t, got)
	assert.Equal(t, "layer2", got.Name())
	assert.Equal(t, 40, score)

	// An EtherType nobody claims is not ours, however the frame looks.
	got, score = r.SelectEtherType(testCtx(), 0x88BA, []byte{1, 2, 3})
	assert.Nil(t, got)
	assert.Zero(t, score)

	// Nor is an empty frame.
	got, _ = r.SelectEtherType(testCtx(), gooseEtherType, nil)
	assert.Nil(t, got)

	// A dissector that scores zero on the frame does not get it either.
	r2 := dissect.NewRegistry()
	r2.Register(&stub{name: "silent", score: 0}, dissect.EtherTypes(gooseEtherType))
	got, _ = r2.SelectEtherType(testCtx(), gooseEtherType, []byte{1, 2, 3})
	assert.Nil(t, got)
}

func TestEtherTypeRegistration(t *testing.T) {
	r := dissect.NewRegistry()
	r.Register(&stub{name: "layer2", score: 50}, dissect.EtherTypes(0x88B8, 0x88BA))
	r.Register(&stub{name: "ported", score: 50}, dissect.TCPPorts(502))

	assert.True(t, r.HasEtherType("layer2", 0x88B8))
	assert.True(t, r.HasEtherType("layer2", 0x88BA))
	assert.False(t, r.HasEtherType("layer2", 0x8892))
	assert.False(t, r.HasEtherType("ported", 0x88B8))
	assert.False(t, r.HasEtherType("absent", 0x88B8))

	assert.Len(t, r.EtherTypeCandidates(0x88B8), 1)
	assert.Empty(t, r.EtherTypeCandidates(0x0800))

	// A protocol bound by EtherType is not offered port-matched streams.
	matched, others := r.Candidates(model.TransportTCP, 1234, 502)
	require.Len(t, matched, 1)
	assert.Equal(t, "ported", matched[0].Name())
	require.Len(t, others, 1)
	assert.Equal(t, "layer2", others[0].Name())
}

// quiet is a minimal dissector with no framer, which is what a datagram-only
// protocol looks like to the registry.
type quiet struct {
	name string
	tier int
}

func (q *quiet) Name() string { return q.name }
func (q *quiet) Tier() int    { return q.tier }
func (*quiet) Probe(*dissect.FlowContext, []byte) int {
	return 50
}
func (*quiet) Parse(*dissect.FlowContext, []byte) ([]model.Event, error) {
	return nil, nil
}

// Registered is what `otinv protocols` prints, so it has to describe a
// registration exactly: its ports, its EtherTypes and how it is fed.
func TestRegisteredDescribesEveryRegistration(t *testing.T) {
	r := dissect.NewRegistry()
	r.Register(&greedy{}, dissect.TCPPorts(502), dissect.UDPPorts(47808))
	r.Register(&quiet{name: "layer2", tier: 3}, dissect.EtherTypes(0x88b8))
	require.NoError(t, r.ExtraTCPPorts("greedy", 1502))

	rows := r.Registered()
	require.Len(t, rows, 2)
	assert.Equal(t, []string{"greedy", "layer2"}, []string{rows[0].Name, rows[1].Name},
		"registration order is kept")

	assert.Equal(t, 2, rows[0].Tier)
	assert.Equal(t, []uint16{502, 1502}, rows[0].TCPPorts, "a configured port is listed too")
	assert.Equal(t, []uint16{47808}, rows[0].UDPPorts)
	assert.Empty(t, rows[0].EtherTypes)
	assert.True(t, rows[0].Framed)
	assert.False(t, rows[0].Defers)

	assert.Equal(t, 3, rows[1].Tier)
	assert.Equal(t, []uint16{0x88b8}, rows[1].EtherTypes)
	assert.Empty(t, rows[1].TCPPorts)
	assert.False(t, rows[1].Framed, "nothing framed: it only ever sees whole frames")

	// The description is a copy: changing it cannot reach the registry.
	rows[0].TCPPorts[0] = 9999
	assert.Equal(t, []uint16{502, 1502}, r.Registered()[0].TCPPorts)
}

// Subset is `analyze --only`: the named dissectors and nothing else.
func TestSubsetKeepsOnlyTheNamedDissectors(t *testing.T) {
	r := dissect.NewRegistry()
	r.Register(&greedy{}, dissect.TCPPorts(502))
	r.Register(&quiet{name: "layer2", tier: 3}, dissect.EtherTypes(0x88b8))

	sub, err := r.Subset("layer2")
	require.NoError(t, err)
	assert.Equal(t, []string{"layer2"}, sub.Names())
	_, ok := sub.Lookup("greedy")
	assert.False(t, ok, "a protocol left out cannot claim a stream")
	_, ok = sub.Lookup("layer2")
	assert.True(t, ok)
	assert.Equal(t, []uint16{0x88b8}, sub.Registered()[0].EtherTypes,
		"the registration travels with the dissector")
	assert.True(t, sub.HasEtherType("layer2", 0x88b8))

	// A repeated name is the same single dissector.
	sub, err = r.Subset("layer2", "layer2")
	require.NoError(t, err)
	assert.Equal(t, []string{"layer2"}, sub.Names())

	// Parse health is the subset's own, so a restricted run reports only what
	// it actually tried.
	_, err = sub.Parse(&quiet{name: "layer2", tier: 3}, testCtx(), []byte{1})
	require.NoError(t, err)
	assert.EqualValues(t, 1, sub.Health()["layer2"].PDUs)
	assert.Empty(t, r.Health()["layer2"].PDUs, "the original is untouched")

	_, err = r.Subset("nosuch")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `no such dissector "nosuch"`)

	_, err = r.Subset()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one protocol name")
}
