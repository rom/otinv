package mms_test

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rom/otinv/internal/dissect"
	"github.com/rom/otinv/internal/dissect/mms"
	"github.com/rom/otinv/internal/model"
)

// TPKT frames taken verbatim from the public IEC 61850 sample captures in
// testdata/pcaps; the comment names the file and packet each came from. Every
// capture was decoded independently before these expectations were written.
const (
	// reports #107 and #109: the transport connection, which on port 102
	// says nothing about which of its protocols will follow.
	frameConnectRequest = "0300001611e00000077800c1020001c2020001c0010d"
	frameConnectConfirm = "0300001611d00778340000c1020001c2020001c0010a"

	// identify #1: a session CONNECT carrying the presentation connect PDU,
	// an AARQ and the MMS initiate request inside it.
	frameAssociateRequest = "030000bf02f0800db60506130100160102140200023302000134020001c1a031819da0038001" +
		"01a28195810400000001820400000001a423300f0201010604520100013004060251013010020103060528ca2202" +
		"0130040602510161623060020101a05b6059a107060528ca220203a20706052901876701a30302010ca60606042901" +
		"8767a70302010cbe33283106025101020103a028a826800300ff0081010a82010a830105a416800101810305f10082" +
		"0c03ee1c000004000000010118"
	// identify #2: the server accepts the association.
	frameAssociateResponse = "0300009e02f0800e95050613010016010214020002c187318184a003800101a27d8304000000" +
		"01a5123007800100810251013007800100810251016161305f020101a05a6158a107060528ca220203a203020100a3" +
		"05a103020100a40706052901876701a50302010cbe33283106025101020103a028a926800300c000810101820101" +
		"830105a416800101810305e100820c03ee1c000004000000010010"
	// identify #3 and #4: the client asks the device what it is, and the
	// device answers with its vendor, model and revision.
	frameIdentifyRequest  = "0300001b02f08001000100610e300c020103a007a0050201018200"
	frameIdentifyResponse = "0300003c02f08001000100612f302d020103a028a126020101a2218009494e464f2054454348" +
		"810d53363138353020666f722050438205302e302e31"
	// identify #5: a status request.
	frameStatusRequest = "0300001c02f08001000100610f300d020103a008a006020102800100"

	// reports #3: an unsolicited report, which is how IEC 61850 delivers
	// data. Its first access result is the report control block's reference.
	frameInformationReport = "030000b302f080010001006181a53081a2020103a0819ca38199a08196a1058003525054a081" +
		"8c8a1a414131433151303141314c44302f4c4c4e30247263625f49303284030650008601398403050100a25da21da2" +
		"09a2078705083e5a95fc8501018403030000910848808dc98a7efa0aa21da209a2078705083dfe7e2285010184030300" +
		"00910848808dc4a353f80aa21da209a2078705083e5beed48501008403030000910848808dcea49ba60a84020240"
	// reports #124, #126 and #128: the client asks for a report control
	// block's attributes, is refused, and then reads it instead.
	frameGetVariableAccessAttributes = "0300004202f0800100010061353033020103a02ea02c020304a273a625a023a1" +
		"211a0e41413145315130314650324c44301a0f4c4c4e30244252247263625f423032"
	frameAccessDenied = "0300002202f0800100010061153013020103a00ea20c800304a273a205a003870102"
	frameRead         = "0300004802f08001000100613b3039020103a034a032020304a274a42ba129a0273025a023a121" +
		"1a0e41413145315130314650324c44301a0f4c4c4e30244252247263625f423032"
	// reports #136, #139 and #140: the orderly end of an association.
	frameConcludeRequest = "0300001602f0800100010061093007020103a0028b00"
	frameReleaseRequest  = "0300001902f0800910c10e610c300a020101a0056203800101"
	frameReleaseResponse = "0300001902f0800a10c10e610c300a020101a0056303800101"

	// write #2: a write to a nameplate attribute, named device-wide.
	frameWrite = "0300004502f0800100010061383036020103a031a02f020100a52aa0233021a01f801d41435453455447" +
		"47494f3830244443244e616d506c742476656e646f72a003850100"
	// write #1: an accept whose user data parameter is declared empty and
	// then sent anyway, and whose parameter field overruns the frame by an
	// octet. Both are off-spec and both are in the field.
	frameOffSpecAccept = "0300009102f0800e89050613010006010214020002c1003178a003800100a271830400000001a5" +
		"12300780010081025201300780010081025101880206006151304f020101a04a614880020780a107060528ca220203" +
		"a203020100a305a103020100a40606042bce0f02a503020117be20281e020103a019a917800100810100820100830100" +
		"a409800100810100820100"
	// write #3: a response whose presentation data value declares one octet
	// more than it carries.
	frameTruncatedResponse = "0300001a02f08001000100610d300b020103a006a10402010030"

	// program_control #8, #12 and #16: MMS straight on top of COTP, with no
	// session, presentation or association layer, stopping and then starting
	// a program invocation.
	frameRawInitiate = "0300002f02f080a8268002001f81010382010383020808a416800101810305e800820c03ffffffff" +
		"ffffffffffffff"
	frameRawStop  = "0300002802f080a01f020101bf29198017523339353032343339374170706c69636174696f6e5f31"
	frameRawStart = "0300002a02f080a021020101bf281b8017523339353032343339374170706c69636174696f6e5f318100"
	// program_control #6: the server's reply, whose TPKT length counts only
	// its own header and whose COTP length indicator is zero.
	frameBrokenServerReply = "0300000500d080"
	// program_control #20: the client concludes.
	frameRawConclude = "0300000902f0808b00"

	// download #12 and #16: taking control of a semaphore and then opening a
	// download into a domain.
	frameRawTakeControl = "0300002002f080a017020101b312a00a80087265736572766564830101860101"
	frameRawDownload    = "0300003202f080a029020101ba24801044544c6f6746696c6573446f6d61696ea10d1a0b4d7553" +
		"656341433830304d820100"
)

func frame(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
	require.NoError(t, err, "test fixture is not valid hex")
	return b
}

func ctxFor(dir model.Direction) *dissect.FlowContext {
	flow := model.Flow{
		SrcIP: "172.16.0.101", DstIP: "172.16.202.5",
		SrcPort: 1345, DstPort: mms.DefaultPort,
		Transport: model.TransportTCP,
	}
	if dir == model.DirResponse {
		flow = flow.Reverse()
	}
	return &dissect.FlowContext{
		CaptureID:   "test",
		Flow:        flow,
		PacketIndex: 124,
		Timestamp:   time.Unix(1256130000, 0).UTC(),
		Direction:   dir,
		ServerPort:  mms.DefaultPort,
	}
}

func parseOne(t *testing.T, dir model.Direction, raw []byte) model.Event {
	t.Helper()
	events, err := mms.New().Parse(ctxFor(dir), raw)
	require.NoError(t, err)
	require.Len(t, events, 1, "one frame yields one event here")
	return events[0]
}

func TestIdentity(t *testing.T) {
	d := mms.New()
	assert.Equal(t, "mms", d.Name())
	assert.Equal(t, 1, d.Tier())
}

func TestRegisteredOnDefaultPort(t *testing.T) {
	reg := dissect.Default()
	d, ok := reg.Lookup("mms")
	require.True(t, ok, "mms must register itself in init()")
	require.NotNil(t, d)
	assert.True(t, reg.HasPort("mms", model.TransportTCP, 102),
		"IEC 61850 MMS runs over ISO-on-TCP, port 102")
}

func TestPDULen(t *testing.T) {
	d := mms.New()

	tests := []struct {
		name    string
		in      string
		want    int
		wantErr error
	}{
		{name: "empty", in: "", wantErr: dissect.ErrNeedMore},
		{name: "version only", in: "03", wantErr: dissect.ErrNeedMore},
		{name: "header without body", in: "03000016", wantErr: dissect.ErrNeedMore},
		{name: "wrong version", in: "04000016", wantErr: dissect.ErrMalformed},
		{name: "reserved octet set", in: "03010016", wantErr: dissect.ErrMalformed},
		{name: "length below the minimum", in: "03000004ff", wantErr: dissect.ErrMalformed},
		{name: "exact frame", in: frameConcludeRequest, want: 22},
		{name: "two frames in one segment",
			in: frameConcludeRequest + frameConcludeRequest, want: 22},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := d.PDULen(frame(t, tc.in))
			if tc.wantErr != nil {
				require.Error(t, err)
				assert.True(t, errors.Is(err, tc.wantErr), "got %v", err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, n)
		})
	}
}

// The score has to come from what sits above COTP. S7comm shares the port and
// opens with the same connection request, so anything that scores the
// connection phase is guessing, and a guess here puts a substation IED in the
// inventory as a Siemens CPU.
func TestProbe(t *testing.T) {
	d := mms.New()
	ctx := ctxFor(model.DirRequest)

	tests := []struct {
		name    string
		in      string
		wantMin int
		wantMax int
	}{
		{name: "association request", in: frameAssociateRequest, wantMin: 85, wantMax: 100},
		{name: "association response", in: frameAssociateResponse, wantMin: 85, wantMax: 100},
		{name: "identify request", in: frameIdentifyRequest, wantMin: 85, wantMax: 100},
		{name: "information report", in: frameInformationReport, wantMin: 85, wantMax: 100},
		{name: "release request", in: frameReleaseRequest, wantMin: 85, wantMax: 100},
		{name: "raw MMS over COTP", in: frameRawStart, wantMin: 85, wantMax: 100},
		{name: "off-spec accept", in: frameOffSpecAccept, wantMin: 85, wantMax: 100},

		// The connection phase alone says nothing, which is what ProbeDefers
		// is for.
		{name: "connection request", in: frameConnectRequest, wantMax: 0},
		{name: "connection confirm", in: frameConnectConfirm, wantMax: 0},

		// Other protocols, including the two that share port 102.
		{name: "s7comm job", in: "0300001902f0803201000000000008000000f0000001000101e0", wantMax: 0},
		{name: "s7comm-plus", in: "0300001b02f08072030000ffff000800000000f0000001000100f0", wantMax: 0},
		{name: "modbus", in: "0001000000060103006b0003", wantMax: 0},
		{name: "http", in: hex.EncodeToString([]byte("GET / HTTP/1.1\r\n\r\n")), wantMax: 0},
		{name: "too short to judge", in: "0300", wantMax: 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := d.Probe(ctx, frame(t, tc.in))
			assert.GreaterOrEqual(t, got, tc.wantMin)
			assert.LessOrEqual(t, got, tc.wantMax)
		})
	}
}

// A stream that has shown only COTP connection management could be any of the
// protocols on port 102, so the binding has to wait for the frame that proves
// one of them.
func TestProbeDefersUntilAPayloadArrives(t *testing.T) {
	d := mms.New()

	assert.True(t, d.ProbeDefers(frame(t, frameConnectRequest)))
	assert.True(t, d.ProbeDefers(frame(t, frameConnectConfirm)))
	assert.True(t, d.ProbeDefers(frame(t, frameConnectRequest+frameConnectConfirm)))
	// An empty data PDU is a keep-alive and still says nothing.
	assert.True(t, d.ProbeDefers(frame(t, "0300000702f080")))

	// Once a payload has arrived there is something to judge.
	assert.False(t, d.ProbeDefers(frame(t, frameConnectRequest+frameAssociateRequest)))
	assert.False(t, d.ProbeDefers(frame(t, frameRawStart)))
	// Not our framing at all: nothing to wait for on our account.
	assert.False(t, d.ProbeDefers(frame(t, "0001000000060103006b0003")))
	assert.False(t, d.ProbeDefers(nil))
}

func TestConnectionCarriesTransportSelectors(t *testing.T) {
	ev := parseOne(t, model.DirRequest, frame(t, frameConnectRequest))
	assert.Equal(t, "ConnectionRequest", ev.Operation)
	assert.Equal(t, "0x0001", ev.Attrs["calling_tsap"])
	assert.Equal(t, "0x0001", ev.Attrs["called_tsap"])
	assert.Equal(t, "8192", ev.Attrs["tpdu_size"])
	assert.Equal(t, model.ClassOther, ev.Class)
	assert.Empty(t, ev.Identity, "the transport says nothing about what the device is")

	confirm := parseOne(t, model.DirResponse, frame(t, frameConnectConfirm))
	assert.Equal(t, "ConnectionConfirm", confirm.Operation)
	assert.Equal(t, "1024", confirm.Attrs["tpdu_size"])
}

func TestEmptyDataFrameYieldsNoEvent(t *testing.T) {
	events, err := mms.New().Parse(ctxFor(model.DirRequest), frame(t, "0300000702f080"))
	require.NoError(t, err)
	assert.Empty(t, events, "a keep-alive carries no operation")
}

// The association layer is where the two ends name each other and the server
// accepts or refuses. A refusal is why a client never reaches the data.
func TestAssociationSetup(t *testing.T) {
	req := parseOne(t, model.DirRequest, frame(t, frameAssociateRequest))
	assert.Equal(t, "initiate-Request", req.Operation)
	assert.Equal(t, "CONNECT", req.Attrs["session"])
	assert.Equal(t, "connect", req.Attrs["presentation"])
	assert.Equal(t, "AARQ", req.Attrs["acse"])
	assert.Equal(t, "1.0.9506.2.3", req.Attrs["application_context"],
		"the MMS application context is what IEC 61850 names")
	assert.Equal(t, "1.1.1.999.1", req.Attrs["called_ap_title"])
	assert.Equal(t, "1.1.1.999", req.Attrs["calling_ap_title"])
	assert.Equal(t, "12", req.Attrs["called_ae_qualifier"])
	assert.Equal(t, "12", req.Attrs["calling_ae_qualifier"])
	assert.Equal(t, "65280", req.Attrs["max_pdu_size"])
	assert.Equal(t, "1", req.Attrs["mms_version"])
	assert.Equal(t, model.ClassOther, req.Class)
	assert.NotContains(t, req.Attrs, "anomaly")

	res := parseOne(t, model.DirResponse, frame(t, frameAssociateResponse))
	assert.Equal(t, "initiate-Response", res.Operation)
	assert.Equal(t, "ACCEPT", res.Attrs["session"])
	assert.Equal(t, "AARE", res.Attrs["acse"])
	assert.Equal(t, "accepted", res.Attrs["result"])
	assert.Equal(t, "1.1.1.999.1", res.Attrs["responding_ap_title"])
	assert.Equal(t, "49152", res.Attrs["max_pdu_size"])
	assert.NotContains(t, res.Attrs, "anomaly")
}

// Identify is the one service where a device describes itself, which makes it
// the enrichment source for MMS, as Read Device Identification is for Modbus
// and an SZL read is for S7.
func TestIdentifyGivesDeviceIdentity(t *testing.T) {
	req := parseOne(t, model.DirRequest, frame(t, frameIdentifyRequest))
	assert.Equal(t, "identify", req.Operation)
	assert.Equal(t, model.ClassDiscovery, req.Class)
	assert.Equal(t, 2, req.FunctionCode)
	assert.Equal(t, "1", req.Attrs["invoke_id"])
	assert.Empty(t, req.Identity, "the request carries no identity, only the question")
	assert.NotContains(t, req.Attrs, "object", "identify names no object")

	res := parseOne(t, model.DirResponse, frame(t, frameIdentifyResponse))
	assert.Equal(t, "identify", res.Operation)
	assert.Equal(t, model.ClassDiscovery, res.Class)
	assert.Equal(t, map[string]string{
		"vendor_name": "INFO TECH",
		"model_name":  "S61850 for PC",
		"revision":    "0.0.1",
	}, res.Identity)
	assert.NotContains(t, res.Attrs, "object",
		"a vendor string in a reply is not an object the client addressed")
}

func TestServices(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		dir      model.Direction
		op       string
		code     int
		class    model.Classification
		quantity *uint32
		attrs    map[string]string
		identity map[string]string
		absent   []string
	}{
		{
			name: "read of a report control block", in: frameRead, dir: model.DirRequest,
			op: "read", code: 4, class: model.ClassRead,
			attrs: map[string]string{
				"invoke_id": "303732",
				"object":    "AA1E1Q01FP2LD0/LLN0$BR$rcb_B02",
				"domain":    "AA1E1Q01FP2LD0",
				"item":      "LLN0$BR$rcb_B02",
			},
			identity: map[string]string{"logical_device": "AA1E1Q01FP2LD0"},
		},
		{
			name: "attributes of the same object", in: frameGetVariableAccessAttributes,
			dir: model.DirRequest, op: "getVariableAccessAttributes", code: 6, class: model.ClassRead,
			attrs: map[string]string{
				"invoke_id": "303731",
				"object":    "AA1E1Q01FP2LD0/LLN0$BR$rcb_B02",
				"domain":    "AA1E1Q01FP2LD0",
			},
			identity: map[string]string{"logical_device": "AA1E1Q01FP2LD0"},
		},
		{
			name: "write to a nameplate attribute", in: frameWrite, dir: model.DirRequest,
			op: "write", code: 5, class: model.ClassWrite,
			attrs: map[string]string{
				"invoke_id": "0",
				"object":    "ACTSETGGIO80$DC$NamPlt$vendor",
			},
			// A device-wide name has no domain, so there is no logical device
			// to learn from it.
			absent: []string{"domain", "item"},
		},
		{
			name: "status", in: frameStatusRequest, dir: model.DirRequest,
			op: "status", code: 0, class: model.ClassRead,
			attrs:  map[string]string{"invoke_id": "2"},
			absent: []string{"object"},
		},
		{
			name: "stop a program invocation", in: frameRawStop, dir: model.DirRequest,
			op: "stop", code: 41, class: model.ClassControl,
			attrs: map[string]string{
				"invoke_id": "1",
				"object":    "R395024397Application_1",
				"stack":     "cotp",
			},
			absent: []string{"session", "presentation"},
		},
		{
			name: "start it again", in: frameRawStart, dir: model.DirRequest,
			op: "start", code: 40, class: model.ClassControl,
			attrs: map[string]string{"object": "R395024397Application_1"},
		},
		{
			name: "take control of a semaphore", in: frameRawTakeControl, dir: model.DirRequest,
			op: "takeControl", code: 19, class: model.ClassControl,
			attrs: map[string]string{"object": "reserved"},
		},
		{
			name: "open a download into a domain", in: frameRawDownload, dir: model.DirRequest,
			op: "initiateDownloadSequence", code: 26, class: model.ClassProgram,
			attrs:    map[string]string{"object": "DTLogFilesDomain"},
			identity: map[string]string{"logical_device": "DTLogFilesDomain"},
		},
		{
			name: "conclude the association", in: frameConcludeRequest, dir: model.DirRequest,
			op: "conclude-Request", code: -1, class: model.ClassOther,
			attrs:  map[string]string{"pdu": "conclude-Request"},
			absent: []string{"service"},
		},
		{
			name: "release it", in: frameReleaseRequest, dir: model.DirRequest,
			op: "RLRQ", code: -1, class: model.ClassOther,
			attrs: map[string]string{"session": "FINISH", "acse": "RLRQ"},
		},
		{
			name: "and the server agrees", in: frameReleaseResponse, dir: model.DirResponse,
			op: "RLRE", code: -1, class: model.ClassOther,
			attrs: map[string]string{"session": "DISCONNECT", "acse": "RLRE"},
		},
		{
			name: "initiate over a bare COTP connection", in: frameRawInitiate,
			dir: model.DirRequest, op: "initiate-Request", code: -1, class: model.ClassOther,
			attrs: map[string]string{"stack": "cotp", "max_pdu_size": "31", "mms_version": "1"},
		},
		{
			name: "conclude over a bare COTP connection", in: frameRawConclude,
			dir: model.DirRequest, op: "conclude-Request", code: -1, class: model.ClassOther,
			attrs: map[string]string{"stack": "cotp"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := parseOne(t, tc.dir, frame(t, tc.in))
			assert.Equal(t, "mms", ev.Protocol)
			assert.Equal(t, tc.op, ev.Operation)
			assert.Equal(t, tc.code, ev.FunctionCode)
			assert.Equal(t, tc.class, ev.Class)
			assert.Equal(t, tc.quantity, ev.Quantity)
			assert.False(t, ev.Malformed, "error: %s", ev.Error)
			for k, want := range tc.attrs {
				assert.Equal(t, want, ev.Attrs[k], "attribute %q", k)
			}
			for _, k := range tc.absent {
				assert.NotContains(t, ev.Attrs, k)
			}
			if tc.identity != nil {
				for k, want := range tc.identity {
					assert.Equal(t, want, ev.Identity[k], "identity %q", k)
				}
			}
		})
	}
}

// A server pushing reports never has to be asked anything, so the reference it
// puts in the first access result is all a passive observer gets — and it
// names the logical device the substation configuration gave the IED.
func TestInformationReportCarriesItsReference(t *testing.T) {
	ev := parseOne(t, model.DirResponse, frame(t, frameInformationReport))
	assert.Equal(t, "informationReport", ev.Operation)
	assert.Equal(t, 0, ev.FunctionCode)
	assert.Equal(t, model.ClassRead, ev.Class)
	assert.Equal(t, model.DirResponse, ev.Direction)
	assert.Equal(t, "RPT", ev.Attrs["object"], "reports are delivered under the device-wide list")
	assert.Equal(t, "AA1C1Q01A1LD0/LLN0$rcb_I02", ev.Attrs["report_id"])
	assert.Equal(t, "AA1C1Q01A1LD0", ev.Identity["logical_device"])
	assert.Nil(t, ev.TransactionID, "an unsolicited report answers no request")
}

// A server refusing a request is the protocol's own error reply, and within
// the access class the code separates "no such object" from "you may not have
// it", which is the difference between a misconfigured client and one reaching
// for what it should not.
func TestAccessDeniedIsAnException(t *testing.T) {
	ev := parseOne(t, model.DirResponse, frame(t, frameAccessDenied))
	assert.Equal(t, "confirmed-Error", ev.Operation)
	assert.Equal(t, "access/object-access-denied", ev.Exception)
	assert.Equal(t, "access/object-access-denied", ev.Attrs["error"])
	require.NotNil(t, ev.TransactionID)
	assert.Equal(t, uint32(303731), *ev.TransactionID, "the error names the request it answers")
	assert.False(t, ev.Malformed, "a refusal is a well formed answer")
}

// IEC 61850 sends an association password in the clear. The fact that one was
// sent is evidence; the value is not something this tool should store and
// render back.
func TestAuthenticationValueIsNotRecorded(t *testing.T) {
	// An AARQ carrying a mechanism name and a password, built here because
	// the public captures use no authentication.
	const password = "s3cret-substation"
	value := "80" + hexLen(len(password)) + hex.EncodeToString([]byte(password))
	body := "a107060528ca220203" + // application-context-name
		"8b0606042bce0f02" + // mechanism-name
		"ac" + hexLen(len(value)/2) + value // calling-authentication-value
	aarq := "60" + hexLen(len(body)/2) + body

	ev := parseOne(t, model.DirRequest, frame(t, wrapDataTransfer(t, 1, aarq)))
	assert.Equal(t, "AARQ", ev.Operation)
	assert.Equal(t, "password", ev.Attrs["authentication"],
		"that authentication was offered is worth recording")
	for k, v := range ev.Attrs {
		assert.NotContains(t, v, password, "attribute %q must not carry the password", k)
	}
	for k, v := range ev.Identity {
		assert.NotContains(t, v, password, "identity %q must not carry the password", k)
	}
	assert.NotContains(t, ev.Error, password)
}

// Encodings that are off-spec but in the field are read rather than refused,
// and the discrepancy is reported rather than passed off as normal.
func TestOffSpecEncodingsAreFlagged(t *testing.T) {
	ev := parseOne(t, model.DirResponse, frame(t, frameOffSpecAccept))
	assert.Equal(t, "initiate-Response", ev.Operation)
	assert.Equal(t, "accepted", ev.Attrs["result"])
	assert.Contains(t, ev.Attrs["anomaly"], "session_user_data_not_declared")
	assert.False(t, ev.Malformed, "the content was readable")

	truncated := parseOne(t, model.DirResponse, frame(t, frameTruncatedResponse))
	assert.Equal(t, "confirmed-Response", truncated.Operation)
	assert.Contains(t, truncated.Attrs["anomaly"], "truncated_pdu")
}

func TestParseMalformed(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		op     string
		reason string
	}{
		{
			name: "COTP length indicator of zero", in: frameBrokenServerReply,
			op: "COTP", reason: "length indicator is zero",
		},
		{
			name: "COTP header runs past the frame", in: "0300000602ff",
			op: "COTP", reason: "runs past the 6 octet frame",
		},
		{
			name: "undefined COTP PDU type", in: "0300000702aa80", op: "COTP",
			reason: "not defined",
		},
		{
			name: "session PDU with nothing in it", in: "0300000802f0800d", op: "Session",
			reason: "cannot hold an SPDU header",
		},
		{
			name: "MMS PDU with an indefinite length", in: "0300000902f080a080",
			op: "MMS", reason: "indefinite length",
		},
		{
			name: "MMS PDU declaring more than it carries", in: "0300000a02f080a07f0201",
			op: "MMS", reason: "element declares",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events, err := mms.New().Parse(ctxFor(model.DirRequest), frame(t, tc.in))
			require.Error(t, err)
			assert.True(t, errors.Is(err, dissect.ErrMalformed), "got %v", err)
			require.Len(t, events, 1, "a malformed frame is still evidence")
			assert.True(t, events[0].Malformed)
			assert.Equal(t, tc.op, events[0].Operation)
			assert.Contains(t, events[0].Error, tc.reason)
		})
	}

	// An MMS PDU has to open with a context tag; every alternative of the
	// MMSpdu CHOICE is one.
	t.Run("MMS PDU opening with a universal tag", func(t *testing.T) {
		events, err := mms.New().Parse(ctxFor(model.DirRequest),
			frame(t, wrapDataTransfer(t, 3, "30030201ff")))
		require.Error(t, err)
		assert.True(t, errors.Is(err, dissect.ErrMalformed), "got %v", err)
		require.Len(t, events, 1)
		assert.True(t, events[0].Malformed)
		assert.Contains(t, events[0].Error, "not a context tag")
	})
}

// Nothing in a frame may be trusted, so every prefix of every fixture has to
// come back as an event or an error, never a panic.
func TestParseNeverPanicsOnTruncation(t *testing.T) {
	d := mms.New()
	for _, fixture := range []string{
		frameConnectRequest, frameAssociateRequest, frameAssociateResponse,
		frameIdentifyResponse, frameInformationReport, frameRead, frameWrite,
		frameAccessDenied, frameRawStart, frameRawDownload, frameOffSpecAccept,
		frameReleaseRequest,
	} {
		raw := frame(t, fixture)
		for i := range len(raw) + 1 {
			ctx := ctxFor(model.DirRequest)
			assert.NotPanics(t, func() { _, _ = d.Parse(ctx, raw[:i]) }, "parse at %d", i)
			assert.NotPanics(t, func() { _ = d.Probe(ctx, raw[:i]) }, "probe at %d", i)
			assert.NotPanics(t, func() { _ = d.ProbeDefers(raw[:i]) }, "defers at %d", i)
			assert.NotPanics(t, func() { _, _ = d.PDULen(raw[:i]) }, "framer at %d", i)
		}
	}
}

// A BER blob nested without end must cost no more than reading it.
func TestDeeplyNestedBERIsBounded(t *testing.T) {
	// 400 levels of constructed context tag 0, far past anything IEC 61850
	// produces.
	const levels = 400
	body := ""
	for range levels {
		body = "a0" + hexLen(len(body)/2) + body
	}
	raw := frame(t, "03"+"00"+hexLen16(4+3+len(body)/2)+"02f080"+body)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = mms.New().Parse(ctxFor(model.DirRequest), raw)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("parsing a deeply nested PDU did not finish")
	}
}

// CLAUDE.md's rule on MMS writes to control objects matches on the
// classification, and the S7 rules on program download and CPU stop have MMS
// counterparts that have to carry the same ones.
func TestSecurityRelevantServicesAreClassified(t *testing.T) {
	tests := []struct {
		service uint32
		name    string
		class   model.Classification
	}{
		{5, "write", model.ClassWrite},
		{40, "start", model.ClassControl},
		{41, "stop", model.ClassControl},
		{42, "resume", model.ClassControl},
		{43, "reset", model.ClassControl},
		{44, "kill", model.ClassControl},
		{19, "takeControl", model.ClassControl},
		{20, "relinquishControl", model.ClassControl},
		{26, "initiateDownloadSequence", model.ClassProgram},
		{27, "downloadSegment", model.ClassProgram},
		{29, "initiateUploadSequence", model.ClassProgram},
		{36, "deleteDomain", model.ClassProgram},
		{38, "createProgramInvocation", model.ClassProgram},
		{39, "deleteProgramInvocation", model.ClassProgram},
		{76, "fileDelete", model.ClassProgram},
		{4, "read", model.ClassRead},
		{2, "identify", model.ClassDiscovery},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := parseOne(t, model.DirRequest, frame(t, serviceRequest(t, tc.service)))
			assert.Equal(t, tc.name, ev.Operation)
			assert.Equal(t, int(tc.service), ev.FunctionCode)
			assert.Equal(t, tc.class, ev.Class)
			assert.True(t, ev.Class.Valid())
		})
	}
}

// A service tag the standard does not define is reported as unknown rather
// than guessed at.
func TestUnknownServiceIsReported(t *testing.T) {
	ev := parseOne(t, model.DirRequest, frame(t, serviceRequest(t, 99)))
	assert.Equal(t, "service99", ev.Operation)
	assert.Equal(t, 99, ev.FunctionCode)
	assert.Equal(t, model.ClassOther, ev.Class)
	assert.NotContains(t, ev.Attrs, "anomaly")
}

// BER lets a context tag run to five figures. Such a tag is not a service, so
// it is not put in the column that holds every other protocol's function
// code, where it would read as one.
func TestServiceTagBeyondOneOctetIsNotAFunctionCode(t *testing.T) {
	ev := parseOne(t, model.DirRequest, frame(t, serviceRequest(t, 1840)))
	assert.Equal(t, "service1840", ev.Operation)
	assert.Equal(t, -1, ev.FunctionCode)
	assert.Equal(t, "1840", ev.Attrs["service_tag"])
	assert.Equal(t, "service_tag_out_of_range", ev.Attrs["anomaly"])
}

// serviceRequest builds a confirmed request for one service, carrying a
// single identifier so that every service's name decoding is exercised.
func serviceRequest(t *testing.T, svc uint32) string {
	t.Helper()
	const name = "OBJ"
	inner := "80" + hexLen(len(name)) + hex.EncodeToString([]byte(name))
	body := contextTag(0xa0, svc, inner)
	pdu := "a0" + hexLen(3+len(body)/2) + "020107" + body
	return wrapDataTransfer(t, 3, pdu)
}

// contextTag encodes a constructed context tag, using the high tag number
// form above 30 the way MMS does for its later services.
func contextTag(base byte, number uint32, body string) string {
	switch {
	case number < 31:
		return hex.EncodeToString([]byte{base | byte(number)}) + hexLen(len(body)/2) + body
	case number < 128:
		return hex.EncodeToString([]byte{base | 0x1f, byte(number)}) + hexLen(len(body)/2) + body
	default:
		return hex.EncodeToString([]byte{
			base | 0x1f, byte(number>>7) | 0x80, byte(number & 0x7f),
		}) + hexLen(len(body)/2) + body
	}
}

// wrapDataTransfer puts a PDU inside a session data transfer and a
// presentation user-data element, the way a live association carries it.
func wrapDataTransfer(t *testing.T, context int, pdu string) string {
	t.Helper()
	single := "a0" + hexLen(len(pdu)/2) + pdu
	ctxID := "0201" + hex.EncodeToString([]byte{byte(context)})
	seq := "30" + hexLen(len(ctxID)/2+len(single)/2) + ctxID + single
	fed := "61" + hexLen(len(seq)/2) + seq
	session := "01000100" + fed
	cotp := "02f080" + session
	return "0300" + hexLen16(4+len(cotp)/2) + cotp
}

func hexLen(n int) string {
	if n < 0x80 {
		return hex.EncodeToString([]byte{byte(n)})
	}
	if n < 0x100 {
		return hex.EncodeToString([]byte{0x81, byte(n)})
	}
	return hex.EncodeToString([]byte{0x82, byte(n >> 8), byte(n)})
}

func hexLen16(n int) string {
	return hex.EncodeToString([]byte{byte(n >> 8), byte(n)})
}
