# Test capture provenance

Only public sample captures belong here (see CLAUDE.md, "Test data"). Never
commit captures from real customer or production environments.

| File | Bytes | SHA-256 |
|------|-------|---------|
| `modbus_test_data_part1.pcap` | 10181 | `94942b3d014810710f50836c95d3faf6df6e6370a6560bae541397c1df50213d` |
| `modbus_test_data_part2.pcap` | 27764 | `f7cca627fe9b740b5881e8b33b4143b59158240192ecbf5caa727a7dda35d110` |
| `dnp3_test_data_part1.pcap` | 15838 | `71779cac342a37b412df5bb6372ec22c35b5127ad2bfed4447d7ab6b92ebb4bf` |
| `dnp3_test_data_part2.pcap` | 2976 | `cb7de30363a64f1a6d3b7332f78d937a1f05677e546db0ad2790b2c481a7bc4b` |
| `s7comm_varservice_libnodavedemo.pcap` | 2846 | `a1ff275c087fafbfdc8821ea59ab9bfb11f5adcc9ce6bb5888a1c4a4d7b6affc` |
| `s7comm_downloading_block_db1.pcap` | 9523 | `48725bd1af7b778821351cd0f50f0ee259e438074a27f8431a8a1a3351dfd3d0` |
| `s7comm_reading_plc_status.pcap` | 25112 | `e71f81b471bd67da2fd6e40dc69a7179574ba66771c6150cd7bfe232cc07b8a9` |
| `iec104_test_dissect.pcap` | 11409 | `292c18a8765db3b1bcaa9bd0b8455e4e61b8366cc5910a7363b7381eb11441b8` |
| `iec104_diverse_commands.pcap` | 13952 | `07b9a0879dc83e420c4cf83b37fb5830d1d8fb5f6ac6edc435896f70b0fc6bc7` |
| `iec61850_mms_reports.pcap` | 43379 | `50e405f9dbca335dcf457424a8e8ad04caa6fc85b81671e7ddb5ba8a99567c30` |
| `iec61850_mms_identify.pcap` | 838 | `5e6d24a3729c1ca69aabd4c3da3d5d9d158e06b0b10c2e6d9399e64622293a0a` |
| `iec61850_mms_write.pcap` | 2970 | `10a45e74f8fd5cf06055b8b18ee9598c2bfb09ba9222348cb35eb708c9659a56` |
| `iec61850_mms_program_control.pcap` | 1906 | `b5a55177b2344dbe5c95263bd31b78797776c62b334642140f91bd8a79097e63` |
| `iec61850_mms_download.pcap` | 1905 | `9d9a836a8e308dfedd6b565e7ee98c98fdc3061e88fc4d7536a22299a7a0e0e0` |
| `iec61850_goose_interlocking.pcap` | 117736 | `7d0ab6ea4580e337e399878ee4c244c69df78c48a5310087d9636fab677c8293` |
| `iec61850_goose_ge_relay.pcap` | 1420 | `746619df546905feb6f1217ee40750004a1ca1d85fe7be1740bacdf52dca6850` |
| `iec61850_goose_minimal.pcap` | 166 | `41cb05f4c7843b884ab40fb503471fba7a5f09ee1ffebc441da7cfcdab6877b7` |

## Origin

Both files come from the **Digital Bond "Quickdraw" SCADA IDS** sample captures,
a long-published public ICS dataset. They are mirrored in several public
collections; these copies were taken from:

- <https://github.com/ITI/ICS-Security-Tools> — `pcaps/quickdraw/`

The same `part1` file is mirrored in <https://github.com/automayt/ICS-pcap>
(`MODBUS/MODBUS-TestDataPart1/`) under Git LFS; its LFS object id is the
identical SHA-256 `94942b3d…`, which cross-confirms these bytes.

## What they contain

Classic libpcap format, linktype 1 (Ethernet), Modbus/TCP on port 502.

`modbus_test_data_part1.pcap` — 118 packets, realistic operator traffic plus
deliberately malformed frames. Useful because it covers, in one small file:

- FC 1 Read Coils, FC 3 Read Holding Registers, FC 5 Write Single Coil,
  FC 6 Write Single Register, FC 7 Read Exception Status
- FC 8 Diagnostics, sub-function 0x0004 (Force Listen Only Mode), 0x0001
  (Restart Communications Option) and 0x000A (Clear Counters)
- FC 17 Report Server ID, whose response carries the ASCII device identity
  `Wingpath Limited` (asset enrichment evidence)
- FC 43 / MEI 14 Read Device Identification requests
- Exception responses: 0x05 Acknowledge, 0x06 Server Device Busy,
  0x0B Gateway Target Device Failed To Respond
- An MBAP header with a bogus length field (34820) that far exceeds both the
  segment and the protocol maximum
- An MBAP header with a non-zero protocol identifier (16)
- An undefined function code (42)

`modbus_test_data_part2.pcap` — a sweep of function codes 1 through 127 with
matching exception responses. It exercises the function-code table, the
reserved/unknown-code path and exception decoding.

`dnp3_test_data_part1.pcap` — 93 DNP3 link frames on port 20000 across eight
connections. It covers, between them, most of what CLAUDE.md names as DNP3
detection rules:

- COLD_RESTART and WARM_RESTART of an outstation
- STOP_APPL, which halts the outstation's application
- DISABLE_UNSOLICITED and ENABLE_UNSOLICITED, which hide or restore event
  reporting to the master
- WRITE of time (group 50), READ of class data (group 60), unsolicited
  responses carrying events (group 51), internal indications (group 80)
- two frames whose first start octet is 0x05 but whose second is 0x05 rather
  than 0x64, a corruption that breaks framing and must be reported

`dnp3_test_data_part2.pcap` — a select-before-operate sequence against a
control relay output block (group 12 variation 1), with the outstation
rejecting each one, and reads of object group 255, which does not exist. It
exercises control decoding, internal indication flags and the unknown-group
path.

## S7comm captures

The three `s7comm_*.pcap` files are the long-published S7comm sample captures
that accompany the Wireshark s7comm dissector; these copies came from the same
public collection as the files above (`pcaps/s7/`), and their filenames and
contents match that sample set.

`s7comm_varservice_libnodavedemo.pcap` — 18 frames of the variable services:
an ISO connection to rack 0 slot 2, the PDU size negotiation, then a read of
DB1 and reads and writes of flag memory. Small enough to reason about by hand.

`s7comm_downloading_block_db1.pcap` — a block download: REQUEST_DOWNLOAD,
DOWNLOAD_BLOCK, DOWNLOAD_ENDED and the PLC_CONTROL `_INSE` service that
activates the block afterwards. This is the traffic behind CLAUDE.md's rule on
S7 program download.

`s7comm_reading_plc_status.pcap` — 218 frames of SZL reads, which is how STEP 7
asks a CPU what it is. It carries the two lists CLAUDE.md names as the S7
enrichment source: list 0x0011 with the Siemens order number and the firmware
version, and list 0x001C with the CPU model, its serial number and the station
name. The device is an IM151-8 PN/DP CPU, order number 6ES7 151-8AB01-0AB0,
firmware V3.2.6, serial S C-C6TW74882012.

It also holds two things a dissector has to take in its stride: COTP data
frames with no payload at all, which STEP 7 sends as keep-alives, and an SZL
reply that is only one data unit of a longer list.

## IEC 60870-5-104 captures

The two `iec104_*.pcap` files came from the same public collection as the files
above (`pcaps/IEC60870-5-104/`), where they are published as
`TestDissectIec104.pcap` and `090813_diverse.pcap`. They are renamed here after
what they hold.

`iec104_test_dissect.pcap` — 147 packets over six connections to port 2404,
carrying 57 APDUs: 26 unnumbered control functions, 12 supervisory frames and
19 information frames, all for common address 37133. Between the APDUs it
injects 17 payloads of filler — runs of a repeated byte around a 0x68 with a
length too short to be an APDU — which is what the file is for: a dissector
has to report each one and then find the next real frame, without inventing
frames out of the filler or losing the rest of the connection. Its ASDUs cover
end of initialisation, general interrogation with its confirmation and
termination, single and double points answering it in a sequence, a time
tagged single point, single and double commands with select and execute, and
clock synchronisation. It also carries the three things that make a reply a
refusal: a negative confirmation, one marked as test traffic, and an
activation with the negative bit set, which the standard leaves undefined in
the control direction.

`iec104_diverse_commands.pcap` — 173 packets of one connection carrying 86
APDUs for common address 3, which is where the command family lives:
single, double and set point commands — C_SC_NA_1, C_DC_NA_1 and C_SE_NC_1 —
with the time tagged C_SC_TA_1, C_DC_TA_1, C_SE_TC_1 and C_SE_TA_1 alongside
them, and measured values and single points reported in between. This is the
traffic behind CLAUDE.md's rule on IEC 104 control commands from unexpected
sources. Eight of its ten commands are issued select-before-operate and two
directly, so it exercises both. Three further things in it are worth knowing:
both endpoints are 10.0.0.10, so the capture is a simulator talking to itself
and its two assets merge into one; the capture starts mid-session with no
handshake, which is what a capture from the field usually looks like; and the
time tags of its commands carry the year less 1900 rather than modulo 100,
which the standard does not allow and which the dissector reports as an
anomaly. One stray NetBIOS datagram is Windows background noise.

## IEC 61850 MMS captures

The five `iec61850_mms_*.pcap` files came from the same public collection as
the files above (`pcaps/IEC61850/`), where they are published as
`Sample_File_MMS_and_GOOSE.pcap`, `piccolo.pcap`, `iec`,
`MMS - Specific Commands/mms-startRequest.pcap` and
`MMS - Specific Commands/mms-initiateDownloadSequence.pcap`. That directory
records them as taken from the pcapr.net MMS collection. They are renamed here
after what they hold.

`iec61850_mms_reports.pcap` — 43 KB of substation traffic from four IEDs to
one client, and the primary MMS capture. Twenty-eight information reports
carry the references of the report control blocks that sent them, which is
where the logical device names come from: `AA1C1Q01A1LD0`, `AA1C1Q01FP1LD0`,
`AA1C1Q01FP2LD0` and `AA1QBQBBFP1ABB05`. One association is recorded whole —
transport connection, session CONNECT, presentation CP, AARQ and AARE,
requests, orderly conclude and ACSE release — and inside it the client asks a
fifth IED for the attributes of `AA1E1Q01FP2LD0/LLN0$BR$rcb_B02`, is refused
with an access error, and reads the object instead. It also holds file sharing
traffic on port 139 and GOOSE frames on EtherType 0x88B8, which nothing claims
yet, so it doubles as proof that this dissector does not reach beyond its own
streams.

`iec61850_mms_identify.pcap` — five frames of an association in which the
client asks the device what it is. The answer names the vendor `INFO TECH`,
the model `S61850 for PC` and the revision `0.0.1`, which is the identity
source CLAUDE.md names for MMS. Its AARQ and AARE also carry application
process titles and application entity qualifiers on both sides, which the
substation captures leave out.

`iec61850_mms_write.pcap` — a write to `ACTSETGGIO80$DC$NamPlt$vendor`, the
vendor attribute of a generic I/O logical node, which is the traffic behind
CLAUDE.md's rule on MMS writes. It is also the awkward one: the first of its
four streams begins mid-session with no handshake, its accepts declare the
user data parameter empty and then send it anyway, their parameter fields
overrun the frame by an octet, and one response declares one octet more than
it carries. All four are off-spec, all four are readable, and the dissector
reports each rather than passing it off as normal.

`iec61850_mms_program_control.pcap` and `iec61850_mms_download.pcap` — two
exchanges that put MMS straight on top of COTP, with no session, presentation
or association layer at all, which is a shape a dissector has to read as
readily as the full stack. The first stops and then starts the program
invocation `R395024397Application_1`; the second takes control of a semaphore
and opens a download into the domain `DTLogFilesDomain`. Between them they
cover what CLAUDE.md's S7 rules name — CPU stop and start, program download —
under the MMS names for the same operations. Every one of the server's replies
in both files declares a TPKT length that counts only its own header, so they
are the hostile framing material as well.

## IEC 61850 GOOSE captures

The three `iec61850_goose_*.pcap` files came from the same public collection
as the files above (`pcaps/IEC61850/GOOSE/`), where they are published as
`Sample_File_GOOSE.pcap`, `GOOSE.pcap` and `GOOSE_DEMO.pcap`. They are
renamed here after what they hold. `iec61850_mms_reports.pcap`, listed above,
carries 34 GOOSE frames of its own alongside its MMS traffic.

`iec61850_goose_interlocking.pcap` — 451 frames and nothing else, from three
bay controllers publishing interlocking data sets of 25 entries to
01:0c:cd:01:00:00 on a priority tagged VLAN. 252 of them report a state
change and 199 are the repeats between changes, and the three publishers'
state numbers interleave across the capture without any of them skipping,
which is what makes it the test that the counters are tracked per publisher
rather than per segment. Its publishers all report an unsynchronised clock,
which is a standing condition of the installation rather than a fault.

`iec61850_goose_ge_relay.pcap` — eight frames from a GE F650 relay,
publishing `GEDeviceF650/LLN0$GO$gcb01` to a vendor multicast address of its
own rather than the one IEC 61850 assigns, and with no VLAN tag: two shapes a
dissector must take as readily as the standard one. It is also two bursts of
the same control block spliced together, so the sequence number goes
backwards once while the state number never moves — a replayed frame looks
exactly like that, and it is the one anomaly in the GOOSE captures that comes
from real traffic rather than being crafted for a test.

`iec61850_goose_minimal.pcap` — one frame, and the smallest shape in the
samples. Its control block, data set and identifier are `111`, `222` and
`333`, which are not object references at all, so nothing can be learnt about
the publisher from them: it is the test that a name with no logical device in
it yields no identity rather than a made-up one.
