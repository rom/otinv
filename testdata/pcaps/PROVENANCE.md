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
