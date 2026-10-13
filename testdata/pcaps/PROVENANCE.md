# Test capture provenance

Only public sample captures belong here (see CLAUDE.md, "Test data"). Never
commit captures from real customer or production environments.

| File | Bytes | SHA-256 |
|------|-------|---------|
| `modbus_test_data_part1.pcap` | 10181 | `94942b3d014810710f50836c95d3faf6df6e6370a6560bae541397c1df50213d` |
| `modbus_test_data_part2.pcap` | 27764 | `f7cca627fe9b740b5881e8b33b4143b59158240192ecbf5caa727a7dda35d110` |
| `dnp3_test_data_part1.pcap` | 15838 | `71779cac342a37b412df5bb6372ec22c35b5127ad2bfed4447d7ab6b92ebb4bf` |
| `dnp3_test_data_part2.pcap` | 2976 | `cb7de30363a64f1a6d3b7332f78d937a1f05677e546db0ad2790b2c481a7bc4b` |

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
