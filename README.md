# otinv

Passive OT/ICS asset inventory from packet captures.

`otinv` builds an asset inventory, communication matrix and network topology for
OT/ICS environments from **packet captures only**, identifying devices and
industrial protocols and flagging anomalies such as write or control commands
from unexpected sources.

**The tool is strictly passive.** It never sends packets, never opens a
connection toward an analysed host and never fingerprints, scans or polls
anything. It reads capture files, nothing else. See `CLAUDE.md` for the full
design and the complete protocol roadmap.

## Status

This repository currently holds the first vertical slice of that design: the
ingest pipeline, the dissector registry and the **Modbus/TCP** dissector,
developed test-first against public sample captures.

| Component | State |
|-----------|-------|
| `internal/ingest` — pcap/pcapng reading, L2–L4 decode, VLAN/QinQ, TCP reassembly, PDU framing | done |
| `internal/dissect` — `Dissector` contract, registry, port and heuristic binding, panic recovery, parse health | done |
| `internal/dissect/modbus` — Tier 1 Modbus/TCP | done |
| `cmd/otinv analyze` — decode a capture and report endpoints, operations and anomalies | done |
| `internal/store` (SQLite), `internal/web` (GUI), `internal/inventory`, `internal/topology`, `internal/rules` | not started |
| Remaining Tier 1/2/3 protocols | not started |

Because the store is not built yet, `analyze` prints its report instead of
persisting it, and there is no `serve` command.

## Quickstart

```sh
make build
bin/otinv analyze testdata/pcaps/modbus_test_data_part1.pcap
bin/otinv analyze testdata/pcaps/*.pcap --json --events > report.json
```

Output on the bundled sample capture names the two Modbus servers, the unit ids
behind them, the vendor string the devices reported, and the crafted frames in
the capture:

```
endpoints
  10.0.0.3:502  modbus
    unit ids    10
    clients     10.0.0.57, 10.0.0.9
    identity    report_server_id = Wingpath Limited
    operations  Diagnostics=16 ReadCoils=4 ReportServerID=4 ...
    classes     control=8 diagnostic=8 read=6 write=6 discovery=4
    exceptions  GatewayTargetDeviceFailedToRespond=4
```

Copy `otinv.example.yaml` to `otinv.yaml` to add non-standard ports. Protocols
are also detected heuristically, so an unlisted port is still found.

## What the Modbus dissector decodes

Modbus/TCP per the MODBUS Application Protocol Specification v1.1b3 and the
Messaging on TCP/IP Implementation Guide v1.0b:

- every public function code, with the user-defined (65–72, 100–110) and
  reserved (9, 10, 13, 14, 41, 42, 90, 91, 125–127) ranges named as such
- addresses and quantities for reads and writes, in requests and responses
- exception replies with their exception code names
- FC 8 diagnostics down to the sub-function, with **Force Listen Only Mode**
  and **Restart Communications Option** classified as `control` rather than as
  read-only diagnostics, because they change how the device behaves on the bus
- device identity for the inventory: FC 17 Report Server ID (vendor string, run
  indicator) and FC 43 / MEI 14 Read Device Identification objects
- anomalies kept as evidence rather than dropped: a non-zero MBAP protocol
  identifier, trailing bytes inside a frame, undefined function codes

Every function code maps to the shared classification set (`read`, `write`,
`control`, `program`, `firmware`, `diagnostic`, `discovery`, `other`) so that
detection rules never have to know raw protocol numbers.

## Development

```sh
make test              # unit, golden and reassembly tests
make fuzz              # short fuzz run for every dissector
make lint              # go vet + golangci-lint
make test-update       # regenerate testdata/golden (review the diff!)
make ci                # generate + lint + test
```

Tests use only public sample captures, described with their provenance and
SHA-256 in [`testdata/pcaps/PROVENANCE.md`](testdata/pcaps/PROVENANCE.md), or
traffic crafted in the test with gopacket serialization. Never commit captures
from real customer or production environments.

### Hostile input

Capture bytes are treated as hostile throughout. Every length field is checked
against both the protocol maximum and the bytes actually present, dissectors
never panic (the registry recovers and counts it as a bug if one does), and
per-stream buffers are capped. `FuzzParse` covers the Modbus dissector; a
45 second run over 1.3 million inputs found no crash and no invariant
violation.

### Known limitations

- A sender whose MBAP length field disagrees with what it actually transmits
  desynchronises its stream. Resynchronisation requires the next candidate
  frame to look convincingly like the protocol, so the frame right after the
  broken one is reported as a `FramingError` rather than decoded. This is
  visible in `modbus_test_data_part1.pcap`, which contains such a sender.
- The ingest throughput target in `CLAUDE.md` (≥ 200k packets/s) has not been
  benchmarked yet; the decode path avoids per-packet allocation but no
  benchmark proves the number.
- IPv6 extension headers are not walked, so such packets are counted as non-IP.
- Only Ethernet link type captures are accepted.
