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

This repository holds the first two slices of that design: the decode path
(ingest, dissector registry, Modbus/TCP) and the storage and GUI path that
makes a capture browsable. Both were developed test first against public
sample captures.

| Component | State |
|-----------|-------|
| `internal/ingest` — pcap/pcapng reading, L2–L4 decode, VLAN/QinQ, TCP reassembly, PDU framing | done |
| `internal/dissect` — `Dissector` contract, registry, port and heuristic binding, panic recovery, parse health | done |
| `internal/dissect/modbus` — Tier 1 Modbus/TCP | done |
| `internal/store` — SQLite (pure Go), embedded migrations, batched event writes, asset queries | done |
| `internal/inventory` — asset identity and merge, gateway detection, role inference, identity enrichment | done |
| `internal/web` — GUI: asset list with server-side filtering and paging, asset detail, captures | done |
| `cmd/otinv` — `analyze`, `serve`, `version` | done |
| `internal/topology`, `internal/rules`, `internal/baseline`, `internal/export` | not started |
| Remaining Tier 1/2/3 protocols | not started |

The GUI has no authentication yet, so it binds to loopback and **refuses to
start on any other address** rather than exposing OT data unprotected. Capture
upload through the GUI, the topology graph, the communication matrix, the
timeline, findings and baselines are later milestones; `analyze` on the command
line is how captures get in for now.

## Quickstart

```sh
make build

# Print what is in a capture, keeping nothing.
bin/otinv analyze testdata/pcaps/modbus_test_data_part1.pcap

# Or store it in a project and browse the inventory.
bin/otinv analyze testdata/pcaps/*.pcap --project demo
bin/otinv serve --project demo          # http://127.0.0.1:8080
```

A project lives in one SQLite file (`demo.otinv.db` by default, `--db` to
override). Re-running `analyze` on the same file is a no-op unless you pass
`--reingest`: the capture's SHA-256 identifies it.

The report on the bundled sample capture names the two Modbus servers, the unit
ids behind them, the vendor string the devices reported, and the crafted frames
in the capture:

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

And the GUI turns that into an inventory:

```
Address                               Role              Vendor            Protocols                          Events
192.168.66.235  00:0c:29:6b:2d:28     HMI / SCADA       —                 modbus (client)                       281
166.161.16.230  00:c0:a8:f2:bf:fb     PLC / RTU / IED   —                 modbus (server)                       281
10.0.0.3        00:02:b3:ce:70:51     PLC / RTU / IED   Wingpath Limited  modbus (server)                        32
10.0.0.8        00:50:04:93:70:67     PLC / RTU / IED   —                 modbus (client), modbus (server)       30
```

Copy `otinv.example.yaml` to `otinv.yaml` to add non-standard ports. Protocols
are also detected heuristically, so an unlisted port is still found.

## What the GUI shows

`otinv serve` renders server-side with templ and uses htmx only to swap the
asset table, so filtering, sorting and paging stay on the server:

- **Assets** — faceted list (search, role, protocol), paged, every view
  deep-linkable through its URL
- **Asset detail** — the inferred role *with the reasons for it*, identity
  fields with their confidence and the packet that proves each one, every
  observed (MAC, IP, VLAN) tuple with its time range, protocols as client and
  as server with their class histogram and unit ids, and the device's recent
  operations
- **Captures** — what has been ingested, with digests and time ranges

Everything is embedded in the binary: htmx is vendored under
`internal/web/static/vendor/` (see its `PROVENANCE.md`) and there are no CDN
references, so the GUI works on an air-gapped laptop. The UI is available in
English and Swedish (`?lang=sv` or `Accept-Language`).

### GUI security posture

- Binds `127.0.0.1` by default; any non-loopback `--listen` is **refused**,
  because `CLAUDE.md` requires mandatory authentication there and
  authentication is not built yet
- Strict CSP with no inline scripts, `nosniff`, `no-referrer`,
  `frame-ancestors 'none'`, and `Cache-Control: no-store` on every page of OT
  data
- Device-supplied strings (vendor names, error text) are escaped on the way
  out; a test asserts that a device reporting `<script>` cannot inject it

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
make test              # unit, golden, reassembly, store, inventory and GUI tests
make fuzz              # short fuzz run for every dissector
make lint              # go vet + golangci-lint
make generate          # regenerate templ components (needs the templ CLI)
make test-update       # regenerate testdata/golden (review the diff!)
make ci                # generate + lint + test
```

The generated `*_templ.go` files are committed, so a build needs nothing but
the Go toolchain; only editing a `.templ` file needs the templ CLI. `make`
pins `GOTOOLCHAIN=local` so that a dependency raising the Go floor fails
loudly instead of silently downloading another toolchain, which would break an
offline build.

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
violation. Asset searches are bound parameters, never concatenated SQL, and a
test tries to drop the table through the search box.

### Known limitations

- **No authentication**, so the GUI is loopback-only by construction. Remote
  access is a later milestone.
- A sender whose MBAP length field disagrees with what it actually transmits
  desynchronises its stream. Resynchronisation requires the next candidate
  frame to look convincingly like the protocol, so the frame right after the
  broken one is reported as a `FramingError` rather than decoded. This is
  visible in `modbus_test_data_part1.pcap`, which contains such a sender.
- Gateway detection needs four or more IPs behind one MAC. Below that a MAC
  fronting several IPs stays one multi-homed asset, which is the right answer
  for a dual-homed controller and the wrong one for a small router; the
  address tuples keep the evidence either way.
- The inventory is rebuilt from all of a project's events on every ingest.
  That is correct and simple, but it is a full scan: incremental rebuilds come
  when they are needed.
- The ingest throughput target in `CLAUDE.md` (≥ 200k packets/s) has not been
  benchmarked yet; the decode path avoids per-packet allocation but no
  benchmark proves the number.
- IPv6 extension headers are not walked, so such packets are counted as
  non-IP. Only Ethernet link type captures are accepted.
- User overrides of inferred fields are not implemented, so the GUI is
  read-only.
