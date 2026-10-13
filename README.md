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

This repository holds the decode path (ingest, dissector registry and seven
Tier 1 dissectors) and the storage and GUI path that makes a capture
browsable. Everything was developed test first against public sample
captures, each dissector cross-checked against an independent decode of the
same bytes and fuzzed.

| Component | State |
|-----------|-------|
| `internal/ingest` — pcap/pcapng reading, L2–L4 decode, VLAN/QinQ, TCP reassembly, PDU framing | done |
| `internal/dissect` — `Dissector` contract, registry, port and heuristic binding, panic recovery, parse health | done |
| `internal/dissect/modbus` — Tier 1 Modbus/TCP | done |
| `internal/dissect/dnp3` — Tier 1 DNP3, link/transport/application layers | done |
| `internal/dissect/s7comm` — Tier 1 Siemens S7comm over ISO-on-TCP | done |
| `internal/dissect/iec104` — Tier 1 IEC 60870-5-104, APCI and ASDU | done |
| `internal/dissect/mms` — Tier 1 IEC 61850 MMS over the ISO stack | done |
| `internal/dissect/goose` — Tier 1 IEC 61850 GOOSE, bound by EtherType | done |
| `internal/dissect/enip` — Tier 1 EtherNet/IP and CIP, explicit, discovery and cyclic I/O | done |
| `internal/store` — SQLite (pure Go), embedded migrations, batched event writes, asset queries | done |
| `internal/inventory` — asset identity and merge, gateway detection, role inference, identity enrichment | done |
| `internal/web` — GUI: asset list with server-side filtering, paging and sorting, asset detail, captures | done |
| `cmd/otinv` — `analyze`, `serve`, `version` | done |
| `internal/topology`, `internal/rules`, `internal/baseline`, `internal/export` | not started |
| Remaining Tier 1 protocols (PROFINET DCP, OPC UA, BACnet/IP) and all of Tiers 2 and 3 | not started |

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

And the GUI turns that into an inventory. Ingesting a DNP3 and a Modbus
capture from the same network into one project shows what the inventory is
for: one device identified across both protocols, and a station classified by
what it did rather than by its address.

```
Address                             Role                      Vendor            Protocols                        Events
192.168.1.40  00:1b:1b:23:eb:3b     PLC / RTU / IED           Siemens           s7comm (server)                     200
192.168.1.10  90:e6:ba:84:5e:41     Engineering workstation   —                 s7comm (client)                     200
10.0.0.3      00:02:b3:ce:70:51     PLC / RTU / IED           Wingpath Limited  dnp3 (server), modbus (server)      127
10.0.0.57     00:20:78:00:62:0d     HMI / SCADA               —                 modbus (client)                      38
```

Nothing there comes from an address or a port alone. 10.0.0.3 is one asset
speaking two protocols, merged on its MAC, with the vendor read out of its own
Modbus identity reply. 192.168.1.40 is a Siemens CPU because it said so when
asked for its SZL lists, and 192.168.1.10 is an engineering workstation
because it downloaded a block into that CPU.

Copy `otinv.example.yaml` to `otinv.yaml` to add non-standard ports. Protocols
are also detected heuristically, so an unlisted port is still found.

## What the DNP3 dissector decodes

DNP3 per IEEE 1815-2012, on TCP and UDP port 20000. All three layers are
decoded, because an operation is not readable until the last one:

- **Data link layer**: start octets, length, control (direction and
  primary/secondary bits, function code), addresses, and the CRC on the header
  and on every 16-octet block. A frame with no user data — an acknowledgement,
  a link reset, a status request — is still reported as evidence that DNP3 is
  spoken.
- **Transport function**: fragments split across frames are reassembled, with
  the sequence checked for gaps and the buffer capped.
- **Application layer**: every function code with the shared classification a
  rule matches on, internal indication flags on replies (so a refused command
  says why), and the object headers with their group, variation, qualifier and
  range.

Control relay output blocks (group 12) are decoded down to the operation:
otinv reports *which point* was selected and *what* was asked of it, for
example `SELECT LATCH_ON point 34463 on time 100 ms`, and the command status
the outstation replied with.

Broadcast addresses (65533–65535) name every outstation on the link rather
than one device, so they are flagged rather than listed as a unit. The bundled
capture has a master broadcasting `STOP_APPL` and `DISABLE_UNSOLICITED`, which
reaches every device at once.

The operations `CLAUDE.md` names as DNP3 rules all classify so that a rule
never needs a function number: cold and warm restart and enable/disable
unsolicited are `control`, stop/start/initialize application, configuration
activation and the file transfers that carry configuration and firmware are
`program`, reads are `read`.

## What the S7comm dissector decodes

The protocol STEP 7 and WinCC speak to S7-300 and S7-400 controllers, over
ISO-on-TCP (RFC 1006) on port 102. Three layers are decoded, because an
operation is not readable until the last one:

- **TPKT** gives the frame its length.
- **COTP** carries the connection, and its TSAPs name the **rack and slot** of
  the CPU the session is aimed at.
- **S7comm**: the message kind, the PDU reference, the error class of a reply,
  the function codes, the memory areas and offsets of the variable services,
  the block filenames of an upload or download, the program invocation
  services, and the SZL lists.

The SZL reads are the point of it. `CLAUDE.md` names them as the S7
enrichment source, and the bundled capture gives up its device completely:

```
Field               Value                  Confidence  Evidence
model               IM151-8 PN/DP CPU      95%         s7comm ReadSZL · Packet 69
order_number        6ES7 151-8AB01-0AB0    95%         s7comm ReadSZL · Packet 59
serial_number       S C-C6TW74882012       95%         s7comm ReadSZL · Packet 69
firmware_revision   V3.2.6                 95%         s7comm ReadSZL · Packet 59
name                IM151-8-CPU            85%         s7comm ReadSZL · Packet 69
vendor              Siemens                90%         s7comm ReadSZL · Packet 69
rack / slot         0 / 2                  80%         s7comm ConnectionConfirm · Packet 6
```

Uploading and downloading blocks is how a PLC's program is changed, so that
whole family classifies as `program`, as do the `_INSE` and `_DELE` services
that activate or delete a block; stopping the CPU is `control`. Both are rules
`CLAUDE.md` names, and a rule never needs an S7 function number to match them.

Two things the dissector handles quietly: the empty COTP frames STEP 7 sends
as keep-alives produce no events at all (72 of the 218 frames in one capture),
and S7comm-plus — what the S7-1200 and S7-1500 speak on the same port — is
reported once per stream rather than flooding the timeline or being dropped in
silence.

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
per-stream buffers are capped. Each dissector has a fuzz target: Modbus
survived 1.3 million inputs, DNP3 1.4 million through `FuzzParse` plus 0.8
million through `FuzzTransportReassembly`, which drives fragments across
frames, and S7comm 2.2 million. No crash and no invariant violation. Asset searches are bound parameters, never concatenated SQL, and a
test tries to drop the table through the search box.

### Known limitations

- **No authentication**, so the GUI is loopback-only by construction. Remote
  access is a later milestone.
- A sender whose MBAP length field disagrees with what it actually transmits
  desynchronises its stream. Resynchronisation requires the next candidate
  frame to look convincingly like the protocol, so the frame right after the
  broken one is reported as a `FramingError` rather than decoded. This is
  visible in `modbus_test_data_part1.pcap`, which contains such a sender.
- **S7comm-plus is not decoded**, so an S7-1200 or S7-1500 is seen but its
  operations are not read; it is a Tier 2 milestone of its own. S7 secure
  communication is likewise out of scope.
- An SZL partial list spanning several data units is decoded per unit rather
  than stitched together. The identity lists arrive in the first unit in
  practice, and an event says when more follow.
- DNP3 object *data* is only walked where the standard fixes its size. An
  unknown variation stops the walk and the event says so
  (`objects_truncated`) rather than guessing a size and reporting invented
  headers. Secure authentication objects (group 120) are not interpreted.
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
