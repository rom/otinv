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

One static binary, Go 1.26, `CGO_ENABLED=0`, no libpcap, no CDN: it runs on an
air-gapped analyst laptop.

## Status

This repository holds the decode path (ingest, dissector registry and all ten
Tier 1 dissectors), the storage and inventory path, the topology and Purdue
placement, the detection rules and their findings, a web GUI that makes a
project browsable and triageable, and JSON/CSV export.
Everything was developed test first against public sample captures, each
dissector cross-checked against an independent decode of the same bytes and
fuzzed.

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
| `internal/dissect/profinet` — Tier 1 PROFINET DCP, bound by EtherType | done |
| `internal/dissect/bacnet` — Tier 1 BACnet/IP | done |
| `internal/dissect/opcua` — Tier 1 OPC UA binary, including the security posture of every endpoint | done |
| `internal/store` — SQLite (pure Go), embedded migrations, batched event writes, asset/event/flow queries, aggregates, per-project settings | done |
| `internal/inventory` — asset identity and merge, gateway detection, role inference, identity enrichment | done |
| `internal/topology` — L2/L3 graph building, Purdue level placement, cross-level flows | done |
| `internal/rules` — rule engine, thirteen built-in rules, the YAML DSL for custom ones | done |
| `internal/web` — GUI: dashboard, assets, topology, flows, communication matrix, events, findings with triage, rules, protocol statistics, captures, settings | done |
| `internal/export` — JSON and CSV export of every stored table | done |
| `cmd/otinv` — `analyze`, `serve`, `export`, `protocols`, `rules`, `version` | done |
| `internal/baseline` | not started |
| Tier 2 and Tier 3 protocols | not started |
| HTML report and CycloneDX-style asset export | not started |

The GUI has no authentication yet, so it binds to loopback and **refuses to
start on any other address** rather than exposing OT data unprotected. Capture
upload through the GUI and baseline diffing are later milestones; `analyze` on
the command line is how captures get in for now.

## Quickstart

```sh
make build

# Print what is in a capture, keeping nothing.
bin/otinv analyze testdata/pcaps/modbus_test_data_part1.pcap

# Or store it in a project and browse the inventory.
bin/otinv analyze testdata/pcaps/*.pcap --project demo
bin/otinv serve --project demo          # http://127.0.0.1:8080

# Take the inventory elsewhere.
bin/otinv export --project demo --what assets --format csv --out assets.csv
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

## Command line

```
otinv analyze <capture…>   decode captures, report, and optionally store them in a project
otinv serve                browse a project in the GUI
otinv export               write a project out as JSON or CSV
otinv protocols            list the dissectors in this binary, with tiers and default ports
otinv rules                list the detection rules, or validate a custom rule file
otinv version              version, commit, build date and the Go toolchain
```

Every command takes the global logging flags: `--log-level`
(`debug|info|warn|error`), `--log-format` (`auto|text|json`, where `auto` is
text on a terminal and JSON when redirected) and `-v` as shorthand for
`--log-level debug`.

### analyze

| Flag | What it does |
|------|--------------|
| `--project`, `-p` | store the results in this project instead of only printing them |
| `--db` | project database file (default `<project>.otinv.db`) |
| `--reingest` | replace a capture that is already in the project |
| `--skip-inventory` | store the events without rebuilding the asset inventory |
| `--skip-rules` | store the events without running the detection rules over them |
| `--json` | emit the report as JSON |
| `--events` / `--max-events N` | include decoded events in the JSON report, all of them or the first N |
| `--out`, `-o` | write the report to a file instead of stdout |
| `--quiet`, `-q` | leave out the per-capture report; with `--project`, print its summary alone |
| `--config`, `-c` | configuration file (default `otinv.yaml` when present) |
| `--only` | dissect with these protocols alone, e.g. `--only modbus,dnp3` |
| `--extra-port` | extra port for a protocol, e.g. `--extra-port modbus=1502,1503` |
| `--min-confidence` | how sure a heuristic must be to claim a stream on an unknown port (1–100) |

`--only` and `--extra-port` are checked against the registry, so a protocol
name that no dissector answers to is an error rather than a flag that silently
does nothing.

### serve

| Flag | What it does |
|------|--------------|
| `--project`, `-p` | project to serve (required) |
| `--db` | project database file |
| `--listen` | address to bind; **loopback only** |
| `--read-only` | refuse every state-changing request, so the GUI can only be read |
| `--lang` | UI language when the project has none stored (`en`, `sv`) |
| `--shutdown-timeout` | how long to wait for requests in flight on SIGINT/SIGTERM |
| `--config`, `-c` | configuration file, so the GUI runs the same rules the command line does |

`--read-only` is enforced by the server, not only by the page: the settings
form is rendered disabled *and* a hand-made post is refused with 403.

### export

| Flag | What it does |
|------|--------------|
| `--project`, `-p` | project to export (required) |
| `--what` | tables, comma separated: `summary`, `captures`, `protocols`, `assets`, `flows`, `findings`, `events`, or `all` |
| `--format`, `-f` | `json` (any mix of tables) or `csv` (one table at a time) |
| `--out`, `-o` | write to a file instead of stdout |
| `--protocol` / `--class` | restrict the flows and events to one protocol or one classification |
| `--limit` | at most this many rows per table (0 means every row) |
| `--compact` | write JSON without indentation |

`all` leaves the events out, because a project can hold millions of them; ask
for them by name. Events are streamed straight from the query to the output,
so exporting them is bounded in memory however large the project is. Exporting
a project that does not exist is an error naming the projects the file does
hold, rather than an empty file that hides the typo.

```sh
# The whole project except its events, as one JSON document.
bin/otinv export -p demo --what all --out demo.json

# Every write and control operation a spreadsheet can sort.
bin/otinv export -p demo --what events --class write --format csv --out writes.csv
```

### protocols

```
$ bin/otinv protocols
PROTOCOL      TIER  TCP    UDP         ETHERTYPE  FRAMING
bacnet        1     -      47808       -          length
dnp3          1     20000  20000       -          length
enip          1     44818  2222,44818  -          length
goose         1     -      -           0x88b8     whole frame
iec104        1     2404   -           -          length
mms           1     102    -           -          length, defers
modbus        1     502    -           -          length
opcua         1     4840   -           -          length
profinet_dcp  1     -      -           0x8892     whole frame
s7comm        1     102    -           -          length, defers
```

`--json` for the machine-readable form, `--tier` to list one depth tier, and
`--config` to show the extra ports a configuration file adds.

### rules

```
$ bin/otinv rules
ID      SEVERITY  TECHNIQUE                                        KIND      TITLE
OT-001  high      T1692.001 Unauthorized Message: Command Message  built-in  Write, control or program operation from a host outside…
OT-002  high      T0858 Change Operating Mode                      built-in  Siemens S7 CPU stopped, started or reprogrammed
…
```

`--json` for the machine-readable form, `--config` to include the custom rules
a configuration file loads, and `--check file.yaml` to validate a rule file and
print what it defines.

## Protocols decoded

Ten Tier 1 protocols, each parsed deeply enough that a detection rule never
needs a raw function number: every dissector maps its own codes to the shared
classification set (`read`, `write`, `control`, `program`, `firmware`,
`diagnostic`, `discovery`, `other`).

| Protocol | Default | What is decoded | Identity it yields |
|----------|---------|-----------------|--------------------|
| Modbus/TCP | 502/tcp | every public function code, addresses and quantities, exception replies, FC 8 diagnostics sub-functions | FC 17 Report Server ID, FC 43 / MEI 14 device identification |
| DNP3 | 20000/tcp+udp | data link layer with CRCs, transport reassembly, application function codes, internal indications, object headers, control relay output blocks | outstation and broadcast addresses |
| Siemens S7comm | 102/tcp | TPKT, COTP with the rack and slot, message kinds, variable services, block upload/download, program invocation, SZL lists | SZL: model, order number, serial number, firmware, module name |
| IEC 60870-5-104 | 2404/tcp | APCI I/S/U formats, ASDU type ids, cause of transmission, information object addresses, command qualifiers, select-before-operate | station and common addresses |
| IEC 61850 MMS | 102/tcp | ISO/OSI stack, confirmed and unconfirmed services, named variables and domains, reads, writes, reports, file transfer | Identify: vendor, model, revision |
| IEC 61850 GOOSE | EtherType 0x88B8 | gocbRef, datSet, goID, confRev, stNum/sqNum with state-number jumps, timeAllowedToLive, the simulation and ndsCom flags, the all-data values | publisher MAC with its control block reference |
| EtherNet/IP + CIP | 44818/tcp, 2222 and 44818/udp | encapsulation commands, CPF items, CIP services with their class and instance paths, Multiple Service Packet, Forward Open, cyclic I/O | List Identity and the Identity object: vendor, product code and name, serial number, revision |
| PROFINET DCP | EtherType 0x8892 | Identify, Hello, Get and Set with all three block layouts, IP parameters, device role, control responses | station name, vendor and device id, the manufacturer's type string, IO role, and the address, netmask and gateway the station reports |
| BACnet/IP | 47808/udp | BVLL including forwarded NPDUs, network layer routing and discovery, APDU types, confirmed and unconfirmed services, object and property identifiers, errors, rejects and aborts | readProperty and i-Am replies: vendor, model, firmware, name, location, serial number |
| OPC UA binary | 4840/tcp | HEL/ACK/ERR/OPN/MSG/CLO framing and chunking, service identifiers, endpoint descriptions with security mode and policy, session activation, node and method lists | application name and URI, product URI, endpoint URL |

The sections below describe the ones whose behaviour is worth knowing in
detail. The others are documented in their package comments, which name the
specification clause behind each decision.

### Modbus/TCP

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

### DNP3

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

### Siemens S7comm

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

### PROFINET DCP

Discovery and Configuration Protocol, on EtherType 0x8892 with no IP layer at
all, so a device is named by its MAC until it says otherwise. PROFINET puts
several protocols under that one EtherType and tells them apart by the first
two octets of the frame; this dissector claims the four DCP frame identifiers
(`0xFEFC` Hello, `0xFEFD` Get/Set, `0xFEFE` Identify request, `0xFEFF`
Identify response) and deliberately leaves the cyclic RT and alarm frames
unrecognised, because reading them properly is a Tier 2 milestone of its own.

DCP blocks come in three layouts — bare, with a block qualifier, with a block
info field — and which one a block uses depends on the service and the option,
not on anything in the block itself. All three are walked, with the option and
suboption named, the IP parameters decoded, and the device role (IO device, IO
controller, IO supervisor, IO multidevice) read out.

A DCP Identify response is a device describing itself to the whole segment,
unasked, which makes it the best inventory material there is in a passive
capture:

```
Field               Value            Confidence  Evidence
name                X208-BORD        90%         profinet_dcp Identify
vendor              Siemens          90%         profinet_dcp Identify
vendor_id           42               90%         profinet_dcp Identify
device_id           0x0a01           85%         profinet_dcp Identify
device_role         io_device        90%         profinet_dcp Identify
model               INC              95%         profinet_dcp Identify
reported_address    192.168.0.6      60%         profinet_dcp Identify
netmask             255.255.255.0    60%         profinet_dcp Identify
gateway_address     192.168.0.1      60%         profinet_dcp Identify
```

The netmask is worth more than it looks: a mask cannot be read off an address,
so a station stating its own is the only way a passive observer learns where a
subnet ends, and the topology groups by it instead of assuming a prefix.

The name of station and the IP address are what PROFINET addresses a device
by, so a `Set` of either takes it off the network as surely as unplugging it:
Set is `write`, a factory reset is `control`, and a signal request (the "flash
the LED" service) is `diagnostic` — the classification of a frame is the
strongest of the contributions its blocks make, so a Set that only flashes an
LED is not reported as a write of a device's identity.

Station names are device-supplied bytes in a restricted character set, so
anything else in that field is reported as `name_of_station_not_printable`.
One of the bundled public captures carries a station name made of format
specifiers and NUL padding, which is exactly the kind of frame that field is
checked for.

### BACnet/IP

The protocol of building automation — air handling, chillers, lighting, access
control, fire panels — which in an industrial plant sits on the same cable as
the process network more often than anyone intends. Three layers stack inside
one UDP datagram and all three are decoded:

- **BVLL**: ordinary, broadcast, and the forwarded NPDUs a BBMD relays on
  someone else's behalf, where the original device's B/IP address is in the
  frame and is reported as the real source.
- **Network layer**: source and destination network addressing, hop count, and
  the router discovery messages (Who-Is-Router, I-Am-Router, Network-Number-Is).
- **Application layer**: the APDU type, the service choice, and the object and
  property identifiers the service addresses, decoded through BACnet's tagged
  encoding with the tag depth, the string length and the number of tags all
  capped.

What makes BACnet unusually good material for a passive inventory is that its
answers are self-describing: a reply echoes the object and property it answers
*for*, so a device can be inventoried from answers alone, with no request to
pair them with. An i-Am gives the same for free, to the whole segment:

```
Field               Value               Confidence  Evidence
vendor              Johnson Controls    90%         bacnet readProperty
model               MS-NAE4510-2        90%         bacnet readProperty
firmware_revision   5.1.0.4400          95%         bacnet readProperty
name                KBRNAE              85%         bacnet readProperty
device_instance     500                 85%         bacnet readProperty
vendor_id           5                   90%         bacnet readProperty
```

Nothing in BACnet authenticates anything. `reinitializeDevice` and
`deviceCommunicationControl` stop a device or silence it and carry their
password in the clear, so both classify as `control`; the dissector records
*that* a password was sent and never its value, the same restraint the MMS
association layer gets. `atomicWriteFile`, `createObject` and `deleteObject`
change what the device is, so they are `program`.

### OPC UA binary

The one modern industrial protocol designed with security in it, which is
exactly why it is worth checking whether the security is switched on.

The transport is simple — a three letter message type, a chunk marker and a
length — and the body is not: a binary encoding of nested structures with
length-prefixed strings and arrays, all of it attacker controlled. The reader
behind this dissector bounds every string, array, nesting depth and node
identifier it reads.

- **Handshake**: Hello and Acknowledge with the buffer sizes and the endpoint
  URL the client asked for, OpenSecureChannel with the **security policy** and
  **message security mode**, CreateSession and ActivateSession with the kind of
  user identity token presented (anonymous, username, certificate, issued).
- **Services**: the service identifier of every request and response, resolved
  through a table generated from the standard's own NodeIds, and classified —
  Read, Browse and the subscription services are `read`, Write and
  HistoryUpdate are `write`, AddNodes, DeleteNodes and the reference services
  are `program`, Call is `control`, FindServers and GetEndpoints are
  `discovery`. Reads, writes and browses name the nodes they touch; a Call
  names the object and the method.
- **Endpoints**: every endpoint description a server returns, with its
  security mode and policy, its user token policies, and its application
  description — the application name, the application URI and the product URI,
  which is the identity this protocol yields.

A `GetEndpoints` reply that offers `SecurityPolicy#None` is flagged with
`offers_insecure_endpoint`, and a channel actually opened with mode `None` is
unsigned, unencrypted traffic that anyone on the segment can read or forge.
That is the rule `CLAUDE.md` asks for, and it is readable without decrypting
anything.

Chunked messages are not reassembled: only the first chunk carries a service
identifier, so the stream state remembers that a message is in progress and
reports a continuation as what it is, rather than reading its first octets as
a service. A sequence number that skips is reported as `sequence_gap`.

## Topology and Purdue levels

`internal/topology` turns the inventory and the flow aggregate into a graph,
and places every asset in a level of the Purdue reference model. Both are
inferences and both carry their reasons, because a level an analyst cannot
argue with is a level they cannot correct.

A device is placed by what it was observed doing, and only then by where it
lives:

| Evidence | Level | Confidence |
|----------|-------|------------|
| serves a control protocol (Modbus, DNP3, S7comm, IEC 104, MMS, GOOSE, EtherNet/IP, PROFINET DCP, BACnet) | 1 — basic control | 80 |
| programs controllers (program or firmware operations as a client) | 2 — supervisory | 70 |
| polls controllers | 2 — supervisory | 65 |
| serves OPC UA and nothing else | 3 — site operations | 45, with the caveat in the reason |
| nothing of its own, but most placed devices in its subnet agree | that level | 40 |
| forwards for several addresses | unplaced, with the reason | — |

Levels 0 and 4 are never inferred: field instrumentation does not appear in IP
traffic at all, and nothing in a capture distinguishes an enterprise host from
a supervisory one without a zone definition the analyst supplies. A gateway is
deliberately left unplaced — a device that forwards across a boundary is on
both sides of it, and putting it in one level would be a claim about traffic
rather than about the device.

Subnets are grouped by a netmask **the devices themselves reported** where one
was observed — a PROFINET DCP IP parameter block carries the station's address,
mask and gateway — and otherwise by an assumed /24, which the subnet table on
the topology page labels as the assumption it is. A station that states its
address in a frame with no IP layer is grouped by that address, which is how
PROFINET devices end up in a subnet at all.

The graph itself: one node per asset however many addresses it has, one edge
per protocol between two devices with both directions merged, oriented from the
client to the server (the inventory knows which side served it), and carrying
the most consequential classification observed on it — an edge with one write
among a thousand reads is a write. A multicast group is drawn as what it is,
with publications running outward to it, so a GOOSE publisher's fast path is
visible rather than hidden. Edges between levels that are not neighbours are
listed under the graph as flows that skip a level, which is the shape of
`CLAUDE.md`'s rule about bypassing the DMZ.

## Detection rules

Rules turn decoded events into findings, each with the packet behind it.
`CLAUDE.md` is categorical about that — "No finding without traceable
evidence" — so the engine drops a finding a rule reports without one, and the
GUI shows capture, packet index, timestamp, protocol, operation and function
code on every finding page.

Thirteen rules ship built in. Each names a MITRE ATT&CK for ICS technique,
transcribed from the published matrix rather than from memory: several of the
techniques this project would once have cited have since been restructured
(Unauthorized Command Message is now T1692.001 under Unauthorized Message,
System Firmware is T1693.001 under Modify Firmware), which is exactly why the
table is generated from ATT&CK's own STIX bundle.

| Rule | What it looks for | Severity | Technique |
|------|-------------------|----------|-----------|
| OT-001 | write, control or program operation from a host outside the engineering allow-list | high | T1692.001 |
| OT-002 | S7 CPU stopped or started, block uploaded, downloaded, activated or deleted | high | T0858, T0843, T0845, T0889 |
| OT-003 | Modbus FC 8 Force Listen Only Mode or Restart Communications Option | high | T0813 |
| OT-004 | DNP3 restart, application stop, unsolicited reporting disabled, file transfer | high | T0816, T0881, T1691.002 |
| OT-005 | IEC 104 control command, raised when it is an execute rather than a select | medium/high | T1692.001 |
| OT-006 | MMS write to a control object (the CO constraint, Oper, SBO, Cancel) | high | T1692.001 |
| OT-007 | GOOSE state or sequence counters that do not add up, or a simulated frame | high | T0848 |
| OT-008 | CIP Stop, Start, Reset or a firmware service | high | T0858, T0816, T1693.001 |
| OT-009 | OPC UA channel or endpoint with security mode None | high/medium | T0830 |
| OT-010 | industrial protocol on a port that is not one of its registered ones | low | T0885 |
| OT-011 | flow between Purdue levels that are not neighbours | medium | T0886 |
| OT-012 | burst of protocol exceptions between two devices | low | T0861 |
| OT-013 | repeated undecodable frames from one source | low | T0814 |

Two of `CLAUDE.md`'s rules are deliberately absent rather than pretended: a
new talker compared with a baseline needs the baseline package, and cleartext
IT protocols on an OT segment need the Tier 3 dissectors that recognise them.

A finding is about a device, not an address: the engine keys them on the asset
the inventory resolved, so a controller with two IPs raises one finding with a
count rather than two. Keying is also what makes a re-run safe — the id is
derived from the rule and what the finding is about, so running the rules
again updates each finding in place and leaves the triage state alone.

On the bundled public captures the built-ins find, among others, an engineering
station downloading a block into a CPU, a master forcing a Modbus device
listen-only, a DNP3 outstation restarted and told to stop reporting, IEC 104
commands with their select and execute steps told apart, a GOOSE sequence
regression, a Logix controller stopped and started over CIP, and an OPC UA
channel running with security mode None.

### The engineering allow-list

OT-001 is the rule `CLAUDE.md` leads with, and it needs to know which stations
are allowed to write. Without that list it cannot answer, so it says so rather
than flagging every write in the plant:

```sh
$ bin/otinv rules
…
inactive in this configuration
  OT-001  no engineering allow-list is configured (rules.engineering_stations in otinv.yaml)
```

```yaml
# otinv.yaml
rules:
  engineering_stations: [192.168.1.10, 10.10.0.0/24]
  disabled: []
  files: [rules.example.yaml]
```

### Custom rules

Custom rules are YAML, validated on load with errors that say what is wrong
and where. They match on protocol, classification, operation, function codes,
unit ids, source and destination sets (addresses, MACs or CIDR blocks, with
exceptions), anomalies and malformed frames, and they can be limited to a time
window or held back until a rate threshold is crossed:

```yaml
rules:
  - id: PLANT-002
    title: Control command outside the maintenance window
    severity: medium
    technique: T1692.001
    match:
      classification: [control, program]
    window:
      days: [mon, tue, wed, thu, fri]
      from: "06:00"
      to: "18:00"
      outside: true

  - id: PLANT-003
    title: Burst of writes from one host
    match:
      classification: [write]
      src: [10.0.0.0/24]
    threshold:
      count: 10
      within: 1m
```

A rule that names nothing to match on is refused rather than loaded, because a
rule that matches every event is a rule that buries the ones that matter.
`otinv rules --check plant.yaml` validates a file and prints what it defines;
see [`rules.example.yaml`](rules.example.yaml).

## What the GUI shows

`otinv serve` renders every page on the server with templ and uses htmx only
to swap a table, so filtering, sorting and paging stay on the server. Every
view is deep-linkable: the whole filter state lives in the URL.

- **Dashboard** — eight tiles: assets (and how many of them are controllers),
  events (and flows), protocols, captures (and packets), malformed frames,
  anomalies, exceptions and the time span the captures cover. Then charts of
  events by protocol, by classification and by operation, assets by role, by
  Purdue level and by vendor, findings by severity, exceptions by name, a
  timeline of the whole project, and the latest events. Every tile, bar and segment links through to the filtered
  view behind it.
- **Assets** — faceted list (search, role, protocol, Purdue level), paged and
  sortable, with the inferred level on every row
- **Asset detail** — the inferred role *with the reasons for it*, identity
  fields with their confidence and the packet that proves each one, every
  observed (MAC, IP, VLAN) tuple with its time range, protocols as client and
  as server with their class histogram and unit ids, and the device's recent
  operations
- **Topology** — the network graph, in three layouts (Purdue layers, subnet
  groups, force-directed), filtered by protocol, classification, level, device
  or a minimum number of events, with the devices outside the filter drawn as
  the context the selection talks to. A node links to its asset, an edge to
  the events behind it. Under the graph: the inventory by level, how each
  subnet was decided, and the flows that skip a level
- **Flows** — who talks to whom over what, with a class breakdown per flow and
  a drill-down to the events behind a row
- **Communication matrix** — source × destination heat map, filterable by
  protocol and classification, with a logarithmic scale so one chatty pair
  does not flatten the rest
- **Events** — every decoded operation, filterable by protocol,
  classification, operation, endpoint, capture, free text, and "only malformed"
  or "only anomalous", sortable and paged
- **Protocols** — one row per protocol: events, flows, the class mix, decode
  health (malformed frames and anomalies) and the time range; pick a protocol
  and it adds that protocol's own timeline, operation histogram and server
  ports
- **Findings** — the triage queue: severity, rule, endpoints, how many
  observations, and the workflow state. Filter by severity, status, rule or
  text, set a state on a batch at once, and open a finding for its evidence —
  the capture, the packet index, the timestamp, the operation and the function
  code, with a link through to the traffic itself and to the ATT&CK technique
- **Rules** — every rule this server runs, built-in and custom, with its
  technique, how many findings it has in this project, and why a rule that
  cannot fire cannot. Re-running the rules over the stored events is one
  button, and it keeps the triage states
- **Captures** — what has been ingested, with digests and time ranges
- **Settings** — fifteen settings stored per project: theme (automatic, light,
  dark), accent colour (six), contrast, density, font size, row stripes,
  monospace addresses, charts on or off, chart height, timeline buckets,
  matrix size, rows per page, number grouping, timestamp format and UI
  language

The charts are drawn as SVG on the server rather than by a charting library in
the browser: a server-drawn chart needs no script, so the strict CSP holds with
no exceptions and the pages work with JavaScript switched off entirely. That is
a deliberate deviation from `CLAUDE.md`, which names ECharts.

The topology graph is the one place where that is not enough — an analyst has
to drag a node out of a hairball — so it is drawn by the vendored Cytoscape in
a 440-line island that loads on no other page. The same graph is **also** drawn
as SVG by the server, which is the no-script fallback, the SVG export, and what
a reader sees for the moment before the island is ready. The extension that
would export SVG from Cytoscape is GPLv3 and is deliberately not vendored.

Two libraries inject a stylesheet of their own at runtime, which a strict
`style-src` refuses. htmx is told not to (`htmx-config`), Cytoscape finds its
stylesheet already linked, and both sets of rules are served from
`static/css/` instead — so the GUI has no content security policy violations
to explain away, and a test asserts the pages carry no inline style or script.

Everything is embedded in the binary: htmx is vendored under
`internal/web/static/vendor/` (see its `PROVENANCE.md`) and there are no CDN
references, so the GUI works on an air-gapped laptop. The UI is available in
English and Swedish (`?lang=sv`, the stored setting, `serve --lang sv`, or
`Accept-Language`).

### GUI security posture

- Binds `127.0.0.1` by default; any non-loopback `--listen` is **refused**,
  because `CLAUDE.md` requires mandatory authentication there and
  authentication is not built yet
- `--read-only` refuses every state-changing request, enforced by the server
  and not only by the rendered page
- Every state-changing request — the settings, a triage change, a rule re-run
  — carries a CSRF token in a `HttpOnly`, `SameSite=Strict` cookie that the
  form repeats, compared in constant time, with the `Origin` and
  `Sec-Fetch-Site` headers checked as well; a value the form does not define
  is dropped rather than stored, and a return address that points anywhere but
  back into the GUI is replaced
- Strict CSP with no inline scripts, `nosniff`, `no-referrer`,
  `frame-ancestors 'none'`, and `Cache-Control: no-store` on every page of OT
  data
- Device-supplied strings (vendor names, station names, error text) are escaped
  on the way out; tests assert that a device reporting `<script>` cannot inject
  it and that no page carries an inline style or script

## Development

```sh
make test              # unit, golden, reassembly, store, inventory, export, CLI and GUI tests
make fuzz              # short fuzz run for every dissector target
make lint              # go vet + golangci-lint
make generate          # regenerate templ components (needs the templ CLI)
make test-update       # regenerate testdata/golden (review the diff!)
make ci                # lint + test, the gate for every change
make verify-generated  # check that the committed templ output is current
```

The generated `*_templ.go` files are committed, so a build needs nothing but
the Go toolchain; only editing a `.templ` file needs the templ CLI. `make`
pins `GOTOOLCHAIN=local` so that a dependency raising the Go floor fails
loudly instead of silently downloading another toolchain, which would break an
offline build — pass `make GOTOOLCHAIN=auto …` where fetching one is
acceptable. golangci-lint refuses a module whose Go version is newer than its
own build, so the Makefile pins the oldest release that can analyse `go.mod`
(`GOLANGCI_VERSION`).

Tests use only public sample captures, described with their provenance and
SHA-256 in [`testdata/pcaps/PROVENANCE.md`](testdata/pcaps/PROVENANCE.md), or
traffic crafted in the test with gopacket serialization. Never commit captures
from real customer or production environments.

### Hostile input

Capture bytes are treated as hostile throughout. Every length field is checked
against both the protocol maximum and the bytes actually present, dissectors
never panic (the registry recovers and counts it as a bug if one does), and
per-stream buffers, object counts, string lengths and nesting depths are all
capped.

Each dissector has a fuzz target seeded from its testdata, and each new one is
run well past the point where the corpus stops growing: Modbus survived 1.3
million inputs, DNP3 1.4 million through `FuzzParse` plus 0.8 million through
`FuzzTransportReassembly`, which drives fragments across frames, S7comm 2.2
million, PROFINET DCP 2.5 million, BACnet/IP 2.4 million and OPC UA 3.5
million. No crash and no invariant violation. Asset searches are bound
parameters, never concatenated SQL, sort columns come from whitelists rather
than from the URL, and a test tries to drop the table through the search box.

### Known limitations

- **No authentication**, so the GUI is loopback-only by construction. Remote
  access is a later milestone.
- **Two of CLAUDE.md's rules are not built yet**: a new talker compared with a
  baseline, which needs the baseline package, and cleartext IT protocols on an
  OT segment, which needs the Tier 3 dissectors. The rule about a protocol in
  the wrong Purdue level is not built either: levels are currently inferred
  *from* the protocols, so such a rule could only ever fire on a user override,
  and overrides are not built yet.
- **Rules are enabled, disabled and edited in `otinv.yaml`**, not in the GUI.
  The rules view lists what the server runs and re-runs them over the stored
  events; `CLAUDE.md` asks for editing custom rules in the GUI as well, which
  is a later milestone.
- **User overrides of inferred fields are not implemented.** The GUI can
  change its own appearance settings but not an asset's vendor, role or Purdue
  level; `CLAUDE.md` requires those to be overridable and they will be. Until
  then a wrong level can be argued with — the asset page shows the reasoning —
  but not corrected.
- **Purdue levels 0 and 4 are never inferred**, and the zones and subnets
  `CLAUDE.md` wants in the settings are not there yet, so a plant with an
  enterprise segment in the capture will see it placed at level 2 by
  behaviour alone.
- **The topology graph is capped** at 500 devices and 2000 links per request,
  busiest first, and says so on the page when it cuts. The static picture
  stops at 150 devices and points at the interactive graph instead of drawing
  a smear.
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
- **PROFINET RT and alarm frames are not decoded.** They share EtherType
  0x8892 with DCP and are left unrecognised rather than half-read; cyclic IO
  is a Tier 2 milestone.
- **OPC UA chunked messages are not reassembled**, so a service whose request
  spans chunks is reported as a continuation rather than decoded, and anything
  carried under a security mode above `None` is not read at all — otinv never
  decrypts.
- **BACnet segmented requests are not reassembled.** Each segment is reported
  on its own with its sequence number; the service choice is in every segment
  header, but the arguments are only in the first, so a later segment names
  the service without the object it addresses.
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
- `export` writes JSON and CSV. The HTML report and the CycloneDX-style asset
  export `CLAUDE.md` names are not built yet.
