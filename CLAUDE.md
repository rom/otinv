# CLAUDE.md — otinv (passive OT asset inventory)

## Purpose
`otinv` builds an asset inventory, communication matrix and network topology for
OT/ICS environments from **packet captures only** (pcap/pcapng), and presents it
in an advanced, self-hosted web GUI. It identifies devices and industrial
protocols, records who talks to whom and how, and flags anomalies such as write
or control commands from unexpected sources.

The whole solution is written in Go and ships as **one static binary** with the
web GUI embedded. It must run on an air-gapped analyst laptop with no internet.

**Hard constraint: the tool is strictly passive.** It never sends packets, never
opens connections toward analysed hosts, never does active fingerprinting,
scanning or polling. Any feature that would require active interaction is out of
scope — do not add it, not even behind a flag.

## Tech stack
- Go 1.23+, modules, `CGO_ENABLED=0` (no libpcap dependency)
- Packet decoding: `github.com/gopacket/gopacket` (maintained fork) with `pcapgo`
  for pcap/pcapng reading; `tcpassembly`/`reassembly` for TCP streams
- Storage: SQLite via `modernc.org/sqlite` (pure Go), one DB file per project
- Migrations: embedded SQL files, applied on startup
- HTTP: standard library `net/http` (Go 1.22+ routing patterns), no heavy framework
- HTML: `github.com/a-h/templ` components + `htmx` for interactivity
- Rich client widgets (small JS islands only where needed):
  - Topology graph: Cytoscape.js
  - Charts/heatmaps/timeline: Apache ECharts
  - Tables: server-side paging/sorting/filtering via htmx (no client-side grid lib)
- All JS/CSS vendored under `web/static/vendor/` and embedded with `embed.FS`.
  **No CDN references** — the GUI must work fully offline.
- CLI: `github.com/spf13/cobra`
- Config: YAML (`gopkg.in/yaml.v3`)
- Logging: `log/slog` (structured, JSON in non-interactive mode)
- Tests: `go test`, table-driven; `testify` allowed for assertions
- Lint: `golangci-lint` (config in `.golangci.yml`), `go vet`, `staticcheck`

## Repository layout
```
cmd/otinv/                main.go — cobra root: analyze, serve, export, version
internal/
  ingest/                 pcap/pcapng reader, L2–L4 decode, VLAN/QinQ, reassembly
  dissect/                registry + Dissector interface
    modbus/ s7comm/ s7plus/ dnp3/ iec104/ mms/ goose/ sv/ enip/ profinet/
    opcua/ bacnet/ fins/ melsec/ srtp/ codesys/ hartip/ ffhse/ c37118/
    ethercat/ powerlink/ knx/ dlms/ fox/ roc/ tristation/ bsap/ pcworx/
    iccp/ mqtt/ coap/ lldp/ cdp/ snmp/ ptp/ ntp/ dhcp/ arp/ dns/
    itproto/              telnet, ftp, http, smb, rdp, vnc, ssh/tls metadata
  model/                  Asset, Flow, Event, Finding, Capture, Project types
  inventory/              asset identity + merge, vendor/model/firmware inference
  topology/               L2/L3 graph building, Purdue-level assignment
  rules/                  Rule interface + built-in rules + YAML rule loader
  baseline/               baseline snapshots and diffing between captures
  store/                  SQLite repository layer + migrations
  oui/                    embedded IEEE OUI table (generated, see Makefile)
  web/                    HTTP server, handlers, middleware, auth, SSE
    templates/            *.templ components
    static/               css, app.js, vendor/ (cytoscape, echarts, htmx)
  export/                 JSON, CSV, HTML report, CycloneDX-style asset export
testdata/
  pcaps/                  small public/crafted captures (< 1 MB each)
  golden/                 expected JSON outputs for golden tests
datasets/                 large public datasets (git-ignored)
```

## Supported protocols
Three depth tiers. Every dissector declares its tier in its registration.

**Tier 1 — deep parsing** (full request/response pairing, function codes,
addresses/objects, device identity where present, read/write classification)
- Modbus/TCP (502) incl. FC 43/14 Read Device Identification
- Siemens S7comm (102, TPKT/COTP) incl. SZL reads for CPU model/firmware
- DNP3 (20000/TCP+UDP) incl. application layer function codes and objects
- IEC 60870-5-104 (2404) — APCI/ASDU, type IDs, COT, IOAs
- IEC 61850 MMS (102, ISO stack) — reads/writes, named variables, domains
- IEC 61850 GOOSE (EtherType 0x88B8) — gocbRef, datSet, stNum/sqNum
- EtherNet/IP + CIP (44818/TCP, 2222/UDP) — List Identity, CIP services, classes
- PROFINET DCP (0x8892) — Name of Station, vendor/device ID, IP config
- OPC UA Binary (4840) — Hello/Open/Session, service types, security mode/policy
- BACnet/IP (47808/UDP) — services, object IDs, I-Am/Who-Is device info

**Tier 2 — function-level parsing** (operation types and identity, no full object model)
- Siemens S7comm-plus (102) — session setup, op types; payload often protected
- IEC 61850 Sampled Values (0x88BA) — svID, smpCnt, stream stats
- PROFINET RT/IO (0x8892 cyclic, PNIO-CM over DCE/RPC 34964)
- Omron FINS (9600 TCP/UDP)
- Mitsubishi MELSEC MC / SLMP (5007, 5000-5006 and configurable)
- GE SRTP (18245)
- CODESYS runtime (1200, 1217, 2455)
- HART-IP (5094)
- Foundation Fieldbus HSE (1089-1091)
- IEEE C37.118 synchrophasor (4712/TCP, 4713/UDP)
- ICCP / TASE.2 (over MMS, 102)
- DLMS/COSEM (4059)
- Niagara Fox (1911, 4911)
- Emerson ROC (4000)
- Triconex TriStation (1502/UDP)
- Bristol BSAP / BSAP-IP (1234/UDP)
- Phoenix PCWorx / ProConOS (1962, 20547)
- EtherCAT (EtherType 0x88A4) — frame/datagram summary only
- Ethernet POWERLINK (EtherType 0x88AB) — node IDs, message types
- KNXnet/IP (3671/UDP)
- MQTT (1883, 8883 metadata) and CoAP (5683/UDP)

**Tier 3 — identification and asset enrichment**
- LLDP, CDP (switch/port topology, system names, capabilities)
- SNMP v1/v2c (sysDescr/sysName from observed responses only — never query)
- PTP / IEEE 1588 (grandmaster, clock hierarchy), NTP
- ARP, DHCP (hostnames, vendor class), DNS, NetBIOS/LLMNR/mDNS
- IT protocols on OT segments: Telnet, FTP, TFTP, HTTP (Server header, titles),
  SMB (dialect, hostnames), RDP, VNC, SSH and TLS (versions, SNI, cert subjects,
  JA3/JA4 fingerprints — metadata only, no decryption)

Ports are defaults only. Every TCP/UDP dissector must also support heuristic
detection (`Probe`) and user-configured extra ports in `otinv.yaml`.

## Dissector contract
```go
type Dissector interface {
    Name() string
    Tier() int
    // Probe returns a confidence 0-100 that the payload belongs to this protocol.
    Probe(ctx *FlowContext, payload []byte) int
    // Parse decodes one PDU and returns events. It must never panic.
    Parse(ctx *FlowContext, payload []byte) ([]model.Event, error)
}
```
- Register in `init()` via `dissect.Register(...)`.
- Each dissector owns a function-code table mapping codes to the shared
  classification: `read`, `write`, `control`, `program`, `firmware`,
  `diagnostic`, `discovery`, `other`. Rules operate on the classification,
  not on raw codes.
- Treat all packet bytes as hostile: bounds-check every length field, never
  trust declared lengths, cap per-stream reassembly buffers and object counts.
- A malformed PDU yields an error that is counted per protocol and shown in
  the GUI ("parse health"), never a panic. Wrap `Parse` with `recover` at the
  registry level as a last line of defence and log it as a bug.
- Every dissector has a fuzz test (`go test -fuzz`) seeded from its testdata.

## Inventory and topology
- Asset identity: primary key is MAC when available, fallback IP. Keep every
  observed (MAC, IP, VLAN, time range) tuple on the asset; routed segments make
  many IPs share one gateway MAC — detect gateways and do not merge behind them.
- Enrichment sources, each with a confidence score and the evidence that produced
  it: OUI vendor, protocol identity responses (Modbus FC43, S7 SZL, CIP Identity,
  PROFINET DCP, BACnet I-Am, OPC UA app description), DHCP, LLDP/CDP, HTTP/TLS.
- Roles inferred from behaviour: PLC/RTU/IED (server of control protocols),
  HMI/SCADA (polling client), engineering workstation (program/config ops),
  historian, switch, gateway. Store role with confidence and reasons.
- Purdue level assignment: inferred from role + subnet, overridable by the user.
- All inferred attributes must be overridable in the GUI; user overrides are
  stored separately and always win over inference.

## Detection rules
Built-in (each has an ID, severity, description, MITRE ATT&CK for ICS technique ID):
- Write/control/program operation from a host not in the engineering allow-list
- New talker to a controller compared with baseline
- S7 CPU stop/start, program upload/download, block delete
- Modbus diagnostics FC 8, force listen-only, unusual exception rates
- DNP3 cold/warm restart, file ops, disable unsolicited, stop application
- IEC 104 control commands (C_SC/C_DC/C_RC/C_SE*) from unexpected sources
- MMS writes to control objects; GOOSE stNum jumps / unexpected publisher
- CIP stop/reset/firmware services; OPC UA SecurityMode None
- Cleartext IT protocols on OT segments; default-credential-prone web UIs
- Protocol on non-standard port; protocol seen in wrong Purdue level
- Cross-level flows that bypass the DMZ (e.g. level 4 directly to level 1)
Custom rules: YAML DSL (match on protocol, classification, src/dst sets,
function codes, time windows, rate thresholds). Validate on load with clear errors.

Every finding carries evidence: capture ID, packet index, timestamp, src, dst,
protocol, function code, and a link to the flow in the GUI. No finding without
traceable evidence.

## Web GUI (`otinv serve`)
Server-rendered with templ + htmx; JS islands only for graph and charts.
Views:
- **Projects & captures** — create project, upload pcaps (chunked, progress via
  SSE), ingest queue with live status, parse-health per capture
- **Dashboard** — asset counts by role/vendor/Purdue level, protocol mix,
  findings by severity, ingest timeline
- **Assets** — server-side paged table with faceted filters (vendor, role,
  protocol, level, VLAN, subnet, tag), saved filters, bulk tagging/overrides
- **Asset detail** — identity, all addresses, evidence for each inferred field,
  protocols spoken (as client/server), peers, function-code histogram,
  findings, notes, change history
- **Topology** — Cytoscape graph with layouts (Purdue layered, subnet groups,
  force-directed), edge styling per protocol and read/write, filter panel,
  click-through to asset/flow, export PNG/SVG
- **Communication matrix** — ECharts heatmap of src×dst by protocol/classification
- **Flows** — table with drill-down to event timeline per flow
- **Timeline** — events and findings over time, brushing to filter other views
- **Findings** — triage workflow (new / investigating / accepted risk /
  false positive / resolved), assignee, comments, bulk actions
- **Baseline & diff** — mark a capture set as baseline, compare a new capture:
  new/removed assets, new flows, new function codes, changed firmware
- **Rules** — list built-ins, enable/disable, edit custom YAML rules with
  validation feedback, rerun rules over stored events
- **Settings** — allow-lists, engineering stations, port mappings, Purdue
  zones/subnets, users
UI requirements: dark and light theme, keyboard navigation in tables,
deep-linkable URLs for every view and filter state, Swedish and English UI
strings via a simple i18n catalogue (default English).

## GUI security (the tool handles sensitive OT data)
- Bind to `127.0.0.1` by default; binding elsewhere requires `--listen` and
  enables mandatory authentication
- Local user accounts with argon2id password hashes; session cookies
  `HttpOnly`, `Secure` (when TLS), `SameSite=Strict`
- Roles: `viewer`, `analyst`, `admin`
- CSRF tokens on all state-changing requests (htmx sends via header)
- Strict CSP (`default-src 'self'`, no inline scripts — use nonces if required)
- Optional TLS with user-supplied cert, or self-signed generated on first run
- Upload limits and pcap magic-byte validation; uploaded files stored outside
  the static web root
- Audit log of logins, overrides, triage changes and exports
- Never render packet payload bytes as HTML — always escape (templ does by
  default; do not bypass with `templ.Raw` for packet data)

## Performance targets
- Ingest ≥ 200k packets/s single core on a modern laptop for Tier 1 traffic
- Stream processing; memory bounded regardless of capture size
- Worker pool for dissection, single writer goroutine for SQLite with batched
  transactions
- GUI pages render < 300 ms on a project with 10k assets and 1M events
  (use indexes and pre-aggregated tables; check with `EXPLAIN QUERY PLAN`)

## Test data
- Only public sample captures (Wireshark samples, published ICS pcap datasets)
  or packets crafted in tests with gopacket serialization.
- `testdata/pcaps/` files < 1 MB; larger in git-ignored `datasets/`, used by
  tests behind the `integration` build tag.
- **Never commit captures from real customer or production environments.**
- Golden tests: `go test ./... -update` regenerates `testdata/golden/`;
  review diffs before committing.

## Commands
```
make build            # go build with embedded web assets -> bin/otinv
make generate         # templ generate + OUI table regeneration
make test             # go test ./...
make test-integration # go test -tags integration ./...
make fuzz             # short fuzz run for all dissectors
make lint             # golangci-lint run
bin/otinv analyze testdata/pcaps/modbus.pcap --project demo
bin/otinv serve --project demo         # http://127.0.0.1:8080
```

## How to work in this repo
- Build in this order: ingest → dissector registry → Modbus (end-to-end through
  store and a minimal GUI asset list) → remaining Tier 1 → topology/GUI views →
  rules → Tier 2 → Tier 3 → baseline/diff.
- Before writing a dissector, add a test pcap and expected events; implement
  until the test passes, then add a fuzz target.
- Run `make generate lint test` before considering any change done.
- Dissectors are independent; a bug in one must not affect others.
- When protocol behaviour is uncertain, write a comment referencing the spec
  section or Wireshark dissector behaviour instead of guessing silently.
- Keep handlers thin: HTTP → service layer → store. No SQL in handlers.
- Code, comments and commit messages in English.

## Out of scope (do not implement)
- Any active scanning, probing, polling, or packet injection
- Writing to or controlling devices
- Exploit or attack functionality
- Decryption of TLS or protected protocol payloads
- Live capture from interfaces (v2 candidate, would require cgo/libpcap or AF_PACKET)
