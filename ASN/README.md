# ASN: Anon-Sec-Net Prototype

C prototype of the Anon-Sec-Net network-layer anonymous communication
system. The instrumented variants used for benchmark measurement are in
[`../tests/ASN/`](../tests/ASN/); the Python evaluation/attack-simulation
suite is in [`eval2/`](eval2/).

---

## Directory layout

```
ASN/
├── common/
│   ├── config.h            : ports, packet constants, protocol modes
│   ├── crypto.h / crypto.c : P-256 ECDHE, AES-256-GCM, AES-256-CTR, HKDF-SHA256
│   ├── net.h / net.c       : TCP helpers
│   ├── packet.h / packet.c : Sphinx packet build / peel / unwrap
│   ├── node_pool.h / node_pool.c : guard-set persistence
│   └── measure.h           : timing/measurement macros
│
├── mix_node/               : mix_node.c handles EXTEND, DATA, RESPONSE, COVER
├── gateway/                : service_gateway.c (9010), cache_server.c (9012)
├── client/                 : client.c handles session setup, GET/PUT, cover traffic
├── sender/                 : sender.c handles session setup and PUT
│
├── scripts/                : Python plot/analysis scripts for production benchmarks
├── eval2/                  : attack-simulation and evaluation suite (see eval2/README.md)
└── Makefile
```

---

## Network topology

```
Client --> MN1 --> MN2 --> MN3 --> ServiceGW:9010 <--> Cache:9012
                                          │
Client <-- MNa <-- MNb <-- MNc <---------┘
      Client return path

      Sender sending path
Sender --> MNi:9040 --> MNii:9041 --> MNiii:9042 --> ServiceGW:9010
Sender <-- MNx:9043 <-- MNy:9044  <-- MNz:9045  <-----------------┘
```

The Service Gateway round-trips to the Cache Server on every `GET`
(fetching the ciphertext + signature the Sender previously `PUT`) before
relaying the response back down the return path; it's a request/response
exchange, not a one-way pass-through.

The same `mix_node.exe` binary runs on every mix-node instance, regardless
of role. **The client's path (MN1/MN2/MN3, MNa/MNb/MNc) is not fixed to
specific ports.** `client.exe` draws its 6 hops on every session from a
weighted, 100-node mix-node pool (`common/node_pool.h`: `POOL_SIZE=100`,
`POOL_PORT_BASE=9100`, so pool nodes listen on ports 9100-9199), matching
the guard-set/bandwidth-weighted selection scheme described in the paper.
The sender's path (MNi/MNii/MNiii, MNx/MNy/MNz) is unaffected and still
uses the fixed ports shown above. See [Running](#running) below for how
to actually bring this topology up. Starting 100+ individual mix-node
processes by hand isn't practical, so use the provided script.

The **instrumented** binaries used for benchmarking
(`../tests/ASN/*_instrumented.c`) are a separate, deliberately frozen
protocol snapshot that still uses the original fixed 12-port topology
(`MN1:9004` … `MNz:9045`) for reproducible measurement. See
[`../tests/ASN/README.md`](../tests/ASN/README.md).

---

## Prerequisites

| Requirement | Install (Linux, e.g. Debian/Ubuntu) |
|-------------|----------------|
| GCC toolchain | `apt install build-essential` |
| OpenSSL dev | `apt install libssl-dev` |
| Make | included in `build-essential` |
| Python 3.8+ | usually preinstalled; `apt install python3` otherwise |
| Python packages | `pip install matplotlib numpy scipy` |

---

## Build

```bash
cd ASN
make all          # standard nodes + instrumented variants
make nodes        # standard nodes only
make instrumented # instrumented variants only
make clean
```

Outputs: `mix_node.exe`, `service_gateway.exe`, `cache_server.exe`,
`client.exe`, `sender.exe`, and `*_instrumented.exe` counterparts (the
instrumented builds add the timing/bandwidth measurement probes used for
benchmarking; see `common/measure.h`).

---

## Running

A live GET requires a **running Sender process that has uploaded the
key you're fetching**: content is served through a live per-request
`K_session`/`K_content` handshake with the Sender, not read as a static
blob from the Cache Server. `scripts/seed_cache.py` writes directly to
the Cache Server and predates this handshake; it no longer produces a
key a client can actually `GET`. Skip it and use the flow below instead,
verified end-to-end.

### 1. Build and start the network

```bash
cd ASN
make nodes
cd ../tests/ASN
./start_nodes_pool.sh
```

This builds the plain binaries, then launches all 108 processes (100
pool mix nodes + 6 fixed sender-path mix nodes + Service Gateway + Cache
Server), each logging to `/tmp/mix_node_pool_<port>.log` etc., and blocks
until every port is accepting connections. Takes a few seconds. Run
`./stop_nodes_pool.sh` when you're done; it kills everything
`start_nodes_pool.sh` started and frees the ports as a fallback.

### 2. Upload content as the Sender

In a terminal, from `ASN/`:

```bash
./sender.exe
```

```
> PUT mykey hello
```

**Keep this process running.** It heartbeats to the Cache Server and
must be alive to answer a Receiver's handshake. Don't `quit` it until
you're done testing `GET`.

Keep PUT content short (a handful of characters to a few dozen bytes
tested reliably). The wire format's raw payload budget is larger
(`MAX_INNER_PAYLOAD` = 463 bytes, `common/config.h`), but the
`K_session`/`K_content` handshake's own overhead eats into that budget
more than the raw number suggests, and a longer value can fail with
`payload too large` / `content too large to encrypt` well under 463
bytes. If you need to store something bigger, test the actual boundary
against your build rather than assuming one.

### 3. Fetch it as the Client

In a second terminal, also from `ASN/`, **while the Sender from step 2
is still running**:

```bash
./client.exe
```

```
> GET mykey
> quit
```

A successful fetch prints `Response (N bytes, signature verified,
confidentiality-protected): hello`. Session setup (8 ECDHE handshakes,
6 for the client's pool-drawn path + 2 with the SG) runs automatically
on first connect. Commands are case-sensitive: `GET`/`PUT` must be
uppercase; `quit` is not.

### 4. Shut everything down

```bash
cd ../tests/ASN
./stop_nodes_pool.sh
```

Also worth clearing between runs if you hit unexpected errors:
`rm -rf sender_pins client_guard_a.txt client_guard_b.txt
client_rate_tier.txt sender_rate_tier.txt` from `ASN/`. These persist
guard-set/pin/rate-tier state across runs by design (matching real
guard-persistence behavior), which is exactly what you don't want while
iterating on a fresh test topology.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `GET` reports "handshake poll timed out" | No Sender is running for that key, or it `quit` already. `PUT` the key first and leave the Sender process alive (§2 above). |
| `PUT` fails with `payload too large` / `content too large to encrypt` | Content too long for this build's effective budget. See the note in §2, and try a much shorter value. |
| `pubkey_load: No such file or directory` printed during a session | Benign on a fresh run: a pinned-key cache miss that gets resolved and re-cached automatically, not a failure if the command that printed it still completes. |
| `bind: Address already in use` on startup | A previous run's nodes are still up. Run `./stop_nodes_pool.sh` (or `fuser -k <port>/tcp`) before starting a fresh set. |
| `start_nodes_pool.sh` hangs waiting for ports | Check `/tmp/mix_node_pool_<port>.log` for the specific node that failed to bind (often a leftover process from a previous run still holding the port). |
| `gcc: fatal error: openssl/... No such file` at build time | Missing OpenSSL dev headers. See [Prerequisites](#prerequisites). |
| Guard-set/rate-tier files (`client_guard_*.txt`, `sender_pins/`) causing confusing repeated behavior across test runs | These persist by design (they model real guard/rate-tier persistence). Delete them between unrelated test sessions, see §4 above. |

---

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/plot_figure2.py` | Plot per-hop processing latency (default: `../results/figure2_perhop_latency_dev_workstation.csv`; or a fresh `hop_timing_figure2.csv`) |
| `scripts/plot_figure3.py` | Plot session-setup time (default: `../results/figure3_path_construction_{asn,tor}.csv`; or a fresh `figure3_asn.csv` / `tor_session_setup.csv`) |
| `scripts/plot_figure5.py` | Plot cover-traffic overhead vs. load (default: `../results/figure7_cover_overhead_hardened.csv`; or a fresh `figure7_cover_overhead_120s.csv`) |
| `scripts/format_table2.py` | Format throughput sweep results into a summary table |
| `scripts/seed_cache.py` | Insert a test key into the cache server directly. Predates the `K_session`/`K_content` handshake, so a key it inserts is **not** fetchable via a live `client.exe` `GET` (see [Running](#running)). Still useful if you're testing the Cache Server in isolation. |

`scripts/plot_figure4.py`, `scripts/montecarlo_figure4.py`, and
`scripts/analyse_figure4.py` model an earlier, retracted disclosure-ladder
exponent and are kept only for reference; do not use them for new figures.

Point these scripts at your own benchmark CSVs (produced by the
instrumented binaries in `../tests/ASN/`) to regenerate plots, or at
the curated data in [`../results/`](../results/), which backs the paper's
published numbers.

---

## Packet format

### Outbound (Client -> MN1 -> MN2 -> MN3 -> ServiceGW)

```
┌--------------------------------------- 1024 bytes ---┐
│  HEADER  285 B = 3 × 95                              │
│  per hop: enc_addr(6) + enc_bkey(32) + enc_flag(1)   │
│           + enc_nonce(8) + mac(16) + hint(32)         │
├───────────────────────────────────────────────────────┤
│  PAYLOAD  739 B: encrypted under K_R-SG-A           │
│  inner: flags(1) + len(2) + MNc_pubkey(65)           │
│         + MNc_IP(6) + return_header(174) + data(≤463)│
└───────────────────────────────────────────────────────┘
```

Each mix node XORs the payload with an AES-CTR blinding key. The
ServiceGW reverses all three blindings and decrypts the payload with
K_R-SG-A. `enc_nonce` is a fresh per-packet random value (real or cover)
each mix node uses to detect and drop an exact resend of a packet
already forwarded in that session (a bounded per-session cache, not
unconditional replay-resistance).

### Return (ServiceGW -> MNc -> MNb -> MNa -> Client)

```
┌--------------------------------------- 1024 bytes ---┐
│  RETURN HEADER  174 B = 3 × 58                       │
│  per hop: enc_addr(6) + enc_nonce(4) + mac(16)       │
│           + hint(32)                                  │
│  (no blinding key IN the header block: the return-  │
│   path blinding key is derived independently by each  │
│   mix node from its own ECDH master, not transmitted) │
├───────────────────────────────────────────────────────┤
│  RETURN PAYLOAD  850 B: encrypted under K_R-SG-B,   │
│  then blinded by the SG and unblinded one layer per   │
│  hop by MNc/MNb/MNa                                    │
└───────────────────────────────────────────────────────┘
```

---

## Configuration

Key constants in `common/config.h`:

| Constant | Value | Meaning |
|----------|-------|---------|
| `WIRE_PACKET_SIZE` | 1024 | Fixed wire packet size |
| `HEADER_BLOCK_SIZE` | 95 | Per-hop header block |
| `MAX_INNER_PAYLOAD` | 463 | Max application data per packet |
| `DUMMY_INTERVAL_MS` | 100 | Legacy single-rate cover interval, superseded by the rate-tier scheme below |
| `N_RATE_TIERS` / `RATE_TIER_INTERVALS_MS` | 3 / `{60, 100, 160}` | Each client draws one tier at first run and persists it for its identity's lifetime, rather than using one network-wide rate (avoids a stable per-client rate fingerprint) |
| `N_PATH_HOPS` | 3 | Hops per path direction |

`common/config.h` documents every constant's rationale inline, including
the optional `ASN_LOOPIX_MIXING` and `ASN_POOL_MIXING` hardened-build
flags described below.

### Build-time flags

| Flag | Effect | Build via |
|------|--------|-----------|
| `ASN_LOOPIX_MIXING` | Shared-clock, bounded-aggregate-rate dispatch plus per-hop exponential mixing delay (see `MIX_DELAY_MEAN_MS`/`MIX_DELAY_MAX_MS`) | `make hardened` |
| `ASN_POOL_MIXING` | Batch/pool mixing at each hop instead of per-packet delay | `make poolmix` |
| `ASN_HOP_DECOY` | Per-hop decoy termination flag | `make hopdecoy` (composes with the two above: `make hopdecoy_hardened`, `make hopdecoy_poolmix`) |

Each variant builds its own suffixed binaries (`mix_node_hardened.exe`,
`client_hopdecoy.exe`, etc.) alongside the plain ones. See the Makefile
for the full target list.
