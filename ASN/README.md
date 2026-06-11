# ASN — Anon-Sec-Net Prototype

C prototype of the Anon-Sec-Net network-layer anonymous communication system. The instrumented variants used for the paper measurements are in [`../tests/ASN/`](../tests/ASN/).

---

## Directory layout

```
ASN/
├── common/
│   ├── config.h            — ports, packet constants, protocol modes
│   ├── crypto.h / crypto.c — P-256 ECDHE, AES-256-GCM, AES-256-CTR, HKDF-SHA256
│   ├── net.h / net.c       — Winsock2 TCP helpers
│   ├── packet.h / packet.c — Sphinx packet build / peel / unwrap
│   └── measure.h           — QueryPerformanceCounter timing macros
│
├── mix_node/               — mix_node.c handles EXTEND, DATA, RESPONSE, COVER
├── gateway/                — service_gateway.c (9010), cache_server.c (9012)
├── client/                 — client.c: session setup, GET/PUT, cover traffic
├── sender/                 — sender.c: session setup + PUT
├── sender_entry/           — entry node stub for sender path (9013)
├── sender_exit/            — exit node stub for sender path (9014)
├── entry/                  — entry node stub for client path (9002)
├── exit/                   — exit node stub for client path (9003)
│
├── scripts/                — Python plot and analysis scripts
├── results/                — pre-collected CSV files
└── Makefile
```

---

## Network topology

```
      Client sending path
Client ──> MN1:9004 ──> MN2:9005 ──> MN3:9006 ──> ServiceGW:9010
                                                          │
                                                    Cache:9012
                                                          │
Client <── MNa:9007 <── MNb:9008 <── MNc:9009 <──────────┘
      Client return path

      Sender sending path
Sender ──> MNi:9030 ──> MNii:9031 ──> MNiii:9032 ──> ServiceGW:9010
Sender <── MNx:9033 <── MNy:9034  <── MNz:9035  <─────────────────┘
```

The same `mix_node.exe` binary runs on all 12 port instances.

---

## Prerequisites

| Requirement | Install (MSYS2) |
|-------------|----------------|
| GCC toolchain | `pacman -S mingw-w64-x86_64-gcc` |
| OpenSSL dev | `pacman -S mingw-w64-x86_64-openssl` |
| Make | `pacman -S make` |
| Python 3.8+ | python.org or `pacman -S python` |
| Python packages | `pip install matplotlib numpy scipy cryptography` |

---

## Build

```bash
cd ASN
make all          # standard nodes + instrumented variants
make nodes        # standard nodes only
make instrumented # instrumented variants only
make clean
```

Outputs: `mix_node.exe`, `service_gateway.exe`, `cache_server.exe`, `client.exe`, `sender.exe`, and `*_instrumented.exe` counterparts.

---

## Running

### 1. Seed the cache

```bash
python scripts/seed_cache.py
```

Inserts a test key `bench` with a 400-byte value.

### 2. Start all nodes

Start each in a separate terminal, in this order:

```bash
mix_node.exe 9004   # client send path
mix_node.exe 9005
mix_node.exe 9006
mix_node.exe 9007   # client return path
mix_node.exe 9008
mix_node.exe 9009
mix_node.exe 9030   # sender send path
mix_node.exe 9031
mix_node.exe 9032
mix_node.exe 9033   # sender return path
mix_node.exe 9034
mix_node.exe 9035
service_gateway.exe
cache_server.exe
```

### 3. Run the client

```bash
client.exe
```

Session setup (8 ECDHE handshakes) runs automatically on first connect, then:

```
> get bench
> put mykey myvalue
> quit
```

---

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/plot_figure2.py` | Plot Figure 5 (per-hop latency) from `results/figure5_per_hop_latency.csv` |
| `scripts/plot_figure3.py` | Plot Figure 6 (session setup) from `results/figure3_path_construction.csv` |
| `scripts/plot_figure4.py` | Plot Figure 3 (anonymity set) from `results/figure4_anonymity_set.csv` |
| `scripts/plot_figure5.py` | Plot Figure 7 (cover overhead) from `results/figure7_cover_overhead_120s.csv` |
| `scripts/montecarlo_figure4.py` | Run Monte Carlo anonymity set simulation |
| `scripts/analyse_figure4.py` | Compute statistics from Monte Carlo output |
| `scripts/format_table2.py` | Format Table 7 throughput results |
| `scripts/seed_cache.py` | Insert test key into cache server |

Regenerate all figures from pre-collected data:

```bash
cd ASN
python scripts/plot_figure2.py
python scripts/plot_figure3.py
python scripts/plot_figure4.py
python scripts/plot_figure5.py
```

---

## Results files

| File | Paper | Description |
|------|-------|-------------|
| `results/figure5_per_hop_latency.csv` | Figure 5 | Per-hop processing time vs payload size. Protocol rows: `asn` (~2.6 µs constant), `tor` (0.51–7.87 µs scaling), `nonanon`. n=5,000 per point. |
| `results/figure3_path_construction.csv` | Figure 6 | Session setup summary for both protocols. ASN: mean=14.9 ms, median=14.4 ms, p95=16.8 ms, n=1,000. Tor: mean=10.4 ms, median=10.1 ms, p95=13.5 ms, n=366. |
| `results/figure4_anonymity_set.csv` | Figure 3 | Monte Carlo de-anonymisation probability vs f (0.0–1.0, step 0.05). Theory curves (f⁶, f³) plus Monte Carlo validation, n=10,000 per f-value. |
| `results/figure7_cover_overhead_120s.csv` | Figure 7 (primary) | Cover overhead vs load (10–90%), 120 s windows, n=558–563 per load level. |
| `results/figure7_cover_overhead_60s.csv` | Figure 7 (supplementary) | Same measurement, 60 s windows — included to show consistency with 120 s data (mean diff 2.4 pp, CIs overlapping). |
| `results/table2_throughput.csv` | Table 7 | Combined ASN and Tor throughput (kbps ±ci95, peak), sessions 1–200. |

The raw Tor session setup samples behind the Figure 6 Tor bar are in [`../TOR-equivalent/results/tor_session_setup.csv`](../TOR-equivalent/results/tor_session_setup.csv).

---

## Packet format

### Outbound (Client → MN1 → MN2 → MN3 → ServiceGW)

```
┌─────────────────────────────────────── 1024 bytes ───┐
│  HEADER  261 B = 3 × 87                              │
│  per hop: enc_addr(6) + enc_bkey(32) + enc_flag(1)   │
│           + mac(16) + hint(32)                        │
├───────────────────────────────────────────────────────┤
│  PAYLOAD  763 B — encrypted under K_R-SG-A           │
│  inner: flags(1) + len(2) + MNc_pubkey(65)           │
│         + MNc_IP(6) + return_header(162) + data(≤499)│
└───────────────────────────────────────────────────────┘
```

Each mix node XORs the payload with an AES-CTR blinding key. The ServiceGW reverses all three blindings and decrypts the payload with K_R-SG-A.

### Return (ServiceGW → MNc → MNb → MNa → Client)

```
┌─────────────────────────────────────── 1024 bytes ───┐
│  RETURN HEADER  162 B = 3 × 54                       │
│  per hop: enc_addr(6) + mac(16) + hint(32)           │
│  (no blinding key — return payload is not blinded)   │
├───────────────────────────────────────────────────────┤
│  RETURN PAYLOAD  862 B — encrypted under K_R-SG-B    │
└───────────────────────────────────────────────────────┘
```

---

## Configuration

Key constants in `common/config.h`:

| Constant | Value | Meaning |
|----------|-------|---------|
| `WIRE_PACKET_SIZE` | 1024 | Fixed wire packet size |
| `HEADER_BLOCK_SIZE` | 87 | Per-hop header block |
| `MAX_INNER_PAYLOAD` | 499 | Max application data per packet |
| `DUMMY_INTERVAL_MS` | 100 | Cover traffic interval |
| `N_PATH_HOPS` | 3 | Hops per path direction |

To run Table 7 sweeps with N > 8: edit `mix_node/mix_node.c`, change `MAX_SESSIONS` from 64 to 1024, then rebuild and restart.
