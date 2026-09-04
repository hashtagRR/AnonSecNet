# Anon-Sec-Net: Anonymous and Secure Communication at the Network Layer

Prototype implementation and evaluation code for:

> **Anon-Sec-Net: Anonymous and Secure Communication at the Network Layer**  

---

## What it does

Tor routes each session through a single 3-hop circuit. An adversary who can observe both ends of that circuit can correlate entry and exit traffic. Anon-Sec-Net (ASN) defends against this by splitting each session across two independent 3-hop paths, so deanonymisation requires compromising all six positions simultaneously — a per-session probability of f⁶ against f³ for Tor.

The two paths are constructed in parallel using a Sphinx-style onion protocol with AES-CTR blinding keys. Per-hop processing cost is constant at ~2.6 µs regardless of payload size. Bidirectional Poisson cover traffic hides session timing and volume at the cost of ~88% bandwidth overhead at 10% real-traffic load, dropping to ~10% at 90% load.

### Key results (loopback testbed, MinGW-w64/GCC, OpenSSL)

| Metric | ASN | Tor-equivalent |
|--------|-----|----------------|
| Median session setup | 14.4 ms (8 ECDHE handshakes) | 10.1 ms (4 handshakes) |
| Per-hop latency | 2.6 µs (constant) | 0.51–7.87 µs (scales with payload) |
| Cover overhead at 10% load | 88% | 0% |
| Cover overhead at 90% load | 10% | 0% |
| De-anon probability at f=0.1 | f⁶ ≈ 10⁻⁶ | f³ ≈ 10⁻³ |

---

## Repository layout

```
├── ASN/                    # Anon-Sec-Net prototype
│   ├── common/             # Shared: crypto, net, packet, config, measure
│   ├── mix_node/           # Mix node (same binary, 6 instances on different ports)
│   ├── gateway/            # Service gateway + cache server
│   ├── client/             # User/receiver node
│   ├── sender/             # Anonymous service (sender) node
│   ├── sender_entry/       # Entry stub for sender path
│   ├── sender_exit/        # Exit stub for sender path
│   ├── entry/              # Entry stub for client path
│   ├── exit/               # Exit stub for client path
│   ├── scripts/            # Python analysis and plot scripts
│   ├── results/            # Pre-collected CSV result files (see below)
│   └── Makefile
│
├── TOR-equivalent/         # Tor-equivalent baseline prototype
│   ├── common/             # Shared crypto/net
│   ├── tor_mix_node.c      # 3-hop mix node (guard/middle/exit in one binary)
│   ├── tor_client.c        # Circuit builder + layered cell sender
│   ├── tor_sg.c            # Destination endpoint
│   ├── tor_config.h        # Ports, constants, cell layout
│   ├── scripts/            # Plot and sweep scripts
│   ├── results/            # Pre-collected CSV result files
│   └── Makefile
│
├── tests/
│   ├── ASN/                # Instrumented ASN nodes + sweep harnesses
│   └── TOR/                # Tor standalone benchmark programs
│
└── README.md
```

---

## Quick start

### Prerequisites

- Windows with [MSYS2](https://www.msys2.org/) MinGW-w64 toolchain
- `pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl make`
- Python 3.8+ with `pip install matplotlib numpy scipy cryptography`

> The socket layer uses Winsock2. Porting to Linux/macOS requires replacing `net.c` with POSIX sockets and removing `-lws2_32 -lbcrypt` from the Makefile. The crypto layer is pure OpenSSL.

### Build and run ASN

```bash
cd ASN
make all
```

See [`ASN/README.md`](ASN/README.md) for how to start the nodes and run the client.

### Build and run the Tor-equivalent baseline

```bash
cd TOR-equivalent
make all
make run_tor
```

### Reproduce figures from pre-collected data

```bash
cd ASN
python scripts/plot_figure2.py   # Figure 5 — per-hop latency
python scripts/plot_figure3.py   # Figure 6 — session setup time
python scripts/plot_figure4.py   # Figure 3 — anonymity set size
python scripts/plot_figure5.py   # Figure 7 — cover traffic overhead
```

---

## Pre-collected results

All CSV files used in the paper figures are included.

| File | Paper | Description |
|------|-------|-------------|
| `ASN/results/figure5_per_hop_latency.csv` | Figure 5 | Per-hop latency vs payload size, all three protocols (asn, tor, nonanon), n=5,000 per point |
| `ASN/results/figure3_path_construction.csv` | Figure 6 | Session setup time summary: ASN mean=14.9 ms median=14.4 ms (n=1,000); Tor mean=10.4 ms median=10.1 ms (n=366) |
| `ASN/results/figure4_anonymity_set.csv` | Figure 3 | Monte Carlo de-anonymisation probability, f=0.0–1.0, n=10,000 per f-value |
| `ASN/results/figure7_cover_overhead_120s.csv` | Figure 7 | Cover overhead vs load (10–90%), 120 s windows, n≈560 per point (primary) |
| `ASN/results/figure7_cover_overhead_60s.csv` | Figure 7 | Same, 60 s windows — consistency check (mean diff 2.4 pp) |
| `ASN/results/table2_throughput.csv` | Table 7 | ASN and Tor throughput (kbps ±ci95, peak), sessions 1–200 |
| `TOR-equivalent/results/tor_session_setup.csv` | Figure 6 | 366 raw Tor session setup samples (ms) |
| `TOR-equivalent/results/tor_table2_results.csv` | Table 7 | Tor throughput with n_samples detail |

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

---

## Implementation notes

Packet format is Sphinx-style. The outbound header is 261 bytes (3 × 87: encrypted next-addr + blinding key + flag + MAC + routing hint). The payload is AES-CTR blinded at each of the three hops; only the ServiceGW holds the key to reverse all three blindings and decrypt the inner payload.

Session setup: 8 P-256 ECDHE handshakes across two parallel paths (4 each, telescoping). The client pre-builds the return header and sends it inside the outbound payload so the ServiceGW can route the response without knowing the return path topology.

Cover traffic: fixed-rate Poisson stream at 100 ms intervals. Mix nodes drop packets flagged `COVER_FLAG` immediately on receipt without forwarding.

---

## License

MIT — see [LICENSE](LICENSE).

## Citation

Citation details to be updated on publication.
