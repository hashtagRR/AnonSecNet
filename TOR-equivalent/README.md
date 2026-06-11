# TOR-equivalent — Tor Baseline Prototype

A Tor-equivalent baseline for benchmarking against Anon-Sec-Net. It runs a 3-hop onion-routing circuit inside the same simulation framework (Windows threads, loopback TCP, OpenSSL, MinGW-w64/GCC) so the comparison isolates protocol design rather than environment.

This is not real Tor — it is a controlled baseline implementing the same per-hop cryptographic operations, in the same testbed, to produce a fair relative comparison.

---

## Circuit topology

```
  Client ──> TN1:9040 ──> TN2:9041 ──> TN3:9042 ──> SG:9043
  Client <── TN1      <── TN2      <── TN3      <── SG
```

The same `tor_mix_node.exe` binary runs at all three positions, differentiated by port number.

---

## Design differences vs Anon-Sec-Net

| Property | Anon-Sec-Net | Tor-equivalent |
|----------|-------------|----------------|
| Paths | Dual (6 mix nodes) | Single (3 mix nodes) |
| Per-hop crypto | AES-CTR XOR blinding (constant cost) | AES-256-GCM decrypt + re-encrypt |
| Session keys | Two independent (K_R-SG-A, K_R-SG-B) | One shared per circuit |
| Mix node state | Stateless (Sphinx) | Per-circuit session state |
| Cover traffic | Bidirectional Poisson at 100 ms | None |
| Return routing | Pre-built return header | Reverse of forward path |
| De-anon probability | f⁶ | f³ (or f² for entry-exit attack) |

---

## Prerequisites

Same toolchain as ASN — see [`../ASN/README.md`](../ASN/README.md#prerequisites).

---

## Build

```bash
cd TOR-equivalent
make all          # node binaries + all benchmark programs
make tor_bench_all  # benchmark programs only
make clean
```

Outputs: `tor_mix_node.exe`, `tor_client.exe`, `tor_sg.exe`.

---

## Functional test

```bash
make run_tor      # starts TN1, TN2, TN3, SG in background
make run_client   # runs the client through a full circuit
make stop         # kills all node instances
```

Expected output: circuit built in ~10 ms, data cell delivered to SG, response echoed back and decrypted by client.

Manual startup if needed:

```bash
tor_mix_node.exe 9040   # Guard  (TN1)
tor_mix_node.exe 9041   # Middle (TN2)
tor_mix_node.exe 9042   # Exit   (TN3)
tor_sg.exe
tor_client.exe
```

---

## Wire cell format

```
[hint 16B][GCM nonce 12B][ciphertext NB][GCM tag 16B]
```

Overhead per hop: 2 (next_port) + 16 (next hint) + 12 (nonce) + 16 (tag) = 46 bytes.
Maximum application payload with 3 hops: 1024 − 3×46 = 886 bytes.

---

## Results files

| File | Paper figure/table | Description |
|------|-------------------|-------------|
| `results/tor_session_setup.csv` | Figure 6 | 366 raw session setup samples (ms) from live instrumented nodes. Mean=10.4 ms, median=10.1 ms, p95=13.5 ms. |
| `results/tor_table2_results.csv` | Table 7 | Tor throughput vs concurrent session count (1–200), mean ±ci95 and peak in kbps. |

Combined ASN+Tor tables are in `../ASN/results/`.

Several intermediate files generated during development (per-second goodput logs, in-process benchmark CSVs) are not committed — they are either not directly used in the paper or already merged into the combined result files. The sweep scripts in `../tests/TOR/` regenerate them.

---

## Configuration

Key constants in `tor_config.h`:

| Constant | Value | Meaning |
|----------|-------|---------|
| `TOR_PORT_TN1/2/3` | 9040/9041/9042 | Mix node ports |
| `TOR_PORT_SG` | 9043 | Service gateway |
| `TOR_CELL_PAYLOAD` | 1024 | Wire cell size (bytes) |
| `TOR_MAX_SESSIONS` | 1024 | Max concurrent circuits per node |
| `TOR_MAX_PAYLOAD` | 886 | Max application payload |
| `TOR_HINT_BYTES` | 16 | Session lookup hint |

---

## Known deviations from real Tor

**Non-telescoping circuit build.** The client contacts TN1, TN2, TN3 directly with separate connections rather than extending through the built portion of the circuit. The relay infrastructure for telescoping (`target_port != 0` in `handle_extend`) is implemented but never exercised. On loopback this underestimates Tor's true circuit-build time slightly, making the ASN overhead in Figure 6 look *larger* relative to Tor than it would be with telescoping — conservative for ASN's case.

**AES-256-GCM per hop (vs AES-128-CTR in real Tor).** Real Tor relay cells use AES-128-CTR; GCM is only used for the TLS link layer between adjacent nodes (Tor spec §5.4.3). The node and the Figure 5 benchmark both use GCM, so they are internally consistent. The benchmark in `tests/TOR/tor_bench_fig2_perhop.c` uses AES-256-CTR (the correct relay-cell model) for the per-hop latency comparison.

**TN1 drops responses in the non-instrumented build.** `tor_mix_node.c` has a `case TOR_PORT_TN1: return;` that prevents responses reaching the client. Fixed in `tor_mix_node_instrumented.c`. Throughput benchmarks are unaffected (forward path only).

**Response path uses first-active-session lookup.** For N > 1 concurrent circuits, `handle_response` picks the wrong session key. Forward-path benchmarks are unaffected.
