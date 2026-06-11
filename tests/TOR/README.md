# tests/TOR — Tor-Equivalent Benchmark Programs

Standalone benchmark programs for the Tor-equivalent baseline. Most run entirely in-process (no live nodes needed) and produce the CSV data for the paper figures.

---

## Files

### Benchmark programs

| File | Figure/Table | Live nodes needed? | What it measures |
|------|-------------|-------------------|-----------------|
| `tor_bench_fig2_perhop.c` | Figure 5 | No | Per-hop AES-256-CTR decryption cost vs payload size |
| `tor_bench_fig3_pathconstruction.c` | Figure 6 | No | 4 in-process P-256 ECDHE handshakes × 1000 iterations |
| `tor_bench_fig4_anonymity.c` | Figure 3 | No | Monte Carlo de-anonymisation probability (f² and f³) |
| `tor_bench_fig5_cover.c` | Figure 7 | No | Tor cover overhead = 0% rows for comparison with ASN |
| `tor_bench_table2_throughput.c` | Table 7 | No | In-process cell processing throughput, N = 1–500 |
| `bench.c` | — | Partial | Older combined harness; GCM model for Fig 2 (see note below) |

### Instrumented nodes (functional testing only)

| File | Role |
|------|------|
| `tor_mix_node_instrumented.c` | Mix node with timing hooks and fixed response forwarding |
| `tor_client_instrumented.c` | Client with session setup timing |
| `tor_sg_instrumented.c` | Service gateway with goodput logging |

### Scripts

`TOR_sweep_table2.py` — throughput sweep using live instrumented nodes.

---

## Build

```bash
cd ../../TOR-equivalent
make tor_bench_all
```

Produces `tor_bench_fig2.exe`, `tor_bench_fig3.exe`, `tor_bench_fig4.exe`, `tor_bench_fig5.exe`, `tor_bench_table2.exe`.

---

## Running benchmarks

### All at once

```bash
cd ../../TOR-equivalent
make run_bench_tor
```

Pre-collected results are already in [`../../TOR-equivalent/results/`](../../TOR-equivalent/results/).

### Individually

### Figure 5 — per-hop latency (no nodes needed)

```bash
tor_bench_fig2.exe > results_tor_fig2.csv
```

Measures AES-256-CTR decryption cost per relay cell at payload sizes 64 B to 64 KB. Real Tor uses AES-128-CTR (Tor spec §5.4.3); we use 256-bit keys throughout the codebase for consistency. The cost difference is negligible relative to the architectural comparison.

### Figure 6 — path construction time (no nodes needed)

```bash
tor_bench_fig3.exe > results_tor_fig3.csv
```

Four in-process P-256 ECDHE handshakes (Guard + Middle + Exit + end-to-end), 1000 iterations. Expected median ~7.5 ms — roughly half ASN's 14.4 ms, consistent with 4 vs 8 handshakes. Does not include telescoping relay overhead (see Known Deviations in `../../TOR-equivalent/README.md`).

### Figure 3 — anonymity set size (no nodes needed)

```bash
tor_bench_fig4.exe > results_tor_fig4.csv
```

Monte Carlo: 10,000 sessions per f-value. Reports both f² (entry-exit correlation, the dominant practical attack) and f³ (full 3-hop path compromise, the theoretical bound used in the paper). Also reports ASN's f⁶ for direct comparison.

### Figure 7 — cover traffic overhead (no nodes needed)

```bash
tor_bench_fig5.exe > results_tor_fig5.csv
```

Tor has no cover traffic (Tor spec §7). Produces formal zero-overhead rows for side-by-side comparison with the ASN overhead curve.

### Table 7 — throughput (no nodes needed)

```bash
tor_bench_table2.exe > results_tor_table2.csv
```

In-process cell processing, N = 1, 5, 10, 50, 100, 200, 500 concurrent sessions.

---

## Functional testing with live nodes

For a full end-to-end circuit test (not required for any of the benchmarks above):

```bash
# Build
cd ../../TOR-equivalent
make tor_mix_node_instrumented.exe tor_client_instrumented.exe tor_sg_instrumented.exe

# Start nodes (separate terminals)
tor_mix_node_instrumented.exe 9040   # Guard
tor_mix_node_instrumented.exe 9041   # Middle
tor_mix_node_instrumented.exe 9042   # Exit
tor_sg_instrumented.exe

# Run client
tor_client_instrumented.exe
```

The instrumented client writes session setup times to `tor_session_setup.csv`; the gateway writes per-second goodput to `tor_sg_goodput.csv`.

Known issue: in the non-instrumented `tor_mix_node.c`, TN1 drops the response packet rather than forwarding it to the client listener. This is fixed in `tor_mix_node_instrumented.c`. The throughput benchmarks are unaffected since they only exercise the forward path.

---

## Note on `bench.c`

`bench.c` is the original combined harness from before the per-figure benchmarks were written. It uses AES-256-GCM for the Tor Figure 5 rows rather than AES-256-CTR. Use `tor_bench_fig2_perhop.c` for the correct per-hop latency data. The Figure 6, 3, 7, and Table 7 sections of `bench.c` are superseded by the individual `tor_bench_fig*.c` programs.
