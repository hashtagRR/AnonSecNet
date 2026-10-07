# tests/TOR: Tor-Equivalent Benchmark Programs

Standalone benchmark programs for the Tor-equivalent baseline. Most run entirely in-process (no live nodes needed) and produce the CSV data for the paper figures.

---

## Files

### Benchmark programs

File names are historical (`fig2`/`fig3`/etc.) and no longer match the
paper's own Table/Figure numbering, which has shifted across revisions;
what each program measures is stable even when the paper's numbering
isn't.

| File | Live nodes needed? | What it measures |
|------|-------------------|-----------------|
| `tor_bench_fig2_perhop.c` | No | Per-hop AES-256-CTR decryption cost vs payload size |
| `tor_bench_fig3_pathconstruction.c` | No | 4 in-process P-256 ECDHE handshakes × 1000 iterations |
| `tor_bench_fig4_anonymity.c` | No | Monte Carlo de-anonymisation probability (f² and f³) |
| `tor_bench_fig5_cover.c` | No | Tor cover overhead = 0% rows for comparison with ASN |
| `tor_bench_table2_throughput.c` | No | In-process cell processing throughput, N = 1-500 |
| `bench.c` | Partial | Older combined harness; GCM model for per-hop cost (see note below) |

### Instrumented nodes (functional testing only)

| File | Role |
|------|------|
| `tor_mix_node_instrumented.c` | Mix node with timing hooks and fixed response forwarding |
| `tor_client_instrumented.c` | Client with session setup timing |
| `tor_sg_instrumented.c` | Service gateway with goodput logging |

### Scripts

`TOR_sweep_table2.py`: throughput sweep using live instrumented nodes.

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

No pre-collected results are shipped in this repository. The commands
above write their output CSVs into the current directory.

### Individually

### Per-hop cryptographic processing latency (no nodes needed)

```bash
tor_bench_fig2.exe > results_tor_fig2.csv
```

Measures AES-256-CTR decryption cost per relay cell at payload sizes 64 B to 64 KB. Real Tor uses AES-128-CTR (Tor spec §5.4.3); we use 256-bit keys throughout the codebase for consistency. The cost difference is negligible relative to the architectural comparison.

### Path construction time (no nodes needed)

```bash
tor_bench_fig3.exe > results_tor_fig3.csv
```

Four in-process P-256 ECDHE handshakes (Guard + Middle + Exit + end-to-end), 1000 iterations. Expected median ~7.5 ms, roughly half ASN's 14.4 ms, consistent with 4 vs 8 handshakes. Does not include telescoping relay overhead (see Known Deviations in `../../TOR-equivalent/README.md`).

### De-anonymisation probability: Monte Carlo validation (no nodes needed)

```bash
tor_bench_fig4.exe > results_tor_fig4.csv
```

Monte Carlo: 10,000 sessions per f-value. Reports both f² (entry-exit correlation, the dominant practical attack) and f³ (full 3-hop path compromise, the theoretical bound used in the paper). Also reports ASN's f² (routing-only) and f⁴ (service-level, the meaningful figure) for direct comparison.

### Cover traffic bandwidth overhead (no nodes needed)

```bash
tor_bench_fig5.exe > results_tor_fig5.csv
```

Tor has no cover traffic (Tor spec §7). Produces formal zero-overhead rows for side-by-side comparison with the ASN overhead curve.

### Aggregate throughput (no nodes needed)

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

`bench.c` is the original combined harness from before the per-figure benchmarks were written. It uses AES-256-GCM for the per-hop latency rows rather than AES-256-CTR. Use `tor_bench_fig2_perhop.c` for the correct per-hop latency data. The path-construction, de-anonymisation-probability, cover-overhead, and throughput sections of `bench.c` are superseded by the individual `tor_bench_fig*.c` programs.
