# tests/ASN — Instrumented Nodes and Measurement Sweeps

Instrumented versions of the ASN nodes and the Python sweep scripts used to collect the paper's measurements. The instrumented nodes emit timing data to CSV; the sweep scripts orchestrate repeated runs.

The standard (non-instrumented) implementations are in [`../../ASN/`](../../ASN/).

---

## Files

### Instrumented nodes (C)

| File | What's added vs standard build |
|------|-------------------------------|
| `mix_node_instrumented.c` | Per-packet timing hooks (µs via QueryPerformanceCounter) |
| `client_instrumented.c` | Session setup timing, cover traffic counters, goodput logging |
| `service_gateway_instrumented.c` | Per-request timing and goodput logging |

### Sweep scripts (Python)

| Script | Figure/Table | Live nodes required |
|--------|-------------|---------------------|
| `sweep_figure2.py` | Figure 5 — per-hop latency | Yes |
| `sweep_figure3.py` | Figure 6 — path construction time | Yes |
| `sweep_figure5.py` | Figure 7 — cover traffic overhead | Yes |
| `ASN_sweep_table2.py` | Table 7 — throughput | Yes |
| `bench_figure2.c` | Figure 5 — in-process crypto microbenchmark | No |

### Utilities

`check_live.py` / `check_live2.py` — verify all nodes are reachable before starting a sweep.

---

## Build instrumented nodes

```bash
cd ../../ASN
make instrumented
```

Produces `mix_node_instrumented.exe`, `client_instrumented.exe`, `service_gateway_instrumented.exe`.

Python deps: `pip install matplotlib numpy scipy cryptography`

---

## Starting the nodes

All sweep scripts require the instrumented binaries to be running. Start in this order, each in a separate terminal:

```bash
mix_node_instrumented.exe 9004   # client send
mix_node_instrumented.exe 9005
mix_node_instrumented.exe 9006
mix_node_instrumented.exe 9007   # client return
mix_node_instrumented.exe 9008
mix_node_instrumented.exe 9009
mix_node_instrumented.exe 9030   # sender send
mix_node_instrumented.exe 9031
mix_node_instrumented.exe 9032
mix_node_instrumented.exe 9033   # sender return
mix_node_instrumented.exe 9034
mix_node_instrumented.exe 9035
service_gateway_instrumented.exe
cache_server.exe
```

Check everything is up: `python check_live.py`

---

## Running the sweeps

### Figure 5 — per-hop latency

```bash
python sweep_figure2.py --reps 1000 --hop-csv hop_timing.csv
# quick smoke test:
python sweep_figure2.py --reps 50
```

Output: `figure5_per_hop_latency.csv` — columns: `payload_bytes, protocol, n, mean_us, ci95_us, min_us, max_us, p50_us, p95_us`

### Figure 6 — path construction time

The sweep launches `client_instrumented.exe` itself.

```bash
# default MAX_SESSIONS=64 limits to ~8 runs before nodes fill up
python sweep_figure3.py --reps 8 --client-exe client_instrumented.exe

# with MAX_SESSIONS=1024 (see below):
python sweep_figure3.py --reps 1000 --client-exe client_instrumented.exe
```

Output: `figure3_path_construction.csv` (ASN summary row; add Tor row by running `../../tests/TOR/tor_bench_fig3.exe` and appending)

### Figure 7 — cover traffic overhead

Seed the cache first: `python ../../ASN/scripts/seed_cache.py`

```bash
python sweep_figure5.py --client-exe client_instrumented.exe --duration 120
# quick test (10s per level):
python sweep_figure5.py --client-exe client_instrumented.exe --duration 10
```

Output: `figure7_cover_overhead_120s.csv` and `figure7_cover_overhead_60s.csv`

### Table 7 — throughput

```bash
# safe with default MAX_SESSIONS=64
python ASN_sweep_table2.py --counts 1,5,8 --duration 60

# full paper sweep (requires MAX_SESSIONS=1024)
python ASN_sweep_table2.py --counts 1,5,10,50,100,200 --duration 60
```

Output: `table2_throughput.csv`

---

## Increasing MAX_SESSIONS

The default `#define MAX_SESSIONS 64` in `mix_node_instrumented.c` limits concurrent sessions. For Table 7 with N > 8:

1. Edit `../../ASN/mix_node/mix_node_instrumented.c`: change `MAX_SESSIONS 64` → `MAX_SESSIONS 1024`
2. `cd ../../ASN && make instrumented`
3. Restart all node instances

---

## In-process crypto microbenchmark

`bench_figure2.c` measures raw AES-CTR blinding cost with no sockets — a lower bound on per-hop latency.

```bash
cd ../../ASN
make bench_figure2.exe
./bench_figure2.exe > bench_figure2_output.csv
```

---

## Output files

| File | Produced by | Paper |
|------|------------|-------|
| `figure5_per_hop_latency.csv` | `sweep_figure2.py` | Figure 5 |
| `figure3_path_construction.csv` | `sweep_figure3.py` | Figure 6 |
| `figure7_cover_overhead_120s.csv` | `sweep_figure5.py` | Figure 7 |
| `figure7_cover_overhead_60s.csv` | `sweep_figure5.py` | Figure 7 |
| `table2_throughput.csv` | `ASN_sweep_table2.py` | Table 7 |

Pre-collected copies are in [`../../ASN/results/`](../../ASN/results/).
