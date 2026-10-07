# tests/ASN: Instrumented Nodes and Measurement Sweeps

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

Script names are historical (kept for compatibility with existing
commands/CSVs) and no longer match the paper's own Table/Figure
numbering, which has shifted across revisions; what each script
measures is stable even when the paper's numbering isn't.

| Script | Measures | Live nodes required |
|--------|-------------|---------------------|
| `sweep_figure2.py` | Per-hop cryptographic processing latency | Yes |
| `sweep_figure3.py` | Path construction (session setup) time | Yes |
| `sweep_figure5.py` | Cover traffic bandwidth overhead | Yes |
| `ASN_sweep_table2.py` | Aggregate throughput vs. concurrent sessions | Yes |
| `bench_figure2.c` | Per-hop latency: in-process crypto microbenchmark | No |

### Utilities

`check_live.py` / `check_live2.py`: verify all nodes are reachable before starting a sweep.

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

All sweep scripts require the instrumented binaries to be running.
Easiest path, from this directory:

```bash
./start_nodes.sh   # launches all 14 processes backgrounded, waits for
                    # every port to accept connections, records PIDs to
                    # nodes.pid
...                 # run your sweep(s)
./stop_nodes.sh     # kills everything start_nodes.sh started
```

Hardened-build (`ASN_LOOPIX_MIXING`) and pool-mixing (`ASN_POOL_MIXING`)
A/B variants have their own matching pairs: `start_nodes_hardened.sh` /
`stop_nodes_hardened.sh` and `start_nodes_pool.sh` / `stop_nodes_pool.sh`
(the latter launches the M=100-node pool topology for the plain,
non-instrumented `client.exe`/`mix_node.exe` demo path; see
[`../../ASN/README.md`](../../ASN/README.md#running). It is not the
instrumented benchmark pipeline this file otherwise covers.)

Equivalently, by hand, each in a separate terminal, on the current
fixed ports (`common/config.h`'s `PORT_MIX_I..Z`):

```bash
mix_node_instrumented.exe 9004   # client send
mix_node_instrumented.exe 9005
mix_node_instrumented.exe 9006
mix_node_instrumented.exe 9007   # client return
mix_node_instrumented.exe 9008
mix_node_instrumented.exe 9009
mix_node_instrumented.exe 9040   # sender send
mix_node_instrumented.exe 9041
mix_node_instrumented.exe 9042
mix_node_instrumented.exe 9043   # sender return
mix_node_instrumented.exe 9044
mix_node_instrumented.exe 9045
service_gateway_instrumented.exe
cache_server.exe
```

Check everything is up: `python check_live.py`

---

## Running the sweeps

### Per-hop cryptographic processing latency

```bash
python sweep_figure2.py --reps 1000 --out-dir .
# quick smoke test:
python sweep_figure2.py --reps 50
```

(There is no `--hop-csv` flag: the output filename is fixed; use `--out-dir`
to change where it's written.)

Output: `hop_timing_figure2.csv`, columns: `payload_bytes, protocol, n, mean_us, ci95_us, min_us, max_us, p50_us, p95_us`

### Path construction time

The sweep launches `client_instrumented.exe` itself.

```bash
# default MAX_SESSIONS=64 limits to ~8 runs before nodes fill up
python sweep_figure3.py --reps 8 --client-exe client_instrumented.exe

# with MAX_SESSIONS=1024 (see below):
python sweep_figure3.py --reps 1000 --client-exe client_instrumented.exe
```

Output: `figure3_asn.csv` (ASN summary row; add Tor row by running `../../tests/TOR/tor_bench_fig3.exe` and appending)

### Cover traffic bandwidth overhead

Seed the cache first: `python ../../ASN/scripts/seed_cache.py`

```bash
python sweep_figure5.py --client-exe client_instrumented.exe --duration 120
# quick test (10s per level):
python sweep_figure5.py --client-exe client_instrumented.exe --duration 10
```

Output: `figure7_cover_overhead_120s.csv` and `figure7_cover_overhead_60s.csv`

### Aggregate throughput

```bash
# safe with default MAX_SESSIONS=64
python ASN_sweep_table2.py --counts 1,5,8 --duration 60

# full paper sweep (requires MAX_SESSIONS=1024)
python ASN_sweep_table2.py --counts 1,5,10,50,100,200 --duration 60
```

Output: `table2_throughput.csv`

---

## Increasing MAX_SESSIONS

The default `#define MAX_SESSIONS 64` in `mix_node_instrumented.c` limits concurrent sessions. For the throughput sweep with N > 8:

1. Edit `../../ASN/mix_node/mix_node_instrumented.c`: change `MAX_SESSIONS 64` to `MAX_SESSIONS 1024`
2. `cd ../../ASN && make instrumented`
3. Restart all node instances

---

## In-process crypto microbenchmark

`bench_figure2.c` measures raw AES-CTR blinding cost with no sockets: a lower bound on per-hop latency.

```bash
cd ../../ASN
make bench_figure2.exe
./bench_figure2.exe > bench_figure2_output.csv
```

---

## Output files

| File | Produced by | Measures |
|------|------------|-------|
| `hop_timing_figure2.csv` | `sweep_figure2.py` | Per-hop cryptographic processing latency |
| `figure3_asn.csv` (+ `figure3_tor.csv`) | `sweep_figure3.py` | Path construction time |
| `figure7_cover_overhead_120s.csv` | `sweep_figure5.py` | Cover traffic bandwidth overhead |
| `figure7_cover_overhead_60s.csv` | `sweep_figure5.py` | Cover traffic bandwidth overhead |
| `table2_throughput.csv` | `ASN_sweep_table2.py` | Aggregate throughput |

The sweep scripts above write these CSVs into the current directory
when run. A curated set of already-collected results backing the
paper's published numbers (multiple machine specs, since several of
these are cross-machine comparisons) is available in
[`../../results/`](../../results/) if you want to check a
number without re-running the full sweep.
