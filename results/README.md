# Results: benchmark measurement data

Curated measurement CSVs backing the live-network benchmark numbers
quoted in this repository (aggregate throughput, per-hop cryptographic
cost, path construction time, cover-traffic overhead and
content-retrieval overhead). File names carry historical figure and
table numbers; the sections below say what each file measures. This is
not the project's full measurement history: it holds the specific runs
each quoted number traces back to, kept because they are expensive to
reproduce (multi-machine sweeps across 2/4/12/16-vCPU hosts), so a
number can be checked without re-running the full benchmark suite.

The Monte Carlo/attack-simulation results in [`../ASN/eval2/`](../ASN/eval2/)
are **not** duplicated here: every one of those is reproducible in
minutes from a single seeded command (see `eval2/README.md`), so the
scripts there are the reproducibility artifact, not a static CSV.

---

## File names: sweep output vs curated copy

The benchmark sweeps write files under generic names. The copies kept here
were renamed to say what they back and where they were measured. The plot
scripts in `../ASN/scripts/` default to the curated names below. Pass a fresh
sweep output with `--csv` (or `--asn-csv` / `--tor-csv`) to plot a new run.

| Sweep script (writes) | Curated file here | Plot script |
|---|---|---|
| `tests/ASN/sweep_figure2.py` (`hop_timing_figure2.csv`) | `figure2_perhop_latency_dev_workstation.csv`, `figure2_perhop_latency_gcp16vcpu_crosscheck.csv` | `plot_figure2.py` |
| `tests/ASN/sweep_figure3.py` (`figure3_asn.csv`) | `figure3_path_construction_asn.csv` | `plot_figure3.py --asn-csv` |
| Tor-equivalent instrumented client (`tor_session_setup.csv`) | `figure3_path_construction_tor.csv` | `plot_figure3.py --tor-csv` |
| `tests/ASN/sweep_figure5.py` (`figure7_cover_overhead_120s.csv`) | `figure7_cover_overhead_hardened.csv` | `plot_figure5.py` |
| `tests/ASN/ASN_sweep_table2.py` / `tests/TOR/TOR_sweep_table2.py` | `table2_throughput_*.csv` | `../ASN/scripts/format_table2.py` |

Run the plot scripts from `ASN/` so the `../results/` defaults resolve.

---

## Aggregate throughput vs. concurrent sessions

| File | Machine | Backs |
|------|---------|-------|
| `table2_throughput_16vcpu.csv` + `_tor.csv` | 16 vCPU / 16 GB (GCP, `n2-custom-16-16384`) | The throughput table's headline numbers: ASN 94.2 -> 8,878.7 kbps, Tor-equivalent 82.2 -> 11,713.4 kbps, N=1..200 |
| `table2_throughput_16vcpu_reverification_asn.csv` + `_tor.csv` | same 16-vCPU spec, independent re-run after a later security-fix pass | Confirms no regression at N=5-200 (within +-4.1%); N=1 flaked to 0 samples in this specific run, a known harness artifact, not re-cited |
| `table2_throughput_4vcpu_dosresponse.csv` | 4 vCPU / 7.8 GB (dev box) | Cross-machine dose response: throughput peaks then declines past N~50-100 on smaller machines, a hardware concurrency ceiling, not a protocol limit |
| `table2_throughput_2vcpu_historical.csv` | 2 vCPU (hardware no longer available) | Third point in the same dose-response argument (severe decline at 2 vCPU, partial at 4, absent at 16) |
| `table2_throughput_12vcpu_plain.csv` + `table2_throughput_12vcpu_hardened.csv` | 12 vCPU | Matched plain-vs-hardened (`ASN_LOOPIX_MIXING`) throughput comparison |

Each CSV's own header comment gives the specific number(s) it backs and
any measurement caveats.

Reproduce: `tests/ASN/ASN_sweep_table2.py`, see
[`../tests/ASN/README.md`](../tests/ASN/README.md#aggregate-throughput).
Exact throughput values are hardware-dependent; expect the shape (flat-
to-rising at low N, tapering or declining at high N depending on core
count) to reproduce, not the exact kbps figures, unless run on matching
hardware.

## Per-hop cryptographic processing latency

| File | Machine | Backs |
|------|---------|-------|
| `figure2_perhop_latency_dev_workstation.csv` | dev workstation | Headline ~5.0us (5.009us mean-of-medians, n=1,000/size) |
| `figure2_perhop_latency_gcp16vcpu_crosscheck.csv` | 16-vCPU GCP host | Disclosed ~6.2us cross-machine cross-check (~1.24x higher) |

Reproduce: `bench_figure2.c` (in-process microbenchmark, no live
network needed) or `tests/ASN/sweep_figure2.py` (live-network variant).
See [`../tests/ASN/README.md`](../tests/ASN/README.md).

## Path construction (session setup) time

| File | Backs |
|------|-------|
| `figure3_path_construction_asn.csv` | ASN headline: mean 6.32ms, median 6.13ms, p95 7.18ms, n=1,000 |
| `figure3_path_construction_tor.csv` | Tor-equivalent headline: mean 0.83ms, median 0.81ms, p95 0.94ms, n=1,000 |

Reproduce: `tests/ASN/sweep_figure3.py`, requires `MAX_SESSIONS` raised
to 1024 for a full 1,000-rep run. See
[`../tests/ASN/README.md`](../tests/ASN/README.md#path-construction-time).

## Cover traffic bandwidth overhead

`figure7_cover_overhead_hardened.csv`: live-binary measurement under
the hardened (`ASN_LOOPIX_MIXING`) build, 82.1% overhead at 10% load
falling to ~0% by 70% load. This is the "Hardened" cover-overhead curve.

The "Adaptive" curve (production discipline, 69.8% at 10% load
falling to 0.03% at 90% load) comes from `eval2/`'s validated simulator
(`coverleak_run.py`'s `asn_adaptive` scheme), not a live binary
measurement yet; reproduce it via `eval2/README.md`'s Task C, not from
a file in this directory. The two curves come from different
measurement methods because the instrumented harness predates the
adaptive cover discipline.

## Content-retrieval overhead ($K_\text{session}$/$K_\text{content}$ handshake)

`content_retrieval_ksession_handshake_throughput.csv`: production
`client.exe`/`sender.exe` binaries under the live per-request handshake
(not the `*_instrumented.exe` harness used for the figures above, which
predates this mechanism). Backs the "sustains 7.66-7.78 GET/s
at K=50-200 concurrent sessions with 100% completion" figure. See
[`../ASN/README.md`](../ASN/README.md#running) for how to run this live.

---

## Live transaction timing

| File | Backs |
|------|-------|
| `live_transaction_timing_baseline.csv` | 12 sequential live GET transactions (handshake + GET + response), plain build: mean 1.458 s, median 1.376 s |
| `live_transaction_timing_hardened50ms.csv` | Same measurement with all mix nodes on the `ASN_LOOPIX_MIXING` build at 50 ms mean per-hop delay: mean 3.152 s, median 3.148 s |
| `live_transaction_timing_summary.json` | Summary statistics for both files |

Collected with the client's opt-in transaction logger (`ASN_V17_CALIB_CSV=<path>`, see `ASN/client/client.c`). Small samples (n=12 each), useful as a timing sanity check only.

---

## A note on exact reproduction

Absolute throughput and latency numbers are hardware-sensitive (see the
dose-response discussion above); a re-run on different hardware will
not reproduce these exact figures, and that is expected, not a bug.
What should reproduce: the relative shape of each curve, and the
qualitative comparison between ASN and the Tor-equivalent baseline.
