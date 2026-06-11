#!/usr/bin/env python3
"""
montecarlo_figure4.py  --  Anon-Sec-Net v2  Figure 4: Anonymity Set Size

Methodology (spec §13.3):
  - Sweep f from 0.00 to 1.00 in steps of F_STEP
  - For each f, run N_SESSIONS simulated sessions
  - Each session randomly assigns each of the 6 mix nodes (3 path-A + 3 path-B)
    as malicious with independent probability f
  - De-anonymisation succeeds iff ALL 6 nodes on BOTH paths are malicious
    (the adversary must control the full dual path to correlate sender and
    receiver -- spec §IV.D: P(deanon) = f^6)
  - The Tor-equivalent baseline uses 3 nodes (single path): P(deanon) = f^3
  - Writes raw per-session results to montecarlo_raw.csv
  - Writes per-f summary to figure4_anonymity_set.csv (used by analyser)

Output CSVs:
  figure4_anonymity_set.csv
    f,asn_theory,tor_theory,asn_mc,asn_mc_ci95,tor_mc,tor_mc_ci95,n_sessions

  montecarlo_raw.csv  (optional, for post-hoc inspection)
    f,protocol,session_id,deanon

Usage:
    python montecarlo_figure4.py [--sessions 10000] [--step 0.05] [--out-dir .]
    python montecarlo_figure4.py --sessions 1000  --step 0.1   # quick smoke test
"""

import argparse
import csv
import math
import os
import random
import sys
import time


# ---------------------------------------------------------------------------
# Constants matching the protocol
# ---------------------------------------------------------------------------
ASN_HOPS   = 6   # 3 nodes path-A + 3 nodes path-B
TOR_HOPS   = 3   # single path, 3 nodes


# ---------------------------------------------------------------------------
# Simulation core
# ---------------------------------------------------------------------------

def simulate_session_asn(f: float, rng: random.Random) -> bool:
    """Return True if an ASN session is de-anonymised.

    De-anonymisation requires ALL 6 hop positions to be malicious.
    Each position is independently malicious with probability f.
    """
    return all(rng.random() < f for _ in range(ASN_HOPS))


def simulate_session_tor(f: float, rng: random.Random) -> bool:
    """Return True if a Tor-equivalent session is de-anonymised.

    Tor-equivalent uses a single 3-hop path.  De-anonymisation requires
    all 3 nodes to be malicious.
    """
    return all(rng.random() < f for _ in range(TOR_HOPS))


def ci95_proportion(k: int, n: int) -> float:
    """Wilson score interval half-width at 95 % confidence.

    Returns the half-width (±) of the Wilson score interval.
    Safe for p near 0 or 1 and small n.
    """
    if n == 0:
        return 0.0
    z    = 1.959964   # z_{0.975}
    p    = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    spread = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    # half-width is spread; centre is the adjusted estimate -- we return spread
    return spread


def run_sweep(n_sessions: int,
              f_values: list,
              raw_fp,
              verbose: bool = True) -> list:
    """Run the Monte Carlo sweep.

    Returns a list of dicts, one per f value, with keys:
        f, asn_theory, tor_theory,
        asn_mc, asn_mc_ci95,
        tor_mc, tor_mc_ci95,
        n_sessions
    """
    rng = random.Random()   # thread-local, seeded from OS entropy
    results = []

    raw_writer = None
    if raw_fp is not None:
        raw_writer = csv.writer(raw_fp)
        raw_writer.writerow(["f", "protocol", "session_id", "deanon"])

    total_f = len(f_values)
    t_start = time.perf_counter()

    for fi, f in enumerate(f_values):
        asn_hits = 0
        tor_hits = 0

        for sid in range(n_sessions):
            asn_deanon = simulate_session_asn(f, rng)
            tor_deanon = simulate_session_tor(f, rng)

            if asn_deanon:
                asn_hits += 1
            if tor_deanon:
                tor_hits += 1

            if raw_writer is not None:
                raw_writer.writerow([f"{f:.4f}", "asn", sid,
                                     1 if asn_deanon else 0])
                raw_writer.writerow([f"{f:.4f}", "tor", sid,
                                     1 if tor_deanon else 0])

        asn_mc     = asn_hits / n_sessions
        tor_mc     = tor_hits / n_sessions
        asn_ci     = ci95_proportion(asn_hits, n_sessions)
        tor_ci     = ci95_proportion(tor_hits, n_sessions)
        asn_theory = f ** ASN_HOPS
        tor_theory = f ** TOR_HOPS

        row = {
            "f":           f,
            "asn_theory":  asn_theory,
            "tor_theory":  tor_theory,
            "asn_mc":      asn_mc,
            "asn_mc_ci95": asn_ci,
            "tor_mc":      tor_mc,
            "tor_mc_ci95": tor_ci,
            "n_sessions":  n_sessions,
        }
        results.append(row)

        if verbose:
            elapsed = time.perf_counter() - t_start
            eta     = (elapsed / (fi + 1)) * (total_f - fi - 1)
            print(
                f"  f={f:.3f}  ASN: theory={asn_theory:.2e} "
                f"mc={asn_mc:.2e}±{asn_ci:.2e}  |  "
                f"TOR: theory={tor_theory:.2e} "
                f"mc={tor_mc:.2e}±{tor_ci:.2e}  "
                f"[{fi+1}/{total_f}  ETA {eta:.0f}s]",
                flush=True,
            )

    return results


# ---------------------------------------------------------------------------
# CSV I/O
# ---------------------------------------------------------------------------

SUMMARY_FIELDS = [
    "f", "asn_theory", "tor_theory",
    "asn_mc", "asn_mc_ci95",
    "tor_mc", "tor_mc_ci95",
    "n_sessions",
]


def write_summary(results: list, path: str) -> None:
    with open(path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net v2 Figure 4 Monte Carlo summary\n")
        fp.write(
            "# f: malicious node fraction\n"
            "# asn_theory: f^6 (theoretical ASN de-anon probability)\n"
            "# tor_theory: f^3 (theoretical Tor-equivalent de-anon probability)\n"
            "# asn_mc / tor_mc: Monte Carlo de-anon rate\n"
            "# asn_mc_ci95 / tor_mc_ci95: Wilson score CI half-width at 95%\n"
        )
        writer = csv.DictWriter(fp, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        for row in results:
            writer.writerow({
                k: (f"{row[k]:.8e}" if isinstance(row[k], float) else row[k])
                for k in SUMMARY_FIELDS
            })
    print(f"  Summary written -> {path}")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Monte Carlo simulation for Figure 4 (anonymity set size)."
    )
    parser.add_argument(
        "--sessions", type=int, default=10_000,
        help="Number of simulated sessions per f value (spec default: 10000)",
    )
    parser.add_argument(
        "--step", type=float, default=0.05,
        help="Step size for f sweep, e.g. 0.05 gives 21 points from 0 to 1",
    )
    parser.add_argument(
        "--f-min", type=float, default=0.0,
        help="Minimum f value (default 0.0)",
    )
    parser.add_argument(
        "--f-max", type=float, default=1.0,
        help="Maximum f value (default 1.0)",
    )
    parser.add_argument(
        "--out-dir", default=".",
        help="Directory to write output CSV files",
    )
    parser.add_argument(
        "--no-raw", action="store_true",
        help="Skip writing montecarlo_raw.csv (saves disk space for large runs)",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Optional RNG seed for reproducibility",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress per-f progress output",
    )
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
        print(f"RNG seed: {args.seed}")

    os.makedirs(args.out_dir, exist_ok=True)

    # Build f value list
    n_steps  = round((args.f_max - args.f_min) / args.step)
    f_values = [round(args.f_min + i * args.step, 10) for i in range(n_steps + 1)]
    # Clamp to [0, 1]
    f_values = [max(0.0, min(1.0, f)) for f in f_values]

    print("=" * 60)
    print("  Anon-Sec-Net v2  Figure 4 Monte Carlo")
    print("=" * 60)
    print(f"  Sessions per f : {args.sessions:,}")
    print(f"  f range        : {args.f_min:.3f} to {args.f_max:.3f} "
          f"step {args.step:.3f} ({len(f_values)} points)")
    print(f"  ASN hops       : {ASN_HOPS}  (f^{ASN_HOPS} bound)")
    print(f"  Tor-eq hops    : {TOR_HOPS}  (f^{TOR_HOPS} bound)")
    print(f"  Output dir     : {os.path.abspath(args.out_dir)}")
    print()

    summary_path = os.path.join(args.out_dir, "figure4_anonymity_set.csv")
    raw_path     = os.path.join(args.out_dir, "montecarlo_raw.csv")

    raw_fp = None
    if not args.no_raw:
        raw_fp = open(raw_path, "w", newline="")
        raw_fp.write("# Per-session raw results -- large file\n")

    t0 = time.perf_counter()
    try:
        results = run_sweep(
            n_sessions=args.sessions,
            f_values=f_values,
            raw_fp=raw_fp,
            verbose=not args.quiet,
        )
    finally:
        if raw_fp is not None:
            raw_fp.close()
            if not args.no_raw:
                print(f"  Raw results    -> {raw_path}")

    elapsed = time.perf_counter() - t0
    print()
    print(f"  Completed in {elapsed:.1f}s")
    print()

    write_summary(results, summary_path)

    # Quick sanity print
    print()
    print("  Spot-check (f=0.10):")
    for row in results:
        if abs(row["f"] - 0.10) < 1e-6:
            print(f"    ASN  theory={row['asn_theory']:.2e}  "
                  f"MC={row['asn_mc']:.2e} ±{row['asn_mc_ci95']:.2e}")
            print(f"    TOR  theory={row['tor_theory']:.2e}  "
                  f"MC={row['tor_mc']:.2e} ±{row['tor_mc_ci95']:.2e}")
            break

    print()
    print("  Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
