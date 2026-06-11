#!/usr/bin/env python3
"""
analyse_figure4.py  --  Anon-Sec-Net v2  Figure 4 Analyser

Reads figure4_anonymity_set.csv produced by montecarlo_figure4.py and prints
a formatted summary matching the style of analyse_measurements.py.

Usage:
    python analyse_figure4.py [--dir <path_to_csv>]
"""

import argparse
import csv
import math
import os


def load_figure4(path):
    rows = []
    if not os.path.exists(path):
        print(f"  [SKIP] {path} not found")
        return rows
    with open(path, newline="") as fp:
        for line in fp:
            if line.startswith("#"):
                continue
            break  # first non-comment line is the header -- let DictReader handle it
        fp.seek(0)
        # skip comment lines manually then hand off to DictReader
        lines = [l for l in fp if not l.startswith("#")]
    reader = csv.DictReader(lines)
    for row in reader:
        try:
            rows.append({
                "f":           float(row["f"]),
                "asn_theory":  float(row["asn_theory"]),
                "tor_theory":  float(row["tor_theory"]),
                "asn_mc":      float(row["asn_mc"]),
                "asn_mc_ci95": float(row["asn_mc_ci95"]),
                "tor_mc":      float(row["tor_mc"]),
                "tor_mc_ci95": float(row["tor_mc_ci95"]),
                "n_sessions":  int(row["n_sessions"]),
            })
        except (KeyError, ValueError):
            continue
    return rows


def sep(label):
    print()
    print("=" * 60)
    print(f"  {label}")
    print("=" * 60)


def fmt_p(v):
    """Format a probability in scientific notation, or 'zero' if below MC resolution."""
    if v == 0.0:
        return "0 (below MC resolution)"
    return f"{v:.3e}"


def mc_agreement(theory, mc, ci):
    """Simple check: does theory fall within MC ± 1.5*CI95?"""
    if theory == 0.0 and mc == 0.0:
        return "OK (both zero)"
    if ci == 0.0:
        return "OK" if abs(theory - mc) < 1e-12 else "MISMATCH"
    ratio = abs(theory - mc) / ci
    if ratio <= 1.5:
        return "OK"
    elif ratio <= 3.0:
        return "CLOSE"
    else:
        return f"CHECK  (|theory-mc|/CI = {ratio:.1f})"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default=".", help="Directory containing figure4_anonymity_set.csv")
    args = parser.parse_args()
    d = args.dir

    sep("Figure 4: Anonymity Set Size  --  Monte Carlo vs Theory")

    path = os.path.join(d, "figure4_anonymity_set.csv")
    rows = load_figure4(path)

    if not rows:
        print("  No data.")
        return

    n = rows[0]["n_sessions"]
    print(f"  Source        : {path}")
    print(f"  f values      : {len(rows)}  ({rows[0]['f']:.3f} to {rows[-1]['f']:.3f})")
    print(f"  Sessions / f  : {n:,}")
    print(f"  ASN bound     : f^6   (dual path, 3 hops each)")
    print(f"  Tor-eq bound  : f^3   (single path, 3 hops)")

    # ── Key manuscript claim: f=0.10 ────────────────────────────────────
    print()
    print("  ── Key claim (f = 0.10) ────────────────────────────────────")
    for r in rows:
        if abs(r["f"] - 0.10) < 1e-6:
            print(f"  ASN  theory = {r['asn_theory']:.2e}   "
                  f"MC = {fmt_p(r['asn_mc'])}  ±{r['asn_mc_ci95']:.2e}")
            print(f"  TOR  theory = {r['tor_theory']:.2e}   "
                  f"MC = {fmt_p(r['tor_mc'])}  ±{r['tor_mc_ci95']:.2e}")
            if r["tor_theory"] > 0 and r["asn_theory"] > 0:
                ratio = r["tor_theory"] / r["asn_theory"]
                print(f"  Ratio TOR/ASN (theory) = {ratio:.0f}x  "
                      f"(spec: ~1000x at f=0.10)")
            break

    # ── Full sweep table ─────────────────────────────────────────────────
    print()
    print(f"  {'f':>6}  {'ASN theory':>12}  {'ASN MC':>12}  {'±CI95':>10}  "
          f"{'TOR theory':>12}  {'TOR MC':>12}  {'±CI95':>10}  {'Agree?':>8}")
    print("  " + "-" * 90)
    for r in rows:
        agree_asn = mc_agreement(r["asn_theory"], r["asn_mc"], r["asn_mc_ci95"])
        print(
            f"  {r['f']:>6.3f}  "
            f"{r['asn_theory']:>12.3e}  "
            f"{r['asn_mc']:>12.3e}  "
            f"{r['asn_mc_ci95']:>10.3e}  "
            f"{r['tor_theory']:>12.3e}  "
            f"{r['tor_mc']:>12.3e}  "
            f"{r['tor_mc_ci95']:>10.3e}  "
            f"{agree_asn:>8}"
        )

    # ── Convergence quality ───────────────────────────────────────────────
    print()
    print("  ── MC convergence quality ──────────────────────────────────")
    mismatches = []
    for r in rows:
        ag = mc_agreement(r["asn_theory"], r["asn_mc"], r["asn_mc_ci95"])
        if ag not in ("OK", "OK (both zero)"):
            mismatches.append((r["f"], ag))

    if not mismatches:
        print("  All f-values: MC within 1.5 × CI95 of theory  [PASS]")
    else:
        print(f"  {len(mismatches)} f-value(s) outside 1.5 × CI95:")
        for f_val, ag in mismatches:
            print(f"    f={f_val:.3f}  {ag}")
        print(f"  Note: deviations at low-f are expected -- MC resolution")
        print(f"  limited to ~1/{n:,} = {1/n:.2e} per session.")

    # ── MC resolution note ───────────────────────────────────────────────
    mc_floor = 1.0 / n
    print()
    print(f"  MC resolution floor : {mc_floor:.2e}  (1 event per {n:,} sessions)")
    low_f_rows = [r for r in rows if r["asn_theory"] < mc_floor and r["f"] > 0]
    if low_f_rows:
        f_vals = [r["f"] for r in low_f_rows]
        print(f"  ASN theory < MC floor at f ∈ {[f'{v:.2f}' for v in f_vals]}")
        print(f"  These points will show MC=0 in the plot -- expected behaviour.")
        print(f"  Use --sessions 100000 to push the floor to {1/100000:.2e} if needed.")

    print()
    print("  Done.")


if __name__ == "__main__":
    main()
