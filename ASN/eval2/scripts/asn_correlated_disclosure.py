#!/usr/bin/env python3
"""
asn_correlated_disclosure.py: Task A: Correlated-compromise disclosure model

Extends the existing independence-only disclosure ladder (P(D1)=f^2 for ASN
and f^3 for Tor full-path, under independent per-position compromise) with a
tunable correlation parameter rho in [0,1].

GENERATIVE MODEL  (latent shared-operator mixture, primary model)
---------------------------------------------------------------------
For a disclosure event requiring k independently-drawn positions to all be
adversary-controlled (k=2 for D1, 4 for D2, 7 for D3 single-CS, see
Result D1/D2/D3's counting argument: routing-level linkage needs only one
path's entry+exit, not every position across both paths), each simulated
session draws:

    with probability rho:      a single shared coin X ~ Bernoulli(f) is drawn
                                once and applied to ALL k positions at once
                                (interpretation: a single physical operator
                                secretly runs every position relevant to this
                                session's disclosure event, mix nodes, SG,
                                CS alike, so either all k are compromised
                                together or none are);
    with probability (1-rho):  each of the k positions is drawn independently
                                ~ Bernoulli(f), exactly as in the existing
                                independence-only model.

rho=0 recovers the existing model exactly (P = f^k). rho=1 means every
session's relevant infrastructure is, with probability f, entirely run by one
adversarial operator: P = f. This has an EXACT closed form for every rho, not
just the two limits:

    P(event | f, rho, k) = rho * f + (1 - rho) * f^k              (*)

We validate this closed form against Monte Carlo at every grid point.

SECOND MODEL  (Beta-Bernoulli mixture, robustness check, analytic only)
---------------------------------------------------------------------
Per-session adversarial propensity p ~ Beta(alpha, beta) with mean f and
intraclass correlation rho (so alpha+beta = (1-rho)/rho for rho in (0,1);
rho=0 is the independence limit alpha+beta -> infinity, i.e. p concentrates
at f; rho=1 is the point-mass limit alpha+beta -> 0, i.e. p concentrates on
{0,1} with P(p=1)=f, which coincides with the primary model's rho=1 case).
Each of the k positions is then drawn ~ Bernoulli(p) independently given p.
This has an exact closed form via the Beta function (no simulation needed):

    P(event | f, rho, k) = E_p[p^k] = prod_{i=0}^{k-1} (alpha+i)/(alpha+beta+i)

Usage:
    python asn_correlated_disclosure.py [--sessions 20000] [--out-dir .] [--seed 20260710]
"""

import argparse
import csv
import math
import os
import random
import sys
import time

# ---------------------------------------------------------------------------
# Disclosure event definitions (component counts under independence)
# ---------------------------------------------------------------------------
EVENTS = {
    "D1": 2,    # mix-network position disclosure: routing-level linkage needs
                # only the entry+exit of ONE path (Correlation-capability
                # assumption), not all 6 positions across both paths
    "D2": 4,    # service-level disclosure: D1 (2) + SG_R + CS
    "D3": 7,    # full bidirectional disclosure, single-CS: D2 (4) + f^2 (2nd
                # path's entry+exit, Result D1's argument) + SG_S
}

# Baselines from the paper's Table (single-path systems), for the crossover analysis
BASELINES = {
    "tor_hs_f3":          3,   # Tor hidden services, service-level: f^3
    "singlepath_sgcs_f4": 4,   # hypothetical single-path + role-decoupled SG+CS: f^4
}


# ---------------------------------------------------------------------------
# Wilson-score CI (matches montecarlo_figure4.py convention)
# ---------------------------------------------------------------------------
def ci95_proportion(k: int, n: int) -> float:
    if n == 0:
        return 0.0
    z = 1.959964
    p = k / n
    denom = 1 + z * z / n
    spread = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return spread


# ---------------------------------------------------------------------------
# Primary model: latent shared-operator mixture
# ---------------------------------------------------------------------------
def analytic_shared_operator(f: float, rho: float, k: int) -> float:
    return rho * f + (1 - rho) * (f ** k)


def simulate_shared_operator(f: float, rho: float, k: int,
                              n_sessions: int, rng: random.Random) -> int:
    hits = 0
    for _ in range(n_sessions):
        if rng.random() < rho:
            # one shared draw governs all k positions at once
            if rng.random() < f:
                hits += 1
        else:
            # k independent draws, as in the original model
            if all(rng.random() < f for _ in range(k)):
                hits += 1
    return hits


# ---------------------------------------------------------------------------
# Second model: Beta-Bernoulli mixture (analytic, robustness check)
# ---------------------------------------------------------------------------
def analytic_beta_mixture(f: float, rho: float, k: int) -> float:
    if rho <= 0.0:
        return f ** k
    if rho >= 1.0:
        return f
    s = (1.0 - rho) / rho          # alpha + beta
    alpha = f * s
    beta = (1.0 - f) * s
    val = 1.0
    for i in range(k):
        val *= (alpha + i) / (alpha + beta + i)
    return val


# ---------------------------------------------------------------------------
# Crossover rho*: solve analytic_shared_operator(f, rho, k) == baseline_prob
# ---------------------------------------------------------------------------
def crossover_rho(f: float, k: int, baseline_prob: float):
    """Return rho* in [0,1] solving rho*f + (1-rho)*f^k = baseline_prob,
    or None if no solution lies in [0,1] (monotone increasing in rho since
    f > f^k for 0<f<1, k>1)."""
    fk = f ** k
    denom = f - fk
    if abs(denom) < 1e-300:
        return None
    rho_star = (baseline_prob - fk) / denom
    if rho_star < 0.0 or rho_star > 1.0:
        return None
    return rho_star


# ---------------------------------------------------------------------------
# Main sweep
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sessions", type=int, default=20_000,
                     help="Sessions per (f, rho, event) grid point (spec min: 10000)")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--seed", type=int, default=20260710)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    rng = random.Random(args.seed)

    # Fine grid: f in [0.05, 0.50] step 0.05, rho in [0.0, 1.0] step 0.1
    f_fine = [round(0.05 * i, 2) for i in range(1, 11)]          # 0.05 .. 0.50
    # Coarse extension to f=1.0 at rho=0 only, for the independence-model
    # validation check (reproducing montecarlo_figure4.py's full range).
    f_coarse_extra = [round(0.05 + 0.05 * i, 2) for i in range(11, 20)]  # 0.55..1.00
    rho_grid = [round(0.1 * i, 1) for i in range(0, 11)]         # 0.0 .. 1.0

    ladder_rows = []
    t0 = time.perf_counter()
    total_points = len(f_fine) * len(rho_grid) * len(EVENTS) + len(f_coarse_extra) * len(EVENTS)
    done = 0

    def run_point(f, rho, event, k):
        nonlocal done
        hits = simulate_shared_operator(f, rho, k, args.sessions, rng)
        mc = hits / args.sessions
        ci = ci95_proportion(hits, args.sessions)
        analytic = analytic_shared_operator(f, rho, k)
        beta_analytic = analytic_beta_mixture(f, rho, k)
        done += 1
        if not args.quiet and done % 20 == 0:
            elapsed = time.perf_counter() - t0
            eta = elapsed / done * (total_points - done)
            print(f"  [{done}/{total_points}] f={f:.2f} rho={rho:.1f} {event} "
                  f"mc={mc:.3e} analytic={analytic:.3e} ETA {eta:.0f}s", flush=True)
        return {
            "f": f, "rho": rho, "event": event,
            "asn_mc": mc, "asn_mc_ci95": ci,
            "asn_analytic_if_available": analytic,
            "asn_analytic_beta_mixture": beta_analytic,
            "n_sessions": args.sessions,
        }

    for f in f_fine:
        for rho in rho_grid:
            for event, k in EVENTS.items():
                ladder_rows.append(run_point(f, rho, event, k))

    # Coarse high-f extension, rho=0 only (independence-model validation)
    for f in f_coarse_extra:
        for event, k in EVENTS.items():
            ladder_rows.append(run_point(f, 0.0, event, k))

    elapsed = time.perf_counter() - t0
    if not args.quiet:
        print(f"\n  Monte Carlo sweep completed in {elapsed:.1f}s\n")

    # -- Write asn_correlated_ladder.csv --------------------------------
    ladder_path = os.path.join(args.out_dir, "asn_correlated_ladder.csv")
    with open(ladder_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net Task A: correlated-compromise disclosure ladder\n")
        fp.write("# f: malicious/adversary fraction per population\n")
        fp.write("# rho: correlation parameter, latent shared-operator mixture model\n")
        fp.write("#      (rho=0 recovers the independence-only model f^k;\n")
        fp.write("#       rho=1 is full correlation, P=f)\n")
        fp.write("# event: D1 (f^2 indep.), D2 (f^4 indep.), D3 (f^7 indep., single-CS)\n")
        fp.write("# asn_mc / asn_mc_ci95: Monte Carlo estimate and Wilson-score 95% CI half-width\n")
        fp.write("# asn_analytic_if_available: closed form rho*f + (1-rho)*f^k (exact for all rho)\n")
        fp.write("# asn_analytic_beta_mixture: robustness-check alternative model (Beta-Bernoulli mixture)\n")
        fields = ["f", "rho", "event", "asn_mc", "asn_mc_ci95",
                  "asn_analytic_if_available", "asn_analytic_beta_mixture", "n_sessions"]
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for row in ladder_rows:
            w.writerow({
                k: (f"{v:.8e}" if isinstance(v, float) else v)
                for k, v in row.items()
            })
    print(f"  Wrote {ladder_path}  ({len(ladder_rows)} rows)")

    # -- Write asn_crossover_rho.csv ------------------------------------
    crossover_path = os.path.join(args.out_dir, "asn_crossover_rho.csv")
    f_dense = [round(0.01 * i, 4) for i in range(1, 100)]   # 0.01 .. 0.99
    crossover_rows = []
    for f in f_dense:
        for name, exp in BASELINES.items():
            baseline_prob = f ** exp
            rho_star = crossover_rho(f, EVENTS["D2"], baseline_prob)
            crossover_rows.append({
                "f": f,
                "baseline": name,
                "rho_star": rho_star if rho_star is not None else "",
            })
    with open(crossover_path, "w", newline="") as fp:
        fp.write("# Anon-Sec-Net Task A: crossover rho* where ASN D2 probability\n")
        fp.write("# equals a single-path baseline's service-level probability\n")
        fp.write("# f: malicious/adversary fraction\n")
        fp.write("# baseline: tor_hs_f3 (Tor hidden services, f^3) or\n")
        fp.write("#           singlepath_sgcs_f4 (hypothetical single-path+SG+CS, f^4)\n")
        fp.write("# rho_star: correlation at which ASN D2 prob == baseline prob\n")
        fp.write("#           (blank if no solution in [0,1] at this f)\n")
        w = csv.DictWriter(fp, fieldnames=["f", "baseline", "rho_star"])
        w.writeheader()
        for row in crossover_rows:
            r = dict(row)
            r["f"] = f"{row['f']:.4f}"
            if row["rho_star"] != "":
                r["rho_star"] = f"{row['rho_star']:.6f}"
            w.writerow(r)
    print(f"  Wrote {crossover_path}  ({len(crossover_rows)} rows)")

    # -- Sanity check: rho=0 should reproduce f^2/f^4/f^7 within CI ------
    print("\n  Sanity check (rho=0 vs independence model), f=0.10:")
    for row in ladder_rows:
        if abs(row["rho"] - 0.0) < 1e-9 and abs(row["f"] - 0.10) < 1e-9:
            k = EVENTS[row["event"]]
            theory = 0.10 ** k
            print(f"    {row['event']}: theory={theory:.3e}  "
                  f"mc={row['asn_mc']:.3e}±{row['asn_mc_ci95']:.3e}  "
                  f"analytic={row['asn_analytic_if_available']:.3e}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
