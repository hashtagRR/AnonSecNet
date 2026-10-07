#!/usr/bin/env python3
"""
asn_statistical_disclosure.py: Task A, genuine follow-up: a Danezis-style
statistical disclosure attack (SDA) with partial-evidence accumulation.

WHY THIS EXISTS
---------------------------------------------------------------------------
Every disclosure-ladder result so far (asn_correlated_disclosure.py,
asn_repeated_sessions.py) models a single BINARY event per session: either
the adversary controls all k relevant positions (full disclosure, certain
sender-receiver linkage) or it controls none of the useful ones (zero
information gained). That is not how a real statistical disclosure attack
(Danezis 2003; Mathewson & Dingledine's long-term-intersection follow-up)
works: the whole point of an SDA is that the adversary never achieves any
single round of full compromise, but accumulates many rounds of WEAK,
partial evidence until a target correspondent can be identified with
arbitrarily high confidence. This script builds that missing piece.

MODEL
---------------------------------------------------------------------------
The adversary already has a partial, non-compromising observation channel:
Task B's flow-correlation attack (flowcorr_run.py / flowcorr_ml.py),
measured empirically at fixed operating points (FPR target, resulting TPR)
in flowcorr_results.csv / flowcorr_ml_results.csv. This script treats each
repeated observation of a candidate (sender, receiver) pair as one Bernoulli
trial in a Wald Sequential Probability Ratio Test (SPRT):

    H1: this candidate IS the target's true correspondent -> match w.p. TPR
    H0: this candidate is a decoy                          -> match w.p. FPR

After each round, the adversary updates a cumulative log-likelihood ratio
(LLR) and stops as soon as it crosses one of two Wald boundaries, set by
target error rates (alpha = false-accept prob. under H0, beta = false-
reject prob. under H1):

    A = ln((1-beta)/alpha)   (accept H1 if LLR >= A)
    B = ln(beta/(1-alpha))   (accept H0 if LLR <= B)

This is the textbook SPRT construction (Wald, 1945) applied to Task B's
already-validated per-round correlator strength, no new attack primitive
is invented, only the ALREADY-MEASURED partial evidence is accumulated
across rounds, which is exactly Danezis-style SDA's core idea: many weak
rounds beat one strong one, and no single round needs to reach the
disclosure ladder's all-or-nothing compromise threshold.

We report both:
  (a) the closed-form Wald average sample number (ASN) formula for
      E[rounds | H1] and E[rounds | H0] (validated against Monte Carlo), and
  (b) a full Monte Carlo simulation of the SPRT itself (median/95th-pct
      rounds-to-decision, empirical accuracy), since the closed form is an
      asymptotic approximation and this script needs an honest small-sample
      check, not just the formula.

Usage:
    python asn_statistical_disclosure.py --trials 20000 --seed 20260710 --out-dir .
"""

import argparse
import csv
import math
import os
import random
import sys

# ---------------------------------------------------------------------------
# Empirical per-round evidence strength, lifted directly from Task B's
# already-measured results (flowcorr_results.csv / flowcorr_ml_results.csv).
# Not re-measured here, this script consumes those numbers as given.
# ---------------------------------------------------------------------------
#
# S-4: these rows previously held the
# single_path_cover ablation arm's TPR values (the Tor-equivalent-plus-
# cover control), mislabeled under the asn_one_path/asn_both_paths names.
# Corrected here to the actual asn_one_path/asn_both_paths rows in the
# 500-session flowcorr_results_fpr_sweep.csv / flowcorr_ml_results_fpr_sweep.csv
# shipped in Submission_revised/plotscripts/. Several of ASN's own measured
# TPR values are exactly 1.000 (0/500 false negatives observed), which is
# not usable directly in ln(tpr/fpr)-style SPRT arithmetic and overstates
# precision a 500-session sample can support; those points use the
# "rule of three" conservative substitute for a zero-event rate,
# TPR_eff = 1 - 3/n = 1 - 3/500 = 0.994, documented inline below. Values
# strictly below 1.000 in the CSV are used as measured.
OPERATING_POINTS = [
    # (label,                      correlator,     vantage,          fpr,    tpr)
    ("fixed_one_path_fpr1e-3",     "combined",     "asn_one_path",   0.001,  0.998),
    ("fixed_both_paths_fpr1e-3",   "combined",     "asn_both_paths", 0.001,  0.994),  # measured 1.000, rule-of-three
    ("learned_one_path_fpr1e-3",   "learned_mlp",  "asn_one_path",   0.001,  0.91),
    ("learned_both_paths_fpr1e-3", "learned_mlp",  "asn_both_paths", 0.001,  0.996),
    ("fixed_one_path_fpr1e-2",     "combined",     "asn_one_path",   0.01,   0.994),  # measured 1.000, rule-of-three
    ("fixed_both_paths_fpr1e-2",   "combined",     "asn_both_paths", 0.01,   0.994),  # measured 1.000, rule-of-three
    ("fixed_one_path_fpr1e-1",     "combined",     "asn_one_path",   0.1,    0.994),  # measured 1.000, rule-of-three
    ("fixed_both_paths_fpr1e-1",   "combined",     "asn_both_paths", 0.1,    0.994),  # measured 1.000, rule-of-three
]

# Target SPRT error-rate budgets to sweep (alpha = beta, symmetric).
ERROR_BUDGETS = [0.05, 0.01, 0.001]


# ---------------------------------------------------------------------------
# Closed-form Wald average sample number (ASN)
# ---------------------------------------------------------------------------
def wald_boundaries(alpha: float, beta: float):
    A = math.log((1.0 - beta) / alpha)
    Bb = math.log(beta / (1.0 - alpha))
    return A, Bb


def per_round_llr_terms(tpr: float, fpr: float):
    """LLR contribution of a 'match' and a 'no-match' observation."""
    llr_match = math.log(tpr / fpr)
    llr_nomatch = math.log((1.0 - tpr) / (1.0 - fpr))
    return llr_match, llr_nomatch


def wald_asn_closed_form(tpr: float, fpr: float, alpha: float, beta: float):
    """Expected number of rounds to reach a decision, under each hypothesis,
    via Wald's classical approximation (ignores boundary overshoot)."""
    A, Bb = wald_boundaries(alpha, beta)
    llr_m, llr_nm = per_round_llr_terms(tpr, fpr)

    # E[LLR increment | H1] = tpr*llr_m + (1-tpr)*llr_nm
    mean_llr_h1 = tpr * llr_m + (1.0 - tpr) * llr_nm
    # E[LLR increment | H0] = fpr*llr_m + (1-fpr)*llr_nm
    mean_llr_h0 = fpr * llr_m + (1.0 - fpr) * llr_nm

    # E[N|H1] ~= [(1-beta)*B + beta*A] / mean_llr_h1   (Wald's approximation,
    # using the fact that decisions land at ~A under H1, ~B under H0)
    e_n_h1 = ((1.0 - beta) * Bb + beta * A) / mean_llr_h1 if mean_llr_h1 != 0 else float("inf")
    e_n_h0 = (alpha * Bb + (1.0 - alpha) * A) / mean_llr_h0 if mean_llr_h0 != 0 else float("inf")
    # E[N|H1] should be positive (both numerator and mean_llr_h1 are negative
    # in the natural sign convention below); take abs to report a round count.
    return abs(e_n_h1), abs(e_n_h0)


# ---------------------------------------------------------------------------
# Monte Carlo SPRT simulation (validates the closed form, gives real
# small-sample distribution rather than only an asymptotic expectation)
# ---------------------------------------------------------------------------
def simulate_sprt(tpr: float, fpr: float, alpha: float, beta: float,
                   n_trials: int, true_hypothesis: str, rng: random.Random,
                   max_rounds: int = 200_000):
    A, Bb = wald_boundaries(alpha, beta)
    llr_m, llr_nm = per_round_llr_terms(tpr, fpr)
    p_match = tpr if true_hypothesis == "H1" else fpr

    rounds_list = []
    correct = 0
    for _ in range(n_trials):
        llr = 0.0
        rounds = 0
        decision = None
        while rounds < max_rounds:
            rounds += 1
            match = rng.random() < p_match
            llr += llr_m if match else llr_nm
            if llr >= A:
                decision = "H1"
                break
            if llr <= Bb:
                decision = "H0"
                break
        if decision is None:
            decision = "H1" if llr > (A + Bb) / 2 else "H0"  # forced call at cap
        rounds_list.append(rounds)
        if decision == true_hypothesis:
            correct += 1
    rounds_list.sort()
    n = len(rounds_list)
    median = rounds_list[n // 2]
    p95 = rounds_list[int(0.95 * n)] if n > 1 else rounds_list[0]
    mean = sum(rounds_list) / n
    return {
        "mean_rounds": mean,
        "median_rounds": median,
        "p95_rounds": p95,
        "empirical_accuracy": correct / n_trials,
    }


# ---------------------------------------------------------------------------
# Noise-aware SPRT: background-noise extension
# ---------------------------------------------------------------------------
# WHY THIS EXISTS, the honest gap flagged in LITERATURE_GAPS.md §3.5 item 2:
# the SPRT above assumes the decoy's per-round match probability is a single,
# precisely-known point value (FPR, taken directly from flowcorr_results.csv).
# Real statistical-disclosure-attack literature (Danezis 2003's original
# framing, and 2023-2024 follow-ups on noise-round estimation) treats this as
# a NOISE ESTIMATION problem: the adversary doesn't actually know the true
# background false-match rate precisely, and different decoy candidates are
# not uniformly "equally fake", some decoys structurally resemble the true
# correspondent more than others (e.g. two users with similar traffic
# patterns), giving them an elevated, candidate-specific match probability
# the naive fixed-FPR model doesn't capture.
#
# Modeled here as a latent per-candidate decoy match rate, drawn ONCE per
# candidate (not per round, this is the key structural change) from a
# Beta distribution with mean = the measured FPR and a tunable coefficient
# of variation (cv) representing how much noisier real decoys are than the
# clean, homogeneous population flowcorr_run.py's synthetic traces assume.
# cv=0 recovers the original clean model exactly. Every ROUND for a given
# candidate then draws from that candidate's OWN latent rate, not the
# population-average FPR, rounds within one candidate's SPRT run are
# therefore correlated through this shared latent variable, structurally
# identical in spirit to Task A's rho-parametrized shared-operator mixture
# (`asn_correlated_disclosure.py`), applied here to decoy noise instead of
# compromise correlation.
#
# The adversary's DECISION RULE is unchanged (same LLR formula, still
# assumes the clean point-FPR model, this models a REAL adversary running
# the same practical test against a MESSIER world, not an adversary who has
# somehow learned the true noise distribution and corrected for it).
def beta_params_from_mean_cv(mean: float, cv: float):
    """alpha/beta for a Beta distribution with the given mean and
    coefficient of variation (std/mean). cv=0 returns None (point mass)."""
    if cv <= 0.0:
        return None
    var = (cv * mean) ** 2
    # Beta variance: mean*(1-mean)/(alpha+beta+1) = var  =>  solve for alpha+beta
    if var >= mean * (1.0 - mean):
        var = mean * (1.0 - mean) * 0.99  # cap to keep alpha,beta > 0
    total = mean * (1.0 - mean) / var - 1.0
    total = max(total, 0.01)
    alpha = mean * total
    beta_ = (1.0 - mean) * total
    return max(alpha, 1e-3), max(beta_, 1e-3)


def simulate_sprt_noisy(tpr: float, fpr: float, alpha: float, beta: float,
                         n_trials: int, true_hypothesis: str, noise_cv: float,
                         rng: random.Random, max_rounds: int = 200_000):
    """Like simulate_sprt, but under H0 each simulated candidate's TRUE
    per-round match probability is drawn once from Beta(mean=fpr, cv=noise_cv)
    rather than fixed at fpr, the adversary's decision rule (LLR formula)
    still assumes the clean fpr, unchanged from simulate_sprt. Under H1 the
    true pair's TPR is left un-noised (the literature's noise concern is
    specifically about background/decoy heterogeneity, not the true-pair
    signal itself, see docstring above)."""
    A, Bb = wald_boundaries(alpha, beta)
    llr_m, llr_nm = per_round_llr_terms(tpr, fpr)
    beta_params = beta_params_from_mean_cv(fpr, noise_cv) if true_hypothesis == "H0" else None

    rounds_list = []
    correct = 0
    for _ in range(n_trials):
        if true_hypothesis == "H1":
            p_match = tpr
        elif beta_params is None:
            p_match = fpr
        else:
            a_b, b_b = beta_params
            p_match = min(0.999999, max(1e-6, rng.betavariate(a_b, b_b)))

        llr = 0.0
        rounds = 0
        decision = None
        while rounds < max_rounds:
            rounds += 1
            match = rng.random() < p_match
            llr += llr_m if match else llr_nm
            if llr >= A:
                decision = "H1"
                break
            if llr <= Bb:
                decision = "H0"
                break
        if decision is None:
            decision = "H1" if llr > (A + Bb) / 2 else "H0"
        rounds_list.append(rounds)
        if decision == true_hypothesis:
            correct += 1
    rounds_list.sort()
    n = len(rounds_list)
    median = rounds_list[n // 2]
    mean_r = sum(rounds_list) / n
    return {
        "mean_rounds": mean_r,
        "median_rounds": median,
        "empirical_accuracy": correct / n_trials,
    }


# ---------------------------------------------------------------------------
# Comparison anchor: how many rounds would the compromise-based ladder need
# for the same confidence level, reusing asn_repeated_sessions.py's model
# (imported, not re-derived) at a realistic f=0.10, rho=0.01 (the paper's own
# realistic deployment point and this round's headline correlation finding).
# ---------------------------------------------------------------------------
def compromise_ladder_comparison():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from asn_correlated_disclosure import analytic_shared_operator
    from asn_repeated_sessions import sessions_to_threshold

    rows = []
    for event, k in (("D1", 2), ("D2", 4)):
        for f, rho in ((0.10, 0.0), (0.10, 0.01)):
            p = analytic_shared_operator(f, rho, k)
            n50 = sessions_to_threshold(p, 0.5)
            rows.append({"event": event, "f": f, "rho": rho,
                          "per_session_p": p, "n50_sessions": n50})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trials", type=int, default=20_000,
                     help="Monte Carlo SPRT simulations per (operating point, alpha, hypothesis)")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--seed", type=int, default=20260710)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    rng = random.Random(args.seed)

    print("=" * 78)
    print("  Task A genuine follow-up: statistical disclosure attack (SPRT)")
    print("=" * 78)

    rows = []
    for label, correlator, vantage, fpr, tpr in OPERATING_POINTS:
        for alpha in ERROR_BUDGETS:
            beta = alpha  # symmetric error budget
            e_n_h1, e_n_h0 = wald_asn_closed_form(tpr, fpr, alpha, beta)
            mc_h1 = simulate_sprt(tpr, fpr, alpha, beta, args.trials, "H1", rng)
            mc_h0 = simulate_sprt(tpr, fpr, alpha, beta, args.trials, "H0", rng)
            rows.append({
                "label": label, "correlator": correlator, "vantage": vantage,
                "fpr": fpr, "tpr": tpr, "alpha": alpha, "beta": beta,
                "closed_form_e_rounds_true_pair": e_n_h1,
                "closed_form_e_rounds_decoy": e_n_h0,
                "mc_mean_rounds_true_pair": mc_h1["mean_rounds"],
                "mc_median_rounds_true_pair": mc_h1["median_rounds"],
                "mc_p95_rounds_true_pair": mc_h1["p95_rounds"],
                "mc_accuracy_true_pair": mc_h1["empirical_accuracy"],
                "mc_mean_rounds_decoy": mc_h0["mean_rounds"],
                "mc_median_rounds_decoy": mc_h0["median_rounds"],
                "mc_accuracy_decoy": mc_h0["empirical_accuracy"],
            })
            print(f"  {label:30s} alpha=beta={alpha:<7} "
                  f"E[N|true]={e_n_h1:7.1f} (mc median {mc_h1['median_rounds']:5d}, "
                  f"acc {mc_h1['empirical_accuracy']:.3f})  "
                  f"E[N|decoy]={e_n_h0:7.1f} (mc median {mc_h0['median_rounds']:5d}, "
                  f"acc {mc_h0['empirical_accuracy']:.3f})")

    out_path = os.path.join(args.out_dir, "asn_sda_sprt.csv")
    fields = ["label", "correlator", "vantage", "fpr", "tpr", "alpha", "beta",
              "closed_form_e_rounds_true_pair", "closed_form_e_rounds_decoy",
              "mc_mean_rounds_true_pair", "mc_median_rounds_true_pair",
              "mc_p95_rounds_true_pair", "mc_accuracy_true_pair",
              "mc_mean_rounds_decoy", "mc_median_rounds_decoy", "mc_accuracy_decoy"]
    with open(out_path, "w", newline="") as fp:
        fp.write("# Task A follow-up: Wald SPRT statistical disclosure attack\n")
        fp.write("# accumulating Task B's per-round flow-correlator evidence\n")
        fp.write("# (tpr, fpr from flowcorr_results.csv / flowcorr_ml_results.csv)\n")
        fp.write("# across repeated observations of the same candidate (sender,\n")
        fp.write("# receiver) pair, WITHOUT requiring any single-round full\n")
        fp.write("# compromise. closed_form_* = Wald's asymptotic ASN approximation;\n")
        fp.write("# mc_* = Monte Carlo simulation of the actual SPRT (validates the\n")
        fp.write("# closed form and reports real small-sample distribution).\n")
        w = csv.DictWriter(fp, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in r.items()})
    print(f"\n  Wrote {out_path}  ({len(rows)} rows)")

    # -- Comparison anchor against the compromise-based ladder -----------
    ladder_rows = compromise_ladder_comparison()
    ladder_path = os.path.join(args.out_dir, "asn_sda_vs_ladder.csv")
    with open(ladder_path, "w", newline="") as fp:
        fp.write("# Comparison anchor: compromise-based disclosure ladder's N_50\n")
        fp.write("# (asn_repeated_sessions.py machinery, f=0.10) vs. this script's\n")
        fp.write("# SPRT statistical-disclosure N (median rounds to confident ID,\n")
        fp.write("# alpha=beta=0.01) at the SAME realistic f=0.10 deployment point.\n")
        w = csv.DictWriter(fp, fieldnames=["event", "f", "rho", "per_session_p", "n50_sessions"])
        w.writeheader()
        for r in ladder_rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in r.items()})
    print(f"  Wrote {ladder_path}  ({len(ladder_rows)} rows)")

    print("\n  Compromise-ladder N_50 (for comparison, f=0.10):")
    for r in ladder_rows:
        n50 = r["n50_sessions"]
        n50_str = f"{n50:,}" if isinstance(n50, int) else str(n50)
        print(f"    {r['event']} rho={r['rho']:.2f}: N_50 = {n50_str} sessions")

    print("\n  SDA (alpha=beta=0.01, strict-FPR operating points):")
    for r in rows:
        if abs(r["alpha"] - 0.01) < 1e-9 and "fpr1e-3" in r["label"]:
            print(f"    {r['label']}: median {r['mc_median_rounds_true_pair']} rounds "
                  f"to confident ID (accuracy {r['mc_accuracy_true_pair']:.3f})")

    # -- Noise-aware SPRT: does the naive model's guarantee erode under
    # decoy population heterogeneity? Swept at the strict FPR=1e-3
    # asn_both_paths operating point, alpha=beta=0.01, both correlators.,
    print("\n" + "=" * 78)
    print("  Noise-aware extension: decoy false-accept rate under population heterogeneity")
    print("=" * 78)
    noise_rows = []
    noise_cvs = [0.0, 0.25, 0.5, 1.0, 2.0]
    # Pulled from OPERATING_POINTS by label instead of retyped, this list
    # used to carry its own separate literal copy of these tuples, which is
    # exactly how the fixed_both_paths_fpr1e-3 TPR (0.55 here vs. the
    # correct 0.545 in OPERATING_POINTS above) silently drifted within this
    # same file. Weaker FPR operating points are included here because the
    # strict FPR=1e-3 points resolve in median 1 round, too fast for
    # accumulated decoy heterogeneity to have any chance to bias the
    # decision. These need multiple rounds to reach a verdict, which is
    # exactly the regime where per-candidate noise correlation across
    # rounds (this section's model) can actually compound.
    _by_label = {label: (label, correlator, vantage, fpr, tpr)
                 for label, correlator, vantage, fpr, tpr in OPERATING_POINTS}
    noise_targets = [_by_label["fixed_both_paths_fpr1e-3"],
                      _by_label["learned_both_paths_fpr1e-3"],
                      _by_label["fixed_both_paths_fpr1e-1"],
                      _by_label["fixed_one_path_fpr1e-1"]]
    alpha = beta = 0.01
    for label, correlator, vantage, fpr, tpr in noise_targets:
        for cv in noise_cvs:
            mc_h1 = simulate_sprt_noisy(tpr, fpr, alpha, beta, args.trials, "H1", cv, rng)
            mc_h0 = simulate_sprt_noisy(tpr, fpr, alpha, beta, args.trials, "H0", cv, rng)
            noise_rows.append({
                "label": label, "correlator": correlator, "vantage": vantage,
                "fpr": fpr, "tpr": tpr, "noise_cv": cv,
                "target_alpha": alpha,
                "mc_median_rounds_true_pair": mc_h1["median_rounds"],
                "mc_mean_rounds_true_pair": mc_h1["mean_rounds"],
                "mc_accuracy_true_pair": mc_h1["empirical_accuracy"],
                "mc_median_rounds_decoy": mc_h0["median_rounds"],
                "mc_false_accept_rate": 1.0 - mc_h0["empirical_accuracy"],
            })
            print(f"  {label:30s} cv={cv:.2f}  "
                  f"median rounds (true)={mc_h1['median_rounds']:3d}  "
                  f"target alpha={alpha}  measured false-accept={1.0 - mc_h0['empirical_accuracy']:.4f}")

    noise_path = os.path.join(args.out_dir, "asn_sda_noise_sensitivity.csv")
    fields2 = ["label", "correlator", "vantage", "fpr", "tpr", "noise_cv", "target_alpha",
               "mc_median_rounds_true_pair", "mc_mean_rounds_true_pair", "mc_accuracy_true_pair",
               "mc_median_rounds_decoy", "mc_false_accept_rate"]
    with open(noise_path, "w", newline="") as fp:
        fp.write("# Task A follow-up: noise-aware SPRT sensitivity sweep.\n")
        fp.write("# noise_cv: coefficient of variation of the decoy population's TRUE\n")
        fp.write("# per-candidate match rate around the measured FPR (Beta-distributed,\n")
        fp.write("# drawn once per candidate, held fixed across that candidate's rounds).\n")
        fp.write("# cv=0 recovers the clean/naive model exactly. The adversary's decision\n")
        fp.write("# rule is unchanged (still assumes the clean point-FPR), this measures\n")
        fp.write("# how much the naive model's alpha=0.01 false-accept guarantee erodes\n")
        fp.write("# when real decoys are heterogeneous rather than uniformly at the mean FPR.\n")
        w = csv.DictWriter(fp, fieldnames=fields2)
        w.writeheader()
        for r in noise_rows:
            w.writerow({k: (f"{v:.6g}" if isinstance(v, float) else v) for k, v in r.items()})
    print(f"\n  Wrote {noise_path}  ({len(noise_rows)} rows)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
