# eval2: Attack-simulation and evaluation suite

Monte Carlo and empirical evaluation scripts covering ASN's disclosure
model, flow-correlation resistance, and cover-traffic behavior under load.

Each task below is reproducible from a single command with a fixed seed.
The production benchmark scripts in `../scripts/` are separate and are
not modified by anything here.

**Setup:** `python3.11 -m venv .venv && .venv/bin/pip install -r
requirements.txt` (run from `ASN/eval2/`, matching every task's own `cd
ASN/eval2` below). `dcf_adapter/` additionally requires
`tensorflow`/`keras`, isolated in its own Docker image. See
`dcf_adapter/README.md`.

## Task A: Correlated-compromise disclosure model

**Status: done.**

```bash
cd ASN/eval2
python scripts/asn_correlated_disclosure.py --sessions 20000 --seed 20260710 --out-dir .
python scripts/plot_correlated.py --dir . --out figures/fig_correlated.pdf
python scripts/plot_correlated.py --dir . --out figures/fig_correlated.eps
```

Outputs: `asn_correlated_ladder.csv`, `asn_crossover_rho.csv`,
`figures/fig_correlated.pdf`/`.eps`.

D1/D2/D3 are `f^2`/`f^4`/`f^7`: a compromised entry+exit pair on a
single path already suffices for routing-level linkage via timing
correlation, so the naive full-position count overstated every exponent.

Headline: at `f=0.1`, ASN's D2 (`f^4`) advantage over Tor hidden services
(`f^3`) survives only up to `ρ ≈ 0.01` correlation between the mix-node/SG/CS
operator populations, a fragile advantage (now one order of magnitude, not
five), not a robust one.

**Follow-up: ablating dual-path routing vs. role-decoupled infrastructure**

```bash
python scripts/asn_ablation_disclosure.py --out-dir .
python scripts/plot_ablation.py --dir . --out figures/fig_ablation.pdf
```

Outputs: `asn_ablation_crossover.csv`, `figures/fig_ablation.pdf`/`.eps`.

Headline: dual-path routing and role-decoupling are **not additive**:
dual-path-only is exactly Event D1 (`k=2`), identical in exponent to a
single path's own entry-exit correlation, so it never crosses the Tor-HS
baseline at all (`f^2 > f^3` for every `f`, i.e. it's already worse than
Tor before any correlation is introduced). Role-decoupling-only (`k=4`) and
the full combination (`k=4`, ASN's actual D2) are **the same curve**,
exactly, at every swept `f`: role decoupling accounts for the entirety of
ASN's advantage over Tor hidden services, crossing the baseline at the same
`ρ*≈0.009` at `f=0.1` either way; dual-path routing's own contribution to
this metric is negative.

**Follow-up: cumulative disclosure risk over repeated sessions**

```bash
python scripts/asn_repeated_sessions.py --out-dir .
python scripts/plot_repeated_sessions.py --dir . --out figures/fig_repeated.pdf
```

Outputs: `asn_repeated_sessions_n50.csv`, `asn_repeated_sessions_curves.csv`,
`figures/fig_repeated.pdf`/`.eps`.

Headline: at `f=0.10`, D2's
per-session `10⁻⁴` probability implies a user could make ~6,932 sessions
before 50% cumulative disclosure risk under pure independence; at
`ρ=0.01` that collapses to **631 sessions**, an ~11-fold drop (not the
originally-claimed hundred-thousand-fold collapse, an artifact of the
wrong `f^8` exponent). D1's own independence-case budget is far lower to
begin with, `N_50≈69` sessions at `ρ=0` (only `64` at `ρ=0.01`); D1 was
never well protected by the independence assumption, a direct consequence
of routing-level linkage costing only `f^2`). Closes a gap the paper
leaves explicit: the Long-Term Intersection Attacks section addresses
identifier linking but says nothing about the compromise-based repeated-use
risk.

**Follow-up: does the implementation actually redraw paths per session?**

```bash
python scripts/asn_topology_freshness.py --out-dir .
```

Outputs: `asn_topology_freshness.csv`.

Headline: checking the Uniformity assumption behind the `N_50` figures
against the code found **no node-selection logic exists anywhere**:
`client.c`/`sender.c` hardcode a fixed 12-node topology. Counter-
intuitively this makes the prototype *safer* against the compromise-based
ladder (risk never compounds with reuse) but introduces a separate,
unquantified network-level linkability risk (fixed first-hop contact
pattern is trivially observable by a passive GPA) that directly bears on
the paper's claimed GPA-resistance.

**Follow-up: quantifying that GPA-linkability risk**

```bash
python scripts/asn_gpa_linkability.py --out-dir .
python scripts/plot_gpa_linkability.py --dir . --out figures/fig_gpa_linkability.pdf
```

Outputs: `asn_gpa_linkability.csv`, `asn_gpa_linkability_curves.csv`,
`figures/fig_gpa_linkability.pdf`/`.png`.

Headline: the actual implementation (a single fixed entry node, `M=1`)
gives a single-vantage-point passive observer **certain linkage on the
very first session, for free**: a deterministic property of the fixed
topology, not a probabilistic risk. A properly diverse deployment
honoring the paper's own Uniformity assumption (entry-node population
`M`) would force the same adversary to wait `O(M)` sessions for even a
50% chance of one observed hit (e.g. `N_50=347` at `M=500`), and would
cost instrumenting the entire population for certain linkage, exactly
what the fixed-topology simplification currently gives away for free.
Closes the second, more consequential half of the gap Sec. 9 left open.

## Task B: Empirical flow-correlation attack on dual-path splitting

**Status: done.**

```bash
cd ASN/eval2
python scripts/flowcorr_run.py --sessions 200 --seed 20260710 --out-dir .
python scripts/plot_flowcorr2.py --dir . --out figures/fig_flowcorr2.pdf --correlator combined
python scripts/plot_flowcorr2.py --dir . --out figures/fig_flowcorr2.eps --correlator combined
```

Outputs: `flowcorr_results.csv`, `flowcorr_roc_curves.csv`,
`flowcorr_traces/*_sample.csv`, `figures/fig_flowcorr2.pdf`/`.eps`.

Note: the codebase does not split a single flow's packets round-robin
across path A/B: path A carries the whole outbound direction, path B the
whole inbound direction. The adversary model in `flowcorr_run.py` is
adapted accordingly rather than assuming a 50/50 split that doesn't
match the implementation.

Headline (current, cover forwarded to every hop of both paths, matching
production `client.c`): at strict FPR=10⁻³, a flow-correlation adversary
reaches TPR=1.000 against the single-path Tor-equivalent baseline and
TPR=0.998-1.000 against ASN's dual-path split, statistically
indistinguishable from the no-cover ceiling. The dual-path split and its
cover traffic provide **no measurable mitigation** on their own; the
routing-level linkage cost this leaves unchanged is exactly the ladder's
own $f^2$ result (Task A). An earlier measurement using cover traffic
generated only at the entry link (not forwarded end to end) had reported
a partial mitigation (~52-55% TPR); the ablation isolating path
multiplicity from cover-traffic placement found that result was an
artifact of that asymmetric placement, not a real defense, and it does
not hold once cover is forwarded to every hop as production actually
does.

**Follow-up: stronger (learned) correlator**

```bash
python scripts/flowcorr_ml.py --train-sessions 500 --test-sessions 200 --neg-per-pos 8 --seed 20260710 --out-dir .
python scripts/plot_flowcorr_ml.py --dir . --out figures/fig_flowcorr_ml.pdf
```

Outputs: `flowcorr_ml_results.csv`, `flowcorr_ml_roc_curves.csv`,
`figures/fig_flowcorr_ml.pdf`/`.eps`.

Headline: stress-tested the finding above against a learned (MLP)
correlator and a Siamese-GRU sequence correlator with access to raw
features, strictly more information than the fixed Pearson/cosine
formulas. At the flow-correlation literature's own strict operating point
(FPR=10⁻⁵), results against the fixed correlators and the GRU correlator
are comparable to or exceed published attacks in this space (DeepCoFFEA,
FlowCoPCL); only the flattened-feature MLP correlator resolves this
specific operating point less cleanly, a tail-resolution artefact rather
than a real design advantage.

**Follow-up: hardened mode (shared-clock dispatch + per-hop mixing delay)**

```bash
python scripts/flowcorr_run.py --sessions 200 --seed 20260710 --hardened-jitter --out-dir hardened/
```

Categorically different from plain-mode cover forwarding, and bundles
two mechanisms behind one flag (`ASN_LOOPIX_MIXING`): real and cover
traffic share one fixed-rate dispatch clock, so the aggregate rate a
passive observer sees is bounded independent of load, and each mix node
additionally applies an independent per-hop mixing delay. Headline: real,
measured mitigation for most correlator/condition pairs (TPR reductions
from ceiling down to as low as 0.006 for the sequence correlator that
reached ceiling in the plain build), with one exception at the loosest
operating point, a partial, correlator-dependent mitigation, not a
defeat of correlation outright. A factorial ablation isolating the two
components (see the companion empirical study) finds the per-hop delay
accounts for almost all of this reduction; the shared clock's own
job is closing the activity-level side channel (Task C below), not this
flow-correlation result. Comes at a real, measured throughput cost (see
the paper's Throughput section).

**Follow-up: per-hop decoy termination and batch mixing**

```bash
# build the hopdecoy variants first (from ASN/): make hopdecoy_hardened
./flowcorr_hopdecoy_live_run.sh hopdecoy out-dir/
python scripts/flowcorr_hopdecoy_score.py --dir out-dir/
```

A structurally different mechanism from the hardened dispatch above:
decoy packets are terminated per hop and genuinely batch-mixed (250ms
flush, matching the production `POOL_MIX_FLUSH_MS` default) rather
than forwarded end to end. Headline: cuts detection by 71.5 percentage
points (100% to 28.5%) against a GRU-contrastive correlator, at
FPR=1e-3 (the strictest this specific live measurement's session count
resolves), against the single-path entry-exit correlation
Task A's D1 result identifies. This is evaluated at a looser FPR than
this same page's pool-mixing-alone TPR@1e-5 figures (as low as 0.032
at the 250ms default), so the two are not directly comparable; neither
number is evidence one mechanism outperforms the other. Decoy
termination defends a different attack than the hardened-mode
mitigation above, so the two are complementary, not alternatives.

## Task C: Cover-traffic load-leakage study

**Status: done.**

```bash
cd ASN/eval2
python scripts/coverleak_run.py --windows 300 --seed 20260710 --out-dir .
python scripts/plot_coverleak.py --dir . --out figures/fig_coverleak.pdf
python scripts/plot_coverleak.py --dir . --out figures/fig_coverleak.eps
```

Outputs: `cover_leakage.csv`, `figures/fig_coverleak.pdf`/`.eps`.

Note: an earlier cover-overhead benchmark had been measured under
`client_instrumented.c`'s Bernoulli fixed-rate cover mechanism, which is
structurally Loopix-style constant-rate, not the load-adaptive "real
traffic takes precedence" mechanism the paper describes and production
`client.c` implements. `coverleak_run.py`'s `asn_adaptive` scheme
measures the correct mechanism.

Headline: the constant-rate baseline stays at chance (AUC≈0.5) at every
load level (sanity check passes); the real adaptive mechanism leaks
activity level sharply once real load exceeds ~1.5× the cover ceiling
(AUC 1.000 by `load_level=0.6`); a smoothed-suppression mitigation was
tried and found to be **dominated**: no AUC improvement, and higher
overhead cost than doing nothing.

## Task D: Emulated WAN evaluation

**Status: not started.** This prototype and its evaluation suite run on
a single-host testbed rather than a wide-area deployment (matching the
methodology of comparable published systems); a WAN evaluation is a
natural next step but out of scope here.
