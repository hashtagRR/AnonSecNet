# Anon-Sec-Net (ASN)

A C prototype of a network-layer anonymous communication system, alongside
a Tor-equivalent baseline implementation and a Python evaluation suite
covering flow-correlation resistance, cover-traffic behavior, and
disclosure risk under partial network compromise.

ASN splits an anonymous session across two independently routed paths and
keeps routing, brokering and service-registry functions in separate
hands. The prototype and the evaluation suites in this repository measure
what that split provides against passive and active network-level
adversaries.

---

## Background

ASN was designed as a role-decoupled
architecture for network-layer anonymous communication ("Anon-Sec-Net: A
Role-Decoupled Architecture for Network-Layer Anonymous Communication").
The repository holds the reference implementation, the protocol design and
the security and performance evaluation of that design, including a
disclosure ladder that separates routing-level linkage, service disclosure
and full bidirectional disclosure under partial and correlated
infrastructure compromise, and two hardening mechanisms (shared-clock cover
dispatch, per-hop decoy termination with batch mixing).

The prototype's client striping, trace probes and exposure scripts also
serve as an independent second implementation in the study *How Much Does
One Path Reveal? Correlation Risk and Split-Policy Design for Multipath
Anonymous Communication*. That study's primary instrument is the AnonTestLab
emulator (https://github.com/hashtagRR/AnonTestLab); ASN cross-validates
its split-policy predictions on a real C network stack. The design
trade-offs listed in `ASN/README.md` (TOFU-style guard pinning, static
guard sets and the other simplifications noted there) are known properties
of this prototype.

---

## Repository layout

```
.
├── README.md             : this file
├── ASN/                  : the ASN prototype
│   ├── README.md
│   ├── Makefile
│   ├── common/           : shared crypto, packet format, networking, node pool
│   ├── client/           : Receiver role: session setup, GET, cover traffic
│   ├── sender/           : Sender role: session setup, PUT
│   ├── mix_node/         : relay node (EXTEND, DATA, RESPONSE, COVER)
│   ├── gateway/          : service gateway + cache server
│   ├── scripts/          : production benchmark plotting scripts
│   └── eval2/            : attack-simulation and evaluation suite
│       ├── README.md
│       ├── requirements.txt
│       ├── scripts/      : Monte Carlo + empirical adversary simulations
│       └── dcf_adapter/  : DeepCoFFEA flow-correlation baseline adapter
│           ├── README.md
│           └── Dockerfile.dcf
│
├── TOR-equivalent/       : baseline onion-routing implementation for comparison
│   ├── README.md
│   ├── Makefile
│   ├── common/
│   └── scripts/
│
├── results/              : curated data backing the paper's published numbers (see results/README.md)
│
└── tests/                : instrumented builds + benchmark/sweep harnesses
    ├── ASN/
    │   ├── README.md
    │   ├── *_instrumented.c        : timing/bandwidth-probed node variants
    │   ├── start_nodes*.sh / stop_nodes*.sh : network-lifecycle automation
    │   └── sweep_*.py, *_sweep_*.py : benchmark sweep drivers
    └── TOR/
        ├── README.md
        └── tor_*instrumented.c, tor_bench_*.c
```

Every directory containing a `README.md` has its own build/run
instructions and a description of what its scripts produce; see
[Documentation](#documentation) below for the full list, or jump
straight to [`ASN/README.md`](ASN/README.md) for the core system and
[`ASN/eval2/README.md`](ASN/eval2/README.md) for the evaluation suite.

---

## Documentation

| README | Covers |
|---|---|
| [`ASN/README.md`](ASN/README.md) | The core prototype: directory layout, network topology, build/run walkthrough (verified working end to end), packet format, config constants, build-time flags, Troubleshooting. **Start here.** |
| [`ASN/eval2/README.md`](ASN/eval2/README.md) | The attack-simulation/evaluation suite: every Task A/B/C condition, exact commands, and headline findings. |
| [`ASN/eval2/dcf_adapter/README.md`](ASN/eval2/dcf_adapter/README.md) | The DeepCoFFEA flow-correlation baseline adapter: why it needs a separate Docker environment and how to build/run it. |
| [`results/README.md`](results/README.md) | Curated measurement data backing the paper's published numbers (throughput, per-hop latency, path construction time, cover-traffic overhead), with the machine spec and exact claim each file backs. |
| [`TOR-equivalent/README.md`](TOR-equivalent/README.md) | The onion-routing baseline used as the comparison point throughout: build/run instructions and packet format. |
| [`tests/ASN/README.md`](tests/ASN/README.md) | Instrumented ASN node variants and the sweep scripts that drive them: network-lifecycle automation, per-sweep commands, output files. |
| [`tests/TOR/README.md`](tests/TOR/README.md) | The Tor-equivalent's own instrumented variants and benchmark sweeps. |

---

## Quickstart

```bash
# Build the core system
cd ASN && make all

# Build the Tor-equivalent baseline
cd ../TOR-equivalent && make

# Run the ASN evaluation suite (Monte Carlo + empirical adversary simulations)
cd ../ASN/eval2
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python scripts/asn_correlated_disclosure.py --sessions 20000 --seed 20260710 --out-dir .
```

Requires a C toolchain (GCC + OpenSSL dev headers) and Python 3.8+. See
[`ASN/README.md`](ASN/README.md#prerequisites) for the full prerequisite
list.

To see the anonymous network actually move content end to end (a
Sender uploading a value, a Receiver fetching it through the full
dual-path mix-node topology), see
[`ASN/README.md`](ASN/README.md#running); that walkthrough is verified
working step by step and covers the one non-obvious requirement (the
Sender process has to stay running for a `GET` to succeed).

---

## What's in each part

- **`ASN/`**: the prototype itself. Sphinx-style packet format, mix-node
  relaying, session setup over ECDHE, cover traffic, and two optional
  hardened-build mechanisms (shared-clock dispatch, pool mixing). See
  `ASN/README.md` for the packet format and wire protocol.
- **`TOR-equivalent/`**: a matched-scope onion-routing baseline used as
  the comparison point for every benchmark and attack simulation.
- **`tests/`**: instrumented variants of the ASN and Tor-equivalent
  binaries (adds timing/bandwidth measurement probes) plus the sweep
  scripts used to drive them across load levels and session counts.
- **`ASN/eval2/`**: the evaluation suite. Correlated-compromise
  disclosure modeling, empirical flow-correlation attacks against the
  dual-path split (fixed statistical correlators, a learned MLP
  correlator, and a DeepCoFFEA-based deep-learning baseline), and a
  cover-traffic load-leakage study. Each script is a self-contained,
  seeded, single-command simulation; see `ASN/eval2/README.md` for the
  full task list and headline findings.

---

## Troubleshooting

Hit an issue running the live network? See
[`ASN/README.md`'s Troubleshooting section](ASN/README.md#troubleshooting):
it covers the most common issues (stale ports from a previous run, the
`GET` handshake requiring a live Sender, content-size limits, benign
first-run warnings). A few things that apply more broadly:

- **`make` fails with a missing OpenSSL header.** Install the OpenSSL
  development package: `libssl-dev` on
  Debian/Ubuntu, `openssl-devel` on Fedora/RHEL.
- **`eval2/` scripts fail to import a package.** Make sure you're
  running them from inside the virtualenv you created
  (`.venv/bin/python`), and that you installed from
  `ASN/eval2/requirements.txt`.
- **`dcf_adapter/` training fails or can't find TensorFlow.** That
  directory uses its own Docker environment, separate from the host
  virtualenv. See `ASN/eval2/dcf_adapter/README.md`.

---

## Notes for reproducing results

Curated benchmark CSVs backing the reported paper results are included in results/. Trained models and the full historical measurement archive are not shipped; evaluation scripts can regenerate the remaining simulation outputs.
Regenerating a specific figure or table is documented in the relevant subdirectory's `README.md`.

---

## Licence

Copyright (C) 2026 the Anon-Sec-Net contributors

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option)
any later version. It is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See [`LICENSE`](LICENSE)
for the full text.

Some files in `ASN/eval2/dcf_adapter/` are copied or adapted from
DeepCoFFEA (Oh et al., IEEE S&P 2022) and remain under its MIT licence; see
[`ASN/eval2/dcf_adapter/README.md`](ASN/eval2/dcf_adapter/README.md#licence).
