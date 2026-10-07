# dcf_adapter: DeepCoFFEA FEN training adapter

Adapts DeepCoFFEA's flow-embedding-network (FEN) training pipeline to run
against Anon-Sec-Net's synthetic traces.

## Split dependency model (why there's a Dockerfile here and nowhere else)

This directory has **two separate Python environments**:

1. **Host virtualenv** (see `../README.md`'s setup section): everything
   except training. `gen_dcf_traces.py`, `run_filter_and_parse.py`,
   `dcf_filter_lib.py`/`dcf_parse_lib.py`, and `extract_and_score*.py` all
   run under the project's normal virtualenv (they need `flowcorr_run.py`
   and the rest of `eval2/scripts/`, not DeepCoFFEA's training stack).
2. **`dcf-env` Docker image** (`Dockerfile.dcf`): only for
   `train_fens_adapted.py`, the actual FEN training step. DeepCoFFEA's
   original code pins `tensorflow==1.13.1`/`keras==2.3.0`
   (2019-era, Python 3 but a TF1 graph-mode API). Installing that
   alongside this project's modern `torch`/`numpy`/`scikit-learn` stack in
   the same environment is not realistically satisfiable (conflicting pins,
   TF1 vs. TF2/PyTorch CUDA runtime clashes), so it's isolated in a
   container instead of forced into `requirements.txt`.

## Building and running

```bash
docker build -t dcf-env -f Dockerfile.dcf .

docker run --rm \
  -e DCF_NB_EPOCHS=3000 -e DCF_LOSS_TARGET=0.002 -e DCF_PATIENCE=300 \
  -v "$PWD":/work -w /work dcf-env \
  python3 train_fens_adapted.py \
    --input parsed_single --model model_out_single_long/model_ --test model_out_single_long/test
```

`run_batch_training.sh` wraps both conditions (`single_path` and
`asn_both_paths`) sequentially with this same pattern.

No pre-generated traces, parsed pickles, or trained models are shipped in
this repository. `gen_dcf_traces.py`/`run_filter_and_parse.py` produce
the `dcf_data_*/` and `parsed_*.pickle` inputs, and
`train_fens_adapted.py` writes its checkpoints to `model_out_*/`.

Everything else in this directory (`gen_dcf_traces.py`, scoring scripts)
runs directly with the host venv's `python3`, no Docker needed.

## Licence

`new_model.py`, `dcf_filter_lib.py`, `dcf_parse_lib.py`,
`train_fens_adapted.py` and `eval_dcf_adapted.py` are copied or adapted
from DeepCoFFEA (https://github.com/traffic-analysis/deepcoffea, Oh et al.,
IEEE S&P 2022) and remain under its MIT licence, reproduced in
[`LICENSE-DeepCoFFEA`](LICENSE-DeepCoFFEA). The rest of this directory is
under the repository's GPL-3.0-or-later licence.
