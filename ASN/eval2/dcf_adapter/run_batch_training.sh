#!/bin/bash
# Long batch run: full DeepCoFFEA FEN training against ASN synthetic traces,
# using DeepCoFFEA authors' own stated convergence target (loss <= 0.002,
# their comment in train_fens_adapted.py) plus a 300-epoch plateau patience
# stop, up to a 3000-epoch ceiling. Runs sequentially (2 vCPUs, no benefit
# to parallelizing) inside the dcf-env Docker image.
set -e
cd "$(dirname "$0")"

echo "=== batch training started: $(date -u +%FT%TZ) ===" > batch_run.log

echo "--- [1/2] single_path condition ---" >> batch_run.log
docker run --rm \
  -e DCF_NB_EPOCHS=3000 -e DCF_LOSS_TARGET=0.002 -e DCF_PATIENCE=300 \
  -v "$PWD":/work -w /work dcf-env \
  python3 train_fens_adapted.py \
    --input parsed_single --model model_out_single_long/model_ --test model_out_single_long/test \
  >> batch_run.log 2>&1

echo "--- single_path finished: $(date -u +%FT%TZ) ---" >> batch_run.log

echo "--- [2/2] asn_both_paths condition ---" >> batch_run.log
docker run --rm \
  -e DCF_NB_EPOCHS=3000 -e DCF_LOSS_TARGET=0.002 -e DCF_PATIENCE=300 \
  -v "$PWD":/work -w /work dcf-env \
  python3 train_fens_adapted.py \
    --input parsed_asn --model model_out_asn_long/model_ --test model_out_asn_long/test \
  >> batch_run.log 2>&1

echo "--- asn_both_paths finished: $(date -u +%FT%TZ) ---" >> batch_run.log
echo "=== batch training DONE ===" >> batch_run.log
touch BATCH_DONE
