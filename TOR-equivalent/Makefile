# Makefile: TOR v1 / AnonSecNet benchmark project (Linux/POSIX build)
#
# Targets:
#   make all              build all binaries (TOR nodes + all benchmarks)
#   make tor_bench_all    build all TOR-side benchmark binaries
#   make run_tor          start nodes + SG in background
#   make stop             kill all running instances
#   make run_bench_tor    run all TOR benchmarks (no nodes needed for most)
#   make clean            remove binaries and results
#
# NOTE: the benchmark sources (bench.c, tor_bench_*.c, tor_*_instrumented.c)
# live in ../tests/TOR, not in this directory, that mismatch predates the
# Linux port. Object/binary files for them are still placed here so
# run_tor/run_bench_tor keep working with bare filenames.

CC        = gcc
CFLAGS    = -O2 -Wall -Wextra -I. -Icommon -pthread
LIBS      = -lssl -lcrypto -lm -pthread
COMMON    = common/crypto.c common/net.c

# tor_bench_fig2/fig3/table2 use flat #include "crypto.h" / "config.h",
# i.e. they expect common/ itself on the include path (not TOR-equivalent/).
BENCHFLAGS = -O2 -Wall -Wextra -I. -Icommon -pthread

.PHONY: all tor_bench_all run_tor stop run_client \
        run_bench_asn run_bench_tor run_bench_all clean

# -- Build all binaries ------------------------------------------------------
all: tor_mix_node.exe tor_client.exe tor_sg.exe bench.exe \
     tor_bench_fig2.exe tor_bench_fig3.exe tor_bench_fig4.exe \
     tor_bench_fig5.exe tor_bench_table2.exe

tor_bench_all: tor_bench_fig2.exe tor_bench_fig3.exe tor_bench_fig4.exe \
               tor_bench_fig5.exe tor_bench_table2.exe

# -- Tor-equivalent node binaries --------------------------------------------
tor_mix_node.exe: tor_mix_node.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

tor_client.exe: tor_client.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

tor_sg.exe: tor_sg.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# -- Combined benchmark harness (sources in ../tests/TOR) -------------------
bench.exe: ../tests/TOR/bench.c $(COMMON) common/packet.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# -- TOR benchmark binaries (sources in ../tests/TOR) ------------------------
# Figure 2: Per-hop processing latency (Tor CTR model, no nodes needed)
tor_bench_fig2.exe: ../tests/TOR/tor_bench_fig2_perhop.c common/crypto.c
	$(CC) $(BENCHFLAGS) -o $@ $^ $(LIBS)

# Figure 3: Path construction time (ECDHE cost, no nodes needed)
tor_bench_fig3.exe: ../tests/TOR/tor_bench_fig3_pathconstruction.c common/crypto.c
	$(CC) $(BENCHFLAGS) -o $@ $^ $(LIBS)

# Figure 4: Anonymity set Monte Carlo (pure simulation, no nodes needed)
tor_bench_fig4.exe: ../tests/TOR/tor_bench_fig4_anonymity.c
	$(CC) $(BENCHFLAGS) -o $@ $^ -lm

# Figure 5: Cover traffic overhead (Tor=0%, comparison table, no nodes needed)
tor_bench_fig5.exe: ../tests/TOR/tor_bench_fig5_cover.c
	$(CC) $(BENCHFLAGS) -o $@ $^ -lm

# Table 2: Throughput comparison (in-process, no nodes needed)
tor_bench_table2.exe: ../tests/TOR/tor_bench_table2_throughput.c common/crypto.c
	$(CC) $(BENCHFLAGS) -o $@ $^ $(LIBS)

# -- Instrumented nodes (functional testing; sources in ../tests/TOR) -------
tor_mix_node_instrumented.exe: ../tests/TOR/tor_mix_node_instrumented.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

tor_client_instrumented.exe: ../tests/TOR/tor_client_instrumented.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

tor_sg_instrumented.exe: ../tests/TOR/tor_sg_instrumented.c $(COMMON)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# -- Start nodes -------------------------------------------------------------
run_tor: tor_mix_node.exe tor_sg.exe
	@echo "Killing any old instances..."
	-pkill -f tor_mix_node.exe 2>/dev/null; true
	-pkill -f tor_sg.exe       2>/dev/null; true
	-pkill -f tor_client.exe   2>/dev/null; true
	@sleep 1
	@echo "Starting Tor-equivalent nodes..."
	./tor_mix_node.exe 9040 &
	./tor_mix_node.exe 9041 &
	./tor_mix_node.exe 9042 &
	./tor_sg.exe &
	@echo "Waiting for nodes to be ready..."
	@sleep 4
	@echo "Nodes ready."

stop:
	-pkill -f tor_mix_node.exe 2>/dev/null; true
	-pkill -f tor_sg.exe       2>/dev/null; true
	-pkill -f tor_client.exe   2>/dev/null; true
	@echo "All instances stopped."

run_client: tor_client.exe
	./tor_client.exe

# -- Run ASN benchmarks (original bench.exe, nodes must be running) ----------
run_bench_asn: bench.exe
	@echo "--- Figure 2: per-hop latency (no nodes needed) ---"
	./bench.exe fig2   > results_asn_fig2.csv
	@echo "--- Figure 3: path construction (nodes needed) ---"
	./bench.exe fig3   > results_asn_fig3.csv
	@echo "--- Figure 4: anonymity set Monte Carlo (no nodes needed) ---"
	./bench.exe fig4   > results_asn_fig4.csv
	@echo "--- Figure 5: cover traffic overhead (no nodes needed) ---"
	./bench.exe fig5   > results_asn_fig5.csv
	@echo "--- Table 2: throughput (nodes needed) ---"
	./bench.exe table2 > results_asn_table2.csv
	@echo "ASN benchmarks complete."

# -- Run TOR benchmarks (standalone, no nodes needed) -----------------------
run_bench_tor: tor_bench_all
	@echo "--- TOR Figure 2: per-hop latency (CTR model, no nodes needed) ---"
	./tor_bench_fig2.exe > results_tor_fig2.csv
	@echo "--- TOR Figure 3: path construction time (no nodes needed) ---"
	./tor_bench_fig3.exe > results_tor_fig3.csv
	@echo "--- TOR Figure 4: anonymity set Monte Carlo (no nodes needed) ---"
	./tor_bench_fig4.exe > results_tor_fig4.csv
	@echo "--- TOR Figure 5: cover traffic overhead (no nodes needed) ---"
	./tor_bench_fig5.exe > results_tor_fig5.csv
	@echo "--- TOR Table 2: throughput (no nodes needed) ---"
	./tor_bench_table2.exe > results_tor_table2.csv
	@echo "TOR benchmarks complete. Run: python scripts/bench_plot.py"

# -- Run all benchmarks ------------------------------------------------------
run_bench_all: run_bench_tor run_bench_asn
	@echo "All benchmarks complete."

# -- Clean -------------------------------------------------------------------
clean:
	-rm -f *.exe results_*.csv
	@echo "Clean done."
