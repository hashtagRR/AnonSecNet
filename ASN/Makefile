CC      := gcc
CFLAGS  := -Wall -Wextra -g -O0 -Icommon -I. -pthread
LDFLAGS := -lssl -lcrypto -lm -pthread

# ASN_LOOPIX_MIXING build: Loopix-style per-hop mixing delay (mix_node.c)
# + constant-rate cover traffic (client.c/sender.c/client_instrumented.c).
# Only these sources' behavior actually depends on the flag; everything
# else (common/*, service_gateway*, cache_server*) is shared unchanged
# between the two builds.
CFLAGS_HARDENED := $(CFLAGS) -DASN_LOOPIX_MIXING

# Track-B experimental pool-mix build: batches packets at each mix node
# into a fixed flush window and releases them in shuffled order, instead
# of (or in place of testing against) ASN_LOOPIX_MIXING's per-packet
# delay. Only mix_node_instrumented.c's behavior depends on this flag;
# paired with the plain (non-hardened) client_instrumented.exe to
# isolate the mix-node-side effect. Experimental, not used by any
# figure/table in the paper.
CFLAGS_POOLMIX := $(CFLAGS) -DASN_POOL_MIXING

# ASN_HOP_DECOY build: per-hop decoy termination (client.c/sender.c build
# extra decoys that die at a random mix hop instead of reaching the SG;
# mix_node.c drops them in place). Composable with ASN_LOOPIX_MIXING,
# the decoy mechanism only handles WHICH packets get dropped where;
# reordering/delaying whatever a hop DOES forward is still
# ASN_LOOPIX_MIXING's job, reused here rather than duplicated. See
# config.h's HOP_DROP_MARKER comment for the design rationale.
CFLAGS_HOPDECOY          := $(CFLAGS) -DASN_HOP_DECOY
CFLAGS_HOPDECOY_HARDENED := $(CFLAGS) -DASN_HOP_DECOY -DASN_LOOPIX_MIXING

# ASN_POOL_MIXING ported into PRODUCTION mix_node.c (this used to exist
# only in the instrumented harness, see CFLAGS_POOLMIX above, same flag
# name, genuinely independent port, not a shared include; see mix_node.c's
# own comment on the HINT_WINDOW compatibility question this raised).
# Composable with ASN_HOP_DECOY: decoy-dropping decides WHICH packets get
# forwarded, pool-mixing decides WHEN/in-what-order whatever survives
# actually leaves, orthogonal mechanisms, combined here to test both
# together, which per-packet delay (ASN_LOOPIX_MIXING) alone did not
# capture (Track A: per-packet delay is too local for a 500ms-bin
# correlator to notice; pool-mixing reorders at that same 500ms scale).
CFLAGS_HOPDECOY_POOLMIX := $(CFLAGS) -DASN_HOP_DECOY -DASN_POOL_MIXING

COMMON_OBJ := common/crypto.o common/net.o common/packet.o common/node_pool.o

.PHONY: all nodes instrumented hardened poolmix hopdecoy hopdecoy_hardened hopdecoy_poolmix clean

all: nodes instrumented

# -- Common object files ---------------------------------------------------
common/%.o: common/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# -- Generic rule for all other subdirectory sources -----------------------
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# -- Standard node binaries ------------------------------------------------
nodes: mix_node.exe \
       service_gateway.exe cache_server.exe \
       client.exe sender.exe

mix_node.exe: $(COMMON_OBJ) mix_node/mix_node.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

service_gateway.exe: $(COMMON_OBJ) gateway/service_gateway.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

cache_server.exe: $(COMMON_OBJ) gateway/cache_server.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

client.exe: $(COMMON_OBJ) client/client.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sender.exe: $(COMMON_OBJ) sender/sender.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# -- Instrumented binaries (used by sweep scripts) --------------------------
# NOTE: the instrumented .c sources actually live in ../tests/ASN (not in
# mix_node/, client/, gateway/ as the object names below might suggest,
# this mismatch predates the Linux port). The object files are placed next
# to their sources in ../tests/ASN so `make clean` and incremental rebuilds
# behave normally.
instrumented: mix_node_instrumented.exe client_instrumented.exe service_gateway_instrumented.exe

../tests/ASN/%.o: ../tests/ASN/%.c
	$(CC) $(CFLAGS) -c $< -o $@

mix_node_instrumented.exe: $(COMMON_OBJ) ../tests/ASN/mix_node_instrumented.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

client_instrumented.exe: $(COMMON_OBJ) ../tests/ASN/client_instrumented.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

service_gateway_instrumented.exe: $(COMMON_OBJ) ../tests/ASN/service_gateway_instrumented.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bench_figure2.exe: $(COMMON_OBJ) ../tests/ASN/bench_figure2.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# -- Hardened (ASN_LOOPIX_MIXING) binaries ----------------------------------
# Same sources as `nodes`/`instrumented` above, compiled with the mixing
# flag on. Distinct object/binary names so both configurations can be
# built side by side without clobbering, `make all hardened` builds
# every binary needed for an A/B before/after benchmark comparison.
hardened: mix_node_hardened.exe client_hardened.exe sender_hardened.exe \
          mix_node_instrumented_hardened.exe client_instrumented_hardened.exe

mix_node/mix_node_hardened.o: mix_node/mix_node.c
	$(CC) $(CFLAGS_HARDENED) -c $< -o $@

mix_node_hardened.exe: $(COMMON_OBJ) mix_node/mix_node_hardened.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

client/client_hardened.o: client/client.c
	$(CC) $(CFLAGS_HARDENED) -c $< -o $@

client_hardened.exe: $(COMMON_OBJ) client/client_hardened.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sender/sender_hardened.o: sender/sender.c
	$(CC) $(CFLAGS_HARDENED) -c $< -o $@

sender_hardened.exe: $(COMMON_OBJ) sender/sender_hardened.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

../tests/ASN/mix_node_instrumented_hardened.o: ../tests/ASN/mix_node_instrumented.c
	$(CC) $(CFLAGS_HARDENED) -c $< -o $@

mix_node_instrumented_hardened.exe: $(COMMON_OBJ) ../tests/ASN/mix_node_instrumented_hardened.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

../tests/ASN/client_instrumented_hardened.o: ../tests/ASN/client_instrumented.c
	$(CC) $(CFLAGS_HARDENED) -c $< -o $@

client_instrumented_hardened.exe: $(COMMON_OBJ) ../tests/ASN/client_instrumented_hardened.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# -- Pool-mix (ASN_POOL_MIXING) binary --------------------------------------
poolmix: mix_node_instrumented_poolmix.exe

../tests/ASN/mix_node_instrumented_poolmix.o: ../tests/ASN/mix_node_instrumented.c
	$(CC) $(CFLAGS_POOLMIX) -c $< -o $@

mix_node_instrumented_poolmix.exe: $(COMMON_OBJ) ../tests/ASN/mix_node_instrumented_poolmix.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# -- Per-hop decoy (ASN_HOP_DECOY) binaries ---------------------------------
# `hopdecoy`: decoy termination only, no reordering (isolates the
# drop-in-place effect). `hopdecoy_hardened`: decoy termination + the
# existing Loopix-style per-hop delay together, the full mechanism as
# discussed. Both are production sources (mix_node.c/client.c/sender.c),
# not the instrumented harness, distinct object/binary names so plain,
# hardened, and hopdecoy builds coexist without clobbering each other.
hopdecoy: mix_node_hopdecoy.exe client_hopdecoy.exe sender_hopdecoy.exe

mix_node/mix_node_hopdecoy.o: mix_node/mix_node.c
	$(CC) $(CFLAGS_HOPDECOY) -c $< -o $@

mix_node_hopdecoy.exe: $(COMMON_OBJ) mix_node/mix_node_hopdecoy.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

client/client_hopdecoy.o: client/client.c
	$(CC) $(CFLAGS_HOPDECOY) -c $< -o $@

client_hopdecoy.exe: $(COMMON_OBJ) client/client_hopdecoy.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sender/sender_hopdecoy.o: sender/sender.c
	$(CC) $(CFLAGS_HOPDECOY) -c $< -o $@

sender_hopdecoy.exe: $(COMMON_OBJ) sender/sender_hopdecoy.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

hopdecoy_hardened: mix_node_hopdecoy_hardened.exe client_hopdecoy_hardened.exe \
                    sender_hopdecoy_hardened.exe

mix_node/mix_node_hopdecoy_hardened.o: mix_node/mix_node.c
	$(CC) $(CFLAGS_HOPDECOY_HARDENED) -c $< -o $@

mix_node_hopdecoy_hardened.exe: $(COMMON_OBJ) mix_node/mix_node_hopdecoy_hardened.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

client/client_hopdecoy_hardened.o: client/client.c
	$(CC) $(CFLAGS_HOPDECOY_HARDENED) -c $< -o $@

client_hopdecoy_hardened.exe: $(COMMON_OBJ) client/client_hopdecoy_hardened.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sender/sender_hopdecoy_hardened.o: sender/sender.c
	$(CC) $(CFLAGS_HOPDECOY_HARDENED) -c $< -o $@

sender_hopdecoy_hardened.exe: $(COMMON_OBJ) sender/sender_hopdecoy_hardened.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# hopdecoy_poolmix: decoy termination + genuine batch/pool mixing at every
# hop (production port, see mix_node.c). Only mix_node.c's behavior
# depends on ASN_POOL_MIXING, pairs with the EXISTING client_hopdecoy.exe/
# sender_hopdecoy.exe (decoy generation is identical regardless of what
# the mix node does with survivors), no new client/sender binary needed.
hopdecoy_poolmix: mix_node_hopdecoy_poolmix.exe

mix_node/mix_node_hopdecoy_poolmix.o: mix_node/mix_node.c
	$(CC) $(CFLAGS_HOPDECOY_POOLMIX) -c $< -o $@

mix_node_hopdecoy_poolmix.exe: $(COMMON_OBJ) mix_node/mix_node_hopdecoy_poolmix.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# -- Test binary -----------------------------------------------------------
test_packet_v2.exe: $(COMMON_OBJ) test_packet_v2.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Committed test binary for the four self-test properties
# node_pool_selftest() reports, previously
# only an uncommitted throwaway driver, see common/node_pool_selftest.c.
node_pool_selftest.exe: $(COMMON_OBJ) common/node_pool_selftest.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# -- Clean -----------------------------------------------------------------
clean:
	rm -f common/*.o
	rm -f mix_node/*.o gateway/*.o client/*.o sender/*.o
	rm -f ../tests/ASN/*.o
	rm -f test_packet_v2.o
	rm -f *.exe
