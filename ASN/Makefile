CC      := gcc
CFLAGS  := -Wall -Wextra -g -O0 -Icommon -I.
LDFLAGS := -lssl -lcrypto -lws2_32 -lbcrypt -lm

COMMON_OBJ := common/crypto.o common/net.o common/packet.o

.PHONY: all nodes instrumented clean

all: nodes instrumented

# ── Common object files ───────────────────────────────────────────────────
common/%.o: common/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# ── Generic rule for all other subdirectory sources ───────────────────────
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# ── Standard node binaries ────────────────────────────────────────────────
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

# ── Instrumented binaries (used by sweep scripts) ─────────────────────────
instrumented: mix_node_instrumented.exe client_instrumented.exe service_gateway_instrumented.exe

mix_node_instrumented.exe: $(COMMON_OBJ) mix_node/mix_node_instrumented.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

client_instrumented.exe: $(COMMON_OBJ) client/client_instrumented.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

service_gateway_instrumented.exe: $(COMMON_OBJ) gateway/service_gateway_instrumented.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ── Test binary ───────────────────────────────────────────────────────────
test_packet_v2.exe: $(COMMON_OBJ) test_packet_v2.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# ── Clean ─────────────────────────────────────────────────────────────────
clean:
	rm -f common/*.o
	rm -f mix_node/*.o gateway/*.o client/*.o sender/*.o
	rm -f entry/*.o exit/*.o sender_entry/*.o sender_exit/*.o
	rm -f test_packet_v2.o
	rm -f *.exe