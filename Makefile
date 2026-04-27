CC      := gcc
CFLAGS  := -Wall -Wextra -g -O0 -I.
LDFLAGS := -lssl -lcrypto -lws2_32 -lbcrypt -lm

COMMON := common/crypto.o common/net.o common/packet.o

.PHONY: all test_packet test_crypto clean nodes

all: test_packet_v2.exe nodes

test_crypto.exe: common/crypto.o test_crypto.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_packet_v2.exe: common/crypto.o common/packet.o test_packet_v2.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_packet: test_packet_v2.exe
	./test_packet_v2.exe

nodes: mix_node.exe \
       service_gateway.exe cache_server.exe \
       sender.exe client.exe

mix_node.exe:       $(COMMON) mix_node/mix_node.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

service_gateway.exe: $(COMMON) gateway/service_gateway.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

cache_server.exe:   $(COMMON) gateway/cache_server.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sender.exe:         $(COMMON) sender/sender.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

client.exe:         $(COMMON) client/client.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f common/*.o mix_node/*.o gateway/*.o
	rm -f sender/*.o sender_entry/*.o sender_exit/*.o client/*.o
	rm -f entry/*.o exit/*.o
	rm -f test_crypto.o test_packet_v2.o
	rm -f *.exe
