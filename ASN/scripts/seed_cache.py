#!/usr/bin/env python3
"""
seed_cache.py  --  Seed the cache server with a test key for benchmarking.

The cache server (port 9012) expects:
  [TYPE(1)][klen(1)][key(klen)][dlen(2)][data(dlen)]

Usage:
    python seed_cache.py [--key bench] [--value "hello world"] [--port 9012]
"""

import argparse
import socket
import sys

TYPE_PUT = 0x02

def seed(host, port, key, value):
    key_b   = key.encode()
    value_b = value.encode()
    klen    = len(key_b)
    dlen    = len(value_b)

    if klen > 64:
        print("ERROR: key too long (max 64 bytes)"); sys.exit(1)

    msg = bytes([TYPE_PUT, klen]) + key_b + bytes([dlen >> 8, dlen & 0xFF]) + value_b

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((host, port))
        s.sendall(msg)
        # read ACK (3 bytes: status + length)
        ack = s.recv(3)
        s.close()
        if ack:
            print(f"  OK  key='{key}'  value='{value}'  ack={ack.hex()}")
        else:
            print(f"  OK  key='{key}'  (no ack bytes)")
    except OSError as e:
        print(f"ERROR: {e}")
        print("       Is cache_server.exe running on port {port}?")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key",   default="bench")
    parser.add_argument("--value", default="benchmark test content for anon-sec-net v2")
    parser.add_argument("--host",  default="127.0.0.1")
    parser.add_argument("--port",  type=int, default=9012)
    args = parser.parse_args()

    print(f"Seeding cache at {args.host}:{args.port} ...")
    seed(args.host, args.port, args.key, args.value)
    print("Done.")

if __name__ == "__main__":
    main()
