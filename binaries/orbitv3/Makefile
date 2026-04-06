# orbitv3 - TCP OrbitV3 Bypass // nigga
CC := gcc
CFLAGS := -Wall -Wextra -O3 -pthread
LDFLAGS := -pthread
.PHONY: all clean
all: orbitv3.x86 orbitv3.x64
orbitv3.x86: orbitv3.c
	$(CC) -m32 $(CFLAGS) -o $@ $< $(LDFLAGS) && strip $@ && echo "[+] $@"
orbitv3.x64: orbitv3.c
	$(CC) -m64 $(CFLAGS) -o $@ $< $(LDFLAGS) && strip $@ && echo "[+] $@"
clean: ; rm -f orbitv3.x86 orbitv3.x64
