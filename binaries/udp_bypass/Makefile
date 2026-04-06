# udp_bypass - UDP Bypass ESP // nigga
CC := gcc
CFLAGS := -Wall -Wextra -O3 -pthread
LDFLAGS := -pthread
.PHONY: all clean
all: udp_bypass.x86 udp_bypass.x64
udp_bypass.x86: udp_bypass.c
	$(CC) -m32 $(CFLAGS) -o $@ $< $(LDFLAGS) && strip $@ && echo "[+] $@"
udp_bypass.x64: udp_bypass.c
	$(CC) -m64 $(CFLAGS) -o $@ $< $(LDFLAGS) && strip $@ && echo "[+] $@"
clean: ; rm -f udp_bypass.x86 udp_bypass.x64
