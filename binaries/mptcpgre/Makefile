# mptcpgre - MPTCP GRE Flood // nigga
CC := gcc
CFLAGS := -Wall -Wextra -O3 -pthread
LDFLAGS := -pthread
.PHONY: all clean
all: mptcpgre.x86 mptcpgre.x64
mptcpgre.x86: mptcpgre.c
	$(CC) -m32 $(CFLAGS) -o $@ $< $(LDFLAGS) && strip $@ && echo "[+] $@"
mptcpgre.x64: mptcpgre.c
	$(CC) -m64 $(CFLAGS) -o $@ $< $(LDFLAGS) && strip $@ && echo "[+] $@"
clean: ; rm -f mptcpgre.x86 mptcpgre.x64
