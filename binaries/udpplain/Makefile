# udpplain - UDP Plain Flood // nigga
CC := gcc
CFLAGS := -Wall -Wextra -O3 -pthread
LDFLAGS := -pthread
.PHONY: all clean
all: udpplain.x86 udpplain.x64
udpplain.x86: udpplain.c
	$(CC) -m32 $(CFLAGS) -o $@ $< $(LDFLAGS) && strip $@ && echo "[+] $@"
udpplain.x64: udpplain.c
	$(CC) -m64 $(CFLAGS) -o $@ $< $(LDFLAGS) && strip $@ && echo "[+] $@"
clean: ; rm -f udpplain.x86 udpplain.x64
