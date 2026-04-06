# cudp - Custom UDP Flood // nigga
CC := gcc
CFLAGS := -Wall -Wextra -O3 -pthread
LDFLAGS := -pthread
.PHONY: all clean
all: cudp.x86 cudp.x64
cudp.x86: cudp.c
	$(CC) -m32 $(CFLAGS) -o $@ $< $(LDFLAGS) && strip $@ && echo "[+] $@"
cudp.x64: cudp.c
	$(CC) -m64 $(CFLAGS) -o $@ $< $(LDFLAGS) && strip $@ && echo "[+] $@"
clean: ; rm -f cudp.x86 cudp.x64
