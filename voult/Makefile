# Makefile for TCP Stomp Flood
# by c0re_x64 for 0v.lol

CC := gcc
CFLAGS := -Wall -Wextra -O3 -pthread
LDFLAGS := -pthread

TARGETS := voult.x86 voult.x64

.PHONY: all clean install

all: $(TARGETS)

voult.x86: voult.c
	@echo "[*] compiling for x86 (32-bit)..."
	$(CC) -m32 $(CFLAGS) -o $@ $< $(LDFLAGS)
	@strip $@
	@echo "[+] $@ ready"

voult.x64: voult.c
	@echo "[*] compiling for x64 (64-bit)..."
	$(CC) -m64 $(CFLAGS) -o $@ $< $(LDFLAGS)
	@strip $@
	@echo "[+] $@ ready"
