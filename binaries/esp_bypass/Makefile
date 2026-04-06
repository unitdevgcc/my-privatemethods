# esp_bypass - ESP Bypass Flood // nigga
CC := gcc
CFLAGS := -Wall -Wextra -O3 -pthread
LDFLAGS := -pthread
.PHONY: all clean
all: esp_bypass.x86 esp_bypass.x64
esp_bypass.x86: esp_bypass.c
	$(CC) -m32 $(CFLAGS) -o $@ $< $(LDFLAGS) && strip $@ && echo "[+] $@"
esp_bypass.x64: esp_bypass.c
	$(CC) -m64 $(CFLAGS) -o $@ $< $(LDFLAGS) && strip $@ && echo "[+] $@"
clean: ; rm -f esp_bypass.x86 esp_bypass.x64
