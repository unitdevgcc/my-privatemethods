# observer - TCP Observer Flood // nigga
# by c0re_x64 for 0v.lol

CC := gcc
CFLAGS := -Wall -Wextra -O3 -pthread
LDFLAGS := -pthread

.PHONY: all clean

all: observer.x86 observer.x64

observer.x86: observer.c
	@echo "[*] observer x86..."
	$(CC) -m32 $(CFLAGS) -o $@ $< $(LDFLAGS)
	@strip $@
	@echo "[+] $@"

observer.x64: observer.c
	@echo "[*] observer x64..."
	$(CC) -m64 $(CFLAGS) -o $@ $< $(LDFLAGS)
	@strip $@
	@echo "[+] $@"

clean:
	rm -f observer.x86 observer.x64
