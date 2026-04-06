# Exterogen - TCP multi-session flood
# by c0redev for 0v.lol

CC := gcc
CFLAGS := -Wall -Wextra -O3 -pthread -fstack-protector-strong -fpie -D_FORTIFY_SOURCE=2
LDFLAGS := -pthread -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,defs

TARGETS := exterogen.x86 exterogen.x64
CLEAN_TARGETS := exterogen.x86.clean exterogen.x64.clean

.PHONY: all clean clean-build

all: $(TARGETS)

exterogen.x86: exterogen.c
	@echo "[*] compiling for x86..."
	$(CC) -m32 $(CFLAGS) -o $@ $< $(LDFLAGS)
	@strip $@
	@echo "[+] $@ ready"

exterogen.x64: exterogen.c
	@echo "[*] compiling for x64..."
	$(CC) -m64 $(CFLAGS) -o $@ $< $(LDFLAGS)
	@strip $@
	@echo "[+] $@ ready"

exterogen.x86.clean: exterogen.c
	@echo "[*] compiling clean (no protection) x86..."
	$(CC) -m32 $(CFLAGS) -DEXTEROGEN_CLEAN -Wno-unused-function -o $@ $< $(LDFLAGS)
	@strip $@
	@echo "[+] $@ ready"

exterogen.x64.clean: exterogen.c
	@echo "[*] compiling clean (no protection) x64..."
	$(CC) -m64 $(CFLAGS) -DEXTEROGEN_CLEAN -Wno-unused-function -o $@ $< $(LDFLAGS)
	@strip $@
	@echo "[+] $@ ready"

clean: clean-build

clean-build:
	rm -f $(TARGETS) $(CLEAN_TARGETS)
