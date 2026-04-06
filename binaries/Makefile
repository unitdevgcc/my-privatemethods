# Build all attack binaries - by c0re_x64 for 0v.lol // nigga
# each method in own folder like stomp/

CC := gcc
CFLAGS := -Wall -Wextra -O3 -pthread
LDFLAGS := -pthread
export CC CFLAGS LDFLAGS

DIRS := stomp observer orbitv3 socket esp_bypass nfolag greip mptcpgre udpplain udp_bypass ssdp ice cudp exterogen voult

.PHONY: all clean $(DIRS)

all: $(DIRS)
	@echo ""
	@echo "[+] all binaries built // nigga"

$(DIRS):
	@echo ""
	@echo "[*] building $@ ..."
	@make -C $@ all

clean: $(addsuffix _clean,$(DIRS))
	@echo "[+] clean"

%_clean:
	@make -C $(subst _clean,,$*) clean 2>/dev/null || true
