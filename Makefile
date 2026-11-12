CC ?= cc
CFLAGS_COMMON = -std=c11 -Wall -Wextra -Werror -Wshadow -Wconversion -Wno-sign-conversion -Isrc
CFLAGS ?= -Os
LDFLAGS ?=
SAN = -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
UNAME := $(shell uname)

CORE = src/proto.c src/sha256.c
DAEMON = $(CORE) src/topo.c src/main.c

# Files written by the tool sandbox on macOS can be quarantined; harmless elsewhere.
ifeq ($(UNAME),Darwin)
FIX = xattr -c $@ 2>/dev/null || true
STRIP ?= strip -x
else
FIX = true
STRIP ?= strip -s
endif

.PHONY: all test unit fuzz-smoke check-noheap size clean

all: build/sparrowd build/sparrowd.stripped

build:
	mkdir -p build

build/sparrowd: $(DAEMON) src/*.h | build
	$(CC) $(CFLAGS_COMMON) $(CFLAGS) $(DAEMON) $(LDFLAGS) -o $@
	@$(FIX)

build/sparrowd.stripped: build/sparrowd
	cp $< $@ && $(STRIP) $@
	@$(FIX)

build/sparrowd.asan: $(DAEMON) src/*.h | build
	$(CC) $(CFLAGS_COMMON) $(SAN) $(DAEMON) -o $@
	@$(FIX)

build/test_unit: tests/test_unit.c $(CORE) src/*.h | build
	$(CC) $(CFLAGS_COMMON) $(SAN) tests/test_unit.c $(CORE) -o $@
	@$(FIX)

build/fuzz_driver: fuzz/fuzz_rx.c fuzz/fuzz_driver.c $(CORE) src/*.h | build
	$(CC) $(CFLAGS_COMMON) $(SAN) fuzz/fuzz_rx.c fuzz/fuzz_driver.c $(CORE) -o $@
	@$(FIX)

# Sanitizer-free builds of the tests, for cross-compiled targets run under qemu-user
# (ASan does not work under qemu-user emulation).
build/test_unit_plain: tests/test_unit.c $(CORE) src/*.h | build
	$(CC) $(CFLAGS_COMMON) -O2 tests/test_unit.c $(CORE) $(LDFLAGS) -o $@
	@$(FIX)

build/fuzz_driver_plain: fuzz/fuzz_rx.c fuzz/fuzz_driver.c $(CORE) src/*.h | build
	$(CC) $(CFLAGS_COMMON) -O2 fuzz/fuzz_rx.c fuzz/fuzz_driver.c $(CORE) $(LDFLAGS) -o $@
	@$(FIX)

# libFuzzer build (needs a clang with the fuzzer runtime, e.g. on Linux CI).
build/fuzz_libfuzzer: fuzz/fuzz_rx.c $(CORE) src/*.h | build
	clang $(CFLAGS_COMMON) -O1 -g -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
		fuzz/fuzz_rx.c $(CORE) -o $@

unit: build/test_unit
	./build/test_unit

fuzz-smoke: build/fuzz_driver
	./build/fuzz_driver 200000 1

# Daemon object code must never call the allocator.
check-noheap: | build
	@for f in $(DAEMON); do $(CC) $(CFLAGS_COMMON) $(CFLAGS) -c $$f -o build/$$(basename $$f .c).o; done
	@if nm -u build/proto.o build/sha256.o build/topo.o build/main.o | grep -E '(^|[ _])(malloc|calloc|realloc|free|strdup)$$'; \
		then echo "heap allocation found"; exit 1; else echo "no heap allocation in daemon code"; fi

test: unit fuzz-smoke check-noheap all build/sparrowd.asan
	python3 tests/test_integration.py

size: build/sparrowd.stripped
	@ls -l build/sparrowd.stripped
	@size build/sparrowd 2>/dev/null || true

clean:
	rm -rf build
