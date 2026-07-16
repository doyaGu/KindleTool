# Rust is the main implementation. The C implementation remains available as the legacy oracle.

CARGO ?= cargo
CARGO_FLAGS ?= --locked

default: all

all:
	$(CARGO) build --release $(CARGO_FLAGS) -p kindletool-cli

debug:
	$(CARGO) build $(CARGO_FLAGS) -p kindletool-cli

test:
	$(CARGO) test --workspace $(CARGO_FLAGS)

check:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets $(CARGO_FLAGS) -- -D warnings
	$(CARGO) test --workspace $(CARGO_FLAGS)

format:
	$(CARGO) fmt --all

clean:
	$(CARGO) clean

install:
	$(CARGO) install --path crates/kindletool-cli $(CARGO_FLAGS)

legacy:
	$(MAKE) -C KindleTool all

legacy-kindle:
	$(MAKE) -C KindleTool kindle

legacy-mingw:
	$(MAKE) -C KindleTool mingw

legacy-debug:
	$(MAKE) -C KindleTool debug

legacy-strip:
	$(MAKE) -C KindleTool strip

legacy-clean:
	$(MAKE) -C KindleTool clean

legacy-install:
	$(MAKE) -C KindleTool install

legacy-format:
	clang-format -style=file -i KindleTool/*.c KindleTool/*.h

.PHONY: default all debug test check format clean install legacy legacy-kindle legacy-mingw \
	legacy-debug legacy-strip legacy-clean legacy-install legacy-format
