# Cargo-backed convenience targets for the Rust implementation.

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

.PHONY: default all debug test check format clean install
