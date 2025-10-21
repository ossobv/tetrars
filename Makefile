.PHONY: default clippy debug prereq release

default: debug clippy release

clippy: prereq
	cargo clippy

debug: prereq
	cargo build

release: prereq
	cargo auditable build --release

prereq: src/cilium/tetragon.rs

# Regenerate? rm src/cilium/tetragon.rs
src/cilium/tetragon.rs:
	# We use build.rs to regenerate src/cilium/tetragon.rs.
	sed -i -e 's/^build = false/#&/' Cargo.toml
	cargo clean
	cargo build
	sed -i -e 's/^#\(build = false\)/\1/' Cargo.toml
