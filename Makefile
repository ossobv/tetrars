.PHONY: default clippy debug release

default: debug clippy release

clippy:
	cargo clippy

debug:
	cargo build

release:
	cargo build --release
