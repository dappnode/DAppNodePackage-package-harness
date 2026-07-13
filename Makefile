.PHONY: dev build test lint typecheck start

dev:
	PACKAGE_MANAGER_MODE=fake cargo run

build:
	cargo build --release

test:
	cargo test --all-features

lint:
	cargo fmt --check
	cargo clippy --all-targets --all-features -- -D warnings

typecheck:
	cargo check --all-targets --all-features

start:
	cargo run --release

