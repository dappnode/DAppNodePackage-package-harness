.PHONY: dev build test lint typecheck check start

dev:
	PACKAGE_MANAGER_MODE=fake cargo run

build:
	cargo build --locked --release

test:
	cargo test --locked --all-targets --all-features

lint:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets --all-features -- -D warnings

typecheck:
	cargo check --locked --all-targets --all-features

check: lint test

start:
	cargo run --release
