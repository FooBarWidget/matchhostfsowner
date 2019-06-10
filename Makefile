.PHONE: static-binary

RUST_MUSL_BUILDER_VERSION := 1.35.0
TTY := $(shell if tty -s; then echo '-ti'; fi)

static-binary:
	mkdir -p target/rust-musl-builder-cache/cargo-git target/rust-musl-builder-cache/cargo-registry
	docker run --rm $(TTY) \
		-v "$$(pwd):/home/rust/src:delegated" \
		-v "$$(pwd)/target/rust-musl-builder-cache/cargo-git:/home/rust/.cargo/git:delegated" \
		-v "$$(pwd)/target/rust-musl-builder-cache/cargo-registry:/home/rust/.cargo/registry:delegated" \
		ekidd/rust-musl-builder:$(RUST_MUSL_BUILDER_VERSION) \
		cargo build --color always --release
	docker run --rm $(TTY) \
		-v "$$(pwd):/home/rust/src:delegated" \
		ekidd/rust-musl-builder:$(RUST_MUSL_BUILDER_VERSION) \
		strip --strip-all /home/rust/src/target/x86_64-unknown-linux-musl/release/activatecontaineruid
