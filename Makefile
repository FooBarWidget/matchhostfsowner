.PHONE: static-binary package

VERSION := $(shell grep '^version' Cargo.toml | cut -d '=' -f 2 | sed 's/[ "]//g')
RUST_MUSL_BUILDER_VERSION := 1.50.0
TTY := $(shell if tty -s; then echo '-ti'; fi)

static-binary: target/docker-helper/matchhostfsowner
	mkdir -p target/rust-musl-builder target/rust-musl-builder-cache/cargo-git target/rust-musl-builder-cache/cargo-registry
	docker run --rm --init $(TTY) \
		-v "$$(pwd):/home/rust/src:delegated" \
		-v "$$(pwd)/target/rust-musl-builder:/home/rust/src/target:delegated" \
		-v "$$(pwd)/target/rust-musl-builder-cache/cargo-git:/home/rust/.cargo/git:delegated" \
		-v "$$(pwd)/target/rust-musl-builder-cache/cargo-registry:/home/rust/.cargo/registry:delegated" \
		-v "$$(pwd)/target/docker-helper/matchhostfsowner:/sbin/matchhostfsowner:delegated" \
		-v "$$(pwd)/release-scripts/hooks.d:/etc/matchhostfsowner/hooks.d:delegated" \
		-e "MHF_HOST_UID=$$(id -u)" \
		-e "MHF_HOST_GID=$$(id -g)" \
		-e "MHF_APP_ACCOUNT=rust" \
		--user 0:0 \
		--entrypoint /sbin/matchhostfsowner \
		ekidd/rust-musl-builder:$(RUST_MUSL_BUILDER_VERSION) \
		cargo build --color always --release
	docker run --rm --init $(TTY) \
		-v "$$(pwd):/home/rust/src:delegated" \
		-v "$$(pwd)/target/rust-musl-builder:/home/rust/src/target:delegated" \
		-v "$$(pwd)/target/docker-helper/matchhostfsowner:/sbin/matchhostfsowner:delegated" \
		-e "MHF_HOST_UID=$$(id -u)" \
		-e "MHF_HOST_GID=$$(id -g)" \
		-e "MHF_APP_ACCOUNT=rust" \
		--user 0:0 \
		--entrypoint /sbin/matchhostfsowner \
		ekidd/rust-musl-builder:$(RUST_MUSL_BUILDER_VERSION) \
		strip --strip-all /home/rust/src/target/x86_64-unknown-linux-musl/release/matchhostfsowner

package: target/rust-musl-builder/x86_64-unknown-linux-musl/release/matchhostfsowner
	gzip --best < target/rust-musl-builder/x86_64-unknown-linux-musl/release/matchhostfsowner > target/rust-musl-builder/x86_64-unknown-linux-musl/release/matchhostfsowner-$(VERSION)-x86_64-linux.gz

# Download a precompiled binary for use in rust-musl-builder.
target/docker-helper/matchhostfsowner:
	mkdir -p target/docker-helper
	curl -sSL -o target/docker-helper/matchhostfsowner.gz \
		https://github.com/FooBarWidget/matchhostfsowner/releases/download/v0.9.4/matchhostfsowner-0.9.4-x86_64-linux.gz
	gunzip target/docker-helper/matchhostfsowner.gz
	chmod +x target/docker-helper/matchhostfsowner
