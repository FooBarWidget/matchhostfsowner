.PHONE: static-binary package

VERSION := $(shell grep '^version' Cargo.toml | cut -d '=' -f 2 | sed 's/[ "]//g')
RUST_MUSL_BUILDER_VERSION := 1.35.0
TTY := $(shell if tty -s; then echo '-ti'; fi)

static-binary: target/docker-helper/activatecontaineruid
	mkdir -p target/rust-musl-builder target/rust-musl-builder-cache/cargo-git target/rust-musl-builder-cache/cargo-registry
	docker run --rm --init $(TTY) \
		-v "$$(pwd):/home/rust/src:delegated" \
		-v "$$(pwd)/target/rust-musl-builder:/home/rust/src/target:delegated" \
		-v "$$(pwd)/target/rust-musl-builder-cache/cargo-git:/home/rust/.cargo/git:delegated" \
		-v "$$(pwd)/target/rust-musl-builder-cache/cargo-registry:/home/rust/.cargo/registry:delegated" \
		-v "$$(pwd)/target/docker-helper/activatecontaineruid:/sbin/activatecontaineruid:delegated" \
		-v "$$(pwd)/release-scripts/hooks.d:/etc/activatecontaineruid/hooks.d:delegated" \
		-e "ACU_TARGET_UID=$$(id -u)" \
		-e "ACU_TARGET_GID=$$(id -g)" \
		-e "ACU_APP_ACCOUNT=rust" \
		-e "ACU_CHOWN_HOME=0" \
		--user 0:0 \
		--entrypoint /sbin/activatecontaineruid \
		ekidd/rust-musl-builder:$(RUST_MUSL_BUILDER_VERSION) \
		cargo build --color always --release
	docker run --rm --init $(TTY) \
		-v "$$(pwd):/home/rust/src:delegated" \
		-v "$$(pwd)/target/rust-musl-builder:/home/rust/src/target:delegated" \
		-v "$$(pwd)/target/docker-helper/activatecontaineruid:/sbin/activatecontaineruid:delegated" \
		-v "$$(pwd)/release-scripts/hooks.d:/etc/activatecontaineruid/hooks.d:delegated" \
		-e "ACU_TARGET_UID=$$(id -u)" \
		-e "ACU_TARGET_GID=$$(id -g)" \
		-e "ACU_APP_ACCOUNT=rust" \
		-e "ACU_CHOWN_HOME=0" \
		--user 0:0 \
		--entrypoint /sbin/activatecontaineruid \
		ekidd/rust-musl-builder:$(RUST_MUSL_BUILDER_VERSION) \
		strip --strip-all /home/rust/src/target/x86_64-unknown-linux-musl/release/activatecontaineruid

package: target/rust-musl-builder/x86_64-unknown-linux-musl/release/activatecontaineruid
	gzip --best < target/rust-musl-builder/x86_64-unknown-linux-musl/release/activatecontaineruid > target/rust-musl-builder/x86_64-unknown-linux-musl/release/activatecontaineruid-$(VERSION)-x86_64-linux.gz

# Download a precompiled binary for use in rust-musl-builder.
target/docker-helper/activatecontaineruid:
	mkdir -p target/docker-helper
	curl -sSL -o target/docker-helper/activatecontaineruid.gz \
		https://github.com/fullstaq-labs/activatecontaineruid/releases/download/v0.9.2/activatecontaineruid-0.9.2-x86_64-linux.gz
	gunzip target/docker-helper/activatecontaineruid.gz
	chmod +x target/docker-helper/activatecontaineruid
