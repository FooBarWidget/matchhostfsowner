## Running tests

Before running tests, build the integration test base image first. Do this every time you've modified the sources.

~~~bash
make integration-test-base
~~~

Then:

~~~bash
cargo test
~~~

## Release process

 1. Bump version number in Cargo.toml. Run `cargo check`, then commit & push the result.
 2. Ensure CI passes for the main branch.
 3. On a local machine, run `make static-binary package`
 4. Create & push a Git tag for the current commit.
 5. Create a Github release. Document the changes. Upload the local file `target/rust-musl-builder/x86_64-unknown-linux-musl/release/matchhostfsowner-X.X.X-x86_64-linux.gz` as an asset.
