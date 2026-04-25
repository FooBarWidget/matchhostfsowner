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
 3. Trigger the release workflow. This creates a draft release.
 4. Edit the release notes and publish the release.
