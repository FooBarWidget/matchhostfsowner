MatchHostFsOwner is a Rust app that solves the Docker host filesystem owner matching problem. It ensures that the container's UID/GID matches the host's. It's an entrypoint program that modifies the container account's UID/GID (among other things, like chowning the home directory), then calls setuid()/setgid()/etc and then proceeds to exec the next entrypoint. Learn more in README.md.

## Coding principles

- Prefer code to be boring and explicit rather than clever or highly abstracted. Optimize for readability and ease of following the logic. Some duplication is acceptable. Only extract shared helpers when doing so clearly improves readability or when the repeated code becomes large enough to be distracting.
- Keep core logic focused. Extract non-core logic into helpers when that makes the core flow easier to follow.
- When extracting helper code, prefer helpers that are generic and reusable rather than tightly coupled to one caller, unless the logic is truly specific to that one call site.
- Use existing helper functions (src/utils.rs for app code, tests/common.rs for test code) when appropriate.
- Place new generic helper code in src/utils.rs or tests/common.rs, depending on whether it is app code or test code.
- Use the 'thiserror' crate instead of using standard Rust Error trait + manual Display/Error impls.

## Testing

When making important changes, add tests. Prefer red/green testing.

There are both unit tests (src/*.rs) and integration tests (tests/integration_test.rs). Integration tests require Docker. Before running integration tests, build the integration test base image first (`make integration-test-base`) which is to contain a Linux build of this project. Do this every time sources are modified.

Use the helper macro `assert_contains_substr!` when appropriate.

## Security

For security considerations, see README.md and SECURITY-NOTES.md
