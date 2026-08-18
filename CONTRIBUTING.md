# Contributing to hoike

## Getting started

```bash
git clone <repo-url>
cd hoike
cargo build
cargo test --workspace
```

## Development workflow

1. Create a Jira ticket or GitHub issue before implementation starts
2. Branch from `main`: `git checkout -b feature/your-feature`
3. Write tests first when possible
4. Run `cargo test --workspace` and `cargo clippy` before committing
5. Commit messages: imperative mood, explain *why* not *what*
6. Add `Assisted-by: Claude Code (claude.ai/code)` trailer if AI-assisted

## Architecture boundaries

- **`ahu` crate** must not depend on tokio, hyper, PKCS#11, or any server runtime.
  It should build with `--no-default-features` in constrained environments.
- **Edge nodes** must never hold signing keys. Any feature requiring a key on an
  edge node breaks the security model.
- **Pre-signed responses** are served as stored bytes — never parse, re-encode,
  or re-sign at the edge.

## Testing

- Unit tests: `cargo test -p ahu`
- Integration tests: `cargo test -p ahu --test integration`
- End-to-end: `cargo test -p hoike-server --test e2e`
- Generate test bundles: `cargo run --example generate_test_bundle -- /tmp/test.ahu`

## License

By contributing, you agree that your contributions will be licensed under the
project's split license (Apache-2.0 OR MIT for ahu, GPL-3.0+ for hoike crates).
