# Cloud worker

Select the `development` profile in Horizon. It provides 4 vCPU and 8 GB RAM,
Claude and Codex, and no GPU, browser or desktop capability. This repository builds
a command line and an MCP server. Its tests use the in-process fake relay and do
not require a real phone, a live relay or credentials.

The image extends the public Ubuntu 24.04 Horizon worker at the digest in
`Dockerfile`. It retains the base's SSH entrypoint and session isolation.
`20-nodkey-cli.env` exposes tools to SSH sessions. Cargo's default cache stays in
the user's persistent home; installed toolchains live outside user homes.

## CI inputs

The push event in `.github/workflows/ci.yml` resolves the OS matrix to
`ubuntu-latest`. The `test` job has no needs, outputs, services, tool setup actions,
cache resets or secrets. `Cargo.toml` and `README.md` require Rust 1.85 or newer;
there is no Rust toolchain file or exact CI version. The worker pins Rust 1.99.0,
the stable release found on 2026-10-11. Cargo.lock locks dependency versions.

| Step | Tool and version | Source | Image provision |
| --- | --- | --- | --- |
| Checkout | Git; actions/checkout v7 | ci.yml | Base Git; Horizon supplies the committed checkout |
| Format | rustfmt from Rust 1.99.0 | Repository minimum 1.85; resolved stable manifest | Checksum-pinned Rust archive |
| Clippy | Cargo and Clippy from Rust 1.99.0 | Same toolchain | Same Rust archive |
| Native compilation | GCC 13, build-essential 12.10ubuntu1, CMake 3.28.3, pkg-config 1.8.1 | Hosted runner; Cargo.lock includes aws-lc-sys | Pinned Ubuntu 24.04 package versions |
| Tests | Cargo from Rust 1.99.0 | ci.yml | Same toolchain; local fake relay |
| Shell scripts | Bash 5.2 and POSIX sh | Implicit hosted-runner tools | Ubuntu base |
| Local CI | localci v0.1.0, Linux x86_64 musl | Newest published release on 2026-10-11 | SHA256SUMS and pinned asset checksum |

AGENTS.md also requires nodkey-proto to remain buildable for WebAssembly. The
image includes Rust 1.99.0's checksum-pinned wasm32-unknown-unknown standard
library. The push CI does not run a WebAssembly check.

Release jobs in `.github/workflows/release.yml` are outside this proof. They use
curl, rustup, musl-tools, sudo, tar and sha256sum on Linux; other OS legs also use
PowerShell and platform SDKs. Artifact upload/download and GitHub publishing
require the hosted environment or its credentials. The worker does not publish,
sign, notarize or prove macOS, Windows or ARM64 release targets.

## Running the same checks

The latest published localci v0.1.0 currently leaves this workflow's dynamic
`fromJSON` OS matrix unresolved. Both `localci check` and `localci plan --json
--event push test` expose this limitation. Once a localci release supports that
expression, the intended commands are:

```sh
localci run --event push test
localci run --event push test --fast
```

The image proof uses these exact Linux CI commands directly because the job
cannot be selected by this localci release. No Linux run step is omitted.
The repeated proof reuses Cargo caches; localci fast mode remains unproven.

The commands are:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
sh -n install.sh && bash -n scripts/sign-macos.sh
```

Horizon owns image builds and proof execution. The proof status, logs and results
are machine-local, outside this repository.

Horizon reported a successful proof on 2026-10-11 for
`horizon-setup-nodkey-cli:candidate`: image build and worker checks in 77 seconds,
Linux CI checks in 36 seconds, and the fast rerun in 8 seconds.

## Companions

AGENTS.md requires protocol changes to be checked with the app and relay in
`peters/nodkey`. Its adjacent `.horizon/cloud.yml` names `development` as its
default profile. It is declared as a separate-cloud companion for the encrypted
relay/phone runtime contract; this repository does not require running its tests
on the same worker.

AGENTS.md also requires checking `peters/nodkey-browser` for protocol changes.
That checkout has no `.horizon/cloud.yml`, so it is omitted until it has a cloud
profile. Its package dependency alone does not establish a runtime companion.
There are no Uses/Used by lines or product-map references in this repository's
AGENTS.md. The available company product map has no Nodkey entries or edges.

Review and commit this directory, then return to Cloud > New cloud and reload
`.horizon/cloud.yml`. Registry and Git credentials stay in machine-local bindings.
