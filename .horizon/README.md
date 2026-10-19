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

The `test` job in `.github/workflows/ci.yml` runs on `ubuntu-latest`,
`macos-latest` and `windows-latest`; the worker covers the Linux leg. The job
has no needs, outputs, services, tool setup actions, cache resets or secrets. `Cargo.toml` and `README.md` require Rust 1.85 or newer;
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
| Verify Horizon pins | Python 3.12 | Ubuntu 24.04 base; horizon-pins job | Base Python; Horizon writes verify-pins.py |
| Local CI | localci v0.1.0, Linux x86_64 musl | Newest published release on 2026-10-11 | SHA256SUMS and pinned asset checksum |

The repository does not name an exact installed toolchain version. Rust 1.85 is
a minimum supported version, not a pin that Rust 1.99.0 refines. Native build
tools and localci also have no version source in repository files, so
`pins.json` declares an empty list. Their versions remain pinned as Dockerfile
ARGs. The `horizon-pins` CI job checks the manifest using the verifier Horizon
generates, with checkout credentials disabled.

AGENTS.md also requires nodkey-proto to remain buildable for WebAssembly. The
image includes Rust 1.99.0's checksum-pinned wasm32-unknown-unknown standard
library. The push CI does not run a WebAssembly check.

Release jobs in `.github/workflows/release.yml` are outside this proof. They use
curl, rustup, musl-tools, sudo, tar and sha256sum on Linux; other OS legs also use
PowerShell and platform SDKs. Artifact upload/download and GitHub publishing
require the hosted environment or its credentials. The worker does not publish,
sign, notarize or prove macOS, Windows or ARM64 release targets.

The `audit` job in `ci.yml` installs cargo-audit 0.22.2 with `cargo install --locked`
and reads the RustSec advisory database from GitHub, so it needs the network. The
image does not include cargo-audit and the proof does not run this job. To run it on
the worker: `cargo install cargo-audit --version 0.22.2 --locked && cargo audit`.

## Running the same checks

The OS matrix of the `test` job is static: Linux, macOS and Windows. On Linux,
localci runs the Linux leg and skips the others:

```sh
localci run --event push horizon-pins test
localci run --event push horizon-pins test --fast
```

The Linux leg runs the same commands as the image proof:

```sh
python3 .horizon/verify-pins.py
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
sh -n install.sh && bash -n scripts/sign-macos.sh
```

Horizon proves the committed checkout, which does not contain newly generated
setup files until they are committed. The image includes only its Dockerfile,
empty pin manifest and generated verifier under `/opt/nodkey-cli-horizon`.
Before committing, the proof runs
`python3 /opt/nodkey-cli-horizon/verify-pins.py` for the pin check. This verifies
the image's configuration without changing the checkout. Future repository CI
uses the `.horizon` copy above. No application source or credentials enter the
image. If repository-backed pins are added later, verify them in the checkout.

Horizon owns image builds and proof execution. The proof status, logs and results
are machine-local, outside this repository.

Horizon reported a successful proof on 2026-10-11 for
`horizon-setup-nodkey-cli:candidate`: image build and worker checks in 3 seconds,
Linux CI commands in 38 seconds, and the repeated command proof in 9 seconds.
All 83 tests passed in each run as UID 10001. Format, Clippy, pin verification and
shell syntax checks also passed. The repeat uses Cargo caches.

## Changes to the existing setup

- Updated the base digest to the Ubuntu 24.04 worker supplied for this setup.
- Exposed the existing native build package versions as installation ARGs.
- Added `pins.json` and the single `horizon-pins` job to the main CI workflow.
- Included the generated verifier and image configuration for pre-commit proof.
- Updated this documentation to describe the pin check and current proof scope.

All existing `cloud.yml` choices are preserved, including the default profile,
provider, image repository, build settings, sizes, GPU flag, capabilities and
Nodkey companion. No storage or placement setting is added.

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
