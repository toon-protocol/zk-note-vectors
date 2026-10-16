# zk-note-vectors

Fixtures and parity vectors that o1js produced, kept **outside** `toon-protocol/connector` on
purpose. ADR 0080 forbids an o1js dependency in that repository, so the script that runs o1js
lives here. Spike [connector#1512](https://github.com/toon-protocol/connector/issues/1512) produced
it, and its findings are in the connector's `docs/research/zk-note-verifier-spike.md`.

## What is here

| Path                    | What it is                                                                                                                                      |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `o1js-3.1.0/`           | Mesa (Mina mainnet since 2026-09-03). `generate.mjs`, an exact-pinned `package.json` and lockfile, and `fixtures/`.                              |
| `o1js-2.15.0/`          | The same script under the last pre-Mesa o1js.                                                                                                   |
| `fixtures/spend.json`   | A `ZkProgram` proof with `maxProofsVerified: 0` and a five-field public input shaped like an allowance statement, with its verification key and hash. |
| `fixtures/wrap.json`    | A `maxProofsVerified: 1` program that verifies a `spend` proof recursively, with a public input and a public output.                            |
| `fixtures/parity.json`  | Poseidon (kimchi, Pallas base field), `hashWithPrefix`, `hashToGroup`, and Mina Schnorr signatures (`Signature.create`, mina-signer `signFields`). |
| `rust/pre-mesa-toon-1512/` | A Rust harness that verifies the fixtures and checks every parity vector. It builds as a member of mina-rust `v0.19.0` (`ed6f4301`).          |
| `rust/mesa-toon-1512/`  | The same harness, for mina-rust with proof-systems repinned to Mesa's `ab84160f`.                                                               |
| `rust/patches/`         | Patches to mina-rust `v0.19.0`. One adds `verify_sideloaded`; the other repins proof-systems to Mesa and fixes the API drift. Both carry spike-only `TOON_1512_DEBUG` diagnostics. |

A proof is random, so rerunning `generate.mjs` produces different `spend.json` and `wrap.json`.
Every fixture is pinned by the commit of this repository, not by regeneration. `parity.json` is
deterministic.

## Reproduce

```sh
cd o1js-3.1.0 && npm ci && node generate.mjs fixtures

git clone https://github.com/o1-labs/mina-rust && cd mina-rust && git checkout v0.19.0
git apply ../zk-note-vectors/rust/patches/mina-rust-v0.19.0-mesa-proof-systems-ab84160.patch
cp -r ../zk-note-vectors/rust/mesa-toon-1512 tools/toon-1512   # and add it to [workspace] members
cargo build --release -p toon-1512 && ./target/release/toon-1512 ../zk-note-vectors/o1js-3.1.0/fixtures
```

Use `mina-rust-v0.19.0.patch` with `pre-mesa-toon-1512` against `o1js-2.15.0/fixtures`. A verifier
build serves one Mina era: each build refuses the other era's proofs.

The private keys in `parity.json` are toy scalars (1, 2, `0xdeadbeef`, 2^250 + 17). Never use them
for anything else.

## Licence

The patches modify mina-rust (Apache-2.0) and stay under that licence. Everything else is MIT.
