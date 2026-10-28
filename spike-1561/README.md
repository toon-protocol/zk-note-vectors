# spike-1561: proving an o1js zkApp method in Rust (PROTOTYPE, throwaway)

Throwaway prototype for [connector#1561](https://github.com/toon-protocol/connector/issues/1561),
written 2026-10-28. It lives on this branch so it never reaches `main`. Its findings are in the
connector's `docs/research/rust-zkapp-prover-spike.md`. Nothing here is production code.

## What it showed

| Step | Result |
| --- | --- |
| o1js exports a method's circuit in the format mina-rust's prover loads | **Yes.** o1js 3.1.0's bindings already contain Mina's `dump_extra_circuit_data` (gates JSON, `internal_vars.bin`, `rows_rev.bin`). `patches/o1js_node.bc.cjs.patch` calls it from `finalize_and_get_gates`. |
| mina-rust's kimchi prover proves an o1js step circuit | **Yes,** fed o1js's own witness: every constraint is satisfied, and the step proof takes 0.95 s. |
| mina-rust's verifier accepts o1js's real `land` proof (range-check and lookup gates) | **Yes.** The VK hash matches o1js and a tampered input is refused. A verify takes 92 ms with a cached index. |
| Wrap proof in Rust | **Not built.** mina-rust's in-circuit wrap verifier assumes N=2, one step key and no optional gates. |
| Step witness in Rust | **Not built.** `land-step-map.txt` maps all 17,962 values to the o1js call site that creates them. |
| A dummy proof on a proofs-off lightnet (4.0.2) | **Accepted,** and a constant (sha256 `00e459f1…2161`). A forged update the method forbids was also accepted. |

## Layout

- `o1js/`: `land.mjs` (the tiny zkApp), `compile.mjs`, `prove-local.mjs` (LocalBlockchain, fixed toy keys
  1001/1002, writes the fixtures), `lightnet.mjs` (`MODE=dummy|real`), `forge.mjs`, `statement.mjs`, `dummyhash.mjs`.
  `patches/` holds the o1js 3.1.0 patches: the circuit, witness and step-proof dumps (`SPIKE_DUMP=<dir>`) and an
  `exists` trace.
- `rust/patches/mina-rust-v0.19.0-mesa-plus-toon-1561.patch` applies **after**
  `rust/patches/mina-rust-v0.19.0-mesa-proof-systems-ab84160.patch`. `rust/toon-1561/` is the harness.
- `fixtures/` (gunzip first): `cs003` = `land` step circuit, `cs004` = `setup` step circuit, `cs005` = the
  wrap circuit, `w003`/`w004` = o1js's step/wrap witnesses for one `land` proof, `stepproof002.b64` = that
  proof's step proof (rmp-serde, base64), plus the transaction and its statement.
- `fx-land/`: the real `land` proof as a `toon-1512` fixture.

## Reproduce

```sh
cd o1js && npm ci && (cd node_modules/o1js/dist/node && patch -p0 < ../../../../patches/o1js_node.bc.cjs.patch && patch -p0 < ../../../../patches/exists.js.patch)
mkdir dump && SPIKE_DUMP=$PWD/dump node prove-local.mjs

git clone https://github.com/o1-labs/mina-rust && cd mina-rust && git checkout v0.19.0
git apply ../rust/patches/mina-rust-v0.19.0-mesa-proof-systems-ab84160.patch   # from this repo's rust/patches
git apply ../spike-1561/rust/patches/mina-rust-v0.19.0-mesa-plus-toon-1561.patch
cp -r ../rust/mesa-toon-1512 tools/toon-1512 && cp -r ../spike-1561/rust/toon-1561 tools/toon-1561
cargo build --release -p toon-1561 && ./target/release/toon-1561 <dump-dir>
```

Lightnet: `docker run -d -p 18080:8080 -p 18181:8181 o1labs/mina-local-network:4.0.2-lightnet`, then
`MODE=dummy OUT=out-dummy node lightnet.mjs` and `node forge.mjs`. That image is compiled with
`proof_level=none`. A proofs-on chain needs `4.0.2-devnet` with `PROOF_LEVEL=full`.

The private keys in `prove-local.mjs` are toy scalars. Never use them for anything else.
