// Generates the fixtures for toon-protocol/connector#1512.
//
// 1. Proof fixtures: two ZkPrograms with custom public inputs, one with
//    maxProofsVerified 0 and one with maxProofsVerified 1 (it verifies the first
//    recursively) and a public output. Each is written with its verification key,
//    so a Rust verifier can be checked against what o1js produced.
// 2. Parity vectors: Poseidon (kimchi parameters, Pallas base field),
//    hashWithPrefix, hashToGroup, and Mina Schnorr signatures (o1js's provable
//    Signature.create, and mina-signer's sign for devnet and mainnet).
//
// Usage: node generate.mjs <out-dir>
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  Field,
  Struct,
  ZkProgram,
  Poseidon,
  PrivateKey,
  Signature,
  SelfProof,
  Provable,
  Scalar,
} from 'o1js';
import Client from 'mina-signer';

const out = process.argv[2] ?? 'out';
mkdirSync(out, { recursive: true });
const write = (name, value) => {
  const text = JSON.stringify(value, null, 2) + '\n';
  writeFileSync(`${out}/${name}`, text);
  console.log(`${name} sha256=${createHash('sha256').update(text).digest('hex')}`);
};

// A stand-in for the vault's proof program: the shape of its public input
// (root, nullifier, binding tag, tier, expiry), not its real constraints.
class AllowanceStatement extends Struct({
  root: Field,
  nullifier: Field,
  binding: Field,
  tier: Field,
  expiry: Field,
}) {}

const Spend = ZkProgram({
  name: 'toon-1512-spend',
  publicInput: AllowanceStatement,
  methods: {
    spend: {
      privateInputs: [Field, Field],
      async method(s, secret, balance) {
        Poseidon.hash([secret, Field(0)]).assertEquals(s.nullifier);
        Poseidon.hash([secret, balance]).assertEquals(s.root);
        balance.assertGreaterThanOrEqual(s.tier);
      },
    },
  },
});

const SpendProof = ZkProgram.Proof(Spend);

const Wrap = ZkProgram({
  name: 'toon-1512-wrap',
  publicInput: Field,
  publicOutput: Field,
  methods: {
    wrap: {
      privateInputs: [SpendProof],
      async method(tag, inner) {
        inner.verify();
        inner.publicInput.binding.assertEquals(tag);
        return { publicOutput: Poseidon.hash([inner.publicInput.nullifier, tag]) };
      },
    },
  },
});

const time = async (f) => {
  const t = performance.now();
  const r = await f();
  return [r, Math.round(performance.now() - t)];
};

const secret = Field(424242);
const balance = Field(1_000_000);
const statement = new AllowanceStatement({
  root: Poseidon.hash([secret, balance]),
  nullifier: Poseidon.hash([secret, Field(0)]),
  binding: Poseidon.hash([Field(1), Field(2), Field(3)]),
  tier: Field(250_000),
  expiry: Field(1_790_000_000),
});

const [{ verificationKey: spendVk }, spendCompileMs] = await time(() => Spend.compile());
const [{ proof: spendProof }, spendProveMs] = await time(() =>
  Spend.spend(statement, secret, balance)
);
const [spendOk, spendVerifyMs] = await time(() => Spend.verify(spendProof));
if (!spendOk) throw Error('o1js rejected its own spend proof');

const flatten = (type, value) => type.toFields(value).map((f) => f.toString());

write('spend.json', {
  program: 'toon-1512-spend',
  maxProofsVerified: spendProof.maxProofsVerified,
  verificationKey: { data: spendVk.data, hash: spendVk.hash.toString() },
  publicInputFields: flatten(AllowanceStatement, spendProof.publicInput),
  publicOutputFields: [],
  proof: spendProof.toJSON().proof,
  timingsMs: { compile: spendCompileMs, prove: spendProveMs, verify: spendVerifyMs },
});

const [{ verificationKey: wrapVk }, wrapCompileMs] = await time(() => Wrap.compile());
const [{ proof: wrapProof }, wrapProveMs] = await time(() =>
  Wrap.wrap(statement.binding, spendProof)
);
const [wrapOk, wrapVerifyMs] = await time(() => Wrap.verify(wrapProof));
if (!wrapOk) throw Error('o1js rejected its own wrap proof');

write('wrap.json', {
  program: 'toon-1512-wrap',
  maxProofsVerified: wrapProof.maxProofsVerified,
  verificationKey: { data: wrapVk.data, hash: wrapVk.hash.toString() },
  publicInputFields: [wrapProof.publicInput.toString()],
  publicOutputFields: [wrapProof.publicOutput.toString()],
  proof: wrapProof.toJSON().proof,
  timingsMs: { compile: wrapCompileMs, prove: wrapProveMs, verify: wrapVerifyMs },
});

// ---- Parity vectors -------------------------------------------------------

const P = 28948022309329048855892746252171976963363056481941560715954676764349967630337n;
const inputs = [
  [],
  [0n],
  [1n],
  [1n, 2n],
  [1n, 2n, 3n],
  [0n, 0n, 0n, 0n, 0n],
  [P - 1n, 12345678901234567890n, 7n, 2n ** 200n, 99n],
].map((xs) => xs.map(String));

const fields = (xs) => xs.map((x) => Field(x));

const poseidon = inputs.map((input) => ({
  input,
  output: Poseidon.hash(fields(input)).toString(),
}));

// o1js zero-pads a short prefix; Rust's mina-hasher pads it with '*'. A prefix
// written out to 20 bytes means the same thing to both.
const prefixes = ['MinaSignatureMainnet', 'CodaSignature*******', 'toon-zk-note********', 'toon-zk-note'];
const hashWithPrefix = prefixes.flatMap((prefix) =>
  inputs.slice(1, 5).map((input) => ({
    prefix,
    input,
    output: Poseidon.hashWithPrefix(prefix, fields(input)).toString(),
  }))
);

const hashToGroup = inputs.slice(1).map((input) => {
  const g = Poseidon.hashToGroup(fields(input));
  return { input, x: g.x.toString(), y: g.y.toString() };
});

const keys = [1n, 2n, 0xdeadbeefn, 2n ** 250n + 17n].map((s) => PrivateKey.fromBigInt(s));
const messages = inputs.slice(1, 6);

const schnorrProvable = keys.flatMap((key) =>
  messages.map((message) => {
    const sig = Signature.create(key, fields(message));
    if (!sig.verify(key.toPublicKey(), fields(message)).toBoolean())
      throw Error('o1js rejected its own signature');
    return {
      privateKey: key.toBigInt().toString(),
      privateKeyBase58: key.toBase58(),
      publicKeyBase58: key.toPublicKey().toBase58(),
      message,
      r: sig.r.toString(),
      s: sig.s.toBigInt().toString(),
    };
  })
);

// mina-signer's signFields signs under 'devnet' whatever network the client
// was created with, so there is one set, not one per network.
const minaSignerClient = new Client({ network: 'mainnet' });
const minaSigner = keys.flatMap((key) =>
  messages.map((message) => {
    const signed = minaSignerClient.signFields(message.map(BigInt), key.toBase58());
    if (!minaSignerClient.verifyFields(signed))
      throw Error('mina-signer rejected its own signature');
    return {
      network: 'devnet',
      privateKey: key.toBigInt().toString(),
      publicKeyBase58: key.toPublicKey().toBase58(),
      message,
      signatureBase58: signed.signature,
      r: Signature.fromBase58(signed.signature).r.toString(),
      s: Signature.fromBase58(signed.signature).s.toBigInt().toString(),
    };
  })
);

write('parity.json', {
  o1js: '3.1.0',
  minaSigner: JSON.parse(readFileSync('node_modules/mina-signer/package.json')).version,
  field: 'Pallas base field (Fp), p = ' + P,
  poseidon,
  hashWithPrefix,
  hashToGroup,
  schnorr: {
    note: 'o1js Signature.create always uses the devnet prefix and devnet nonce derivation',
    provable: schnorrProvable,
    minaSigner,
  },
});

// Silence the unused-import lint for helpers kept for interactive use.
void Provable;
void Scalar;
void SelfProof;
