// PROTOTYPE for connector#1561 — throwaway driver.
// MODE=dummy : proofsEnabled=false, every proof-authorized update carries o1js's dummy proof.
// MODE=real  : compile and prove in o1js (baseline, and the source of the witness dumps).
import { Mina, Lightnet, PrivateKey, AccountUpdate, UInt64, Signature, fetchAccount } from 'o1js';
import { Land } from './land.mjs';
import fs from 'fs';
import { dummyBase64Proof } from './node_modules/o1js/dist/node/lib/proof-system/zkprogram.js';

const MODE = process.env.MODE ?? 'dummy';
const GQL = process.env.GQL ?? 'http://localhost:18080/graphql';
const ACM = process.env.ACM ?? 'http://localhost:18181';
const OUT = process.env.OUT ?? './out';
fs.mkdirSync(OUT, { recursive: true });

const net = Mina.Network({ mina: GQL, lightnetAccountManager: ACM });
net.proofsEnabled = MODE === 'real';
Mina.setActiveInstance(net);

const fee = await Lightnet.acquireKeyPair({ lightnetAccountManagerEndpoint: ACM });
const feePayer = fee.publicKey;
const zkKey = PrivateKey.random(), zkAddr = zkKey.toPublicKey();
const payerKey = PrivateKey.random(), payer = payerKey.toPublicKey();
fs.writeFileSync(`${OUT}/keys.json`, JSON.stringify({ feePayer: fee.privateKey.toBase58(), zkapp: zkKey.toBase58(), payer: payerKey.toBase58() }));
const zk = new Land(zkAddr);

if (MODE === 'real') {
  let t = Date.now();
  const { verificationKey } = await Land.compile();
  console.log('compile ms', Date.now() - t, 'vk', verificationKey.hash.toString());
}

async function send(label, f, keys) {
  const t0 = Date.now();
  const tx = await Mina.transaction({ sender: feePayer, fee: 1e8 }, f);
  const t1 = Date.now();
  if (MODE === 'dummy') {
    const dummy = await dummyBase64Proof();
    fs.writeFileSync(`${OUT}/dummy-proof.b64`, dummy);
    for (const au of tx.transaction.accountUpdates)
      if (au.lazyAuthorization?.kind === 'lazy-proof') { au.authorization = { proof: dummy }; au.lazyAuthorization = undefined; }
  } else await tx.prove();
  const t2 = Date.now();
  tx.sign([fee.privateKey, ...keys]);
  fs.writeFileSync(`${OUT}/${label}.tx.json`, tx.toJSON());
  const pending = await tx.send();
  console.log(label, 'status', pending.status, pending.errors ?? '', 'hash', pending.hash, `build ${t1 - t0}ms prove ${t2 - t1}ms`);
  if (pending.status !== 'pending') throw new Error(label + ' rejected: ' + JSON.stringify(pending.errors));
  const inc = await pending.wait({ maxAttempts: 90, interval: 10000 });
  console.log(label, 'included', inc.status, `after ${Date.now() - t2}ms`);
}

await send('deploy', async () => { AccountUpdate.fundNewAccount(feePayer); await zk.deploy(); }, [zkKey]);
await send('setup', async () => { await zk.setup(payer); }, []);
await fetchAccount({ publicKey: zkAddr });
const cumulative = UInt64.from(5);
const sig = Signature.create(payerKey, cumulative.toFields());
await send('land', async () => { await zk.land(cumulative, sig); }, []);
await fetchAccount({ publicKey: zkAddr });
console.log('landed =', zk.landed.get().toString());
// A voucher that does not raise the watermark must be refused.
try {
  await fetchAccount({ publicKey: zkAddr });
  await send('land-again', async () => { await zk.land(cumulative, sig); }, []);
  console.log('UNEXPECTED: replay accepted');
} catch (e) { console.log('replay refused:', String(e.message).slice(0, 200)); }
await Lightnet.releaseKeyPair({ publicKey: feePayer.toBase58(), lightnetAccountManagerEndpoint: ACM });
