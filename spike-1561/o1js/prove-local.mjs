// PROTOTYPE #1561: prove `land` on a LocalBlockchain with fixed keys, dumping o1js's
// step/wrap witnesses (SPIKE_DUMP) and the transaction, as the Rust prover's reference.
import { Mina, PrivateKey, AccountUpdate, UInt64, Signature } from 'o1js';
import { Land } from './land.mjs';
import fs from 'fs';
const OUT = process.env.SPIKE_DUMP;
const Local = await Mina.LocalBlockchain({ proofsEnabled: true });
Mina.setActiveInstance(Local);
const [fee] = Local.testAccounts;
const zkKey = PrivateKey.fromBigInt(1001n), zkAddr = zkKey.toPublicKey();
const payerKey = PrivateKey.fromBigInt(1002n), payer = payerKey.toPublicKey();
const zk = new Land(zkAddr);
const { verificationKey } = await Land.compile();
let tx = await Mina.transaction(fee, async () => { AccountUpdate.fundNewAccount(fee); await zk.deploy(); });
await tx.sign([fee.key, zkKey]).send();
tx = await Mina.transaction(fee, async () => { await zk.setup(payer); });
await tx.prove(); await tx.sign([fee.key]).send();
const cumulative = UInt64.from(5);
const sig = Signature.create(payerKey, cumulative.toFields());
tx = await Mina.transaction(fee, async () => { await zk.land(cumulative, sig); });
globalThis.__spikeTrace = []; globalThis.__spikeMark = true;
fs.writeFileSync(`${OUT}/land.unproved.tx.json`, tx.toJSON());
const t = Date.now();
await tx.prove();
console.log('land prove ms', Date.now() - t);
fs.writeFileSync(`${OUT}/land.proved.tx.json`, tx.toJSON());
await tx.sign([fee.key]).send();
console.log('landed', zk.landed.get().toString(), 'vk', verificationKey.hash.toString());
fs.writeFileSync(`${OUT}/inputs.json`, JSON.stringify({ zkapp: zkAddr.toBase58(), payer: payer.toBase58(), cumulative: '5', sig: sig.toBase58(), vk: verificationKey.data, vkHash: verificationKey.hash.toString() }));
