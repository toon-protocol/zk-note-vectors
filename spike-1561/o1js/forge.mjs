// PROTOTYPE #1561: does a proofs-off lightnet accept an update the circuit would refuse?
// Replays out-dummy/land.tx.json with landed rewritten DOWN to 3 (the method requires an increase).
import { Mina, PrivateKey, Field, Bool, fetchAccount, Transaction, UInt32 } from 'o1js';
import fs from 'fs';
const GQL = 'http://localhost:18080/graphql';
Mina.setActiveInstance(Mina.Network({ mina: GQL }));
const keys = JSON.parse(fs.readFileSync('out-dummy/keys.json'));
const fee = PrivateKey.fromBase58(keys.feePayer);
const zkAddr = PrivateKey.fromBase58(keys.zkapp).toPublicKey();
const { account: fp } = await fetchAccount({ publicKey: fee.toPublicKey() });
const tx = Transaction.fromJSON(JSON.parse(fs.readFileSync('out-dummy/land.tx.json')));
tx.transaction.feePayer.body.nonce = fp.nonce;
tx.transaction.feePayer.lazyAuthorization = { kind: 'lazy-signature' };
const au = tx.transaction.accountUpdates.find(a => a.body.publicKey.equals(zkAddr).toBoolean());
au.body.update.appState[0] = { isSome: Bool(true), value: Field(3) };
au.body.preconditions.account.state[0] = { isSome: Bool(true), value: Field(5) };
tx.sign([fee]);
const p = await tx.send();
console.log('forged land status', p.status, JSON.stringify(p.errors ?? []).slice(0, 300));
if (p.status === 'pending') { const r = await p.wait({ maxAttempts: 60, interval: 10000 }); console.log('forged', r.status); }
const { account } = await fetchAccount({ publicKey: zkAddr });
console.log('landed on chain now =', account.zkapp.appState[0].toString());
