// PROTOTYPE #1561: the zkApp statement (public input) and proof of the proved `land` update.
import { Mina, PublicKey } from 'o1js';
import fs from 'fs';
const dir = process.argv[2];
const inputs = JSON.parse(fs.readFileSync(`${dir}/inputs.json`));
const tx = Mina.Transaction.fromJSON(JSON.parse(fs.readFileSync(`${dir}/land.proved.tx.json`)));
const zk = PublicKey.fromBase58(inputs.zkapp);
const au = tx.transaction.accountUpdates.find(a => a.body.publicKey.equals(zk).toBoolean() && a.authorization.proof);
const pi = au.toPublicInput(tx.transaction);
const out = { accountUpdate: pi.accountUpdate.toString(), calls: pi.calls.toString(), proof: au.authorization.proof, vk: inputs.vk };
fs.writeFileSync(`${dir}/land.statement.json`, JSON.stringify(out));
console.log(out.accountUpdate, out.calls, out.proof.length);
