import { Land } from './land.mjs';
import fs from 'fs';
const t = Date.now();
const { verificationKey } = await Land.compile({ forceRecompile: true });
console.log('compile ms', Date.now() - t, 'vk hash', verificationKey.hash.toString());
fs.writeFileSync(process.env.SPIKE_DUMP + '/vk.json', JSON.stringify({ data: verificationKey.data, hash: verificationKey.hash.toString() }));
const a = await Land.analyzeMethods();
for (const [k, v] of Object.entries(a)) console.log(k, 'rows', v.rows, 'digest', v.digest);
