import 'o1js';
import { dummyBase64Proof } from './node_modules/o1js/dist/node/lib/proof-system/zkprogram.js';
import crypto from 'crypto';
const p = await dummyBase64Proof();
console.log(p.length, crypto.createHash('sha256').update(p).digest('hex'));
