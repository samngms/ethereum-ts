import * as Elliptic from 'elliptic';
import * as RLP from 'rlp';
import * as IP from 'ip';
import * as Digest from 'js-sha3';
import * as dgram from "dgram";
import * as BN from 'bn.js';
import * as fs from "fs";
import * as winston from 'winston';
import {Node} from "./lib/Node";
import { DiscoveryProtocol } from './lib/DiscoveryProtocol';

winston.loggers.add('DiscoveryProtocol', {
    console: {
        level: 'silly',
        colorize: true,
        label: 'DiscoveryProtocol',
        timestamp: true
    }
});

let discovery = new DiscoveryProtocol();

discovery.privateKey = "59e8fcddc11590e4baac204e376a2ae9e3f50455474bc7a864a9e670764a3ffb";
discovery.startInternal( () => {
    discovery.pingPong(Node.fromIpAndPort('52.59.174.100', 40304)).then(() => {
        console.log("Yeah, it WORKS!!");
    }).catch((err) => {
        console.log("Oops... error: " + err);
    })
});


/*let rawData = [
    0xDE, 0x03, 0xCB, 0x84, 0x7F, 0x00, 0x00, 0x01, 0x82, 0x76, 0x5F, 0x82,
    0x76, 0x5F, 0xCB, 0x84, 0x0D, 0x4B, 0x9A, 0x8A, 0x82, 0x76, 0x5F, 0x82,
    0x76, 0x5F, 0x84, 0x5A, 0xAF, 0xCA, 0xE0
];

let buf = Buffer.from(rawData);
let x = RLP.decode(buf);
console.log(x);
*/


// Create and initialize EC context
// (better do it once and reuse it)
//let ec = new Elliptic.ec('secp256k1');

//let key =  ec.keyFromPrivate("c7979aed5d7b14c1854f617a67c724d16e7852391f47ab1d1c433952a3ad8aa3");
//console.log(key.getPublic());

//let key = ec.genKeyPair();
//console.log(key.getPublic());
//console.log(key.getPrivate());

/*let pingData = ['\x03',
    [IP.toBuffer('127.0.0.1'), 30303, 30303],
    [IP.toBuffer('13.75.154.138'), 30303, 30303],
    //0x5aafcae0
    Math.floor(new Date().getTime()/1000 + 10)
];

let packed = RLP.encode(pingData);
console.log(packed);

let digest = Digest.keccak256.create();
digest.update('\x01');
digest.update(packed);
console.log(digest.hex());

let signature = key.sign(digest.digest(), { canonical: 1 });
console.log(signature);

// Ethereum uses Keccak256, not SHA3
// although doc all around talks about SHA3
let digest2 = Digest.keccak256.create();
let sig_r = signature.r.toArray()
digest2.update(sig_r);
let sig_s = signature.s.toArray()
digest2.update(sig_s);
digest2.update(String.fromCharCode(signature.recoveryParam));
digest2.update('\x01');
digest2.update(packed);
console.log(digest2.hex());
let hash = digest2.digest();

let server = dgram.createSocket('udp4');
server.on('error', (err) => {
    console.log(`server error:\n${err.stack}`);
    server.close();
});

server.on('message', (msg, rinfo) => {
    console.log(`server got: ${msg} from ${rinfo.address}:${rinfo.port}`);
    fs.writeFileSync('pong_data', msg, {encoding: null, flag: 'w', mode: 0o666});
    server.close();
});

server.on('listening', () => {
    const address = server.address();
    console.log(`server listening ${address.address}:${address.port}`);
});

server.bind(30303);

let packet = new Uint8Array(hash.length + sig_r.length + sig_s.length + 1 + 1 + packed.length);
packet.set(hash, 0);
var offset = hash.length;
packet.set(sig_r, offset);
offset += sig_r.length;
packet.set(sig_s, offset);
offset += sig_s.length;
packet.set([signature.recoveryParam], offset);
offset++;
packet.set([1], offset);
offset++;
packet.set(packed, offset);
console.log(packet);
console.log(offset + packed.length);

console.log(new BN(packet, 16));

//let client = dgram.createSocket('udp4');
server.send(Buffer.from(packet), 30303, '13.75.154.138', (err) => {
    console.log("Error: " + err);
});

/*let tmp1 = new Uint8Array(packed);
let tmp2 = new Uint8Array(tmp1.length + 1);
tmp2.set([1]);
tmp2.set(tmp1);
let tmp3 = CryptoJS.lib.WordArray.create(tmp2);

console.log(tmp3);

let sha3 = CryptoJS.algo.SHA3.create({ outputLength: 256 })
sha3.update(tmp3);
let hash = sha3.finalize();
console.log(hash);

let signature = key.sign(hash.words);
console.log(signature.toDER());
//let derSignature = signature.toDER();*/
