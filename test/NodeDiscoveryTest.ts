import {NodeDiscovery} from "../lib/NodeDiscovery";
import * as elliptic from 'elliptic';
import * as log4js from 'log4js';
import * as MockDgram from 'mock-dgram';
import {EventEmitter} from "events";
import {Node} from '../lib/Node';
import 'mocha';
import { expect } from 'chai';
import * as dgram from "dgram";
import {Endpoint} from "../lib/Endpoint";
import {AddressInfo} from "dgram";
import  * as recording from 'log4js/lib/appenders/recording';
import {keccak256} from "js-sha3";


log4js.configure({
    appenders: { console: { type: 'console' }, memory: { type: 'recording' } },
    categories: { default: { appenders: [ 'console', 'memory' ], level: 'debug' } }
});

const ec = new elliptic.ec('secp256k1');
const key = ec.keyFromPrivate('49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee');
const node = Node.fromIpAndPort('127.0.0.1', 30303);
const socket = dgram.createSocket('udp4');
let discovery = new NodeDiscovery(key, node, socket);

let encryptedData: Buffer;
let rawData: Buffer;

// redefine socket.send
socket.send = function(buf, port, ip, cb) {
    encryptedData = buf;
    cb(null);
};
// redefine discovery.send
const oldDiscoverySend = discovery.send;
discovery.send = function(remote: Endpoint, packetType: number, packetData: Buffer, beforeSend?: (b: Buffer) => void ) {
    rawData = packetData;
    return oldDiscoverySend.apply(this, arguments);
};
// redefine discovery.now
discovery.now = function() { return 0x5ab09d9c; };

describe('NodeDiscovery', () => {
    describe('#ping', () => {
        it('correct ping raw packet', async () => {
            const remote = Node.fromUrl('enode://ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31387574077f301b421bc84df7266c44e9e6d569fc56be00812904767bf5ccd1fc7f@12.34.56.78:12345');
            const packet = await discovery.ping(remote, null);
            expect(rawData.toString('hex')).eq('de03cb847f00000182765f82765fcb840c22384e823039823039845ab09da1');
        });

        it('correct ping raw packet with discport in URL', async () => {
            const remote = Node.fromUrl('enode://ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31387574077f301b421bc84df7266c44e9e6d569fc56be00812904767bf5ccd1fc7f@12.34.56.78:54321?discport=12345');
            const packet = await discovery.ping(remote, null);
            expect(rawData.toString('hex')).eq('de03cb847f00000182765f82765fcb840c22384e82303982d431845ab09da1');
        });
    });

    describe('#ping received', () => {
        it('correct ping packet', (done) => {
            let data = '94a39698380bd55ef26a4ff2c8971fdfd6a8e45d02e170465b88233393267d3e7a11d5836834325918988ea1c50820b4f9ef679b323eecc7c17d2e45a824476fa3e84ba169853854b8acaf0effd9e0e83b24b897eb25df6f2a5a96fde67e4d000101de03cb847f00000182765f82765fcb840c22384e823039823039845ab09da1';
            discovery.once('pingReceived', (endpoint: Endpoint, hash: number[]) => {
                expect(Buffer.from(hash).toString('hex')).equals('94a39698380bd55ef26a4ff2c8971fdfd6a8e45d02e170465b88233393267d3e');
                done();
            });
            discovery.onMessage(Buffer.from(data, 'hex'), {address: '127.0.0.1', family: 'ipv4', port: 30303});
        });

        it('invalid hash', (done) => {
            recording.erase();
            let data = '94b39698380bd55ef26a4ff2c8971fdfd6a8e45d02e170465b88233393267d3e7a11d5836834325918988ea1c50820b4f9ef679b323eecc7c17d2e45a824476fa3e84ba169853854b8acaf0effd9e0e83b24b897eb25df6f2a5a96fde67e4d000101de03cb847f00000182765f82765fcb840c22384e823039823039845ab09da1';
            discovery.once('pingReceived', (endpoint: Endpoint, hash: number[]) => {
                throw new Error("The program shouldn't read here");
            });
            discovery.onMessage(Buffer.from(data, 'hex'), {address: '127.0.0.1', family: 'ipv4', port: 30303});
            const events = recording.replay();
            var rx = /invalid hash/;
            expect(events.find(item => { return rx.test(item.data[0]) })).is.not.undefined.and.not.null;
            done();
        });

        it('invalid signature', (done) => {
            recording.erase();
            let data = '57703297aecca0cf31a69a5e64c3bcfa70b1bc02ef99c642273394e78c3f2f857a11d5836834325918988ea1c51820b4f9ef679b323eecc7c17d2e45a824476fa3e84ba169853854b8acaf0effd9e0e83b24b897eb25df6f2a5a96fde67e4d000101de03cb847f00000182765f82765fcb840c22384e823039823039845ab09da1';
            discovery.onMessage(Buffer.from(data, 'hex'), {address: '127.0.0.1', family: 'ipv4', port: 30303});
            const events = recording.replay();
            let rx = /invalid signature/;
            let logEntry = events.find(item => { return rx.test(item.data[0]) });
            expect(logEntry).is.not.undefined.and.not.null;
            done();
        });
    })
})