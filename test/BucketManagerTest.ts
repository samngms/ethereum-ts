import * as elliptic from 'elliptic';
import {Bucket, BucketManger} from "../lib/BucketManger";
import {NodeDiscovery} from "../lib/NodeDiscovery";
import {Node} from "../lib/Node";
import { expect } from 'chai';

const ec = new elliptic.ec('secp256k1');

describe('BucketManager', () => {
    const keypair = ec.genKeyPair();
    const thisNode = Node.fromIpAndPort('127.0.0.1', 30303);
    const remote1 = Node.fromUrl('enode://ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31387574077f301b421bc84df7266c44e9e6d569fc56be00812904767bf5ccd1fc7f@12.34.56.78:12345');
    const remote2 = Node.fromUrl('enode://b6d82fa3409da933dbf9cb0140c5dde89f4e64aec88d476af648880f4a10e1e49fe35ef3e69e93dd300b4797765a747c6384a6ecf5db9c2690398607a86181e4@33.44.55.66:20123');
    const discovery = new NodeDiscovery(keypair, thisNode);
    const bucketManager = new BucketManger(thisNode, discovery);
    const oldPingPongFunction = discovery.pingPong;
    const bucket = new Bucket(discovery);

    describe('#distance', () => {
        it('same data, distance=10', () => {
            let h1 = [0xFF, 0xFF, 0xFF, 0xFF]
            let h2 = [0xFF, 0xFF, 0xFF, 0xFF]
            let dist = bucketManager.distance(h1, h2)

            expect(dist).eq(10)
        })

        it('only check the first two bytes', () => {
            let h1 = [0xFF, 0xFF, 0xFF, 0xFF]
            let h2 = [0xFF, 0xFF, 0x12, 0x23]
            let dist = bucketManager.distance(h1, h2)

            expect(dist).eq(10)
        })

        it('first bit is different', () => {
            let h1 = [0b10101010, 0x5A]
            let h2 = [0b00101010, 0x5A]
            let dist = bucketManager.distance(h1, h2)

            expect(dist).eq(0)
        })

        it('second bit is different', () => {
            let h1 = [0b10101010, 0x5A]
            let h2 = [0b11101010, 0x5A]
            let dist = bucketManager.distance(h1, h2)

            expect(dist).eq(1)
        })

        it('first bit of the second byte is different', () => {
            let h1 = [0b10101010, 0b01010101]
            let h2 = [0b10101010, 0b11010101]
            let dist = bucketManager.distance(h1, h2)

            expect(dist).eq(8)
        })

        it('second bit of the second byte is different', () => {
            let h1 = [0b10101010, 0b01010101]
            let h2 = [0b10101010, 0b00010101]
            let dist = bucketManager.distance(h1, h2)

            expect(dist).eq(9)
        })

        it('third bit of the second byte is different', () => {
            let h1 = [0b10101010, 0b01010101]
            let h2 = [0b10101010, 0b01110101]
            let dist = bucketManager.distance(h1, h2)

            expect(dist).eq(10)
        })

        it('forth bit of the second byte is different', () => {
            let h1 = [0b10101010, 0b01010101]
            let h2 = [0b10101010, 0b01000101]
            let dist = bucketManager.distance(h1, h2)

            expect(dist).eq(10)
        })
    });

    describe('#Bucket', () => {
        let pingPongError = false;

        before(() => {
            // redefine pingPong to just resolve after 200ms
            discovery.pingPong = (remote: Node, retry = 2) => {
                return new Promise((resolve, reject) => {
                    setTimeout(() => {
                        const str = '04' + remote.nodeId.toString('hex');
                        const keypair = ec.keyFromPublic(str, 'hex');
                        if ( pingPongError ) {
                            reject(new Error('Simulated PingPong Error'));
                        } else {
                            resolve({
                                rinfo: {address: remote.endpoint.ip, family: 'ipv4', port: remote.endpoint.udp},
                                pubKey: keypair.getPublic()
                            })
                        }
                    }, 200)
                })
            }
        });

        beforeEach(() => {
            _nodeCounter = 10;
            bucket.list = [];
            // insert 10 random nodes to
            for(let i=0; i<bucket.BUCKET_SIZE; i++) {
                bucket.touchNode(genRandomNode());
            }
        });

        it('insert nodes', () => {
            expect(bucket.list.length).eq(bucket.BUCKET_SIZE);
        });

        it('Bucket eviction (keep old nodes)', (done) => {
            pingPongError = false;
            let tmp = bucket.list[bucket.BUCKET_SIZE-3];
            bucket.touchNode(remote1);
            bucket.touchNode(remote1);
            bucket.touchNode(remote2);

            setTimeout(() => {
                expect(bucket.list.length).eq(bucket.BUCKET_SIZE);
                expect(bucket.list[bucket.BUCKET_SIZE-1]).eq(tmp);
                done();
            }, 1000);
        }).timeout(5000);

        it('Bucket eviction (replace by new nodes)', (done) => {
            pingPongError = true;
            let removed0 = bucket.list[bucket.BUCKET_SIZE-1];
            let removed1 = bucket.list[bucket.BUCKET_SIZE-2];
            bucket.touchNode(remote1);
            bucket.touchNode(remote1);
            bucket.touchNode(remote2);

            setTimeout(() => {
                expect(bucket.list.length).eq(bucket.BUCKET_SIZE);
                expect(bucket.list[0].node).eq(remote2);
                expect(bucket.list[1].node).eq(remote1);
                expect(bucket.findNode(removed0.node.hash)).eq(-1);
                expect(bucket.findNode(removed1.node.hash)).eq(-1);
                done();
            }, 1000);
        }).timeout(5000);
    })
})

let _nodeCounter = 10;
function genRandomNode() {
    const keypair = ec.genKeyPair()
    const pubKey = keypair.getPublic();
    const pubStr = Buffer.from(pubKey.encode(true, false)).slice(1).toString('hex');
    const str = `enode://${pubStr}@10.${_nodeCounter}.${_nodeCounter}.${_nodeCounter}:30303`;
    _nodeCounter++;
    return Node.fromUrl(str);
}

