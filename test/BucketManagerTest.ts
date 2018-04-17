import * as elliptic from 'elliptic';
import {BucketManger} from "../lib/BucketManger";
import {NodeDiscovery} from "../lib/NodeDiscovery";
import {Node} from "../lib/Node";
import { expect } from 'chai';

describe('BucketManager', () => {
    const ec = new elliptic.ec('secp256k1')
    const keypair = ec.genKeyPair()
    const node = Node.fromIpAndPort('127.0.0.1', 30303)
    const discovery = new NodeDiscovery(keypair, node);
    const bucketManager = new BucketManger(node, discovery);
    const oldPingPongFunction = discovery.pingPong;

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
    })

    describe('')
})