import {Hasher, keccak256} from "js-sha3";
import {createCipheriv} from "crypto";
import * as assert from "assert";

export class Mac {
    private hash: Hasher;

    constructor(private macSecret: Buffer, initData: Buffer) {
        this.hash = keccak256.create();
        this.hash.update(initData);
    }

    /** calculate header mac
     * egress-mac.update(aes(mac-secret,egress-mac) ^ header-ciphertext).digest
     *
     * @param data
     * @returns {Buffer}
     */
    public headerMac(header) : Buffer {
        const digest = this.runningDigest();
        const aes = createCipheriv('aes-256-ecb', this.macSecret, '');
        const encrypted = aes.update(digest);
        this.hash.update(this.xor(encrypted, header));
        return this.runningDigest();
    }

    /** calculate frame mac
     * egress-mac.update(aes(mac-secret,egress-mac) ^ egress-mac.update(frame-ciphertext).digest)
     *
     * @param data
     * @returns {Buffer}
     */
    public frameMac(frame) : Buffer {
        this.hash.update(frame);
        const digest = this.runningDigest();
        const aes = createCipheriv('aes-256-ecb', this.macSecret, '');
        const encrypted = aes.update(digest);
        this.hash.update(this.xor(encrypted, digest));
        return this.runningDigest();
    }

    public runningDigest() : Buffer {
        let tmp = keccak256.create();
        tmp = Object.assign(tmp, this.hash);
        // object.assign only clone nested array as a reference
        // need to manually clone 's' and 'blocks'
        tmp['s'] = tmp['s'].slice(0);
        tmp['blocks'] = tmp['blocks'].slice(0);
        return Buffer.from(tmp.digest().slice(0, 16));
    }

    private xor(input1: Buffer, input2: Buffer) {
        assert.equal(input1.length, input2.length, `XOR input size doesn't match: ${input1.length} != ${input2.length}`);

        const output = new Buffer(input1.length);
        for(let i=0; i<input1.length; i++) {
            output[i] = input1[i] ^ input2[i];
        }
        return output;
    }
}