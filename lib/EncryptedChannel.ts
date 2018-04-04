import * as elliptic from 'elliptic';
import * as crypto from 'crypto';
import * as assert from "assert";
import {keccak256} from "js-sha3";
import * as net from "net";
import {Endpoint} from "./Endpoint";
import {isNullOrUndefined} from "util";
import {Cipher, Decipher} from "crypto";
import {Mac} from "./Mac";
import * as rlp from 'rlp';

export class EncryptedChannel {
    private ec = new elliptic.ec('secp256k1');

    private localEphemeralKey: any;
    private localNonce: Buffer;
    private remoteEphemeralKey: any;
    private remoteNonce: Buffer;

    private aesSecret: Buffer;
    private decipher: Decipher;
    private cipher: Cipher;
    private macSecret: Buffer;
    private macIn: Mac;
    private macOut: Mac;

    private authPacket: Buffer; // we need this to init macIngress

    private remotePubKey: any;

    private sock: net.Socket;
    private sockTimeout = 10000;

    /** we may need to "concat" multiple chunk into one single Buffer until it is long enough so that the handler is able to process it */
    private readBuf : Buffer;
    /** when data is received, it will call readCallback[0](), the function object is supposed to remove itself if it has read enough data */
    private readCallback: (() => boolean)[] = [];

    constructor(private key: any) {
        this.localEphemeralKey = this.ec.genKeyPair();
        this.localNonce = crypto.randomBytes(32);

        this.sock = new net.Socket({allowHalfOpen: true});
        let self = this;
        this.sock.on('data', (data: Buffer): void => {
            self.readData(data);
        });
    }

    /** connect to remote node
     *
     * @param {Endpoint} remote
     * @returns {Promise<void>} resolve if connect successfully, reject upon socket error or timeout
     */
    public connect(remote: Endpoint) {
        return new Promise((resolve, reject) => {
            let done = false;
            const errFunc = (err: Error): void => {
                if (!done) {
                    done = true;
                    reject(err);
                }
            };
            this.sock.once('error', errFunc);
            setTimeout(() => {
                if (!done) {
                    done = true;
                    this.sock.removeListener('error', errFunc);
                    reject(new Error("sock connect timeout"));
                }
            }, this.sockTimeout);
            this.sock.connect({host: remote.ip, port: remote.tcp, localPort: 30303}, () => {
                if ( !done ) {
                    done = true;
                    this.sock.removeListener('error', errFunc);
                    resolve();
                }
            })
        });
    }

    /** Wait and read authentication acknowledgement, should ONLY be called after a authentication has been sent
     *
     * @returns {Promise<void>} resolve if valid authAck is received, reject upon socket error, timeout or invalid authAck
     */
    public readAuthAck() {
        return new Promise((resolve, reject) => {
            let done = false;
            const errFunc = (err: Error): void => {
                if (!done) {
                    done = true;
                    reject(err);
                }
            };
            this.sock.once('error', errFunc);
            this.readCallback.push((): boolean => {
                if ( !done ) {
                    // simply quit and wait for more data if we don't have enough data
                    // the expected data: remote-ephemeral-pubk (64 bytes) || nonce (32 bytes) || 0x0 (1 byte)
                    // total: pubKey (65 bytes) || data (64+32+1) || iv (16 bytes) || tag (32 bytes)
                    // total = 210
                    if ( isNullOrUndefined(this.readBuf) || this.readBuf.length < 210) return;

                    done = true;

                    // Good, we got enough data
                    // 1. remove error listener
                    this.sock.removeListener('error', errFunc);
                    // 2. remove ourselves from readCallback
                    // we must be the top one, I can't think of how we are not
                    this.readCallback.shift();

                    let data: Buffer;
                    if ( this.readBuf.length > 210 ) {
                        data = this.readBuf.slice(0, 210);
                        this.readBuf = this.readBuf.slice(210);
                    } else {
                        // this.readBuf.length == 210
                        data = this.readBuf;
                        this.readBuf = null;
                    }

                    let decryptedData: Buffer;
                    try {
                        decryptedData = this.decryptMessage(data);
                        if ( decryptedData.length != 64+32+1 ) {
                            reject(new Error(`Decrypted authAck size is ${decryptedData.length}, expected to be 97 bytes`));
                            return;
                        }
                        this.remoteEphemeralKey = this.ec.keyFromPublic(Buffer.concat([
                            Buffer.from([0x04]),
                            decryptedData.slice(0, 64)
                        ]));
                    } catch (err) {
                        reject(err);
                        return;
                    }

                    this.remoteNonce = decryptedData.slice(64, 64+32);

                    this.setupKeys(this.authPacket, data);

                    resolve();
                }
            });
            setTimeout(() => {
                if ( !done ) {
                    done = true;
                    this.sock.removeListener('error', errFunc);
                    reject(new Error("socket read timeout"));
                }
            }, this.sockTimeout);
        });
    }

    private setupKeys(authPacket: Buffer, ackPacket: Buffer) : void {
        // ref to https://github.com/ethereum/devp2p/blob/master/rlpx.md
        // ephemeral-shared-secret = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
        // shared-secret = sha3(ephemeral-shared-secret || sha3(nonce || initiator-nonce))
        let ephemeralSharedSecret = this.localEphemeralKey.derive(this.remoteEphemeralKey.getPublic());
        let twoNonce = keccak256.create().update(this.remoteNonce).update(this.localNonce).digest();
        let sharedSecret = keccak256.create().update(ephemeralSharedSecret).update(twoNonce).digest();

        const IV = Buffer.alloc(16);

        //aes-secret = sha3(ephemeral-shared-secret || shared-secret)
        this.aesSecret = Buffer.from(keccak256.create().update(ephemeralSharedSecret).update(sharedSecret).digest());
        this.decipher = crypto.createDecipheriv('aes-256-ctr', this.aesSecret, IV);
        this.cipher = crypto.createCipheriv('aes-256-ctr', this.aesSecret, IV);

        // mac-secret = sha3(ephemeral-shared-secret || aes-secret)
        this.macSecret = Buffer.from(keccak256.create().update(ephemeralSharedSecret).update(this.aesSecret).digest());
        // ingress-mac = sha3.update(mac-secret ^ initiator-nonce || auth-recvd-ack)
        this.macIn = new Mac(this.macSecret, Buffer.concat([
            this.xor(this.macSecret, this.localNonce),
            ackPacket
        ]));
        // egress-mac = sha3.update(mac-secret ^ recipient-nonce || auth-sent-init)
        this.macOut = new Mac(this.macSecret, Buffer.concat([
            this.xor(this.macSecret, this.remoteNonce),
            authPacket
        ]));
    }

    /** this is the event handler for 'data' event
     * This function will/may "concat" multiple read packet(s) and pass it to readCallback
     * You NEVER need to use this function directly
     *
     * @param {Buffer} input
     */
    private readData(input: Buffer) {
        if ( isNullOrUndefined(this.readBuf) ) {
            this.readBuf = input;
        } else {
            // need to "concat" into one single buffer
            this.readBuf = Buffer.concat([this.readBuf, input]);
        }
        if ( this.readCallback.length > 0 ) {
            this.readCallback[0]();
        }
    }

    public send(data: Buffer) {
        return new Promise((resolve, reject) => {
            let done = false;
            const errFunc = (err: Error): void => {
                if ( !done ) {
                    done = true;
                    reject(err);
                }
            };
            this.sock.once('error', errFunc);
            this.sock.write(data, () => {
                if ( !done ) {
                    done = true;
                    this.sock.removeListener('error', errFunc);
                    resolve();
                }
            });
        });
    }

    /** send a frame to remote node
     * Note: we currently don't fragment frames (chunking), it's all-in-one frame, and therefore max data size is 0xFFFFFF
     * @param {Buffer} data
     * @returns {Promise<void>}
     */
    public sendFrame(data: Buffer) {
        assert.ok(data.length < 0xFFFFFF, `Frame size too big: ${data.length} > 0xFFFFFF`);

        let header = this.createFrameHeader(data.length);

        const n = data.length % 16;
        let paddedData : Buffer;
        if ( n == 0 ) {
            paddedData = data;
        } else {
            paddedData = Buffer.concat([data, Buffer.alloc(16-n)]);
        }
        const encData = this.cipher.update(paddedData);
        const dataMac = this.macOut.frameMac(encData);
        return this.send(Buffer.concat([header, encData, dataMac]));
    }

    /** create a frame header, including header mac
     *
     * @param {number} frameSize
     * @returns {Buffer}
     */
    public createFrameHeader(frameSize: number) : Buffer {
        // header: frame-size || header-data || padding
        //     frame-size: 3-byte integer size of frame, big endian encoded (excludes padding)
        // header-data:
        //     normal: rlp.list(protocol-type[, context-id])
        //     chunked-0: rlp.list(protocol-type, context-id, total-packet-size)
        //     chunked-n: rlp.list(protocol-type, context-id)
        // values:
        //     protocol-type: < 2**16
        //     context-id: < 2**16 (optional for normal frames)
        //     total-packet-size: < 2**32
        //     padding: zero-fill to 16-byte boundary
        ///////////////////////////////////////////////////
        // note, the max possible data for the header is [0xFFFF, 0xFFFF, 0xFFFFFFFF]
        // and the rlp encoded format is cb82ffff82ffff84ffffffff = 12 bytes
        // so total header is 3+12 = 15, and that means it always fit in 16 bytes and the last byte is always 0
        ///////////////////////////////////////////////////

        // part1 is frame-size
        let part1 = Buffer.allocUnsafe(4);
        part1.writeInt32BE(frameSize, 0);
        part1 = part1.slice(1);

        // part2 is header-data
        // protocol-type is set to 0, no context-id nor total-packet-size
        const part2 = rlp.encode([0]);

        const n = (part1.length + part2.length) % 16;
        let list = [part1, part2];
        if ( n != 0 ) list.push(Buffer.alloc(16-n));

        const header = Buffer.concat(list);
        const encHeader = this.cipher.update(header);
        const headerMac = this.macOut.headerMac(encHeader);
        return Buffer.concat([encHeader, headerMac]);
    }

    /** send initial authentication packet
     *
     * @param remotePubKey
     * @returns {Promise<any>} resolve if send auth packet send, reject upon socket error
     */
    public sendAuth(remotePubKey: any) {
        this.remotePubKey = remotePubKey;

        // signature = Sign(using ephemeral-privk: static-shared-secret ^ nonce)
        const secret = Buffer.from(this.key.derive(remotePubKey).toArray());
        const tobeSigned = this.xor(secret, this.localNonce);
        const signature = this.recoverableSign(this.localEphemeralKey, tobeSigned);

        // I don't know the meaning of the first parameter to encode(), but second parameter is compress
        // as for slice(1), the first byte is always '0x04', and is not included
        const hash = keccak256.create().update(this.localEphemeralKey.getPublic().encode(true, false).slice(1)).digest();

        // signature(32+32+1) || hash(32) || pubk(64) || nonce(32) || 0x0
        const msg = Buffer.concat([
            Buffer.from(signature.r.toArray()),
            Buffer.from(signature.s.toArray()),
            Buffer.from([signature.recoveryParam]),
            Buffer.from(hash),
            Buffer.from(this.key.getPublic().encode(true, false).slice(1)),
            this.localNonce,
            Buffer.from([0])
        ]);

        this.authPacket = this.encryptMessage(remotePubKey, msg);
        return this.send(this.authPacket);
    }

    public sendHello() {

    }

    /** key derived function
     *
     * @param {Buffer} input
     * @param {number} length
     * @returns {Buffer}
     */
    private kdf(input: Buffer, length: number) {
        const SHA256BlockSize = 64;
        const rounds = Math.ceil(length/SHA256BlockSize);

        const arr = [];
        const buf = new Buffer(4);
        for (let i=1; i<=rounds; i++) {
            buf.writeUInt32BE(i, 0);
            let hasher = crypto.createHash('sha256').update(buf);
            hasher.update(input);
            arr.push(hasher.digest());
        }

        return Buffer.concat(arr).slice(0, length);
    }

    private encryptMessage(remotePublicKey: any, data : Buffer, sharedMacData? : Buffer) {
        const msgKey = this.ec.genKeyPair();
        const secret = Buffer.from(msgKey.derive(remotePublicKey).toArray());
        const sharedKey = this.kdf(secret, 32);
        const ekey = sharedKey.slice(0, 16); // encryption key
        const mkey = crypto.createHash('sha256').update(sharedKey.slice(16, 32)).digest(); // MAC key

        // encrypt
        const IV = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-128-ctr', ekey, IV);
        const encryptedData = cipher.update(data);
        const dataIV = Buffer.concat([ IV, encryptedData ]);

        // create tag
        if (!sharedMacData) {
            sharedMacData = Buffer.from([]);
        }
        const tag = crypto.createHmac('sha256', mkey).update(Buffer.concat([dataIV, sharedMacData])).digest();

        const msgPublic = Buffer.from(msgKey.getPublic().encode(true, false));
        return Buffer.concat([ msgPublic, dataIV, tag ]);
    }

    private decryptMessage(data: Buffer, sharedMacData? : Buffer) {
        /*util.assertEq(data.slice(0, 1), Buffer.from('04', 'hex'), 'wrong ecies header (possible cause: EIP8 upgrade)')*/

        const msgPublic = this.ec.keyFromPublic(data.slice(0, 65)).getPublic();
        const dataIV = data.slice(65, -32);
        const hash = data.slice(-32);

        // derive keys
        const secret = Buffer.from(this.key.derive(msgPublic).toArray());
        const sharedKey = this.kdf(secret, 32);
        const ekey = sharedKey.slice(0, 16); // encryption key
        const mkey = crypto.createHash('sha256').update(sharedKey.slice(16, 32)).digest(); // MAC key

        // check the tag
        if (!sharedMacData) {
            sharedMacData = Buffer.from([])
        }
        const calculatedHash = crypto.createHmac('sha256', mkey).update(Buffer.concat([dataIV, sharedMacData])).digest();
        if ( calculatedHash.compare(hash) != 0 ) throw new Error(`Incorrect packet hash:${hash.toString('hex')} != calculated:${calculatedHash.toString('hex')}`);

        // decrypt data
        const IV = dataIV.slice(0, 16);
        const encryptedData = dataIV.slice(16);
        const decipher = crypto.createDecipheriv('aes-128-ctr', ekey, IV);
        return decipher.update(encryptedData);
    }

    private xor(input1: Buffer, input2: Buffer) {
        assert.equal(input1.length, input2.length, `XOR input size doesn't match: ${input1.length} != ${input2.length}`);

        const output = new Buffer(input1.length);
        for(let i=0; i<input1.length; i++) {
            output[i] = input1[i] ^ input2[i];
        }
        return output;
    }

    private recoverableSign(key: any, data: Buffer) {
        const hasher = keccak256.create().update(data);
        return key.sign(hasher.digest(), { canonical: 1 });
    }
}