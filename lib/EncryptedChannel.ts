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
import {EventEmitter} from "events";
import {pubk2id} from "./Util";

/** A frame header, for internal use only
 * <pre>
 * header: frame-size || header-data || padding
 *     frame-size: 3-byte integer size of frame, big endian encoded (excludes padding)
 * header-data:
 *     normal: rlp.list(protocol-type[, context-id])
 *     chunked-0: rlp.list(protocol-type, context-id, total-packet-size)
 *     chunked-n: rlp.list(protocol-type, context-id)
 * values:
 *     protocol-type: < 2**16
 *     context-id: < 2**16 (optional for normal frames)
 *     total-packet-size: < 2**32
 *     padding: zero-fill to 16-byte boundary
 * </pre>
 */
class FrameHeader {
    constructor(public frameSize: number, public protocolType=0, public contextId=0, public totalPacketSize=0) { }

    public toBufferWithPadding() : Buffer {
        // part1 is frame-size
        let part1 = Buffer.allocUnsafe(3);
        part1.writeUInt8((this.frameSize >> 16) & 0xFF, 0);
        part1.writeUInt8((this.frameSize >> 8) & 0xFF, 1);
        part1.writeUInt8(this.frameSize & 0xFF, 2);

        // part2 is header-data
        let array = [this.protocolType];
        if ( this.contextId > 0 ) {
            array.push(this.contextId);
            if ( this.totalPacketSize > 0 ) {
                array.push(this.totalPacketSize);
            }
        }
        let part2 = rlp.encode(array);

        const n = (part1.length + part2.length) % 16;
        let list = [part1, part2];
        if ( n != 0 ) list.push(Buffer.alloc(16-n));

        return Buffer.concat(list);
    }

    /** parse input buffer into a frame header
     *
     * @param {Buffer} buffer expect length=16
     */
    static parse(input: Buffer) {
        assert.equal(input.length, 16, `Frame header length is not 16, length=${input.length}`);
        assert.equal(input[15], 0, `Frame last padding is not 0, value=${input[15]}`);

        const size = (input.readUInt8(0) << 16) + (input.readUInt8(1) << 8) + input.readUInt8(2);
        const payload = rlp.decode(input.slice(3), true);
        const count = payload.data.length;
        assert.ok(count > 0, 'Invalid frame header, expect at least the protocol-type but contains no data');
        assert.ok(count <= 3, `Invalid frame header, expect at most 3 items but there are ${count} elements`);
        const pType = payload[0];
        const id = (count > 1) ? payload.data[1] : 0;
        const total = (count > 2) ? payload.data[2] : 0;
        return new FrameHeader(size, pType, id, total);
    }
}

export class EncryptedChannel extends EventEmitter {
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

    private authInitPacket: Buffer; // we need this to setup macIn

    private remotePubKey: any;

    private sock: net.Socket;
    private sockTimeout = 10000;

    /** we may need to "concat" multiple chunk into one single Buffer until it is long enough so that the handler is able to process it */
    private readBuf : Buffer;
    private isReadingFrames = false; // authInit and authReceipt are not framed, after that, all messages are framed
    private frameHeader: FrameHeader; // the received frame header

    constructor(private key: any) {
        super();
        this.localEphemeralKey = this.ec.genKeyPair();
        this.localNonce = crypto.randomBytes(32);

        this.sock = new net.Socket({allowHalfOpen: true});
        let self = this;
        this.sock.on('data', (data: Buffer): void => {
            try {
                self.onData(data);
            } catch (err) {
                console.log("haha: " + err);
                self.emit('error', err);
            }
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

    /** Wait and read authentication receipt, should ONLY be called after a authentication has been sent
     *
     * @returns {Promise<void>} resolve if valid authReceipt is received, reject upon socket error, timeout or invalid authAck
     */
    public readAuthReceipt() {
        return new Promise((resolve, reject) => {
            let done = false;
            const errFunc = (err: Error): void => {
                if (!done) {
                    done = true;
                    reject(err);
                }
            };
            this.sock.once('error', errFunc);
            this.once('authReceipt', (err) => {
                if ( !done ) {
                    done = true;
                    this.sock.removeListener('error', errFunc);
                    if ( err ) reject(err);
                    else resolve();
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

    private setupKeys(authInitPacket: Buffer, authReceiptPacket: Buffer) : void {
        // ref to https://github.com/ethereum/devp2p/blob/master/rlpx.md
        // ephemeral-shared-secret = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
        // shared-secret = sha3(ephemeral-shared-secret || sha3(nonce || initiator-nonce))
        let ephemeralSharedSecret = this.localEphemeralKey.derive(this.remoteEphemeralKey.getPublic()).toArray();
        let twoNonce = keccak256.create().update(this.remoteNonce).update(this.localNonce).digest();
        let sharedSecret = keccak256.create().update(ephemeralSharedSecret).update(twoNonce).digest();

        const IV = Buffer.alloc(16);

        //aes-secret = sha3(ephemeral-shared-secret || shared-secret)
        this.aesSecret = Buffer.from(keccak256.create().update(ephemeralSharedSecret).update(sharedSecret).digest());
        console.log(`setupKeys.aesSecret: ${this.aesSecret.toString('hex')}`)
        this.decipher = crypto.createDecipheriv('aes-256-ctr', this.aesSecret, IV);
        this.cipher = crypto.createCipheriv('aes-256-ctr', this.aesSecret, IV);

        // mac-secret = sha3(ephemeral-shared-secret || aes-secret)
        this.macSecret = Buffer.from(keccak256.create().update(ephemeralSharedSecret).update(this.aesSecret).digest());
        console.log(`setupKeys.macSecret: ${this.macSecret.toString('hex')}`);
        // ingress-mac = sha3.update(mac-secret ^ initiator-nonce || auth-recvd-ack)
        this.macIn = new Mac(this.macSecret, Buffer.concat([
            this.xor(this.macSecret, this.localNonce),
            authReceiptPacket
        ]));
        // egress-mac = sha3.update(mac-secret ^ recipient-nonce || auth-sent-init)
        this.macOut = new Mac(this.macSecret, Buffer.concat([
            this.xor(this.macSecret, this.remoteNonce),
            authInitPacket
        ]));
    }

    /** this is the event handler for 'data' event
     *
     * If isReadingFrames is false
     *   - we are expecting an authReceipt
     *   - we will call parseAndEmitAuthReceipt() and it will emit('authReceipt')
     * If isReadingFrames is true
     *   - we are expecting a regular message
     *   - we will decrypt the data and emit(messageId)
     *
     */
    private onData(input: Buffer) {
        console.log("hello1");
        if ( isNullOrUndefined(this.readBuf) ) {
            this.readBuf = input;
        } else {
            // need to "concat" into one single buffer
            this.readBuf = Buffer.concat([this.readBuf, input]);
        }

        if ( !this.isReadingFrames ) {
            if ( this.parseAndEmitAuthReceipt() ) {
                this.isReadingFrames = true;
            }
        } else {
            if ( isNullOrUndefined(this.frameHeader) ) {
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
                // mac is 16 bytes
                if (this.readBuf.length >= 16 + 16) {
                    const encHeader = this.readBuf.slice(0, 16);
                    const mac = this.readBuf.slice(16, 32);
                    this.readBuf = (this.readBuf.length == 32) ? null : this.readBuf.slice(32);
                    const calculatedMac = this.macIn.headerMac(encHeader);
                    assert.ok(0 == calculatedMac.compare(mac), `Incorrect frame header mac, ${mac.toString('hex')} != ${calculatedMac.toString('hex')}`);
                    const plainHeader = this.decipher.update(encHeader);
                    console.log(`plainHeader: ${plainHeader.toString('hex')}`);
                    this.frameHeader = FrameHeader.parse(plainHeader);
                } else {
                    // wait for more data
                    return;
                }
            }

            if ( !isNullOrUndefined(this.frameHeader) ) {
                // we already have the frame header
                let size = this.frameHeader.frameSize;
                if ( size % 16 ) size += 16  - (size % 16);
                size += 16; // extra 16 bytes for mac
                if ( !isNullOrUndefined(this.readBuf) && this.readBuf.length >= size ) {
                    // ok, we have the whole packet
                    const encBody = this.readBuf.slice(0, size-16);
                    const mac = this.readBuf.slice(size-16, size);
                    this.readBuf = (this.readBuf.length == size) ? null : this.readBuf.slice(size);
                    const calculatedMac = this.macIn.frameMac(encBody);
                    assert.ok(0 == calculatedMac.compare(mac), `Incorrect frame body mac, ${mac.toString('hex')} != ${calculatedMac.toString('hex')}`);
                    const body = this.decipher.update(encBody).slice(0, this.frameHeader.frameSize);

                    let b = body[0];
                    let packetType = 0;
                    let offset = 1;
                    if ( b >= 0 && b < 0x7F ) {
                        packetType = b;
                    } else if ( b >= 0x80 && b <= 0x82 ) {
                        for(let i=0; i<b-0x80; i++) {
                            packetType = (packetType<<8) + body[1+i];
                            offset++;
                        }
                    } else {
                        throw new Error(`Invalid frame packet-type rlp prefix: ${body[0]}`);
                    }
                    this.emit(`msgid:${packetType}`, body.slice(offset));
                } else {
                    // not enough data
                    return;
                }
            }
        }
    }

    private parseAndEmitAuthReceipt(): boolean {
        // simply quit and wait for more data if we don't have enough data
        // the expected data: remote-ephemeral-pubk (64 bytes) || nonce (32 bytes) || 0x0 (1 byte)
        // total: pubKey (65 bytes) || data (64+32+1) || iv (16 bytes) || tag (32 bytes)
        // total = 210
        if ( isNullOrUndefined(this.readBuf) || this.readBuf.length < 210) return false;

        let data: Buffer;
        if ( this.readBuf.length > 210 ) {
            data = this.readBuf.slice(0, 210);
            this.readBuf = this.readBuf.slice(210);
        } else {
            // this.readBuf.length == 210
            data = this.readBuf;
            this.readBuf = null;
        }

        let decryptedData = this.decryptAuthReceipt(data);
        if ( decryptedData.length != 64+32+1 ) {
            this.emit('authReceipt', new Error(`Decrypted authAck size is ${decryptedData.length}, expected to be 97 bytes`));
            return true; // true/false doesn't matter in here, we probably will disconnect
        }
        this.remoteEphemeralKey = this.ec.keyFromPublic(Buffer.concat([
            Buffer.from([0x04]),
            decryptedData.slice(0, 64)
        ]));
        console.log(`parseAndEmitAuthReceipt.remoteEphemeralKey ${decryptedData.slice(0, 64).toString('hex')}`);

        this.remoteNonce = decryptedData.slice(64, 64+32);
        console.log(`parseAndEmitAuthReceipt.remoteNonce ${this.remoteNonce.toString('hex')}`);
        this.setupKeys(this.authInitPacket, data);
        this.emit('authReceipt');
        return true;
    }

    private sendRaw(data: Buffer) {
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
     * @param {number} msgId 0x00 for Hello, 0x01 for Disconnect, not included as part of data
     * @param {Buffer} msgBody encoded message body
     * @returns {Promise<void>}
     */
    public sendFrame(msgId: number, msgBody: Buffer) {
        let data = Buffer.concat([Buffer.from[msgId], msgBody]);

        assert.ok(data.length < 0xFFFFFF, `Frame size too big: ${data.length} > 0xFFFFFF`);

        const headerBuf = new FrameHeader(data.length).toBufferWithPadding();
        const encHeader = this.cipher.update(headerBuf);
        const headerMac = this.macOut.headerMac(encHeader);
        const header = Buffer.concat([encHeader, headerMac]);

        const n = data.length % 16;
        let paddedData : Buffer;
        if ( n == 0 ) {
            paddedData = data;
        } else {
            paddedData = Buffer.concat([data, Buffer.alloc(16-n)]);
        }
        const encData = this.cipher.update(paddedData);
        const dataMac = this.macOut.frameMac(encData);
        return this.sendRaw(Buffer.concat([header, encData, dataMac]));
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
        console.log(`secret: ${secret.toString('hex')}`);
        const tobeSigned = this.xor(secret, this.localNonce);
        console.log(`tobeSigned: ${tobeSigned.toString('hex')}`);
        console.log(`localEphemeralKey: ${this.localEphemeralKey.toString('hex')}`);
        const signature = this.recoverableSign(this.localEphemeralKey, tobeSigned);
        const xyz = Buffer.concat([
            Buffer.from(signature.r.toArray()),
            Buffer.from(signature.s.toArray()),
            Buffer.from([signature.recoveryParam])
        ])
        console.log(`signature: ${xyz.toString('hex')}`);

        const hash = keccak256.create().update(pubk2id(this.localEphemeralKey.getPublic())).digest();
        console.log(`hash: ${hash}`);

        // signature(32+32+1) || hash(32) || pubk(64) || nonce(32) || 0x0
        const msg = Buffer.concat([
            Buffer.from(signature.r.toArray()),
            Buffer.from(signature.s.toArray()),
            Buffer.from([signature.recoveryParam]),
            Buffer.from(hash),
            pubk2id(this.key.getPublic()),
            this.localNonce,
            Buffer.from([0])
        ]);
        console.log(`msg: ${msg.toString('hex')}`)

        this.authInitPacket = this.encryptAuthInit(remotePubKey, msg);
        return this.sendRaw(this.authInitPacket);
    }

    public sendHello() {
        const msgBody = [
            4, // <-- no idea what this mean
            "ethereum-ts/1.0.0",
            [
                {name: "eth", version: 62 }
            ],
            30303,
            pubk2id(this.key.getPublic())
        ];
        return this.sendFrame(0x00, rlp.encode(msgBody));
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
        const buf = Buffer.alloc(4);
        for (let i=1; i<=rounds; i++) {
            buf.writeUInt32BE(i, 0);
            let hasher = crypto.createHash('sha256').update(buf);
            hasher.update(input);
            arr.push(hasher.digest());
        }

        return Buffer.concat(arr).slice(0, length);
    }

    private encryptAuthInit(remotePublicKey: any, data : Buffer, sharedMacData? : Buffer) {
        // const msgKey = this.ec.keyFromPrivate('c7cbbcbdc43d7a85e989cb11ec7a3341607b3aceecfcc2c61b73ab4bf7097317'); // this.ec.genKeyPair();
        const msgKey = this.ec.genKeyPair();
        const secret = Buffer.from(msgKey.derive(remotePublicKey).toArray());
        console.log(`encryptAuthInit.secret: ${secret.toString('hex')}`);
        const sharedKey = this.kdf(secret, 32);
        console.log(`encryptAuthInit.sharedKey: ${sharedKey.toString('hex')}`)
        const ekey = sharedKey.slice(0, 16); // encryption key
        console.log(`encryptAuthInit.ekey: ${ekey.toString('hex')}`);
        const mkey = crypto.createHash('sha256').update(sharedKey.slice(16, 32)).digest(); // MAC key
        console.log(`encryptAuthInit.mkey: ${mkey.toString('hex')}`);

        // encrypt
        // const IV = Buffer.from('e304c0adc7f633da5a91bd133faff0bc', 'hex'); // crypto.randomBytes(16);
        const IV = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-128-ctr', ekey, IV);
        const encryptedData = cipher.update(data);
        console.log(`encryptAuthInit.encryptedData: ${encryptedData.toString('hex')}`);
        const dataIV = Buffer.concat([ IV, encryptedData ]);
        console.log(`encryptAuthInit.dataIV: ${dataIV.toString('hex')}`);

        // create tag
        if (!sharedMacData) {
            sharedMacData = Buffer.from([]);
        }
        const tag = crypto.createHmac('sha256', mkey).update(Buffer.concat([dataIV, sharedMacData])).digest();
        console.log(`encryptAuthInit.tag: ${tag.toString('hex')}`);

        const msgPublic = Buffer.from(msgKey.getPublic().encode(true, false));
        const output = Buffer.concat([ msgPublic, dataIV, tag ]);
        console.log(`encryptAuthInit.output: ${output.toString('hex')}`);
        return output;
    }

    private decryptAuthReceipt(data: Buffer, sharedMacData? : Buffer) {
        // the expected data: remote-ephemeral-pubk (64 bytes) || nonce (32 bytes) || 0x0 (1 byte)
        // total: pubKey (65 bytes) || data (64+32+1) || iv (16 bytes) || tag (32 bytes)

        const msgPublic = this.ec.keyFromPublic(data.slice(0, 65)).getPublic();
        const dataIV = data.slice(65, -32);
        const tag = data.slice(-32);

        // derive keys
        const secret = Buffer.from(this.key.derive(msgPublic).toArray());
        const sharedKey = this.kdf(secret, 32);
        const ekey = sharedKey.slice(0, 16); // encryption key
        const mkey = crypto.createHash('sha256').update(sharedKey.slice(16, 32)).digest(); // MAC key

        // check the tag
        if (!sharedMacData) {
            sharedMacData = Buffer.from([])
        }
        const calculatedTag = crypto.createHmac('sha256', mkey).update(Buffer.concat([dataIV, sharedMacData])).digest();
        if ( calculatedTag.compare(tag) != 0 ) throw new Error(`Incorrect packet tag:${tag.toString('hex')} != calculated:${calculatedTag.toString('hex')}`);

        // decrypt data
        const IV = dataIV.slice(0, 16);
        const encryptedData = dataIV.slice(16);
        const decipher = crypto.createDecipheriv('aes-128-ctr', ekey, IV);
        return decipher.update(encryptedData);
    }

    private xor(input1: Buffer, input2: Buffer) {
        assert.equal(input1.length, input2.length, `XOR input size doesn't match: ${input1.length} != ${input2.length}`);

        const output = Buffer.alloc(input1.length);
        for(let i=0; i<input1.length; i++) {
            output[i] = input1[i] ^ input2[i];
        }
        return output;
    }

    private recoverableSign(key: any, data: Buffer) {
        //const hasher = keccak256.create().update(data);
        return key.sign(data, { canonical: 1 });
    }
}