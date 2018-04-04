import * as elliptic from 'elliptic';
import * as winston from 'winston';
import * as dgram from "dgram";
import * as ip from "ip";
import * as rlp from 'rlp';
import { keccak256 } from 'js-sha3';
import {AddressInfo} from "dgram";
import {EventEmitter} from "events";
import {isNullOrUndefined} from "util";
import {Endpoint} from "./Endpoint";
import {Node} from "./Node";
import {BucketManger} from "./BucketManger";

// internal use only
interface PingRegistryObject {
    /** the keccak256 hash of the ping packet */
    packetHash: string;
    /** timestamp in second */
    timestamp: number;
    /** the remote node */
    remote: Node;
    eventEmitter: EventEmitter;
}

export class NodeDiscovery {
    private bucketManager : BucketManger;
    private started = false;
    private node: Node = Node.fromIpAndPort("127.0.0.1", 30303); // this node
    private key: elliptic.KeyPair;
    private ec = new elliptic.ec('secp256k1');
    private server = dgram.createSocket('udp4');

    /**
     * When we PING, we will put the hash into this map.
     * And when when we receive the PONG, we will check if the PingRegistryObject exists, the expiry time, source IP, and public key if exist
     */
    private pingRegistry = new Map<string, PingRegistryObject>();

    /** expiry time, used for timestamp in almost all data structures, unit in second */
    public expiryTime = 5;

    public log = winston.loggers.get('devp2p');

    constructor() {
        this.bucketManager = new BucketManger(this.node, this);

        this.server.on('error', (err) => {
            this.log.error('Network error', err);
        });

        this.server.on('message', (msg: Buffer, rinfo: AddressInfo) => {
            this.onMessage(msg, rinfo);
        });

        this.server.on('listening', () => {
            const a = this.server.address();
            this.log.info('Server started', {address: a.address, port: a.port});
        });

        this.server.on('close', () => {
            const a = this.server.address();
            this.log.info('Server stopped', {address: a.address, port: a.port});
        });
    }

    public get endpoint() {
        return new Endpoint(this.node.endpoint.ip, this.node.endpoint.udp, this.node.endpoint.tcp);
    }

    public set endpoint(value: Endpoint) {
        if ( this.started ) throw new Error("Can't change end point after the network has started, please call stop() first");
        this.node.endpoint = new Endpoint(value.ip, value.udp, value.tcp);
    }

    /** get the public key of this PeerNetwork
     *
     * @returns {any}
     */
    public get publicKey() {
        return this.key.getPublic();
    }

    /** set the private key of this PeerNetwork
     * The public key will be calculated based on the private key
     * @param {string} value
     */
    public set privateKey(value: string) {
        if ( this.started ) throw new Error("Can't change encryption key after PeerNetwork has started, please call stop() first");
        this.key = this.ec.keyFromPrivate(value);

        // setup node Id as well
        // I don't know the meaning of the first parameter to encode(), but second parameter is compress
        // as for slice(1), the first byte is always '0x04', and is not included in nodeId
        this.node.nodeId = this.key.getPublic().encode(true, false).slice(1)
    }

    /** you shouldn't call this one, use start(string[]) instead
     *
     * @returns {Promise<any>}
     */
    public startInternal() {
        if ( this.started ) return;

        return new Promise((resolve) => {
            this.server.bind(this.node.endpoint.udp, () => {
                this.started = true;
                resolve();
            })
        });
    }

    public start(initPeers: string[]) {
        this.bucketManager.start(initPeers);
    }

    public stop(callback: Function) {
        if ( !this.started ) return;

        this.server.close(() => {
            this.started = false;
            callback();
        });
    }

    public now() : number {
        return Math.floor(new Date().getTime()/1000);
    }

    public onMessage(msg: Buffer, rinfo: AddressInfo) {
        this.log.silly("UDP packet received", rinfo);

        // hash (32-byte) || signature (65-byte) || packet-type (1-byte) || packet-data (variable length)
        if ( msg.length < 32+65+1+1 ) {
            this.log.debug("Dropping packet due to invalid size", rinfo);
            return;
        }

        // verify the hash
        let hasher = keccak256.create().update(msg.slice(32));
        if ( 0 != msg.compare(Buffer.from(hasher.digest()), 0,32, 0, 32) ) {
            this.log.debug("Dropping packet due to invalid hash", {calculated: hasher.hex(), received: msg.slice(0, 32).toString('hex')});
            return;
        }

        // verify the signature
        let sigHasher = keccak256.create().update(msg.slice(32+65));
        let signature = {r: msg.slice(32, 64), s: msg.slice(64, 32+64), recoveryParam: msg[32+64]};
        let remoteId: number[];
        try {
            // the return from recoverPubKey is a complex object
            let pubKey = this.ec.recoverPubKey(sigHasher.digest(), signature, signature.recoveryParam);
            if ( !this.ec.verify(sigHasher.digest(), signature, pubKey) ) {
                this.log.debug("Dropping packet to due signature verification failed", signature);
                return;
            }
            // the return from recoverPubKey is a complex object
            // I don't know the meaning of the first parameter to encode(), but second parameter is compress
            // as for slice(1), the first byte is always '0x04', and is not included in nodeId
            remoteId = pubKey.encode(true, false).slice(1);
        } catch (err) {
            this.log.debug("Dropping packet to due invalid signature", err);
            return;
        }

        // decode the packet
        let packetType = msg[32+65];
        let decoded: any;
        try {
            decoded = rlp.decode(msg.slice(32 + 65 + 1));
        } catch (err) {
            this.log.debug("Dropping packet to due RLP encoding error", err);
            return;
        }

        try {
            if (packetType === 0x01) {
                // Ping packet
                this.handlePingReceived(rinfo, remoteId, hasher.digest(), decoded);
            } else if (packetType === 0x02) {
                // Pong packet
                this.handlePongReceived(rinfo, remoteId, decoded);
            } else if (packetType === 0x03) {
                // FindNeighbours
                this.log.info("FindNeighbours packet received");
            } else if (packetType === 0x04) {
                // Neighbors
                this.log.info("Neighbors packet received");
            } else {
                this.log.info("Unknown packet type: " + packetType);
            }
        } catch (err) {
            this.log.debug("Error processing UDP packet", err);
        }
    }

    /** ping and pong in one call
     *
     * @param {Node} remote
     * @param {number} retry default value is 2, meaning total try 3 times
     * @returns {Promise<{rinfo: AddressInfo, pubKey: Buffer>} a promise that resolve if both ping and pong are successful, reject otherwise.
     */
    public pingPong(remote: Node, retry = 2) {
        let eventEmitter = new EventEmitter();
        return this.ping(remote, eventEmitter).then((pingPacketHash: Buffer) => {
            // at this point, ping packet send() is successful, now we need to handle pong
            // if the system receives a PONG packet, it will emit an event with the hash of the PING packet as the key
            // so if it receives the event, it's fulfilled
            // if nothing happens within [time] seconds, it's rejected
            return new Promise((resolve, reject) => {
                let done = false;
                let h = pingPacketHash.slice(0, 32).toString('hex')
                eventEmitter.once(h, (rinfo: AddressInfo, remoteId: number[]) => {
                    if (!done ) {
                        done = true;
                        resolve({rinfo: rinfo, remoteId: remoteId});
                    }
                });
                setTimeout(() => {
                    if ( !done ) {
                        done = true;
                        delete this.pingRegistry[h];
                        reject(new Error("Connection timeout"));
                    }
                }, this.expiryTime*1000);
            });
        }).catch((error) => {
            if ( retry > 0 ) {
                return this.pingPong(remote, retry-1);
            } else {
                return Promise.reject(error);
            }
        })
    }

    /** send a PING request to a remote node
     * The function will register the relevant data to the PingRegistry so that when we receive a PONG, we will be able to correlate the two
     * @param {Node} remote
     * @param {"events".internal.EventEmitter} eventEmitter can be null
     * @returns {Promise<Buffer>} promise full packet as a buffer
     */
    public ping(remote: Node, eventEmitter: EventEmitter) {
        let record = [
            0x03, // this is version number
            [this.node.endpoint.ipAsBuffer, this.node.endpoint.udp, this.node.endpoint.tcp],
            [remote.endpoint.ipAsBuffer, remote.endpoint.udp, remote.endpoint.tcp],
            // "+expiryTime" because peers will ignore the ping request if timestamp is from the past
            this.now() + this.expiryTime
            //0x5ab09d9c
        ];

        let data = rlp.encode(record);
        this.log.debug("PING-ing remote peer", remote);

        // ping packet type is 0x01
        return this.send(remote.endpoint, 0x01, data, (packet: Buffer) => {
            let item = {
                packetHash: packet.slice(0, 32).toString('hex'),
                timestamp: this.now() + 2 * this.expiryTime,
                remote: remote,
                eventEmitter: eventEmitter
            };
            this.pingRegistry[item.packetHash] = item;
        });
    }

    /** handle a PING request (another node PING us)
     *
     * @param {"dgram".AddressInfo} rinfo
     * @param {AddressInfo} rinfo the remote node to ping
     * @param {number[]} remoteId the remote nodeId
     * @param {number[]} hash the hash or the received packet, we need this in the PONG reply
     * @param {Array<any>} data expected to be the output from rlp.decode(packet_data)
     */
    public handlePingReceived(rinfo: AddressInfo, remoteId: number[], hash: number[], data: Array<any>) {
        let version = (data[0].readUInt8(0));
        let remoteEndpoint = this.toEndPoint(data[1] as Array<Buffer>);
        let myEndpoint = this.toEndPoint(data[2] as Array<Buffer>);
        let timestamp = data[3].readUInt32BE(0);

        // https://github.com/ethereum/devp2p/blob/master/rlpx.md said it should be 3
        // Geth PING version is 4
        // we need to support both
        if ( version !== 0x03 && version !== 0x04 ) {
            this.log.debug("Don't know how to reply this PING request", {version: version});
            return;
        }

        let now = Math.floor(new Date().getTime()/1000);
        if (  now > timestamp ) {
            this.log.debug("Ignore PING request due to invalid timestamp", {packet_time: timestamp});
        }

        this.log.debug("PING data received", {remote: rinfo, local: myEndpoint, hash: Buffer.from(hash).toString('hex'), timestamp: timestamp});

        // auto reply with a PONG
        // note: we reply with rinfo, not peerEndpoint beacuse it might be behind NAT
        this.pong(new Endpoint(rinfo.address, rinfo.port, remoteEndpoint.tcp), hash);
    }

    /** send a PONG request back to the remote node
     *
     * @param {Endpoint} remote node to pong
     * @param {number[]} lastPingHash the hash of the received PING packet
     * @returns {Promise<Buffer>}
     */
    public pong(remote: Endpoint, lastPingHash: number[]) {
        let record = [
            [remote.ipAsBuffer, remote.udp, remote.tcp],
            lastPingHash,
            // "+expiryTime" because peers will ignore the ping request if timestamp is from the past
            this.now() + this.expiryTime
        ];

        let data = rlp.encode(record);
        this.log.debug("PONG-ing remote peer", remote);

        // ping packet type is 0x01
        return this.send(remote, 0x02, data);
    }

    /** handle the received PONG request
     *
     * @param {"dgram".AddressInfo} rinfo
     * @param {number[]} remoteId the recovered sender public key, total 64 bytes long, w/o leading '0x04'
     * @param {Array<any>} packetData expected to be the output from rlp.decode(packet_data)
     */
    public handlePongReceived(rinfo: AddressInfo, remoteId: number[], packetData: Array<any>) : void {
        let endpoint = this.toEndPoint(packetData[0] as Array<Buffer>); // this is my address:port seen by the peer
        let hash = packetData[1] as Buffer;
        let timestamp = (packetData[2] as Buffer).readUInt32BE(0);

        let pingHash = hash.toString('hex');
        if ( !(pingHash in this.pingRegistry) ) {
            this.log.debug("Dropping unsolicited PONG packet", rinfo);
            return;
        }

        let registry = this.pingRegistry[pingHash];
        // "+expiryTime" as suggested by Ethereum protocol, see https://github.com/ethereum/devp2p/blob/master/rlpx.md section "Node Discovery"
        if ( (registry.timestamp+this.expiryTime < this.now())
            || (!registry.remote.nodeId && registry.remote.endpoint.ip != rinfo.address) // we check ip only if we don't have the public key (nodeId)
            || (registry.remote.nodeId && registry.remote.nodeId != remoteId) ) {

            if ( registry.timestamp+this.expiryTime < this.now() ) {
                this.log.debug("Dropping expired PONG packet: " + new Date(registry.timestamp*1000));
            } else if ( !registry.remote.nodeId && registry.remote.endpoint.ip != rinfo.address ) {
                this.log.debug("Dropping PONG packet from unexpected IP", {expected: registry.remote.endpoint.ip, actual: rinfo.address});
            } else {
                this.log.debug("Dropping PONG packet with another nodeId", {expected: registry.remote.nodeId, actual: remoteId});
            }
            // if we don't clear all listener, we may have memory leak
            if ( !isNullOrUndefined(registry.eventEmitter) ) registry.eventEmitter.removeAllListeners();
            delete this.pingRegistry[pingHash];
            return;
        }

        this.log.debug("PONG data received", {remote: rinfo, local: endpoint, hash: hash.toString('hex'), timestamp: timestamp});

        if ( !isNullOrUndefined(registry.eventEmitter) ) {
            registry.eventEmitter.emit(pingHash, rinfo, remoteId);
            registry.eventEmitter.removeAllListeners();
        }
        delete this.pingRegistry[pingHash];
    }

    public toEndPoint(data: Array<Buffer>) {
        return { address: ip.toString(data[0]), udp: this.toPort(data[1]), tcp: this.toPort(data[2]) };
    }

    /** convert a buffer into a port number
     * Why we do this? Because the port can be 2 bytes (e.g. 30303 = 0x765f), 1 byte (e.g. 80), or can be empty!!
     * Empty is seen from Geth PING request, when Geth PING me, maybe because my TCP port is not sure yet, it is left empty
     * @param {Buffer} data
     * @returns {number} the converted port number, it can be 0
     */
    public toPort(data: Buffer) : number {
        let len = data.length;
        if ( len > 2 ) throw new Error("Invalid port number: " + data.toString('hex'));
        let p = 0;
        for(let i=0; i<len; i++) {
            p += p*256 + data[i];
        }
        return p;
    }

    /**
     *
     * @param {Endpoint} remote
     * @param {number} packetType
     * @param {Buffer} packetData
     * @param {(b: Buffer) => void} beforeSend
     * @returns {Promise<Buffer>} the packet packed in Promise<Buffer>
     */
    public send(remote: Endpoint, packetType: number, packetData: Buffer, beforeSend?: (b: Buffer) => void ) : Promise<Buffer> {
        // first 32-byte are for the packet.hash, next 65-byte are for signature (32+32+1), the last "1" is for packetType
        // hash (32-byte) || signature (65-byte) || packet-type (1-byte) || packet-data (variable length)
        let packet = new Buffer(packetData.length + 32 + 65 + 1);

        packet.set([packetType], 32+65);
        packet.set(packetData, 32+65+1);

        let signature = this.recoverableSign(packet.slice(32+65));
        packet.set(signature.r.toArray(), 32);
        packet.set(signature.s.toArray(), 32+32);
        packet.set([signature.recoveryParam], 32+64);

        let hasher = keccak256.create().update(packet.slice(32));
        packet.set(hasher.digest());

        if ( null != beforeSend ) beforeSend(packet);

        this.log.silly("send data: " + packet.toString('hex'));

        return new Promise((resolve, reject) => {
            this.server.send(packet, remote.udp, remote.ip, (err) => {
                if (err) reject(err);
                else resolve(packet);
            });
        });
    }

    private recoverableSign(data: Buffer) {
        let hasher = keccak256.create().update(data);
        // canonical:1 is critical in here
        return this.key.sign(hasher.digest(), { canonical: 1 });
    }
}