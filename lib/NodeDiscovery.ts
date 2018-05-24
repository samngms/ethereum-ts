import * as elliptic from 'elliptic';
import * as log4js from '@log4js-node/log4js-api';
import * as ip from "ip";
import * as rlp from 'rlp';
import { keccak256 } from 'js-sha3';
import * as dgram from 'dgram';
import {AddressInfo, Socket} from 'dgram';
import {EventEmitter} from "events";
import {Endpoint} from "./Endpoint";
import {Node} from "./Node";
import {pubk2id} from "./Util";
import * as _ from 'lodash';

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

/** The Node Discovery UDP protocol
 * The class handles the message encryption/decryption, encode/decode, send/receive, etc...
 * The class is designed to be used by BucketManager
 * @see BucketManager
 */
export class NodeDiscovery extends EventEmitter {
    private ec = new elliptic.ec('secp256k1');
    private started = false;
    /**
     * When we PING, we will put the hash into this map.
     * And when when we receive the PONG, we will check if the PingRegistryObject exists, the expiry time, source IP, and public key if exist
     */
    private pingRegistry = new Map<string, PingRegistryObject>();

    /** expiry time, used for timestamp in almost all data structures, unit in second */
    public expiryTime = 5;

    public log = log4js.getLogger('devp2p.NodeDiscovery');

    /**
     *
     * @param {Node} node endpoint, id, of this node
     * @param key the keypair of this node
     * @param {"dgram".Socket} server
     */
    public constructor(private key: any,
                       private node: Node = Node.fromIpAndPort('127.0.0.1', 30303),
                       private server: Socket = dgram.createSocket('udp4')) {

        super();
        if ( !node.nodeId ) node.nodeId = pubk2id(key.getPublic());

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

    public listen() {
        if ( this.started ) return;

        return new Promise((resolve) => {
            this.server.bind(this.node.endpoint.udp, () => {
                this.started = true;
                resolve();
            })
        });
    }

    public close(callback: Function) {
        if ( !this.started ) return;

        this.server.close(() => {
            this.started = false;
            callback();
        });
    }

    /** return the current time in second
     *
     * @returns {number}
     */
    public now() : number {
        return Math.floor(new Date().getTime()/1000);
    }

    public onMessage(msg: Buffer, rinfo: AddressInfo) {
        if (this.log.isTraceEnabled()) this.log.trace('Received UDP packet', rinfo, msg);

        // hash (32-byte) || signature (65-byte) || packet-type (1-byte) || packet-data (variable length)
        if ( msg.length < 32+65+1+1 ) {
            this.log.debug('Dropping packet due to invalid size', rinfo);
            return;
        }

        // verify the hash
        let hasher = keccak256.create().update(msg.slice(32));
        if ( 0 != msg.compare(Buffer.from(hasher.digest()), 0,32, 0, 32) ) {
            this.log.debug('Dropping packet due to invalid hash', {calculated: hasher.hex(), received: msg.slice(0, 32).toString('hex')});
            return;
        }

        // verify the signature
        let sigHasher = keccak256.create().update(msg.slice(32+65));
        let signature = {r: msg.slice(32, 64), s: msg.slice(64, 32+64), recoveryParam: msg[32+64]};
        let remoteId: Buffer;
        try {
            // the return from recoverPubKey is a complex object
            let pubKey = this.ec.recoverPubKey(sigHasher.digest(), signature, signature.recoveryParam);
            // the following is not needed, a successfully recovered public key is internally checked with verify
            // if ( !this.ec.verify(sigHasher.digest(), signature, pubKey) ) {
            //     this.log.debug('Dropping packet to due signature verification failed', signature);
            //     return;
            // }
            remoteId = pubk2id(pubKey);
        } catch (err) {
            this.log.debug('Dropping packet to due invalid signature', err);
            return;
        }

        // decode the packet
        let packetType = msg[32+65];
        let decoded: any;
        try {
            decoded = rlp.decode(msg.slice(32 + 65 + 1));
        } catch (err) {
            this.log.debug('Dropping packet to due RLP encoding error', err);
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
                this.log.info('FindNeighbours packet received');
            } else if (packetType === 0x04) {
                // Neighbors
                this.log.info(`Neighbors packet received`);
            } else {
                this.log.info(`Received an unknown packet type: ${packetType}`);
            }
        } catch (err) {
            this.log.debug('Error processing UDP packet', err);
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
                let h = pingPacketHash.slice(0, 32).toString('hex');
                eventEmitter.once(h, (rinfo: AddressInfo, remoteId: Buffer) => {
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
     * @returns {Promise<Buffer>} return full packet as a buffer
     */
    public ping(remote: Node, eventEmitter: EventEmitter) {
        let record = [
            0x03, // this is version number
            [this.node.endpoint.ipAsBuffer, this.node.endpoint.udp, this.node.endpoint.tcp],
            [remote.endpoint.ipAsBuffer, remote.endpoint.udp, remote.endpoint.tcp],
            // "+expiryTime" because peers will ignore the ping request if timestamp is from the past
            this.now() + this.expiryTime
        ];

        let data = rlp.encode(record);
        this.log.debug('Sending PING packet to remote peer', remote);

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
     * @param {Buffer} remoteId the remote nodeId
     * @param {number[]} hash the hash of the received packet, we need this in the PONG reply
     * @param {Array<any>} data expected to be the output from rlp.decode(packet_data)
     */
    public handlePingReceived(rinfo: AddressInfo, remoteId: Buffer, hash: number[], data: Array<any>) {
        const version = (data[0].readUInt8(0));
        const remoteEndpoint = this.toEndPoint(data[1] as Array<Buffer>);
        const myEndpoint = this.toEndPoint(data[2] as Array<Buffer>);
        const timestamp = data[3].readUInt32BE(0);

        // https://github.com/ethereum/devp2p/blob/master/rlpx.md said it should be 3
        // Geth PING version is 4
        // we need to support both
        if ( version !== 0x03 && version !== 0x04 ) {
            this.log.debug("Don't know how to reply this PING request", {version: version});
            return;
        }

        if (  this.now() > timestamp ) {
            this.log.debug('Ignore PING request due to invalid timestamp', {packet_time: timestamp});
            return;
        }

        if (this.log.isDebugEnabled()) {
            this.log.debug('PING data received', {
                remote: rinfo,
                local: myEndpoint,
                hash: Buffer.from(hash).toString('hex'),
                timestamp: timestamp
            });
        }

        // note: we reply with rinfo, not peerEndpoint beacuse it might be behind NAT
        const remoteNode = new Node();
        remoteNode.nodeId = remoteId;
        remoteNode.endpoint = new Endpoint(rinfo.address, rinfo.port, remoteEndpoint.tcp);
        this.emit('pingReceived', remoteNode, hash);
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
        this.log.debug('Sending PONG packet to remote peer', remote);

        // pong packet type is 0x02
        return this.send(remote, 0x02, data);
    }

    /** handle PONG request (remote node send PONG back to us)
     *
     * @param {"dgram".AddressInfo} rinfo
     * @param {Buffer} remoteId the recovered sender public key, total 64 bytes long, w/o leading '0x04'
     * @param {Array<any>} packetData expected to be the output from rlp.decode(packet_data)
     */
    public handlePongReceived(rinfo: AddressInfo, remoteId: Buffer, packetData: Array<any>) : void {
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
            || (registry.remote.nodeId && !registry.remote.nodeId.equals(remoteId) ) ) {

            if ( registry.timestamp+this.expiryTime < this.now() ) {
                this.log.debug("Dropping expired PONG packet: " + new Date(registry.timestamp*1000));
            } else if ( !registry.remote.nodeId && registry.remote.endpoint.ip != rinfo.address ) {
                this.log.debug("Dropping PONG packet from unexpected IP", {expected: registry.remote.endpoint.ip, actual: rinfo.address});
            } else {
                this.log.debug("Dropping PONG packet with unexpected nodeId", {expected: registry.remote.nodeId, actual: remoteId});
            }
            // if we don't clear all listener, we may have memory leak
            if ( registry.eventEmitter ) registry.eventEmitter.removeAllListeners();
            delete this.pingRegistry[pingHash];
            return;
        }

        if (this.log.isDebugEnabled()) {
            this.log.debug("PONG data received", {
                remote: rinfo,
                local: endpoint,
                hash: hash.toString('hex'),
                timestamp: timestamp
            });
        }

        if ( registry.eventEmitter ) {
            registry.eventEmitter.emit(pingHash, rinfo, remoteId);
            registry.eventEmitter.removeAllListeners();
        }
        delete this.pingRegistry[pingHash];
    }

    /** send a FindNode packet (0x03)
     * packet-data = [target, expiration]
     * @param {Endpoint} remote node to send packet to
     * @param {Buffer} target 65-byte public key
     * @returns {Promise<Buffer>}
     */
    public findNode(remote: Endpoint, target: Buffer) {
        let record = [
            target,
            // "+expiryTime" because peers will ignore the ping request if timestamp is from the past
            this.now() + this.expiryTime
        ];

        let data = rlp.encode(record);
        this.log.debug('Sending FINDNODE packet to remote peer', remote);

        // findNode packet type is 0x03
        return this.send(remote, 0x03, data);
    }

    public handleFindNodeReceived(rinfo: AddressInfo, remoteId: Buffer, packetData: Array<any>) : void {
        let target : Buffer = packetData[0];
        let b = (target instanceof Buffer);
        // if I put the above instanceof into the following if-condition, it will have compile-time error
        if ( !b || (target.length != 65)) {
            this.log.debug(!b ? 'Invalid target in findNode packet' : 'Incorrect target length in findNode packet', {
                remote: rinfo,
                nodeId: remoteId.toString('hex'),
                packetData: packetData
            });
            return;
        }
        let expiration = packetData[1];
        if ( !_.isNumber(expiration) || expiration < this.now() ) {
            this.log.debug(_.isNumber(expiration) ? 'Expired findNode packet' : 'Invalid expiration in findNode packet', {
                remote: rinfo,
                nodeId: remoteId.toString('hex'),
                packetData: packetData
            });
            return;
        }
        this.emit('findNodeReceived', {nodeId: remoteId, target: target});
    }

    /** send a Neighbors Packet (0x04)
     * packet-data = [nodes, expiration]
     * nodes = [[ip, udp-port, tcp-port, node-id], ... ]
     * @param {Endpoint} remote node to send packet to
     * @param {Node[]} nodes
     * @returns {Promise<Buffer>}
     */
    public neighbor(remote: Endpoint, nodes: Node[]) {
        let list = [];
        for(let node of nodes) {
            let tmp = rlp.encode([
                node.endpoint.ip,
                node.endpoint.udp,
                node.endpoint.tcp,
                node.nodeId
            ]);
            list.push(tmp);
        }
        let record = [
            list,
            // "+expiryTime" because peers will ignore the ping request if timestamp is from the past
            this.now() + this.expiryTime
        ];

        let data = rlp.encode(record);
        this.log.debug('Sending NEIGHBOR packet to remote peer', remote);

        // findNode packet type is 0x03
        return this.send(remote, 0x04, data);
    }

    public handleNeighborsReceived(rinfo: AddressInfo, remoteId: Buffer, packetData: Array<any>) : void {
        let array = packetData[0] as Array<Array<Buffer>>;
        if ( !_.isArray(array) ) {
            this.log.debug('Result is not an array in NEIGHBOUR packet', {
                remote: rinfo,
                nodeId: remoteId.toString('hex'),
                packetData: packetData
            });
            return;
        }
        let expiration = packetData[1];
        if ( !_.isNumber(expiration) || expiration < this.now() ) {
            this.log.debug(_.isNumber(expiration) ? 'Expired NEIGHBOUR packet' : 'Invalid expiration in NEIGHBOUR packet', {
                remote: rinfo,
                nodeId: remoteId.toString('hex'),
                packetData: packetData
            });
            return;
        }

        let nodes: Array<Node>;
        for(let item of array) {
            let tmp = this.toEndPoint(item);
            let n = Node.fromIpAndPort(tmp.address, tmp.udp, tmp.tcp);
            n.nodeId = item[3];
            let b = (n.nodeId instanceof Buffer);
            if( !b || n.nodeId.length !== 65 ) {
                this.log.debug(!b ? 'Invalid node in NEIGHBOUR packet' : 'Incorrect id length in NEIGHBOUR packet', {
                    remote: rinfo,
                    nodeId: remoteId.toString('hex'),
                    data: n.nodeId
                });
            } else {
                nodes.push(n);
            }
        }
        this.emit('neighborsReceived', {nodeId: remoteId, nodes: nodes});
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
            p = (p<<8) + data[i];
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

        if ( beforeSend ) beforeSend(packet);

        if (this.log.isTraceEnabled()) this.log.trace('Sending UDP packet', remote, packet);

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