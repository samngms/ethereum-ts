import * as log4js from '@log4js-node/log4js-api';
import {NodeDiscovery} from "./NodeDiscovery";
import {Node} from './Node';
import {AddressInfo} from "dgram";
import * as _ from 'lodash';
import * as assert from "assert";
import Timer = NodeJS.Timer;
import {EventEmitter} from "events";
import * as crypto from 'crypto';

class BucketItem {
    public lastAccess: number;

    private isPinging = false;
    private extraPingObservers = [];
    private timer: Timer;
    public isInBucket = false;

    /**
     *
     * @param {Node} node
     */
    constructor(public node: Node, private bucket: Bucket) {
        this.lastAccess = Bucket.now();
        this.startPingPongTimer();
    }

    /**
     * To prevent traffic amplification attacks, implementations must verify that the sender of a query participates in the discovery protocol.
     * The sender of a packet is considered verified if it has sent a valid pong response with matching ping hash within the last 12 hours.
     * @see https://github.com/ethereum/devp2p/blob/master/discv4.md#endpoint-proof
     */
    public startPingPongTimer() {
        if ( this.timer ) clearTimeout(this.timer);
        this.timer = setTimeout(() => {
            this.timer = null;
            this.ping().then(() => {
                // do nothing
            }).catch((err) => {
                // do nothing
            });
        }, 10*60*60*1000); // set timeout to 10h
    }

    public destroy() {
        if ( this.timer ) clearTimeout(this.timer);
        for(let e of this.extraPingObservers) {
            e.emit('ping', new Error('Destroying BucketItem'));
            e.removeAllListeners();
        }
    }

    public touchNode() {
        this.lastAccess = Bucket.now();
    }

    /** we try to avoid two ping at the same time
     * In general, this may not be a big problem, but there may be a problem when we are running bucket refresh and bucket eviction at exactly the same time
     * There are two issues during that short period of time
     * 1. the two PING packet will have the same hash (same second, same hash), and we don't handle double pingRegistry
     * 2. bucket eviction will temporarily move BucketItem from the Bucket main list to pendingEvictionEntries
     * Our solution is if we are in the middle of a PING-PONG, the second (and afterwards as well) ping request will just observe the result of the first ping request
     * @returns {any}
     * @see isInBucket
     */
    public ping() {
        if ( !this.isPinging ) {
            this.isPinging = true;
            let self = this;
            return this.bucket.discovery.pingPong(this.node).then(() => {
                self.isPinging = false;
                for (let e of self.extraPingObservers) e.emit('ping', null);
                self.extraPingObservers = [];
                if (self.isInBucket) self.bucket.setFirst(this);
                self.startPingPongTimer();
                return Promise.resolve();
            }).catch((err) => {
                self.isPinging = false;
                for(let e of self.extraPingObservers) e.emit('ping', err);
                self.extraPingObservers = [];
                if ( self.isInBucket ) self.bucket.remove(this);
                return Promise.reject(err);
            });
        } else {
            let event = new EventEmitter();
            this.extraPingObservers.push(event);
            return new Promise((resolve, reject) => {
                event.once('ping', (err) => {
                    if ( err ) reject(err);
                    else resolve();
                })
            })
        }
    }
}

interface EvictionPair {
    newNode: Node;
    oldItem: BucketItem;
}

export class Bucket {
    /** the number of items per bucket, denoted k in Kademlia
     * Default value is 16 as specified in Ethereum's spec
     * @type {number}
     */
    public readonly BUCKET_SIZE = 16;

    /** the key is the nodeId of the existing item
     *
     * @type {Map<string, EvictionPair>}
     */
    private pendingEvictionEntries = new Map<string, EvictionPair>();

    public list: Array<BucketItem>;
    public lastRefresh: number;
    public lastAccess: number;
    public randomNodes : Node[] = [];

    public readonly log = log4js.getLogger('devp2p.Bucket');

    constructor(readonly discovery: NodeDiscovery) {
        this.list = [];
        this.lastAccess = new Date().getTime();
        this.lastRefresh = this.lastAccess;
    }

    /** Act like UNIX touch command, if the node doesn't exist we will add it to one of the bucket, and then update the last access time
     * Note: don't call this function directly, you should only touch a non-existing node after successful PING-PONG
     * @param {Node} node the remote node to touch
     */
    public touchNode(node: Node) {
        // TODO: cache the calculation of node.hash to improve performance
        let idx = this.findNode(node.hash);
        if ( -2 === idx ) {
            // this node is in this.pendingEvictionEntries, give up
        } else if ( -1 === idx ) {
            // this node is not in this.list nor this.pendingEvictionEntries
            assert.ok(this.list.length + this.pendingEvictionEntries.size <= this.BUCKET_SIZE, 'Bucket size larger than BUCKET_SIZE');
            if ( this.list.length + this.pendingEvictionEntries.size === this.BUCKET_SIZE ) {
                // bucket is full
                if ( this.list[this.list.length-1].lastAccess > Bucket.now()-60*1000 ) {
                    // last node access time is within 60s, we simply ignore the new node
                } else {
                    this.challengeLast(node);
                }
            } else {
                // bucket not full
                this.setFirst(new BucketItem(node, this));
            }
        } else {
            // the node is definitely inside this.list
            let item = this.list[idx];
            item.touchNode();
            if ( idx > 0 ) {
                // move it to the front
                this.list.slice(idx, 1);
                this.setFirst(item);
            }
        }
    }

    /**
     *
     * @param {number[]} hash
     * @returns {number} return >=0 if found in this.list, -2 if found in this.pendingEvictionEntries (either oldItem or newNode), -1 if not found in either location
     */
    public findNode(hash: number[]) {
        let idx = this.list.findIndex( x => _.isEqual(x.node.hash, hash) );
        if ( -1 !== idx ) return idx;

        for(let pair of this.pendingEvictionEntries.values()) {
            if ( _.isEqual(pair.oldItem.node.hash, hash) || _.isEqual(pair.newNode.hash, hash) ) return -2;
        }

        return -1;
    }

    /** ping the least recently accessed node (the last node), if no pong rely, remove it and add challenger to the head, otherwise, drop challenger
     * @param {Node} challenger
     */
    private challengeLast(challenger: Node) {
        if ( 0 === this.list.length ) return;

        const lastItem = this.popLast();
        const lastNodeId = lastItem.node.nodeId.toString('hex');
        this.pendingEvictionEntries.set(lastNodeId, {oldItem: lastItem, newNode: challenger});
        lastItem.ping().then((result: { rinfo: AddressInfo, pubKey: any }) => {
            // pingPong successful, keep old data
            this.pendingEvictionEntries.delete(lastNodeId);
            this.setFirst(lastItem);
        }).catch((error: any) => {
            // pingPong failed, replace with new data
            lastItem.destroy();
            this.pendingEvictionEntries.delete(lastNodeId);
            this.setFirst(new BucketItem(challenger, this));
        })
    }

    public popLast() : BucketItem {
        const item = this.list.pop();
        item.isInBucket = false;
        return item;
    }

    public setFirst(item: BucketItem) {
        this.list.unshift(item);
        item.isInBucket = true;
    }

    public remove(item: BucketItem) {
        let idx = this.list.findIndex(x => x === item);
        assert(idx !== -1);
        this.list.splice(idx, 1);
    }

    public clear() {
        for(let item of this.list) item.destroy();
        this.list = [];
    }

    /** current time in millisecond
     * We have it because we need to mock it during testing
     * @returns {number}
     */
    static now() {
        return new Date().getTime();
    }
}

export class BucketManger {
    /** No of buckets in the system
     * The distance is calculated by xor(keccak256(nodeID a), keccak256(nodeID b))
     * If the first bit of the result is 1 (the keccak hashes are the different), then it will be in bucket 0
     * Else if the second bit of the result is 1, then it will be in bucket 1
     * Else if the third bit of the result is 1, then it will be in bucket 2
     * And so on
     * Therefore, the probability for having a "1" in the n-th bit (and all preceding bits are 0) is 2^n
     * For NO_OF_BUCKETS=10, 2^10 is 1024
     * Now, as of this writing, there are below 18k Ethereum nodes in MainNet, so 10 sounds a reasonable number
     * @type {number}
     */
    public readonly NO_OF_BUCKETS = 10;

    /** how often do we need to refresh the bucket? */
    public readonly FRESH_INTERVAL = 30*60*1000;

    private buckets: Array<Bucket>;

    public readonly log = log4js.getLogger('devp2p.BucketManager');

    constructor(private owner: Node, private discovery: NodeDiscovery) {
        this.buckets = new Array<Bucket>(this.NO_OF_BUCKETS);
        for(let i=0; i<this.buckets.length; i++) {
            this.buckets[i] = new Bucket(discovery);
        }

        discovery.on('pingReceived', (node: Node, hash: number[]) => {
            this.pingReceived(node, hash);
        });
    }

    public async start(initPeers: string[]) {
        let array = [];
        initPeers.forEach((item) => {
            if ( /^enode:\/\/[0-9a-fA-F]{128}@\d{1,3}(\.\d{1,3}){3}:\d{1,5}(\?.*)?"$/.test(item) ) {
                array.push(Node.fromUrl(item));
            } else if ( /^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$/.test(item) ) {
                let i = item.indexOf(':');
                array.push(Node.fromIpAndPort(item.substring(0, i), parseInt(item.substring(i+1))));
            } else {
                throw new Error(`Invalid bootstrap peer: ${item}`);
            }
        });

        this.log.info('Starting BucketManager nodeId: ' + this.owner.nodeId.toString('hex'));

        await this.discovery.listen();

        let totalCount = array.length;
        let successfulCount = 0;
        let emitter = new EventEmitter();
        let result = new Promise((resolve, reject) => {
            emitter.once('done', (successfulCount: number) => {
                if ( successfulCount ) resolve();
                else reject(new Error('No active peer found'));
            })
        });
        array.forEach((node) => {
            this.discovery.pingPong(node).then((result : {rinfo: AddressInfo, remoteId: number[]}) => {
                if ( !node.nodeId ) node.nodeId = result.remoteId;
                this.touchNode(node);
                totalCount--;
                successfulCount++;
                if ( !totalCount ) emitter.emit('done', successfulCount);
            }).catch(error => {
                this.log.info(`Error Ping-Pong: ${node}`, error);
                totalCount--;
                if ( !totalCount ) emitter.emit('done', successfulCount);
            })
        });

        return result;
    }

    public stop() {
        for(let bucket of this.buckets) bucket.clear();
    }

    private pingReceived(remote: Node, hash: number[]) {
        this.discovery.pong(remote.endpoint, hash).then(() => {
            if ( -1 !== this.findBucket(remote).findNode(remote.hash) ) {
                // node already exist
                this.touchNode(remote);
                this.discovery.pong(remote.endpoint, hash);
            } else {
                // node not exist yet, in this case, we only add it after PING-PONG successful
                this.discovery.pong(remote.endpoint, hash);
                this.discovery.pingPong(remote).then(() => {
                    this.touchNode(remote);
                }).catch((err) => {
                    // do nothing
                });
            }
        }).catch((err) => {
            // TODO: maybe we want to re-pong if err=timeout
        })
    }

    /** find the Bucket for the node, by calculating the xor distance between my hash with node.hash
     *
     * @param {Node} node
     * @returns {Bucket}
     */
    public findBucket(node: Node) : Bucket {
        let dist = this.distance(this.owner.hash, node.hash);
        return this.buckets[dist];
    }

    /** Act like UNIX touch command, if the node doesn't exist we will add it to one of the bucket, and then update the last access time
     * Note: don't call this function directly, you should only touch a non-existing node after successful PING-PONG
     * @param {Node} node the remote node to touch
     */
    public touchNode(node: Node) {
        let bucket = this.findBucket(node);
        bucket.touchNode(node);
    }

    /** calculate the distance between two node IDs by XOR
     *
     * @param {number[]} hash1 expected to be a keccak256 hash
     * @param {number[]} hash2 expected to be a keccak256 hash
     * @returns {number} a value between 0 to NO_OF_BUCKETS, with 0 meaning very far away!!
     * @see NO_OF_BUCKETS
     */
    public distance(hash1: number[], hash2: number[]) {
        // NO_OF_BUCKETS is 10, i.e. 16-bit, that's why we only xor the first two bytes
        let xor = (((hash1[0] ^ hash2[0]) & 0xFF) << 8) + ((hash1[1] ^ hash2[1]) & 0xFF);

        let i=0;
        // check most significant bit first
        const one = 0x8000;
        while(i<this.NO_OF_BUCKETS) {
            if ( 0 !== (xor & (one >> i)) ) {
                break;
            } else {
                i++;
            }
        }

        return i;
    }

    private startRefreshTimer() {
        setTimeout(() => {
            if ( !this.hasEnoughRandomNodes() ) {
                this.fillRandomNodes(16);
                if ( !this.hasEnoughRandomNodes() ) this.startRefreshTimer();
            }
            // we want to be able to finish generating all randomNodes in 1/2 of the FRESH_INTERVAL
            // and we generate 16 random nodes in each batch
        }, Math.round(this.FRESH_INTERVAL / 2 / Math.pow(2, this.NO_OF_BUCKETS) * 16)).unref();
    }

    private fillRandomNodes(max: number) {
        for(let i=0; i<max; i++) {
            let node = new Node();
            node.nodeId = crypto.randomBytes(64);
            let dist = this.distance(this.owner.hash, node.hash);
            // we keep max 8 randomIds
            if ( this.buckets[dist].randomNodes.length < 8 ) {
                this.buckets[dist].randomNodes.push(node);
            }
        }
    }

    private hasEnoughRandomNodes() {
        // loop backward
        for(let i=this.buckets.length-1; i>=0; i--) {
            if ( this.buckets[i].randomNodes.length === 0 ) {
                return false;
            }
        }
        return true;
    }
}