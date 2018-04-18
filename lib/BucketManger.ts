import {keccak256} from "js-sha3";
import * as log4js from '@log4js-node/log4js-api';
import {NodeDiscovery} from "./NodeDiscovery";
import {Node} from './Node';
import {AddressInfo} from "dgram";
import {Endpoint} from "./Endpoint";
import * as _ from 'lodash';
import * as assert from "assert";

class BucketItem {
    public lastAccess: number;

    /**
     *
     * @param {Node} node
     */
    constructor(public node: Node) {

    }

    public touchNode() {
        this.lastAccess = new Date().getTime();
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
    public BUCKET_SIZE = 16;

    /** the key is the nodeId of the existing item
     *
     * @type {Map<string, EvictionPair>}
     */
    private pendingEvictionEntries = new Map<string, EvictionPair>();

    public list: Array<BucketItem>;
    public lastRefresh: number;
    public lastAccess: number;

    public log = log4js.getLogger('devp2p.Bucket');

    constructor(private discovery: NodeDiscovery) {
        this.list = [];
        this.lastAccess = new Date().getTime();
        this.lastRefresh = this.lastAccess;
    }

    public touchNode(node: Node) {
        // TODO: cache the calculation of node.hash to improve performance
        let idx = this.findNode(node.hash);
        if ( -2 === idx ) {
            // this node is in this.pendingEvictionEntries, give up
        } else if ( -1 === idx ) {
            // this node is not in this.list nor this.pendingEvictionEntries
            assert.ok(this.list.length + this.pendingEvictionEntries.size <= this.BUCKET_SIZE, 'Bucket size larger than BUCKET_SIZE');
            if ( this.list.length + this.pendingEvictionEntries.size === this.BUCKET_SIZE ) {
                // bucket full
                this.challengeLast(node);
            } else {
                // bucket not full
                this.list.unshift(new BucketItem(node));
            }
        } else {
            // the node is definitely inside this.list
            let item = this.list[idx];
            item.touchNode();
            if ( idx > 0 ) {
                // move it to the front
                this.list.slice(idx, 1);
                this.list.unshift(item);
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

        const lastItem = this.list.pop();
        const lastNodeId = lastItem.node.nodeId.toString('hex');
        this.pendingEvictionEntries.set(lastNodeId, {oldItem: lastItem, newNode: challenger});
        if ( lastItem.lastAccess > new Date().getTime()-60*1000 ) {
            this.pendingEvictionEntries.delete(lastNodeId);
            this.list.unshift(lastItem);
        } else {
            this.discovery.pingPong(lastItem.node).then((result: { rinfo: AddressInfo, pubKey: any }) => {
                // pingPong successful, keep old data
                this.pendingEvictionEntries.delete(lastNodeId);
                this.list.unshift(lastItem);
            }).catch((error: any) => {
                // pingPong failed, replace with new data
                this.pendingEvictionEntries.delete(lastNodeId);
                this.list.unshift(new BucketItem(challenger));
            })
        }
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
    private NO_OF_BUCKETS = 10;

    private buckets: Array<Bucket>;

    public log = log4js.getLogger('devp2p.BucketManager');

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

        let count = 0;
        array.forEach((node) => {
            this.discovery.pingPong(node).then((result : {rinfo: AddressInfo, remoteId: number[]}) => {
                if ( !node.nodeId ) node.nodeId = result.remoteId;
                this.touchNode(node);
                count++;
            }).catch(error => {
                this.log.info(`Error Ping-Pong: ${node}`, error);
            })
        });

        if (!count) throw new Error('No active peer found');
    }

    private pingReceived(remote: Node, hash: number[]) {
        this.discovery.pong(remote.endpoint, hash).then(() => {
            this.touchNode(remote);
        }).catch((err) => {
            // TODO: maybe we want to re-pong if err=timeout
        })
    }

    /** Act like UNIX touch command, if the node doesn't exist we will add it to one of the bucket, and then update the last access time
     *
     * @param {number[]} hash expected to be keccak256 hash
     * @param node contain any valid info about the node, should at least include ip address, udp/tcp ports
     */
    public touchNode(node: Node) {
        let dist = this.distance(this.owner.hash, node.hash);
        let bucket = this.buckets[dist];
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
}