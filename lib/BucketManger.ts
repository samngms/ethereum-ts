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

class Bucket {
    /** the number of items per bucket, denoted k in Kademlia
     * Default value is 16 as specified in Ethereum's spec
     * @type {number}
     */
    private BUCKET_SIZE = 16;
    private challengeInProgress = 0;
    private pendingEvictionChallengers = [];

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
        if ( idx === -1 ) {
            assert.ok(this.list.length <= this.BUCKET_SIZE, 'Bucket size larger than BUCKET_SIZE');

            if ( this.list.length === this.BUCKET_SIZE ) {
                this.challengeLast(node);
            } else {
                this.list.unshift(new BucketItem(node));
            }
        } else {
            let item = this.list[idx];
            item.touchNode();
            if ( idx > 0 ) {
                // move it to the front
                this.list.slice(idx, 1);
                this.list.unshift(item);
            }
        }
    }

    public findNode(hash: number[]) {
        return this.list.findIndex( x => _.isEqual(x.node.hash, hash) );
    }

    /** ping the least recently accessed node (the last node), if no pong rely, remove it and add challenger to the head, otherwise, drop challenger
     * Note: there is a special case when two pings are received at almost the same time
     *       i.e. we may be handling (waiting for pong reply) while we want to run evictLast again
     *       in that case, we will just put the challenger in an array and let the other "thread" to do this for us
     * @param {Node} challenger
     */
    private challengeLast(challenger: Node) {
        if ( this.challengeInProgress ) {
            // if we are already running an eviction process, we will rely on another "thread" to do it for us
            this.pendingEvictionChallengers.push(challenger);
        } else {
            // while-loop because we may need to handle other items in pendingEvictionChallengers[] array as well
            while(challenger) {
                let lastItem = this.list[this.list.length - 1];
                // just a safe-guard, if the lastAccess time is within 1 minute, we simply assume the node is still alive
                if ( lastItem.lastAccess > new Date().getTime()-60*1000 ) {
                    // do nothing, we ignore the challenger
                } else {
                    this.challengeInProgress++;
                    this.discovery.pingPong(lastItem.node).then((result: { rinfo: AddressInfo, pubKey: any }) => {
                        // pingPong successful, keep old data
                        let tmp = this.list.pop();
                        assert(tmp === lastItem, 'Bucket item mid-air change detected');
                        lastItem.touchNode();
                        this.list.unshift(lastItem);
                        this.challengeInProgress--;
                    }).catch((error: any) => {
                        // pingPong failed, replace with new data
                        let tmp = this.list.pop();
                        assert(tmp === lastItem, 'Bucket item mid-air change detected');
                        this.list.unshift(new BucketItem(challenger));
                        this.challengeInProgress--;
                    })
                }
                challenger = this.pendingEvictionChallengers.shift();
            }
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

    static hash(input: Buffer) : number[] {
        let hasher = keccak256.create().update(input);
        return hasher.digest();
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