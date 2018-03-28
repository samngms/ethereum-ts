import * as BN from 'bn';
import {keccak256} from "js-sha3";
import {isNullOrUndefined, isUndefined} from "util";
import * as winston from 'winston';
import {NodeDiscovery} from "./NodeDiscovery";
import {Node} from './Node';
import {AddressInfo} from "dgram";

class BucketItem {
    private lastAccess: number;

    /**
     *
     * @param {number[]} hash note: this.hash != node.nodeId, this.hash = keccak256(node.nodeId)
     * @param {Node} node
     */
    constructor(public hash: number[], public nodeData: Node) {

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

    public list: Array<BucketItem>;
    public lastRefresh: number;
    public lastAccess: number;

    public log = winston.loggers.get('devp2p');

    constructor(private discovery: NodeDiscovery) {
        this.list = [];
        this.lastAccess = new Date().getTime();
        this.lastRefresh = this.lastAccess;
    }

    public touchNode(hash: number[], nodeData: Node) {
        let idx = this.findNode(hash);
        if ( idx == -1 ) {
            if ( this.list.length >= this.BUCKET_SIZE ) {
                // we *may* need to remove the last node
                let item = this.list.pop();
                this.discovery.pingPong(item.nodeData).then((result : {rinfo: AddressInfo, pubKey: any}) => {
                    // pingPong successful, keep old data
                }).catch((error: any) => {
                    // pingPong failed, replace with new data
                    let i = this.findNode(item.hash);
                    if ( -1 != i ) {
                        this.list.splice(i, 1);
                    } else {
                        this.log.warn("Trying to delete a node from Bucket but it is no longer exist", nodeData);
                    }
                    this.list.push(new BucketItem(hash, nodeData));
                })
            } else {
                this.list.push(new BucketItem(hash, nodeData));
            }
        } else {
            let item = this.list[idx];
            item.touchNode();
            this.list.slice(idx, 1);
            this.list.unshift(item);
        }
    }

    public findNode(hash: number[]) {
        return this.list.findIndex( x => x.hash == hash );
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

    public log = winston.loggers.get('devp2p');

    constructor(private owner: Node, private discovery: NodeDiscovery) {
        this.buckets = new Array<Bucket>(this.NO_OF_BUCKETS);
        for(let i=0; i<this.buckets.length; i++) {
            this.buckets[i] = new Bucket(discovery);
        }
    }

    public start(initPeers: string[]) {
        let array = [];
        initPeers.forEach((item) => {
            if ( /^enode:\/\/[0-9a-fA-F]{65}@\d{1,3}(\.\d{1,3}){3}:\d{1,5}(\?.*)?"$/.test(item) ) {
                array.push(Node.fromUrl(item));
            } else if ( /^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$/.test(item) ) {
                let i = item.indexOf(':');
                array.push(Node.fromIpAndPort(item.substring(0, i), parseInt(item.substring(i+1))));
            } else {
                throw new Error("Invalid bootstrap peer: " + item);
            }
        });

        this.log.info("My nodeId: " + Buffer.from(this.owner.nodeId).toString('hex'));

        this.discovery.startInternal().then(() => {
            array.forEach((node) => {
                this.discovery.pingPong(node).then((result : {rinfo: AddressInfo, remoteId: number[]}) => {
                    if ( !node.nodeId ) node.nodeId = result.remoteId;
                    this.touchNode(BucketManger.keccak256(node.nodeId), node);
                }).catch(error => {
                    this.log.info("Error Ping-Pong " + node, error);
                })
            });
        });
    }

    static keccak256(input: Buffer) : number[] {
        let hasher = keccak256.create().update(input);
        return hasher.digest();
    }

    /** Act like UNIX touch command, if the node doesn't exist we will add it to one of the bucket, and then update the last access time
     *
     * @param {number[]} hash expected to be keccak256 hash
     * @param nodeData contain any valid info about the node, should at least include ip address, udp/tcp ports
     */
    public touchNode(hash: number[], nodeData: Node) {
        if ( hash.length < 2 ) {
            return;
        }

        let dist = this.distance(this.owner.hash, hash);
        let bucket = this.buckets[dist];
        bucket.touchNode(hash, nodeData);
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
            if ( 0 != (xor & (one >> i)) ) {
                break;
            } else {
                i++;
            }
        }

        return i;
    }
}