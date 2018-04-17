import { Endpoint } from './Endpoint';
import * as BN from 'bn';
import {URL} from "url";
import {isNullOrUndefined} from "util";
import {keccak256} from "js-sha3";

export class Node {
    public endpoint: Endpoint;
    public nodeId: Buffer;
    private _hash: number[];

    static fromUrl(url: string) : Node {
        let u = new URL(url);
        if ( 'enode:' != u.protocol ) throw new Error("Not a enode URL: " + url);
        if ( !u.username ) throw new Error("URL does not contain a node ID: " + url);
        if ( ! (/^[0-9a-fA-F]{128}$/.test(u.username)) ) throw new Error("URL does not have a valid node ID: " + url);

        let n = new Node();
        n.nodeId = Buffer.from(u.username, 'hex');

        let tcp = u.port ? parseInt(u.port) : 30303;
        let udp = u.searchParams.get("discport") ? parseInt(u.searchParams.get("discport")) : tcp;
        n.endpoint = new Endpoint(u.hostname, udp, tcp);
        return n;
    }

    static fromIpAndPort(ip: string, udp: number) : Node {
        let n = new Node();
        n.endpoint = new Endpoint(ip, udp, udp);
        return n;
    }

    public get hash() : number[] {
        if ( !this._hash ) {
            if ( !this.nodeId ) return null;
            this._hash = keccak256.create().update(this.nodeId).digest();
        }
        return this._hash;
    }
}

