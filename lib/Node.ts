import { Endpoint } from './Endpoint';
import * as BN from 'bn';
import {URL} from "url";
import {isNullOrUndefined} from "util";

export class Node {
    public endpoint: Endpoint;
    public nodeId: Buffer;
    public hashId: number[];

    static fromUrl(url: string) : Node {
        let u = new URL(url);
        if ( 'enode' != u.protocol ) throw new Error("Not a enode URL: " + url);
        if ( isNullOrUndefined(u.username) ) throw new Error("URL does not contain a node ID: " + url);
        if ( ! (/^[0-9a-fA-F]{65}$/.test(u.username)) ) throw new Error("URL does not have a valid node ID: " + url);

        let n = new Node();
        n.nodeId = new BN(u.username, 16);

        let tcp = u.port ? parseInt(u.port) : 30303;
        let udp = u.searchParams.get("discport") ? parseInt(u.searchParams.get("discport")) : tcp;
        n.endpoint = new Endpoint(u.host, udp, tcp);
        return n;
    }

    static fromIpAndPort(ip: string, udp: number) : Node {
        let n = new Node();
        n.endpoint = new Endpoint(ip, udp, udp);
        return n;
    }
}

