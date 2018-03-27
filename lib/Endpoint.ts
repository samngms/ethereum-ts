import * as IP from "ip";

export class Endpoint {
    public ipAsBuffer: Buffer;

    constructor(public ip: string, public udp: number, public tcp: number) {
        this.ipAsBuffer = IP.toBuffer(ip)
    }
}