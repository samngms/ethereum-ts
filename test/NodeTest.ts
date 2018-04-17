import 'mocha';
import { expect } from 'chai';
import {Node} from '../lib/Node';

describe('devp2p.Node', () => {
    it('from valid URL', () => {
        let n = Node.fromUrl('enode://ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31387574077f301b421bc84df7266c44e9e6d569fc56be00812904767bf5ccd1fc7f@12.34.56.78:12345');
        expect(n.nodeId.toString('hex')).equals('ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31387574077f301b421bc84df7266c44e9e6d569fc56be00812904767bf5ccd1fc7f');
        expect(n.endpoint.ip).equals('12.34.56.78');
        expect(n.endpoint.tcp).equals(12345);
        expect(n.endpoint.udp).equals(12345);
        expect(n.endpoint.ipAsBuffer).deep.equals(Buffer.from([12, 34, 56, 78]));
        expect(Buffer.from(n.hash).toString('hex')).equals('a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7')
    });

    it('from valid URL with discport', () => {
        let n = Node.fromUrl('enode://ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31387574077f301b421bc84df7266c44e9e6d569fc56be00812904767bf5ccd1fc7f@12.34.56.78:12345?discport=54321');
        expect(n.nodeId.toString('hex')).equals('ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31387574077f301b421bc84df7266c44e9e6d569fc56be00812904767bf5ccd1fc7f');
        expect(n.endpoint.ip).equals('12.34.56.78');
        expect(n.endpoint.tcp).equals(12345);
        expect(n.endpoint.udp).equals(54321);
        expect(n.endpoint.ipAsBuffer).deep.equals(Buffer.from([12, 34, 56, 78]));
        expect(Buffer.from(n.hash).toString('hex')).equals('a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7')
    });

    it('from invalid URL (too short)', () => {
        let f = () => {
            Node.fromUrl('enode://634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31387574077f301b421bc84df7266c44e9e6d569fc56be00812904767bf5ccd1fc7f@12.34.56.78:12345');
        }
        expect(f).throw();
    });

    it('from invalid URL (too long)', () => {
        let f = () => {
            Node.fromUrl('enode://caca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31387574077f301b421bc84df7266c44e9e6d569fc56be00812904767bf5ccd1fc7f@12.34.56.78:12345');
        }
        expect(f).throw();
    });
});