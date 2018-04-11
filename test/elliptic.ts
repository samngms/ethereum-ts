import 'mocha';
import { expect } from 'chai';
import * as elliptic from 'elliptic';
import * as crypto from 'crypto';
import {pubk2buf} from "../lib/Util";

describe('secp256k1', () => {
    describe('keypair', () => {
        it('from private key', () => {
            const str = '49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee';
            const ec = new elliptic.ec('secp256k1');
            const keypair = ec.keyFromPrivate(str);
            expect(keypair.getPrivate().toString('hex')).to.equal(str);
            expect(pubk2buf(keypair.getPublic()).toString('hex')).to.equal('04fda1cff674c90c9a197539fe3dfb53086ace64f83ed7c6eabec741f7f381cc803e52ab2cd55d5569bce4347107a310dfd5f88a010cd2ffd1005ca406f1842877');
        });

        it('read public key', () => {
            const str = '04fda1cff674c90c9a197539fe3dfb53086ace64f83ed7c6eabec741f7f381cc803e52ab2cd55d5569bce4347107a310dfd5f88a010cd2ffd1005ca406f1842877';
            const ec = new elliptic.ec('secp256k1');
            const keypair = ec.keyFromPublic(str, 'hex');
            expect(pubk2buf(keypair.getPublic()).toString('hex')).to.equal(str);
            expect(keypair.getPrivate()).to.be.null;
        });

        it('read public key w/o 04 prefix will throw an Error', () => {
            const str = 'fda1cff674c90c9a197539fe3dfb53086ace64f83ed7c6eabec741f7f381cc803e52ab2cd55d5569bce4347107a310dfd5f88a010cd2ffd1005ca406f1842877';
            const ec = new elliptic.ec('secp256k1');
            expect(() => {ec.keyFromPublic(str, 'hex')}).throw();
        });
    });

    describe('sign', () => {
        it('recoverable signature', () => {
            const ec = new elliptic.ec('secp256k1');
            const keypair = ec.genKeyPair();
            const data = crypto.randomBytes(32);
            // canonical=true can produce diff sign than canonical=false
            // but sometimes they are the same
            // bitcoin and ethereum use canonical=true
            const signature = keypair.sign(data, { canonical: true });
            const sig2 = {r: signature.r, s: signature.s};
            const recoveredPublic = ec.recoverPubKey(data, sig2, signature.recoveryParam);
            expect(pubk2buf(recoveredPublic).toString('hex')).eq(pubk2buf(keypair.getPublic()).toString('hex'));
        });
    })

});