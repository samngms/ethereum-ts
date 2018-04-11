import {keccak256} from "js-sha3";
import 'mocha';
import 'chai/register-should';

describe('Just to make sure this is keccak256 and not SHA3', () => {
    it('keccak256.hex', () => {
        const test = keccak256.create().update('testing').hex();
        test.should.be.a('string');
        test.should.eq('5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02');
    });

    it('keccak256.digest', () => {
        const test = keccak256.create().update('testing').digest();
        test.should.be.an('array');
        test.length.should.eq(32);
        Buffer.from(test).toString('hex').should.eq('5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02');
    });

    it('keccak256 and create.update should be the same', () => {
        const t1 = keccak256('testing');
        const t2 = keccak256.create().update('testing').hex();
        t1.should.eq(t2);
    });
});