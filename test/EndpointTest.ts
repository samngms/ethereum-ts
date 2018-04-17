import 'mocha';
import { expect } from 'chai';
import {Endpoint} from "../lib/Endpoint";

describe('Endpoint', () => {
    it('#ipAsBuffer', () => {
        let endpoint = new Endpoint('1.2.3.4', 123, 456);
        expect(endpoint.ipAsBuffer).deep.equals(Buffer.from([1 ,2, 3, 4]));
    });
});