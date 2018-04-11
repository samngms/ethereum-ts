/** convert a elliptic curve public key into a 65 bytes Buffer
 *
 * @param pubKey an object from elliptic.KeyPair.getPublic()
 * @returns {string} the public key as a Buffer, with '0x04' prefix
 */
function pubk2buf(pubKey: any) : Buffer {
    // I don't know the meaning of the first parameter to encode(), but second parameter is compress
    return Buffer.from(pubKey.encode(true, false));
}

/** convert a elliptic curve public key into a 64 bytes Buffer
 *
 * @param pubKey an object from elliptic.KeyPair.getPublic()
 * @returns {Buffer} the public key as a Buffer, WITHOUT '0x04' prefix
 */
function pubk2id(pubKey: any) : Buffer {
    return pubk2buf(pubKey).slice(1);
}

export { pubk2buf, pubk2id };