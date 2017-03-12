const crypto = require('crypto');

class HKDFBufferGenerator {
  constructor(alg, ikm, info, salt, size) { return hkdfBufferGenerator(alg, ikm, info, salt, size) }
}

function hkdfBufferGenerator(hashAlg, ikm, info, salt, outLen) {
  let buffers = [],
      hashLen = crypto.createHash(hashAlg).digest().length,
      n       = Math.ceil(outLen / hashLen),
      prev    = Buffer.alloc(0),
      prk     = crypto.createHmac(hashAlg, salt).update(ikm).digest();

  if(n >= 256) 
    throw Error('HKDF cannot generate more than 255 blocks of HashLen size');
  if (outLen > 255 * hashLen) 
    throw Error('HKDF may only be used for 255 * HashLen bytes of output');

  info = Buffer.from(info); // typeof info === 'string'
  salt = salt || Buffer.alloc(hashLength);

  for (let i = 0; i < n; i++) {
    prev = crypto.createHmac(hashAlg, prk).update(
        Buffer.concat([prev, info, Buffer.from(String.fromCharCode(i + 1))])
    ).digest();

    buffers.push(prev);
  }

  return Buffer.concat(buffers, outLen);
}

module.exports = HKDFBufferGenerator;
