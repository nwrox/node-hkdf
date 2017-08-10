const hash = require('crypto').createHash
		, hmac = require('crypto').createHmac

class HKDFBufferGenerator {
  constructor(alg, ikm, info, salt, size) {
    this._alg = alg
    this._ikm = ikm
    this._info = info
    this._salt = salt
    this._size = size
  }

  getOKM(){
    const hashLen = hashDigest(this._alg).length
        , n       = Math.ceil(this._size / hashLen)

    if(n > 255)
      throw new Error('HKDF cannot generate more than 255 blocks of HashLen size')
    if (this._size > 255 * hashLen)
      throw new Error('HKDF may only be used for 255 * HashLen bytes of output')

    this._info = Buffer.from(this._info)
    this._salt = this._salt || Buffer.alloc(hashLen)
    this._prk  = hmacDigest(this._alg, this._salt)(this._ikm)

		const buffer = nSeq(n).reduce((acc, curr) => bufConcat([
			acc,
			hmacDigest(this._alg, this._prk)(
				bufConcat([
					acc.slice(acc.length - hashLen, acc.length),
					this._info,
					asciiBuffer(curr)
				])
			)
		]), Buffer.alloc(0))

    return buffer.slice(0, this._size)
  }

  getPRK() {
    return this._prk || hmacDigest(this._alg, this._salt)(this._ikm).digest()
  }
}

const asciiBuffer = (n) => Buffer.from(String.fromCharCode(n + 1))

const bufConcat = (buffers) => Buffer.concat([...buffers])

const hashDigest = (alg) => hash(alg).digest()

const hmacDigest = (alg, key) => (buf) => {
	return hmac(alg, key).update(buf)
		.digest()
}

const nSeq = (n) => [...Array(n).keys()]

module.exports = HKDFBufferGenerator
