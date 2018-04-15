import {
	createHash,
	createHmac
} from 'crypto'

const hkdf = (alg = 'sha256', ikm, info, salt, size) => {
	const asciiBuffer = n => Buffer.from(String.fromCharCode(n + 1))

	const getOKM = () => {
		const n = Math.ceil(size / hashLen)

		if(n > 255) {
      throw new Error('HKDF cannot generate more than 255 blocks of HashLen size')
		}

    if (size > 255 * hashLen) {
			throw new Error('HKDF may only be used for 255 * HashLen bytes of output')
		}

    info = Buffer.from(info)
    salt = salt || Buffer.alloc(hashLen)

    return numSeq(n).reduce(reduceNSeqToBuffer, Buffer.alloc(0))
			.slice(0, size)
	}

	const getPRK = () => prk

	const hashDigest = alg => createHash(alg).digest()

	const hashLen = hashDigest(alg).length

	const hmacDigest = (alg, key) => buf => createHmac(alg, key).update(buf)
		.digest()

	const numSeq = n => [...Array(n).keys()]

	const prk = hmacDigest(alg, salt)(ikm)

	const reduceNSeqToBuffer = (acc, curr) => {
		const { length: len } = acc
		const buffer = Buffer.concat([
			acc.slice(len - hashLen, len), info, asciiBuffer(curr)
		])
		const digest = hmacDigest(alg, prk)(buffer)

		return Buffer.concat([acc, digest])
	}

	return {
		getOKM,
		getPRK
	}
}

// const ikm = Buffer.from(
// 	'0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex'
// )
// const salt = Buffer.from('000102030405060708090a0b0c', 'hex')
// const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex')
// const {
// 	getOKM,
// 	getPRK
// } = hkdf('sha256', ikm, info, salt, 42)
// const okm = getOKM().toString('hex')
// const prk = getPRK().toString('hex')
//
// console.log(okm)
// console.log(prk)

module.exports = hkdf
