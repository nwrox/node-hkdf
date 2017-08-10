const expect = require('chai').expect
    , hkdf = require('../lib/hkdf')

describe('Appendix A.  Test Vectors', function(){
  describe('A.1.  Test Case 1', function(){
    it('Basic test case with SHA-256', function(){
    	const ikm = Buffer.from(
              '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex'
            )
    	    , salt = Buffer.from('000102030405060708090a0b0c', 'hex')
          , info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex')
          , gen = new hkdf('sha256', ikm, info, salt, 42)
          , okm = gen.getOKM().toString('hex')
          , prk = gen.getPRK().toString('hex')

      expect(okm).to.equal(
        '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5d' +
        'b02d56ecc4c5bf34007208d5b887185865'
      )
      expect(prk).to.equal(
        '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122' +
        'ec844ad7c2b3e5'
      )
    })
  })

  describe('A.2.  Test Case 2', () => {
    it('Test with SHA-256 and longer inputs/outputs', () => {
      const ikm = Buffer.from(
              '000102030405060708090a0b0c0d0e0f101112131415161718' +
              '191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031' +
              '32333435363738393a3b3c3d3e3f404142434445464748494a' +
              '4b4c4d4e4f', 'hex'
            )
          , salt = Buffer.from(
      		    '606162636465666768696a6b6c6d6e6f707172737475767778' +
              '797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091' +
              '92939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aa' +
              'abacadaeaf', 'hex'
      	    )
          , info = Buffer.from(
      		    'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8' +
              'c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1' +
              'e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa' +
              'fbfcfdfeff', 'hex'
      	    )
          , gen = new hkdf('sha256', ikm, info, salt, 82)
          , okm = gen.getOKM().toString('hex')
          , prk = gen.getPRK().toString('hex')

      expect(okm).to.equal(
        'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a0' +
        '50cc4c19afa97c59045a99cac7827271cb41c65e590e09da32' +
        '75600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01' +
        'd5c1f3434f1d87'
      )
      expect(prk).to.equal(
        '06a6b88c5853361a06104c9ceb35b45cef760014904671014a' +
        '193f40c15fc244'
      )
    })
  })

  describe('A.3.  Test Case 3', () => {
    it('Test with SHA-256 and zero-length salt/info', () => {
      const ikm = Buffer.from(
              '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex'
            )
    	    , salt = Buffer.alloc(0)
          , info = Buffer.alloc(0)
          , gen = new hkdf('sha256', ikm, info, salt, 42)
          , okm = gen.getOKM().toString('hex')
          , prk = gen.getPRK().toString('hex')

      expect(okm).to.equal(
        '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3' +
        '454e5f3c738d2d9d201395faa4b61a96c8'
      )
      expect(prk).to.equal(
        '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac' +
        '434c1c293ccb04'
      )
    })
  })

  describe('A.4.  Test Case 4', () => {
    it('Basic test case with SHA-1', () => {
      const ikm = Buffer.from('0b0b0b0b0b0b0b0b0b0b0b', 'hex')
    	    , salt = Buffer.from('000102030405060708090a0b0c', 'hex')
          , info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex')
          , gen = new hkdf('sha1', ikm, info, salt, 42)
          , okm = gen.getOKM().toString('hex')
          , prk = gen.getPRK().toString('hex')

      expect(okm).to.equal(
        '085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568' +
        'a9cdd4f155fda2c22e422478d305f3f896'
      )
      expect(prk).to.equal(
        '9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243'
      )
    })
  })

  describe('A.5.  Test Case 5', () => {
    it('Test with SHA-1 and longer inputs/outputs', () => {
      const ikm = Buffer.from(
              '000102030405060708090a0b0c0d0e0f101112131415161718' +
              '191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031' +
              '32333435363738393a3b3c3d3e3f404142434445464748494a' +
              '4b4c4d4e4f', 'hex'
            )
    	    , salt = Buffer.from(
              '606162636465666768696a6b6c6d6e6f707172737475767778' +
              '797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f9091' +
              '92939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aa' +
              'abacadaeaf', 'hex'
            )
          , info = Buffer.from(
              'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8' +
              'c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1' +
              'e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fa' +
              'fbfcfdfeff', 'hex'
            )
          , gen = new hkdf('sha1', ikm, info, salt, 82)
          , okm = gen.getOKM().toString('hex')
          , prk = gen.getPRK().toString('hex')

      expect(okm).to.equal(
        '0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191f' +
        'e4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486e' +
        'a37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cf' +
        'f0d0900b52d3b4'
      )
      expect(prk).to.equal(
        '8adae09a2a307059478d309b26c4115a224cfaf6'
      )
    })
  })

  describe('A.6.  Test Case 6', () => {
    it('Test with SHA-1 and zero-length salt/info', () => {
      const ikm = Buffer.from(
            '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', 'hex'
          )
    	    , salt = Buffer.alloc(0)
          , info = Buffer.alloc(0)
          , gen = new hkdf('sha1', ikm, info, salt, 42)
          , okm = gen.getOKM().toString('hex')
          , prk = gen.getPRK().toString('hex')

      expect(okm).to.equal(
        '0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e0' +
        '7b6b87e8df21d0ea00033de03984d34918'
      )
      expect(prk).to.equal(
        'da8c8a73c7fa77288ec6f5e7c297786aa0d32d01'
      )
    })
  })

  describe('A.7.  Test Case 7', () => {
    it('Test with SHA-1, salt not provided (defaults to HashLen zero octets), zero-length info', () => {
      const ikm = Buffer.from(
            '0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c', 'hex'
          )
    	    , salt = Buffer.alloc(0)
          , info = Buffer.alloc(0)
          , gen = new hkdf('sha1', ikm, info, salt, 42)
          , okm = gen.getOKM().toString('hex')
          , prk = gen.getPRK().toString('hex')

      expect(okm).to.equal(
        '2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0' +
        'd1f27ebba6f5e5673a081d70cce7acfc48'
      )
      expect(prk).to.equal(
        '2adccada18779e7c2077ad2eb19d3f3e731385dd'
      )
    })
  })
})
