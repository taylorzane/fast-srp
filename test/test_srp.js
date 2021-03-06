import chai, { expect } from 'chai'
import sinon from 'sinon' // eslint-disable-line no-unused-vars
import sinonChai from 'sinon-chai'
chai.use(sinonChai)

import srp from '..'
const params = srp.params[8192]

const salt = new Buffer("salt")
const identity = new Buffer("identity")
const password = new Buffer("password")
const VERIFIER = new Buffer('b86d11c479886ede87ff9227e8599978252c32298c4ea31c6d40767b97ecd7b963f94978af92de19a9379229553828f689216dae1bde4d7136f035d2fac88f6056722485147c3e5a1905ae978de057bf7d2fb711810037649361e701b13f212dee17ff99d1390cb79f4b41f86ecfa9062d471bac7ffcfbdfaa9c06258ca9b9a1e0ed9788c13ddda338717acdbff96944b53564673bee85ee1b37bb261edc78a607ef3ef75de067aa90dba60bd51c8df200ef8c17475eabfe3f7b418926b7e504bd421681bed76324ee285a21badf8768f59294a4ba1404f0e1cb4c406a22ce45596cbeb93cf902a203ef18c192e94068c0e8fdae9a408e30684507b0347fa38424e2e56d16c8a6c972d44eb18f8f331d08dee8f1a9ac913c0607cf70ff3dc66f199e4f2b5ef245d148499ac4f0495725513d1cfcf1c8281f9d61bb025652b219491ef3d0b0ac6ed2b12e91161d99c4fb84327442e4e8784fb7e010219769793207334ae0cda37d459a6f8d1f106d31b0d742985982d57bc60ba6867cfc8177fa0e2a99b53085b192cc9dfec87e54782322180b03a4246e50146a148602ac7e83fcb2da1e6321e56db509eba031fb9043e620496d0582558c9bf362a081649e0230f0caaddc4c9430b5375120d6c37eb1044e2de77c4d236592904aa0d72cdafbe28789cb84dfb1a1169d0a07c672f569f6c91d2a84bae93faacd83615bc4445ef6f085ba4032bea3b14cba6cc52e4feee8d205a831440371d2e799f8d6f041ed6bfd6d067b4a7aca6d0a8236b9341d23566163cd34856d8af112c343ad205323891a7146362c6bdf436998b21d40bdf479a4ebc9446e651141f18431a871e11a62f4618cf4744fe6b610c97c6deba20421ef8c7435e649f136fcf4970a316eab167252cfb66c728b2711d6ad220d18f00bab951c243be2b486025fa42fc3b6b452edc0847bc57c68cca6a16cea3d3473bfb54dc503163851f59a451ed4f7cda673e2930d13e1fe3f233133233dc1057649094b0751e513fefc2306aa01ee133458f6077a977a147afb23526276b6e4f6ba1d3182e95fc067f9e85ebf093a687eb1fdb6e322c611e02a9cb7cc9fa914cf0433b7d41d819ed98ae10184987203db6be38dccf5b12eeac1fe778b6209bac140e16e65595113f7dfe65f0138b17ba35ad94f80c568f39e90d41eb9680300cbde01eb8d7c57139ba870a1501c8b54b628a76b3cde5fb2ed8af8ef618f3d528475a15517aee7c594f068e6be3f85a5a818edba5acf4a0113b597a6b0853fa3e17c71cc007e0efcee98d539204b1e6c4c18885fa6cfe36f68d9361d71e5b6560a655c373ce569fddea9f0446c0fae5fb07797d9e37e3a50af1dda9d21bba86ed03afdfa9af40eda306c827c07a40689578c3ee2f2c183c6b35d6e3c84659036d437e930215d37c2fa36ec1ade8df40c47', 'hex')

describe('SRP with sha256', function() {
  this.timeout(0)
  it('computes verifier', function() {
    const expected = VERIFIER

    const verifier = srp.computeVerifier(params, salt, identity, password)
    const result = verifier

    expect(result).to.eql(expected)
  })

  it('creates a and b', function(done) {
    srp.genKey(64, function(err, a) {
      expect(err).to.be.null
      expect(a).to.be.an.instanceof(Buffer)

      srp.genKey(32, function(err, b) {
        expect(err).to.be.null
        expect(b).to.be.an.instanceof(Buffer)

        done()
      })
    })
  })

  describe('key exchange', function() {
    let a
    let b

    beforeEach(function(done) {
      srp.genKey(64, function(err, a_buf) {
        if (err) {
          throw err
        }

        a = a_buf

        srp.genKey(32, function(err, b_buf) {
          if (err) {
            throw err
          }

          b = b_buf

          done()
        })
      })
    })

    it('authenticates successfully', function() {
      const client = new srp.Client(params, salt, identity, password, a)

      // client produces A
      const A = client.computeA()

      // create server
      const server = new srp.Server(params, VERIFIER, b)

      // server produces B
      const B = server.computeB()

      // server accepts A
      server.setA(A)

      // client doesn't produce M1 too early
      expect(client.computeM1.bind(client)).to.throw(/incomplete protocol/)

      // client accepts B
      client.setB(B)

      // client produces M1 now
      client.computeM1()

      // server likes client's M1
      const serverM2 = server.checkM1(client.computeM1())

      // client and server agree on K
      const client_K = client.computeK()
      const server_K = server.computeK()
      expect(client_K).to.eql(server_K)
      // assert.equal(client_K.toString("hex"), server_K.toString("hex"))

      // server is authentic
      expect(() => client.checkM2(serverM2)).to.not.throw()
      // assert.doesNotThrow(function(){client.checkM2(serverM2)}, "M2 didn't check")
    })

    it('authenticates successfully (without `new`)', function(){
      const client = srp.Client(params, salt, identity, password, a)

      // client produces A
      const A = client.computeA()

      // create server
      const server = srp.Server(params, VERIFIER, b)

      // server produces B
      const B = server.computeB()

      // server accepts A
      server.setA(A)

      // client doesn't produce M1 too early
      expect(client.computeM1.bind(client)).to.throw(/incomplete protocol/)

      // client accepts B
      client.setB(B)

      // client produces M1 now
      client.computeM1()

      // server likes client's M1
      const serverM2 = server.checkM1(client.computeM1())

      // client and server agree on K
      const client_K = client.computeK()
      const server_K = server.computeK()
      expect(client_K).to.eql(server_K)
      // assert.equal(client_K.toString("hex"), server_K.toString("hex"))

      // server is authentic
      expect(() => client.checkM2(serverM2)).to.not.throw()
      // assert.doesNotThrow(function(){client.checkM2(serverM2)}, "M2 didn't check")
    })

    it('server rejects wrong M1', function() {
      var bad_client = new srp.Client(params, salt, identity, Buffer("bad"), a)
      var server2 = new srp.Server(params, VERIFIER, b)
      bad_client.setB(server2.computeB())
      server2.setA(bad_client.computeA())

      expect(() => server2.checkM1(bad_client.computeM1())).to.throw(/client did not use the same password/)
    }),

    it('server rejects bad A', function() {
      // client's "A" must be 1..N-1 . Reject 0 and N and N+1. We should
      // reject 2*N too, but our Buffer-length checks reject it before the
      // number itself is examined.

      var server2 = new srp.Server(params, VERIFIER, b)
      var Azero = new Buffer(params.N_length_bits/8)
      Azero.fill(0)

      var BigInteger = params.N.constructor

      var AN = params.N.add(BigInteger.ZERO).toBuffer()
      var AN1 = params.N.add(BigInteger.ONE).toBuffer()
      expect(function() {server2.setA(Azero)}).to.throw(
                    /invalid client-supplied 'A'/)
      expect(function() {server2.setA(AN)}).to.throw(
                    /A was 1025, expected 1024/)
      expect(function() {server2.setA(AN1)}).to.throw(
                    /A was 1025, expected 1024/)
    }),

    it('client rejects bad B', function() {
      // server's "B" must be 1..N-1 . Reject 0 and N and N+1
      var client2 = new srp.Client(params, salt, identity, password, a)
      var Bzero = new Buffer(params.N_length_bits/8)
      Bzero.fill(0)

      var BigInteger = params.N.constructor

      var BN = params.N.add(BigInteger.ZERO).toBuffer()
      var BN1 = params.N.add(BigInteger.ONE).toBuffer()
      expect(function() {client2.setB(Bzero)}).to.throw(
                    /invalid server-supplied 'B'/)
      expect(function() {client2.setB(BN)}).to.throw(
                    /B was 1025, expected 1024/)
      expect(function() {client2.setB(BN1)}).to.throw(
                    /B was 1025, expected 1024/)
    })

    it('client rejects bad M2', function() {
      const client = srp.Client(params, salt, identity, password, a)

      // client produces A
      const A = client.computeA()

      // create server
      const server = srp.Server(params, VERIFIER, b)

      // server produces B
      const B = server.computeB()

      // server accepts A
      server.setA(A)

      // client doesn't produce M1 too early
      expect(client.computeM1.bind(client)).to.throw(/incomplete protocol/)

      // client accepts B
      client.setB(B)

      // client produces M1 now
      client.computeM1()

      // server likes client's M1
      let serverM2 = server.checkM1(client.computeM1())

      serverM2 += 'a'

      // client and server agree on K
      const client_K = client.computeK()
      const server_K = server.computeK()
      expect(client_K).to.eql(server_K)
      // assert.equal(client_K.toString("hex"), server_K.toString("hex"))

      // server is authentic
      expect(() => client.checkM2(serverM2)).to.throw(/server is not authentic/)
      // assert.throws(function(){client.checkM2(serverM2);}, "M2 didn't check");
      // assert.doesNotThrow(function(){client.checkM2(serverM2)}, "M2 didn't check")
    })
  })
})
