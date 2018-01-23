import chai, { expect } from 'chai'
import sinon from 'sinon' // eslint-disable-line no-unused-vars
import sinonChai from 'sinon-chai'
chai.use(sinonChai)

import srp from '..'
const params = srp.params['scrypt_8192']

const salt = new Buffer("salt")
const identity = new Buffer("identity")
const password = new Buffer("password")
const VERIFIER = new Buffer('cc7f4db4411dedd257feb0aa9c6617cb5e5ce8f2303712d3f477d4fa82f139c159b68fe2f9ce2524ec8d5e8c0f576fcd32500d02076c60915938fc87775704f8fd8d21869e83c2929c593a0966d23b6fa3548a0dc93d833569368df34157998326afb1e07f1cb7b3ab27659ac8805984956801bd81f978c8ee7ddc22ba84e91c6ebf64200523e99e404a373e9cbc1a2255ca28ac5dc5e39be19105b51d3ee5224d18d284dc1681aa5144705066a068b0d4d5c3eb12abebb7d2b2b4db27dc24f37f576ba06dcaa14462e8175b6e62f4e9779701a9c14db6bf58ecaf92e6bd2c54ad67762893912406107f46d587925582916295f74e590adfbd434e44fb250d3d2d285396d0eac34ecd34a003ceabd96511156ef4eb1f353ac388df5b1fcd87e0b89690f26fe5b766c5b5ae1ea54a3d36fbccc5c882a0e6e04e1dbf03230e80b60e65851be541b9a61b5a32431972511b34bcd8d467d0b6c6847a9165a90f1d76768fa3dc462f02da3162db89272c2eeaeb23cdaf22fd79f9c15fb2946c03915b626418f79442ebd5e8238b8a6323b2da05a475ba3b427659855c739219daef757b38619d8682645d88073ba66399af17fa3dc64062564f033ea80657bda8249f33def0992773c93f6a90e124baeeb288ca5ff13baef8adcdfd5e4805e5dbb90b8cd041b4e2265fb741be94e273ee5847a6d9c3fca60d4c69c2f3efcf415b2dca3a7373b970d22625da3612bf08b4e9e79624f6a043d24879a3400823135b087834aae2fa0b1c5e3ca78b2b2eff88d83c280da221d55941eda01e65e7331575a490dc7eae05b57d54636d1b006f60902f145aa9813251070b3f160f4f53029c60490c364004c5310b9f531991cc23835ad38ba8a5f78c3f0ddd1190c6358387eea2fa969223ed76e7454a65102b8c797f16e2936ab157829c86982d013046f785658de216973907f6dbe5676d08d240fa024ba10e3d175086584493a12c938fa68b4b85f4b3cb639a04f27eb42da4b0ff1fc9e2e4887850b4e57b926c383797d19588368157a93f54dc65572117aa2a9166c6eedf3c36043e2538dd5aa37afdd0dd6adfe52ff8a99b2d21eae794b1becd3589b317e40817b80c12f1d567e7f29b0db92c20df5cb5d3aff51feefabd794f4e6045e302dba4f8e2e632565011f4da975965133b625cd42bc75948d981f9d638f9a5b8e111255e35d8db85007816bf3c0bb09396cd4686e1b12d5cac98c8292b2bf26f801969d1a91cf22982a331e47e9553e03fba6fc91c802140f149b8b478cb597513f523f9be8b06158cec6460a28142354ecf1ed4b1984e2e230ab45daa45f7dac2c809ca0586159299d9ad46635e6fff5a5ba8feec64a7c23e96e051f74e86f661065d957d1e65da1224fbd9bbd2ab72eed6c9c71e3ca9b1e4de87595f439e6d11a8ad1c213dcd38f38f7bd7', 'hex')

describe('SRP with scrypt', function() {
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
