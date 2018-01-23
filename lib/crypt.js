/*IMPORT_CRYPTO*/
import scrypt from 'scryptsy'

var ScryptHash = function() {
    return {
        _digest: null,
        update(data) {
            if (!this._digest) {
                if (Buffer.isBuffer(data)) {
                    this._digest = data
                } else {
                    this._digest = new Buffer(data.normalize('NFKC'), 'utf8')
                }
            } else {
                if (Buffer.isBuffer(data)) {
                    this._digest = Buffer.concat([this._digest, data])
                } else {
                    this._digest = Buffer.concat([this._digest, new Buffer(data.normalize('NFKC'), 'utf8')])
                }
            }

            return this
        },
        digest(encoding) {
            var salt = new Buffer(crypt.randomBytes(32), 'utf8')

            // TODO: Allow this to be customizable
            // FIXME: Update the salt to something longer
            return scrypt(this._digest, new Buffer('NaCl'), 32768, 8, 1, 32)
        }
    }
}

var crypt = {}
if (typeof window == 'undefined') {
    crypt = {
        createHash(hash) {
            if (hash === 'scrypt') {
                return new ScryptHash
            } else {
                return crypt_.createHash(hash)
            }
        },
        randomBytes: crypt_.randomBytes
    }
} else {
    crypt = {
        createHash() {
            return new ScryptHash
        },
        // TODO: Update this to use the polyfill from crypto-browserify
        randomBytes(size, callback) {
            var values = window.crypto.getRandomValues(new Uint8Array(size))

            if (callback && typeof callback === 'function') {
                callback(null, values)
            } else {
                return values
            }
        }
    }
}

export default crypt
