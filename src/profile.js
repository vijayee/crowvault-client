'use strict'

let _ledger = new WeakMap()
let _creationDate = new WeakMap()
let _publicKey = new WeakMap()
let _privateKey = new WeakMap()
let _cache = new WeakMap()
module.exports = class Profile {
  constructor (account) {
    if (!account) {
      _creationDate.set(this, new Date())
      _ledger.set(this, new keypair())
    } else {
      //TODO: Case for intialization from object
    }
  }

  get creationDate () {
    let date = _creationDate.get(this)
    return date
  }

  get publicKey () {
    let pub = _publicKey.get(this)
    return pub
  }
  get privateKey () {
    let priv = _privateKey.get(this)
    return priv
  }

  toPB () {
    let profile = {
      creationDate: this.creationDate.marshal(),
      publicKey: this.ledger.marshal(),
      privateKey: this.profile.marshal(),
    }
    let marsh = ipld.marshal(account)
    _cache.set(this, ipld.multihash(marsh))
    return marsh

  }
}
