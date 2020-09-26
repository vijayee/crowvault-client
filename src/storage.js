const fs = require('fs')
const mkdirp = require('mkdirp')
const _path = new WeakMap()
const bs58 = require('bs58')
const path = require('path')
const util = require('./utility')

function _hash(buf) {
  return bs58.encode(util.hash(buf))
}
module.exports = class Storage {
  constructor(options) {
    if (typeof options === 'string') {
      options = {path: options}
    }
    mkdirp.sync(options.path)
    _path.set(this, options.path)
  }
  put(key, value, cb) {
    let hash = _hash(key)
    let fn = path.join(_path.get(this), hash)
    fs.writeFile(fn, value, (err) => {
      if (err) {
        return cb(err)
      }
      return cb(null, fn)
    })
  }
  get(key, cb) {
    let hash = _hash(key)
    let fn = path.join(_path.get(this), hash)
    fs.readFile(fn, cb)
  }
  store(value, cb) {
    let hash = _hash(value)
    let fn = path.join(_path.get(this), hash)
    fs.writeFile(fn, value, (err) => {
      if (err) {
        return cb(err)
      }
      return cb(null, hash)
    })
  }

  retrieve (hash, cb) {
    let fn = path.join(_path.get(this), hash)
    fs.readFile(fn, cb)
  }
  delete (hash, cb) {
    let fn = path.join(_path.get(this), hash)
    fs.unlink(fn, cb)
  }
  remove (buf, cb) {
    let fn = path.join(_path.get(this), bs58.encode(util.hash(buf)))
    fs.unlink(fn, cb)
  }
}