const crypto = require('crypto')
const scrypt = require('scryptsy')
const _defaultSecretKeySize = 32
const _defaultSaltSize = 32
const _defaultAESCipher = 'aes-256-cbc'
var util = {}

util.defaultSecretKeySize = _defaultSecretKeySize
util.defaultSaltSize = _defaultSaltSize
util.defaultAESCipher = _defaultAESCipher

util.encryptAES = (buf, key)=> {
  const cipher = crypto.createCipher(_defaultAESCipher, key)
  let enc = cipher.update(buf)
  return Buffer.concat([enc, cipher.final()])
}
util.decryptAES = (buf, key)=> {
  const decipher = crypto.createDecipher(_defaultAESCipher, key);
  let dec = decipher.update(buf)
  return Buffer.concat([dec, decipher.final()])
}
util.encryptPassword = (password, salt) => {
  enc = scrypt(password, salt, 16384, 8, 1, 32)
  return enc
}
util.hash = (data) => {
  let hash = crypto.createHash('sha256', { digestLength: 32 })
  hash.update(data)
  return hash.digest()
}
util.splitThrice = (buf) => {
  let pad = buf.length % 3
  let step = Math.floor(buf.length / 3)
  let step1 = step
  let step2 = (step * 2)
  let step3 = (step * 3) + pad
  return { one: buf.slice(0, step1), two: buf.slice(step1, step2), three: buf.slice(step2, step3) }
}

module.exports = util