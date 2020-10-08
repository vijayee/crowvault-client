const crypto = require('crypto')
const forge  = require('node-forge')
const rsa = forge.pki.rsa;
const util = require('./utility')
const path = require('path')
const fs = require('fs')
const profileProto = path.join(__dirname, 'profile.proto')
const protobuf = require('protocol-buffers')
const messages = protobuf(fs.readFileSync(profileProto))
const Storage = require('./storage')
const storage = new Storage('./Storage')
const bs58 = require('bs58')

module.exports = class Crowvault {
  static register (profileName, password, QAPairs, cb) {
    return new Promise ((resolve, reject) => {
      if(!profileName || typeof profileName !== 'string') {
        let err = new Error("Invalid Profile Name")
        reject(err)
        cb && cb(err)
        return
      }
      if(!password || typeof password !== 'string') {
        let err = new Error("Invalid Password")
        reject(err)
        cb && cb(err)
        return
      }
      if(!QAPairs || !Array.isArray(QAPairs) || QAPairs.length < 3) {
        let err = new Error("Invalid Question/Answer Pairs")
        reject(err)
        cb && cb(err)
        return
      }
      storage.get(profileName, (err, loginHash) => {
        if (!err) {
          let err = new Error("Invalid Profile Name: Duplicate")
          reject(err)
          cb && cb(err)
          return
        }
      })
      rsa.generateKeyPair({bits: 4096, workers: 2}, (err, keys) => {
        try {
          let cryptographicKey = crypto.randomBytes(util.defaultSecretKeySize)
          let privateKey = forge.pki.publicKeyToPem(keys.publicKey)
          let publicKey = forge.pki.privateKeyToPem(keys.privateKey)
          let registrationDate = (new Date()).getTime()
          let profile = { privateKey, publicKey, registrationDate }
          let profilePb = messages.Profile.encode(profile)
          let profileEnc = util.encryptAES(profilePb, cryptographicKey)

          storage.store(profileEnc, (err, fileKey) => {
            if (err) {
              reject(err)
              cb && cb(err)
              return
            }
            try {
              let salt = crypto.randomBytes(util.defaultSaltSize)
              let derivedKey = util.encryptPassword(password, salt)

              let split = util.splitThrice(derivedKey)
              let qs1 = split.one
              let qs2 = split.two
              let qs3 = split.three
              let qSalt1 = crypto.randomBytes(util.defaultSecretKeySize)
              let qSalt2 = crypto.randomBytes(util.defaultSecretKeySize)
              let qSalt3 = crypto.randomBytes(util.defaultSecretKeySize)

              let qKey1 = util.encryptPassword(QAPairs[ 0 ].answer, qSalt1)
              let qKey2 = util.encryptPassword(QAPairs[ 1 ].answer, qSalt2)
              let qKey3 = util.encryptPassword(QAPairs[ 2 ].answer, qSalt3)

              let qKenc1 = util.encryptAES(qKey1, derivedKey)
              let qKenc2 = util.encryptAES(qKey2, derivedKey)
              let qKenc3 = util.encryptAES(qKey3, derivedKey)

              let qSenc1 = util.encryptAES(qs1, qKey1)
              let qSenc2 = util.encryptAES(qs2, qKey2)
              let qSenc3 = util.encryptAES(qs3, qKey3)

              let credentials = {
                file: util.encryptAES(fileKey, derivedKey),
                password: util.encryptAES(cryptographicKey, derivedKey)
              }

              let login = {
                salt,
                credentials,
                question1: QAPairs[ 0 ].question,
                question2: QAPairs[ 1 ].question,
                question3: QAPairs[ 2 ].question,
                qSenc1,
                qSenc2,
                qSenc3,
                qSalt1,
                qSalt2,
                qSalt3,
                qKenc1,
                qKenc2,
                qKenc3
              }

              let deviceKey = crypto.randomBytes(util.defaultSecretKeySize)
              let deviceRecord = {
                password: util.encryptAES(cryptographicKey, deviceKey),
                file: util.encryptAES(fileKey, deviceKey)
              }
              let deviceRecordPb = messages.DeviceRecord.encode(deviceRecord)
              storage.store(deviceRecordPb, (err, deviceFile) => {
                if (err) {
                  reject(err)
                  cb && cb(err)
                  return
                }
                try {
                  let deviceLogin = {
                    deviceKey,
                    deviceFile
                  }
                  let deviceLoginPb = messages.DeviceLogin.encode(deviceLogin)
                  login.deviceFile = deviceFile
                  let loginpb = messages.Login.encode(login)
                  storage.store(loginpb, (err, loginKey) => {
                    if (err) {
                      reject(err)
                      cb && cb(err)
                      return
                    }
                    try {
                      let loginHash = bs58.decode(loginKey)
                      storage.put(profileName, loginHash, (err) => {
                        if (err) {
                          reject(err)
                          cb && cb(err)
                          return
                        }
                        resolve(deviceLoginPb)
                        cb && cb(null, deviceLoginPb)
                        return
                      })
                    } catch(ex) {
                      reject(ex)
                      cb && cb(ex)
                      return
                    }
                  })
                } catch (ex) {
                  reject(ex)
                  cb && cb(ex)
                  return
                }
              })
            } catch(ex) {
              reject(ex)
              cb && cb(ex)
            }
          })
        } catch (ex) {
          reject(ex)
          cb && cb(ex)
          return
        }
      })
    })
  }

  static login (profileName, password, cb)  {
    return new Promise((resolve, reject) => {
      if (!profileName || typeof profileName !== 'string') {
        let err = new Error("Invalid Profile Name")
        reject(err)
        cb && cb(err)
        return
      }
      if(!password || typeof password !== 'string') {
        let err = new Error("Invalid Password")
        reject(err)
        cb && cb(err)
        return
      }
      try {
        storage.get(profileName, (err, loginHash) => {
          if (err) {
            reject(err)
            cb && cb(err)
            return
          }
          try {
            let loginKey = bs58.encode(loginHash)
            storage.retrieve(loginKey, (err, loginPb) => {
              if (err) {
                reject(err)
                cb && cb(err)
                return
              }
              try {
                let login = messages.Login.decode(loginPb)
                let derivedKey = util.encryptPassword(password, login.salt)
                let fileKey = util.decryptAES(login.credentials.file, derivedKey).toString()
                let cryptographicKey = util.decryptAES(login.credentials.password, derivedKey)
                storage.retrieve(fileKey, (err, profileEnc) => {
                  if (err) {
                    reject(err)
                    cb && cb(err)
                    return
                  }
                  try {
                    let profilePb = util.decryptAES(profileEnc, cryptographicKey)
                    let profile = messages.Profile.decode(profilePb)
                    resolve(profile)
                    cb && cb(null, profile)
                    return
                  } catch (ex) {
                    reject(ex)
                    cb && cb(ex)
                    return
                  }
                })
              } catch (ex) {
                reject(ex)
                cb && cb(ex)
                return
              }
            })
          } catch (ex) {
            reject(ex)
            cb && cb(ex)
          }
        })
      } catch (ex) {
        reject(ex)
        cb && cb(ex)
        return
      }
    })
  }
  static deviceLogin (deviceLoginPb, cb) {
    return new Promise((resolve, reject) => {
      try {
        let deviceLogin = messages.DeviceLogin.decode(deviceLoginPb)
        storage.retrieve(deviceLogin.deviceFile.toString(), (err, deviceRecordPb) => {
          if (err) {
            reject(err)
            cb && cb(err)
            return
          }
          try {
            let deviceRecord = messages.DeviceRecord.decode(deviceRecordPb)
            let cryptographicKey = util.decryptAES(deviceRecord.password, deviceLogin.deviceKey)
            let fileKey = util.decryptAES(deviceRecord.file, deviceLogin.deviceKey).toString()

            storage.retrieve(fileKey, (err, profileEnc) => {
              if (err) {
                reject(err)
                cb && cb(err)
                return
              }
              try {
                let profilePb = util.decryptAES(profileEnc, cryptographicKey)
                let profile = messages.Profile.decode(profilePb)
                resolve(profile)
                cb && cb(null, profile)
                return
              } catch (ex) {
                reject(ex)
                cb && cb(ex)
                return
              }
            })
          } catch (ex) {
            reject(ex)
            cb && cb(ex)
            return
          }
        })
      } catch (ex) {
        reject(ex)
        cb && cb(ex)
        return
      }
    })
  }
  static changePassword (profileName, oldPassword, newPassword, cb)  {
    return new Promise((resolve, reject) => {
      if (!profileName || typeof profileName !== 'string') {
        let err = new Error("Invalid Profile Name")
        reject(err)
        cb && cb(err)
        return
      }
      if (!oldPassword || typeof oldPassword !== 'string') {
        let err = new Error("Invalid Old Password")
        reject(err)
        cb && cb(err)
        return
      }
      if (!newPassword || typeof newPassword !== 'string') {
        let err = new Error("Invalid New Password")
        reject(err)
        cb && cb(err)
        return
      }
      storage.get(profileName, (err, oldLoginHash) => {
        if (err) {
          reject(err)
          cb && cb(err)
          return
        }

        let oldLoginKey = bs58.encode(oldLoginHash)
        storage.retrieve(oldLoginKey, (err, oldLoginPb) => {
          if (err) {
            reject(err)
            cb && cb(err)
            return
          }

          let oldLogin = messages.Login.decode(oldLoginPb)
          let oldDerivedKey = util.encryptPassword(oldPassword, oldLogin.salt)
          let oldFileKey = util.decryptAES(oldLogin.credentials.file, oldDerivedKey).toString()

          let oldCryptographicKey = util.decryptAES(oldLogin.credentials.password, oldDerivedKey)
          storage.retrieve(oldFileKey, (err, oldProfileEnc) => {
            if (err) {
              reject(err)
              cb && cb(err)
              return
            }
            try {
              let oldProfilePb = util.decryptAES(oldProfileEnc, oldCryptographicKey)
              let newSalt = crypto.randomBytes(util.defaultSaltSize)
              let newDerivedKey = util.encryptPassword(newPassword, newSalt)
              let newCryptographicKey = crypto.randomBytes(util.defaultSecretKeySize)

              let newProfileEnc = util.encryptAES(oldProfilePb, newCryptographicKey)
              storage.store(newProfileEnc,(err, newFileKey) => {
                if (err) {
                  reject(err)
                  cb && cb(err)
                  return
                }
                try {
                  let split = util.splitThrice(newDerivedKey)
                  let qs1 = split.one
                  let qs2 = split.two
                  let qs3 = split.three
                  let qSalt1 = oldLogin.qSalt1
                  let qSalt2 = oldLogin.qSalt2
                  let qSalt3 = oldLogin.qSalt3

                  let qKey1 = util.decryptAES(oldLogin.qKenc1, oldDerivedKey)
                  let qKey2 = util.decryptAES(oldLogin.qKenc2, oldDerivedKey)
                  let qKey3 = util.decryptAES(oldLogin.qKenc3, oldDerivedKey)

                  let qKenc1 = util.encryptAES(qKey1, newDerivedKey)
                  let qKenc2 = util.encryptAES(qKey2, newDerivedKey)
                  let qKenc3 = util.encryptAES(qKey3, newDerivedKey)

                  let qSenc1 = util.encryptAES(qs1, qKey1)
                  let qSenc2 = util.encryptAES(qs2, qKey2)
                  let qSenc3 = util.encryptAES(qs3, qKey3)


                  let newCredentials = {
                    file: util.encryptAES(newFileKey, newDerivedKey),
                    password: util.encryptAES(newCryptographicKey, newDerivedKey)
                  }

                  let newLogin = {
                    salt: newSalt,
                    credentials: newCredentials,
                    question1: oldLogin.question1,
                    question2: oldLogin.question2,
                    question3: oldLogin.question3,
                    qSenc1,
                    qSenc2,
                    qSenc3,
                    qSalt1,
                    qSalt2,
                    qSalt3,
                    qKenc1,
                    qKenc2,
                    qKenc3
                  }

                  let newDeviceKey = crypto.randomBytes(util.defaultSecretKeySize)
                  let newDeviceRecord = {
                    password: util.encryptAES(newCryptographicKey, newDeviceKey),
                    file: util.encryptAES(newFileKey, newDeviceKey)
                  }

                  let newDeviceRecordPb = messages.DeviceRecord.encode(newDeviceRecord)
                  storage.store(newDeviceRecordPb, (err, newDeviceFile) => {
                    if (err) {
                      reject(err)
                      cb && cb(err)
                      return
                    }
                    try {
                      newLogin.deviceFile = newDeviceFile
                      let deviceLogin = {
                        deviceKey: newDeviceKey,
                        deviceFile: newDeviceFile
                      }
                      let newDeviceLoginPb =  messages.DeviceLogin.encode(deviceLogin)

                      let newLoginPb = messages.Login.encode(newLogin)
                      storage.store(newLoginPb, (err, newLoginKey) => {
                        if (err) {
                          reject(err)
                          cb && cb(err)
                          return
                        }
                        try {
                          let newLoginHash = bs58.decode(newLoginKey)
                          storage.put(profileName, newLoginHash, (err) => {
                            if (err) {
                              reject(err)
                              cb && cb(err)
                              return
                            }
                            resolve(newDeviceLoginPb)
                            cb && cb(null, newDeviceLoginPb)
                            storage.delete(oldLoginKey, (err) => {
                              if (err){
                                return console.log(err)
                              }
                            })
                            storage.delete(oldLogin.deviceFile.toString(), (err) => {
                              if (err){
                                return console.log(err)
                              }
                            })
                          })
                        } catch(ex) {
                          reject(ex)
                          cb && cb(ex)
                          return
                        }
                      })
                    } catch(ex){
                      reject(ex)
                      cb && cb(ex)
                      return
                    }
                  })
                } catch (ex) {
                  reject(ex)
                  cb && cb(ex)
                  return
                }
              })
            } catch (ex) {
              reject(ex)
              cb && cb(ex)
              return
            }
          })
        })
      })
    })
  }
  static changeQuestions (profileName, password, QAPairs, cb ) {
    return new Promise((resolve,reject) => {
      if(!profileName || typeof profileName !== 'string') {
        let err = new Error("Invalid Profile Name")
        reject(err)
        cb && cb(err)
        return
      }
      if(!password || typeof password !== 'string'){
        let err = new Error("Invalid Password")
        reject(err)
        cb && cb(err)
        return
      }
      if(!QAPairs || !Array.isArray(QAPairs) || QAPairs.length < 3){
        let err = new Error("Invalid Question/Answer Pairs")
        reject(err)
        cb && cb()
        return
      }
      storage.get(profileName, (err, oldLoginHash) => {
        if (err) {
          reject(err)
          cb && cb(err)
          return cb(err)
        }
        try {
          let oldLoginKey = bs58.encode(oldLoginHash)
          storage.retrieve(oldLoginKey, (err, oldLoginPb) => {
            if (err) {
              reject(err)
              cb && cb (err)
              return
            }
            try {
              let oldLogin = messages.Login.decode(oldLoginPb)
              let oldDerivedKey = util.encryptPassword(password, oldLogin.salt)
              let oldFileKey = util.decryptAES(oldLogin.credentials.file, oldDerivedKey).toString()
              let oldCryptographicKey = util.decryptAES(oldLogin.credentials.password, oldDerivedKey)

              let split = util.splitThrice(oldDerivedKey)
              let qs1 = split.one
              let qs2 = split.two
              let qs3 = split.three
              let qSalt1 = crypto.randomBytes(util.defaultSecretKeySize)
              let qSalt2 = crypto.randomBytes(util.defaultSecretKeySize)
              let qSalt3 = crypto.randomBytes(util.defaultSecretKeySize)

              let qKey1 = util.encryptPassword(QAPairs[0].answer, qSalt1)
              let qKey2 = util.encryptPassword(QAPairs[1].answer, qSalt2)
              let qKey3 = util.encryptPassword(QAPairs[2].answer, qSalt3)

              let qKenc1 = util.encryptAES(qKey1, oldDerivedKey)
              let qKenc2 = util.encryptAES(qKey2, oldDerivedKey)
              let qKenc3 = util.encryptAES(qKey3, oldDerivedKey)

              let qSenc1 = util.encryptAES(qs1, qKey1)
              let qSenc2 = util.encryptAES(qs2, qKey2)
              let qSenc3 = util.encryptAES(qs3, qKey3)

              let newCredentials = {
                file: util.encryptAES(oldFileKey, oldDerivedKey),
                password: util.encryptAES(oldCryptographicKey, oldDerivedKey)
              }

              let newLogin = {
                salt: oldLogin.salt,
                credentials: newCredentials,
                question1: QAPairs[0].question,
                question2: QAPairs[1].question,
                question3: QAPairs[2].question,
                qSenc1,
                qSenc2,
                qSenc3,
                qSalt1,
                qSalt2,
                qSalt3,
                qKenc1,
                qKenc2,
                qKenc3,
                deviceFile: oldLogin.deviceFile
              }
              let newLoginPb = messages.Login.encode(newLogin)
              storage.store(newLoginPb,(err, newLoginKey) => {
                if (err) {
                  reject(err)
                  cb && cb(err)
                  return
                }
                try {
                  let newLoginHash = bs58.decode(newLoginKey)
                  storage.put(profileName, newLoginHash, (err) => {
                    if (err) {
                      reject(err)
                      cb && cb(err)
                      return
                    }
                    resolve()
                    cb && cb()
                    storage.delete(oldLoginKey, (err) => {
                      if (err) {
                        return console.log(err)
                      }
                    })
                  })
                } catch (ex) {
                  reject(ex)
                  cb && cb(ex)
                  return
                }
              })
            } catch (ex) {
              reject(ex)
              cb && cb(ex)
              return
            }
          })
        } catch(ex) {
          reject(ex)
          cb && cb(ex)
          return
        }
      })
    })
  }
  static recover (profileName, newPassword, QAPairs, cb) {
    return new Promise((resolve, reject) => {
      if(!profileName || typeof profileName !== 'string'){
        let err = new Error("Invalid Profile Name")
        reject(err)
        cb && cb(err)
        return
      }
      if(!newPassword || typeof newPassword !== 'string'){
        let err = new Error("Invalid New Password")
        reject(err)
        cb && cb(err)
        return
      }
      if(!QAPairs || !Array.isArray(QAPairs) || QAPairs.length < 3){
        let err = new Error("Invalid Question/Answer Pairs")
        reject(err)
        cb && cb(err)
        return
      }
      storage.get(profileName, (err, oldLoginHash) => {
        if (err) {
          reject(err)
          cb & cb(err)
          return
        }
        try {
          let oldLoginKey = bs58.encode(oldLoginHash)
          storage.retrieve(oldLoginKey, (err, oldLoginPb) => {
            if (err) {
              reject(err)
              cb && cb(err)
              return
            }
            try {
              let oldLogin = messages.Login.decode(oldLoginPb)

              let qKey1 = util.encryptPassword(QAPairs[0].answer, oldLogin.qSalt1)
              let qKey2 = util.encryptPassword(QAPairs[1].answer, oldLogin.qSalt2)
              let qKey3 = util.encryptPassword(QAPairs[2].answer, oldLogin.qSalt3)

              let qs1 = util.decryptAES(oldLogin.qSenc1, qKey1)
              let qs2 = util.decryptAES(oldLogin.qSenc2, qKey2)
              let qs3 = util.decryptAES(oldLogin.qSenc3, qKey3)
              let oldDerivedKey = Buffer.concat([qs1, qs2, qs3])
              let oldFileKey = util.decryptAES(oldLogin.credentials.file, oldDerivedKey).toString()
              let oldCryptographicKey = util.decryptAES(oldLogin.credentials.password, oldDerivedKey)

              storage.retrieve(oldFileKey,(err, oldProfileEnc) => {
                if (err) {
                  reject(err)
                  cb && cb(err)
                  return
                }
                try {
                  let newSalt = crypto.randomBytes(util.defaultSaltSize)
                  let newDerivedKey = util.encryptPassword(newPassword, newSalt)
                  let newCryptographicKey = crypto.randomBytes(util.defaultSecretKeySize)
                  let profilePb =  util.decryptAES(oldProfileEnc, oldCryptographicKey)
                  let newProfileEnc = util.encryptAES(profilePb, newCryptographicKey)
                  storage.store(newProfileEnc, (err, newFileKey) => {
                    if (err) {
                      reject(err)
                      cb && cb(err)
                      return
                    }
                    try {
                      let newCredentials = {
                        file: util.encryptAES(newFileKey, newDerivedKey),
                        password: util.encryptAES(newCryptographicKey, newDerivedKey)
                      }

                      let split = util.splitThrice(newDerivedKey)
                      let qs1 = split.one
                      let qs2 = split.two
                      let qs3 = split.three
                      let qSalt1 = crypto.randomBytes(util.defaultSecretKeySize)
                      let qSalt2 = crypto.randomBytes(util.defaultSecretKeySize)
                      let qSalt3 = crypto.randomBytes(util.defaultSecretKeySize)

                      let qKey1 = util.encryptPassword(QAPairs[0].answer, qSalt1)
                      let qKey2 = util.encryptPassword(QAPairs[1].answer, qSalt2)
                      let qKey3 = util.encryptPassword(QAPairs[2].answer, qSalt3)

                      let qKenc1 = util.encryptAES(qKey1, newDerivedKey)
                      let qKenc2 = util.encryptAES(qKey2, newDerivedKey)
                      let qKenc3 = util.encryptAES(qKey3, newDerivedKey)

                      let qSenc1 = util.encryptAES(qs1, qKey1)
                      let qSenc2 = util.encryptAES(qs2, qKey2)
                      let qSenc3 = util.encryptAES(qs3, qKey3)

                      let newLogin = {
                        salt: newSalt,
                        credentials: newCredentials,
                        question1: QAPairs[0].question,
                        question2: QAPairs[1].question,
                        question3: QAPairs[2].question,
                        qSenc1,
                        qSenc2,
                        qSenc3,
                        qSalt1,
                        qSalt2,
                        qSalt3,
                        qKenc1,
                        qKenc2,
                        qKenc3
                      }
                      let newDeviceKey = crypto.randomBytes(util.defaultSecretKeySize)
                      let newDeviceRecord = {
                        password: util.encryptAES(newCryptographicKey, newDeviceKey),
                        file: util.encryptAES(newFileKey, newDeviceKey)
                      }

                      let newDeviceRecordPb = messages.DeviceRecord.encode(newDeviceRecord)
                      storage.store(newDeviceRecordPb, (err, newDeviceFile) => {
                        if (err) {
                          reject(err)
                          cb && cb(err)
                          return
                        }
                        try {
                          let newDeviceLogin = {
                            deviceKey: newDeviceKey,
                            deviceFile: newDeviceFile
                          }
                          let newDeviceLoginPb = messages.DeviceLogin.encode(newDeviceLogin)
                          newLogin.deviceFile = newDeviceFile
                          let newLoginPb =  messages.Login.encode(newLogin)
                          storage.store(newLoginPb , (err, newLoginKey) => {
                            if (err) {
                              reject(err)
                              cb && cb(err)
                              return
                            }
                            try {
                              let newLoginHash = bs58.decode(newLoginKey)
                              storage.put(profileName, newLoginHash , (err) => {
                                if (err) {
                                  reject(err)
                                  cb && cb(err)
                                  return
                                }
                                resolve(newDeviceLoginPb)
                                cb && cb(null, newDeviceLoginPb)
                                storage.delete(oldLoginKey, (err) => {
                                  if (err){
                                    return console.log(err)
                                  }
                                })
                                storage.delete(oldLogin.deviceFile.toString(), (err) => {
                                  if (err){
                                    return console.log(err)
                                  }
                                })
                              })
                            } catch (ex) {
                              reject(ex)
                              cb && cb(ex)
                              return
                            }
                          })
                        } catch (ex) {
                          reject(ex)
                          cb && cb(ex)
                          return
                        }
                      })
                    } catch (ex) {
                      reject(ex)
                      cb && cb(ex)
                      return
                    }
                  })
                } catch(ex) {
                  reject(ex)
                  cb && cb(ex)
                  return
                }
              })
            } catch (ex) {
              reject(ex)
              cb && cb(ex)
              return
            }
          })
        } catch (ex) {
          reject(ex)
          cb && cb(ex)
          return
        }
      })
    })
  }
  static recoveryQuestions(profileName, cb)  {
    return new Promise((resolve, reject) => {
      if (!profileName || typeof profileName !== 'string') {
        let err = new Error("Invalid Profile Name")
        reject(err)
        cb && cb(err)
        return
      }
      try {
        storage.get(profileName, (err, loginHash) => {
          if (err) {
            reject(err)
            cb && cb(err)
            return
          }
          try {
            let loginKey = bs58.encode(loginHash)
            storage.retrieve(loginKey, (err, loginPb) => {
              if (err) {
                reject(err)
                cb && cb(err)
                return
              }
              try {
                let login = messages.Login.decode(loginPb)
                let questions = [login.question1, login.question2, login.question3]
                resolve(questions)
                cb && cb(null, questions)
                return
              } catch (ex) {
                reject(ex)
                cb && cb(ex)
                return
              }
            })
          } catch (ex) {
            reject(ex)
            cb && cb(ex)
          }
        })
      } catch (ex) {
        reject(ex)
        cb && cb(ex)
        return
      }
    })
  }
}