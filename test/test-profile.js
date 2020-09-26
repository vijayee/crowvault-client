const test = require('tape')
const Crowvault = require('../src/index')

test('test profile creation', function (t) {
  let QAPairs = [
    { question: "Mother's Maiden Name?", answer: "Bonaparte" },
    { question: "First Pet's Name?", answer: "Rufus" },
    { question: "Am I the baddest?", answer: "Shonuff"}
  ]
  t.plan(17)
  Crowvault.register("testUser", "testtest", QAPairs, (err, deviceLogin) => {
    t.equal(err, null, 'Test no error occured during Registration')
    t.notEqual(deviceLogin, null, 'Test got a device login')
    Crowvault.login("testUser", "testtest", (err, profile) => {
      t.equal(err, null, 'Test no error occured during login')
      t.notEqual(profile, null, 'Test a profile was received')

      Crowvault.changePassword("testUser", "testtest", "testytest", (err, deviceLogin) => {
        t.equal(err, null, 'Test no error occured while changing password')
        t.notEqual(deviceLogin, null, 'Test received device login')
        Crowvault.login("testUser", "testytest", (err, profile) => {
          t.equal(err, null, 'Test no error occured logging in with new password')
          t.notEqual(profile, null, 'Test profile object was received')
          Crowvault.recover("testUser","testastic", QAPairs, (err, deviceLogin) => {
            t.equal(err, null, 'Test no error occured while recovering profile')
            t.notEqual(deviceLogin, null, 'Test got a device login')
            Crowvault.login("testUser", "testastic", (err, profile) => {
              t.equal(err, null, 'Test no error occured logging in with new password')
              t.notEqual(profile, null, 'Test profile object was received')
              let QAPairs2 = [
                { question: "What's your home planet", answer: "Melmac" },
                { question: "What's you Grandma's middle name", answer: "Lisa" },
                { question: "Am I the baddest?", answer: "Not Technically"}
              ]
              Crowvault.changeQuestions("testUser", "testastic", QAPairs2 ,() => {
                t.equal(err, null, 'Test no error occured while changing questions')
                Crowvault.recover("testUser","testastic", QAPairs2, (err, deviceLogin) => {
                  t.equal(err, null, 'Test no error occured while recovering profile')
                  t.notEqual(deviceLogin, null, 'Test got a device login')
                  Crowvault.deviceLogin(deviceLogin, (err, profile) => {
                    t.equal(err, null, 'Test no error occured during login')
                    t.notEqual(profile, null, 'Test a profile was received')
                  })
                })
              })
            })
          })
        })
      })
    })
  })
})