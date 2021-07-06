import base64
import donna25519
import ed25519
import os
import random

def bytesToUint8ArrayFromBase64(data: bytes) -> str:
    return 'Uint8Array.from(atob(\'' + base64.b64encode(data).decode('utf-8') + '\'),e=>e.charCodeAt())'

testTemplate = '''
    if (typeof btoa === 'undefined') {
        global.btoa = str => Buffer.from(str, 'binary').toString('base64');
    }

    if (typeof atob === 'undefined') {
        global.atob = b64Encoded => Buffer.from(b64Encoded, 'base64').toString('binary');
    }

    const {
        X25519: X25519Size,
        Ed25519: Ed25519Size,
    } = require('./dist/c25519-wasm.size.min.js');
    const {
        X25519: X25519Speed,
        Ed25519: Ed25519Speed,
    } = require('./dist/c25519-wasm.speed.min.js');
    const { performance } = require('perf_hooks');

    let timeStart, timeEnd;

    (async () => {

    for (const [X25519, Ed25519] of [
        [X25519Size, Ed25519Size],
        [X25519Speed, Ed25519Speed],
    ]) {
        await Promise.all([
            X25519.ready,
            Ed25519.ready,
        ]);

        let x25519PublicTime = 0;
        let x25519SharedTime = 0;
        let x25519PublicCounter = 0;
        let x25519SharedCounter = 0;
        let privateA, privateB, publicA, publicB, sharedA, sharedB;
        /* X25519 Test Code */
        console.log(`Finished X25519.getPublic tests (${x25519PublicCounter}) in ${x25519PublicTime}ms, ${x25519PublicTime / x25519PublicCounter} ms/key`);
        console.log(`Finished X25519.getShared tests (${x25519SharedCounter}) in ${x25519SharedTime}ms, ${x25519SharedTime / x25519SharedCounter} ms/key`);

        let ed25519PublicTime = 0;
        let ed25519SignTime = 0;
        let ed25519VerifyTime = 0;
        let ed25519PublicCounter = 0;
        let ed25519SignCounter = 0;
        let ed25519VerifyCounter = 0;
        let privateC, publicC, messageC, signC, verifyC;
        /* Ed25519 Test Code */
        console.log(`Finished Ed25519.getPublic tests (${ed25519PublicCounter}) in ${ed25519PublicTime}ms, ${ed25519PublicTime / ed25519PublicCounter} ms/key`);
        console.log(`Finished Ed25519.sign tests (${ed25519SignCounter}) in ${ed25519SignTime}ms, ${ed25519SignCounter / ed25519SignTime} bytes/ms`);
        console.log(`Finished Ed25519.verify tests (${ed25519VerifyCounter}) in ${ed25519VerifyTime}ms, ${ed25519VerifyCounter / ed25519VerifyTime} bytes/ms`);
    }

    })();
'''

x25519TestCode = ''
ed25519TestCode = ''
for i in range(512):
    privateA = donna25519.PrivateKey()
    publicA = privateA.get_public()
    privateB = donna25519.PrivateKey()
    publicB = privateB.get_public()
    shared = privateA.do_exchange(publicB)
    x25519TestCode += f'''
        privateA = {bytesToUint8ArrayFromBase64(privateA.private)};
        privateB = {bytesToUint8ArrayFromBase64(privateB.private)};
        timeStart = performance.now();
        publicA = X25519.getPublic(privateA);
        publicB = X25519.getPublic(privateB);
        timeEnd = performance.now();
        x25519PublicTime += timeEnd - timeStart;
        x25519PublicCounter += 2;
        timeStart = performance.now();
        sharedA = X25519.getShared(privateA, publicB);
        sharedB = X25519.getShared(privateB, publicA);
        timeEnd = performance.now();
        x25519SharedTime += timeEnd - timeStart;
        x25519SharedCounter += 2;
        if (![
            Buffer.from({bytesToUint8ArrayFromBase64(publicA.public)}).equals(Buffer.from(publicA)),
            Buffer.from({bytesToUint8ArrayFromBase64(publicB.public)}).equals(Buffer.from(publicB)),
            Buffer.from({bytesToUint8ArrayFromBase64(shared)}).equals(Buffer.from(sharedA)),
            Buffer.from({bytesToUint8ArrayFromBase64(shared)}).equals(Buffer.from(sharedB)),
        ].every(Boolean)) throw new Error('Test failed');
    '''
for i in range(256):
    privateC, publicC = ed25519.create_keypair()
    messageC = os.urandom(random.randint(1, 131072))
    signC = privateC.sign(messageC)
    ed25519TestCode += f'''
        privateC = {bytesToUint8ArrayFromBase64(privateC.to_seed())};
        messageC = {bytesToUint8ArrayFromBase64(messageC)};
        timeStart = performance.now();
        publicC = Ed25519.getPublic(privateC);
        timeEnd = performance.now();
        ed25519PublicTime += timeEnd - timeStart;
        ed25519PublicCounter++;
        timeStart = performance.now();
        signC = Ed25519.sign(messageC, privateC);
        timeEnd = performance.now();
        ed25519SignTime += timeEnd - timeStart;
        ed25519SignCounter += messageC.length;
        timeStart = performance.now();
        verifyC = Ed25519.verify(messageC, signC, publicC);
        timeEnd = performance.now();
        ed25519VerifyTime += timeEnd - timeStart;
        ed25519VerifyCounter += messageC.length;
        if (![
            Buffer.from({bytesToUint8ArrayFromBase64(publicC.to_bytes())}).equals(Buffer.from(publicC)),
            Buffer.from({bytesToUint8ArrayFromBase64(signC)}).equals(Buffer.from(signC)),
            verifyC,
        ].every(Boolean)) throw new Error('Test failed');
    '''

with open('test-massive.js', 'w') as f:
    f.write(
        testTemplate
            .replace('/* X25519 Test Code */', x25519TestCode)
            .replace('/* Ed25519 Test Code */', ed25519TestCode)
    )
