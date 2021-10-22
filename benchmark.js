if (typeof btoa === 'undefined') {
    global.btoa = str => Buffer.from(str, 'binary').toString('base64');
}

if (typeof atob === 'undefined') {
    global.atob = b64Encoded => Buffer.from(b64Encoded, 'base64').toString('binary');
}

const { performance } = require('perf_hooks');

const crypto = require('crypto');
const {
    X25519: X25519Size,
    Ed25519: Ed25519Size,
} = require('./dist/c25519-wasm.size.cjs.min.js');
const {
    X25519: X25519Speed,
    Ed25519: Ed25519Speed,
} = require('./dist/c25519-wasm.speed.cjs.min.js');
const x25519PrivateKeyPkcs8Header = Buffer.from('302e020100300506032b656e04220420', 'hex');
const x25519PublicKeySpkiHeader = Buffer.from('302a300506032b656e032100', 'hex');
const ed25519PrivateKeyPkcs8Header = Buffer.from('302e020100300506032b657004220420', 'hex');
const ed25519PublicKeySpkiHeader = Buffer.from('302a300506032b6570032100', 'hex');

(async () => {

for (const [X25519, Ed25519] of [
    [X25519Size, Ed25519Size],
    [X25519Speed, Ed25519Speed],
]) {
    await Promise.all([
        X25519.ready,
        Ed25519.ready,
    ]);

    console.time('X25519 standard test');

    // Test vector from:
    // https://datatracker.ietf.org/doc/html/rfc7748.html#section-6.1
    const privateA = Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', 'hex');
    const privateB = Buffer.from('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', 'hex');
    const publicA = X25519.getPublic(privateA);
    const publicB = X25519.getPublic(privateB);
    console.assert(Buffer.from(publicA).toString('hex') === '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'Public A');
    console.assert(Buffer.from(publicB).toString('hex') === 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f', 'Public B');
    const sharedA = X25519.getShared(privateA, publicB);
    const sharedB = X25519.getShared(privateB, publicA);
    console.assert(Buffer.from(sharedA).toString('hex') === '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742', 'Shared A');
    console.assert(Buffer.from(sharedB).toString('hex') === '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742', 'Shared B');

    // Test vector from:
    // https://github.com/TomCrypto/pycurve25519/blob/master/test_curve25519.py
    const privateC = Buffer.from('a8abababababababababababababababababababababababababababababab6b', 'hex');
    const privateD = Buffer.from('c8cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd4d', 'hex');
    const publicC = X25519.getPublic(privateC);
    const publicD = X25519.getPublic(privateD);
    console.assert(Buffer.from(publicC).toString('hex') === 'e3712d851a0e5d79b831c5e34ab22b41a198171de209b8b8faca23a11c624859', 'Public C');
    console.assert(Buffer.from(publicD).toString('hex') === 'b5bea823d9c9ff576091c54b7c596c0ae296884f0e150290e88455d7fba6126f', 'Public D');
    const sharedC = X25519.getShared(privateC, publicD);
    const sharedD = X25519.getShared(privateD, publicC);
    console.assert(Buffer.from(sharedC).toString('hex') === '235101b705734aae8d4c2d9d0f1baf90bbb2a8c233d831a80d43815bb47ead10', 'Shared C');
    console.assert(Buffer.from(sharedD).toString('hex') === '235101b705734aae8d4c2d9d0f1baf90bbb2a8c233d831a80d43815bb47ead10', 'Shared D');

    console.timeEnd('X25519 standard test');

    console.time('Ed25519 standard test');

    // Test vectors from:
    // https://datatracker.ietf.org/doc/html/rfc8032#section-7.1
    const privateE = Buffer.from('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', 'hex');
    const messageE = Buffer.from('72', 'hex');
    const publicE = Ed25519.getPublic(privateE);
    console.assert(Buffer.from(publicE).toString('hex') === '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', 'Public E');
    const signE = Ed25519.sign(messageE, privateE);
    console.assert(
        Buffer.from(signE).toString('hex') === '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
        'Sign E'
    );
    const verifyE = Ed25519.verify(messageE, signE, publicE);
    console.assert(verifyE, 'Verify E');

    const privateF = Buffer.from('c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7', 'hex');
    const messageF = Buffer.from('af82', 'hex');
    const publicF = Ed25519.getPublic(privateF);
    console.assert(Buffer.from(publicF).toString('hex') === 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'Public F');
    const signF = Ed25519.sign(messageF, privateF);
    console.assert(
        Buffer.from(signF).toString('hex') === '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
        'Sign F'
    );
    const verifyF = Ed25519.verify(messageF, signF, publicF);
    console.assert(verifyF, 'Verify F');

    const privateG = Buffer.from('833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42', 'hex');
    const messageG = Buffer.from(''
        + 'ddaf35a193617abacc417349ae204131'
        + '12e6fa4e89a97ea20a9eeee64b55d39a'
        + '2192992a274fc1a836ba3c23a3feebbd'
        + '454d4423643ce80e2a9ac94fa54ca49f',
        'hex'
    );
    const publicG = Ed25519.getPublic(privateG);
    console.assert(Buffer.from(publicG).toString('hex') === 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf', 'Public G');
    const signG = Ed25519.sign(messageG, privateG);
    console.assert(
        Buffer.from(signG).toString('hex') === 'dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704',
        'Sign G'
    );
    const verifyG = Ed25519.verify(messageG, signG, publicG);
    console.assert(verifyG, 'Verify G');

    const privateH = Buffer.from('f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5', 'hex');
    const messageH = Buffer.from(''
        + '08b8b2b733424243760fe426a4b54908'
        + '632110a66c2f6591eabd3345e3e4eb98'
        + 'fa6e264bf09efe12ee50f8f54e9f77b1'
        + 'e355f6c50544e23fb1433ddf73be84d8'
        + '79de7c0046dc4996d9e773f4bc9efe57'
        + '38829adb26c81b37c93a1b270b20329d'
        + '658675fc6ea534e0810a4432826bf58c'
        + '941efb65d57a338bbd2e26640f89ffbc'
        + '1a858efcb8550ee3a5e1998bd177e93a'
        + '7363c344fe6b199ee5d02e82d522c4fe'
        + 'ba15452f80288a821a579116ec6dad2b'
        + '3b310da903401aa62100ab5d1a36553e'
        + '06203b33890cc9b832f79ef80560ccb9'
        + 'a39ce767967ed628c6ad573cb116dbef'
        + 'efd75499da96bd68a8a97b928a8bbc10'
        + '3b6621fcde2beca1231d206be6cd9ec7'
        + 'aff6f6c94fcd7204ed3455c68c83f4a4'
        + '1da4af2b74ef5c53f1d8ac70bdcb7ed1'
        + '85ce81bd84359d44254d95629e9855a9'
        + '4a7c1958d1f8ada5d0532ed8a5aa3fb2'
        + 'd17ba70eb6248e594e1a2297acbbb39d'
        + '502f1a8c6eb6f1ce22b3de1a1f40cc24'
        + '554119a831a9aad6079cad88425de6bd'
        + 'e1a9187ebb6092cf67bf2b13fd65f270'
        + '88d78b7e883c8759d2c4f5c65adb7553'
        + '878ad575f9fad878e80a0c9ba63bcbcc'
        + '2732e69485bbc9c90bfbd62481d9089b'
        + 'eccf80cfe2df16a2cf65bd92dd597b07'
        + '07e0917af48bbb75fed413d238f5555a'
        + '7a569d80c3414a8d0859dc65a46128ba'
        + 'b27af87a71314f318c782b23ebfe808b'
        + '82b0ce26401d2e22f04d83d1255dc51a'
        + 'ddd3b75a2b1ae0784504df543af8969b'
        + 'e3ea7082ff7fc9888c144da2af58429e'
        + 'c96031dbcad3dad9af0dcbaaaf268cb8'
        + 'fcffead94f3c7ca495e056a9b47acdb7'
        + '51fb73e666c6c655ade8297297d07ad1'
        + 'ba5e43f1bca32301651339e22904cc8c'
        + '42f58c30c04aafdb038dda0847dd988d'
        + 'cda6f3bfd15c4b4c4525004aa06eeff8'
        + 'ca61783aacec57fb3d1f92b0fe2fd1a8'
        + '5f6724517b65e614ad6808d6f6ee34df'
        + 'f7310fdc82aebfd904b01e1dc54b2927'
        + '094b2db68d6f903b68401adebf5a7e08'
        + 'd78ff4ef5d63653a65040cf9bfd4aca7'
        + '984a74d37145986780fc0b16ac451649'
        + 'de6188a7dbdf191f64b5fc5e2ab47b57'
        + 'f7f7276cd419c17a3ca8e1b939ae49e4'
        + '88acba6b965610b5480109c8b17b80e1'
        + 'b7b750dfc7598d5d5011fd2dcc5600a3'
        + '2ef5b52a1ecc820e308aa342721aac09'
        + '43bf6686b64b2579376504ccc493d97e'
        + '6aed3fb0f9cd71a43dd497f01f17c0e2'
        + 'cb3797aa2a2f256656168e6c496afc5f'
        + 'b93246f6b1116398a346f1a641f3b041'
        + 'e989f7914f90cc2c7fff357876e506b5'
        + '0d334ba77c225bc307ba537152f3f161'
        + '0e4eafe595f6d9d90d11faa933a15ef1'
        + '369546868a7f3a45a96768d40fd9d034'
        + '12c091c6315cf4fde7cb68606937380d'
        + 'b2eaaa707b4c4185c32eddcdd306705e'
        + '4dc1ffc872eeee475a64dfac86aba41c'
        + '0618983f8741c5ef68d3a101e8a3b8ca'
        + 'c60c905c15fc910840b94c00a0b9d0',
        'hex'
    );
    const publicH = Ed25519.getPublic(privateH);
    console.assert(Buffer.from(publicH).toString('hex') === '278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e', 'Public H');
    const signH = Ed25519.sign(messageH, privateH);
    console.assert(
        Buffer.from(signH).toString('hex') === '0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03',
        'Sign D'
    );
    const verifyH = Ed25519.verify(messageH, signH, publicH);
    console.assert(verifyH, 'Verify H');

    // Long message (more than 64 KB) test
    const privateI = Buffer.from('462cb5313d7750d38416df62931cd826a3657267ecf062dfc81bdfb13539ba10', 'hex');
    const messageI = Buffer.from('00'.repeat(114514), 'hex');
    const publicI = Ed25519.getPublic(privateI);
    console.assert(Buffer.from(publicI).toString('hex') === '53717a5e0051b029235237e6f7b44bc002b69ddd0414c78e0e746a6380bc991f', 'Public I');
    const signI = Ed25519.sign(messageI, privateI);
    console.assert(
        Buffer.from(signI).toString('hex') === '1caab6b17bfb2283cf6faffe27e9a06c38b73140f2496f6bb9149907fc39133cd16d0266ac5884a1c0d4f0986e3357820f388c0b06d9486b5723387cef530d04',
        'Sign I'
    );
    const verifyI = Ed25519.verify(messageI, signI, publicI);
    console.assert(verifyI, 'Verify I');

    const privateJ = Buffer.from('19d4910fde31bd187e983b86290e528601a893929e48e2695a2d58cb38fa223c', 'hex');
    const messageJ = Buffer.from('00'.repeat(1919810), 'hex');
    const publicJ = Ed25519.getPublic(privateJ);
    console.assert(Buffer.from(publicJ).toString('hex') === '70507c89cbb93c30b08396043eb18e462ca16d19f936ba428009033bb608750e', 'Public J');
    const signJ = Ed25519.sign(messageJ, privateJ);
    console.assert(
        Buffer.from(signJ).toString('hex') === '4148aff47ff0c79e8be5782d6681c6aee99b868fa289b50073aed05200b02958cca7b4817b452f76a36181be5cbe448a61ea4e1c9353d5ec19768a4e2cf4a302',
        'Sign J'
    );
    const verifyJ = Ed25519.verify(messageJ, signJ, publicJ);
    console.assert(verifyJ, 'Verify J');

    console.timeEnd('Ed25519 standard test');
}

for (const [X25519, Ed25519] of [
    [X25519Size, Ed25519Size],
    [X25519Speed, Ed25519Speed],
]) {
    await Promise.all([
        X25519.ready,
        Ed25519.ready,
    ]);

    let timeStart, timeEnd;

    const x25519TestCount = 128;
    let x25519PublicTime = 0;
    let x25519SharedTime = 0;
    for (let i = 0; i < x25519TestCount; i++) {
        const {
            privateKey: privateKeyA,
            publicKey: publicKeyA,
        } = crypto.generateKeyPairSync('x25519');
        const {
            privateKey: privateKeyB,
            publicKey: publicKeyB,
        } = crypto.generateKeyPairSync('x25519');
        const sharedKeyNodeA = crypto.diffieHellman({
            privateKey: privateKeyA,
            publicKey: publicKeyB,
        });
        const sharedKeyNodeB = crypto.diffieHellman({
            privateKey: privateKeyB,
            publicKey: publicKeyA,
        });

        const privateKeyNodeA = privateKeyA.export({ format: 'der', type: 'pkcs8' }).subarray(x25519PrivateKeyPkcs8Header.length);
        const privateKeyNodeB = privateKeyB.export({ format: 'der', type: 'pkcs8' }).subarray(x25519PrivateKeyPkcs8Header.length);
        const publicKeyNodeA = publicKeyA.export({ format: 'der', type: 'spki' }).subarray(x25519PublicKeySpkiHeader.length);
        const publicKeyNodeB = publicKeyB.export({ format: 'der', type: 'spki' }).subarray(x25519PublicKeySpkiHeader.length);

        timeStart = performance.now();
        const sharedKeyWasmA = X25519.getShared(privateKeyNodeA, publicKeyNodeB);
        const sharedKeyWasmB = X25519.getShared(privateKeyNodeB, publicKeyNodeA);
        timeEnd = performance.now();
        x25519SharedTime += timeEnd - timeStart;

        timeStart = performance.now();
        const publicKeyWasmA = X25519.getPublic(privateKeyNodeA);
        const publicKeyWasmB = X25519.getPublic(privateKeyNodeB);
        timeEnd = performance.now();
        x25519PublicTime += timeEnd - timeStart;

        if (![
            Buffer.from(publicKeyWasmA).equals(publicKeyNodeA),
            Buffer.from(publicKeyWasmB).equals(publicKeyNodeB),
            Buffer.from(sharedKeyWasmA).equals(sharedKeyNodeA),
            Buffer.from(sharedKeyWasmB).equals(sharedKeyNodeB),
            sharedKeyNodeA.equals(sharedKeyNodeB),
        ].every(Boolean)) throw new Error('Test failed');
    }

    console.log(`Finished ${x25519TestCount * 2} X25519.getPublic tests in ${x25519PublicTime}ms, ${x25519PublicTime / (x25519TestCount * 2)} ms/op`);
    console.log(`Finished ${x25519TestCount * 2} X25519.getShared tests in ${x25519SharedTime}ms, ${x25519SharedTime / (x25519TestCount * 2)} ms/op`);

    const ed25519TestCount = 128;
    const ed25519TestMessageLength = 16384;
    let ed25519PublicTime = 0;
    let ed25519SignTime = 0;
    let ed25519VerifyTime = 0;
    for (let i = 0; i < ed25519TestCount; i++) {
        const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
        const message = crypto.randomBytes(ed25519TestMessageLength);

        const privateKeyNode = privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(ed25519PrivateKeyPkcs8Header.length);
        const publicKeyNode = publicKey.export({ format: 'der', type: 'spki' }).subarray(ed25519PublicKeySpkiHeader.length);
        const signNode = crypto.sign(null, message, privateKey);
        const verifyNode = crypto.verify(null, message, publicKey, signNode);

        timeStart = performance.now();
        const publicKeyWasm = Ed25519.getPublic(privateKeyNode);
        timeEnd = performance.now();
        ed25519PublicTime += timeEnd - timeStart;

        timeStart = performance.now();
        const signWasm = Ed25519.sign(message, privateKeyNode);
        timeEnd = performance.now();
        ed25519SignTime += timeEnd - timeStart;

        timeStart = performance.now();
        const verifyWasm = Ed25519.verify(message, signWasm, publicKeyWasm);
        timeEnd = performance.now();
        ed25519VerifyTime += timeEnd - timeStart;

        if (![
            Buffer.from(publicKeyWasm).equals(publicKeyNode),
            Buffer.from(signWasm).equals(signNode),
            verifyNode,
            verifyWasm,
        ].every(Boolean)) throw new Error('Test failed');
    }

    console.log(`Finished ${ed25519TestCount} Ed25519.getPublic tests in ${ed25519PublicTime}ms, ${ed25519PublicTime / ed25519TestCount} ms/op`);
    console.log(`Finished ${ed25519TestCount} Ed25519.sign tests in ${ed25519SignTime}ms, ${ed25519SignTime / ed25519TestCount} ms/op`);
    console.log(`Finished ${ed25519TestCount} Ed25519.verify tests in ${ed25519VerifyTime}ms, ${ed25519VerifyTime / ed25519TestCount} ms/op`);
    console.log(`Message length: ${ed25519TestMessageLength} bytes`);

}
})();
