# wasm-c25519

[![build](https://github.com/TransparentLC/wasm-c25519/actions/workflows/build.yml/badge.svg)](https://github.com/TransparentLC/wasm-c25519/actions/workflows/build.yml)

使用 WASM 运行的 X25519 密钥交换算法和 Ed25519 数字签名算法，预编译版可在 [Actions](https://github.com/TransparentLC/wasm-c25519/actions/workflows/build.yml) 或 [nightly.link](https://nightly.link/TransparentLC/wasm-c25519/workflows/build/master/wasm-c25519) 下载。

实现来自 [Daniel Beer 的“Curve25519 and Ed25519 for low-memory systems”](https://www.dlbeer.co.nz/oss/c25519.html)。

## 使用方式

```js
class X25519 {
    /**
     * @param {Uint8Array} privateKey 32字节的私钥
     * @returns {Uint8Array} 32字节的对应的公钥
     */
    static getPublic(privateKey) {}

    /**
     * @param {Uint8Array} publicKey 32字节的对方的公钥
     * @param {Uint8Array} privateKey 32字节的私钥
     * @returns {Uint8Array} 32字节的共享密钥
     */
    static getShared(publicKey, privateKey) {}

    /** @type {Promise<void>} 在WASM模块加载完成后fulfill的Promise */
    static ready,
}

class Ed25519 {
    /**
     * @param {Uint8Array} privateKey 32字节的私钥
     * @returns {Uint8Array} 32字节的对应的公钥
     */
    static getPublic(privateKey) {}

    /**
     * @param {Uint8Array} message 需要签名的数据
     * @param {Uint8Array} privateKey 32字节的私钥
     * @returns {Uint8Array} 64字节的签名
     */
    static sign(message, privateKey) {}

    /**
     * @param {Uint8Array} message 需要验证的数据
     * @param {Uint8Array} sign 64字节的签名
     * @param {Uint8Array} publicKey 32字节的公钥
     * @returns {Boolean}
     */
    static verify(message, sign, publicKey) {}

    /** @type {Promise<void>} 在WASM模块加载完成后fulfill的Promise */
    static ready,
}

```
<details>

<summary>试试看！</summary>

```js
// 在浏览器中加载时，名称为X25519和Ed25519
const { X25519, Ed25519 } = require('./dist/c25519-wasm.speed.min.js');

(async () => {

// 等待WASM模块异步加载完成
// 也可以使用X25519.ready.then(() => {...})
await Promise.all([X25519.ready, Ed25519.ready]);

// 以下的测试向量来自 https://datatracker.ietf.org/doc/html/rfc7748.html#section-6.1

// 双方各自的私钥
const privateA = new Uint8Array([
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
]);
const privateB = new Uint8Array([
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
    0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
    0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
]);
// 从私钥产生公钥
const publicA = X25519.getPublic(privateA);
const publicB = X25519.getPublic(privateB);
// 收到对方的公钥后得到相同的共享密钥
const sharedA = X25519.getShared(privateA, publicB);
const sharedB = X25519.getShared(privateB, publicA);
// Uint8Array(32) [74, 93, 157, 91, ...]
console.log(sharedA);
// Uint8Array(32) [74, 93, 157, 91, ...]
console.log(sharedB);

// 以下的测试向量来自 https://datatracker.ietf.org/doc/html/rfc8032#section-7.1

// 签名方的私钥和公钥
const privateC = new Uint8Array([
    0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b,
    0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7, 0xb1,
    0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b,
    0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7,
]);
const publicC = Ed25519.getPublic(privateC);
// 需要签名的消息
const messageC = new Uint8Array([0xaf, 0x82]);
// 生成的签名
const signC = Ed25519.sign(messageC, privateC);
// 对签名进行验证
// true
console.log(Ed25519.verify(messageC, signC, publicC));
// 修改消息后验证失败
messageC[0]++;
// false
console.log(Ed25519.verify(messageC, signC, publicC));
})()
```

</details>

注意事项：

* 私钥可以使用任意的 32 字节，可以使用 [`crypto.getRandomValues`](https://developer.mozilla.org/zh-CN/docs/Web/API/Crypto/getRandomValues) 生成。
* X25519 和 Ed25519 的公钥不通用。
* 内部已对私钥进行了 clamp 处理（将私钥的某几位钦定，具体数学原理参见[这里](https://www.jcraige.com/an-explainer-on-ed25519-clamping)），因此不需要手动操作。

## 编译

需要安装 [Emscripten](https://emscripten.org) 和 [Node.js](https://nodejs.org) 环境。

```bash
npm install -g terser
node build.js
```

运行后可以在 `dist` 目录找到以下文件：

* `c25519.{mode}.wasm`
* `c25519-wasm.{mode}.js`
* `c25519-wasm.{mode}.d.ts`
* `c25519-wasm.{mode}.min.js`
* `c25519-wasm.{mode}.min.d.ts`

`{mode}` 是 size 和 speed 之一，对应文件大小或运行速度的优化（也就是 Emscripten 编译时使用的 `-Oz` 或 `-O3` 参数）。使用时在浏览器 / Node.js 中加载 JS 文件即可，WASM 文件可以不保留。

运行 `node test-standard.js` 进行测试。

## 测试

以 Python 的 [`donna25519`](https://pypi.org/project/donna25519/) 和 [`ed25519`](https://pypi.org/project/donna25519/) 模块作为参考，随机生成数据进行密钥交换和签名，检查运行结果是否相同。

```bash
pip3 install donna25519==0.1.* ed25519==1.*
python3 test-massive-generate.py
node test-massive.js
```

以下测试结果是在 WSL Ubuntu 20.04 Node.js v14.15.5 下运行的，仅供参考：

| 操作 | `-O3` 版速度 | `-Oz` 版速度 |
| - | - | - |
| `X25519.getPublic` | 5.17 ms/key | 7.71 ms/key |
| `X25519.getShared` | 5.20 ms/key | 7.72 ms/key |
| `Ed25519.getPublic` | 5.21 ms/key | 7.81 ms/key |
| `Ed25519.sign` | 6142.96 bytes/ms | 3798.07 bytes/ms |
| `Ed25519.verify` | 5318.62 bytes/ms | 3435.83 bytes/ms |
