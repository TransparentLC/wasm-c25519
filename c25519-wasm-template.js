(() => {

/** @type {globalThis} */
const GLOBAL = typeof globalThis !== 'undefined' ? globalThis : (global || self);

const {
    Uint8Array,
    WebAssembly,
} = GLOBAL;

const wasmMemory = new WebAssembly.Memory({
    'initial': 0,
});
/** @type {Uint8Array} */
let wasmHeapU8;
/**
 * @param {Number} size
 */
const wasmMemoryAlloc = size => {
    const wasmMemoryLength = wasmMemory.buffer.byteLength;
    if (size <= wasmMemoryLength) return;
    wasmMemory['grow'](Math.ceil((size - wasmMemoryLength) / 65536));
    wasmHeapU8 = new Uint8Array(wasmMemory.buffer);
};
wasmMemoryAlloc(1);
const $memoryStackPointer = 0x01000;
const $memoryFreeArea = 0x01000;

/** @typedef {Number} Pointer */

/** @type {WebAssembly.Exports} */
/**
 * @type {{
 *  $$WASMEXPORTS_c25519_smult$$(sharedKey: Pointer, publicKey: Pointer, privateKey: Pointer) => void,
 *  $$WASMEXPORTS_c25519_sbasemult$$(publicKey: Pointer, privateKey: Pointer) => void,
 *  $$WASMEXPORTS_edsign_sec_to_pub$$(publicKey: Pointer, privateKey: Pointer) => void,
 *  $$WASMEXPORTS_edsign_sign$$(sign: Pointer, publicKey: Pointer, privateKey: Pointer, message: Pointer, len: Number) => void,
 *  $$WASMEXPORTS_edsign_verify$$(sign: Pointer, publicKey: Pointer, message: Pointer, len: Number) => Number,
 * }}
 */
let wasmExports;
/** @type {Promise<void>} */
const wasmReady = new Promise(resolve => WebAssembly
    .instantiate(
        Uint8Array.from(atob('$$WASM_BASE64$$'), e => e.charCodeAt()),
        {
            'env': {
                'memory': wasmMemory,
                '__memory_base': 0x0000,
                '__stack_pointer': new WebAssembly.Global(
                    {
                        'mutable': true,
                        'value': 'i32',
                    },
                    $memoryStackPointer,
                ),
            },
        }
    )
    .then(result => {
        wasmExports = result['instance']['exports'];
        resolve();
    })
);

const X25519 = {
    /**
     * @param {Uint8Array} privateKey 32 bytes
     * @returns {Uint8Array} 32 bytes
     */
    'getPublic': privateKey => {
        wasmHeapU8.set(privateKey, $memoryFreeArea);
        wasmExports['$$WASMEXPORTS_c25519_sbasemult$$']($memoryFreeArea + 32, $memoryFreeArea)
        return wasmHeapU8.slice($memoryFreeArea + 32, $memoryFreeArea + 64);
    },
    /**
     * @param {Uint8Array} publicKey 32 bytes
     * @param {Uint8Array} privateKey 32 bytes
     * @returns {Uint8Array} 32 bytes
     */
    'getShared': (publicKey, privateKey) => {
        wasmHeapU8.set(publicKey, $memoryFreeArea);
        wasmHeapU8.set(privateKey, $memoryFreeArea + 32);
        wasmExports['$$WASMEXPORTS_c25519_smult$$']($memoryFreeArea + 64, $memoryFreeArea + 32, $memoryFreeArea);
        return wasmHeapU8.slice($memoryFreeArea + 64, $memoryFreeArea + 96);
    },
    /** @type {Promise<void>} */
    'ready': wasmReady,
};

const Ed25519 = {
    /**
     * @param {Uint8Array} privateKey 32 bytes
     * @returns {Uint8Array} 32 bytes
     */
    'getPublic': privateKey => {
        wasmHeapU8.set(privateKey, $memoryFreeArea);
        wasmExports['$$WASMEXPORTS_edsign_sec_to_pub$$']($memoryFreeArea + 32, $memoryFreeArea);
        return wasmHeapU8.slice($memoryFreeArea + 32, $memoryFreeArea + 64);
    },
    /**
     * @param {Uint8Array} message
     * @param {Uint8Array} privateKey 32 bytes
     * @returns {Uint8Array} 64 bytes
     */
    'sign': (message, privateKey) => {
        wasmMemoryAlloc($memoryFreeArea + 128 + message.length);
        wasmHeapU8.set(privateKey, $memoryFreeArea);
        wasmHeapU8.set(message, $memoryFreeArea + 128);
        wasmExports['$$WASMEXPORTS_edsign_sec_to_pub$$']($memoryFreeArea + 32, $memoryFreeArea);
        wasmExports['$$WASMEXPORTS_edsign_sign$$']($memoryFreeArea + 64, $memoryFreeArea + 32, $memoryFreeArea, $memoryFreeArea + 128, message.length);
        return wasmHeapU8.slice($memoryFreeArea + 64, $memoryFreeArea + 128);
    },
    /**
     * @param {Uint8Array} message
     * @param {Uint8Array} sign 64 bytes
     * @param {Uint8Array} publicKey 32 bytes
     * @returns {Boolean}
     */
    'verify': (message, sign, publicKey) => {
        wasmMemoryAlloc($memoryFreeArea + 96 + message.length);
        wasmHeapU8.set(publicKey, $memoryFreeArea);
        wasmHeapU8.set(sign, $memoryFreeArea + 32);
        wasmHeapU8.set(message, $memoryFreeArea + 96);
        return !!wasmExports['$$WASMEXPORTS_edsign_verify$$']($memoryFreeArea + 32, $memoryFreeArea, $memoryFreeArea + 96, message.length);
    },
    /** @type {Promise<void>} */
    'ready': wasmReady,
};

if (typeof module !== 'undefined') {
    module.exports = {
        'X25519': X25519,
        'Ed25519': Ed25519,
    };
} else {
    GLOBAL['X25519'] = X25519;
    GLOBAL['Ed25519'] = Ed25519;
}

})()