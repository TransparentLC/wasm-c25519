const childProcess = require('child_process');
const fs = require('fs');
const terser = require('terser');
const ReplacementCollector = require('./src/replacement-collector.js');

(async () => {

await fs.promises.rmdir('dist', { recursive: true });
await fs.promises.mkdir('dist');

const template = await fs.promises.readFile('src/c25519-wasm-template.js', { encoding: 'utf-8' });

await Promise.all([
    // ['simd', '-O3', '-msimd128', '-DWASM_SIMD_COMPAT_SLOW'],
    ['speed', '-O3'],
    ['size', '-Oz'],
].map(async e => {
    const [optimizeMode, optimizeParam, ...otherParam] = e;

    const rc = new ReplacementCollector(/__.+?__/g, {
        __WASM_BASE64__: null,
    });
    await Promise.all([
        'src/wasm/c25519.h',
        'src/wasm/edsign.h',
        'src/c25519-wasm-template.js'
    ].map(f => fs.promises.readFile(f, { encoding: 'utf-8' }).then(e => rc.collect(e)).catch(() => {})));

    console.log(`${optimizeMode} emcc output:\n`, await new Promise((resolve, reject) => childProcess.execFile(
        'emcc',
        [
            'src/wasm/c25519.c',
            'src/wasm/ed25519.c',
            'src/wasm/edsign.c',
            'src/wasm/f25519.c',
            'src/wasm/fprime.c',
            'src/wasm/memcpy.c',
            'src/wasm/memset.c',
            'src/wasm/morph25519.c',
            'src/wasm/sha512.c',
            optimizeParam,
            ...otherParam,
            ...rc.exportEmscriptenDefine(),
            '-v',
            '-flto',
            '-s', 'SIDE_MODULE=2',
            '-o', `dist/c25519.${optimizeMode}.wasm`,
        ],
        (error, stdout, stderr) => error ? reject(error) : resolve(stderr)
    )));
    rc.mapping.set('__WASM_BASE64__', (await fs.promises.readFile(`dist/c25519.${optimizeMode}.wasm`, { encoding: 'base64' })).replace(/=+$/g, ''));

    await Promise.all(['cjs', 'esm'].map(async moduleFormat => {
        const wrappedTemplate = (await fs.promises.readFile(`src/wrapper/${moduleFormat}.js`, { encoding: 'utf-8' })).replace(/\/\*\* TEMPLATE \*\*\//g, template);
        return Promise.all([
            terser.minify(wrappedTemplate, {
                ecma: 2020,
                compress: {
                    defaults: false,
                    global_defs: rc.exportTerserDefine(),
                },
                mangle: false,
                format: {
                    beautify: true,
                    comments: 'all',
                },
            })
                .then(e => fs.promises.writeFile(`dist/c25519-wasm.${optimizeMode}.${moduleFormat}.js`, e.code))
                .catch(console.log),
            terser.minify(wrappedTemplate, {
                ecma: 2020,
                module: moduleFormat === 'esm',
                compress: {
                    passes: 2,
                    unsafe_math: true,
                    unsafe_methods: true,
                    unsafe_proto: true,
                    unsafe_regexp: true,
                    unsafe_undefined: true,
                    global_defs: rc.exportTerserDefine(),
                },
                mangle: {
                    properties: {
                        keep_quoted: 'strict',
                    },
                },
                format: {
                    comments: false,
                },
            })
                .then(e => fs.promises.writeFile(`dist/c25519-wasm.${optimizeMode}.${moduleFormat}.min.js`, e.code))
                .catch(console.log),
        ]);
    }));
    await fs.promises.copyFile('src/c25519-wasm-template.d.ts', 'dist/c25519-wasm.d.ts');
}));

})();