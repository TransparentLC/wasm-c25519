const childProcess = require('child_process');
const fs = require('fs');
const path = require('path');
const terser = require('terser');
const ReplacementCollector = require('./src/replacement-collector.js');

(async () => {

await fs.promises.rm('dist', { recursive: true, force: true });
await fs.promises.mkdir('dist');

/** @type {String} */
const emccPath = (await new Promise((resolve, reject) => childProcess.execFile(
    process.platform === 'win32' ? 'where' : 'which', ['emcc'],
    (error, stdout, stderr) => error ? reject(error) : resolve(stdout)
))).split('\n').map(e => e.trim())[0];
const wasmdisPath = path.dirname(emccPath) + '/../bin/wasm-dis';
const wasmoptPath = path.dirname(emccPath) + '/../bin/wasm-opt';

const template = await fs.promises.readFile('src/c25519-wasm-template.js', { encoding: 'utf-8' });
await fs.promises.copyFile('src/c25519-wasm-template.d.ts', 'dist/c25519-wasm.d.ts');

await Promise.all([
    // ['simd', '-O3', '-msimd128', '-DWASM_SIMD_COMPAT_SLOW'],
    ['speed', '-O3'],
    ['size', '-Oz'],
].map(async e => {
    const [optimizeMode, optimizeParam, ...otherParam] = e;

    const rc = new ReplacementCollector(/__.+?__/g, {
        __WASM_BASE64__: null,
    });
    const wasmSource = (await fs.promises.readdir('src/wasm')).filter(e => path.extname(e) === '.c').map(e => `src/wasm/${e}`);
    const wasmHeader = (await fs.promises.readdir('src/wasm')).filter(e => path.extname(e) === '.h').map(e => `src/wasm/${e}`);
    await Promise.all([
        ...wasmHeader,
        'src/c25519-wasm-template.js'
    ].map(f => fs.promises.readFile(f, { encoding: 'utf-8' }).then(e => rc.collect(e)).catch(() => {})));

    // Compile WASM file
    const emccArgs = [
        ...wasmSource,
        optimizeParam,
        ...otherParam,
        '-v',
        '-flto',
        '-s', 'SIDE_MODULE=2',
        '-o', `dist/c25519.${optimizeMode}.wasm`,
    ];
    console.log(`${optimizeMode} emcc output:\n`, await new Promise((resolve, reject) => process.platform === 'win32' ?
        childProcess.execFile(
            'cmd', ['/s', '/c', 'emcc', ...emccArgs],
            (error, stdout, stderr) => error ? reject(error) : resolve(stderr)
        ) :
        childProcess.execFile(
            'emcc', emccArgs,
            (error, stdout, stderr) => error ? reject(error) : resolve(stderr)
        )
    ));

    // Disassemble WASM to WAT and modify
    await new Promise((resolve, reject) => childProcess.execFile(
        wasmdisPath, ['-all', '-o', `dist/c25519.${optimizeMode}.wat`, `dist/c25519.${optimizeMode}.wasm`],
        (error, stdout, stderr) => error ? reject(error) : resolve(stdout)
    ));
    let watContent = await fs.promises.readFile(`dist/c25519.${optimizeMode}.wat`, { encoding: 'utf-8' });
    watContent = watContent.replace(/^\s*\(import "env" "(.+?)"/gm, '(import "__env__" "__$1__"');
    watContent = watContent.replace(/^\s*\(export "__wasm_call_ctors" \(func \$\d+\)\)\s*$/gm, '');
    watContent = rc.applyReplace(watContent);
    await fs.promises.writeFile(`dist/c25519.${optimizeMode}.wat`, watContent);
    await new Promise((resolve, reject) => childProcess.execFile(
        wasmoptPath, [
            '-all',
            '-O0',
            '--remove-unused-module-elements',
            '-o', `dist/c25519.${optimizeMode}.wasm`,
            `dist/c25519.${optimizeMode}.wat`,
        ],
        (error, stdout, stderr) => error ? reject(error) : resolve(stdout)
    ));
    rc.mapping.set('__WASM_BASE64__', (await fs.promises.readFile(`dist/c25519.${optimizeMode}.wasm`, { encoding: 'base64' })).replace(/=+$/g, ''));
    await fs.promises.rm(`dist/c25519.${optimizeMode}.wat`);

    await Promise.all(['cjs', 'esm'].map(async moduleFormat => {
        const wrappedTemplate = rc.applyReplace(
            (await fs.promises.readFile(`src/wrapper/${moduleFormat}.js`, { encoding: 'utf-8' })).replace(/\/\*\* TEMPLATE \*\*\//g, template)
        );
        return Promise.all([
            fs.promises.writeFile(`dist/c25519-wasm.${optimizeMode}.${moduleFormat}.js`, wrappedTemplate),
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
}));

})();