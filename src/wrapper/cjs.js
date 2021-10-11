(() => {

/** TEMPLATE **/

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