#ifndef EMSCRIPTEN_EXPORTS_H
#define EMSCRIPTEN_EXPORTS_H

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#else
#define EMSCRIPTEN_KEEPALIVE
#endif

#endif