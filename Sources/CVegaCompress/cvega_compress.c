/* Body compression and permessage-deflate: see cvega_compress.h. */

#include "cvega_compress.h"

#if defined(_WIN32)

/* No zlib in the Windows SDK: nothing is available. */
int cv_enc_available(int codec) { (void)codec; return 0; }
void *cv_enc_new(int codec, int level) { (void)codec; (void)level; return NULL; }
void cv_enc_free(void *enc) { (void)enc; }
int cv_enc_run(void *enc, const uint8_t *in, size_t n, int mode,
               uint8_t *out, size_t cap, size_t *consumed, size_t *produced) {
    (void)enc; (void)in; (void)n; (void)mode; (void)out; (void)cap;
    *consumed = 0;
    *produced = 0;
    return -1;
}
int cv_dec_available(int codec) { (void)codec; return 0; }
void *cv_dec_new(int codec) { (void)codec; return NULL; }
void cv_dec_free(void *dec) { (void)dec; }
int cv_dec_run(void *dec, const uint8_t *in, size_t n,
               uint8_t *out, size_t cap, size_t *consumed, size_t *produced) {
    (void)dec; (void)in; (void)n; (void)out; (void)cap;
    *consumed = 0;
    *produced = 0;
    return -1;
}
int cv_ws_available(void) { return 0; }
void *cv_ws_deflate_new(int window_bits, int mem_level) { (void)window_bits; (void)mem_level; return NULL; }
void *cv_ws_inflate_new(int window_bits) { (void)window_bits; return NULL; }
void cv_ws_deflate_free(void *z) { (void)z; }
void cv_ws_inflate_free(void *z) { (void)z; }
int cv_ws_deflate_reset(void *z) { (void)z; return -1; }
int cv_ws_inflate_reset(void *z) { (void)z; return -1; }
int cv_ws_deflate_run(void *z, const uint8_t *in, size_t n,
                      uint8_t *out, size_t cap, size_t *consumed, size_t *produced) {
    (void)z; (void)in; (void)n; (void)out; (void)cap;
    *consumed = 0;
    *produced = 0;
    return -1;
}
int cv_ws_inflate_run(void *z, const uint8_t *in, size_t n,
                      uint8_t *out, size_t cap, size_t *consumed, size_t *produced) {
    (void)z; (void)in; (void)n; (void)out; (void)cap;
    *consumed = 0;
    *produced = 0;
    return -1;
}

#else

#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* Default levels are chosen for a response compressed while a client waits,
 * not for an archive. gzip 5 is within a few percent of 9 on text at a
 * fraction of the time; brotli 4 is the last quality before its cost climbs
 * steeply; zstd 3 is its own default. */
#define GZIP_LEVEL   5
#define BROTLI_LEVEL 4
#define ZSTD_LEVEL   3

/* --- brotli, by symbol ---------------------------------------------------
 * Declared here rather than included: the headers are often not installed
 * where the runtime library is, and these signatures have been stable since
 * 1.0. */

typedef int (*brotli_set_parameter_fn)(void *, int, uint32_t);
typedef void *(*brotli_create_fn)(void *, void *, void *);
typedef void (*brotli_destroy_fn)(void *);
typedef int (*brotli_compress_stream_fn)(void *, int, size_t *, const uint8_t **,
                                         size_t *, uint8_t **, size_t *);
typedef int (*brotli_bool_fn)(void *);
typedef int (*brotli_dec_stream_fn)(void *, size_t *, const uint8_t **, size_t *,
                                    uint8_t **, size_t *);

#define BROTLI_PARAM_QUALITY     1
#define BROTLI_PARAM_LGWIN       2
#define BROTLI_OPERATION_PROCESS 0
#define BROTLI_OPERATION_FLUSH   1
#define BROTLI_OPERATION_FINISH  2
#define BROTLI_DECODER_RESULT_SUCCESS           1
#define BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT  2
#define BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT 3

static struct {
    brotli_create_fn create;
    brotli_set_parameter_fn set_parameter;
    brotli_compress_stream_fn compress_stream;
    brotli_bool_fn has_more_output;
    brotli_bool_fn is_finished;
    brotli_destroy_fn destroy;
} brotli;

static struct {
    brotli_create_fn create;
    brotli_dec_stream_fn decompress_stream;
    brotli_destroy_fn destroy;
} brotli_dec;

/* --- zstd, by symbol ----------------------------------------------------- */

typedef struct { const void *src; size_t size; size_t pos; } zstd_in;
typedef struct { void *dst; size_t size; size_t pos; } zstd_out;

typedef void *(*zstd_create_fn)(void);
typedef size_t (*zstd_free_fn)(void *);
typedef size_t (*zstd_set_parameter_fn)(void *, int, int);
typedef size_t (*zstd_compress_stream2_fn)(void *, zstd_out *, zstd_in *, int);
typedef size_t (*zstd_decompress_stream_fn)(void *, zstd_out *, zstd_in *);
typedef unsigned (*zstd_is_error_fn)(size_t);

#define ZSTD_C_COMPRESSION_LEVEL 100
#define ZSTD_C_WINDOW_LOG        101
#define ZSTD_D_WINDOW_LOG_MAX    100
#define ZSTD_E_CONTINUE 0
#define ZSTD_E_FLUSH    1
#define ZSTD_E_END      2

static struct {
    zstd_create_fn create;
    zstd_free_fn free;
    zstd_set_parameter_fn set_parameter;
    zstd_compress_stream2_fn compress_stream2;
    zstd_is_error_fn is_error;
} zstd;

static struct {
    zstd_create_fn create;
    zstd_free_fn free;
    zstd_set_parameter_fn set_parameter;
    zstd_decompress_stream_fn decompress_stream;
    zstd_is_error_fn is_error;
} zstd_dec;

static pthread_once_t load_once = PTHREAD_ONCE_INIT;
static int have_brotli, have_brotli_dec, have_zstd, have_zstd_dec;

static void *open_first(const char *const *names) {
    for (; *names; names++) {
        void *h = dlopen(*names, RTLD_NOW | RTLD_LOCAL);
        if (h) return h;
    }
    return NULL;
}

static void load_libraries(void) {
    static const char *const brotli_enc_names[] = {
        "libbrotlienc.so.1", "libbrotlienc.so",
        "libbrotlienc.1.dylib", "/opt/homebrew/lib/libbrotlienc.1.dylib",
        "/usr/local/lib/libbrotlienc.1.dylib", NULL,
    };
    static const char *const brotli_dec_names[] = {
        "libbrotlidec.so.1", "libbrotlidec.so",
        "libbrotlidec.1.dylib", "/opt/homebrew/lib/libbrotlidec.1.dylib",
        "/usr/local/lib/libbrotlidec.1.dylib", NULL,
    };
    static const char *const zstd_names[] = {
        "libzstd.so.1", "libzstd.so",
        "libzstd.1.dylib", "/opt/homebrew/lib/libzstd.1.dylib",
        "/usr/local/lib/libzstd.1.dylib", NULL,
    };

    void *b = open_first(brotli_enc_names);
    if (b) {
        brotli.create = (brotli_create_fn)dlsym(b, "BrotliEncoderCreateInstance");
        brotli.set_parameter = (brotli_set_parameter_fn)dlsym(b, "BrotliEncoderSetParameter");
        brotli.compress_stream = (brotli_compress_stream_fn)dlsym(b, "BrotliEncoderCompressStream");
        brotli.has_more_output = (brotli_bool_fn)dlsym(b, "BrotliEncoderHasMoreOutput");
        brotli.is_finished = (brotli_bool_fn)dlsym(b, "BrotliEncoderIsFinished");
        brotli.destroy = (brotli_destroy_fn)dlsym(b, "BrotliEncoderDestroyInstance");
        have_brotli = brotli.create && brotli.set_parameter && brotli.compress_stream
            && brotli.has_more_output && brotli.is_finished && brotli.destroy;
    }
    void *bd = open_first(brotli_dec_names);
    if (bd) {
        brotli_dec.create = (brotli_create_fn)dlsym(bd, "BrotliDecoderCreateInstance");
        brotli_dec.decompress_stream = (brotli_dec_stream_fn)dlsym(bd, "BrotliDecoderDecompressStream");
        brotli_dec.destroy = (brotli_destroy_fn)dlsym(bd, "BrotliDecoderDestroyInstance");
        have_brotli_dec = brotli_dec.create && brotli_dec.decompress_stream && brotli_dec.destroy;
    }
    void *z = open_first(zstd_names);
    if (z) {
        zstd.create = (zstd_create_fn)dlsym(z, "ZSTD_createCCtx");
        zstd.free = (zstd_free_fn)dlsym(z, "ZSTD_freeCCtx");
        zstd.set_parameter = (zstd_set_parameter_fn)dlsym(z, "ZSTD_CCtx_setParameter");
        zstd.compress_stream2 = (zstd_compress_stream2_fn)dlsym(z, "ZSTD_compressStream2");
        zstd.is_error = (zstd_is_error_fn)dlsym(z, "ZSTD_isError");
        have_zstd = zstd.create && zstd.free && zstd.set_parameter
            && zstd.compress_stream2 && zstd.is_error;
        zstd_dec.create = (zstd_create_fn)dlsym(z, "ZSTD_createDCtx");
        zstd_dec.free = (zstd_free_fn)dlsym(z, "ZSTD_freeDCtx");
        zstd_dec.set_parameter = (zstd_set_parameter_fn)dlsym(z, "ZSTD_DCtx_setParameter");
        zstd_dec.decompress_stream = (zstd_decompress_stream_fn)dlsym(z, "ZSTD_decompressStream");
        zstd_dec.is_error = zstd.is_error;
        have_zstd_dec = zstd_dec.create && zstd_dec.free && zstd_dec.set_parameter
            && zstd_dec.decompress_stream && zstd_dec.is_error;
    }
}

/* zlib counts in uInt: longer input or output is taken in pieces. */
static uInt clamp_uint(size_t n) { return n > UINT_MAX ? UINT_MAX : (uInt)n; }

/* ======================================================================== */
/* Encoding                                                                 */
/* ======================================================================== */

int cv_enc_available(int codec) {
    switch (codec) {
    case CV_CODEC_GZIP:
    case CV_CODEC_DEFLATE: return 1;
    case CV_CODEC_BR:   pthread_once(&load_once, load_libraries); return have_brotli;
    case CV_CODEC_ZSTD: pthread_once(&load_once, load_libraries); return have_zstd;
    default:            return 0;
    }
}

struct cv_enc {
    int codec;
    int finished;
    union {
        z_stream z;
        void *brotli;
        void *zstd;
    } u;
};

void *cv_enc_new(int codec, int level) {
    if (!cv_enc_available(codec)) return NULL;
    struct cv_enc *e = calloc(1, sizeof *e);
    if (!e) return NULL;
    e->codec = codec;

    switch (codec) {
    case CV_CODEC_GZIP:
    case CV_CODEC_DEFLATE: {
        /* A 32 KiB window; + 16 wraps it as gzip rather than zlib. */
        int bits = codec == CV_CODEC_GZIP ? 15 + 16 : 15;
        if (level < 1 || level > 9) level = GZIP_LEVEL;
        if (deflateInit2(&e->u.z, level, Z_DEFLATED, bits, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
            free(e);
            return NULL;
        }
        return e;
    }
    case CV_CODEC_BR:
        e->u.brotli = brotli.create(NULL, NULL, NULL);
        if (!e->u.brotli) { free(e); return NULL; }
        if (level < 1 || level > 11) level = BROTLI_LEVEL;
        brotli.set_parameter(e->u.brotli, BROTLI_PARAM_QUALITY, (uint32_t)level);
        /* 2^22 bytes, the encoder's default; a stream has no size hint. */
        brotli.set_parameter(e->u.brotli, BROTLI_PARAM_LGWIN, 22);
        return e;
    case CV_CODEC_ZSTD:
        e->u.zstd = zstd.create();
        if (!e->u.zstd) { free(e); return NULL; }
        if (level < 1 || level > 19) level = ZSTD_LEVEL;
        zstd.set_parameter(e->u.zstd, ZSTD_C_COMPRESSION_LEVEL, level);
        /* RFC 9659: a decoder for the zstd content coding need not accept a
         * window over 8 MiB, and Chrome does not. */
        zstd.set_parameter(e->u.zstd, ZSTD_C_WINDOW_LOG, 23);
        return e;
    }
    free(e);
    return NULL;
}

void cv_enc_free(void *enc) {
    struct cv_enc *e = enc;
    if (!e) return;
    switch (e->codec) {
    case CV_CODEC_GZIP:
    case CV_CODEC_DEFLATE: deflateEnd(&e->u.z); break;
    case CV_CODEC_BR:      brotli.destroy(e->u.brotli); break;
    case CV_CODEC_ZSTD:    zstd.free(e->u.zstd); break;
    }
    free(e);
}

int cv_enc_run(void *enc, const uint8_t *in, size_t n, int mode,
               uint8_t *out, size_t cap, size_t *consumed, size_t *produced) {
    struct cv_enc *e = enc;
    *consumed = 0;
    *produced = 0;
    if (!e) return -1;
    if (e->finished) return n == 0 ? 0 : -1;

    switch (e->codec) {
    case CV_CODEC_GZIP:
    case CV_CODEC_DEFLATE: {
        static const uint8_t nothing = 0;
        z_stream *z = &e->u.z;
        uInt n32 = clamp_uint(n), cap32 = clamp_uint(cap);
        z->next_in = (Bytef *)(n > 0 ? in : &nothing);
        z->avail_in = n32;
        z->next_out = out;
        z->avail_out = cap32;
        /* Input over 4 GiB goes in pieces: only the last may finish. */
        int whole = n32 == n;
        int flush = !whole ? Z_NO_FLUSH
                  : mode == CV_ENC_FINISH ? Z_FINISH
                  : mode == CV_ENC_FLUSH ? Z_SYNC_FLUSH : Z_NO_FLUSH;
        int rc = deflate(z, flush);
        *consumed = n32 - z->avail_in;
        *produced = cap32 - z->avail_out;
        if (rc == Z_STREAM_END) { e->finished = 1; return 0; }
        /* Z_BUF_ERROR only means no progress was possible, which after a
         * flush that already went out is the expected answer. */
        if (rc != Z_OK && rc != Z_BUF_ERROR) return -1;
        if (!whole || mode == CV_ENC_FINISH) return 1;
        /* Output space used up means there may be more; zlib says to call
         * again with the same flush until it leaves some unused. */
        return (z->avail_in == 0 && z->avail_out != 0) ? 0 : 1;
    }
    case CV_CODEC_BR: {
        size_t avail_in = n, avail_out = cap;
        const uint8_t *next_in = in;
        uint8_t *next_out = out;
        int op = mode == CV_ENC_FINISH ? BROTLI_OPERATION_FINISH
               : mode == CV_ENC_FLUSH ? BROTLI_OPERATION_FLUSH : BROTLI_OPERATION_PROCESS;
        if (!brotli.compress_stream(e->u.brotli, op, &avail_in, &next_in,
                                    &avail_out, &next_out, NULL)) {
            return -1;
        }
        *consumed = n - avail_in;
        *produced = cap - avail_out;
        if (mode == CV_ENC_FINISH && brotli.is_finished(e->u.brotli)) {
            e->finished = 1;
            return 0;
        }
        if (avail_in == 0 && !brotli.has_more_output(e->u.brotli) && mode != CV_ENC_FINISH) return 0;
        return 1;
    }
    case CV_CODEC_ZSTD: {
        zstd_in zin = { in, n, 0 };
        zstd_out zout = { out, cap, 0 };
        int directive = mode == CV_ENC_FINISH ? ZSTD_E_END
                      : mode == CV_ENC_FLUSH ? ZSTD_E_FLUSH : ZSTD_E_CONTINUE;
        size_t left = zstd.compress_stream2(e->u.zstd, &zout, &zin, directive);
        *consumed = zin.pos;
        *produced = zout.pos;
        if (zstd.is_error(left)) return -1;
        if (mode == CV_ENC_CONTINUE) return zin.pos == zin.size ? 0 : 1;
        if (left == 0 && zin.pos == zin.size) {
            if (mode == CV_ENC_FINISH) e->finished = 1;
            return 0;
        }
        return 1;
    }
    }
    return -1;
}

/* ======================================================================== */
/* Decoding                                                                 */
/* ======================================================================== */

int cv_dec_available(int codec) {
    switch (codec) {
    case CV_CODEC_GZIP:
    case CV_CODEC_DEFLATE: return 1;
    case CV_CODEC_BR:   pthread_once(&load_once, load_libraries); return have_brotli_dec;
    case CV_CODEC_ZSTD: pthread_once(&load_once, load_libraries); return have_zstd_dec;
    default:            return 0;
    }
}

struct cv_dec {
    int codec;
    /* For deflate, whether the zlib stream has been set up: zlib or raw is
     * decided from the first two bytes. */
    int started;
    int ended;
    union {
        z_stream z;
        void *brotli;
        void *zstd;
    } u;
};

void *cv_dec_new(int codec) {
    if (!cv_dec_available(codec)) return NULL;
    struct cv_dec *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->codec = codec;

    switch (codec) {
    case CV_CODEC_GZIP:
        /* 15 + 16: a 32 KiB window, gzip wrapper only. */
        if (inflateInit2(&d->u.z, 15 + 16) != Z_OK) { free(d); return NULL; }
        d->started = 1;
        return d;
    case CV_CODEC_DEFLATE:
        return d;
    case CV_CODEC_BR:
        d->u.brotli = brotli_dec.create(NULL, NULL, NULL);
        if (!d->u.brotli) { free(d); return NULL; }
        return d;
    case CV_CODEC_ZSTD:
        d->u.zstd = zstd_dec.create();
        if (!d->u.zstd) { free(d); return NULL; }
        /* RFC 9659: the zstd content coding's window is at most 8 MiB. */
        zstd_dec.set_parameter(d->u.zstd, ZSTD_D_WINDOW_LOG_MAX, 23);
        return d;
    }
    free(d);
    return NULL;
}

void cv_dec_free(void *dec) {
    struct cv_dec *d = dec;
    if (!d) return;
    switch (d->codec) {
    case CV_CODEC_GZIP:    inflateEnd(&d->u.z); break;
    case CV_CODEC_DEFLATE: if (d->started) inflateEnd(&d->u.z); break;
    case CV_CODEC_BR:      brotli_dec.destroy(d->u.brotli); break;
    case CV_CODEC_ZSTD:    zstd_dec.free(d->u.zstd); break;
    }
    free(d);
}

static int inflate_step(struct cv_dec *d, const uint8_t *in, size_t n,
                        uint8_t *out, size_t cap, size_t *consumed, size_t *produced) {
    z_stream *z = &d->u.z;
    static const uint8_t nothing = 0;
    uInt n32 = clamp_uint(n), cap32 = clamp_uint(cap);
    z->next_in = (Bytef *)(n > 0 ? in : &nothing);
    z->avail_in = n32;
    z->next_out = out;
    z->avail_out = cap32;
    for (;;) {
        int rc = inflate(z, Z_NO_FLUSH);
        *consumed = n32 - z->avail_in;
        *produced = cap32 - z->avail_out;
        if (rc == Z_STREAM_END) {
            /* Another gzip member follows: carry on into it. */
            if (d->codec == CV_CODEC_GZIP && z->avail_in >= 2
                && z->next_in[0] == 0x1f && z->next_in[1] == 0x8b) {
                /* With no room left, the next call finds the end again and
                 * starts the member then. */
                if (z->avail_out == 0) return 1;
                if (inflateReset(z) != Z_OK) return -1;
                continue;
            }
            d->ended = 1;
            return 2;
        }
        if (rc == Z_OK) return z->avail_out == 0 || z->avail_in != 0 ? 1 : 0;
        if (rc == Z_BUF_ERROR) {
            if (z->avail_out == 0) return 1;
            return z->avail_in == 0 ? 0 : -1;
        }
        return -1;
    }
}

int cv_dec_run(void *dec, const uint8_t *in, size_t n,
               uint8_t *out, size_t cap, size_t *consumed, size_t *produced) {
    struct cv_dec *d = dec;
    *consumed = 0;
    *produced = 0;
    if (!d) return -1;
    if (d->ended) return 2;

    switch (d->codec) {
    case CV_CODEC_DEFLATE:
        if (!d->started) {
            /* Both header bytes are needed to tell zlib from raw deflate. */
            if (n < 2) return 0;
            /* A zlib header: compression method 8, and the two bytes read as
             * a number a multiple of 31. Anything else is raw deflate. */
            int zlib = (in[0] & 0x0f) == 8 && ((in[0] << 8) | in[1]) % 31 == 0;
            if (inflateInit2(&d->u.z, zlib ? 15 : -15) != Z_OK) return -1;
            d->started = 1;
        }
        return inflate_step(d, in, n, out, cap, consumed, produced);
    case CV_CODEC_GZIP:
        return inflate_step(d, in, n, out, cap, consumed, produced);
    case CV_CODEC_BR: {
        size_t avail_in = n, avail_out = cap;
        const uint8_t *next_in = in;
        uint8_t *next_out = out;
        int rc = brotli_dec.decompress_stream(d->u.brotli, &avail_in, &next_in,
                                              &avail_out, &next_out, NULL);
        *consumed = n - avail_in;
        *produced = cap - avail_out;
        switch (rc) {
        case BROTLI_DECODER_RESULT_SUCCESS: d->ended = 1; return 2;
        case BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT: return 0;
        case BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT: return 1;
        default: return -1;
        }
    }
    case CV_CODEC_ZSTD: {
        zstd_in zin = { in, n, 0 };
        zstd_out zout = { out, cap, 0 };
        size_t hint = zstd_dec.decompress_stream(d->u.zstd, &zout, &zin);
        *consumed = zin.pos;
        *produced = zout.pos;
        if (zstd_dec.is_error(hint)) return -1;
        if (hint == 0) { d->ended = 1; return 2; }
        if (zout.pos == zout.size) return 1;
        return zin.pos == zin.size ? 0 : 1;
    }
    }
    return -1;
}

/* ======================================================================== */
/* permessage-deflate                                                       */
/* ======================================================================== */

/* Level 5, as for HTTP gzip: most of the ratio, little of the time. */
#define WS_LEVEL 5

int cv_ws_available(void) { return 1; }

void *cv_ws_deflate_new(int window_bits, int mem_level) {
    /* zlib cannot make a raw stream with an 8-bit window; the negotiation
     * refuses to promise one. */
    if (window_bits < 9) window_bits = 9;
    if (window_bits > 15) window_bits = 15;
    if (mem_level < 1) mem_level = 1;
    if (mem_level > 9) mem_level = 9;
    z_stream *z = calloc(1, sizeof *z);
    if (!z) return NULL;
    if (deflateInit2(z, WS_LEVEL, Z_DEFLATED, -window_bits, mem_level, Z_DEFAULT_STRATEGY) != Z_OK) {
        free(z);
        return NULL;
    }
    return z;
}

void *cv_ws_inflate_new(int window_bits) {
    if (window_bits < 8) window_bits = 8;
    if (window_bits > 15) window_bits = 15;
    z_stream *z = calloc(1, sizeof *z);
    if (!z) return NULL;
    /* zlib's raw inflate takes no 8: 9 reads an 8-bit window's stream. */
    if (inflateInit2(z, -(window_bits < 9 ? 9 : window_bits)) != Z_OK) {
        free(z);
        return NULL;
    }
    return z;
}

void cv_ws_deflate_free(void *z) {
    if (!z) return;
    deflateEnd((z_stream *)z);
    free(z);
}

void cv_ws_inflate_free(void *z) {
    if (!z) return;
    inflateEnd((z_stream *)z);
    free(z);
}

int cv_ws_deflate_reset(void *z) { return deflateReset((z_stream *)z) == Z_OK ? 0 : -1; }
int cv_ws_inflate_reset(void *z) { return inflateReset((z_stream *)z) == Z_OK ? 0 : -1; }

int cv_ws_deflate_run(void *zp, const uint8_t *in, size_t n,
                      uint8_t *out, size_t cap, size_t *consumed, size_t *produced) {
    z_stream *z = (z_stream *)zp;
    static const uint8_t nothing = 0;
    uInt n32 = clamp_uint(n), cap32 = clamp_uint(cap);
    z->next_in = (Bytef *)(n > 0 ? in : &nothing);
    z->avail_in = n32;
    z->next_out = out;
    z->avail_out = cap32;
    int rc = deflate(z, n32 == n ? Z_SYNC_FLUSH : Z_NO_FLUSH);
    *consumed = n32 - z->avail_in;
    *produced = cap32 - z->avail_out;
    /* Z_BUF_ERROR is "no progress possible", which after a completed flush is
     * simply done. */
    if (rc != Z_OK && rc != Z_BUF_ERROR) return -1;
    return z->avail_out == 0 || n32 != n ? 1 : 0;
}

int cv_ws_inflate_run(void *zp, const uint8_t *in, size_t n,
                      uint8_t *out, size_t cap, size_t *consumed, size_t *produced) {
    z_stream *z = (z_stream *)zp;
    static const uint8_t nothing = 0;
    uInt n32 = clamp_uint(n), cap32 = clamp_uint(cap);
    z->next_in = (Bytef *)(n > 0 ? in : &nothing);
    z->avail_in = n32;
    z->next_out = out;
    z->avail_out = cap32;
    int rc = inflate(z, Z_SYNC_FLUSH);
    *consumed = n32 - z->avail_in;
    *produced = cap32 - z->avail_out;
    switch (rc) {
    case Z_STREAM_END:
        return 2;
    case Z_OK:
        return z->avail_out == 0 || z->avail_in != 0 ? 1 : 0;
    case Z_BUF_ERROR:
        if (z->avail_in == 0) return 0;
        return z->avail_out == 0 ? 1 : -1;
    default:
        return -1;
    }
}

#endif
