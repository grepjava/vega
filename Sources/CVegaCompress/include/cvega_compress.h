#ifndef CVEGA_COMPRESS_H
#define CVEGA_COMPRESS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Body compression: gzip and deflate through zlib, which is linked (it is on
 * every Linux and Apple system); brotli and zstd through whichever shared
 * libraries the system has, loaded with dlopen the first time they are asked
 * for, so a machine without them still runs and just offers less. Windows
 * builds without any of them for now: every codec says unavailable.
 *
 * One streaming interface over all of them. Swift drives it in a loop: feed
 * input, give it output space, call again while it says there is more.
 * ------------------------------------------------------------------------- */

#define CV_CODEC_GZIP    1
#define CV_CODEC_BR      2
#define CV_CODEC_ZSTD    3
/* The zlib format (RFC 9110's "deflate"). Decoding also takes raw deflate,
 * which some servers send instead: the first two bytes decide. */
#define CV_CODEC_DEFLATE 4

/* What to do with the input once it has been taken. */
#define CV_ENC_CONTINUE 0   /* buffer it; output whenever the codec likes */
#define CV_ENC_FLUSH    1   /* everything so far must be decodable by the peer */
#define CV_ENC_FINISH   2   /* end the stream */

/* 1 when the codec can compress in this process. */
int cv_enc_available(int codec);

/* A new stream at `level` (0 for the codec's default here: gzip and deflate
 * 5, brotli 4, zstd 3), or NULL when the codec is unavailable or out of
 * memory. */
void *cv_enc_new(int codec, int level);
void cv_enc_free(void *enc);

/* Takes up to `n` bytes of `in` and writes up to `cap` bytes to `out`.
 *
 * Returns 0 when all of the input has been taken and whatever `mode` asked for
 * is complete, 1 when it must be called again with fresh output space (and
 * the input that was not yet consumed), and -1 when the codec failed.
 *
 * `*consumed` and `*produced` say how far it got either way. */
int cv_enc_run(void *enc, const uint8_t *in, size_t n, int mode,
               uint8_t *out, size_t cap, size_t *consumed, size_t *produced);

/* 1 when the codec can decompress in this process. */
int cv_dec_available(int codec);

/* A new stream, or NULL when the codec is unavailable or out of memory. */
void *cv_dec_new(int codec);
void cv_dec_free(void *dec);

/* Takes up to `n` bytes of `in` and writes up to `cap` bytes to `out`.
 *
 * Returns 0 when all of the input has been taken and more is expected, 1 when
 * it must be called again with fresh output space (and the input not yet
 * consumed), 2 when the encoded stream has ended, and -1 when the input is not
 * valid for the codec. Input left over after the end is not consumed. A gzip
 * stream of several members is read as one.
 *
 * `*consumed` and `*produced` say how far it got either way. */
int cv_dec_run(void *dec, const uint8_t *in, size_t n,
               uint8_t *out, size_t cap, size_t *consumed, size_t *produced);

/* ---------------------------------------------------------------------------
 * Raw deflate for WebSocket permessage-deflate (RFC 7692).
 *
 * A message is compressed with a sync flush, so it ends on a byte boundary with
 * the empty stored block 00 00 ff ff, which the sender strips and the receiver
 * puts back. There is no zlib or gzip wrapper, and the context may carry from
 * one message to the next, which is what makes a stream of small, similar
 * messages compress at all.
 * ------------------------------------------------------------------------- */

/* 1 when zlib is there. */
int cv_ws_available(void);
/* window_bits 9..15, mem_level 1..9. NULL when zlib cannot make one. */
void *cv_ws_deflate_new(int window_bits, int mem_level);
/* window_bits 8..15: at least the window the peer compresses with. */
void *cv_ws_inflate_new(int window_bits);
void cv_ws_deflate_free(void *z);
void cv_ws_inflate_free(void *z);
/* Forget the context, for no_context_takeover. 0 on success. */
int cv_ws_deflate_reset(void *z);
int cv_ws_inflate_reset(void *z);

/* Compresses `in` with a sync flush into `out`. Returns 1 when `out` filled and
 * the call should be repeated with the input not yet consumed, 0 when the
 * flush is complete, -1 on error. */
int cv_ws_deflate_run(void *z, const uint8_t *in, size_t n,
                      uint8_t *out, size_t cap, size_t *consumed, size_t *produced);
/* Inflates `in` into `out`. Returns 1 when `out` filled, 0 when all of `in` is
 * consumed, 2 when the peer ended its deflate stream (the context must then be
 * reset before the next message), -1 when `in` is not valid deflate. */
int cv_ws_inflate_run(void *z, const uint8_t *in, size_t n,
                      uint8_t *out, size_t cap, size_t *consumed, size_t *produced);

#ifdef __cplusplus
}
#endif

#endif
