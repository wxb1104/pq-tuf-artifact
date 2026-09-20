/* Minimal verify-only footprint harness for a PQClean signature scheme.
 * Links against one scheme's PQClean objects; the linker garbage-collects
 * keygen/sign code that is unreachable from a verify-only entry point.
 * A header-instrumented malloc wrapper reports the peak live heap reached
 * during crypto_sign_open only (counters reset right before verification).
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "pqtuf_api.h"   /* generated shim: maps generic names to PQCLEAN_<NS> */

#define HDR 32
static size_t g_cur = 0, g_peak = 0;

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void __real_free(void *);
void *__real_realloc(void *, size_t);

static size_t align16(size_t n) { return (n + 15u) & ~(size_t)15u; }

void *__wrap_malloc(size_t n) {
    unsigned char *raw = (unsigned char *)__real_malloc(n + HDR);
    if (!raw) return NULL;
    size_t a = align16(n);
    memcpy(raw, &a, sizeof(a));
    g_cur += a;
    if (g_cur > g_peak) g_peak = g_cur;
    return raw + HDR;
}
void *__wrap_calloc(size_t x, size_t y) {
    size_t n = x * y;
    unsigned char *raw = (unsigned char *)__real_malloc(n + HDR);
    if (!raw) return NULL;
    memset(raw + HDR, 0, n);
    size_t a = align16(n);
    memcpy(raw, &a, sizeof(a));
    g_cur += a;
    if (g_cur > g_peak) g_peak = g_cur;
    return raw + HDR;
}
void __wrap_free(void *p) {
    if (!p) return;
    unsigned char *raw = (unsigned char *)p - HDR;
    size_t a;
    memcpy(&a, raw, sizeof(a));
    g_cur -= a;
    __real_free(raw);
}
void *__wrap_realloc(void *p, size_t n) {
    if (!p) return __wrap_malloc(n);
    unsigned char *old = (unsigned char *)p - HDR;
    size_t oa;
    memcpy(&oa, old, sizeof(oa));
    unsigned char *raw = (unsigned char *)__real_realloc(old, n + HDR);
    if (!raw) return NULL;
    size_t na = align16(n);
    memcpy(raw, &na, sizeof(na));
    g_cur += (na > oa) ? (na - oa) : 0;
    if (g_cur > g_peak) g_peak = g_cur;
    return raw + HDR;
}

int main(void) {
    size_t pkl = CRYPTO_PUBLICKEYBYTES, skl = CRYPTO_SECRETKEYBYTES;
    size_t sml = 0, oml = 0;
    uint8_t *pk = malloc(pkl);
    uint8_t *sk = malloc(skl);
    uint8_t msg[64];
    uint8_t *sm = malloc(CRYPTO_BYTES + sizeof msg);
    uint8_t *om = malloc(CRYPTO_BYTES + sizeof msg);
    crypto_sign_keypair(pk, sk);
    memset(msg, 0x42, sizeof msg);
    crypto_sign(sm, &sml, msg, sizeof msg, sk);

    g_cur = 0; g_peak = 0;                 /* measure verification only */
    int rc = crypto_sign_open(om, &oml, sm, sml, pk);
    printf("VERIFY_RC=%d HEAP_PEAK=%zu\n", rc, g_peak);
    if (rc != 0 || oml != sizeof msg) return 1;
    return 0;
}
