//
// Created by Dusan Klinec on 29/04/2018.
//

#ifndef TREZOR_CRYPTO_CRYPTO_H
#define TREZOR_CRYPTO_CRYPTO_H

#include <stddef.h>
#include <ed25519-donna/ed25519-donna.h>
#include <ed25519-donna/modm-donna-32bit.h>

extern const bignum25519 fe_sqrtm1;
extern const bignum25519 fe_d;
extern const bignum25519 fe_d2;
extern const bignum25519 fe_ma2;
extern const bignum25519 fe_ma;
extern const bignum25519 fe_fffb1;
extern const bignum25519 fe_fffb2;
extern const bignum25519 fe_fffb3;
extern const bignum25519 fe_fffb4;

void ge25519_mul8(ge25519 *r, const ge25519 *t);
void curve25519_set(bignum25519 r, int x);
int curve25519_isnegative(const bignum25519 f);
int curve25519_isnonzero(const bignum25519 f);
void curve25519_expand_reduce(bignum25519 out, const unsigned char in[32]);

void xmr_hash_to_scalar(const void *data, size_t length, bignum256modm r);
void xmr_hash_to_ec(const void *data, size_t length, ge25519 *P);

// TODO: uint64_t to scalar


#endif //TREZOR_CRYPTO_CRYPTO_H
