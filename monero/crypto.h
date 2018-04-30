//
// Created by Dusan Klinec on 29/04/2018.
//

#ifndef TREZOR_XMR_CRYPTO_H
#define TREZOR_XMR_CRYPTO_H

#include <stddef.h>
#include <ed25519-donna/ed25519-donna.h>
#include <ed25519-donna/modm-donna-32bit.h>

/* 64bit uint to scalar value*/
void set256_modm(bignum256modm r, uint64_t v);

/* 8*P */
void ge25519_mul8(ge25519 *r, const ge25519 *t);

/* uint32_t to Zmod(2^255-19) */
void curve25519_set(bignum25519 r, uint32_t x);

/* constant time Zmod(2^255-19) negative test */
int curve25519_isnegative(const bignum25519 f);

/* constant time Zmod(2^255-19) non-zero test */
int curve25519_isnonzero(const bignum25519 f);

/* Zmod(2^255-19) from byte array to bignum25519 expansion with modular reduction */
void curve25519_expand_reduce(bignum25519 out, const unsigned char in[32]);

/* H_s(buffer) */
void xmr_hash_to_scalar(const void *data, size_t length, bignum256modm r);

/* H_p(buffer) */
void xmr_hash_to_ec(const void *data, size_t length, ge25519 *P);


#endif //TREZOR_XMR_CRYPTO_H
