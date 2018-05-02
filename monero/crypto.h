//
// Created by Dusan Klinec on 29/04/2018.
//

#ifndef TREZOR_XMR_CRYPTO_H
#define TREZOR_XMR_CRYPTO_H

#include <stddef.h>
#include <ed25519-donna/ed25519-donna.h>
#include <hasher.h>

extern const ge25519 ALIGN(16) xmr_h;

/* 64bit uint to scalar value*/
void set256_modm(bignum256modm r, uint64_t v);

/* equality test on two reduced scalar values */
int eq256_modm(const bignum256modm x, const bignum256modm y);

/* comparison of two reduced scalar values */
int cmp256_modm(const bignum256modm x, const bignum256modm y);

/* scalar null check, has to be reduced */
int iszero256_modm(const bignum256modm x);

/* (aa - bb * cc) % l */
void mulsub256_modm(bignum256modm r, const bignum256modm a, const bignum256modm b, const bignum256modm c);

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

/* copies one point to another */
void ge25519_copy(ge25519 *dst, const ge25519 *src);

/* sets B point to r */
void ge25519_set_base(ge25519 *r);

/* sets H point to r */
void ge25519_set_xmr_h(ge25519 *r);

/* cn_fast_hash */
void xmr_fast_hash(const void *data, size_t length, uint8_t * hash);

/* incremental hashing wrappers */
void xmr_hasher_init(Hasher * hasher);
void xmr_hasher_update(Hasher * hasher, const void *data, size_t length);
void xmr_hasher_final(Hasher * hasher, uint8_t * hash);

/* H_s(buffer) */
void xmr_hash_to_scalar(const void *data, size_t length, bignum256modm r);

/* H_p(buffer) */
void xmr_hash_to_ec(const void *data, size_t length, ge25519 *P);

// TODO: varint serialization to buffer, simple one
// TODO: derivation to scalar
// TODO: sc_check, point check on curve when expanding.
// TODO: check point on curve

#endif //TREZOR_XMR_CRYPTO_H
