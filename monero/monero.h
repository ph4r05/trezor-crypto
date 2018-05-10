//
// Created by Dusan Klinec on 10/05/2018.
//

#ifndef TREZOR_CRYPTO_MONERO_H
#define TREZOR_CRYPTO_MONERO_H

#include "base58.h"
#include "crypto.h"
#include "serialize.h"

extern const ge25519 ALIGN(16) xmr_h;

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

/* derivation to scalar value */
void xmr_derivation_to_scalar(bignum256modm s, const ge25519 * p, uint32_t output_index);

/* derivation */
void xmr_generate_key_derivation(ge25519 * r, const ge25519 * A, const bignum256modm b);

/* H_s(derivation || varint(output_index)) + base */
void xmr_derive_private_key(bignum256modm s, const ge25519 * deriv, uint32_t idx, const bignum256modm base);

/* H_s(derivation || varint(output_index))G + base */
void xmr_derive_public_key(ge25519 * r, const ge25519 * deriv, uint32_t idx, const ge25519 * base);

/* Generates Pedersen commitment C = aG + bH */
void xmr_gen_c(ge25519 * r, const bignum256modm a, uint64_t amount);

/* aG + bB, G is basepoint */
void xmr_add_keys1(ge25519 * r, const bignum256modm a, const bignum256modm b, const ge25519 * p);

/* aA + bB */
void xmr_add_keys2(ge25519 * r, const bignum256modm a, const ge25519 * A, const bignum256modm b, const ge25519 * B);

/* subaddress secret */
void xmr_get_subaddress_secret_key(bignum256modm a, uint32_t major, uint32_t minor, bignum256modm m);

#endif //TREZOR_CRYPTO_MONERO_H
