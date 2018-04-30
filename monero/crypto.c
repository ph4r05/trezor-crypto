//
// Created by Dusan Klinec on 29/04/2018.
//

#include "crypto.h"
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include <hasher.h>

static const uint32_t reduce_mask_25 = (1 << 25) - 1;
static const uint32_t reduce_mask_26 = (1 << 26) - 1;

/* sqrt(x) is such an integer y that 0 <= y <= p - 1, y % 2 = 0, and y^2 = x (mod p). */
/* d = -121665 / 121666 */
const bignum25519 ALIGN(16) fe_d = {
    0x35978a3, 0x0d37284, 0x3156ebd, 0x06a0a0e, 0x001c029, 0x179e898, 0x3a03cbb, 0x1ce7198, 0x2e2b6ff, 0x1480db3}; /* d */
const bignum25519 ALIGN(16) fe_sqrtm1 = {
    0x20ea0b0, 0x186c9d2, 0x08f189d, 0x035697f, 0x0bd0c60, 0x1fbd7a7, 0x2804c9e, 0x1e16569, 0x004fc1d, 0x0ae0c92}; /* sqrt(-1) */
const bignum25519 ALIGN(16) fe_d2 = {
    0x2b2f159, 0x1a6e509, 0x22add7a, 0x0d4141d, 0x0038052, 0x0f3d130, 0x3407977, 0x19ce331, 0x1c56dff, 0x0901b67}; /* 2 * d */
/* A = 2 * (1 - d) / (1 + d) = 486662 */

const bignum25519 ALIGN(16) fe_ma2 = {
    0x33de3c9, 0x1fff236, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff}; /* -A^2 */
const bignum25519 ALIGN(16) fe_ma = {
    0x3f892e7, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff}; /* -A */
const bignum25519 ALIGN(16) fe_fffb1 = {
    0x1e3bdff, 0x025a2b3, 0x18e5bab, 0x0ba36ac, 0x0b9afed, 0x004e61c, 0x31d645f, 0x09d1bea, 0x102529e, 0x0063810}; /* sqrt(-2 * A * (A + 2)) */
const bignum25519 ALIGN(16) fe_fffb2 = {
    0x383650d, 0x066df27, 0x10405a4, 0x1cfdd48, 0x2b887f2, 0x1e9a041, 0x1d7241f, 0x0612dc5, 0x35fba5d, 0x0cbe787}; /* sqrt(2 * A * (A + 2)) */
const bignum25519 ALIGN(16) fe_fffb3 = {
    0x0cfd387, 0x1209e3a, 0x3bad4fc, 0x18ad34d, 0x2ff6c02, 0x0f25d12, 0x15cdfe0, 0x0e208ed, 0x32eb3df, 0x062d7bb}; /* sqrt(-sqrt(-1) * A * (A + 2)) */
const bignum25519 ALIGN(16) fe_fffb4 = {
    0x2b39186, 0x14640ed, 0x14930a7, 0x04509fa, 0x3b91bf0, 0x0f7432e, 0x07a443f, 0x17f24d8, 0x031067d, 0x0690fcc}; /* sqrt(sqrt(-1) * A * (A + 2)) */

const ge25519 ALIGN(16) xmr_h = {
    {0x1861ec7, 0x1ceac77, 0x2f11626, 0x1f261d3, 0x346107c, 0x06d8c4a, 0x254201d, 0x1675c09, 0x1301c3f, 0x0211d73},
    {0x326feb4, 0x12e30cc, 0x0cf54b4, 0x1117305, 0x318f5d5, 0x06cf754, 0x2e578a1, 0x1daf058, 0x34430a1, 0x04410e9},
    {0x0fde4d2, 0x0774049, 0x22ca951, 0x05aec2b, 0x07a36a5, 0x1394f13, 0x3c5385c, 0x1adb924, 0x2b6c581, 0x0a55fa4},
    {0x24517f7, 0x05ee936, 0x3acf5d9, 0x14b08aa, 0x3363738, 0x1051745, 0x360601e, 0x0f3f2c9, 0x1ead2cd, 0x1d3e3df}
};

void set256_modm(bignum256modm r, uint64_t v) {
  r[0] = (bignum256modm_element_t) (v & 0x3fffffff); v >>= 30;
  r[1] = (bignum256modm_element_t) (v & 0x3fffffff); v >>= 30;
  r[2] = (bignum256modm_element_t) (v & 0x3fffffff);
  r[3] = 0;
  r[4] = 0;
  r[5] = 0;
  r[6] = 0;
  r[7] = 0;
  r[8] = 0;
}

int eq256_modm(const bignum256modm x, const bignum256modm y){
  size_t differentbits = 0;
  int len = bignum256modm_limb_size;
  while (len--) {
    differentbits |= (*x++ ^ *y++);
  }
  return (int) (1 & ((differentbits - 1) >> 8));
}

int cmp256_modm(const bignum256modm x, const bignum256modm y){
  int len = 2*bignum256modm_limb_size;
  uint32_t a_gt = 0;
  uint32_t b_gt = 0;

  // 16B chunks
  while (len--) {
    const uint32_t ln = (const uint32_t) len;
    const uint32_t a = (x[ln>>1] >> 16*(ln & 1)) & 0xffff;
    const uint32_t b = (y[ln>>1] >> 16*(ln & 1)) & 0xffff;

    const uint32_t limb_a_gt = ((b - a) >> 16) & 1;
    const uint32_t limb_b_gt = ((a - b) >> 16) & 1;
    a_gt |= limb_a_gt & ~b_gt;
    b_gt |= limb_b_gt & ~a_gt;
  }

  return a_gt - b_gt;
}

int iszero256_modm(const bignum256modm x){
  size_t differentbits = 0;
  int len = bignum256modm_limb_size;
  while (len--) {
    differentbits |= (*x++);
  }
  return (int) (1 & ((differentbits - 1) >> 8));
}

void ge25519_mul8(ge25519 *r, const ge25519 *t) {
  ge25519_double_partial(r, t);
  ge25519_double_partial(r, r);
  ge25519_double(r, r);
}

void curve25519_set(bignum25519 r, uint32_t x){
   r[0] = x & reduce_mask_26; x >>= 26;
   r[1] = x & reduce_mask_25;
   r[2] = 0;
   r[3] = 0;
   r[4] = 0;
   r[5] = 0;
   r[6] = 0;
   r[7] = 0;
   r[8] = 0;
   r[9] = 0;
}

int curve25519_isnegative(const bignum25519 f) {
  unsigned char s[32];
  curve25519_contract(s, f);
  return s[0] & 1;
}

int curve25519_isnonzero(const bignum25519 f) {
  unsigned char s[32];
  curve25519_contract(s, f);
  return (((int) (s[0] | s[1] | s[2] | s[3] | s[4] | s[5] | s[6] | s[7] | s[8] |
                  s[9] | s[10] | s[11] | s[12] | s[13] | s[14] | s[15] | s[16] | s[17] |
                  s[18] | s[19] | s[20] | s[21] | s[22] | s[23] | s[24] | s[25] | s[26] |
                  s[27] | s[28] | s[29] | s[30] | s[31]) - 1) >> 8) + 1;
}

static void curve25519_divpowm1(bignum25519 r, const bignum25519 u, const bignum25519 v) {
  bignum25519 v3={0}, uv7={0}, t0={0}, t1={0}, t2={0};
  int i;

  curve25519_square(v3, v);
  curve25519_mul(v3, v3, v); /* v3 = v^3 */
  curve25519_square(uv7, v3);
  curve25519_mul(uv7, uv7, v);
  curve25519_mul(uv7, uv7, u); /* uv7 = uv^7 */

  /*fe_pow22523(uv7, uv7);*/
  /* From fe_pow22523.c */

  curve25519_square(t0, uv7);
  curve25519_square(t1, t0);
  curve25519_square(t1, t1);
  curve25519_mul(t1, uv7, t1);
  curve25519_mul(t0, t0, t1);
  curve25519_square(t0, t0);
  curve25519_mul(t0, t1, t0);
  curve25519_square(t1, t0);
  for (i = 0; i < 4; ++i) {
    curve25519_square(t1, t1);
  }
  curve25519_mul(t0, t1, t0);
  curve25519_square(t1, t0);
  for (i = 0; i < 9; ++i) {
    curve25519_square(t1, t1);
  }
  curve25519_mul(t1, t1, t0);
  curve25519_square(t2, t1);
  for (i = 0; i < 19; ++i) {
    curve25519_square(t2, t2);
  }
  curve25519_mul(t1, t2, t1);
  for (i = 0; i < 10; ++i) {
    curve25519_square(t1, t1);
  }
  curve25519_mul(t0, t1, t0);
  curve25519_square(t1, t0);
  for (i = 0; i < 49; ++i) {
    curve25519_square(t1, t1);
  }
  curve25519_mul(t1, t1, t0);
  curve25519_square(t2, t1);
  for (i = 0; i < 99; ++i) {
    curve25519_square(t2, t2);
  }
  curve25519_mul(t1, t2, t1);
  for (i = 0; i < 50; ++i) {
    curve25519_square(t1, t1);
  }
  curve25519_mul(t0, t1, t0);
  curve25519_square(t0, t0);
  curve25519_square(t0, t0);
  curve25519_mul(t0, t0, uv7);

  /* End fe_pow22523.c */
  /* t0 = (uv^7)^((q-5)/8) */
  curve25519_mul(t0, t0, v3);
  curve25519_mul(r, t0, u); /* u^(m+1)v^(-(m+1)) */
}

void curve25519_expand_reduce(bignum25519 out, const unsigned char in[32]) {
  const union { uint8_t b[2]; uint16_t s; } endian_check = {{1,0}};
  uint32_t x0,x1,x2,x3,x4,x5,x6,x7;
  if (endian_check.s == 1) {
    /* Take care, this only works when in is aligned */
    x0 = *(uint32_t *)(in + 0);
    x1 = *(uint32_t *)(in + 4);
    x2 = *(uint32_t *)(in + 8);
    x3 = *(uint32_t *)(in + 12);
    x4 = *(uint32_t *)(in + 16);
    x5 = *(uint32_t *)(in + 20);
    x6 = *(uint32_t *)(in + 24);
    x7 = *(uint32_t *)(in + 28);
  } else {
#define F(s)                         \
			((((uint32_t)in[s + 0])      ) | \
			 (((uint32_t)in[s + 1]) <<  8) | \
			 (((uint32_t)in[s + 2]) << 16) | \
			 (((uint32_t)in[s + 3]) << 24))
    x0 = F(0);
    x1 = F(4);
    x2 = F(8);
    x3 = F(12);
    x4 = F(16);
    x5 = F(20);
    x6 = F(24);
    x7 = F(28);
#undef F
  }

  out[0] = (                        x0       ) & reduce_mask_26;
  out[1] = ((((uint64_t)x1 << 32) | x0) >> 26) & reduce_mask_25;
  out[2] = ((((uint64_t)x2 << 32) | x1) >> 19) & reduce_mask_26;
  out[3] = ((((uint64_t)x3 << 32) | x2) >> 13) & reduce_mask_25;
  out[4] = ((                       x3) >>  6) & reduce_mask_26;
  out[5] = (                        x4       ) & reduce_mask_25;
  out[6] = ((((uint64_t)x5 << 32) | x4) >> 25) & reduce_mask_26;
  out[7] = ((((uint64_t)x6 << 32) | x5) >> 19) & reduce_mask_25;
  out[8] = ((((uint64_t)x7 << 32) | x6) >> 12) & reduce_mask_26;
  out[9] = ((                       x7) >>  6); // & reduce_mask_25; /* ignore the top bit */
  out[0] += 19 * (out[9] >> 25);
  out[9] &= reduce_mask_25;
}

void ge25519_copy(ge25519 *dst, const ge25519 *src){
  curve25519_copy(dst->x, src->x);
  curve25519_copy(dst->y, src->y);
  curve25519_copy(dst->z, src->z);
  curve25519_copy(dst->t, src->t);
}

void ge25519_set_xmr_h(ge25519 *r){
  ge25519_copy(r, &xmr_h);
}

void ge25519_fromfe_frombytes_vartime(ge25519 *r, const unsigned char *s){
  bignum25519 u, v, w, x, y, z;
  unsigned char sign;

  curve25519_expand_reduce(u, s);

  curve25519_square(v, u);
  curve25519_add_reduce(v, v, v); /* 2 * u^2 */
  curve25519_set(w, 1);
  curve25519_add_reduce(w, v, w); /* w = 2 * u^2 + 1 */

  curve25519_square(x, w); /* w^2 */
  curve25519_mul(y, fe_ma2, v); /* -2 * A^2 * u^2 */
  curve25519_add_reduce(x, x, y); /* x = w^2 - 2 * A^2 * u^2 */

  curve25519_divpowm1(r->x, w, x); /* (w / x)^(m + 1) */
  curve25519_square(y, r->x);
  curve25519_mul(x, y, x);
  curve25519_sub_reduce(y, w, x);
  curve25519_copy(z, fe_ma);

  if (curve25519_isnonzero(y)) {
    curve25519_add_reduce(y, w, x);
    if (curve25519_isnonzero(y)) {
      goto negative;
    } else {
      curve25519_mul(r->x, r->x, fe_fffb1);
    }
  } else {
    curve25519_mul(r->x, r->x, fe_fffb2);
  }
  curve25519_mul(r->x, r->x, u); /* u * sqrt(2 * A * (A + 2) * w / x) */
  curve25519_mul(z, z, v); /* -2 * A * u^2 */
  sign = 0;
  goto setsign;
negative:
  curve25519_mul(x, x, fe_sqrtm1);
  curve25519_sub_reduce(y, w, x);
  if (curve25519_isnonzero(y)) {
    assert((curve25519_add_reduce(y, w, x), !curve25519_isnonzero(y)));
    curve25519_mul(r->x, r->x, fe_fffb3);
  } else {
    curve25519_mul(r->x, r->x, fe_fffb4);
  }
  /* r->x = sqrt(A * (A + 2) * w / x) */
  /* z = -A */
  sign = 1;
setsign:
  if (curve25519_isnegative(r->x) != sign) {
    assert(curve25519_isnonzero(r->x));
    curve25519_neg(r->x, r->x);
  }
  curve25519_add_reduce(r->z, z, w);
  curve25519_sub_reduce(r->y, z, w);
  curve25519_mul(r->x, r->x, r->z);

  // Partial form, saving from T coord computation .
  // Later is mul8 discarding T anyway.
  // rt = ((rx * ry % q) * inv(rz)) % q
  // curve25519_mul(x, r->x, r->y);
  // curve25519_recip(z, r->z);
  // curve25519_mul(r->t, x, z);

#if !defined(NDEBUG)
  {
    bignum25519 check_x, check_y, check_iz, check_v;
    curve25519_recip(check_iz, r->z);
    curve25519_mul(check_x, r->x, check_iz);
    curve25519_mul(check_y, r->y, check_iz);
    curve25519_square(check_x, check_x);
    curve25519_square(check_y, check_y);
    curve25519_mul(check_v, check_x, check_y);
    curve25519_mul(check_v, fe_d, check_v);
    curve25519_add_reduce(check_v, check_v, check_x);
    curve25519_sub_reduce(check_v, check_v, check_y);
    curve25519_set(check_x, 1);
    curve25519_add_reduce(check_v, check_v, check_x);
    assert(!curve25519_isnonzero(check_v));
  }
#endif
}

void xmr_hash_to_scalar(const void *data, size_t length, bignum256modm r){
  uint8_t hash[HASHER_DIGEST_LENGTH];
  hasher_Raw(HASHER_SHA3K, data, length, hash);
  expand256_modm(r, hash, HASHER_DIGEST_LENGTH);
}

void xmr_hash_to_ec(const void *data, size_t length, ge25519 *P){
  ge25519 point2;
  uint8_t hash[HASHER_DIGEST_LENGTH];
  hasher_Raw(HASHER_SHA3K, data, length, hash);

  ge25519_fromfe_frombytes_vartime(&point2, hash);
  ge25519_mul8(P, &point2);
}

