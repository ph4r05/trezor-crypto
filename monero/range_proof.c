//
// Created by Dusan Klinec on 10/05/2018.
//

#include "range_proof.h"


static void xmr_hash_ge25519_to_scalar(bignum256modm r, const ge25519 *p){
  unsigned char buff[32];
  ge25519_pack(buff, p);
  xmr_hash_to_scalar(buff, sizeof(buff), r);
}

void xmr_gen_range_sig(xmr_range_sig_t * sig, xmr_key_t * C, xmr_key_t * mask, xmr_amount amount, bignum256modm * last_mask){
  const int n = XMR_ATOMS;
  bignum256modm a={0};
  bignum256modm ai[64];
  bignum256modm alpha[64];
  bignum256modm si={0};
  bignum256modm c={0};
  bignum256modm ee={0};
  unsigned char buff[32];

  Hasher kck;
  xmr_hasher_init(&kck);

  ge25519 C_acc;
  ge25519 C_h;
  ge25519 C_tmp;
  ge25519 L;
  ge25519 Zero;

  ge25519_set_neutral(&Zero);
  ge25519_set_neutral(&C_acc);
  ge25519_set_xmr_h(&C_h);
  set256_modm(a, 0);

#define BB(i) ((amount>>(i)) & 1)

  // First pass, generates: ai, alpha, Ci, ee, s1
  for(unsigned ii=0; ii<n; ++ii){
    xmr_random_scalar(ai[ii]);
    if (last_mask != NULL && ii == n - 1){
      sub256_modm(ai[ii], *last_mask, a);
    }

    add256_modm(a, a, ai[ii]);  // creating the total mask since you have to pass this to receiver...
    xmr_random_scalar(alpha[ii]);

    ge25519_scalarmult_base_niels(&L, ge25519_niels_base_multiples, alpha[ii]);
    ge25519_scalarmult_base_niels(&C_tmp, ge25519_niels_base_multiples, ai[ii]);

    // C_tmp += &Zero if BB(ii) == 0 else &C_h
    ge25519_add(&C_tmp, &C_tmp, BB(ii) == 0 ? &Zero : &C_h, 0);
    ge25519_add(&C_acc, &C_acc, &C_tmp, 0);

    // Set Ci[ii] to sigs
    ge25519_pack(sig->Ci[ii].bytes, &C_tmp);

    if (BB(ii) == 0) {
      xmr_random_scalar(si);
      xmr_hash_ge25519_to_scalar(c, &L);

      ge25519_add(&C_tmp, &C_tmp, &C_h, 1); // Ci[ii] -= c_h
      xmr_add_keys1(&L, si, c, &C_tmp);

      // Set s1[ii] to sigs
      contract256_modm(sig->asig.s1[ii].bytes, si);
    }

    ge25519_pack(buff, &L);
    xmr_hasher_update(&kck, buff, sizeof(buff));

    ge25519_double(&C_h, &C_h);  // c_H = crypto.scalarmult(c_H, 2)
  }

  // Compute ee
  xmr_hasher_final(&kck, buff);
  expand256_modm(ee, buff, sizeof(buff));

  ge25519_set_xmr_h(&C_h);

  // Second pass, s0, s1
  for(unsigned ii=0; ii<n; ++ii){
    if (BB(ii) != 1){
      mulsub256_modm(si, alpha[ii], ai[ii], ee);
      contract256_modm(sig->asig.s0[ii].bytes, si);

    } else {
      xmr_random_scalar(si);
      contract256_modm(sig->asig.s0[ii].bytes, si);

      ge25519_unpack_vartime(&C_tmp, sig->Ci[ii].bytes);
      xmr_add_keys1(&L, si, ee, &C_tmp);
      xmr_hash_ge25519_to_scalar(c, &L);

      mulsub256_modm(si, alpha[ii], ai[ii], c);
      contract256_modm(sig->asig.s1[ii].bytes, si);
    }

    ge25519_double(&C_h, &C_h);  // c_H = crypto.scalarmult(c_H, 2)
  }

  ge25519_pack(C->bytes, &C_tmp);
  contract256_modm(mask->bytes, a);
  contract256_modm(sig->asig.ee.bytes, ee);
#undef BB
}

