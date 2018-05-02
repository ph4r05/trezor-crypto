/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <check.h>

#ifdef VALGRIND
#include <valgrind/valgrind.h>
#include <valgrind/memcheck.h>
#endif

#include "options.h"

#include "aes/aes.h"
#include "bignum.h"
#include "base58.h"
#include "bip32.h"
#include "bip39.h"
#include "pbkdf2.h"
#include "blake2b.h"
#include "blake2s.h"
#include "curves.h"
#include "secp256k1.h"
#include "nist256p1.h"
#include "ed25519-donna/ed25519-donna.h"
#include "ed25519-donna/ed25519-keccak.h"
#include "script.h"
#include "rfc6979.h"
#include "address.h"
#include "rc4.h"
#include "nem.h"

#include "monero/base58.h"
#include "monero/crypto.h"


/*
 * This is a clever trick to make Valgrind's Memcheck verify code
 * is constant-time with respect to secret data.
 */
#ifdef VALGRIND
/* Call after secret data is written, before first use */
#define   MARK_SECRET_DATA(addr, len) VALGRIND_MAKE_MEM_UNDEFINED(addr, len)
/* Call before secret data is freed or to mark non-secret data (public keys or signatures) */
#define UNMARK_SECRET_DATA(addr, len) VALGRIND_MAKE_MEM_DEFINED  (addr, len)
#else
#define   MARK_SECRET_DATA(addr, len)
#define UNMARK_SECRET_DATA(addr, len)
#endif

#define FROMHEX_MAXLEN 512

#define VERSION_PUBLIC  0x0488b21e
#define VERSION_PRIVATE 0x0488ade4

#define DECRED_VERSION_PUBLIC  0x02fda926
#define DECRED_VERSION_PRIVATE 0x02fda4e8

const uint8_t *fromhex(const char *str)
{
	static uint8_t buf[FROMHEX_MAXLEN];
	size_t len = strlen(str) / 2;
	if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
	for (size_t i = 0; i < len; i++) {
		uint8_t c = 0;
		if (str[i * 2] >= '0' && str[i*2] <= '9') c += (str[i * 2] - '0') << 4;
		if ((str[i * 2] & ~0x20) >= 'A' && (str[i*2] & ~0x20) <= 'F') c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
		if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') c += (str[i * 2 + 1] - '0');
		if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F') c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
		buf[i] = c;
	}
	return buf;
}

void nem_private_key(const char *reversed_hex, ed25519_secret_key private_key) {
	const uint8_t *reversed_key = fromhex(reversed_hex);
	for (size_t j = 0; j < sizeof(ed25519_secret_key); j++) {
		private_key[j] = reversed_key[sizeof(ed25519_secret_key) - j - 1];
	}
}

// from https://github.com/bitcoin/bitcoin/blob/master/src/test/data/base58_keys_valid.json
START_TEST(test_base58)
{
	static const char *base58_vector[] = {
		"0065a16059864a2fdbc7c99a4723a8395bc6f188eb", "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
		"0574f209f6ea907e2ea48f74fae05782ae8a665257", "3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou",
		"6f53c0307d6851aa0ce7825ba883c6bd9ad242b486", "mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs",
		"c46349a418fc4578d10a372b54b45c280cc8c4382f", "2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br",
		"80eddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19", "5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLr",
		"8055c9bccb9ed68446d1b75273bbce89d7fe013a8acd1625514420fb2aca1a21c401", "Kz6UJmQACJmLtaQj5A3JAge4kVTNQ8gbvXuwbmCj7bsaabudb3RD",
		"ef36cb93b9ab1bdabf7fb9f2c04f1b9cc879933530ae7842398eef5a63a56800c2", "9213qJab2HNEpMpYNBa7wHGFKKbkDn24jpANDs2huN3yi4J11ko",
		"efb9f4892c9e8282028fea1d2667c4dc5213564d41fc5783896a0d843fc15089f301", "cTpB4YiyKiBcPxnefsDpbnDxFDffjqJob8wGCEDXxgQ7zQoMXJdH",
		"006d23156cbbdcc82a5a47eee4c2c7c583c18b6bf4", "1Ax4gZtb7gAit2TivwejZHYtNNLT18PUXJ",
		"05fcc5460dd6e2487c7d75b1963625da0e8f4c5975", "3QjYXhTkvuj8qPaXHTTWb5wjXhdsLAAWVy",
		"6ff1d470f9b02370fdec2e6b708b08ac431bf7a5f7", "n3ZddxzLvAY9o7184TB4c6FJasAybsw4HZ",
		"c4c579342c2c4c9220205e2cdc285617040c924a0a", "2NBFNJTktNa7GZusGbDbGKRZTxdK9VVez3n",
		"80a326b95ebae30164217d7a7f57d72ab2b54e3be64928a19da0210b9568d4015e", "5K494XZwps2bGyeL71pWid4noiSNA2cfCibrvRWqcHSptoFn7rc",
		"807d998b45c219a1e38e99e7cbd312ef67f77a455a9b50c730c27f02c6f730dfb401", "L1RrrnXkcKut5DEMwtDthjwRcTTwED36thyL1DebVrKuwvohjMNi",
		"efd6bca256b5abc5602ec2e1c121a08b0da2556587430bcf7e1898af2224885203", "93DVKyFYwSN6wEo3E2fCrFPUp17FtrtNi2Lf7n4G3garFb16CRj",
		"efa81ca4e8f90181ec4b61b6a7eb998af17b2cb04de8a03b504b9e34c4c61db7d901", "cTDVKtMGVYWTHCb1AFjmVbEbWjvKpKqKgMaR3QJxToMSQAhmCeTN",
		"007987ccaa53d02c8873487ef919677cd3db7a6912", "1C5bSj1iEGUgSTbziymG7Cn18ENQuT36vv",
		"0563bcc565f9e68ee0189dd5cc67f1b0e5f02f45cb", "3AnNxabYGoTxYiTEZwFEnerUoeFXK2Zoks",
		"6fef66444b5b17f14e8fae6e7e19b045a78c54fd79", "n3LnJXCqbPjghuVs8ph9CYsAe4Sh4j97wk",
		"c4c3e55fceceaa4391ed2a9677f4a4d34eacd021a0", "2NB72XtkjpnATMggui83aEtPawyyKvnbX2o",
		"80e75d936d56377f432f404aabb406601f892fd49da90eb6ac558a733c93b47252", "5KaBW9vNtWNhc3ZEDyNCiXLPdVPHCikRxSBWwV9NrpLLa4LsXi9",
		"808248bd0375f2f75d7e274ae544fb920f51784480866b102384190b1addfbaa5c01", "L1axzbSyynNYA8mCAhzxkipKkfHtAXYF4YQnhSKcLV8YXA874fgT",
		"ef44c4f6a096eac5238291a94cc24c01e3b19b8d8cef72874a079e00a242237a52", "927CnUkUbasYtDwYwVn2j8GdTuACNnKkjZ1rpZd2yBB1CLcnXpo",
		"efd1de707020a9059d6d3abaf85e17967c6555151143db13dbb06db78df0f15c6901", "cUcfCMRjiQf85YMzzQEk9d1s5A4K7xL5SmBCLrezqXFuTVefyhY7",
		"00adc1cc2081a27206fae25792f28bbc55b831549d", "1Gqk4Tv79P91Cc1STQtU3s1W6277M2CVWu",
		"05188f91a931947eddd7432d6e614387e32b244709", "33vt8ViH5jsr115AGkW6cEmEz9MpvJSwDk",
		"6f1694f5bc1a7295b600f40018a618a6ea48eeb498", "mhaMcBxNh5cqXm4aTQ6EcVbKtfL6LGyK2H",
		"c43b9b3fd7a50d4f08d1a5b0f62f644fa7115ae2f3", "2MxgPqX1iThW3oZVk9KoFcE5M4JpiETssVN",
		"80091035445ef105fa1bb125eccfb1882f3fe69592265956ade751fd095033d8d0", "5HtH6GdcwCJA4ggWEL1B3jzBBUB8HPiBi9SBc5h9i4Wk4PSeApR",
		"80ab2b4bcdfc91d34dee0ae2a8c6b6668dadaeb3a88b9859743156f462325187af01", "L2xSYmMeVo3Zek3ZTsv9xUrXVAmrWxJ8Ua4cw8pkfbQhcEFhkXT8",
		"efb4204389cef18bbe2b353623cbf93e8678fbc92a475b664ae98ed594e6cf0856", "92xFEve1Z9N8Z641KQQS7ByCSb8kGjsDzw6fAmjHN1LZGKQXyMq",
		"efe7b230133f1b5489843260236b06edca25f66adb1be455fbd38d4010d48faeef01", "cVM65tdYu1YK37tNoAyGoJTR13VBYFva1vg9FLuPAsJijGvG6NEA",
		"00c4c1b72491ede1eedaca00618407ee0b772cad0d", "1JwMWBVLtiqtscbaRHai4pqHokhFCbtoB4",
		"05f6fe69bcb548a829cce4c57bf6fff8af3a5981f9", "3QCzvfL4ZRvmJFiWWBVwxfdaNBT8EtxB5y",
		"6f261f83568a098a8638844bd7aeca039d5f2352c0", "mizXiucXRCsEriQCHUkCqef9ph9qtPbZZ6",
		"c4e930e1834a4d234702773951d627cce82fbb5d2e", "2NEWDzHWwY5ZZp8CQWbB7ouNMLqCia6YRda",
		"80d1fab7ab7385ad26872237f1eb9789aa25cc986bacc695e07ac571d6cdac8bc0", "5KQmDryMNDcisTzRp3zEq9e4awRmJrEVU1j5vFRTKpRNYPqYrMg",
		"80b0bbede33ef254e8376aceb1510253fc3550efd0fcf84dcd0c9998b288f166b301", "L39Fy7AC2Hhj95gh3Yb2AU5YHh1mQSAHgpNixvm27poizcJyLtUi",
		"ef037f4192c630f399d9271e26c575269b1d15be553ea1a7217f0cb8513cef41cb", "91cTVUcgydqyZLgaANpf1fvL55FH53QMm4BsnCADVNYuWuqdVys",
		"ef6251e205e8ad508bab5596bee086ef16cd4b239e0cc0c5d7c4e6035441e7d5de01", "cQspfSzsgLeiJGB2u8vrAiWpCU4MxUT6JseWo2SjXy4Qbzn2fwDw",
		"005eadaf9bb7121f0f192561a5a62f5e5f54210292", "19dcawoKcZdQz365WpXWMhX6QCUpR9SY4r",
		"053f210e7277c899c3a155cc1c90f4106cbddeec6e", "37Sp6Rv3y4kVd1nQ1JV5pfqXccHNyZm1x3",
		"6fc8a3c2a09a298592c3e180f02487cd91ba3400b5", "myoqcgYiehufrsnnkqdqbp69dddVDMopJu",
		"c499b31df7c9068d1481b596578ddbb4d3bd90baeb", "2N7FuwuUuoTBrDFdrAZ9KxBmtqMLxce9i1C",
		"80c7666842503db6dc6ea061f092cfb9c388448629a6fe868d068c42a488b478ae", "5KL6zEaMtPRXZKo1bbMq7JDjjo1bJuQcsgL33je3oY8uSJCR5b4",
		"8007f0803fc5399e773555ab1e8939907e9badacc17ca129e67a2f5f2ff84351dd01", "KwV9KAfwbwt51veZWNscRTeZs9CKpojyu1MsPnaKTF5kz69H1UN2",
		"efea577acfb5d1d14d3b7b195c321566f12f87d2b77ea3a53f68df7ebf8604a801", "93N87D6uxSBzwXvpokpzg8FFmfQPmvX4xHoWQe3pLdYpbiwT5YV",
		"ef0b3b34f0958d8a268193a9814da92c3e8b58b4a4378a542863e34ac289cd830c01", "cMxXusSihaX58wpJ3tNuuUcZEQGt6DKJ1wEpxys88FFaQCYjku9h",
		"001ed467017f043e91ed4c44b4e8dd674db211c4e6", "13p1ijLwsnrcuyqcTvJXkq2ASdXqcnEBLE",
		"055ece0cadddc415b1980f001785947120acdb36fc", "3ALJH9Y951VCGcVZYAdpA3KchoP9McEj1G",
		0, 0,
	};
	const char **raw = base58_vector;
	const char **str = base58_vector + 1;
	uint8_t rawn[34];
	char strn[53];
	int r;
	while (*raw && *str) {
		int len = strlen(*raw) / 2;

		memcpy(rawn, fromhex(*raw), len);
		r = base58_encode_check(rawn, len, HASHER_SHA2D, strn, sizeof(strn));
		ck_assert_int_eq((size_t)r, strlen(*str) + 1);
		ck_assert_str_eq(strn, *str);

		r = base58_decode_check(strn, HASHER_SHA2D, rawn, len);
		ck_assert_int_eq(r, len);
		ck_assert_mem_eq(rawn,  fromhex(*raw), len);

		raw += 2; str += 2;
	}
}
END_TEST



START_TEST(test_ecdsa_signature)
{
	int res;
	uint8_t digest[32];
	uint8_t pubkey[65];
	const ecdsa_curve *curve = &secp256k1;


	// sha2(sha2("\x18Bitcoin Signed Message:\n\x0cHello World!"))
	memcpy(digest, fromhex("de4e9524586d6fce45667f9ff12f661e79870c4105fa0fb58af976619bb11432"), 32);
	// r = 2:  Four points should exist
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("00000000000000000000000000000000000000000000000000000000000000020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), digest, 0);
	ck_assert_int_eq(res, 0);
	ck_assert_mem_eq(pubkey,  fromhex("043fc5bf5fec35b6ffe6fd246226d312742a8c296bfa57dd22da509a2e348529b7ddb9faf8afe1ecda3c05e7b2bda47ee1f5a87e952742b22afca560b29d972fcf"), 65);
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("00000000000000000000000000000000000000000000000000000000000000020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), digest, 1);
	ck_assert_int_eq(res, 0);
	ck_assert_mem_eq(pubkey,  fromhex("0456d8089137b1fd0d890f8c7d4a04d0fd4520a30b19518ee87bd168ea12ed8090329274c4c6c0d9df04515776f2741eeffc30235d596065d718c3973e19711ad0"), 65);
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("00000000000000000000000000000000000000000000000000000000000000020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), digest, 2);
	ck_assert_int_eq(res, 0);
	ck_assert_mem_eq(pubkey,  fromhex("04cee0e740f41aab39156844afef0182dea2a8026885b10454a2d539df6f6df9023abfcb0f01c50bef3c0fa8e59a998d07441e18b1c60583ef75cc8b912fb21a15"), 65);
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("00000000000000000000000000000000000000000000000000000000000000020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), digest, 3);
	ck_assert_int_eq(res, 0);
	ck_assert_mem_eq(pubkey,  fromhex("0490d2bd2e9a564d6e1d8324fc6ad00aa4ae597684ecf4abea58bdfe7287ea4fa72968c2e5b0b40999ede3d7898d94e82c3f8dc4536a567a4bd45998c826a4c4b2"), 65);

	memcpy(digest, fromhex("0000000000000000000000000000000000000000000000000000000000000000"), 32);
	// r = 7:  No point P with P.x = 7,  but P.x = (order + 7) exists
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("00000000000000000000000000000000000000000000000000000000000000070123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), digest, 2);
	ck_assert_int_eq(res, 0);
	ck_assert_mem_eq(pubkey,  fromhex("044d81bb47a31ffc6cf1f780ecb1e201ec47214b651650867c07f13ad06e12a1b040de78f8dbda700f4d3cd7ee21b3651a74c7661809699d2be7ea0992b0d39797"), 65);
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("00000000000000000000000000000000000000000000000000000000000000070123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), digest, 3);
	ck_assert_int_eq(res, 0);
	ck_assert_mem_eq(pubkey,  fromhex("044d81bb47a31ffc6cf1f780ecb1e201ec47214b651650867c07f13ad06e12a1b0bf21870724258ff0b2c32811de4c9ae58b3899e7f69662d41815f66c4f2c6498"), 65);
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("00000000000000000000000000000000000000000000000000000000000000070123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), digest, 0);
	ck_assert_int_eq(res, 1);

	memcpy(digest, fromhex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), 32);
	// r = 1:  Two points P with P.x = 1,  but P.x = (order + 7) doesn't exist
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("00000000000000000000000000000000000000000000000000000000000000010123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), digest, 0);
	ck_assert_int_eq(res, 0);
	ck_assert_mem_eq(pubkey,  fromhex("045d330b2f89dbfca149828277bae852dd4aebfe136982cb531a88e9e7a89463fe71519f34ea8feb9490c707f14bc38c9ece51762bfd034ea014719b7c85d2871b"), 65);
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("00000000000000000000000000000000000000000000000000000000000000010123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), digest, 1);
	ck_assert_int_eq(res, 0);
	ck_assert_mem_eq(pubkey,  fromhex("049e609c3950e70d6f3e3f3c81a473b1d5ca72739d51debdd80230ae80cab05134a94285375c834a417e8115c546c41da83a263087b79ef1cae25c7b3c738daa2b"), 65);

	// r = 0 is always invalid
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("00000000000000000000000000000000000000000000000000000000000000010123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), digest, 2);
	ck_assert_int_eq(res, 1);
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("00000000000000000000000000000000000000000000000000000000000000000123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), digest, 0);
	ck_assert_int_eq(res, 1);
	// r >= order is always invalid
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd03641410123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), digest, 0);
	ck_assert_int_eq(res, 1);
	// check that overflow of r is handled
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("000000000000000000000000000000014551231950B75FC4402DA1722FC9BAEE0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), digest, 2);
	ck_assert_int_eq(res, 1);
	// s = 0 is always invalid
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000"), digest, 0);
	ck_assert_int_eq(res, 1);
	// s >= order is always invalid
	res = ecdsa_verify_digest_recover(curve, pubkey, fromhex("0000000000000000000000000000000000000000000000000000000000000002fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"), digest, 0);
	ck_assert_int_eq(res, 1);
}
END_TEST

#define test_deterministic(KEY, MSG, K) do { \
	sha256_Raw((uint8_t *)MSG, strlen(MSG), buf); \
	init_rfc6979(fromhex(KEY), buf, &rng); \
	generate_k_rfc6979(&k, &rng); \
	bn_write_be(&k, buf); \
	ck_assert_mem_eq(buf, fromhex(K), 32); \
} while (0)

START_TEST(test_rfc6979)
{
	bignum256 k;
	uint8_t buf[32];
	rfc6979_state rng;

	test_deterministic("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", "sample", "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60");
	test_deterministic("cca9fbcc1b41e5a95d369eaa6ddcff73b61a4efaa279cfc6567e8daa39cbaf50", "sample", "2df40ca70e639d89528a6b670d9d48d9165fdc0febc0974056bdce192b8e16a3");
	test_deterministic("0000000000000000000000000000000000000000000000000000000000000001", "Satoshi Nakamoto", "8f8a276c19f4149656b280621e358cce24f5f52542772691ee69063b74f15d15");
	test_deterministic("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140", "Satoshi Nakamoto", "33a19b60e25fb6f4435af53a3d42d493644827367e6453928554f43e49aa6f90");
	test_deterministic("f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181", "Alan Turing", "525a82b70e67874398067543fd84c83d30c175fdc45fdeee082fe13b1d7cfdf1");
	test_deterministic("0000000000000000000000000000000000000000000000000000000000000001", "All those moments will be lost in time, like tears in rain. Time to die...", "38aa22d72376b4dbc472e06c3ba403ee0a394da63fc58d88686c611aba98d6b3");
	test_deterministic("e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2", "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!", "1f4b84c23a86a221d233f2521be018d9318639d5b8bbd6374a8a59232d16ad3d");
}
END_TEST


#define TEST1    "abc"
#define TEST2_1  \
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
#define TEST2_2a \
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
#define TEST2_2b \
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
#define TEST2_2  TEST2_2a TEST2_2b
#define TEST3    "a"                            /* times 1000000 */
#define TEST4a   "01234567012345670123456701234567"
#define TEST4b   "01234567012345670123456701234567"
    /* an exact multiple of 512 bits */
#define TEST4   TEST4a TEST4b                   /* times 10 */

#define TEST7_1 \
  "\x49\xb2\xae\xc2\x59\x4b\xbe\x3a\x3b\x11\x75\x42\xd9\x4a\xc8"
#define TEST8_1 \
  "\x9a\x7d\xfd\xf1\xec\xea\xd0\x6e\xd6\x46\xaa\x55\xfe\x75\x71\x46"
#define TEST9_1 \
  "\x65\xf9\x32\x99\x5b\xa4\xce\x2c\xb1\xb4\xa2\xe7\x1a\xe7\x02\x20" \
  "\xaa\xce\xc8\x96\x2d\xd4\x49\x9c\xbd\x7c\x88\x7a\x94\xea\xaa\x10" \
  "\x1e\xa5\xaa\xbc\x52\x9b\x4e\x7e\x43\x66\x5a\x5a\xf2\xcd\x03\xfe" \
  "\x67\x8e\xa6\xa5\x00\x5b\xba\x3b\x08\x22\x04\xc2\x8b\x91\x09\xf4" \
  "\x69\xda\xc9\x2a\xaa\xb3\xaa\x7c\x11\xa1\xb3\x2a"
#define TEST10_1 \
  "\xf7\x8f\x92\x14\x1b\xcd\x17\x0a\xe8\x9b\x4f\xba\x15\xa1\xd5\x9f" \
  "\x3f\xd8\x4d\x22\x3c\x92\x51\xbd\xac\xbb\xae\x61\xd0\x5e\xd1\x15" \
  "\xa0\x6a\x7c\xe1\x17\xb7\xbe\xea\xd2\x44\x21\xde\xd9\xc3\x25\x92" \
  "\xbd\x57\xed\xea\xe3\x9c\x39\xfa\x1f\xe8\x94\x6a\x84\xd0\xcf\x1f" \
  "\x7b\xee\xad\x17\x13\xe2\xe0\x95\x98\x97\x34\x7f\x67\xc8\x0b\x04" \
  "\x00\xc2\x09\x81\x5d\x6b\x10\xa6\x83\x83\x6f\xd5\x56\x2a\x56\xca" \
  "\xb1\xa2\x8e\x81\xb6\x57\x66\x54\x63\x1c\xf1\x65\x66\xb8\x6e\x3b" \
  "\x33\xa1\x08\xb0\x53\x07\xc0\x0a\xff\x14\xa7\x68\xed\x73\x50\x60" \
  "\x6a\x0f\x85\xe6\xa9\x1d\x39\x6f\x5b\x5c\xbe\x57\x7f\x9b\x38\x80" \
  "\x7c\x7d\x52\x3d\x6d\x79\x2f\x6e\xbc\x24\xa4\xec\xf2\xb3\xa4\x27" \
  "\xcd\xbb\xfb"
#define length(x) (sizeof(x)-1)

// test vectors from rfc-4634
START_TEST(test_sha1)
{
	struct {
		const char* test;
		int   length;
		int   repeatcount;
		int   extrabits;
		int   numberExtrabits;
		const char* result;
	} tests[] = {
		/* 1 */ { TEST1, length(TEST1), 1, 0, 0,
				  "A9993E364706816ABA3E25717850C26C9CD0D89D" },
		/* 2 */ { TEST2_1, length(TEST2_1), 1, 0, 0,
				  "84983E441C3BD26EBAAE4AA1F95129E5E54670F1" },
		/* 3 */ { TEST3, length(TEST3), 1000000, 0, 0,
				  "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F" },
		/* 4 */ { TEST4, length(TEST4), 10, 0, 0,
				  "DEA356A2CDDD90C7A7ECEDC5EBB563934F460452" },
		/* 5 */ {  "", 0, 0, 0x98, 5,
				  "29826B003B906E660EFF4027CE98AF3531AC75BA" },
		/* 6 */ {  "\x5e", 1, 1, 0, 0,
				  "5E6F80A34A9798CAFC6A5DB96CC57BA4C4DB59C2" },
		/* 7 */ { TEST7_1, length(TEST7_1), 1, 0x80, 3,
				  "6239781E03729919C01955B3FFA8ACB60B988340" },
		/* 8 */ { TEST8_1, length(TEST8_1), 1, 0, 0,
				  "82ABFF6605DBE1C17DEF12A394FA22A82B544A35" },
		/* 9 */ { TEST9_1, length(TEST9_1), 1, 0xE0, 3,
				  "8C5B2A5DDAE5A97FC7F9D85661C672ADBF7933D4" },
		/* 10 */ { TEST10_1, length(TEST10_1), 1, 0, 0,
				  "CB0082C8F197D260991BA6A460E76E202BAD27B3" }
	};

	for (int i = 0; i < 10; i++) {
		SHA1_CTX ctx;
		uint8_t digest[SHA1_DIGEST_LENGTH];
		sha1_Init(&ctx);
		/* extra bits are not supported */
		if (tests[i].numberExtrabits)
			continue;
		for (int j = 0; j < tests[i].repeatcount; j++) {
			sha1_Update(&ctx, (const uint8_t*) tests[i].test, tests[i].length);
		}
		sha1_Final(&ctx, digest);
		ck_assert_mem_eq(digest, fromhex(tests[i].result), SHA1_DIGEST_LENGTH);
	}
}
END_TEST

#define TEST7_256 \
  "\xbe\x27\x46\xc6\xdb\x52\x76\x5f\xdb\x2f\x88\x70\x0f\x9a\x73"
#define TEST8_256 \
  "\xe3\xd7\x25\x70\xdc\xdd\x78\x7c\xe3\x88\x7a\xb2\xcd\x68\x46\x52"
#define TEST9_256 \
  "\x3e\x74\x03\x71\xc8\x10\xc2\xb9\x9f\xc0\x4e\x80\x49\x07\xef\x7c" \
  "\xf2\x6b\xe2\x8b\x57\xcb\x58\xa3\xe2\xf3\xc0\x07\x16\x6e\x49\xc1" \
  "\x2e\x9b\xa3\x4c\x01\x04\x06\x91\x29\xea\x76\x15\x64\x25\x45\x70" \
  "\x3a\x2b\xd9\x01\xe1\x6e\xb0\xe0\x5d\xeb\xa0\x14\xeb\xff\x64\x06" \
  "\xa0\x7d\x54\x36\x4e\xff\x74\x2d\xa7\x79\xb0\xb3"
#define TEST10_256 \
  "\x83\x26\x75\x4e\x22\x77\x37\x2f\x4f\xc1\x2b\x20\x52\x7a\xfe\xf0" \
  "\x4d\x8a\x05\x69\x71\xb1\x1a\xd5\x71\x23\xa7\xc1\x37\x76\x00\x00" \
  "\xd7\xbe\xf6\xf3\xc1\xf7\xa9\x08\x3a\xa3\x9d\x81\x0d\xb3\x10\x77" \
  "\x7d\xab\x8b\x1e\x7f\x02\xb8\x4a\x26\xc7\x73\x32\x5f\x8b\x23\x74" \
  "\xde\x7a\x4b\x5a\x58\xcb\x5c\x5c\xf3\x5b\xce\xe6\xfb\x94\x6e\x5b" \
  "\xd6\x94\xfa\x59\x3a\x8b\xeb\x3f\x9d\x65\x92\xec\xed\xaa\x66\xca" \
  "\x82\xa2\x9d\x0c\x51\xbc\xf9\x33\x62\x30\xe5\xd7\x84\xe4\xc0\xa4" \
  "\x3f\x8d\x79\xa3\x0a\x16\x5c\xba\xbe\x45\x2b\x77\x4b\x9c\x71\x09" \
  "\xa9\x7d\x13\x8f\x12\x92\x28\x96\x6f\x6c\x0a\xdc\x10\x6a\xad\x5a" \
  "\x9f\xdd\x30\x82\x57\x69\xb2\xc6\x71\xaf\x67\x59\xdf\x28\xeb\x39" \
  "\x3d\x54\xd6"

// test vectors from rfc-4634
START_TEST(test_sha256)
{
	struct {
		const char* test;
		int   length;
		int   repeatcount;
		int   extrabits;
		int   numberExtrabits;
		const char* result;
	} tests[] = {
		/* 1 */ { TEST1, length(TEST1), 1, 0, 0, "BA7816BF8F01CFEA4141"
				  "40DE5DAE2223B00361A396177A9CB410FF61F20015AD" },
		/* 2 */ { TEST2_1, length(TEST2_1), 1, 0, 0, "248D6A61D20638B8"
				  "E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1" },
		/* 3 */ { TEST3, length(TEST3), 1000000, 0, 0, "CDC76E5C9914FB92"
				  "81A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0" },
		/* 4 */ { TEST4, length(TEST4), 10, 0, 0, "594847328451BDFA"
				  "85056225462CC1D867D877FB388DF0CE35F25AB5562BFBB5" },
		/* 5 */ { "", 0, 0, 0x68, 5, "D6D3E02A31A84A8CAA9718ED6C2057BE"
				  "09DB45E7823EB5079CE7A573A3760F95" },
		/* 6 */ { "\x19", 1, 1, 0, 0, "68AA2E2EE5DFF96E3355E6C7EE373E3D"
				  "6A4E17F75F9518D843709C0C9BC3E3D4" },
		/* 7 */ { TEST7_256, length(TEST7_256), 1, 0x60, 3, "77EC1DC8"
				  "9C821FF2A1279089FA091B35B8CD960BCAF7DE01C6A7680756BEB972" },
		/* 8 */ { TEST8_256, length(TEST8_256), 1, 0, 0, "175EE69B02BA"
				  "9B58E2B0A5FD13819CEA573F3940A94F825128CF4209BEABB4E8" },
		/* 9 */ { TEST9_256, length(TEST9_256), 1, 0xA0, 3, "3E9AD646"
				  "8BBBAD2AC3C2CDC292E018BA5FD70B960CF1679777FCE708FDB066E9" },
		/* 10 */ { TEST10_256, length(TEST10_256), 1, 0, 0, "97DBCA7D"
				   "F46D62C8A422C941DD7E835B8AD3361763F7E9B2D95F4F0DA6E1CCBC" },
	};

	for (int i = 0; i < 10; i++) {
		SHA256_CTX ctx;
		uint8_t digest[SHA256_DIGEST_LENGTH];
		sha256_Init(&ctx);
		/* extra bits are not supported */
		if (tests[i].numberExtrabits)
			continue;
		for (int j = 0; j < tests[i].repeatcount; j++) {
			sha256_Update(&ctx, (const uint8_t*) tests[i].test, tests[i].length);
		}
		sha256_Final(&ctx, digest);
		ck_assert_mem_eq(digest, fromhex(tests[i].result), SHA256_DIGEST_LENGTH);
	}
}
END_TEST

#define TEST7_512 \
  "\x08\xec\xb5\x2e\xba\xe1\xf7\x42\x2d\xb6\x2b\xcd\x54\x26\x70"
#define TEST8_512 \
  "\x8d\x4e\x3c\x0e\x38\x89\x19\x14\x91\x81\x6e\x9d\x98\xbf\xf0\xa0"
#define TEST9_512 \
  "\x3a\xdd\xec\x85\x59\x32\x16\xd1\x61\x9a\xa0\x2d\x97\x56\x97\x0b" \
  "\xfc\x70\xac\xe2\x74\x4f\x7c\x6b\x27\x88\x15\x10\x28\xf7\xb6\xa2" \
  "\x55\x0f\xd7\x4a\x7e\x6e\x69\xc2\xc9\xb4\x5f\xc4\x54\x96\x6d\xc3" \
  "\x1d\x2e\x10\xda\x1f\x95\xce\x02\xbe\xb4\xbf\x87\x65\x57\x4c\xbd" \
  "\x6e\x83\x37\xef\x42\x0a\xdc\x98\xc1\x5c\xb6\xd5\xe4\xa0\x24\x1b" \
  "\xa0\x04\x6d\x25\x0e\x51\x02\x31\xca\xc2\x04\x6c\x99\x16\x06\xab" \
  "\x4e\xe4\x14\x5b\xee\x2f\xf4\xbb\x12\x3a\xab\x49\x8d\x9d\x44\x79" \
  "\x4f\x99\xcc\xad\x89\xa9\xa1\x62\x12\x59\xed\xa7\x0a\x5b\x6d\xd4" \
  "\xbd\xd8\x77\x78\xc9\x04\x3b\x93\x84\xf5\x49\x06"
#define TEST10_512 \
  "\xa5\x5f\x20\xc4\x11\xaa\xd1\x32\x80\x7a\x50\x2d\x65\x82\x4e\x31" \
  "\xa2\x30\x54\x32\xaa\x3d\x06\xd3\xe2\x82\xa8\xd8\x4e\x0d\xe1\xde" \
  "\x69\x74\xbf\x49\x54\x69\xfc\x7f\x33\x8f\x80\x54\xd5\x8c\x26\xc4" \
  "\x93\x60\xc3\xe8\x7a\xf5\x65\x23\xac\xf6\xd8\x9d\x03\xe5\x6f\xf2" \
  "\xf8\x68\x00\x2b\xc3\xe4\x31\xed\xc4\x4d\xf2\xf0\x22\x3d\x4b\xb3" \
  "\xb2\x43\x58\x6e\x1a\x7d\x92\x49\x36\x69\x4f\xcb\xba\xf8\x8d\x95" \
  "\x19\xe4\xeb\x50\xa6\x44\xf8\xe4\xf9\x5e\xb0\xea\x95\xbc\x44\x65" \
  "\xc8\x82\x1a\xac\xd2\xfe\x15\xab\x49\x81\x16\x4b\xbb\x6d\xc3\x2f" \
  "\x96\x90\x87\xa1\x45\xb0\xd9\xcc\x9c\x67\xc2\x2b\x76\x32\x99\x41" \
  "\x9c\xc4\x12\x8b\xe9\xa0\x77\xb3\xac\xe6\x34\x06\x4e\x6d\x99\x28" \
  "\x35\x13\xdc\x06\xe7\x51\x5d\x0d\x73\x13\x2e\x9a\x0d\xc6\xd3\xb1" \
  "\xf8\xb2\x46\xf1\xa9\x8a\x3f\xc7\x29\x41\xb1\xe3\xbb\x20\x98\xe8" \
  "\xbf\x16\xf2\x68\xd6\x4f\x0b\x0f\x47\x07\xfe\x1e\xa1\xa1\x79\x1b" \
  "\xa2\xf3\xc0\xc7\x58\xe5\xf5\x51\x86\x3a\x96\xc9\x49\xad\x47\xd7" \
  "\xfb\x40\xd2"

// test vectors from rfc-4634
START_TEST(test_sha512)
{
	struct {
		const char* test;
		int   length;
		int   repeatcount;
		int   extrabits;
		int   numberExtrabits;
		const char* result;
	} tests[] = {
		/* 1 */ { TEST1, length(TEST1), 1, 0, 0,
				  "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA2"
				  "0A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD"
				  "454D4423643CE80E2A9AC94FA54CA49F" },
		/* 2 */ { TEST2_2, length(TEST2_2), 1, 0, 0,
				  "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA1"
				  "7299AEADB6889018501D289E4900F7E4331B99DEC4B5433A"
				  "C7D329EEB6DD26545E96E55B874BE909" },
		/* 3 */ { TEST3, length(TEST3), 1000000, 0, 0,
				  "E718483D0CE769644E2E42C7BC15B4638E1F98B13B204428"
				  "5632A803AFA973EBDE0FF244877EA60A4CB0432CE577C31B"
				  "EB009C5C2C49AA2E4EADB217AD8CC09B" },
		/* 4 */ { TEST4, length(TEST4), 10, 0, 0,
				  "89D05BA632C699C31231DED4FFC127D5A894DAD412C0E024"
				  "DB872D1ABD2BA8141A0F85072A9BE1E2AA04CF33C765CB51"
				  "0813A39CD5A84C4ACAA64D3F3FB7BAE9" },
		/* 5 */ { "", 0, 0, 0xB0, 5,
				  "D4EE29A9E90985446B913CF1D1376C836F4BE2C1CF3CADA0"
				  "720A6BF4857D886A7ECB3C4E4C0FA8C7F95214E41DC1B0D2"
				  "1B22A84CC03BF8CE4845F34DD5BDBAD4" },
		/* 6 */ { "\xD0", 1, 1, 0, 0,
				  "9992202938E882E73E20F6B69E68A0A7149090423D93C81B"
				  "AB3F21678D4ACEEEE50E4E8CAFADA4C85A54EA8306826C4A"
				  "D6E74CECE9631BFA8A549B4AB3FBBA15" },
		/* 7 */ { TEST7_512, length(TEST7_512), 1, 0x80, 3,
				  "ED8DC78E8B01B69750053DBB7A0A9EDA0FB9E9D292B1ED71"
				  "5E80A7FE290A4E16664FD913E85854400C5AF05E6DAD316B"
				  "7359B43E64F8BEC3C1F237119986BBB6" },
		/* 8 */ { TEST8_512, length(TEST8_512), 1, 0, 0,
				  "CB0B67A4B8712CD73C9AABC0B199E9269B20844AFB75ACBD"
				  "D1C153C9828924C3DDEDAAFE669C5FDD0BC66F630F677398"
				  "8213EB1B16F517AD0DE4B2F0C95C90F8" },
		/* 9 */ { TEST9_512, length(TEST9_512), 1, 0x80, 3,
				  "32BA76FC30EAA0208AEB50FFB5AF1864FDBF17902A4DC0A6"
				  "82C61FCEA6D92B783267B21080301837F59DE79C6B337DB2"
				  "526F8A0A510E5E53CAFED4355FE7C2F1" },
		/* 10 */ { TEST10_512, length(TEST10_512), 1, 0, 0,
				   "C665BEFB36DA189D78822D10528CBF3B12B3EEF726039909"
				   "C1A16A270D48719377966B957A878E720584779A62825C18"
				   "DA26415E49A7176A894E7510FD1451F5" }
	};

	for (int i = 0; i < 10; i++) {
		SHA512_CTX ctx;
		uint8_t digest[SHA512_DIGEST_LENGTH];
		sha512_Init(&ctx);
		/* extra bits are not supported */
		if (tests[i].numberExtrabits)
			continue;
		for (int j = 0; j < tests[i].repeatcount; j++) {
			sha512_Update(&ctx, (const uint8_t*) tests[i].test, tests[i].length);
		}
		sha512_Final(&ctx, digest);
		ck_assert_mem_eq(digest, fromhex(tests[i].result), SHA512_DIGEST_LENGTH);
	}
}
END_TEST

// test vectors from http://www.di-mgt.com.au/sha_testvectors.html
START_TEST(test_sha3_256)
{
	uint8_t digest[SHA3_256_DIGEST_LENGTH];

	sha3_256((uint8_t *)"", 0, digest);
	ck_assert_mem_eq(digest, fromhex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"), SHA3_256_DIGEST_LENGTH);

	sha3_256((uint8_t *)"abc", 3, digest);
	ck_assert_mem_eq(digest, fromhex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"), SHA3_256_DIGEST_LENGTH);

	sha3_256((uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, digest);
	ck_assert_mem_eq(digest, fromhex("41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"), SHA3_256_DIGEST_LENGTH);

	sha3_256((uint8_t *)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112, digest);
	ck_assert_mem_eq(digest, fromhex("916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"), SHA3_256_DIGEST_LENGTH);
}
END_TEST

// test vectors from http://www.di-mgt.com.au/sha_testvectors.html
START_TEST(test_sha3_512)
{
	uint8_t digest[SHA3_512_DIGEST_LENGTH];

	sha3_512((uint8_t *)"", 0, digest);
	ck_assert_mem_eq(digest, fromhex("a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"), SHA3_512_DIGEST_LENGTH);

	sha3_512((uint8_t *)"abc", 3, digest);
	ck_assert_mem_eq(digest, fromhex("b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"), SHA3_512_DIGEST_LENGTH);

	sha3_512((uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, digest);
	ck_assert_mem_eq(digest, fromhex("04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e"), SHA3_512_DIGEST_LENGTH);

	sha3_512((uint8_t *)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112, digest);
	ck_assert_mem_eq(digest, fromhex("afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185"), SHA3_512_DIGEST_LENGTH);
}
END_TEST

// test vectors from https://raw.githubusercontent.com/NemProject/nem-test-vectors/master/0.test-sha3-256.dat
START_TEST(test_keccak_256)
{
	static const struct {
		const char *hash;
		size_t length;
		const char *data;
	} tests[] = {
		{ "4e9e79ab7434f6c7401fb3305d55052ee829b9e46d5d05d43b59fefb32e9a619", 293, "a6151d4904e18ec288243028ceda30556e6c42096af7150d6a7232ca5dba52bd2192e23daa5fa2bea3d4bd95efa2389cd193fcd3376e70a5c097b32c1c62c80af9d710211545f7cdddf63747420281d64529477c61e721273cfd78f8890abb4070e97baa52ac8ff61c26d195fc54c077def7a3f6f79b36e046c1a83ce9674ba1983ec2fb58947de616dd797d6499b0385d5e8a213db9ad5078a8e0c940ff0cb6bf92357ea5609f778c3d1fb1e7e36c35db873361e2be5c125ea7148eff4a035b0cce880a41190b2e22924ad9d1b82433d9c023924f2311315f07b88bfd42850047bf3be785c4ce11c09d7e02065d30f6324365f93c5e7e423a07d754eb314b5fe9db4614275be4be26af017abdc9c338d01368226fe9af1fb1f815e7317bdbb30a0f36dc69", },
		{ "c1268babc42d00c3463dc388222100f7e525a74a64665c39f112f788ddb5da42", 376, "9db801077952c2324e0044a4994edfb09b3edfcf669bfdd029f4bf42d5b0eab3056b0bf82708ca7bfadba43c9de806b10a19d0f00c2351ef1086b6b108f306e035c6b61b2e70fd7087ba848601c8a3f626a66666423717ef305a1068bfa3a1f7ffc1e5a78cb6182ffc8a577ca2a821630bf900d0fbba848bdf94b77c5946771b6c3f8c02269bc772ca56098f724536d96be68c284ee1d81697989d40029b8ea63ac1fd85f8b3cae8b194f6834ff65a5858f9498ddbb467995eb2d49cdfc6c05d92038c6e9aaeee85f8222b3784165f12a2c3df4c7a142e26dddfd831d07e22dfecc0eded48a69c8a9e1b97f1a4e0efcd4edd310de0edf82af38a6e4d5ab2a19da586e61210d4f75e7a07e2201f9c8154ca52a414a70d2eb2ac1c5b9a2900b4d871f62fa56f70d03b3dd3704bd644808c45a13231918ea884645b8ec054e8bab2935a66811fe590ddc119ae901dfeb54fc2a87c1e0a236778baab2fa8843709c6676d3c1888ba19d75ec52d73a7d035c143179b93823726b7", },
		{ "e83b50e8c83cb676a7dd64c055f53e5110d5a4c62245ceb8f683fd87b2b3ec77", 166, "c070a957550b7b34113ee6543a1918d96d241f27123425db7f7b9004e047ffbe05612e7fa8c54b23c83ea427e625e97b7a28b09a70bf6d91e478eeed01d7907931c29ea86e70f2cdcfb243ccf7f24a1619abf4b5b9e6f75cbf63fc02baf4a820a9790a6b053e50fd94e0ed57037cfc2bab4d95472b97d3c25f434f1cc0b1ede5ba7f15907a42a223933e5e2dfcb518c3531975268c326d60fa911fbb7997eee3ba87656c4fe7", },
		{ "8ebd2c9d4ff00e285a9b6b140bfc3cef672016f0098100e1f6f250220af7ce1a", 224, "b502fbdce4045e49e147eff5463d4b3f37f43461518868368e2c78008c84c2db79d12b58107034f67e7d0abfee67add0342dd23dce623f26b9156def87b1d7ac15a6e07301f832610fe869ada13a2b0e3d60aa6bb81bc04487e2e800f5106b0402ee0331df745e021b5ea5e32faf1c7fc1322041d221a54191c0af19948b5f34411937182e30d5cd39b5a6c959d77d92d21bb1de51f1b3411cb6eec00600429916227fb62d2c88e69576f4ac8e5efcde8efa512cc80ce7fb0dfaa6c74d26e898cefe9d4f7dce232a69f2a6a9477aa08366efcdfca117c89cb79eba15a23755e0", },
		{ "db3961fdddd0c314289efed5d57363459a6700a7bd015e7a03d3e1d03f046401", 262, "22e203a98ba2c43d8bc3658f0a48a35766df356d6a5e98b0c7222d16d85a00b317207d4aef3fc7cabb67b9d8f5838de0b733e1fd59c31f0667e53286972d7090421ad90d54db2ea40047d0d1700c86f53dbf48da532396307e68edad877dcae481848801b0a5db44dbdba6fc7c63b5cd15281d57ca9e6be96f530b209b59d6127ad2bd8750f3f80798f62521f0d5b42633c2f5a9aaefbed38779b7aded2338d66850b0bb0e33c48e040c99f2dcee7a7ebb3d7416e1c5bf038c19d09682dab67c96dbbfad472e45980aa27d1b301b15f7de4d4f549bad2501931c9d4f1a3b1692dcb4b1b834ddd4a636126702307ddaeec61841693b21887d56e76cc2069dafb557fd6682160f", },
		{ "25dd3acacd6bf688c0eace8d33eb7cc550271969142deb769a05b4012f7bb722", 122, "99e7f6e0ed46ec866c43a1ab494998d47e9309a79fde2a629eb63bb2160a5ffd0f2206de9c32dd20e9b23e57ab7422cf82971cc2873ec0e173fe93281c7b33e1c76ac79223a6f435f230bdd30260c00d00986c72a399d3ba70f6e783d834bbf8a6127844def559b8b6db742b2cfd715f7ff29e7b42bf7d567beb", },
		{ "00d747c9045c093484290afc161437f11c2ddf5f8a9fc2acae9c7ef5fcf511e5", 440, "50c392f97f8788377f0ab2e2aab196cb017ad157c6f9d022673d39072cc198b06622a5cbd269d1516089fa59e28c3373a92bd54b2ebf1a79811c7e40fdd7bce200e80983fda6e77fc44c44c1b5f87e01cef2f41e1141103f73364e9c2f25a4597e6517ef31b316300b770c69595e0fa6d011df1566a8676a88c7698562273bbfa217cc69d4b5c89a8907b902f7dc14481fefc7da4a810c15a60f5641aae854d2f8cc50cbc393015560f01c94e0d0c075dbcb150ad6eba29dc747919edcaf0231dba3eb3f2b1a87e136a1f0fd4b3d8ee61bad2729e9526a32884f7bcfa41e361add1b4c51dc81463528372b4ec321244de0c541ba00df22b8773cdf4cf898510c867829fa6b4ff11f9627338b9686d905cb7bcdf085080ab842146e0035c808be58cce97827d8926a98bd1ff7c529be3bc14f68c91b2ca4d2f6fc748f56bcf14853b7f8b9aa6d388f0fd82f53fdc4bacf9d9ba10a165f404cf427e199f51bf6773b7c82531e17933f6d8b8d9181e22f8921a2dbb20fc7c8023a87e716e245017c399d0942934f5e085219b3f8d26a196bf8b239438b8e561c28a61ff08872ecb052c5fcb19e2fdbc09565924a50ebee1461c4b414219d4257", },
		{ "dadcde7c3603ef419d319ba3d50cf00ad57f3e81566fd11b9b6f461cbb9dcb0f", 338, "18e1df97abccc91e07dc7b7ffab5ee8919d5610721453176aa2089fb96d9a477e1476f507fa1129f04304e960e8017ff41246cacc0153055fc4b1dc6168a74067ebb077cb5aa80a9df6e8b5b821e906531159668c4c164b9e511d8724aedbe17c1f41da8809417d3c30b79ea5a2e3c961f6bac5436d9af6be24a36eebcb17863fed82c0eb8962339eb612d58659dddd2ea06a120b3a2d8a17050be2de367db25a5bef4290c209bdb4c16c4df5a1fe1ead635169a1c35f0a56bc07bcf6ef0e4c2d8573ed7a3b58030fa268c1a5974b097288f01f34d5a1087946410688016882c6c7621aad680d9a25c7a3e5dbcbb07ffdb7243b91031c08a121b40785e96b7ee46770c760f84aca8f36b7c7da64d25c8f73b4d88ff3acb7eeefc0b75144dffea66d2d1f6b42b905b61929ab3f38538393ba5ca9d3c62c61f46fa63789cac14e4e1d8722bf03cceef6e3de91f783b0072616c", },
		{ "d184e84a2507fc0f187b640dd5b849a366c0383d9cbdbc6fa30904f054111255", 141, "13b8df9c1bcfddd0aa39b3055f52e2bc36562b6677535994b173f07041d141699db42589d6091ef0e71b645b41ab57577f58c98da966562d24823158f8e1d43b54edea4e61dd66fe8c59ad8405f5a0d9a3eb509a77ae3d8ae4adf926fd3d8d31c3dcccfc140814541010937024cc554e1daaee1b333a66316e7fbebb07ac8dfb134a918b9090b14168012c4824", },
		{ "20c19635364a00b151d0168fe5ae03bac6dd7d06030475b40d2e8c577a192f53", 84, "e1e96da4b7d8dcc2b316006503a990ea26a5b200cb7a7edfc14f5ce827f06d8d232ec95b1acdc1422ffc16da11d258f0c7b378f026d64c74b2fb41df8bfd3cd30066caecdc6f76c8163de9309d9fd0cf33d54a29", },
		{ "86cc2c428d469e43fb4ee8d38dffbf5128d20d1659dbc45edf4a855399ca730e", 319, "30391840ad14e66c53e1a5aaa03989ff059940b60c44c3b21295a93d023f2e6c7cdcf60208b7d87a7605fb5cee94630d94cad90bc6955328357fa37fea47c09f9cee759c31537187321c7d572e3554eeb90f441a9494575454dfbf8cfd86128da15de9418821ca158856eb84ff6a29a2c8380711e9e6d4955388374fcd3c1ca45b49e0679fc7157f96bc6e4f86ce20a89c12d4449b1ca7056e0b7296fc646f68f6ddbfa6a48e384d63ab68bc75fd69a2add59b8e41c4a0f753935df9a703d7df82a430798b0a67710a78061485a9d15de16f154582082459b4462485ce8a82d35ac6b9498ae40df3a23d5f00e0e86661cb02c52f677fd374c32969ec63028b5dd2c1d4bce67a6d9f79ba5e7eeb5a2763dc9fe2a05aa2ebaad36aaec2541e343a677fb4e6b6a180eff33c93744a4624f6a79f054c6c9e9c5b6928dbe7ba5fca", },
		{ "e80eee72a76e6957f7cb7f68c41b92f0ad9aac6e58aa8fc272c1e7364af11c70", 108, "3c210ed15889ae938781d2cebd49d4a8007f163ffba1f7669bccdccf6ad5a1418299d5f4348f5cd03b0ba9e6999ab154e46836c3546feb395d17bcc60f23d7ba0e8efe6aa616c00b6bf552fe1cb5e28e3e7bc39dfc20c63ae3901035e91ddd110e43fe59ed744beeedb6bc1e", },
		{ "f971bbae97dd8a034835269fb246867de358a889de6de13672e771d6fb4c89b7", 468, "64e9a3a99c021df8bea59368cfe1cd3b0a4aca33ffcd5cf6028d9307c0b904b8037d056a3c12803f196f74c4d360a3132452d365922b1157e5b0d76f91fb94bebfdcb4d50fa23ed5be3d3c5712219e8666debc8abcd5e6c69a542761a6cbbd1b3c0f0524875204b64d2788465f90cb19b6f6da9f8bec6d6e684196e713549ec83e47cbaeff77838ac4936b312562e2de17c970449d49d214ec2597c6d4f642e6c94a613a0c53285abccd7794a3d72241808594fb4e6e4d5d2c310ef1cdcbfd34805ca2408f554797a6cfd49d0f25ed8927f206acb127e6436e1234902489ec2e7f3058e26c0eba80341bc7ad0da8b8bd80bd1b43c9099269e3f8b68445c69b79d8cf5693d4a0d47a44f9e9114dbb33992d2ea9d3b5b86e4ea57a44a638848de4ac365bb6bb7855305ade62b07ebf0954d70b7c2fb5e6fcc154c7a36fb1756df5f20a84d35696627ebf22d44f40f805c0878ad110bc17dcd66821084ca87902e05bc0afa61161086956b85a6ea900d35c7784d4c361a43fe294e267d5762408be58962cdb4f45a9c0efd7d2335916df3acb98ccfbcf5ee39530540e5f3d3c5f3326a9a536d7bfa37aae2b143e2499b81bf0670e3a418c26c7dc82b293d9bd182dd6435670514237df88d8286e19ce93e0a0db2790", },
		{ "b97fd51f4e4eaa40c7a2853010fc46be5be2f43b9520ea0c533b68f728c978a2", 214, "ced3a43193caceb269d2517f4ecb892bb7d57d7201869e28e669b0b17d1c44d286e02734e2210ea9009565832975cc6303b9b6008fe1165b99ae5f1b29962ef042ebad8b676d7433ed2fe0d0d6f4f32b2cb4c519da61552328c2caea799bb2fd907308173a1cd2b798fb0df7d2eaf2ff0be733af74f42889e211843fc80b09952ae7eb246725b91d31c1f7a5503fdf3bc9c269c76519cf2dc3225e862436b587bb74adbad88c773056cfea3bddb1f6533c01125eeae0986e5c817359912c9d0472bf8320b824ee097f82a8e05b9f53a5be7d153225de", },
		{ "f0fecf766e4f7522568b3be71843cce3e5fcb10ea96b1a236c8c0a71c9ad55c9", 159, "8aca4de41275f5c4102f66266d70cff1a2d56f58df8d12061c64cb6cd8f616a5bf19c2bb3c91585c695326f561a2d0eb4eef2e202d82dcc9089e4bee82b62a199a11963cd08987d3abd5914def2cdd3c1e4748d46b654f338e3959121e869c18d5327e88090d0ba0ac6762a2b14514cc505af7499f1a22f421dbe978494f9ffe1e88f1c59228f21da5bc9fcc911d022300a443bca17258bdd6cfbbf52fde61", },
		{ "5c4f16043c0084bf98499fc7dc4d674ce9c730b7135210acdbf5e41d3dcf317b", 87, "01bbc193d0ee2396a7d8267ad63f18149667b31d8f7f48c8bb0c634755febc9ef1a79e93c475f6cd137ee37d4dc243ea2fdcdc0d098844af2208337b7bbf6930e39e74e23952ac1a19b4d38b83810a10c3b069e4fafb06", },
		{ "14b61fc981f7d9449b7b6a2d57eb48cc8f7896f4dced2005291b2a2f38cb4a63", 358, "cbc1709a531438d5ead32cea20a9e4ddc0101ec555ab42b2e378145013cc05a97b9e2c43c89bfa63ae5e9e9ce1fc022035c6b68f0a906ee1f53396d9dbe41cb2bc4bfeb144b005b0f40e0fec872d9c4aca9929ba3cbacd84c58ab43c26f10d345a24692bbd55a76506876768e8e32a461bf160cee953da88920d36ad4aff6eea7126aa6f44a7a6fce770ce43f0f90a20590bdaad3ffcda30ca8e3700f832c62caa5df030c16bcf74aff492466f781eb69863a80663535fc154abd7cfdd02eef1019221cf608b9780f807e507fbbf559b1dfe4e971b4d08fe45263a3c697ba90f9f71bec97e12438b4b12f6a84ab66872b888097089d76c9c2502d9ed2eece6bef8eee1d439782e218f5cc75d38f9886012cdcb4bbe6caf812e97c5a336bcceae38b1109e3243a291ce23d097aaee7d9a711de6886749a7a6d15d7e7cbc4a51b1b4da9fcf139e4a6fd7dc0bc017db624b17fc9b8f847592ed42467c25ad9fe96acbf20c0ffd18", },
		{ "47ec7f3a362becbb110867995a0f066a66152603c4d433f11bf51870c67e2864", 354, "0636983353c9ea3f75256ed00b70e8b7cfc6f4e4c0ba3aa9a8da59b6e6ad9dfb5bc2c49f48cc0b4237f87dedf34b888e54ecebf1d435bcd4aab72eb4ce39e5262fb68c6f86423dac123bf59e903989eda7df4a982822d0831521403cedcfe9a5bbea648bb2e7ef8cd81442ea5abe468b3ee8b06376ef8099447255c2fdc1b73af37fe0e0b852ffbc9339868db756680db99e6e9837dbd28c39a69f229044ad7ec772524a6e01f679d25fdc2e736a2418e5dfd7c2ab1348d0f821b777c975244c6cfc2fca5c36ccae7cf1d07b190a9d17a088a1276bd096250b92f53b29b6ef88ef69d744b56fb2ec5078cc0b68a9106943ef242b466097b9e29df11eb5cb0c06c29d7917410ba1097215d6aa4dafd90adff0c3e7221b9e8832613bd9aca8bcc6b2aa7b43acedcbc11aee1b5ba56f77a210be7cf3485ee813e1126c3eeccd8419bbf22c412cad32cc0fc7a73aca4e379651caac3d13d6cf5ca05508fd2d96f3ad94e7", },
		{ "73778e7f1943646a89d3c78909e0afbe584071ba5230546a39cd73e44e36d78a", 91, "6217504a26b3395855eab6ddeb79f2e3490d74b80eff343721150ee0c1c02b07186743589f93c22a03dc5ed29fb5bf592de0a089763e83e5b95f9dd524d66c8da3e04c1814e65e68b2810c1b517648aabc266ad62896c51864a7f4", },
		{ "35ef6868e750cf0c1d5285992c231d93ec644670fb79cf85324067a9f77fde78", 185, "0118b7fb15f927a977e0b330b4fa351aeeec299d6ba090eb16e5114fc4a6749e5915434a123c112697390c96ea2c26dc613eb5c75f5ecfb6c419317426367e34da0ddc6d7b7612cefa70a22fea0025f5186593b22449dab71f90a49f7de7352e54e0c0bd8837e661ca2127c3313a7268cafdd5ccfbf3bdd7c974b0e7551a2d96766579ef8d2e1f376af74cd1ab62162fc2dc61a8b7ed4163c1caccf20ed73e284da2ed257ec974eee96b502acb2c60a04886465e44debb0317", },
	};

	uint8_t hash[SHA3_256_DIGEST_LENGTH];

	for (size_t i = 0; i < (sizeof(tests) / sizeof(*tests)); i++) {
		keccak_256(fromhex(tests[i].data), tests[i].length, hash);
		ck_assert_mem_eq(hash, fromhex(tests[i].hash), SHA3_256_DIGEST_LENGTH);
	}
}
END_TEST

// test vectors from https://raw.githubusercontent.com/monero-project/monero/master/tests/hash/tests-extra-blake.txt
START_TEST(test_blake256)
{
	struct {
		const char *hash;
		const char *data;
	} tests[] = {
		{ "716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a", "", },
		{ "e104256a2bc501f459d03fac96b9014f593e22d30f4de525fa680c3aa189eb4f", "cc", },
		{ "8f341148be7e354fdf38b693d8c6b4e0bd57301a734f6fd35cd85b8491c3ddcd", "41fb", },
		{ "bc334d1069099f10c601883ac6f3e7e9787c6aa53171f76a21923cc5ad3ab937", "1f877c", },
		{ "b672a16f53982bab1e77685b71c0a5f6703ffd46a1c834be69f614bd128d658e", "c1ecfdfc", },
		{ "d9134b2899057a7d8d320cc99e3e116982bc99d3c69d260a7f1ed3da8be68d99", "21f134ac57", },
		{ "637923bd29a35aa3ecbbd2a50549fc32c14cf0fdcaf41c3194dd7414fd224815", "c6f50bb74e29", },
		{ "70c092fd5c8c21e9ef4bbc82a5c7819e262a530a748caf285ff0cba891954f1e", "119713cc83eeef", },
		{ "fdf092993edbb7a0dc7ca67f04051bbd14481639da0808947aff8bfab5abed4b", "4a4f202484512526", },
		{ "6f6fc234bf35beae1a366c44c520c59ad5aa70351b5f5085e21e1fe2bfcee709", "1f66ab4185ed9b6375", },
		{ "4fdaf89e2a0e78c000061b59455e0ea93a4445b440e7562c8f0cfa165c93de2e", "eed7422227613b6f53c9", },
		{ "d6b780eee9c811f664393dc2c58b5a68c92b3c9fe9ceb70371d33ece63b5787e", "eaeed5cdffd89dece455f1", },
		{ "d0015071d3e7ed048c764850d76406eceae52b8e2e6e5a2c3aa92ae880485b34", "5be43c90f22902e4fe8ed2d3", },
		{ "9b0207902f9932f7a85c24722e93e31f6ed2c75c406509aa0f2f6d1cab046ce4", "a746273228122f381c3b46e4f1", },
		{ "258020d5b04a814f2b72c1c661e1f5a5c395d9799e5eee8b8519cf7300e90cb1", "3c5871cd619c69a63b540eb5a625", },
		{ "4adae3b55baa907fefc253365fdd99d8398befd0551ed6bf9a2a2784d3c304d1", "fa22874bcc068879e8ef11a69f0722", },
		{ "6dd10d772f8d5b4a96c3c5d30878cd9a1073fa835bfe6d2b924fa64a1fab1711", "52a608ab21ccdd8a4457a57ede782176", },
		{ "0b8741ddf2259d3af2901eb1ae354f22836442c965556f5c1eb89501191cb46a", "82e192e4043ddcd12ecf52969d0f807eed", },
		{ "f48a754ca8193a82643150ab94038b5dd170b4ebd1e0751b78cfb0a98fa5076a", "75683dcb556140c522543bb6e9098b21a21e", },
		{ "5698409ab856b74d9fa5e9b259dfa46001f89041752da424e56e491577b88c86", "06e4efe45035e61faaf4287b4d8d1f12ca97e5", },
	};

	uint8_t hash[BLAKE256_DIGEST_LENGTH];

	for (size_t i = 0; i < (sizeof(tests) / sizeof(*tests)); i++) {
		blake256(fromhex(tests[i].data), i, hash);
		ck_assert_mem_eq(hash, fromhex(tests[i].hash), BLAKE256_DIGEST_LENGTH);
	}
}
END_TEST

// test vectors from https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2b-kat.txt
START_TEST(test_blake2b)
{
	uint8_t key[BLAKE2B_KEY_LENGTH];
	memcpy(key, fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"), BLAKE2B_KEY_LENGTH);

	uint8_t digest[BLAKE2B_DIGEST_LENGTH];

	blake2b_Key((uint8_t *)"", 0, key, BLAKE2B_KEY_LENGTH, digest, BLAKE2B_DIGEST_LENGTH);
	ck_assert_mem_eq(digest, fromhex("10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568"), BLAKE2B_DIGEST_LENGTH);

	blake2b_Key(fromhex("000102"), 3, key, BLAKE2B_KEY_LENGTH, digest, BLAKE2B_DIGEST_LENGTH);
	ck_assert_mem_eq(digest, fromhex("33d0825dddf7ada99b0e7e307104ad07ca9cfd9692214f1561356315e784f3e5a17e364ae9dbb14cb2036df932b77f4b292761365fb328de7afdc6d8998f5fc1"), BLAKE2B_DIGEST_LENGTH);

	blake2b_Key(fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"), 56, key, BLAKE2B_KEY_LENGTH, digest, BLAKE2B_DIGEST_LENGTH);
	ck_assert_mem_eq(digest, fromhex("f8f3726ac5a26cc80132493a6fedcb0e60760c09cfc84cad178175986819665e76842d7b9fedf76dddebf5d3f56faaad4477587af21606d396ae570d8e719af2"), BLAKE2B_DIGEST_LENGTH);

	blake2b_Key(fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"), 112, key, BLAKE2B_KEY_LENGTH, digest, BLAKE2B_DIGEST_LENGTH);
	ck_assert_mem_eq(digest, fromhex("227e3aed8d2cb10b918fcb04f9de3e6d0a57e08476d93759cd7b2ed54a1cbf0239c528fb04bbf288253e601d3bc38b21794afef90b17094a182cac557745e75f"), BLAKE2B_DIGEST_LENGTH);
}
END_TEST

// test vectors from https://raw.githubusercontent.com/BLAKE2/BLAKE2/master/testvectors/blake2s-kat.txt
START_TEST(test_blake2s)
{
	uint8_t key[BLAKE2S_KEY_LENGTH];
	memcpy(key, fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), BLAKE2S_KEY_LENGTH);

	uint8_t digest[BLAKE2S_DIGEST_LENGTH];

	blake2s_Key((uint8_t *)"", 0, key, BLAKE2S_KEY_LENGTH, digest, BLAKE2S_DIGEST_LENGTH);
	ck_assert_mem_eq(digest, fromhex("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"), BLAKE2S_DIGEST_LENGTH);

	blake2s_Key(fromhex("000102"), 3, key, BLAKE2S_KEY_LENGTH, digest, BLAKE2S_DIGEST_LENGTH);
	ck_assert_mem_eq(digest, fromhex("1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b"), BLAKE2S_DIGEST_LENGTH);

	blake2s_Key(fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"), 56, key, BLAKE2S_KEY_LENGTH, digest, BLAKE2S_DIGEST_LENGTH);
	ck_assert_mem_eq(digest, fromhex("2966b3cfae1e44ea996dc5d686cf25fa053fb6f67201b9e46eade85d0ad6b806"), BLAKE2S_DIGEST_LENGTH);

	blake2s_Key(fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"), 112, key, BLAKE2S_KEY_LENGTH, digest, BLAKE2S_DIGEST_LENGTH);
	ck_assert_mem_eq(digest, fromhex("90a83585717b75f0e9b725e055eeeeb9e7a028ea7e6cbc07b20917ec0363e38c"), BLAKE2S_DIGEST_LENGTH);
}
END_TEST

// test vectors from https://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors
START_TEST(test_pbkdf2_hmac_sha256)
{
	uint8_t k[40], s[40];

	strcpy((char *)s, "salt");
	pbkdf2_hmac_sha256((uint8_t *)"password", 8, s, 4, 1, k);
	ck_assert_mem_eq(k, fromhex("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"), 32);

	strcpy((char *)s, "salt");
	pbkdf2_hmac_sha256((uint8_t *)"password", 8, s, 4, 2, k);
	ck_assert_mem_eq(k, fromhex("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"), 32);

	strcpy((char *)s, "salt");
	pbkdf2_hmac_sha256((uint8_t *)"password", 8, s, 4, 4096, k);
	ck_assert_mem_eq(k, fromhex("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"), 32);

	strcpy((char *)s, "saltSALTsaltSALTsaltSALTsaltSALTsalt");
	pbkdf2_hmac_sha256((uint8_t *)"passwordPASSWORDpassword", 3*8, s, 9*4, 4096, k);
	ck_assert_mem_eq(k, fromhex("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1"), 32);
}
END_TEST

// test vectors from http://stackoverflow.com/questions/15593184/pbkdf2-hmac-sha-512-test-vectors
START_TEST(test_pbkdf2_hmac_sha512)
{
	uint8_t k[64], s[40];

	strcpy((char *)s, "salt");
	pbkdf2_hmac_sha512((uint8_t *)"password", 8, s, 4, 1, k);
	ck_assert_mem_eq(k, fromhex("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"), 64);

	strcpy((char *)s, "salt");
	pbkdf2_hmac_sha512((uint8_t *)"password", 8, s, 4, 2, k);
	ck_assert_mem_eq(k, fromhex("e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"), 64);

	strcpy((char *)s, "salt");
	pbkdf2_hmac_sha512((uint8_t *)"password", 8, s, 4, 4096, k);
	ck_assert_mem_eq(k, fromhex("d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5"), 64);

	strcpy((char *)s, "saltSALTsaltSALTsaltSALTsaltSALTsalt");
	pbkdf2_hmac_sha512((uint8_t *)"passwordPASSWORDpassword", 3*8, s, 9*4, 4096, k);
	ck_assert_mem_eq(k, fromhex("8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8"), 64);
}
END_TEST

START_TEST(test_mnemonic)
{
	static const char *vectors[] = {
		"00000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
		"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
		"legal winner thank year wave sausage worth useful legal winner thank yellow",
		"2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
		"80808080808080808080808080808080",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
		"d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
		"ffffffffffffffffffffffffffffffff",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
		"ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
		"000000000000000000000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
		"035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
		"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
		"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
		"f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
		"808080808080808080808080808080808080808080808080",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
		"107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
		"ffffffffffffffffffffffffffffffffffffffffffffffff",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
		"0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		"bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
		"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
		"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
		"bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
		"8080808080808080808080808080808080808080808080808080808080808080",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
		"c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		"dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
		"77c2b00716cec7213839159e404db50d",
		"jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
		"b5b6d0127db1a9d2226af0c3346031d77af31e918dba64287a1b44b8ebf63cdd52676f672a290aae502472cf2d602c051f3e6f18055e84e4c43897fc4e51a6ff",
		"b63a9c59a6e641f288ebc103017f1da9f8290b3da6bdef7b",
		"renew stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
		"9248d83e06f4cd98debf5b6f010542760df925ce46cf38a1bdb4e4de7d21f5c39366941c69e1bdbf2966e0f6e6dbece898a0e2f0a4c2b3e640953dfe8b7bbdc5",
		"3e141609b97933b66a060dcddc71fad1d91677db872031e85f4c015c5e7e8982",
		"dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
		"ff7f3184df8696d8bef94b6c03114dbee0ef89ff938712301d27ed8336ca89ef9635da20af07d4175f2bf5f3de130f39c9d9e8dd0472489c19b1a020a940da67",
		"0460ef47585604c5660618db2e6a7e7f",
		"afford alter spike radar gate glance object seek swamp infant panel yellow",
		"65f93a9f36b6c85cbe634ffc1f99f2b82cbb10b31edc7f087b4f6cb9e976e9faf76ff41f8f27c99afdf38f7a303ba1136ee48a4c1e7fcd3dba7aa876113a36e4",
		"72f60ebac5dd8add8d2a25a797102c3ce21bc029c200076f",
		"indicate race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
		"3bbf9daa0dfad8229786ace5ddb4e00fa98a044ae4c4975ffd5e094dba9e0bb289349dbe2091761f30f382d4e35c4a670ee8ab50758d2c55881be69e327117ba",
		"2c85efc7f24ee4573d2b81a6ec66cee209b2dcbd09d8eddc51e0215b0b68e416",
		"clutch control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
		"fe908f96f46668b2d5b37d82f558c77ed0d69dd0e7e043a5b0511c48c2f1064694a956f86360c93dd04052a8899497ce9e985ebe0c8c52b955e6ae86d4ff4449",
		"eaebabb2383351fd31d703840b32e9e2",
		"turtle front uncle idea crush write shrug there lottery flower risk shell",
		"bdfb76a0759f301b0b899a1e3985227e53b3f51e67e3f2a65363caedf3e32fde42a66c404f18d7b05818c95ef3ca1e5146646856c461c073169467511680876c",
		"7ac45cfe7722ee6c7ba84fbc2d5bd61b45cb2fe5eb65aa78",
		"kiss carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
		"ed56ff6c833c07982eb7119a8f48fd363c4a9b1601cd2de736b01045c5eb8ab4f57b079403485d1c4924f0790dc10a971763337cb9f9c62226f64fff26397c79",
		"4fa1a8bc3e6d80ee1316050e862c1812031493212b7ec3f3bb1b08f168cabeef",
		"exile ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
		"095ee6f817b4c2cb30a5a797360a81a40ab0f9a4e25ecd672a3f58a0b5ba0687c096a6b14d2c0deb3bdefce4f61d01ae07417d502429352e27695163f7447a8c",
		"18ab19a9f54a9274f03e5209a2ac8a91",
		"board flee heavy tunnel powder denial science ski answer betray cargo cat",
		"6eff1bb21562918509c73cb990260db07c0ce34ff0e3cc4a8cb3276129fbcb300bddfe005831350efd633909f476c45c88253276d9fd0df6ef48609e8bb7dca8",
		"18a2e1d81b8ecfb2a333adcb0c17a5b9eb76cc5d05db91a4",
		"board blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
		"f84521c777a13b61564234bf8f8b62b3afce27fc4062b51bb5e62bdfecb23864ee6ecf07c1d5a97c0834307c5c852d8ceb88e7c97923c0a3b496bedd4e5f88a9",
		"15da872c95a13dd738fbf50e427583ad61f18fd99f628c417a61cf8343c90419",
		"beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
		"b15509eaa2d09d3efd3e006ef42151b30367dc6e3aa5e44caba3fe4d3e352e65101fbdb86a96776b91946ff06f8eac594dc6ee1d3e82a42dfe1b40fef6bcc3fd",
		0,
		0,
		0,
	};

	const char **a, **b, **c, *m;
	uint8_t seed[64];

	a = vectors;
	b = vectors + 1;
	c = vectors + 2;
	while (*a && *b && *c) {
		m = mnemonic_from_data(fromhex(*a), strlen(*a) / 2);
		ck_assert_str_eq(m, *b);
		mnemonic_to_seed(m, "TREZOR", seed, 0);
		ck_assert_mem_eq(seed, fromhex(*c), strlen(*c) / 2);
#if USE_BIP39_CACHE
		// try second time to check whether caching results work
		mnemonic_to_seed(m, "TREZOR", seed, 0);
		ck_assert_mem_eq(seed, fromhex(*c), strlen(*c) / 2);
#endif
		a += 3; b += 3; c += 3;
	}
}
END_TEST

START_TEST(test_mnemonic_check)
{
	static const char *vectors_ok[] = {
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"legal winner thank year wave sausage worth useful legal winner thank yellow",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
		"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
		"letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		"jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
		"renew stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
		"dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
		"afford alter spike radar gate glance object seek swamp infant panel yellow",
		"indicate race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
		"clutch control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
		"turtle front uncle idea crush write shrug there lottery flower risk shell",
		"kiss carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
		"exile ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
		"board flee heavy tunnel powder denial science ski answer betray cargo cat",
		"board blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
		"beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
		0,
	};
	static const char *vectors_fail[] = {
		"above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"above winner thank year wave sausage worth useful legal winner thank yellow",
		"above advice cage absurd amount doctor acoustic avoid letter advice cage above",
		"above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
		"above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
		"above winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
		"above advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
		"above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
		"above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		"above winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
		"above advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
		"above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		"above better achieve collect unaware mountain thought cargo oxygen act hood bridge",
		"above stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
		"above pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
		"above alter spike radar gate glance object seek swamp infant panel yellow",
		"above race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
		"above control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
		"above front uncle idea crush write shrug there lottery flower risk shell",
		"above carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
		"above ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
		"above flee heavy tunnel powder denial science ski answer betray cargo cat",
		"above blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
		"above stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"winner thank year wave sausage worth useful legal winner thank yellow",
		"advice cage absurd amount doctor acoustic avoid letter advice cage above",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
		"winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
		"advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
		"winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
		"advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
		"zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
		"better achieve collect unaware mountain thought cargo oxygen act hood bridge",
		"stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
		"pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
		"alter spike radar gate glance object seek swamp infant panel yellow",
		"race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
		"control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
		"front uncle idea crush write shrug there lottery flower risk shell",
		"carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
		"ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
		"flee heavy tunnel powder denial science ski answer betray cargo cat",
		"blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
		"stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
		0,
	};

	const char **m;
	int r;
	m = vectors_ok;
	while (*m) {
		r = mnemonic_check(*m);
		ck_assert_int_eq(r, 1);
		m++;
	}
	m = vectors_fail;
	while (*m) {
		r = mnemonic_check(*m);
		ck_assert_int_eq(r, 0);
		m++;
	}
}
END_TEST

START_TEST(test_address)
{
	char address[36];
	uint8_t pub_key[65];

	memcpy(pub_key, fromhex("0226659c1cf7321c178c07437150639ff0c5b7679c7ea195253ed9abda2e081a37"), 33);
	ecdsa_get_address(pub_key,   0, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "139MaMHp3Vjo8o4x8N1ZLWEtovLGvBsg6s");
	ecdsa_get_address(pub_key, 111, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "mhfJsQNnrXB3uuYZqvywARTDfuvyjg4RBh");
	ecdsa_get_address(pub_key,  52, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "MxiimznnxsqMfLKTQBL8Z2PoY9jKpjgkCu");
	ecdsa_get_address(pub_key,  48, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "LMNJqZbe89yrPbm7JVzrcXJf28hZ1rKPaH");
	ecdsa_get_address(pub_key,  36, HASHER_SHA2, HASHER_GROESTLD_TRUNC, address, sizeof(address)); ck_assert_str_eq(address, "FXK52G2BbzRLaQ651U12o23DU5cEQdhvU6");
	ecdsa_get_address_segwit_p2sh(pub_key, 5, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "34PyTHn74syS796eTgsyoLfwoBC3cwLn6p");

	memcpy(pub_key, fromhex("025b1654a0e78d28810094f6c5a96b8efb8a65668b578f170ac2b1f83bc63ba856"), 33);
	ecdsa_get_address(pub_key,   0, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "19Ywfm3witp6C1yBMy4NRYHY2347WCRBfQ");
	ecdsa_get_address(pub_key, 111, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "mp4txp8vXvFLy8So5Y2kFTVrt2epN6YzdP");
	ecdsa_get_address(pub_key,  52, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "N58JsQYveGueiZDgdnNwe4SSkGTAToutAY");
	ecdsa_get_address(pub_key,  48, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "LTmtvyMmoZ49SpfLY73fhZMJEFRPdyohKh");
	ecdsa_get_address(pub_key,  36, HASHER_SHA2, HASHER_GROESTLD_TRUNC, address, sizeof(address)); ck_assert_str_eq(address, "Fdif7fnKHPVddczJF53qt45rgCL51yWN6x");
	ecdsa_get_address_segwit_p2sh(pub_key, 5, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "35trq6eeuHf6VL9L8pQv46x3vegHnHoTuB");

	memcpy(pub_key, fromhex("03433f246a12e6486a51ff08802228c61cf895175a9b49ed4766ea9a9294a3c7fe"), 33);
	ecdsa_get_address(pub_key,   0, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "1FWE2bn3MWhc4QidcF6AvEWpK77sSi2cAP");
	ecdsa_get_address(pub_key, 111, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "mv2BKes2AY8rqXCFKp4Yk9j9B6iaMfWRLN");
	ecdsa_get_address(pub_key,  52, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "NB5bEFH2GtoAawy8t4Qk8kfj3LWvQs3MhB");
	ecdsa_get_address(pub_key,  48, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "LZjBHp5sSAwfKDQnnP5UCFaaXKV9YheGxQ");
	ecdsa_get_address(pub_key,  36, HASHER_SHA2, HASHER_GROESTLD_TRUNC, address, sizeof(address)); ck_assert_str_eq(address, "FjfwUWWQv1P9W1jkVM5eNkK8yGPq5XyZZy");
	ecdsa_get_address_segwit_p2sh(pub_key, 5, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "3456DYaKUWuY6RWWw8Hp5CftHLcQN29h9Y");

	memcpy(pub_key, fromhex("03aeb03abeee0f0f8b4f7a5d65ce31f9570cef9f72c2dd8a19b4085a30ab033d48"), 33);
	ecdsa_get_address(pub_key,   0, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "1yrZb8dhdevoqpUEGi2tUccUEeiMKeLcs");
	ecdsa_get_address(pub_key, 111, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "mgVoreDcWf6BaxJ5wqgQiPpwLEFRLSr8U8");
	ecdsa_get_address(pub_key,  52, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "MwZDmEdcd1kVLP4yW62c6zmXCU3mNbveDo");
	ecdsa_get_address(pub_key,  48, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "LLCopoSTnHtz4eWdQQhLAVgNgT1zTi4QBK");
	ecdsa_get_address(pub_key,  36, HASHER_SHA2, HASHER_GROESTLD_TRUNC, address, sizeof(address)); ck_assert_str_eq(address, "FW9a1Vs1G8LUFSqb7NhWLzQw8PvfwAxmxA");
	ecdsa_get_address_segwit_p2sh(pub_key, 5, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "3DBU4tJ9tkMR9fnmCtjW48kjvseoNLQZXd");

	memcpy(pub_key, fromhex("0496e8f2093f018aff6c2e2da5201ee528e2c8accbf9cac51563d33a7bb74a016054201c025e2a5d96b1629b95194e806c63eb96facaedc733b1a4b70ab3b33e3a"), 65);
	ecdsa_get_address(pub_key,   0, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "194SZbL75xCCGBbKtMsyWLE5r9s2V6mhVM");
	ecdsa_get_address(pub_key, 111, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "moaPreR5tydT3J4wbvrMLFSQi9TjPCiZc6");
	ecdsa_get_address(pub_key,  52, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "N4domEq61LHkniqqABCYirNzaPG5NRU8GH");
	ecdsa_get_address(pub_key,  48, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "LTHPpodwAcSFWzHV4VsGnMHr4NEJajMnKX");
	ecdsa_get_address(pub_key,  36, HASHER_SHA2, HASHER_GROESTLD_TRUNC, address, sizeof(address)); ck_assert_str_eq(address, "FdEA1W4UeSsjhncSmTsSxr2QWK8z2xGkjc");

	memcpy(pub_key, fromhex("0498010f8a687439ff497d3074beb4519754e72c4b6220fb669224749591dde416f3961f8ece18f8689bb32235e436874d2174048b86118a00afbd5a4f33a24f0f"), 65);
	ecdsa_get_address(pub_key,   0, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "1A2WfBD4BJFwYHFPc5KgktqtbdJLBuVKc4");
	ecdsa_get_address(pub_key, 111, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "mpYTxEJ2zKhCKPj1KeJ4ap4DTcu39T3uzD");
	ecdsa_get_address(pub_key,  52, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "N5bsrpi36gMW4pVtsteFyQzoKrhPE7nkxK");
	ecdsa_get_address(pub_key,  48, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "LUFTvPWtFxVzo5wYnDJz2uueoqfcMYiuxH");
	ecdsa_get_address(pub_key,  36, HASHER_SHA2, HASHER_GROESTLD_TRUNC, address, sizeof(address)); ck_assert_str_eq(address, "FeCE75wRjnwUytGWVBKADQeDFnaHpJ8t3B");

	memcpy(pub_key, fromhex("04f80490839af36d13701ec3f9eebdac901b51c362119d74553a3c537faff31b17e2a59ebddbdac9e87b816307a7ed5b826b8f40b92719086238e1bebf19b77a4d"), 65);
	ecdsa_get_address(pub_key,   0, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "19J81hrPnQxg9UGx45ibTieCkb2ttm8CLL");
	ecdsa_get_address(pub_key, 111, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "mop5JkwNbSPvvakZmegyHdrXcadbjLazww");
	ecdsa_get_address(pub_key,  52, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "N4sVDMMNho4Eg1XTKu3AgEo7UpRwq3aNbn");
	ecdsa_get_address(pub_key,  48, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "LTX5GvADs5CjQGy7EDhtjjhxxoQB2Uhicd");
	ecdsa_get_address(pub_key,  36, HASHER_SHA2, HASHER_GROESTLD_TRUNC, address, sizeof(address)); ck_assert_str_eq(address, "FdTqTcamLueDb5J4wBi4vESXQkJrS54H6k");
}
END_TEST

START_TEST(test_pubkey_validity)
{
	uint8_t pub_key[65];
	curve_point pub;
	int res;
	const ecdsa_curve *curve = &secp256k1;

	memcpy(pub_key, fromhex("0226659c1cf7321c178c07437150639ff0c5b7679c7ea195253ed9abda2e081a37"), 33);
	res = ecdsa_read_pubkey(curve, pub_key, &pub);
	ck_assert_int_eq(res, 1);

	memcpy(pub_key, fromhex("025b1654a0e78d28810094f6c5a96b8efb8a65668b578f170ac2b1f83bc63ba856"), 33);
	res = ecdsa_read_pubkey(curve, pub_key, &pub);
	ck_assert_int_eq(res, 1);

	memcpy(pub_key, fromhex("03433f246a12e6486a51ff08802228c61cf895175a9b49ed4766ea9a9294a3c7fe"), 33);
	res = ecdsa_read_pubkey(curve, pub_key, &pub);
	ck_assert_int_eq(res, 1);

	memcpy(pub_key, fromhex("03aeb03abeee0f0f8b4f7a5d65ce31f9570cef9f72c2dd8a19b4085a30ab033d48"), 33);
	res = ecdsa_read_pubkey(curve, pub_key, &pub);
	ck_assert_int_eq(res, 1);

	memcpy(pub_key, fromhex("0496e8f2093f018aff6c2e2da5201ee528e2c8accbf9cac51563d33a7bb74a016054201c025e2a5d96b1629b95194e806c63eb96facaedc733b1a4b70ab3b33e3a"), 65);
	res = ecdsa_read_pubkey(curve, pub_key, &pub);
	ck_assert_int_eq(res, 1);

	memcpy(pub_key, fromhex("0498010f8a687439ff497d3074beb4519754e72c4b6220fb669224749591dde416f3961f8ece18f8689bb32235e436874d2174048b86118a00afbd5a4f33a24f0f"), 65);
	res = ecdsa_read_pubkey(curve, pub_key, &pub);
	ck_assert_int_eq(res, 1);

	memcpy(pub_key, fromhex("04f80490839af36d13701ec3f9eebdac901b51c362119d74553a3c537faff31b17e2a59ebddbdac9e87b816307a7ed5b826b8f40b92719086238e1bebf19b77a4d"), 65);
	res = ecdsa_read_pubkey(curve, pub_key, &pub);
	ck_assert_int_eq(res, 1);

	memcpy(pub_key, fromhex("04f80490839af36d13701ec3f9eebdac901b51c362119d74553a3c537faff31b17e2a59ebddbdac9e87b816307a7ed5b826b8f40b92719086238e1bebf00000000"), 65);
	res = ecdsa_read_pubkey(curve, pub_key, &pub);
	ck_assert_int_eq(res, 0);

	memcpy(pub_key, fromhex("04f80490839af36d13701ec3f9eebdac901b51c362119d74553a3c537faff31b17e2a59ebddbdac9e87b816307a7ed5b8211111111111111111111111111111111"), 65);
	res = ecdsa_read_pubkey(curve, pub_key, &pub);
	ck_assert_int_eq(res, 0);

	memcpy(pub_key, fromhex("00"), 1);
	res = ecdsa_read_pubkey(curve, pub_key, &pub);
	ck_assert_int_eq(res, 0);
}
END_TEST

START_TEST(test_pubkey_uncompress)
{
	uint8_t pub_key[65];
	uint8_t uncompressed[65];
	int res;
	const ecdsa_curve *curve = &secp256k1;

	memcpy(pub_key, fromhex("0226659c1cf7321c178c07437150639ff0c5b7679c7ea195253ed9abda2e081a37"), 33);
	res = ecdsa_uncompress_pubkey(curve, pub_key, uncompressed);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(uncompressed, fromhex("0426659c1cf7321c178c07437150639ff0c5b7679c7ea195253ed9abda2e081a37b3cfbad6b39a8ce8cb3a675f53b7b57e120fe067b8035d771fd99e3eba7cf4de"), 65);

	memcpy(pub_key, fromhex("03433f246a12e6486a51ff08802228c61cf895175a9b49ed4766ea9a9294a3c7fe"), 33);
	res = ecdsa_uncompress_pubkey(curve, pub_key, uncompressed);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(uncompressed, fromhex("04433f246a12e6486a51ff08802228c61cf895175a9b49ed4766ea9a9294a3c7feeb4c25bcb840f720a16e8857a011e6b91e0ab2d03dbb5f9762844bb21a7b8ca7"), 65);

	memcpy(pub_key, fromhex("0496e8f2093f018aff6c2e2da5201ee528e2c8accbf9cac51563d33a7bb74a016054201c025e2a5d96b1629b95194e806c63eb96facaedc733b1a4b70ab3b33e3a"), 65);
	res = ecdsa_uncompress_pubkey(curve, pub_key, uncompressed);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(uncompressed, fromhex("0496e8f2093f018aff6c2e2da5201ee528e2c8accbf9cac51563d33a7bb74a016054201c025e2a5d96b1629b95194e806c63eb96facaedc733b1a4b70ab3b33e3a"), 65);

	memcpy(pub_key, fromhex("00"), 1);
	res = ecdsa_uncompress_pubkey(curve, pub_key, uncompressed);
	ck_assert_int_eq(res, 0);
}
END_TEST

START_TEST(test_wif)
{
	uint8_t priv_key[32];
	char wif[53];

	memcpy(priv_key, fromhex("1111111111111111111111111111111111111111111111111111111111111111"), 32);
	ecdsa_get_wif(priv_key, 0x80, HASHER_SHA2D, wif, sizeof(wif)); ck_assert_str_eq(wif, "KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp");
	ecdsa_get_wif(priv_key, 0xEF, HASHER_SHA2D, wif, sizeof(wif)); ck_assert_str_eq(wif, "cN9spWsvaxA8taS7DFMxnk1yJD2gaF2PX1npuTpy3vuZFJdwavaw");

	memcpy(priv_key, fromhex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"), 32);
	ecdsa_get_wif(priv_key, 0x80, HASHER_SHA2D, wif, sizeof(wif)); ck_assert_str_eq(wif, "L4ezQvyC6QoBhxB4GVs9fAPhUKtbaXYUn8YTqoeXwbevQq4U92vN");
	ecdsa_get_wif(priv_key, 0xEF, HASHER_SHA2D, wif, sizeof(wif)); ck_assert_str_eq(wif, "cV1ysqy3XUVSsPeKeugH2Utm6ZC1EyeArAgvxE73SiJvfa6AJng7");

	memcpy(priv_key, fromhex("47f7616ea6f9b923076625b4488115de1ef1187f760e65f89eb6f4f7ff04b012"), 32);
	ecdsa_get_wif(priv_key, 0x80, HASHER_SHA2D, wif, sizeof(wif)); ck_assert_str_eq(wif, "KydbzBtk6uc7M6dXwEgTEH2sphZxSPbmDSz6kUUHi4eUpSQuhEbq");
	ecdsa_get_wif(priv_key, 0xEF, HASHER_SHA2D, wif, sizeof(wif)); ck_assert_str_eq(wif, "cPzbT6tbXyJNWY6oKeVabbXwSvsN6qhTHV8ZrtvoDBJV5BRY1G5Q");
}
END_TEST

START_TEST(test_address_decode)
{
	int res;
	uint8_t decode[MAX_ADDR_RAW_SIZE];

	res = ecdsa_address_decode("1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T", 0, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(decode, fromhex("00c4c5d791fcb4654a1ef5e03fe0ad3d9c598f9827"), 21);

	res = ecdsa_address_decode("myTPjxggahXyAzuMcYp5JTkbybANyLsYBW", 111, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(decode, fromhex("6fc4c5d791fcb4654a1ef5e03fe0ad3d9c598f9827"), 21);

	res = ecdsa_address_decode("NEWoeZ6gh4CGvRgFAoAGh4hBqpxizGT6gZ", 52, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(decode, fromhex("34c4c5d791fcb4654a1ef5e03fe0ad3d9c598f9827"), 21);

	res = ecdsa_address_decode("LdAPi7uXrLLmeh7u57pzkZc3KovxEDYRJq", 48, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(decode, fromhex("30c4c5d791fcb4654a1ef5e03fe0ad3d9c598f9827"), 21);

	res = ecdsa_address_decode("1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8", 0, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(decode, fromhex("0079fbfc3f34e7745860d76137da68f362380c606c"), 21);

	res = ecdsa_address_decode("mrdwvWkma2D6n9mGsbtkazedQQuoksnqJV", 111, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(decode, fromhex("6f79fbfc3f34e7745860d76137da68f362380c606c"), 21);

	res = ecdsa_address_decode("N7hMq7AmgNsQXaYARrEwybbDGei9mcPNqr", 52, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(decode, fromhex("3479fbfc3f34e7745860d76137da68f362380c606c"), 21);

	res = ecdsa_address_decode("LWLwtfycqf1uFqypLAug36W4kdgNwrZdNs", 48, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(decode, fromhex("3079fbfc3f34e7745860d76137da68f362380c606c"), 21);

	// invalid char
	res = ecdsa_address_decode("1JwSSubhmg6i000jtyqhUYYH7bZg3Lfy1T", 0, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 0);

	// invalid address
	res = ecdsa_address_decode("1111Subhmg6iPtRjtyqhUYYH7bZg3Lfy1T", 0, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 0);

	// invalid version
	res = ecdsa_address_decode("LWLwtfycqf1uFqypLAug36W4kdgNwrZdNs", 0, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 0);
}
END_TEST

START_TEST(test_ecdsa_der)
{
	uint8_t sig[64], der[72];
	int res;

	memcpy(sig,      fromhex("9a0b7be0d4ed3146ee262b42202841834698bb3ee39c24e7437df208b8b70771"), 32);
	memcpy(sig + 32, fromhex("2b79ab1e7736219387dffe8d615bbdba87e11477104b867ef47afed1a5ede781"), 32);
	res = ecdsa_sig_to_der(sig, der);
	ck_assert_int_eq(res, 71);
	ck_assert_mem_eq(der, fromhex("30450221009a0b7be0d4ed3146ee262b42202841834698bb3ee39c24e7437df208b8b7077102202b79ab1e7736219387dffe8d615bbdba87e11477104b867ef47afed1a5ede781"), 71);

	memcpy(sig,      fromhex("6666666666666666666666666666666666666666666666666666666666666666"), 32);
	memcpy(sig + 32, fromhex("7777777777777777777777777777777777777777777777777777777777777777"), 32);
	res = ecdsa_sig_to_der(sig, der);
	ck_assert_int_eq(res, 70);
	ck_assert_mem_eq(der, fromhex("30440220666666666666666666666666666666666666666666666666666666666666666602207777777777777777777777777777777777777777777777777777777777777777"), 70);

	memcpy(sig,      fromhex("6666666666666666666666666666666666666666666666666666666666666666"), 32);
	memcpy(sig + 32, fromhex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"), 32);
	res = ecdsa_sig_to_der(sig, der);
	ck_assert_int_eq(res, 71);
	ck_assert_mem_eq(der, fromhex("304502206666666666666666666666666666666666666666666666666666666666666666022100eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"), 71);

	memcpy(sig,      fromhex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"), 32);
	memcpy(sig + 32, fromhex("7777777777777777777777777777777777777777777777777777777777777777"), 32);
	res = ecdsa_sig_to_der(sig, der);
	ck_assert_int_eq(res, 71);
	ck_assert_mem_eq(der, fromhex("3045022100eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee02207777777777777777777777777777777777777777777777777777777777777777"), 71);

	memcpy(sig,      fromhex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"), 32);
	memcpy(sig + 32, fromhex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), 32);
	res = ecdsa_sig_to_der(sig, der);
	ck_assert_int_eq(res, 72);
	ck_assert_mem_eq(der, fromhex("3046022100eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee022100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), 72);

	memcpy(sig,      fromhex("0000000000000000000000000000000000000000000000000000000000000066"), 32);
	memcpy(sig + 32, fromhex("0000000000000000000000000000000000000000000000000000000000000077"), 32);
	res = ecdsa_sig_to_der(sig, der);
	ck_assert_int_eq(res, 8);
	ck_assert_mem_eq(der, fromhex("3006020166020177"), 8);

	memcpy(sig,      fromhex("0000000000000000000000000000000000000000000000000000000000000066"), 32);
	memcpy(sig + 32, fromhex("00000000000000000000000000000000000000000000000000000000000000ee"), 32);
	res = ecdsa_sig_to_der(sig, der);
	ck_assert_int_eq(res, 9);
	ck_assert_mem_eq(der, fromhex("3007020166020200ee"), 9);

	memcpy(sig,      fromhex("00000000000000000000000000000000000000000000000000000000000000ee"), 32);
	memcpy(sig + 32, fromhex("0000000000000000000000000000000000000000000000000000000000000077"), 32);
	res = ecdsa_sig_to_der(sig, der);
	ck_assert_int_eq(res, 9);
	ck_assert_mem_eq(der, fromhex("3007020200ee020177"), 9);

	memcpy(sig,      fromhex("00000000000000000000000000000000000000000000000000000000000000ee"), 32);
	memcpy(sig + 32, fromhex("00000000000000000000000000000000000000000000000000000000000000ff"), 32);
	res = ecdsa_sig_to_der(sig, der);
	ck_assert_int_eq(res, 10);
	ck_assert_mem_eq(der, fromhex("3008020200ee020200ff"), 10);
}
END_TEST

static void test_codepoints_curve(const ecdsa_curve *curve) {
	int i, j;
	bignum256 a;
	curve_point p, p1;
	for (i = 0; i < 64; i++) {
		for (j = 0; j < 8; j++) {
			bn_zero(&a);
			a.val[(4*i)/30] = (uint32_t) (2*j+1) << (4*i % 30);
			bn_normalize(&a);
			// note that this is not a trivial test.  We add 64 curve
			// points in the table to get that particular curve point.
			scalar_multiply(curve, &a, &p);
			ck_assert_mem_eq(&p, &curve->cp[i][j], sizeof(curve_point));
			bn_zero(&p.y); // test that point_multiply curve, is not a noop
			point_multiply(curve, &a, &curve->G, &p);
			ck_assert_mem_eq(&p, &curve->cp[i][j], sizeof(curve_point));
			// mul 2 test. this should catch bugs
			bn_lshift(&a);
			bn_mod(&a, &curve->order);
			p1 = curve->cp[i][j];
			point_double(curve, &p1);
			// note that this is not a trivial test.  We add 64 curve
			// points in the table to get that particular curve point.
			scalar_multiply(curve, &a, &p);
			ck_assert_mem_eq(&p, &p1, sizeof(curve_point));
			bn_zero(&p.y); // test that point_multiply curve, is not a noop
			point_multiply(curve, &a, &curve->G, &p);
			ck_assert_mem_eq(&p, &p1, sizeof(curve_point));
		}
	}
}

START_TEST(test_codepoints_secp256k1) { test_codepoints_curve(&secp256k1); } END_TEST
START_TEST(test_codepoints_nist256p1) { test_codepoints_curve(&nist256p1); } END_TEST

static void test_mult_border_cases_curve(const ecdsa_curve *curve) {
	bignum256 a;
	curve_point p;
	curve_point expected;
	bn_zero(&a);  // a == 0
	scalar_multiply(curve, &a, &p);
	ck_assert(point_is_infinity(&p));
	point_multiply(curve, &a, &p, &p);
	ck_assert(point_is_infinity(&p));
	point_multiply(curve, &a, &curve->G, &p);
	ck_assert(point_is_infinity(&p));

	bn_addi(&a, 1);  // a == 1
	scalar_multiply(curve, &a, &p);
	ck_assert_mem_eq(&p, &curve->G, sizeof(curve_point));
	point_multiply(curve, &a, &curve->G, &p);
	ck_assert_mem_eq(&p, &curve->G, sizeof(curve_point));

	bn_subtract(&curve->order, &a, &a);  // a == -1
	expected = curve->G;
	bn_subtract(&curve->prime, &expected.y, &expected.y);
	scalar_multiply(curve, &a, &p);
	ck_assert_mem_eq(&p, &expected, sizeof(curve_point));
	point_multiply(curve, &a, &curve->G, &p);
	ck_assert_mem_eq(&p, &expected, sizeof(curve_point));

	bn_subtract(&curve->order, &a, &a);
	bn_addi(&a, 1);  // a == 2
	expected = curve->G;
	point_add(curve, &expected, &expected);
	scalar_multiply(curve, &a, &p);
	ck_assert_mem_eq(&p, &expected, sizeof(curve_point));
	point_multiply(curve, &a, &curve->G, &p);
	ck_assert_mem_eq(&p, &expected, sizeof(curve_point));

	bn_subtract(&curve->order, &a, &a);  // a == -2
	expected = curve->G;
	point_add(curve, &expected, &expected);
	bn_subtract(&curve->prime, &expected.y, &expected.y);
	scalar_multiply(curve, &a, &p);
	ck_assert_mem_eq(&p, &expected, sizeof(curve_point));
	point_multiply(curve, &a, &curve->G, &p);
	ck_assert_mem_eq(&p, &expected, sizeof(curve_point));
}

START_TEST(test_mult_border_cases_secp256k1) { test_mult_border_cases_curve(&secp256k1); } END_TEST
START_TEST(test_mult_border_cases_nist256p1) { test_mult_border_cases_curve(&nist256p1); } END_TEST

static void test_scalar_mult_curve(const ecdsa_curve *curve) {
	int i;
	// get two "random" numbers
	bignum256 a = curve->G.x;
	bignum256 b = curve->G.y;
	curve_point p1, p2, p3;
	for (i = 0; i < 1000; i++) {
		/* test distributivity: (a + b)G = aG + bG */
		bn_mod(&a, &curve->order);
		bn_mod(&b, &curve->order);
		scalar_multiply(curve, &a, &p1);
		scalar_multiply(curve, &b, &p2);
		bn_addmod(&a, &b, &curve->order);
		bn_mod(&a, &curve->order);
		scalar_multiply(curve, &a, &p3);
		point_add(curve, &p1, &p2);
		ck_assert_mem_eq(&p2, &p3, sizeof(curve_point));
		// new "random" numbers
		a = p3.x;
		b = p3.y;
	}
}

START_TEST(test_scalar_mult_secp256k1) { test_scalar_mult_curve(&secp256k1); } END_TEST
START_TEST(test_scalar_mult_nist256p1) { test_scalar_mult_curve(&nist256p1); } END_TEST

static void test_point_mult_curve(const ecdsa_curve *curve) {
	int i;
	// get two "random" numbers and a "random" point
	bignum256 a = curve->G.x;
	bignum256 b = curve->G.y;
	curve_point p = curve->G;
	curve_point p1, p2, p3;
	for (i = 0; i < 200; i++) {
		/* test distributivity: (a + b)P = aP + bP */
		bn_mod(&a, &curve->order);
		bn_mod(&b, &curve->order);
		point_multiply(curve, &a, &p, &p1);
		point_multiply(curve, &b, &p, &p2);
		bn_addmod(&a, &b, &curve->order);
		bn_mod(&a, &curve->order);
		point_multiply(curve, &a, &p, &p3);
		point_add(curve, &p1, &p2);
		ck_assert_mem_eq(&p2, &p3, sizeof(curve_point));
		// new "random" numbers and a "random" point
		a = p1.x;
		b = p1.y;
		p = p3;
	}
}

START_TEST(test_point_mult_secp256k1) { test_point_mult_curve(&secp256k1); } END_TEST
START_TEST(test_point_mult_nist256p1) { test_point_mult_curve(&nist256p1); } END_TEST

static void test_scalar_point_mult_curve(const ecdsa_curve *curve) {
	int i;
	// get two "random" numbers
	bignum256 a = curve->G.x;
	bignum256 b = curve->G.y;
	curve_point p1, p2;
	for (i = 0; i < 200; i++) {
		/* test commutativity and associativity:
		 * a(bG) = (ab)G = b(aG)
		 */
		bn_mod(&a, &curve->order);
		bn_mod(&b, &curve->order);
		scalar_multiply(curve, &a, &p1);
		point_multiply(curve, &b, &p1, &p1);

		scalar_multiply(curve, &b, &p2);
		point_multiply(curve, &a, &p2, &p2);

		ck_assert_mem_eq(&p1, &p2, sizeof(curve_point));

		bn_multiply(&a, &b, &curve->order);
		bn_mod(&b, &curve->order);
		scalar_multiply(curve, &b, &p2);

		ck_assert_mem_eq(&p1, &p2, sizeof(curve_point));

		// new "random" numbers
		a = p1.x;
		b = p1.y;
	}
}

START_TEST(test_scalar_point_mult_secp256k1) { test_scalar_point_mult_curve(&secp256k1); } END_TEST
START_TEST(test_scalar_point_mult_nist256p1) { test_scalar_point_mult_curve(&nist256p1); } END_TEST

START_TEST(test_ed25519) {
	// test vectors from https://github.com/torproject/tor/blob/master/src/test/ed25519_vectors.inc
	static const char *vectors[] = {
		"26c76712d89d906e6672dafa614c42e5cb1caac8c6568e4d2493087db51f0d36", // secret
		"c2247870536a192d142d056abefca68d6193158e7c1a59c1654c954eccaff894", // public
		"d23188eac3773a316d46006fa59c095060be8b1a23582a0dd99002a82a0662bd246d8449e172e04c5f46ac0d1404cebe4aabd8a75a1457aa06cae41f3334f104", // selfsig
		"fba7a5366b5cb98c2667a18783f5cf8f4f8d1a2ce939ad22a6e685edde85128d",
		"1519a3b15816a1aafab0b213892026ebf5c0dc232c58b21088d88cb90e9b940d",
		"3a785ac1201c97ee5f6f0d99323960d5f264c7825e61aa7cc81262f15bef75eb4fa5723add9b9d45b12311b6d403eb3ac79ff8e4e631fc3cd51e4ad2185b200b",
		"67e3aa7a14fac8445d15e45e38a523481a69ae35513c9e4143eb1c2196729a0e",
		"081faa81992e360ea22c06af1aba096e7a73f1c665bc8b3e4e531c46455fd1dd",
		"cf431fd0416bfbd20c9d95ef9b723e2acddffb33900edc72195dea95965d52d888d30b7b8a677c0bd8ae1417b1e1a0ec6700deadd5d8b54b6689275e04a04509",
		"d51385942033a76dc17f089a59e6a5a7fe80d9c526ae8ddd8c3a506b99d3d0a6",
		"73cfa1189a723aad7966137cbffa35140bb40d7e16eae4c40b79b5f0360dd65a",
		"2375380cd72d1a6c642aeddff862be8a5804b916acb72c02d9ed052c1561881aa658a5af856fcd6d43113e42f698cd6687c99efeef7f2ce045824440d26c5d00",
		"5c8eac469bb3f1b85bc7cd893f52dc42a9ab66f1b02b5ce6a68e9b175d3bb433",
		"66c1a77104d86461b6f98f73acf3cd229c80624495d2d74d6fda1e940080a96b",
		"2385a472f599ca965bbe4d610e391cdeabeba9c336694b0d6249e551458280be122c2441dd9746a81bbfb9cd619364bab0df37ff4ceb7aefd24469c39d3bc508",
		"eda433d483059b6d1ff8b7cfbd0fe406bfb23722c8f3c8252629284573b61b86",
		"d21c294db0e64cb2d8976625786ede1d9754186ae8197a64d72f68c792eecc19",
		"e500cd0b8cfff35442f88008d894f3a2fa26ef7d3a0ca5714ae0d3e2d40caae58ba7cdf69dd126994dad6be536fcda846d89dd8138d1683cc144c8853dce7607",
		"4377c40431c30883c5fbd9bc92ae48d1ed8a47b81d13806beac5351739b5533d",
		"c4d58b4cf85a348ff3d410dd936fa460c4f18da962c01b1963792b9dcc8a6ea6",
		"d187b9e334b0050154de10bf69b3e4208a584e1a65015ec28b14bcc252cf84b8baa9c94867daa60f2a82d09ba9652d41e8dde292b624afc8d2c26441b95e3c0e",
		"c6bbcce615839756aed2cc78b1de13884dd3618f48367a17597a16c1cd7a290b",
		"95126f14d86494020665face03f2d42ee2b312a85bc729903eb17522954a1c4a",
		"815213640a643d198bd056e02bba74e1c8d2d931643e84497adf3347eb485079c9afe0afce9284cdc084946b561abbb214f1304ca11228ff82702185cf28f60d",
		0,
		0,
		0,
	};
	const char **ssk, **spk, **ssig;
	ssk = vectors;
	spk = vectors + 1;
	ssig = vectors + 2;
	ed25519_public_key pk;
	ed25519_secret_key sk;
	ed25519_signature sig;
	while (*ssk && *spk && *ssig) {
		memcpy(sk, fromhex(*ssk), 32);
		MARK_SECRET_DATA(sk, sizeof(sk));

		ed25519_publickey(sk, pk);
		UNMARK_SECRET_DATA(pk, sizeof(pk));
		ck_assert_mem_eq(pk, fromhex(*spk), 32);

		ed25519_sign(pk, 32, sk, pk, sig);
		UNMARK_SECRET_DATA(sig, sizeof(sig));
		ck_assert_mem_eq(sig, fromhex(*ssig), 64);

		ssk += 3;
		spk += 3;
		ssig += 3;

		UNMARK_SECRET_DATA(sk, sizeof(sk));
	}
}
END_TEST

// test vectors from https://raw.githubusercontent.com/NemProject/nem-test-vectors/master/2.test-sign.dat
START_TEST(test_ed25519_keccak)
{
	static const struct {
		const char *private_key;
		const char *public_key;
		const char *signature;
		size_t length;
		const char *data;
	} tests[] = {
		{ "abf4cf55a2b3f742d7543d9cc17f50447b969e6e06f5ea9195d428ab12b7318d", "8a558c728c21c126181e5e654b404a45b4f0137ce88177435a69978cc6bec1f4", "d9cec0cc0e3465fab229f8e1d6db68ab9cc99a18cb0435f70deb6100948576cd5c0aa1feb550bdd8693ef81eb10a556a622db1f9301986827b96716a7134230c", 41, "8ce03cd60514233b86789729102ea09e867fc6d964dea8c2018ef7d0a2e0e24bf7e348e917116690b9", },
		{ "6aa6dad25d3acb3385d5643293133936cdddd7f7e11818771db1ff2f9d3f9215", "bbc8cbb43dda3ecf70a555981a351a064493f09658fffe884c6fab2a69c845c6", "98bca58b075d1748f1c3a7ae18f9341bc18e90d1beb8499e8a654c65d8a0b4fbd2e084661088d1e5069187a2811996ae31f59463668ef0f8cb0ac46a726e7902", 49, "e4a92208a6fc52282b620699191ee6fb9cf04daf48b48fd542c5e43daa9897763a199aaa4b6f10546109f47ac3564fade0", },
		{ "8e32bc030a4c53de782ec75ba7d5e25e64a2a072a56e5170b77a4924ef3c32a9", "72d0e65f1ede79c4af0ba7ec14204e10f0f7ea09f2bc43259cd60ea8c3a087e2", "ef257d6e73706bb04878875c58aa385385bf439f7040ea8297f7798a0ea30c1c5eff5ddc05443f801849c68e98111ae65d088e726d1d9b7eeca2eb93b677860c", 40, "13ed795344c4448a3b256f23665336645a853c5c44dbff6db1b9224b5303b6447fbf8240a2249c55", },
		{ "c83ce30fcb5b81a51ba58ff827ccbc0142d61c13e2ed39e78e876605da16d8d7", "3ec8923f9ea5ea14f8aaa7e7c2784653ed8c7de44e352ef9fc1dee81fc3fa1a3", "0c684e71b35fed4d92b222fc60561db34e0d8afe44bdd958aaf4ee965911bef5991236f3e1bced59fc44030693bcac37f34d29e5ae946669dc326e706e81b804", 49, "a2704638434e9f7340f22d08019c4c8e3dbee0df8dd4454a1d70844de11694f4c8ca67fdcb08fed0cec9abb2112b5e5f89", },
		{ "2da2a0aae0f37235957b51d15843edde348a559692d8fa87b94848459899fc27", "d73d0b14a9754eec825fcb25ef1cfa9ae3b1370074eda53fc64c22334a26c254", "6f17f7b21ef9d6907a7ab104559f77d5a2532b557d95edffd6d88c073d87ac00fc838fc0d05282a0280368092a4bd67e95c20f3e14580be28d8b351968c65e03", 40, "d2488e854dbcdfdb2c9d16c8c0b2fdbc0abb6bac991bfe2b14d359a6bc99d66c00fd60d731ae06d0", },
		{ "0c066261fb1b18ebf2a9bcdeda81eb47d5a3745438b3d0b9d19b75885ad0a154", "2e5773f0e725024bc0359ce93a44e15d6507e7b160b6c592200385fee4a269cf", "13b5d2dd1b04f62cc2ec1544fed256423684f2dbca4538ceddda1d15c59dc7196c87840ea303ea30f4f6914a6ec9167841980c1d717f47fd641225068de88507", 41, "f15cb706e29fcfbcb324e38cbac62bb355deddb845c142e970f0c029ea4d05e59fd6adf85573cf1775", },
		{ "ef3d8e22a592f04c3a31aa736e10901757a821d053f1a49a525b4ec91eacdee3", "72a2b4910a502b30e13a96aba643c59c79328c1ba1462be6f254e817ef157fee", "95f2437a0210d2d2f125a3c377ed666c0d596cd104185e70204924a182a11a6eb3bdba4395bbfc3f4e827d38805752657ee52d1ce0f17e70f59bfd4999282509", 50, "6c3e4387345740b8d62cf0c9dec48f98c292539431b2b54020d8072d9cb55f0197f7d99ff066afcf9e41ea8b7aea78eb082d", },
		{ "f7fb79743e9ba957d2a4f1bd95ceb1299552abecaf758bf840d2dc2c09f3e3cb", "8b7d7531280f76a8abac8293d87508e3953894087112ae01b6ad32485d4e9b67", "c868ecf31cee783fe8799ac7e6a662431c822967351d8b79687f4ddf608f79a080c4ff9eed4fdee8c99fe1be905f734cae2a172f1cfdb00771625c0695a5260e", 42, "55d8e60c307ee533b1af9ff677a2de40a6eace722bcc9eb5d79907b420e533bc06db674dafbd9f43d672", },
		{ "8cc9a2469a77fad18b44b871b2b6932cd354641d2d1e84403f746c4fff829791", "aed5da202d4983dac560faf6704dc76ac111616318570e244043e82ed1bbcd2b", "aee9616db4135150818eaffa3e4503c2d7e9e834847a4c7d0a8856e952761d361a657104d36950c9b75770ded00d56a96e06f383fa2406bc935dcf51f272300e", 42, "d9b8be2f71b83261304e333d6e35563dc3c36c2eb5a23e1461b6e95aa7c6f381f9c3bd39deaa1b6df2f9", },
		{ "a247abbef0c1affbf021d1aff128888550532fc0edd77bc39f6ef5312317ec47", "98ededbad1e5ad7a0d5a0cf4fcd7a794eb5c6900a65e7e921884a636f19b131d", "f8cc02933851432f0c5df0b70f2067f740ccb72de7d6fa1e9a9b0d6de1402b9c6c525fd848e45aaaac1423b52880ec3474a2f64b38db6fc8e008d95a310e6e0c", 47, "4a5f07eb713932532fc3132c96efdc45862fe7a954c1d2ae4640afdf4728fb58c65e8a4ebfe0d53d5797d5146442b9", },
		{ "163d69079ddad1f16695c47d81c3b72f869b2fdd50e6e47113db6c85051a6ede", "93fe602642ee5773f4aaf6a3bc21e98e354035225353f419e78e43c3ec36c88a", "da747fa2cb47aae1effc1e4cfde0e39fa79937948592a712a7665bf948b8311e7f3f80f966301679520d5c2afa3eadd60e061f0d264887500d8d03a17e10fd02", 41, "65fe5c1a0214a59644892e5ac4216f09fbb4e191b89bfb63d6540177d25ef9e3714850b8453bd6b2b6", },
		{ "7b061bf90eb760971b9ec66a96fd6609635ca4b531f33e3c126b9ae6fdb3d491", "cb392ebb6912df4111efeeb1278160daf9da396e9291b83979a5ac479f7276d2", "f6eebe86f7ea672e0707ee518e1798d6fbd118c11b2aa30be07d10e3882e3721f2030f9f044b77c3a7a9a2f1feba7e7ce75d1f7f3807a96a764fded35d341d02", 45, "a17f5ce39b9ba7b7cf1147e515d6aa84b22fd0e2d8323a91367198fc6c3aff04ebb21fc2bdbe7bc0364e8040a9", },
		{ "c9f8ccbf761cec00ab236c52651e76b5f46d90f8936d44d40561ed5c277104de", "a3192641e343b669ffd43677c2e5cd4efaed174e876141f1d773bd6cfe30d875", "d44f884ec9eae2e99e74194b5acc769b7aa369aaad359e92ba6ff0fe629af2a9a7156c19b720e7de8c7f03c039563f160948073cab6f99b26a56a8bb1023ba08", 47, "3d7e33b0ecead8269966e9dcd192b73eb8a12573fc8a5fdfbe5753541026ef2e49f5280cba9bc2515a049b3a1c1b49", },
		{ "ebfa409ac6f987df476858dd35310879bf564eeb62984a52115d2e6c24590124", "7bb1601fe7215f3f4da9c8ab5e804dc58f57ba41b03223f57ec80d9c9a2dd0e1", "f3e7c1abfcc9f35556cb1e4c5a2b34445177ac188312d9148f1d1d8467ea8411fa3cda031d023034e45bbe407ef7d1b937bfb098266138857d35cb4efe407306", 52, "0c37564f718eda683aa6f3e9ab2487620b1a8b5c8f20adb3b2d7550af0d635371e531f27cebe76a2abcc96de0875bdae987a45ac", },
		{ "f993f61902b7da332f2bb001baa7accaf764d824eb0cd073315f7ec43158b8fb", "55fc8e0da1b454cab6ddefb235311db2b01504bf9ac3f71c7e3f3d0d1f09f80b", "178bd147673c0ca330e45da63cbd1f1811906bd5284bb44e4bb00f7d7163d1f396975610b6f71c1ae4686466fad4c5e7bb9685099e21ca4f1a45bb3fcf56ae0c", 42, "b7dd613bc9c364d9eeb9a52636d72bc881dfc81a836b6537bbb928bff5b73831358947ea9edea1570550", },
		{ "05188c09c31b4bb63f0d49b47ccc1654c2aba907b8c6c0a82ee403e950169167", "e096d808dfabe8e44eb74950199dadcd586f9de6b141a0ce85ab94b3d97866eb", "669491c8eb7cedbbc0252f3eafb048b39a2a37f60ac87837777c72c879ac8b726c39e10060750c2f539102999b71889746111bc5f71ec8c158cc81cf566aef03", 44, "bb8e22469d1c7f1d5418563e8781f69eccb56678bd36d8919f358c2778562ff6b50de916c12d44f1a778a7f3", },
		{ "eabe57e1a916ebbffa4ba7abc7f23e83d4deb1338816cc1784d7495d92e98d0b", "3aad275642f48a46ed1032f3de9f4053e0fd35cf217e065d2e4579c3683932f7", "b2e9dac2c83942ca374f29c8eff5a30c377c3db3c1c645e593e524d17484e7705b11f79573e2d63495fc3ce3bf216a209f0cb7bea477ae0f8bd297f193af8805", 44, "3f2c2d6682ee597f2a92d7e560ac53d5623550311a4939d68adfb904045ed8d215a9fdb757a2368ea4d89f5f", },
		{ "fef7b893b4b517fab68ca12d36b603bc00826bf3c9b31a05149642ae10bb3f55", "b3fb891868708dfa5da5b9b5234058767ab42c117f12c3228c02a1976d1c0f83", "6243e289314b7c7587802909a9be6173a916b36f9de1e164954dfe5d1ebd57c869a79552d770e13b51855502be6b15e7be42a3675298a81284df58e609b06503", 47, "38c69f884045cdbeebe4478fdbd1ccc6cf00a08d8a3120c74e7167d3a2e26a67a043b8e5bd198f7b0ce0358cef7cf9", },
		{ "16228bec9b724300a37e88e535fc1c58548d34d7148b57c226f2b3af974c1822", "3c92423a8360c9a5d9a093730d72831bec4601dcadfe84de19fc8c8f91fc3d4b", "6aebfa9a4294ec888d54bcb517fcb6821e4c16d2708a2afe701f431a28149ff4f139f9d16a52a63f1f91baf4c8dea37710c73f25c263a8035a39cc118ad0280f", 44, "a3d7b122cd4431b396b20d8cc46cc73ed4a5253a44a76fc83db62cdc845a2bf7081d069a857955a161cccf84", },
		{ "2dc3f5f0a0bc32c6632534e1e8f27e59cbe0bf7617d31aff98098e974c828be7", "b998a416edc28ded988dcacb1caf2bd96c87354b0d1eeccb6980e54a3104f21f", "76a2ddfc4bea48c47e0c82bcbfee28a37c61ec626af39a468e643e0ef9f6533056a5a0b44e64d614ba3c641a40e5b003a99463445ae2c3c8e1e9882092d74b07", 42, "bdae276d738b9758ea3d322b54fd12fe82b767e8d817d8ef3d41f78705748e28d15e9c506962a1b85901", },
	};

	ed25519_secret_key private_key;
	ed25519_public_key public_key;
	ed25519_signature signature;

	for (size_t i = 0; i < (sizeof(tests) / sizeof(*tests)); i++) {
		nem_private_key(tests[i].private_key, private_key);
		MARK_SECRET_DATA(private_key, sizeof(private_key));

		ed25519_publickey_keccak(private_key, public_key);
		UNMARK_SECRET_DATA(public_key, sizeof(public_key));
		ck_assert_mem_eq(public_key, fromhex(tests[i].public_key), 32);

		ed25519_sign_keccak(fromhex(tests[i].data), tests[i].length, private_key, public_key, signature);
		UNMARK_SECRET_DATA(signature, sizeof(signature));
		ck_assert_mem_eq(signature, fromhex(tests[i].signature), 64);

		UNMARK_SECRET_DATA(private_key, sizeof(private_key));
	}
}
END_TEST

START_TEST(test_ed25519_cosi) {
	const int MAXN = 10;
	ed25519_secret_key keys[MAXN];
	ed25519_public_key pubkeys[MAXN];
	ed25519_secret_key nonces[MAXN];
	ed25519_public_key Rs[MAXN];
	ed25519_cosi_signature sigs[MAXN];
	uint8_t msg[32];
	rfc6979_state rng;
	int res;

	init_rfc6979(fromhex("26c76712d89d906e6672dafa614c42e5cb1caac8c6568e4d2493087db51f0d36"),
				 fromhex("26659c1cf7321c178c07437150639ff0c5b7679c7ea195253ed9abda2e081a37"), &rng);

	for (int N = 1; N < 11; N++) {
		ed25519_public_key pk;
		ed25519_public_key R;
		ed25519_signature sig;
		/* phase 0: create priv/pubkeys and combine pubkeys */
		for (int j = 0; j < N; j++) {
			generate_rfc6979(keys[j], &rng);
			ed25519_publickey(keys[j], pubkeys[j]);
		}
		res = ed25519_cosi_combine_publickeys(pk, pubkeys, N);
		ck_assert_int_eq(res, 0);

		generate_rfc6979(msg, &rng);

		/* phase 1: create nonces, commitments (R values) and combine commitments */
		for (int j = 0; j < N; j++) {
			generate_rfc6979(nonces[j], &rng);
			ed25519_publickey(nonces[j], Rs[j]);
		}
		res = ed25519_cosi_combine_publickeys(R, Rs, N);
		ck_assert_int_eq(res, 0);

		MARK_SECRET_DATA(keys, sizeof(keys));
		/* phase 2: sign and combine signatures */
		for (int j = 0; j < N; j++) {
			ed25519_cosi_sign(msg, sizeof(msg), keys[j], nonces[j], R, pk, sigs[j]);
		}
		UNMARK_SECRET_DATA(sigs, sizeof(sigs));

		ed25519_cosi_combine_signatures(sig, R, sigs, N);

		/* check signature */
		res = ed25519_sign_open(msg, sizeof(msg), pk, sig);
		ck_assert_int_eq(res, 0);

		UNMARK_SECRET_DATA(keys, sizeof(keys));
	}
}
END_TEST

static void test_bip32_ecdh_init_node(HDNode *node, const char *seed_str, const char *curve_name) {
	hdnode_from_seed((const uint8_t *)seed_str, strlen(seed_str), curve_name, node);
	hdnode_fill_public_key(node);
	if (node->public_key[0] == 1) {
		node->public_key[0] = 0x40;  // Curve25519 public keys start with 0x40 byte
	}
}

static void test_bip32_ecdh(const char *curve_name, int expected_key_size, const uint8_t *expected_key) {
	int res, key_size;
	HDNode alice, bob;
	uint8_t session_key1[expected_key_size], session_key2[expected_key_size];

	test_bip32_ecdh_init_node(&alice, "Alice", curve_name);
	test_bip32_ecdh_init_node(&bob, "Bob", curve_name);

	// Generate shared key from Alice's secret key and Bob's public key
	res = hdnode_get_shared_key(&alice, bob.public_key, session_key1, &key_size);
	ck_assert_int_eq(res, 0);
	ck_assert_int_eq(key_size, expected_key_size);
	ck_assert_mem_eq(session_key1, expected_key, key_size);

	// Generate shared key from Bob's secret key and Alice's public key
	res = hdnode_get_shared_key(&bob, alice.public_key, session_key2, &key_size);
	ck_assert_int_eq(res, 0);
	ck_assert_int_eq(key_size, expected_key_size);
	ck_assert_mem_eq(session_key2, expected_key, key_size);
}

START_TEST(test_bip32_ecdh_nist256p1) {
	test_bip32_ecdh(
		NIST256P1_NAME, 65,
		fromhex("044aa56f917323f071148cd29aa423f6bee96e7fe87f914d0b91a0f95388c6631646ea92e882773d7b0b1bec356b842c8559a1377673d3965fb931c8fe51e64873"));
}
END_TEST

START_TEST(test_bip32_ecdh_curve25519) {
	test_bip32_ecdh(
		CURVE25519_NAME, 33,
		fromhex("04f34e35516325bb0d4a58507096c444a05ba13524ccf66910f11ce96c62224169"));
}
END_TEST

START_TEST(test_bip32_ecdh_errors) {
	HDNode node;
	const uint8_t peer_public_key[65] = {0};  // invalid public key
	uint8_t session_key[65];
	int res, key_size = 0;

	test_bip32_ecdh_init_node(&node, "Seed", ED25519_NAME);
	res = hdnode_get_shared_key(&node, peer_public_key, session_key, &key_size);
	ck_assert_int_eq(res, 1);
	ck_assert_int_eq(key_size, 0);

	test_bip32_ecdh_init_node(&node, "Seed", CURVE25519_NAME);
	res = hdnode_get_shared_key(&node, peer_public_key, session_key, &key_size);
	ck_assert_int_eq(res, 1);
	ck_assert_int_eq(key_size, 0);

	test_bip32_ecdh_init_node(&node, "Seed", NIST256P1_NAME);
	res = hdnode_get_shared_key(&node, peer_public_key, session_key, &key_size);
	ck_assert_int_eq(res, 1);
	ck_assert_int_eq(key_size, 0);
}
END_TEST

START_TEST(test_output_script) {
	static const char *vectors[] = {
		"76A914010966776006953D5567439E5E39F86A0D273BEE88AC", "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
		"A914010966776006953D5567439E5E39F86A0D273BEE87", "31nVrspaydBz8aMpxH9WkS2DuhgqS1fCuG",
		"0014010966776006953D5567439E5E39F86A0D273BEE", "p2xtZoXeX5X8BP8JfFhQK2nD3emtjch7UeFm",
		"00200102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20", "7XhPD7te3C6CVKnJWUhrTJbFTwudhHqfrjpS59AS6sMzL4RYFiCNg",
		0, 0,
	};
	const char **scr, **adr;
	scr = vectors;
	adr = vectors + 1;
	char address[60];
	while (*scr && *adr) {
		int r = script_output_to_address(fromhex(*scr), strlen(*scr)/2, address, 60);
		ck_assert_int_eq(r, (int)(strlen(*adr) + 1));
		ck_assert_str_eq(address, *adr);
		scr += 2;
		adr += 2;
	}
}
END_TEST

START_TEST(test_ethereum_pubkeyhash)
{
	uint8_t pubkeyhash[20];
	int res;
	HDNode node;

	// init m
	hdnode_from_seed(fromhex("000102030405060708090a0b0c0d0e0f"), 16, SECP256K1_NAME, &node);

	// [Chain m]
	res = hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(pubkeyhash, fromhex("056db290f8ba3250ca64a45d16284d04bc6f5fbf"), 20);

	// [Chain m/0']
	hdnode_private_ckd_prime(&node, 0);
	res = hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(pubkeyhash, fromhex("bf6e48966d0dcf553b53e7b56cb2e0e72dca9e19"), 20);

	// [Chain m/0'/1]
	hdnode_private_ckd(&node, 1);
	res = hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(pubkeyhash, fromhex("29379f45f515c494483298225d1b347f73d1babf"), 20);

	// [Chain m/0'/1/2']
	hdnode_private_ckd_prime(&node, 2);
	res = hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(pubkeyhash, fromhex("d8e85fbbb4b3b3c71c4e63a5580d0c12fb4d2f71"), 20);

	// [Chain m/0'/1/2'/2]
	hdnode_private_ckd(&node, 2);
	res = hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(pubkeyhash, fromhex("1d3462d2319ac0bfc1a52e177a9d372492752130"), 20);

	// [Chain m/0'/1/2'/2/1000000000]
	hdnode_private_ckd(&node, 1000000000);
	res = hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(pubkeyhash, fromhex("73659c60270d326c06ac204f1a9c63f889a3d14b"), 20);

	// init m
	hdnode_from_seed(fromhex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"), 64, SECP256K1_NAME, &node);

	// [Chain m]
	res = hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(pubkeyhash, fromhex("6dd2a6f3b05fd15d901fbeec61b87a34bdcfb843"), 20);

	// [Chain m/0]
	hdnode_private_ckd(&node, 0);
	res = hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(pubkeyhash, fromhex("abbcd4471a0b6e76a2f6fdc44008fe53831e208e"), 20);

	// [Chain m/0/2147483647']
	hdnode_private_ckd_prime(&node, 2147483647);
	res = hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(pubkeyhash, fromhex("40ef2cef1b2588ae862e7a511162ec7ff33c30fd"), 20);

	// [Chain m/0/2147483647'/1]
	hdnode_private_ckd(&node, 1);
	res = hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(pubkeyhash, fromhex("3f2e8905488f795ebc84a39560d133971ccf9b50"), 20);

	// [Chain m/0/2147483647'/1/2147483646']
	hdnode_private_ckd_prime(&node, 2147483646);
	res = hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(pubkeyhash, fromhex("a5016fdf975f767e4e6f355c7a82efa69bf42ea7"), 20);

	// [Chain m/0/2147483647'/1/2147483646'/2]
	hdnode_private_ckd(&node, 2);
	res = hdnode_get_ethereum_pubkeyhash(&node, pubkeyhash);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(pubkeyhash, fromhex("8ff2a9f7e7917804e8c8ec150d931d9c5a6fbc50"), 20);
}
END_TEST

START_TEST(test_ethereum_address)
{
	static const char *vectors[] = {
		"52908400098527886E0F7030069857D2E4169EE7",
		"8617E340B3D01FA5F11F306F4090FD50E238070D",
		"de709f2102306220921060314715629080e2fb77",
		"27b1fdb04752bbc536007a920d24acb045561c26",
		"5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
		"5A4EAB120fB44eb6684E5e32785702FF45ea344D",
		"5be4BDC48CeF65dbCbCaD5218B1A7D37F58A0741",
		"a7dD84573f5ffF821baf2205745f768F8edCDD58",
		"027a49d11d118c0060746F1990273FcB8c2fC196",
		"CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
		0
	};
	uint8_t addr[20];
	char address[41];
	const char **vec = vectors;
	while (*vec) {
		memcpy(addr, fromhex(*vec), 20);
		ethereum_address_checksum(addr, address);
		ck_assert_str_eq(address, *vec);
		vec++;
	}
}
END_TEST

// test vectors from https://raw.githubusercontent.com/NemProject/nem-test-vectors/master/1.test-keys.dat
START_TEST(test_nem_address)
{
	static const struct {
		const char *private_key;
		const char *public_key;
		const char *address;
	} tests[] = {
		{ "575dbb3062267eff57c970a336ebbc8fbcfe12c5bd3ed7bc11eb0481d7704ced", "c5f54ba980fcbb657dbaaa42700539b207873e134d2375efeab5f1ab52f87844", "NDD2CT6LQLIYQ56KIXI3ENTM6EK3D44P5JFXJ4R4", },
		{ "5b0e3fa5d3b49a79022d7c1e121ba1cbbf4db5821f47ab8c708ef88defc29bfe", "96eb2a145211b1b7ab5f0d4b14f8abc8d695c7aee31a3cfc2d4881313c68eea3", "NABHFGE5ORQD3LE4O6B7JUFN47ECOFBFASC3SCAC", },
		{ "738ba9bb9110aea8f15caa353aca5653b4bdfca1db9f34d0efed2ce1325aeeda", "2d8425e4ca2d8926346c7a7ca39826acd881a8639e81bd68820409c6e30d142a", "NAVOZX4HDVOAR4W6K4WJHWPD3MOFU27DFHC7KZOZ", },
		{ "e8bf9bc0f35c12d8c8bf94dd3a8b5b4034f1063948e3cc5304e55e31aa4b95a6", "4feed486777ed38e44c489c7c4e93a830e4c4a907fa19a174e630ef0f6ed0409", "NBZ6JK5YOCU6UPSSZ5D3G27UHAPHTY5HDQMGE6TT", },
		{ "c325ea529674396db5675939e7988883d59a5fc17a28ca977e3ba85370232a83", "83ee32e4e145024d29bca54f71fa335a98b3e68283f1a3099c4d4ae113b53e54", "NCQW2P5DNZ5BBXQVGS367DQ4AHC3RXOEVGRCLY6V", },
		{ "a811cb7a80a7227ae61f6da536534ee3c2744e3c7e4b85f3e0df3c6a9c5613df", "6d34c04f3a0e42f0c3c6f50e475ae018cfa2f56df58c481ad4300424a6270cbb", "NA5IG3XFXZHIPJ5QLKX2FBJPEZYPMBPPK2ZRC3EH", },
		{ "9c66de1ec77f4dfaaebdf9c8bc599ca7e8e6f0bc71390ffee2c9dd3f3619242a", "a8fefd72a3b833dc7c7ed7d57ed86906dac22f88f1f4331873eb2da3152a3e77", "NAABHVFJDBM74XMJJ52R7QN2MTTG2ZUXPQS62QZ7", },
		{ "c56bc16ecf727878c15e24f4ae68569600ac7b251218a44ef50ce54175776edc", "c92f761e6d83d20068fd46fe4bd5b97f4c6ba05d23180679b718d1f3e4fb066e", "NCLK3OLMHR3F2E3KSBUIZ4K5PNWUDN37MLSJBJZP", },
		{ "9dd73599283882fa1561ddfc9be5830b5dd453c90465d3fe5eeb646a3606374e", "eaf16a4833e59370a04ccd5c63395058de34877b48c17174c71db5ed37b537ed", "ND3AHW4VTI5R5QE5V44KIGPRU5FBJ5AFUCJXOY5H", },
		{ "d9639dc6f49dad02a42fd8c217f1b1b4f8ce31ccd770388b645e639c72ff24fa", "0f74a2f537cd9c986df018994dde75bdeee05e35eb9fe27adf506ca8475064f7", "NCTZ4YAP43ONK3UYTASQVNDMBO24ZHJE65F3QPYE", },
		{ "efc1992cd50b70ca55ac12c07aa5d026a8b78ffe28a7dbffc9228b26e02c38c1", "2ebff201255f6cf948c78f528658b99a7c13ac791942fa22d59af610558111f5", "NDQ2TMCMXBSFPZQPE2YKH6XLC24HD6LUMN6Z4GIC", },
		{ "143a815e92e43f3ed1a921ee48cd143931b88b7c3d8e1e981f743c2a5be3c5ba", "419ed11d48730e4ae2c93f0ea4df853b8d578713a36dab227517cf965861af4e", "NA32IDDW2C53BDSBJNFL3Z6UU3J5CJZJMCZDXCF4", },
		{ "bc1a082f5ac6fdd3a83ade211e5986ac0551bad6c7da96727ec744e5df963e2a", "a160e6f9112233a7ce94202ed7a4443e1dac444b5095f9fecbb965fba3f92cac", "NADUCEQLC3FTGB25GTA5HOUTB53CBVQNVOIP7NTJ", },
		{ "4e47b4c6f4c7886e49ec109c61f4af5cfbb1637283218941d55a7f9fe1053f72", "fbb91b16df828e21a9802980a44fc757c588bc1382a4cea429d6fa2ae0333f56", "NBAF3BFLLPWH33MYE6VUPP5T6DQBZBKIDEQKZQOE", },
		{ "efc4389da48ce49f85365cfa578c746530e9eac42db1b64ec346119b1becd347", "2232f24dda0f2ded3ecd831210d4e8521a096b50cadd5a34f3f7083374e1ec12", "NBOGTK2I2ATOGGD7ZFJHROG5MWL7XCKAUKSWIVSA", },
		{ "bdba57c78ca7da16a3360efd13f06276284db8c40351de7fcd38ba0c35ac754d", "c334c6c0dad5aaa2a0d0fb4c6032cb6a0edd96bf61125b5ea9062d5a00ee0eee", "NCLERTEFYXKLK7RA4MVACEFMXMK3P7QMWTM7FBW2", },
		{ "20694c1ec3c4a311bcdb29ed2edc428f6d4f9a4c429ad6a5bf3222084e35695f", "518c4de412efa93de06a55947d11f697639443916ec8fcf04ebc3e6d17d0bd93", "NB5V4BPIJHXVONO7UGMJDPFARMFA73BOBNOOYCOV", },
		{ "e0d4f3760ac107b33c22c2cac24ab2f520b282684f5f66a4212ff95d926323ce", "b3d16f4ead9de67c290144da535a0ed2504b03c05e5f1ceb8c7863762f786857", "NC4PBAO5TPCAVQKBVOC4F6DMZP3CFSQBU46PSKBD", },
		{ "efa9afc617412093c9c7a7c211a5332dd556f941e1a88c494ec860608610eea2", "7e7716e4cebceb731d6f1fd28676f34888e9a0000fcfa1471db1c616c2ddf559", "NCFW2LPXIWLBWAQN2QVIWEOD7IVDO3HQBD2OU56K", },
		{ "d98499b3db61944684ce06a91735af4e14105338473fcf6ebe2b0bcada3dfd21", "114171230ad6f8522a000cdc73fbc5c733b30bb71f2b146ccbdf34499f79a810", "NCUKWDY3J3THKQHAKOK5ALF6ANJQABZHCH7VN6DP", },
	};

	HDNode node;
	ed25519_secret_key private_key;
	uint8_t chain_code[32];
	char address[41];

	for (size_t i = 0; i < (sizeof(tests) / sizeof(*tests)); i++) {
		nem_private_key(tests[i].private_key, private_key);

		ck_assert(hdnode_from_xprv(0, 0, chain_code, private_key, ED25519_KECCAK_NAME, &node));

		ck_assert(hdnode_get_nem_address(&node, NEM_NETWORK_MAINNET, address));
		ck_assert_str_eq(address, tests[i].address);

		ck_assert_mem_eq(&node.public_key[1], fromhex(tests[i].public_key), 32);
	}
}
END_TEST

// test vectors from https://raw.githubusercontent.com/NemProject/nem-test-vectors/master/3.test-derive.dat
START_TEST(test_nem_derive)
{
	static const struct {
		const char *salt;
		const char *private_key;
		const char *public_key;
		const char *mul;
		const char *shared_key;
	} tests[] = {
		{ "ad63ac08f9afc85eb0bf4f8881ca6eaa0215924c87aa2f137d56109bb76c6f98", "e8857f8e488d4e6d4b71bcd44bb4cff49208c32651e1f6500c3b58cafeb8def6", "9d8e5f200b05a2638fb084a375408cabd6d5989590d96e3eea5f2cb34668178e", "a8352060ba5718745ee4d78b9df564e0fbe13f50d50ab15a8dd524159d81d18b", "990a5f611c65fbcde735378bdec38e1039c5466503511e8c645bbe42795c752b", },
		{ "96104f0a28f9cca40901c066cd435134662a3b053eb6c8df80ee0d05dc941963", "d7f67b5f52cbcd1a1367e0376a8eb1012b634acfcf35e8322bae8b22bb9e8dea", "9735c92d150dcee0ade5a8d1822f46a4db22c9cda25f33773ae856fe374a3e8a", "ea14d521d83328dba70982d42094300585818cc2da609fdb1f73bb32235576ff", "b498aa21d4ba4879ea9fd4225e93bacc760dcd9c119f8f38ab0716457d1a6f85", },
		{ "d8f94a0bbb1de80aea17aab42e2ffb982e73fc49b649a318479e951e392d8728", "d026ddb445fb3bbf3020e4b55ed7b5f9b7fd1278c34978ca1a6ed6b358dadbae", "d19e6beca3b26b9d1abc127835ebeb7a6c19c33dec8ec472e1c4d458202f4ec8", "0d561f54728ad837ae108ec66c2ece2bb3b26041d3ee9b77fdc6d36d9ebfb2e3", "d012afe3d1d932304e613c91545bf571cf2c7281d6cafa8e81393a551f675540", },
		{ "3f8c969678a8abdbfb76866a142c284a6f01636c1c1607947436e0d2c30d5245", "c522b38c391d1c3fa539cc58802bc66ac34bb3c73accd7f41b47f539bedcd016", "ea5b6a0053237f7712b1d2347c447d3e83e0f2191762d07e1f53f8eb7f2dfeaa", "23cccd3b63a9456e4425098b6df36f28c8999461a85e4b2b0c8d8f53c62c9ea9", "7e27efa50eed1c2ac51a12089cbab6a192624709c7330c016d5bc9af146584c1", },
		{ "e66415c58b981c7f1f2b8f45a42149e9144616ff6de49ff83d97000ac6f6f992", "2f1b82be8e65d610a4e588f000a89a733a9de98ffc1ac9d55e138b3b0a855da0", "65aeda1b47f66c978a4a41d4dcdfbd8eab5cdeb135695c2b0c28f54417b1486d", "43e5b0a5cc8146c03ac63e6f8cf3d8825a9ca1ed53ea4a88304af4ddf5461b33", "bb4ab31c334e55d378937978c90bb33779b23cd5ef4c68342a394f4ec8fa1ada", },
		{ "58487c9818c9d28ddf97cb09c13331941e05d0b62bf4c35ee368de80b552e4d1", "f3869b68183b2e4341307653e8f659bd7cd20e37ea5c00f5a9e203a8fa92359a", "c7e4153a18b4162f5c1f60e1ba483264aa5bb3f4889dca45b434fcd30b9cf56f", "5ae9408ab3156b8828c3e639730bd5e5db93d7afe2cee3fcda98079316c5bb3a", "0224d85ae8f17bfe127ec24b8960b7639a0dbde9c8c39a0575b939448687bb14", },
		{ "ad66f3b654844e53d6fb3568134fae75672ba63868c113659d3ca58c2c39d24f", "d38f2ef8dfdc7224fef596130c3f4ff68ac83d3f932a56ee908061466ac28572", "d0c79d0340dc66f0a895ce5ad60a933cf6be659569096fb9d4b81e5d32292372", "1ea22db4708ed585ab541a4c70c3069f8e2c0c1faa188ddade3efaa53c8329f6", "886a7187246934aedf2794748deadfe038c9fd7e78d4b7be76c5a651440ac843", },
		{ "eed48604eab279c6ad8128aa83483a3da0928271a4cae1a5745671284e1fb89d", "e2342a8450fc0adfa0ea2fbd0b1d28f100f0a3a905a3da29de34d1353afa7df7", "d2dbe07e0f2dbc3dbb01c70092e3c4247d12827ddcd8d76534fd740a65c30de2", "4c4b30eb6a2bfa17312f5729b4212cb51c2eee8fbfaea82a0e957ca68f4f6a30", "dcae613ac5641ff9d4c3ca58632245f93b0b8657fe4d48bac7b062cc53dd21ad", },
		{ "f35b315287b268c0d0b386fb5b31810f65e1c4497cffae24527f69a3abac3884", "049016230dbef7a14a439e5ab2f6d12e78cb8df127db4e0c312673b3c361e350", "1b3b1925a8a535cd7d78725d25298f45bba8ca3dee2cdaabf14241c9b51b37c4", "04c9685dae1f8eb72a6438f24a87dc83a56d79c9024edf7e01aa1ae34656f29e", "b48469d0428c223b93cd1fe34bb2cafd3fb78a8fa15f98f89f1ac9c0ce7c9001", },
		{ "d6cf082c5d9a96e756a94a2e27703138580a7c7c1af505c96c3abf7ab6802e1d", "67cd02b0b8b0adcf6fdd4d4d64a1f4193ced68bb8605d0ec941a62011326d140", "a842d5127c93a435e4672dcadd9fccbfd0e9208c79c5404848b298597eccdbdb", "d5c6bd6d81b99659d0bafe91025b6ecf73b16c6b07931cf44718b13f00fde3f7", "8aa160795b587f4be53aa35d26e9b618b4cd6ec765b523bc908e53c258ca8fd4", },
		{ "dda32c91c95527a645b00dd05d13f0b98ed612a726ce5f5221431430b7660944", "eba026f92a8ffb5e95060a22e15d597fe838a99a0b2bbcb423c933b6bc718c50", "7dbaf9c313a1ff9128c54d6cd740c7d0cc46bca588e7910d438dd619ca4fd69a", "5bb20a145de83ba27a0c261e1f54bfd7dcea61888fc2eebbe6166876f7b000b8", "3a96f152ad8bf355cccb307e4a40108aa17f8e925522a2b5bb0b3f1e1a262914", },
		{ "63c500acbd4ff747f7dadde7d3286482894ac4d7fe68f396712bca29879aa65c", "9663cd3c2030a5fe4a3ea3cc9a1d182b3a63ade68616aaeb4caf40b495f6f227", "b1e7d9070ac820d986d839b79f7aa594dcf708473529dad87af8682cc6197374", "1f7a97584d8db9f395b9ac4447de4b33c5c1f5020187cd4996286a49b07eb8a7", "4d2a974ec12dcf525b5654d31053460850c3092648b7e15598b7131d2930e9fb", },
		{ "91f340961029398cc8bcd906388044a6801d24328efdf919d8ed0c609862a073", "45a588500d00142e2226231c01fd11ac6f842ab6a85872418f5b6a1999f8bd98", "397233c96069b6f4a57d6e93f759fa327222eaef71fc981afa673b248206df3f", "062123ef9782e3893f7b2e1d557b4ecce92b9f9aa8577e76380f228b75152f84", "235848cb04230a16d8978aa7c19fe7fbff3ebe29389ea6eb24fb8bc3cb50afc6", },
		{ "46120b4da6ba4eb54fb65213cfef99b812c86f7c42a1de1107f8e8c12c0c3b6b", "cc19a97a99ad71ce348bcf831c0218e6a1f0a8d52186cabe6298b56f24e640f9", "c54631bb62f0f9d86b3301fcb2a671621e655e578c95504af5f78da83f7fec4f", "ab73cc20c75260ff3a7cefea8039291d4d15114a07a9250375628cca32225bb6", "70040a360b6a2dfa881272ef4fa6616e2e8fcc45194fa2a21a1eef1160271cd5", },
		{ "f0a69ded09f1d731ab9561d0c3a40b7ef30bcb2bf60f92beccd8734e2441403d", "ea732822a381c46a7ac9999bf5ef85e16b7460b26aaf6c1a1c6ffa8c8c82c923", "110decbff79c382b1e60af4259564a3c473087792350b24fca98ae9a74ba9dd9", "81bdee95aecdcf821a9d682f79056f1abdcf1245d2f3b55244447881a283e0d4", "1bc29d4470ccf97d4e35e8d3cd4b12e3ebf2cb0a82425d35984aeedf7ad0f6f9", },
		{ "e79cf4536fb1547e57626c0f1a87f71a396fdfb985b00731c0c2876a00645eda", "04213fc02b59c372e3e7f53faa71a2f73b31064102cb6fc8b68432ba7cdf7eb4", "ca1c750aaed53bc30dac07d0696ed86bcd7cdbbcbd3d15bb90d90cb5c6117bac", "c68cd0872a42a3a64e8a229ef7fcad3d722047d5af966f7dda4d4e32d0d57203", "bfdd3d07563d966d95afe4b8abea4b567265fceea8c4ecddb0946256c33e07b2", },
		{ "81a40db4cddaf076e0206bd2b0fa7470a72cc456bad34aa3a0469a4859f286be", "52156799fd86cc63345cdbffd65ef4f5f8df0ffd9906a40af5f41d269bbcff5d", "54d61aa0b0b17a87f1376fe89cd8cd6b314827c1f1b9e5e7b20e7a7eee2a8335", "4553fb2cab8555068c32f86ceb692bbf1c2beeaf21627ef1b1be57344b52eea8", "55096b6710ade3bbe38702458ee13faa10c24413261bc076f17675dcbf2c4ee6", },
		{ "d28e4a9e6832a3a4dad014a2bf1f666f01093cbba8b9ad4d1dcad3ea10cb42b9", "8ca134404c8fa199b0c72cb53cfa0adcf196dfa560fb521017cce5cbace3ba59", "3a6c39a1e5f9f550f1debedd9a0bc84210cce5f9834797db8f14122bf5817e45", "eb632ca818b4f659630226a339a3ce536b31c8e1e686fea8da3760e8abc20b8e", "9fbb3fbaf1cd54ee0cd90685f59b082545983f1f662ef701332379306a6ad546", },
		{ "f9c4bfad9e2a3d98c44c12734881a6f217d6c9523cc210772fad1297993454b4", "b85960fcadda8d0a0960559b6b7818a0d8d4574b4e928b17c9b498fa9ffab4ef", "6a1d0ef23ce0b40a7077ecb7b7264945054e3bdb58ee25e1b0ee8b3e19dbfcdc", "bb145dddcb75074a6a03249fca1aa7d6fa9549e3ed965f138ca5e7071b7878f2", "87d3faea4a98e41009eb8625611ea0fc12094c295af540c126c14a0f55afa76e", },
		{ "656df4789a369d220aceb7b318517787d27004ecccedea019d623bcb2d79f5ff", "acf83e30afb2a5066728ec5d93564c08abe5e68e3a2a2ff953bdcf4d44f9da06", "bdda65efe56d7890286aada1452f62f85ba157d0b4621ba641de15d8d1c9e331", "958beef5dc6babc6de383c32ad7dd3a6d6eb8bb3236ed5558eec0f9eb31e5458", "6f6d4ee36d9d76e462c9635adfbb6073134a276cfc7cb86762004ec47197afa0", },
	};

	HDNode node;
	ed25519_secret_key private_key;
	uint8_t chain_code[32];
	ed25519_public_key public_key, mul;
	uint8_t shared_key[SHA3_256_DIGEST_LENGTH];

	for (size_t i = 0; i < (sizeof(tests) / sizeof(*tests)); i++) {
		nem_private_key(tests[i].private_key, private_key);

		ck_assert(hdnode_from_xprv(0, 0, chain_code, private_key, ED25519_KECCAK_NAME, &node));
		memcpy(public_key, fromhex(tests[i].public_key), 32);

		ck_assert(hdnode_get_nem_shared_key(&node, public_key, fromhex(tests[i].salt), mul, shared_key));
		ck_assert_mem_eq(mul, fromhex(tests[i].mul), sizeof(mul));
		ck_assert_mem_eq(shared_key, fromhex(tests[i].shared_key), sizeof(shared_key));
	}
}
END_TEST

// test vectors from https://raw.githubusercontent.com/NemProject/nem-test-vectors/master/4.test-cipher.dat
START_TEST(test_nem_cipher)
{
	static const struct {
		const char *private_key;
		const char *public_key;
		const char *salt;
		const char *iv;
		const char *input;
		const char *output;
	} tests[] = {
		{ "3140f94c79f249787d1ec75a97a885980eb8f0a7d9b7aa03e7200296e422b2b6", "57a70eb553a7b3fd621f0dba6abf51312ea2e2a2a1e19d0305516730f4bcbd21", "83616c67f076d356fd1288a6e0fd7a60488ba312a3adf0088b1b33c7655c3e6a", "a73ff5c32f8fd055b09775817a6a3f95", "86ddb9e713a8ebf67a51830eff03b837e147c20d75e67b2a54aa29e98c", "70815da779b1b954d7a7f00c16940e9917a0412a06a444b539bf147603eef87f", },
		{ "3140f94c79f249787d1ec75a97a885980eb8f0a7d9b7aa03e7200296e422b2b6", "57a70eb553a7b3fd621f0dba6abf51312ea2e2a2a1e19d0305516730f4bcbd21", "703ce0b1d276b10eef35672df03234385a903460db18ba9d4e05b3ad31abb284", "91246c2d5493867c4fa3e78f85963677", "86ddb9e713a8ebf67a51830eff03b837e147c20d75e67b2a54aa29e98c", "564b2f40d42c0efc1bd6f057115a5abd1564cae36d7ccacf5d825d38401aa894", },
		{ "3140f94c79f249787d1ec75a97a885980eb8f0a7d9b7aa03e7200296e422b2b6", "57a70eb553a7b3fd621f0dba6abf51312ea2e2a2a1e19d0305516730f4bcbd21", "b22e8e8e7373ac31ca7f0f6eb8b93130aba5266772a658593f3a11792e7e8d92", "9f8e33d82374dad6aac0e3dbe7aea704", "86ddb9e713a8ebf67a51830eff03b837e147c20d75e67b2a54aa29e98c", "7cab88d00a3fc656002eccbbd966e1d5d14a3090d92cf502cdbf843515625dcf", },
		{ "3140f94c79f249787d1ec75a97a885980eb8f0a7d9b7aa03e7200296e422b2b6", "57a70eb553a7b3fd621f0dba6abf51312ea2e2a2a1e19d0305516730f4bcbd21", "af646c54cd153dffe453b60efbceeb85c1e95a414ea0036c4da94afb3366f5d9", "6acdf8e01acc8074ddc807281b6af888", "86ddb9e713a8ebf67a51830eff03b837e147c20d75e67b2a54aa29e98c", "aa70543a485b63a4dd141bb7fd78019092ac6fad731e914280a287c7467bae1a", },
		{ "3140f94c79f249787d1ec75a97a885980eb8f0a7d9b7aa03e7200296e422b2b6", "57a70eb553a7b3fd621f0dba6abf51312ea2e2a2a1e19d0305516730f4bcbd21", "d9c0d386636c8a024935c024589f9cd39e820a16485b14951e690a967830e269", "f2e9f18aeb374965f54d2f4e31189a8f", "86ddb9e713a8ebf67a51830eff03b837e147c20d75e67b2a54aa29e98c", "33d97c216ea6498dfddabf94c2e2403d73efc495e9b284d9d90aaff840217d25", },
		{ "d5c0762ecea2cd6b5c56751b58debcb32713aab348f4a59c493e38beb3244f3a", "66a35941d615b5644d19c2a602c363ada8b1a8a0dac3682623852dcab4afac04", "06c227baac1ae3b0b1dc583f4850f13f9ba5d53be4a98fa5c3ea16217847530d", "3735123e78c44895df6ea33fa57e9a72", "86ddb9e713a8ebf67a51830eff03b837e147c20d75e67b2a54aa29e98c", "d5b5d66ba8cee0eb7ecf95b143fa77a46d6de13749e12eff40f5a7e649167ccb", },
		{ "d5c0762ecea2cd6b5c56751b58debcb32713aab348f4a59c493e38beb3244f3a", "66a35941d615b5644d19c2a602c363ada8b1a8a0dac3682623852dcab4afac04", "92f55ba5bc6fc2f23e3eedc299357c71518e36ba2447a4da7a9dfe9dfeb107b5", "1cbc4982e53e370052af97ab088fa942", "86ddb9e713a8ebf67a51830eff03b837e147c20d75e67b2a54aa29e98c", "d48ef1ef526d805656cfc932aff259eadb17aa3391dde1877a722cba31d935b2", },
		{ "d5c0762ecea2cd6b5c56751b58debcb32713aab348f4a59c493e38beb3244f3a", "66a35941d615b5644d19c2a602c363ada8b1a8a0dac3682623852dcab4afac04", "10f15a39ba49866292a43b7781bc71ca8bbd4889f1616461caf056bcb91b0158", "c40d531d92bfee969dce91417346c892", "49de3cd5890e0cd0559f143807ff688ff62789b7236a332b7d7255ec0b4e73e6b3a4", "e6d75afdb542785669b42198577c5b358d95397d71ec6f5835dca46d332cc08dbf73ea790b7bcb169a65719c0d55054c", },
		{ "d5c0762ecea2cd6b5c56751b58debcb32713aab348f4a59c493e38beb3244f3a", "66a35941d615b5644d19c2a602c363ada8b1a8a0dac3682623852dcab4afac04", "9c01ed42b219b3bbe1a43ae9d7af5c1dd09363baacfdba8f4d03d1046915e26e", "059a35d5f83249e632790015ed6518b9", "49de3cd5890e0cd0559f143807ff688ff62789b7236a332b7d7255ec0b4e73e6b3a4", "5ef11aadff2eccee8b712dab968fa842eb770818ec0e6663ed242ea8b6bbc1c66d6285ee5b5f03d55dfee382fb4fa25d", },
		{ "d5c0762ecea2cd6b5c56751b58debcb32713aab348f4a59c493e38beb3244f3a", "66a35941d615b5644d19c2a602c363ada8b1a8a0dac3682623852dcab4afac04", "bc1067e2a7415ea45ff1ca9894338c591ff15f2e57ae2789ae31b9d5bea0f11e", "8c73f0d6613898daeefa3cf8b0686d37", "49de3cd5890e0cd0559f143807ff688ff62789b7236a332b7d7255ec0b4e73e6b3a4", "6d220213b1878cd40a458f2a1e6e3b48040455fdf504dcd857f4f2ca1ad642e3a44fc401d04e339d302f66a9fad3d919", },
		{ "9ef87ba8aa2e664bdfdb978b98bc30fb61773d9298e7b8c72911683eeff41921", "441e76d7e53be0a967181076a842f69c20fd8c0e3f0ce3aa421b490b059fe094", "cf4a21cb790552165827b678ca9695fcaf77566d382325112ff79483455de667", "bfbf5482e06f55b88bdd9e053b7eee6e", "49de3cd5890e0cd0559f143807ff688ff62789b7236a332b7d7255ec0b4e73e6b3a4", "1198a78c29c215d5c450f7b8513ead253160bc9fde80d9cc8e6bee2efe9713cf5a09d6293c41033271c9e8c22036a28b", },
		{ "9ef87ba8aa2e664bdfdb978b98bc30fb61773d9298e7b8c72911683eeff41921", "441e76d7e53be0a967181076a842f69c20fd8c0e3f0ce3aa421b490b059fe094", "eba5eae8aef79114082c3e70baef95bb02edf13b3897e8be7a70272962ef8838", "af9a56da3da18e2fbd2948a16332532b", "49de3cd5890e0cd0559f143807ff688ff62789b7236a332b7d7255ec0b4e73e6b3a4", "1062ab5fbbdee9042ad35bdadfd3047c0a2127fe0f001da1be1b0582185edfc9687be8d68f85795833bb04af9cedd3bb", },
		{ "9ef87ba8aa2e664bdfdb978b98bc30fb61773d9298e7b8c72911683eeff41921", "441e76d7e53be0a967181076a842f69c20fd8c0e3f0ce3aa421b490b059fe094", "518f8dfd0c138f1ffb4ea8029db15441d70abd893c3d767dc668f23ba7770e27", "42d28307974a1b2a2d921d270cfce03b", "49de3cd5890e0cd0559f143807ff688ff62789b7236a332b7d7255ec0b4e73e6b3a4", "005e49fb7c5da540a84b034c853fc9f78a6b901ea495aed0c2abd4f08f1a96f9ffefc6a57f1ac09e0aea95ca0f03ffd8", },
		{ "9ef87ba8aa2e664bdfdb978b98bc30fb61773d9298e7b8c72911683eeff41921", "441e76d7e53be0a967181076a842f69c20fd8c0e3f0ce3aa421b490b059fe094", "582fdf58b53715c26e10ba809e8f2ab70502e5a3d4e9a81100b7227732ab0bbc", "91f2aad3189bb2edc93bc891e73911ba", "49de3cd5890e0cd0559f143807ff688ff62789b7236a332b7d7255ec0b4e73e6b3a4", "821a69cb16c57f0cb866e590b38069e35faec3ae18f158bb067db83a11237d29ab1e6b868b3147236a0958f15c2e2167", },
		{ "9ef87ba8aa2e664bdfdb978b98bc30fb61773d9298e7b8c72911683eeff41921", "441e76d7e53be0a967181076a842f69c20fd8c0e3f0ce3aa421b490b059fe094", "a415b4c006118fb72fc37b2746ef288e23ac45c8ff7ade5f368a31557b6ac93a", "2b7c5f75606c0b8106c6489ea5657a9e", "24512b714aefd5cbc4bcc4ef44ce6c67ffc447c65460a6c6e4a92e85", "2781d5ee8ef1cb1596f8902b33dfae5045f84a987ca58173af5830dbce386062", },
		{ "ed93c5a101ab53382ceee4f7e6b5aa112621d3bb9d18891509b1834ede235bcc", "5a5e14c633d7d269302849d739d80344ff14db51d7bcda86045723f05c4e4541", "47e73ec362ea82d3a7c5d55532ad51d2cdf5316b981b2b2bd542b0efa027e8ea", "b2193f59030c8d05a7d3577b7f64dd33", "24512b714aefd5cbc4bcc4ef44ce6c67ffc447c65460a6c6e4a92e85", "3f43912db8dd6672b9996e5272e18c4b88fec9d7e8372db9c5f4709a4af1d86f", },
		{ "ed93c5a101ab53382ceee4f7e6b5aa112621d3bb9d18891509b1834ede235bcc", "5a5e14c633d7d269302849d739d80344ff14db51d7bcda86045723f05c4e4541", "aaa006c57b6d1e402650577fe9787d8d285f4bacd7c01f998be49c766f8860c7", "130304ddb9adc8870cf56bcae9487b7f", "24512b714aefd5cbc4bcc4ef44ce6c67ffc447c65460a6c6e4a92e85", "878cc7d8c0ef8dac0182a78eedc8080a402f59d8062a6b4ca8f4a74f3c3b3de7", },
		{ "ed93c5a101ab53382ceee4f7e6b5aa112621d3bb9d18891509b1834ede235bcc", "5a5e14c633d7d269302849d739d80344ff14db51d7bcda86045723f05c4e4541", "28dc7ccd6c2a939eef64b8be7b9ae248295e7fcd8471c22fa2f98733fea97611", "cb13890d3a11bc0a7433738263006710", "24512b714aefd5cbc4bcc4ef44ce6c67ffc447c65460a6c6e4a92e85", "e74ded846bebfa912fa1720e4c1415e6e5df7e7a1a7fedb5665d68f1763209a4", },
		{ "ed93c5a101ab53382ceee4f7e6b5aa112621d3bb9d18891509b1834ede235bcc", "5a5e14c633d7d269302849d739d80344ff14db51d7bcda86045723f05c4e4541", "79974fa2cad95154d0873902c153ccc3e7d54b17f2eeb3f29b6344cad9365a9a", "22123357979d20f44cc8eb0263d84e0e", "24512b714aefd5cbc4bcc4ef44ce6c67ffc447c65460a6c6e4a92e85", "eb14dec7b8b64d81a2ee4db07b0adf144d4f79a519bbf332b823583fa2d45405", },
		{ "ed93c5a101ab53382ceee4f7e6b5aa112621d3bb9d18891509b1834ede235bcc", "5a5e14c633d7d269302849d739d80344ff14db51d7bcda86045723f05c4e4541", "3409a6f8c4dcd9bd04144eb67e55a98696b674735b01bf1196191f29871ef966", "a823a0965969380ea1f8659ea5fd8fdd", "24512b714aefd5cbc4bcc4ef44ce6c67ffc447c65460a6c6e4a92e85", "00a7eb708eae745847173f8217efb05be13059710aee632e3f471ac3c6202b51", },
		{ "a73a0b2686f7d699c018b6b08a352856e556070caa329c26241aec889eefde10", "9b493403bee45ae6277430ef8d0c4163ffd81ace2db6c7821205da09a664a86c", "c25701b9b7328c4ac3d23223d10623bd527c0a98e38ae9c62fbc403c80ab20ae", "4b4ee0e4443779f3af429a749212f476", "b6926d0ec82cec86c0d27ec9a33a0e0f", "f39f7d66e0fde39ecdf58be2c0ef361a17cfd6843e310adbe0ec3118cd72800d", },
		{ "a73a0b2686f7d699c018b6b08a352856e556070caa329c26241aec889eefde10", "9b493403bee45ae6277430ef8d0c4163ffd81ace2db6c7821205da09a664a86c", "31d18fdffc480310828778496ff817039df5d6f30bf6d9edd0b4396863d05f93", "418bcbdf52860a450bfacc96920d02cf", "b6926d0ec82cec86c0d27ec9a33a0e0f", "0e6ce9889fe7b3cd82794b0ae27c1f5985d2f2a1f398371a138f8db1df1f54de", },
		{ "e2e4dee102fad0f47f60202269605589cd9cf70f816b34016796c74b766f3041", "c5ce283033a3255ae14d42dff1e4c18a224ac79d084b285123421b105ee654c9", "56b4c645f81dbfb6ba0c6d3f1626e1e5cd648eeb36562715f7cd7e9ea86a0d7f", "dc9bdce76d68d2e4d72267cf4e72b022", "b6926d0ec82cec86c0d27ec9a33a0e0f", "dc6f046c3008002041517a7c4f3ababe609cf02616fcccda39c075d1be4175f5", },
		{ "e2e4dee102fad0f47f60202269605589cd9cf70f816b34016796c74b766f3041", "c5ce283033a3255ae14d42dff1e4c18a224ac79d084b285123421b105ee654c9", "df180b91986c8c7000792f96d1faa61e30138330430a402322be1855089b0e7f", "ccf9b77341c866465b474e2f4a3b1cf8", "b6926d0ec82cec86c0d27ec9a33a0e0f", "94e4ae89041437f39826704f02cb5d775226f34344635e592846417497a5020b", },
		{ "e2e4dee102fad0f47f60202269605589cd9cf70f816b34016796c74b766f3041", "c5ce283033a3255ae14d42dff1e4c18a224ac79d084b285123421b105ee654c9", "a0eee7e84c76e63fdae6e938b43330775eaf17d260e40b98c9e6616b668102a7", "662c681cfec6f6d052ff0e2c1255f2c2", "b6926d0ec82cec86c0d27ec9a33a0e0f", "70bba3c48be9c75a144b1888ca3d21a6b21f52eec133981a024390a6a0ba36f9", },
		{ "e2e4dee102fad0f47f60202269605589cd9cf70f816b34016796c74b766f3041", "c5ce283033a3255ae14d42dff1e4c18a224ac79d084b285123421b105ee654c9", "c6acd2d90eb782c3053b366680ffa0e148de81fea198c87bb643869fd97e5cb0", "908dc33ba80520f2f0f04e7890e3a3c0", "b6926d0ec82cec86c0d27ec9a33a0e0f", "f6efe1d76d270aac264aa35d03049d9ce63be1996d543aef00559219c8666f71", },
	};

	HDNode node;
	ed25519_secret_key private_key;
	uint8_t chain_code[32];
	ed25519_public_key public_key;
	uint8_t salt[sizeof(public_key)];

	uint8_t iv[AES_BLOCK_SIZE];
	uint8_t buffer[FROMHEX_MAXLEN];

	uint8_t input[FROMHEX_MAXLEN];
	uint8_t output[FROMHEX_MAXLEN];

	for (size_t i = 0; i < (sizeof(tests) / sizeof(*tests)); i++) {
		nem_private_key(tests[i].private_key, private_key);

		ck_assert(hdnode_from_xprv(0, 0, chain_code, private_key, ED25519_KECCAK_NAME, &node));
		memcpy(public_key, fromhex(tests[i].public_key), 32);
		memcpy(salt, fromhex(tests[i].salt), sizeof(salt));

		size_t input_size = strlen(tests[i].input) / 2;
		size_t output_size = strlen(tests[i].output) / 2;

		memcpy(input, fromhex(tests[i].input), input_size);
		memcpy(output, fromhex(tests[i].output), output_size);

		memcpy(iv, fromhex(tests[i].iv), sizeof(iv));
		ck_assert(hdnode_nem_encrypt(&node, public_key, iv, salt, input, input_size, buffer));
		ck_assert_int_eq(output_size, NEM_ENCRYPTED_SIZE(input_size));
		ck_assert_mem_eq(buffer, output, output_size);

		memcpy(iv, fromhex(tests[i].iv), sizeof(iv));
		ck_assert(hdnode_nem_decrypt(&node, public_key, iv, salt, output, output_size, buffer));
		ck_assert_int_eq(input_size, NEM_DECRYPTED_SIZE(buffer, output_size));
		ck_assert_mem_eq(buffer, input, input_size);
	}
}
END_TEST

START_TEST(test_nem_transaction_transfer)
{
	nem_transaction_ctx ctx;

	uint8_t buffer[1024], hash[SHA3_256_DIGEST_LENGTH];

	// http://bob.nem.ninja:8765/#/transfer/0acbf8df91e6a65dc56c56c43d65f31ff2a6a48d06fc66e78c7f3436faf3e74f

	nem_transaction_start(&ctx, fromhex("e59ef184a612d4c3c4d89b5950eb57262c69862b2f96e59c5043bf41765c482f"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_transfer(&ctx,
			NEM_NETWORK_TESTNET, 0, NULL, 0, 0,
			"TBGIMRE4SBFRUJXMH7DVF2IBY36L2EDWZ37GVSC4", 50000000000000,
			NULL, 0, false,
			0));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("0acbf8df91e6a65dc56c56c43d65f31ff2a6a48d06fc66e78c7f3436faf3e74f"), sizeof(hash));

	// http://bob.nem.ninja:8765/#/transfer/3409d9ece28d6296d6d5e220a7e3cb8641a3fb235ffcbd20c95da64f003ace6c

	nem_transaction_start(&ctx, fromhex("994793ba1c789fa9bdea918afc9b06e2d0309beb1081ac5b6952991e4defd324"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_transfer(&ctx,
			NEM_NETWORK_TESTNET, 14072100, NULL, 194000000, 14075700,
			"TBLOODPLWOWMZ2TARX4RFPOSOWLULHXMROBN2WXI", 3000000,
			(uint8_t *) "sending you 3 pairs of paddles\n", 31, false,
			2));

	ck_assert(nem_transaction_write_mosaic(&ctx,
			"gimre.games.pong", "paddles", 2));

	ck_assert(nem_transaction_write_mosaic(&ctx,
			"nem", "xem", 44000000));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("3409d9ece28d6296d6d5e220a7e3cb8641a3fb235ffcbd20c95da64f003ace6c"), sizeof(hash));

	// http://chain.nem.ninja/#/transfer/e90e98614c7598fbfa4db5411db1b331d157c2f86b558fb7c943d013ed9f71cb

	nem_transaction_start(&ctx, fromhex("8d07f90fb4bbe7715fa327c926770166a11be2e494a970605f2e12557f66c9b9"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_transfer(&ctx,
			NEM_NETWORK_MAINNET, 0, NULL, 0, 0,
			"NBT3WHA2YXG2IR4PWKFFMO772JWOITTD2V4PECSB", 5175000000000,
			(uint8_t *) "Good luck!", 10, false,
			0));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("e90e98614c7598fbfa4db5411db1b331d157c2f86b558fb7c943d013ed9f71cb"), sizeof(hash));

	// http://chain.nem.ninja/#/transfer/40e89160e6f83d37f7c82defc0afe2c1605ae8c919134570a51dd27ea1bb516c

	nem_transaction_start(&ctx, fromhex("f85ab43dad059b9d2331ddacc384ad925d3467f03207182e01296bacfb242d01"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_transfer(&ctx,
			NEM_NETWORK_MAINNET, 77229, NULL, 30000000, 80829,
			"NALICEPFLZQRZGPRIJTMJOCPWDNECXTNNG7QLSG3", 30000000,
			fromhex("4d9dcf9186967d30be93d6d5404ded22812dbbae7c3f0de5"
				"01bcd7228cba45bded13000eec7b4c6215fc4d3588168c92"
				"18167cec98e6977359153a4132e050f594548e61e0dc61c1"
				"53f0f53c5e65c595239c9eb7c4e7d48e0f4bb8b1dd2f5ddc"), 96, true,
			0));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("40e89160e6f83d37f7c82defc0afe2c1605ae8c919134570a51dd27ea1bb516c"), sizeof(hash));

	// http://chain.nem.ninja/#/transfer/882dca18dcbe075e15e0ec5a1d7e6ccd69cc0f1309ffd3fde227bfbc107b3f6e

	nem_transaction_start(&ctx, fromhex("f85ab43dad059b9d2331ddacc384ad925d3467f03207182e01296bacfb242d01"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_transfer(&ctx,
			NEM_NETWORK_MAINNET, 26730750, NULL, 179500000, 26734350,
			"NBE223WPKEBHQPCYUC4U4CDUQCRRFMPZLOQLB5OP", 1000000,
			(uint8_t *) "enjoy! :)", 9, false,
			1));

	ck_assert(nem_transaction_write_mosaic(&ctx,
			"imre.g", "tokens", 1));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("882dca18dcbe075e15e0ec5a1d7e6ccd69cc0f1309ffd3fde227bfbc107b3f6e"), sizeof(hash));
}
END_TEST

START_TEST(test_nem_transaction_multisig)
{
	nem_transaction_ctx ctx, other_trans;

	uint8_t buffer[1024], inner[1024];
	const uint8_t *signature;

	// http://bob.nem.ninja:8765/#/multisig/7d3a7087023ee29005262016706818579a2b5499eb9ca76bad98c1e6f4c46642

	nem_transaction_start(&other_trans, fromhex("abac2ee3d4aaa7a3bfb65261a00cc04c761521527dd3f2cf741e2815cbba83ac"), inner, sizeof(inner));

	ck_assert(nem_transaction_create_aggregate_modification(&other_trans,
			NEM_NETWORK_TESTNET, 3939039, NULL, 16000000, 3960639,
			1, false));

	ck_assert(nem_transaction_write_cosignatory_modification(&other_trans, 2, fromhex("e6cff9b3725a91f31089c3acca0fac3e341c00b1c8c6e9578f66c4514509c3b3")));

	nem_transaction_start(&ctx, fromhex("59d89076964742ef2a2089d26a5aa1d2c7a7bb052a46c1de159891e91ad3d76e"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_multisig(&ctx,
			NEM_NETWORK_TESTNET, 3939039, NULL, 6000000, 3960639,
			&other_trans));

	signature = fromhex("933930a8828b560168bddb3137df9252048678d829aa5135fa27bb306ff6562efb92755462988b852b0314bde058487d00e47816b6fb7df6bcfd7e1f150d1d00");
	ck_assert_int_eq(ed25519_sign_open_keccak(ctx.buffer, ctx.offset, ctx.public_key, signature), 0);

	nem_transaction_start(&ctx, fromhex("71cba4f2a28fd19f902ba40e9937994154d9eeaad0631d25d525ec37922567d4"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_multisig_signature(&ctx,
			NEM_NETWORK_TESTNET, 3939891, NULL, 6000000, 3961491,
			&other_trans));

	signature = fromhex("a849f13bfeeba808a8a4a79d579febe584d831a3a6ad03da3b9d008530b3d7a79fcf7156121cd7ee847029d94af7ea7a683ca8e643dc5e5f489557c2054b830b");
	ck_assert_int_eq(ed25519_sign_open_keccak(ctx.buffer, ctx.offset, ctx.public_key, signature), 0);

	// http://chain.nem.ninja/#/multisig/1016cf3bdd61bd57b9b2b07b6ff2dee390279d8d899265bdc23d42360abe2e6c

	nem_transaction_start(&other_trans, fromhex("a1df5306355766bd2f9a64efdc089eb294be265987b3359093ae474c051d7d5a"), inner, sizeof(inner));

	ck_assert(nem_transaction_create_provision_namespace(&other_trans,
			NEM_NETWORK_MAINNET, 59414272, NULL, 20000000, 59500672,
			"dim", NULL,
			"NAMESPACEWH4MKFMBCVFERDPOOP4FK7MTBXDPZZA", 5000000000));

	nem_transaction_start(&ctx, fromhex("cfe58463f0eaebceb5d00717f8aead49171a5d7c08f6b1299bd534f11715acc9"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_multisig(&ctx,
			NEM_NETWORK_MAINNET, 59414272, NULL, 6000000, 59500672,
			&other_trans));

	signature = fromhex("52a876a37511068fe214bd710b2284823921ec7318c01e083419a062eae5369c9c11c3abfdb590f65c717fab82873431d52be62e10338cb5656d1833bbdac70c");
	ck_assert_int_eq(ed25519_sign_open_keccak(ctx.buffer, ctx.offset, ctx.public_key, signature), 0);

	nem_transaction_start(&ctx, fromhex("1b49b80203007117d034e45234ffcdf402c044aeef6dbb06351f346ca892bce2"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_multisig_signature(&ctx,
			NEM_NETWORK_MAINNET, 59414342, NULL, 6000000, 59500742,
			&other_trans));

	signature = fromhex("b9a59239e5d06992c28840034ff7a7f13da9c4e6f4a6f72c1b1806c3b602f83a7d727a345371f5d15abf958208a32359c6dd77bde92273ada8ea6fda3dc76b00");
	ck_assert_int_eq(ed25519_sign_open_keccak(ctx.buffer, ctx.offset, ctx.public_key, signature), 0);

	nem_transaction_start(&ctx, fromhex("7ba4b39209f1b9846b098fe43f74381e43cb2882ccde780f558a63355840aa87"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_multisig_signature(&ctx,
			NEM_NETWORK_MAINNET, 59414381, NULL, 6000000, 59500781,
			&other_trans));

	signature = fromhex("e874ae9f069f0538008631d2df9f2e8a59944ff182e8672f743d2700fb99224aafb7a0ab09c4e9ea39ee7c8ca04a8a3d6103ae1122d87772e871761d4f00ca01");
	ck_assert_int_eq(ed25519_sign_open_keccak(ctx.buffer, ctx.offset, ctx.public_key, signature), 0);
}
END_TEST

START_TEST(test_nem_transaction_provision_namespace)
{
	nem_transaction_ctx ctx;

	uint8_t buffer[1024], hash[SHA3_256_DIGEST_LENGTH];

	// http://bob.nem.ninja:8765/#/namespace/f7cab28da57204d01a907c697836577a4ae755e6c9bac60dcc318494a22debb3

	nem_transaction_start(&ctx, fromhex("84afa1bbc993b7f5536344914dde86141e61f8cbecaf8c9cefc07391f3287cf5"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_provision_namespace(&ctx,
			NEM_NETWORK_TESTNET, 56999445, NULL, 20000000, 57003045,
			"gimre", NULL,
			"TAMESPACEWH4MKFMBCVFERDPOOP4FK7MTDJEYP35", 5000000000));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("f7cab28da57204d01a907c697836577a4ae755e6c9bac60dcc318494a22debb3"), sizeof(hash));

	// http://bob.nem.ninja:8765/#/namespace/7ddd5fe607e1bfb5606e0ac576024c318c8300d237273117d4db32a60c49524d

	nem_transaction_start(&ctx, fromhex("244fa194e2509ac0d2fbc18779c2618d8c2ebb61c16a3bcbebcf448c661ba8dc"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_provision_namespace(&ctx,
			NEM_NETWORK_TESTNET, 21496797, NULL, 108000000, 21500397,
			"misc", "alice",
			"TAMESPACEWH4MKFMBCVFERDPOOP4FK7MTDJEYP35", 5000000000));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("7ddd5fe607e1bfb5606e0ac576024c318c8300d237273117d4db32a60c49524d"), sizeof(hash));

	// http://chain.nem.ninja/#/namespace/57071aad93ca125dc231dc02c07ad8610cd243d35068f9b36a7d231383907569

	nem_transaction_start(&ctx, fromhex("9f3c14f304309c8b72b2821339c4428793b1518bea72d58dd01f19d523518614"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_provision_namespace(&ctx,
			NEM_NETWORK_MAINNET, 26699717, NULL, 108000000, 26703317,
			"sex", NULL,
			"NAMESPACEWH4MKFMBCVFERDPOOP4FK7MTBXDPZZA", 50000000000));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("57071aad93ca125dc231dc02c07ad8610cd243d35068f9b36a7d231383907569"), sizeof(hash));
}
END_TEST

START_TEST(test_nem_transaction_mosaic_creation)
{
	nem_transaction_ctx ctx;

	uint8_t buffer[1024], hash[SHA3_256_DIGEST_LENGTH];

	// http://bob.nem.ninja:8765/#/mosaic/68364353c29105e6d361ad1a42abbccbf419cfc7adb8b74c8f35d8f8bdaca3fa/0

	nem_transaction_start(&ctx, fromhex("994793ba1c789fa9bdea918afc9b06e2d0309beb1081ac5b6952991e4defd324"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_mosaic_creation(&ctx,
			NEM_NETWORK_TESTNET, 14070896, NULL, 108000000, 14074496,
			"gimre.games.pong", "paddles",
			"Paddles for the bong game.\n",
			0, 10000, true, true,
			0, 0, NULL, NULL, NULL,
			"TBMOSAICOD4F54EE5CDMR23CCBGOAM2XSJBR5OLC", 50000000000));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("68364353c29105e6d361ad1a42abbccbf419cfc7adb8b74c8f35d8f8bdaca3fa"), sizeof(hash));

	// http://bob.nem.ninja:8765/#/mosaic/b2f4a98113ff1f3a8f1e9d7197aa982545297fe0aa3fa6094af8031569953a55/0

	nem_transaction_start(&ctx, fromhex("244fa194e2509ac0d2fbc18779c2618d8c2ebb61c16a3bcbebcf448c661ba8dc"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_mosaic_creation(&ctx,
			NEM_NETWORK_TESTNET, 21497248, NULL, 108000000, 21500848,
			"alice.misc", "bar",
			"Special offer: get one bar extra by bying one foo!",
			0, 1000, false, true,
			1, 1, "TALICE2GMA34CXHD7XLJQ536NM5UNKQHTORNNT2J", "nem", "xem",
			"TBMOSAICOD4F54EE5CDMR23CCBGOAM2XSJBR5OLC", 50000000000));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("b2f4a98113ff1f3a8f1e9d7197aa982545297fe0aa3fa6094af8031569953a55"), sizeof(hash));

	// http://chain.nem.ninja/#/mosaic/269c6fda657aba3053a0e5b138c075808cc20e244e1182d9b730798b60a1f77b/0

	nem_transaction_start(&ctx, fromhex("58956ac77951622dc5f1c938affbf017c458e30e6b21ddb5783d38b302531f23"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_mosaic_creation(&ctx,
			NEM_NETWORK_MAINNET, 26729938, NULL, 108000000, 26733538,
			"jabo38", "red_token",
			"This token is to celebrate the release of Namespaces and Mosaics on the NEM system. "
			"This token was the fist ever mosaic created other than nem.xem. "
			"There are only 10,000 Red Tokens that will ever be created. "
			"It has no levy and can be traded freely among third parties.",
			2, 10000, false, true,
			0, 0, NULL, NULL, NULL,
			"NBMOSAICOD4F54EE5CDMR23CCBGOAM2XSIUX6TRS", 50000000000));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("269c6fda657aba3053a0e5b138c075808cc20e244e1182d9b730798b60a1f77b"), sizeof(hash));

	// http://chain.nem.ninja/#/mosaic/e8dc14821dbea4831d9051f86158ef348001447968fc22c01644fdaf2bda75c6/0

	nem_transaction_start(&ctx, fromhex("a1df5306355766bd2f9a64efdc089eb294be265987b3359093ae474c051d7d5a"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_mosaic_creation(&ctx,
			NEM_NETWORK_MAINNET, 69251020, NULL, 20000000, 69337420,
			"dim", "coin",
			"DIM COIN",
			6, 9000000000, false, true,
			2, 10, "NCGGLVO2G3CUACVI5GNX2KRBJSQCN4RDL2ZWJ4DP", "dim", "coin",
			"NBMOSAICOD4F54EE5CDMR23CCBGOAM2XSIUX6TRS", 500000000));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("e8dc14821dbea4831d9051f86158ef348001447968fc22c01644fdaf2bda75c6"), sizeof(hash));
}
END_TEST

START_TEST(test_nem_transaction_mosaic_supply_change)
{
	nem_transaction_ctx ctx;

	uint8_t buffer[1024], hash[SHA3_256_DIGEST_LENGTH];

	// http://bigalice2.nem.ninja:7890/transaction/get?hash=33a50fdd4a54913643a580b2af08b9a5b51b7cee922bde380e84c573a7969c50

	nem_transaction_start(&ctx, fromhex("994793ba1c789fa9bdea918afc9b06e2d0309beb1081ac5b6952991e4defd324"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_mosaic_supply_change(&ctx,
			NEM_NETWORK_TESTNET, 14071648, NULL, 108000000, 14075248,
			"gimre.games.pong", "paddles",
			1, 1234));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("33a50fdd4a54913643a580b2af08b9a5b51b7cee922bde380e84c573a7969c50"), sizeof(hash));

	// http://bigalice2.nem.ninja:7890/transaction/get?hash=1ce8e8894d077a66ff22294b000825d090a60742ec407efd80eb8b19657704f2

	nem_transaction_start(&ctx, fromhex("84afa1bbc993b7f5536344914dde86141e61f8cbecaf8c9cefc07391f3287cf5"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_mosaic_supply_change(&ctx,
			NEM_NETWORK_TESTNET, 14126909, NULL, 108000000, 14130509,
			"jabo38_ltd.fuzzy_kittens_cafe", "coupons",
			2, 1));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("1ce8e8894d077a66ff22294b000825d090a60742ec407efd80eb8b19657704f2"), sizeof(hash));

	// http://bigalice3.nem.ninja:7890/transaction/get?hash=694e493e9576d2bcf60d85747e302ac2e1cc27783187947180d4275a713ff1ff

	nem_transaction_start(&ctx, fromhex("b7ccc27b21ba6cf5c699a8dc86ba6ba98950442597ff9fa30e0abe0f5f4dd05d"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_mosaic_supply_change(&ctx,
			NEM_NETWORK_MAINNET, 53377685, NULL, 20000000, 53464085,
			"abvapp", "abv",
			1, 9000000));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("694e493e9576d2bcf60d85747e302ac2e1cc27783187947180d4275a713ff1ff"), sizeof(hash));

	// http://bigalice3.nem.ninja:7890/transaction/get?hash=09836334e123970e068d5b411e4d1df54a3ead10acf1ad5935a2cdd9f9680185

	nem_transaction_start(&ctx, fromhex("75f001a8641e2ce5c4386883dda561399ed346177411b492a677b73899502f13"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_mosaic_supply_change(&ctx,
			NEM_NETWORK_MAINNET, 55176304, NULL, 20000000, 55262704,
			"sushi", "wasabi",
			2, 20));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("09836334e123970e068d5b411e4d1df54a3ead10acf1ad5935a2cdd9f9680185"), sizeof(hash));
}
END_TEST

START_TEST(test_nem_transaction_aggregate_modification)
{
	nem_transaction_ctx ctx;

	uint8_t buffer[1024], hash[SHA3_256_DIGEST_LENGTH];

	// http://bob.nem.ninja:8765/#/aggregate/6a55471b17159e5b6cd579c421e95a4e39d92e3f78b0a55ee337e785a601d3a2

	nem_transaction_start(&ctx, fromhex("462ee976890916e54fa825d26bdd0235f5eb5b6a143c199ab0ae5ee9328e08ce"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_aggregate_modification(&ctx,
			NEM_NETWORK_TESTNET, 0, NULL, 22000000, 0,
			2, false));

	ck_assert(nem_transaction_write_cosignatory_modification(&ctx, 1, fromhex("994793ba1c789fa9bdea918afc9b06e2d0309beb1081ac5b6952991e4defd324")));
	ck_assert(nem_transaction_write_cosignatory_modification(&ctx, 1, fromhex("c54d6e33ed1446eedd7f7a80a588dd01857f723687a09200c1917d5524752f8b")));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("6a55471b17159e5b6cd579c421e95a4e39d92e3f78b0a55ee337e785a601d3a2"), sizeof(hash));

	// http://bob.nem.ninja:8765/#/aggregate/1fbdae5ba753e68af270930413ae90f671eb8ab58988116684bac0abd5726584

	nem_transaction_start(&ctx, fromhex("6bf7849c1eec6a2002995cc457dc00c4e29bad5c88de63f51e42dfdcd7b2131d"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_aggregate_modification(&ctx,
			NEM_NETWORK_TESTNET, 6542254, NULL, 40000000, 6545854,
			4, true));

	ck_assert(nem_transaction_write_cosignatory_modification(&ctx, 1, fromhex("5f53d076c8c3ec3110b98364bc423092c3ec2be2b1b3c40fd8ab68d54fa39295")));
	ck_assert(nem_transaction_write_cosignatory_modification(&ctx, 1, fromhex("9eb199c2b4d406f64cb7aa5b2b0815264b56ba8fe44d558a6cb423a31a33c4c2")));
	ck_assert(nem_transaction_write_cosignatory_modification(&ctx, 1, fromhex("94b2323dab23a3faba24fa6ddda0ece4fbb06acfedd74e76ad9fae38d006882b")));
	ck_assert(nem_transaction_write_cosignatory_modification(&ctx, 1, fromhex("d88c6ee2a2cd3929d0d76b6b14ecb549d21296ab196a2b3a4cb2536bcce32e87")));

	ck_assert(nem_transaction_write_minimum_cosignatories(&ctx, 2));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("1fbdae5ba753e68af270930413ae90f671eb8ab58988116684bac0abd5726584"), sizeof(hash));

	// http://chain.nem.ninja/#/aggregate/cc64ca69bfa95db2ff7ac1e21fe6d27ece189c603200ebc9778d8bb80ca25c3c

	nem_transaction_start(&ctx, fromhex("f41b99320549741c5cce42d9e4bb836d98c50ed5415d0c3c2912d1bb50e6a0e5"), buffer, sizeof(buffer));

	ck_assert(nem_transaction_create_aggregate_modification(&ctx,
			NEM_NETWORK_MAINNET, 0, NULL, 40000000, 0,
			5, false));

	ck_assert(nem_transaction_write_cosignatory_modification(&ctx, 1, fromhex("1fbdbdde28daf828245e4533765726f0b7790e0b7146e2ce205df3e86366980b")));
	ck_assert(nem_transaction_write_cosignatory_modification(&ctx, 1, fromhex("f94e8702eb1943b23570b1b83be1b81536df35538978820e98bfce8f999e2d37")));
	ck_assert(nem_transaction_write_cosignatory_modification(&ctx, 1, fromhex("826cedee421ff66e708858c17815fcd831a4bb68e3d8956299334e9e24380ba8")));
	ck_assert(nem_transaction_write_cosignatory_modification(&ctx, 1, fromhex("719862cd7d0f4e875a6a0274c9a1738f38f40ad9944179006a54c34724c1274d")));
	ck_assert(nem_transaction_write_cosignatory_modification(&ctx, 1, fromhex("43aa69177018fc3e2bdbeb259c81cddf24be50eef9c5386db51d82386c41475a")));

	keccak_256(ctx.buffer, ctx.offset, hash);
	ck_assert_mem_eq(hash, fromhex("cc64ca69bfa95db2ff7ac1e21fe6d27ece189c603200ebc9778d8bb80ca25c3c"), sizeof(hash));
}
END_TEST

START_TEST(test_multibyte_address)
{
	uint8_t priv_key[32];
	char wif[57];
	uint8_t pub_key[33];
	char address[40];
	uint8_t decode[24];
	int res;

	memcpy(priv_key, fromhex("47f7616ea6f9b923076625b4488115de1ef1187f760e65f89eb6f4f7ff04b012"), 32);
	ecdsa_get_wif(priv_key, 0, HASHER_SHA2D, wif, sizeof(wif)); ck_assert_str_eq(wif, "13QtoXmbhELWcrwD9YA9KzvXy5rTaptiNuFR8L8ArpBNn4xmQj4N");
	ecdsa_get_wif(priv_key, 0x12, HASHER_SHA2D, wif, sizeof(wif)); ck_assert_str_eq(wif, "3hrF6SFnqzpzABB36uGDf8dJSuUCcMmoJrTmCWMshRkBr2Vx86qJ");
	ecdsa_get_wif(priv_key, 0x1234, HASHER_SHA2D, wif, sizeof(wif)); ck_assert_str_eq(wif, "CtPTF9awbVbfDWGepGdVhB3nBhr4HktUGya8nf8dLxgC8tbqBreB9");
	ecdsa_get_wif(priv_key, 0x123456, HASHER_SHA2D, wif, sizeof(wif)); ck_assert_str_eq(wif, "uTrDevVQt5QZgoL3iJ1cPWHaCz7ZMBncM7QXZfCegtxiMHqBvWoYJa");
	ecdsa_get_wif(priv_key, 0x12345678, HASHER_SHA2D, wif, sizeof(wif)); ck_assert_str_eq(wif, "4zZWMzv1SVbs95pmLXWrXJVp9ntPEam1mfwb6CXBLn9MpWNxLg9huYgv");
	ecdsa_get_wif(priv_key, 0xffffffff, HASHER_SHA2D, wif, sizeof(wif)); ck_assert_str_eq(wif, "y9KVfV1RJXcTxpVjeuh6WYWh8tMwnAUeyUwDEiRviYdrJ61njTmnfUjE");

	memcpy(pub_key, fromhex("0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71"), 33);
	ecdsa_get_address(pub_key, 0, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8");
	ecdsa_get_address(pub_key, 0x12, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "8SCrMR2yYF7ciqoDbav7VLLTsVx5dTVPPq");
	ecdsa_get_address(pub_key, 0x1234, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "ZLH8q1UgMPg8o2s1MD55YVMpPV7vqms9kiV");
	ecdsa_get_address(pub_key, 0x123456, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "3ThqvsQVFnbiF66NwHtfe2j6AKn75DpLKpQSq");
	ecdsa_get_address(pub_key, 0x12345678, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "BrsGxAHga3VbopvSnb3gmLvMBhJNCGuDxBZL44");
	ecdsa_get_address(pub_key, 0xffffffff, HASHER_SHA2, HASHER_SHA2D, address, sizeof(address)); ck_assert_str_eq(address, "3diW7paWGJyZRLGqMJZ55DMfPExob8QxQHkrfYT");

	res = ecdsa_address_decode("1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8", 0, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(decode, fromhex("0079fbfc3f34e7745860d76137da68f362380c606c"), 21);
	res = ecdsa_address_decode("8SCrMR2yYF7ciqoDbav7VLLTsVx5dTVPPq", 0x12, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(decode, fromhex("1279fbfc3f34e7745860d76137da68f362380c606c"), 21);
	res = ecdsa_address_decode("ZLH8q1UgMPg8o2s1MD55YVMpPV7vqms9kiV", 0x1234, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(decode, fromhex("123479fbfc3f34e7745860d76137da68f362380c606c"), 21);
	res = ecdsa_address_decode("3ThqvsQVFnbiF66NwHtfe2j6AKn75DpLKpQSq", 0x123456, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(decode, fromhex("12345679fbfc3f34e7745860d76137da68f362380c606c"), 21);
	res = ecdsa_address_decode("BrsGxAHga3VbopvSnb3gmLvMBhJNCGuDxBZL44", 0x12345678, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(decode, fromhex("1234567879fbfc3f34e7745860d76137da68f362380c606c"), 21);
	res = ecdsa_address_decode("3diW7paWGJyZRLGqMJZ55DMfPExob8QxQHkrfYT", 0xffffffff, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 1);
	ck_assert_mem_eq(decode, fromhex("ffffffff79fbfc3f34e7745860d76137da68f362380c606c"), 21);

	// wrong length
	res = ecdsa_address_decode("BrsGxAHga3VbopvSnb3gmLvMBhJNCGuDxBZL44", 0x123456, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 0);

	// wrong address prefix
	res = ecdsa_address_decode("BrsGxAHga3VbopvSnb3gmLvMBhJNCGuDxBZL44", 0x22345678, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 0);

	// wrong checksum
	res = ecdsa_address_decode("BrsGxAHga3VbopvSnb3gmLvMBhJNCGuDxBZL45", 0x12345678, HASHER_SHA2D, decode);
	ck_assert_int_eq(res, 0);
}
END_TEST

// https://tools.ietf.org/html/rfc6229#section-2
START_TEST(test_rc4_rfc6229)
{
	static const size_t offsets[] = {
		  0x0,
		 0xf0,
		0x1f0,
		0x2f0,
		0x3f0,
		0x5f0,
		0x7f0,
		0xbf0,
		0xff0,
	};

	static const struct {
		char key[65];
		char vectors[sizeof(offsets) / sizeof(*offsets)][65];
	} tests[] = {
		{
			"0102030405",
			{
				"b2396305f03dc027ccc3524a0a1118a8" "6982944f18fc82d589c403a47a0d0919",
				"28cb1132c96ce286421dcaadb8b69eae" "1cfcf62b03eddb641d77dfcf7f8d8c93",
				"42b7d0cdd918a8a33dd51781c81f4041" "6459844432a7da923cfb3eb4980661f6",
				"ec10327bde2beefd18f9277680457e22" "eb62638d4f0ba1fe9fca20e05bf8ff2b",
				"45129048e6a0ed0b56b490338f078da5" "30abbcc7c20b01609f23ee2d5f6bb7df",
				"3294f744d8f9790507e70f62e5bbceea" "d8729db41882259bee4f825325f5a130",
				"1eb14a0c13b3bf47fa2a0ba93ad45b8b" "cc582f8ba9f265e2b1be9112e975d2d7",
				"f2e30f9bd102ecbf75aaade9bc35c43c" "ec0e11c479dc329dc8da7968fe965681",
				"068326a2118416d21f9d04b2cd1ca050" "ff25b58995996707e51fbdf08b34d875",
			}
		}, {
			"01020304050607",
			{
				"293f02d47f37c9b633f2af5285feb46b" "e620f1390d19bd84e2e0fd752031afc1",
				"914f02531c9218810df60f67e338154c" "d0fdb583073ce85ab83917740ec011d5",
				"75f81411e871cffa70b90c74c592e454" "0bb87202938dad609e87a5a1b079e5e4",
				"c2911246b612e7e7b903dfeda1dad866" "32828f91502b6291368de8081de36fc2",
				"f3b9a7e3b297bf9ad804512f9063eff1" "8ecb67a9ba1f55a5a067e2b026a3676f",
				"d2aa902bd42d0d7cfd340cd45810529f" "78b272c96e42eab4c60bd914e39d06e3",
				"f4332fd31a079396ee3cee3f2a4ff049" "05459781d41fda7f30c1be7e1246c623",
				"adfd3868b8e51485d5e610017e3dd609" "ad26581c0c5be45f4cea01db2f3805d5",
				"f3172ceffc3b3d997c85ccd5af1a950c" "e74b0b9731227fd37c0ec08a47ddd8b8",
			}
		}, {
			"0102030405060708",
			{
				"97ab8a1bf0afb96132f2f67258da15a8" "8263efdb45c4a18684ef87e6b19e5b09",
				"9636ebc9841926f4f7d1f362bddf6e18" "d0a990ff2c05fef5b90373c9ff4b870a",
				"73239f1db7f41d80b643c0c52518ec63" "163b319923a6bdb4527c626126703c0f",
				"49d6c8af0f97144a87df21d91472f966" "44173a103b6616c5d5ad1cee40c863d0",
				"273c9c4b27f322e4e716ef53a47de7a4" "c6d0e7b226259fa9023490b26167ad1d",
				"1fe8986713f07c3d9ae1c163ff8cf9d3" "8369e1a965610be887fbd0c79162aafb",
				"0a0127abb44484b9fbef5abcae1b579f" "c2cdadc6402e8ee866e1f37bdb47e42c",
				"26b51ea37df8e1d6f76fc3b66a7429b3" "bc7683205d4f443dc1f29dda3315c87b",
				"d5fa5a3469d29aaaf83d23589db8c85b" "3fb46e2c8f0f068edce8cdcd7dfc5862",
			}
		}, {
			"0102030405060708090a",
			{
				"ede3b04643e586cc907dc21851709902" "03516ba78f413beb223aa5d4d2df6711",
				"3cfd6cb58ee0fdde640176ad0000044d" "48532b21fb6079c9114c0ffd9c04a1ad",
				"3e8cea98017109979084b1ef92f99d86" "e20fb49bdb337ee48b8d8dc0f4afeffe",
				"5c2521eacd7966f15e056544bea0d315" "e067a7031931a246a6c3875d2f678acb",
				"a64f70af88ae56b6f87581c0e23e6b08" "f449031de312814ec6f319291f4a0516",
				"bdae85924b3cb1d0a2e33a30c6d79599" "8a0feddbac865a09bcd127fb562ed60a",
				"b55a0a5b51a12a8be34899c3e047511a" "d9a09cea3ce75fe39698070317a71339",
				"552225ed1177f44584ac8cfa6c4eb5fc" "7e82cbabfc95381b080998442129c2f8",
				"1f135ed14ce60a91369d2322bef25e3c" "08b6be45124a43e2eb77953f84dc8553",
			}
		}, {
			"0102030405060708090a0b0c0d0e0f10",
			{
				"9ac7cc9a609d1ef7b2932899cde41b97" "5248c4959014126a6e8a84f11d1a9e1c",
				"065902e4b620f6cc36c8589f66432f2b" "d39d566bc6bce3010768151549f3873f",
				"b6d1e6c4a5e4771cad79538df295fb11" "c68c1d5c559a974123df1dbc52a43b89",
				"c5ecf88de897fd57fed301701b82a259" "eccbe13de1fcc91c11a0b26c0bc8fa4d",
				"e7a72574f8782ae26aabcf9ebcd66065" "bdf0324e6083dcc6d3cedd3ca8c53c16",
				"b40110c4190b5622a96116b0017ed297" "ffa0b514647ec04f6306b892ae661181",
				"d03d1bc03cd33d70dff9fa5d71963ebd" "8a44126411eaa78bd51e8d87a8879bf5",
				"fabeb76028ade2d0e48722e46c4615a3" "c05d88abd50357f935a63c59ee537623",
				"ff38265c1642c1abe8d3c2fe5e572bf8" "a36a4c301ae8ac13610ccbc12256cacc",
			}
		}, {
			"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			{
				"eaa6bd25880bf93d3f5d1e4ca2611d91" "cfa45c9f7e714b54bdfa80027cb14380",
				"114ae344ded71b35f2e60febad727fd8" "02e1e7056b0f623900496422943e97b6",
				"91cb93c787964e10d9527d999c6f936b" "49b18b42f8e8367cbeb5ef104ba1c7cd",
				"87084b3ba700bade955610672745b374" "e7a7b9e9ec540d5ff43bdb12792d1b35",
				"c799b596738f6b018c76c74b1759bd90" "7fec5bfd9f9b89ce6548309092d7e958",
				"40f250b26d1f096a4afd4c340a588815" "3e34135c79db010200767651cf263073",
				"f656abccf88dd827027b2ce917d464ec" "18b62503bfbc077fbabb98f20d98ab34",
				"8aed95ee5b0dcbfbef4eb21d3a3f52f9" "625a1ab00ee39a5327346bddb01a9c18",
				"a13a7c79c7e119b5ab0296ab28c300b9" "f3e4c0a2e02d1d01f7f0a74618af2b48",
			}
		}, {
			"833222772a",
			{
				"80ad97bdc973df8a2e879e92a497efda" "20f060c2f2e5126501d3d4fea10d5fc0",
				"faa148e99046181fec6b2085f3b20ed9" "f0daf5bab3d596839857846f73fbfe5a",
				"1c7e2fc4639232fe297584b296996bc8" "3db9b249406cc8edffac55ccd322ba12",
				"e4f9f7e0066154bbd125b745569bc897" "75d5ef262b44c41a9cf63ae14568e1b9",
				"6da453dbf81e82334a3d8866cb50a1e3" "7828d074119cab5c22b294d7a9bfa0bb",
				"adb89cea9a15fbe617295bd04b8ca05c" "6251d87fd4aaae9a7e4ad5c217d3f300",
				"e7119bd6dd9b22afe8f89585432881e2" "785b60fd7ec4e9fcb6545f350d660fab",
				"afecc037fdb7b0838eb3d70bcd268382" "dbc1a7b49d57358cc9fa6d61d73b7cf0",
				"6349d126a37afcba89794f9804914fdc" "bf42c3018c2f7c66bfde524975768115",
			}
		}, {
			"1910833222772a",
			{
				"bc9222dbd3274d8fc66d14ccbda6690b" "7ae627410c9a2be693df5bb7485a63e3",
				"3f0931aa03defb300f060103826f2a64" "beaa9ec8d59bb68129f3027c96361181",
				"74e04db46d28648d7dee8a0064b06cfe" "9b5e81c62fe023c55be42f87bbf932b8",
				"ce178fc1826efecbc182f57999a46140" "8bdf55cd55061c06dba6be11de4a578a",
				"626f5f4dce652501f3087d39c92cc349" "42daac6a8f9ab9a7fd137c6037825682",
				"cc03fdb79192a207312f53f5d4dc33d9" "f70f14122a1c98a3155d28b8a0a8a41d",
				"2a3a307ab2708a9c00fe0b42f9c2d6a1" "862617627d2261eab0b1246597ca0ae9",
				"55f877ce4f2e1ddbbf8e13e2cde0fdc8" "1b1556cb935f173337705fbb5d501fc1",
				"ecd0e96602be7f8d5092816cccf2c2e9" "027881fab4993a1c262024a94fff3f61",
			}
		}, {
			"641910833222772a",
			{
				"bbf609de9413172d07660cb680716926" "46101a6dab43115d6c522b4fe93604a9",
				"cbe1fff21c96f3eef61e8fe0542cbdf0" "347938bffa4009c512cfb4034b0dd1a7",
				"7867a786d00a7147904d76ddf1e520e3" "8d3e9e1caefcccb3fbf8d18f64120b32",
				"942337f8fd76f0fae8c52d7954810672" "b8548c10f51667f6e60e182fa19b30f7",
				"0211c7c6190c9efd1237c34c8f2e06c4" "bda64f65276d2aacb8f90212203a808e",
				"bd3820f732ffb53ec193e79d33e27c73" "d0168616861907d482e36cdac8cf5749",
				"97b0f0f224b2d2317114808fb03af7a0" "e59616e469787939a063ceea9af956d1",
				"c47e0dc1660919c11101208f9e69aa1f" "5ae4f12896b8379a2aad89b5b553d6b0",
				"6b6b098d0c293bc2993d80bf0518b6d9" "8170cc3ccd92a698621b939dd38fe7b9",
			}
		}, {
			"8b37641910833222772a",
			{
				"ab65c26eddb287600db2fda10d1e605c" "bb759010c29658f2c72d93a2d16d2930",
				"b901e8036ed1c383cd3c4c4dd0a6ab05" "3d25ce4922924c55f064943353d78a6c",
				"12c1aa44bbf87e75e611f69b2c38f49b" "28f2b3434b65c09877470044c6ea170d",
				"bd9ef822de5288196134cf8af7839304" "67559c23f052158470a296f725735a32",
				"8bab26fbc2c12b0f13e2ab185eabf241" "31185a6d696f0cfa9b42808b38e132a2",
				"564d3dae183c5234c8af1e51061c44b5" "3c0778a7b5f72d3c23a3135c7d67b9f4",
				"f34369890fcf16fb517dcaae4463b2dd" "02f31c81e8200731b899b028e791bfa7",
				"72da646283228c14300853701795616f" "4e0a8c6f7934a788e2265e81d6d0c8f4",
				"438dd5eafea0111b6f36b4b938da2a68" "5f6bfc73815874d97100f086979357d8",
			}
		}, {
			"ebb46227c6cc8b37641910833222772a",
			{
				"720c94b63edf44e131d950ca211a5a30" "c366fdeacf9ca80436be7c358424d20b",
				"b3394a40aabf75cba42282ef25a0059f" "4847d81da4942dbc249defc48c922b9f",
				"08128c469f275342adda202b2b58da95" "970dacef40ad98723bac5d6955b81761",
				"3cb89993b07b0ced93de13d2a11013ac" "ef2d676f1545c2c13dc680a02f4adbfe",
				"b60595514f24bc9fe522a6cad7393644" "b515a8c5011754f59003058bdb81514e",
				"3c70047e8cbc038e3b9820db601da495" "1175da6ee756de46a53e2b075660b770",
				"00a542bba02111cc2c65b38ebdba587e" "5865fdbb5b48064104e830b380f2aede",
				"34b21ad2ad44e999db2d7f0863f0d9b6" "84a9218fc36e8a5f2ccfbeae53a27d25",
				"a2221a11b833ccb498a59540f0545f4a" "5bbeb4787d59e5373fdbea6c6f75c29b",
			}
		}, {
			"c109163908ebe51debb46227c6cc8b37641910833222772a",
			{
				"54b64e6b5a20b5e2ec84593dc7989da7" "c135eee237a85465ff97dc03924f45ce",
				"cfcc922fb4a14ab45d6175aabbf2d201" "837b87e2a446ad0ef798acd02b94124f",
				"17a6dbd664926a0636b3f4c37a4f4694" "4a5f9f26aeeed4d4a25f632d305233d9",
				"80a3d01ef00c8e9a4209c17f4eeb358c" "d15e7d5ffaaabc0207bf200a117793a2",
				"349682bf588eaa52d0aa1560346aeafa" "f5854cdb76c889e3ad63354e5f7275e3",
				"532c7ceccb39df3236318405a4b1279c" "baefe6d9ceb651842260e0d1e05e3b90",
				"e82d8c6db54e3c633f581c952ba04207" "4b16e50abd381bd70900a9cd9a62cb23",
				"3682ee33bd148bd9f58656cd8f30d9fb" "1e5a0b8475045d9b20b2628624edfd9e",
				"63edd684fb826282fe528f9c0e9237bc" "e4dd2e98d6960fae0b43545456743391",
			}
		}, {
			"1ada31d5cf688221c109163908ebe51debb46227c6cc8b37641910833222772a",
			{
				"dd5bcb0018e922d494759d7c395d02d3" "c8446f8f77abf737685353eb89a1c9eb",
				"af3e30f9c095045938151575c3fb9098" "f8cb6274db99b80b1d2012a98ed48f0e",
				"25c3005a1cb85de076259839ab7198ab" "9dcbc183e8cb994b727b75be3180769c",
				"a1d3078dfa9169503ed9d4491dee4eb2" "8514a5495858096f596e4bcd66b10665",
				"5f40d59ec1b03b33738efa60b2255d31" "3477c7f764a41baceff90bf14f92b7cc",
				"ac4e95368d99b9eb78b8da8f81ffa795" "8c3c13f8c2388bb73f38576e65b7c446",
				"13c4b9c1dfb66579eddd8a280b9f7316" "ddd27820550126698efaadc64b64f66e",
				"f08f2e66d28ed143f3a237cf9de73559" "9ea36c525531b880ba124334f57b0b70",
				"d5a39e3dfcc50280bac4a6b5aa0dca7d" "370b1c1fe655916d97fd0d47ca1d72b8",
			}
		}
	};

	RC4_CTX ctx;
	uint8_t key[64];
	uint8_t buffer[0x1010];

	for (size_t i = 0; i < (sizeof(tests) / sizeof(*tests)); i++) {
		size_t length = strlen(tests[i].key) / 2;
		memcpy(key, fromhex(tests[i].key), length);
		memset(buffer, 0, sizeof(buffer));

		rc4_init(&ctx, key, length);
		rc4_encrypt(&ctx, buffer, sizeof(buffer));

		for (size_t j = 0; j < (sizeof(offsets) / sizeof(*offsets)); j++) {
			size_t size = strlen(tests[i].vectors[j]) / 2;
			ck_assert_mem_eq(&buffer[offsets[j]], fromhex(tests[i].vectors[j]), size);
		}
	}
}
END_TEST

// ----------------------------------------------------------------------------------------


START_TEST(test_ed25519_modl_add)
{
	char tests[][3][65] = {
      {"0000000000000000000000000000000000000000000000000000000000000000",
       "0000000000000000000000000000000000000000000000000000000000000000",
       "0000000000000000000000000000000000000000000000000000000000000000",
      },

      {"eef80ad5a9aad8b35b84f6a4eb3a7e2b222f403d455d8cdf40ad27e4cd5ae90a",
       "0000000000000000000000000000000000000000000000000000000000000000",
       "eef80ad5a9aad8b35b84f6a4eb3a7e2b222f403d455d8cdf40ad27e4cd5ae90a"
      },

      {"0000000000000000000000000000000000000000000000000000000000000000",
       "eef80ad5a9aad8b35b84f6a4eb3a7e2b222f403d455d8cdf40ad27e4cd5ae90a",
       "eef80ad5a9aad8b35b84f6a4eb3a7e2b222f403d455d8cdf40ad27e4cd5ae90a"
      },

      {"0100000000000000000000000000000000000000000000000000000000000000",
       "0200000000000000000000000000000000000000000000000000000000000000",
       "0300000000000000000000000000000000000000000000000000000000000000"
      },

      {"e3d3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
       "0a00000000000000000000000000000000000000000000000000000000000000",
       "0000000000000000000000000000000000000000000000000000000000000000"
      },

      {"f7bb3bf42b3e58e2edd06f173fc7bfbc7aaf657217946b75648447101136aa08",
       "3c16b013109cc27ff39805be2abe04ba4cd6a8526a1d3023047693e950936c06",
       "33d2eb073cda1a62e16975d56985c476c7850ec581b19b9868fadaf961c9160f"
      },

	};

	unsigned char buff[32];
	bignum256modm a={0}, b={0}, c={0};

	for (size_t i = 0; i < (sizeof(tests) / sizeof(*tests)); i++) {
		expand256_modm(a, fromhex(tests[i][0]), 32);
		expand256_modm(b, fromhex(tests[i][1]), 32);
		add256_modm(c, a, b);
		contract256_modm(buff, c);
		ck_assert_mem_eq(buff, fromhex(tests[i][2]), 32);
	}
}
END_TEST

START_TEST(test_ed25519_modl_neg)
{
  char tests[][2][65] = {
      {"05d0f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
       "e803000000000000000000000000000000000000000000000000000000000000"},

      {"4d4df45c1a631258d69cf7a2def9de1400000000000000000000000000000010",
       "a086010000000000000000000000000000000000000000000000000000000000"},

      {"25958944a1b7d4073975ca48996a1d740d0ed98ceec366760c5358da681e9608",
       "c83e6c1879ab3d509d272d5a458fc1a0f2f12673113c9989f3aca72597e16907"},

      {"0100000000000000000000000000000000000000000000000000000000000000",
       "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"},

      {"ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
       "0100000000000000000000000000000000000000000000000000000000000000"},

      {"0000000000000000000000000000000000000000000000000000000000000000",
       "0000000000000000000000000000000000000000000000000000000000000000"},
  };

  unsigned char buff[32];
  bignum256modm a={0}, b={0};

  for (size_t i = 0; i < (sizeof(tests) / sizeof(*tests)); i++) {
    expand256_modm(a, fromhex(tests[i][0]), 32);
    neg256_modm(b, a);
    contract256_modm((unsigned char *) buff, b);
    ck_assert_mem_eq(buff, fromhex(tests[i][1]), 32);
  }
}
END_TEST

START_TEST(test_ed25519_modl_sub)
{
  char tests[][3][65] = {
			{"0000000000000000000000000000000000000000000000000000000000000000",
			 "0000000000000000000000000000000000000000000000000000000000000000",
			 "0000000000000000000000000000000000000000000000000000000000000000",
			},

      {"eef80ad5a9aad8b35b84f6a4eb3a7e2b222f403d455d8cdf40ad27e4cd5ae90a",
       "53732f60e51ee3a48d21d2d526548c0dadbb79a185678fd7710613d0e76aad0c",
			 "8859d1d1deee0767a4ff1b72a3e0d0327573c69bbff5fc07cfa61414e6ef3b0e"
			},

      {"9d91e26dbe7a14fdca9f5b20d13e828dc8c1ffe03fe90136a6bba507436ce500",
       "9ca406705ccce65eb8cbf63706d3df09fcc67216c0dc3990270731aacbb2e607",
			 "eec0d15a7c1140f6e8705c8ba9658198ccfa8cca7f0cc8a57eb4745d77b9fe08"
			},

      {"eef80ad5a9aad8b35b84f6a4eb3a7e2b222f403d455d8cdf40ad27e4cd5ae90a",
       "0000000000000000000000000000000000000000000000000000000000000000",
			 "eef80ad5a9aad8b35b84f6a4eb3a7e2b222f403d455d8cdf40ad27e4cd5ae90a"
			},

      {"0000000000000000000000000000000000000000000000000000000000000000",
       "39897fbebf137a34572b014b0638ac0186d17874e3cc142ebdfe24327f5b8509",
			 "b44a769e5a4f98237f71f657d8c132137a2e878b1c33ebd14201dbcd80a47a06"
			},

      {"0200000000000000000000000000000000000000000000000000000000000000",
       "e3d3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
			 "0c00000000000000000000000000000000000000000000000000000000000000"
			},

      {"e3d3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
       "0800000000000000000000000000000000000000000000000000000000000000",
			 "dbd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
			},

      {"ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
       "0000000000000000000000000000000000000000000000000000000000000000",
			 "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
			},

      {"0000000000000000000000000000000000000000000000000000000000000000",
       "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
			 "0100000000000000000000000000000000000000000000000000000000000000"
			},

      {"0000000000000000000000000000000000000000000000000000000000000000",
       "0000000000000000000000000000000000000000000000000000000000000010",
			 "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000000"
			},

      {"0000000000000000000000000000000000000000000000000000000000000000",
       "ffffff3f00000000000000000000000000000000000000000000000000000010",
			 "eed3f51c1a631258d69cf7a2def9de1400000000000000000000000000000000"
			},

      {"0000000000000000000000000000000000000000000000000000000000000000",
       "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000000",
			 "0000000000000000000000000000000000000000000000000000000000000010"
			},

      {"0000000000000000000000000000000000000000000000000000000000000000",
       "e75f947f11d49d25a137fac8757538a980dec23811235cf63c48ee6bc6e4ed03",
			 "067461dd088f74323565fdd96884a66b7f213dc7eedca309c3b71194391b120c"
			},

      {"0000000000000000000000000000000000000000000000000000000000000000",
       "ecd3f55c1a631258d69cf7a2def9de140000000000000000000000000000ff0f",
			 "0100000000000000000000000000000000000000000000000000000000000100"
			},

      {"0000000000000000000000000000000000000000000000000000000000000000",
       "edd3f55c1a631258d69cf7a2def9de140000000000000000000004000000ff0f",
			 "0000000000000000000000000000000000000000000000000000fcffffff0000"
			},

      {"0000000000000000000000000000000000000000000000000000000000000000",
       "edd3f55c1a631258d69cf7a2def9de150000c0ffffffffffffffffffffffff0f",
			 "000000000000000000000000000000ffffff3f00000000000000000000000000"
			},

      {"0000000000000000000000000000000000000000000000000000000000000000",
       "edd3f55c1a631258d69cf7a2def9de1200000000000000000000000000000110",
			 "edd3f55c1a631258d69cf7a2def9de160000000000000000000000000000ff0f"
			},

      {"0000000000000000000000000000000000000000000000000000000000000000",
       "edd3f55c1a631258d69cf7a2def9de1300000000000000000000000000000010",
			 "0000000000000000000000000000000100000000000000000000000000000000"
			},

  };

  unsigned char buff[32];
  bignum256modm a={0}, b={0}, c={0};

  for (size_t i = 0; i < (sizeof(tests) / sizeof(*tests)); i++) {
		expand256_modm(a, fromhex(tests[i][0]), 32);
		expand256_modm(b, fromhex(tests[i][1]), 32);
		sub256_modm(c, a, b);
		contract256_modm(buff, c);
		ck_assert_mem_eq(buff, fromhex(tests[i][2]), 32);
  }
}
END_TEST


START_TEST(test_xmr_base58)
{
  static const struct {
    uint64_t tag;
    char * v1;
    char * v2;
  } tests[] = {
      {0x12,
          "3bec484c5d7f0246af520aab550452b5b6013733feabebd681c4a60d457b7fc12d5918e31d3c003da3c778592c07b398ad6f961a67082a75fd49394d51e69bbe",
          "43tpGG9PKbwCpjRvNLn1jwXPpnacw2uVUcszAtgmDiVcZK4VgHwjJT9BJz1WGF9eMxSYASp8yNMkuLjeQfWqJn3CNWdWfzV"
      },
      {53,
          "5a10cca900ee47a7f412cd661b29f5ab356d6a1951884593bb170b5ec8b6f2e83b1da411527d062c9fedeb2dad669f2f5585a00a88462b8c95c809a630e5734c",
          "9vacMKaj8JJV6MnwDzh2oNVdwTLJfTDyNRiB6NzV9TT7fqvzLivH2dB8Tv7VYR3ncn8vCb3KdNMJzQWrPAF1otYJ9cPKpkr"
      },
  };

  uint8_t rawn[512];
  char strn[512];
  int r;
  uint64_t tag;

  for (size_t i = 0; i < (sizeof(tests) / sizeof(*tests)); i++) {
    const char *raw = tests[i].v1;
    const char *str = tests[i].v2;
    const size_t len = strlen(raw) / 2;

    memcpy(rawn, fromhex(raw), len);

    r = xmr_base58_addr_encode_check(tests[i].tag, rawn, len, strn, sizeof(strn));
    ck_assert_int_eq((size_t)r, strlen(str));
    ck_assert_mem_eq(strn, str, r);

    r = xmr_base58_addr_decode_check(strn, r, &tag, rawn, len);
    ck_assert_int_eq(r, len);
    ck_assert_mem_eq(rawn, fromhex(raw), len);
  }
}
END_TEST

START_TEST(test_xmr_hash_to_scalar)
{
	bignum256modm a1;
	unsigned char out[32];
	char * xx = "259ef2aba8feb473cf39058a0fe30b9ff6d245b42b6826687ebd6b63128aff6405";
	char * exp = "9907925b254e12162609fc0dfd0fef2aa4d605b0d10e6507cac253dd31a3ec06";
	xmr_hash_to_scalar(fromhex(xx), 33, a1);
	contract256_modm(out, a1);
	ck_assert_mem_eq(out, fromhex(exp), 32);
}
END_TEST

START_TEST(test_xmr_hash_to_ec)
{
	ge25519 p1;
	unsigned char out[32];
	char * yy = "42f6835bf83114a1f5f6076fe79bdfa0bd67c74b88f127d54572d3910dd09201";
	char * exp = "54863a0464c008acc99cffb179bc6cf34eb1bbdf6c29f7a070a7c6376ae30ab5";
	xmr_hash_to_ec(fromhex(yy), 32, &p1);
	ge25519_pack(out, &p1);
	ck_assert_mem_eq(out, fromhex(exp), 32);
}
END_TEST

void dummy(){
	
}

// define test suite and cases
Suite *test_suite(void)
{
	Suite *s = suite_create("trezor-crypto");
	TCase *tc;

	tc = tcase_create("ed25519t");
	tcase_add_test(tc, test_ed25519_modl_add);
	tcase_add_test(tc, test_ed25519_modl_neg);
	tcase_add_test(tc, test_ed25519_modl_sub);
	suite_add_tcase(s, tc);

	tc = tcase_create("xmr_base58");
	tcase_add_test(tc, test_xmr_base58);
	suite_add_tcase(s, tc);

	tc = tcase_create("xmr_crypto");
	tcase_add_test(tc, test_xmr_hash_to_scalar);
	tcase_add_test(tc, test_xmr_hash_to_ec);
	suite_add_tcase(s, tc);

	tc = tcase_create("base58");
	tcase_add_test(tc, test_base58);
	suite_add_tcase(s, tc);
//
//	tc = tcase_create("bip32-ecdh");
//	tcase_add_test(tc, test_bip32_ecdh_nist256p1);
//	tcase_add_test(tc, test_bip32_ecdh_curve25519);
//	tcase_add_test(tc, test_bip32_ecdh_errors);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("ecdsa");
//	tcase_add_test(tc, test_ecdsa_signature);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("rfc6979");
//	tcase_add_test(tc, test_rfc6979);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("address");
//	tcase_add_test(tc, test_address);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("address_decode");
//	tcase_add_test(tc, test_address_decode);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("ethereum_address");
//	tcase_add_test(tc, test_ethereum_address);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("wif");
//	tcase_add_test(tc, test_wif);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("ecdsa_der");
//	tcase_add_test(tc, test_ecdsa_der);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("sha2");
//	tcase_add_test(tc, test_sha1);
//	tcase_add_test(tc, test_sha256);
//	tcase_add_test(tc, test_sha512);
//	suite_add_tcase(s, tc);

	tc = tcase_create("sha3");
	tcase_add_test(tc, test_sha3_256);
	tcase_add_test(tc, test_sha3_512);
	tcase_add_test(tc, test_keccak_256);
	suite_add_tcase(s, tc);

//	tc = tcase_create("blake");
//	tcase_add_test(tc, test_blake256);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("blake2");
//	tcase_add_test(tc, test_blake2b);
//	tcase_add_test(tc, test_blake2s);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("pbkdf2");
//	tcase_add_test(tc, test_pbkdf2_hmac_sha256);
//	tcase_add_test(tc, test_pbkdf2_hmac_sha512);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("bip39");
//	tcase_add_test(tc, test_mnemonic);
//	tcase_add_test(tc, test_mnemonic_check);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("pubkey_validity");
//	tcase_add_test(tc, test_pubkey_validity);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("pubkey_uncompress");
//	tcase_add_test(tc, test_pubkey_uncompress);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("codepoints");
//	tcase_add_test(tc, test_codepoints_secp256k1);
//	tcase_add_test(tc, test_codepoints_nist256p1);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("mult_border_cases");
//	tcase_add_test(tc, test_mult_border_cases_secp256k1);
//	tcase_add_test(tc, test_mult_border_cases_nist256p1);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("scalar_mult");
//	tcase_add_test(tc, test_scalar_mult_secp256k1);
//	tcase_add_test(tc, test_scalar_mult_nist256p1);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("point_mult");
//	tcase_add_test(tc, test_point_mult_secp256k1);
//	tcase_add_test(tc, test_point_mult_nist256p1);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("scalar_point_mult");
//	tcase_add_test(tc, test_scalar_point_mult_secp256k1);
//	tcase_add_test(tc, test_scalar_point_mult_nist256p1);
//	suite_add_tcase(s, tc);

	tc = tcase_create("ed25519");
	tcase_add_test(tc, test_ed25519);
	suite_add_tcase(s, tc);

	tc = tcase_create("ed25519_keccak");
	tcase_add_test(tc, test_ed25519_keccak);
	suite_add_tcase(s, tc);

	tc = tcase_create("ed25519_cosi");
	tcase_add_test(tc, test_ed25519_cosi);
	suite_add_tcase(s, tc);

//	tc = tcase_create("script");
//	tcase_add_test(tc, test_output_script);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("ethereum_pubkeyhash");
//	tcase_add_test(tc, test_ethereum_pubkeyhash);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("nem_address");
//	tcase_add_test(tc, test_nem_address);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("nem_encryption");
//	tcase_add_test(tc, test_nem_derive);
//	tcase_add_test(tc, test_nem_cipher);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("nem_transaction");
//	tcase_add_test(tc, test_nem_transaction_transfer);
//	tcase_add_test(tc, test_nem_transaction_multisig);
//	tcase_add_test(tc, test_nem_transaction_provision_namespace);
//	tcase_add_test(tc, test_nem_transaction_mosaic_creation);
//	tcase_add_test(tc, test_nem_transaction_mosaic_supply_change);
//	tcase_add_test(tc, test_nem_transaction_aggregate_modification);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("multibyte_address");
//	tcase_add_test(tc, test_multibyte_address);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("rc4");
//	tcase_add_test(tc, test_rc4_rfc6229);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("segwit");
//	tcase_add_test(tc, test_segwit);
//	suite_add_tcase(s, tc);
//
//	tc = tcase_create("cashaddr");
//	tcase_add_test(tc, test_cashaddr);
//	suite_add_tcase(s, tc);

	return s;
}

// run suite
int main(void)
{
  dummy();


	int number_failed;
	Suite *s = test_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	if (number_failed == 0) {
		printf("PASSED ALL TESTS\n");
	}
	return number_failed;
}
