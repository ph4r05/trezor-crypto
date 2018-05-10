cmake_minimum_required(VERSION 3.10)
project(trezor_crypto)

set(CMAKE_CXX_STANDARD 11)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(PkgConfig REQUIRED)
pkg_check_modules(check check)

include_directories(.)
include_directories(aes)
include_directories(chacha20poly1305)
include_directories(ed25519-donna)
include_directories(gui)
include_directories(tests)
include_directories(monero)


SET(SOURCES
        aes/aes.h
        aes/aes_modes.c
        aes/aescrypt.c
        aes/aeskey.c
        aes/aesopt.h
        aes/aestab.c
        aes/aestab.h
        #aes/aestst.c
        #aes/aestst.h
        aes/brg_types.h
        chacha20poly1305/chacha20poly1305.c
        chacha20poly1305/chacha20poly1305.h
        chacha20poly1305/chacha_merged.c
        chacha20poly1305/ecrypt-config.h
        chacha20poly1305/ecrypt-machine.h
        chacha20poly1305/ecrypt-portable.h
        chacha20poly1305/ecrypt-sync.h
        chacha20poly1305/poly1305-donna-32.h
        chacha20poly1305/poly1305-donna.c
        chacha20poly1305/poly1305-donna.h
        chacha20poly1305/rfc7539.c
        chacha20poly1305/rfc7539.h
        ed25519-donna/curve25519-donna-32bit.c
        ed25519-donna/curve25519-donna-32bit.h
        ed25519-donna/curve25519-donna-helpers.c
        ed25519-donna/curve25519-donna-helpers.h
        ed25519-donna/curve25519-donna-scalarmult-base.c
        ed25519-donna/curve25519-donna-scalarmult-base.h
        ed25519-donna/ed25519-donna-32bit-tables.c
        ed25519-donna/ed25519-donna-32bit-tables.h
        ed25519-donna/ed25519-donna-basepoint-table.c
        ed25519-donna/ed25519-donna-basepoint-table.h
        ed25519-donna/ed25519-donna-impl-base.c
        ed25519-donna/ed25519-donna-impl-base.h
        ed25519-donna/ed25519-donna-portable.h
        ed25519-donna/ed25519-donna.h
        ed25519-donna/ed25519-hash-custom-keccak.h
        ed25519-donna/ed25519-hash-custom-sha3.h
        ed25519-donna/ed25519-hash-custom.h
        ed25519-donna/ed25519-keccak.c
        ed25519-donna/ed25519-keccak.h
        ed25519-donna/ed25519-sha3.c
        ed25519-donna/ed25519-sha3.h
        ed25519-donna/ed25519.c
        ed25519-donna/ed25519.h
        ed25519-donna/modm-donna-32bit.c
        ed25519-donna/modm-donna-32bit.h
        monero/int-util.h
        monero/base58
        monero/serialize
        monero/crypto
        monero/xmr
        monero/monero
        monero/range_proof
        address.c
        address.h
        base32.c
        base32.h
        base58.c
        base58.h
        bignum.c
        bignum.h
        bip32.c
        bip32.h
        bip39.c
        bip39.h
        bip39_english.h
        blake256.c
        blake256.h
        blake2_common.h
        blake2b.c
        blake2b.h
        blake2s.c
        blake2s.h
        cash_addr.c
        cash_addr.h
        check_mem.h
        curves.c
        curves.h
        ecdsa.c
        ecdsa.h
        groestl.c
        groestl.h
        groestl_internal.h
        hasher.c
        hasher.h
        hmac.c
        hmac.h
        memzero.c
        memzero.h
        nem.c
        nem.h
        nem_serialize.h
        nist256p1.c
        nist256p1.h
        options.h
        pbkdf2.c
        pbkdf2.h
        rand.c
        rand.h
        rc4.c
        rc4.h
        ripemd160.c
        ripemd160.h
        script.c
        script.h
        secp256k1.c
        secp256k1.h
        segwit_addr.c
        segwit_addr.h
        sha2.c
        sha2.h
        sha3.c
        sha3.h)


add_executable(trezor_crypto ${SOURCES} tests/test_check.c)
target_compile_options(trezor_crypto PUBLIC -DUSE_ETHEREUM=1 -DUSE_GRAPHENE=1
        -DUSE_NEM=1 -DUSE_KECCAK=1 -DUSE_MONERO=1 -DNO_VALGRIND=1
        -I/opt/local/include)
target_link_libraries(trezor_crypto ${OPENSSL_LIBRARIES} ${check_LIBRARIES})

add_executable(trezor_crypto2 ${SOURCES} tests/test_check2.c)
target_compile_options(trezor_crypto2 PUBLIC -DUSE_ETHEREUM=1 -DUSE_GRAPHENE=1
        -DUSE_NEM=1 -DUSE_KECCAK=1 -DUSE_MONERO=1 -DNO_VALGRIND=1
        -I/opt/local/include)
target_link_libraries(trezor_crypto2 ${OPENSSL_LIBRARIES} ${check_LIBRARIES})


