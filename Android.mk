LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libsodium

LOCAL_C_INCLUDES := $(LOCAL_PATH) \
	$(LOCAL_PATH)/src/libsodium/include \
	$(LOCAL_PATH)/src/libsodium/include/sodium

LOCAL_SRC_FILES := \
	src/libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c \
	src/libsodium/crypto_auth/crypto_auth.c \
	src/libsodium/crypto_auth/hmacsha256/auth_hmacsha256_api.c \
	src/libsodium/crypto_auth/hmacsha256/cp/hmac_hmacsha256.c \
	src/libsodium/crypto_auth/hmacsha256/cp/verify_hmacsha256.c \
	src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512_api.c \
	src/libsodium/crypto_auth/hmacsha512/cp/hmac_hmacsha512.c \
	src/libsodium/crypto_auth/hmacsha512/cp/verify_hmacsha512.c \
	src/libsodium/crypto_auth/hmacsha512256/auth_hmacsha512256_api.c \
	src/libsodium/crypto_auth/hmacsha512256/cp/hmac_hmacsha512256.c \
	src/libsodium/crypto_auth/hmacsha512256/cp/verify_hmacsha512256.c \
	src/libsodium/crypto_box/crypto_box.c \
	src/libsodium/crypto_box/crypto_box_easy.c \
	src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305_api.c \
	src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/after_curve25519xsalsa20poly1305.c \
	src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/before_curve25519xsalsa20poly1305.c \
	src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/box_curve25519xsalsa20poly1305.c \
	src/libsodium/crypto_box/curve25519xsalsa20poly1305/ref/keypair_curve25519xsalsa20poly1305.c \
	src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20.c \
	src/libsodium/crypto_core/hsalsa20/core_hsalsa20_api.c \
	src/libsodium/crypto_core/salsa20/ref/core_salsa20.c \
	src/libsodium/crypto_core/salsa20/core_salsa20_api.c \
	src/libsodium/crypto_generichash/crypto_generichash.c \
	src/libsodium/crypto_generichash/blake2/generichash_blake2_api.c \
	src/libsodium/crypto_generichash/blake2/ref/blake2b-ref.c \
	src/libsodium/crypto_generichash/blake2/ref/generichash_blake2b.c \
	src/libsodium/crypto_hash/crypto_hash.c \
	src/libsodium/crypto_hash/sha256/hash_sha256_api.c \
	src/libsodium/crypto_hash/sha256/cp/hash_sha256.c \
	src/libsodium/crypto_hash/sha512/hash_sha512_api.c \
	src/libsodium/crypto_hash/sha512/cp/hash_sha512.c \
	src/libsodium/crypto_onetimeauth/crypto_onetimeauth.c \
	src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c \
	src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305_api.c \
	src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305_try.c \
	src/libsodium/crypto_onetimeauth/poly1305/donna/auth_poly1305_donna.c \
	src/libsodium/crypto_onetimeauth/poly1305/donna/verify_poly1305_donna.c \
	src/libsodium/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c \
	src/libsodium/crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c \
	src/libsodium/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c \
	src/libsodium/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c \
	src/libsodium/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c \
	src/libsodium/crypto_pwhash/scryptsalsa208sha256/sse/pwhash_scryptsalsa208sha256_sse.c \
	src/libsodium/crypto_scalarmult/crypto_scalarmult.c \
	src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519_api.c \
	src/libsodium/crypto_secretbox/crypto_secretbox.c \
	src/libsodium/crypto_secretbox/crypto_secretbox_easy.c \
	src/libsodium/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305_api.c \
	src/libsodium/crypto_secretbox/xsalsa20poly1305/ref/box_xsalsa20poly1305.c \
	src/libsodium/crypto_shorthash/crypto_shorthash.c \
	src/libsodium/crypto_shorthash/siphash24/shorthash_siphash24_api.c \
	src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphash24.c \
	src/libsodium/crypto_sign/crypto_sign.c \
	src/libsodium/crypto_sign/ed25519/sign_ed25519_api.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_0.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_1.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_add.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_cmov.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_copy.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_frombytes.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_invert.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_isnegative.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_isnonzero.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_mul.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_neg.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_pow22523.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_sq.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_sq2.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_sub.c \
	src/libsodium/crypto_sign/ed25519/ref10/fe_tobytes.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_add.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_double_scalarmult.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_frombytes.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_madd.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_msub.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_p1p1_to_p2.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_p1p1_to_p3.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_p2_0.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_p2_dbl.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_p3_0.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_p3_dbl.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_p3_to_cached.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_p3_to_p2.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_p3_tobytes.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_precomp_0.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_scalarmult_base.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_sub.c \
	src/libsodium/crypto_sign/ed25519/ref10/ge_tobytes.c \
	src/libsodium/crypto_sign/ed25519/ref10/keypair.c \
	src/libsodium/crypto_sign/ed25519/ref10/open.c \
	src/libsodium/crypto_sign/ed25519/ref10/sc_muladd.c \
	src/libsodium/crypto_sign/ed25519/ref10/sc_reduce.c \
	src/libsodium/crypto_sign/ed25519/ref10/sign.c \
	src/libsodium/crypto_stream/crypto_stream.c \
	src/libsodium/crypto_stream/chacha20/stream_chacha20_api.c \
	src/libsodium/crypto_stream/chacha20/ref/stream_chacha20_ref.c \
	src/libsodium/crypto_stream/salsa20/stream_salsa20_api.c \
	src/libsodium/crypto_stream/xsalsa20/stream_xsalsa20_api.c \
	src/libsodium/crypto_stream/xsalsa20/ref/stream_xsalsa20.c \
	src/libsodium/crypto_stream/xsalsa20/ref/xor_xsalsa20.c \
	src/libsodium/crypto_verify/16/verify_16_api.c \
	src/libsodium/crypto_verify/16/ref/verify_16.c \
	src/libsodium/crypto_verify/32/verify_32_api.c \
	src/libsodium/crypto_verify/32/ref/verify_32.c \
	src/libsodium/crypto_verify/64/verify_64_api.c \
	src/libsodium/crypto_verify/64/ref/verify_64.c \
	src/libsodium/randombytes/randombytes.c \
	src/libsodium/randombytes/salsa20/randombytes_salsa20_random.c \
	src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c \
	src/libsodium/sodium/core.c \
	src/libsodium/sodium/runtime.c \
	src/libsodium/sodium/utils.c \
	src/libsodium/sodium/version.c \
	src/libsodium/crypto_scalarmult/curve25519/ref10/base_curve25519_ref10.c \
	src/libsodium/crypto_scalarmult/curve25519/ref10/fe_0_curve25519_ref10.c \
	src/libsodium/crypto_scalarmult/curve25519/ref10/fe_1_curve25519_ref10.c \
	src/libsodium/crypto_scalarmult/curve25519/ref10/fe_add_curve25519_ref10.c \
	src/libsodium/crypto_scalarmult/curve25519/ref10/fe_copy_curve25519_ref10.c \
	src/libsodium/crypto_scalarmult/curve25519/ref10/fe_cswap_curve25519_ref10.c \
	src/libsodium/crypto_scalarmult/curve25519/ref10/fe_frombytes_curve25519_ref10.c \
	src/libsodium/crypto_scalarmult/curve25519/ref10/fe_invert_curve25519_ref10.c \
	src/libsodium/crypto_scalarmult/curve25519/ref10/fe_mul_curve25519_ref10.c \
	src/libsodium/crypto_scalarmult/curve25519/ref10/fe_mul121666_curve25519_ref10.c \
	src/libsodium/crypto_scalarmult/curve25519/ref10/fe_sq_curve25519_ref10.c \
	src/libsodium/crypto_scalarmult/curve25519/ref10/fe_sub_curve25519_ref10.c \
	src/libsodium/crypto_scalarmult/curve25519/ref10/fe_tobytes_curve25519_ref10.c \
	src/libsodium/crypto_scalarmult/curve25519/ref10/scalarmult_curve25519_ref10.c \
	src/libsodium/crypto_stream/salsa20/ref/stream_salsa20_ref.c \
	src/libsodium/crypto_stream/salsa20/ref/xor_salsa20_ref.c 

LOCAL_CFLAGS += \
        -w \
	-Os \
	-DHAVE_CONFIG_H \
	-DLOCALEDIR=\"/data/locale\" \
	-DMINIMAL_TRUE=\"\#\" \
	-DMINIMAL_FALSE=\"\"

include $(BUILD_SHARED_LIBRARY)

include $(call all-makefiles-under,$(LOCAL_PATH))

