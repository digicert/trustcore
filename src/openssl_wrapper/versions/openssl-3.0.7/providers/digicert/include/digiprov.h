/*
 * digiprov.h
 *
 * Header file for declaring DigiProv functions.
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#ifndef __DIGIPROV_HEADER__
#define __DIGIPROV_HEADER__

#include "openssl/types.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int digiprov_is_running(void);

extern const OSSL_DISPATCH digiprov_md4_functions[];
extern const OSSL_DISPATCH digiprov_md5_functions[];
extern const OSSL_DISPATCH digiprov_sha1_functions[];
extern const OSSL_DISPATCH digiprov_sha224_functions[];
extern const OSSL_DISPATCH digiprov_sha256_functions[];
extern const OSSL_DISPATCH digiprov_sha384_functions[];
extern const OSSL_DISPATCH digiprov_sha512_functions[];
extern const OSSL_DISPATCH digiprov_sha3_224_functions[];
extern const OSSL_DISPATCH digiprov_sha3_256_functions[];
extern const OSSL_DISPATCH digiprov_sha3_384_functions[];
extern const OSSL_DISPATCH digiprov_sha3_512_functions[];
extern const OSSL_DISPATCH digiprov_shake_128_functions[];
extern const OSSL_DISPATCH digiprov_shake_256_functions[];
extern const OSSL_DISPATCH digiprov_blake2s256_functions[];
extern const OSSL_DISPATCH digiprov_blake2b512_functions[];

extern const OSSL_DISPATCH digiprov_hmac_functions[];
extern const OSSL_DISPATCH digiprov_blake2bmac_functions[];
extern const OSSL_DISPATCH digiprov_blake2smac_functions[];
extern const OSSL_DISPATCH digiprov_cmac_functions[];
extern const OSSL_DISPATCH digiprov_poly1305_functions[];

extern const OSSL_DISPATCH digiprov_aes128cbc_functions[];
extern const OSSL_DISPATCH digiprov_aes192cbc_functions[];
extern const OSSL_DISPATCH digiprov_aes256cbc_functions[];
extern const OSSL_DISPATCH digiprov_aes128ecb_functions[];
extern const OSSL_DISPATCH digiprov_aes192ecb_functions[];
extern const OSSL_DISPATCH digiprov_aes256ecb_functions[];
extern const OSSL_DISPATCH digiprov_aes128ofb_functions[];
extern const OSSL_DISPATCH digiprov_aes192ofb_functions[];
extern const OSSL_DISPATCH digiprov_aes256ofb_functions[];
extern const OSSL_DISPATCH digiprov_aes128cfb_functions[];
extern const OSSL_DISPATCH digiprov_aes192cfb_functions[];
extern const OSSL_DISPATCH digiprov_aes256cfb_functions[];

extern const OSSL_DISPATCH digiprov_aes128ctr_functions[];
extern const OSSL_DISPATCH digiprov_aes192ctr_functions[];
extern const OSSL_DISPATCH digiprov_aes256ctr_functions[];
extern const OSSL_DISPATCH digiprov_aes256xts_functions[];
extern const OSSL_DISPATCH digiprov_aes512xts_functions[];

extern const OSSL_DISPATCH digiprov_aes128gcm_functions[];
extern const OSSL_DISPATCH digiprov_aes192gcm_functions[];
extern const OSSL_DISPATCH digiprov_aes256gcm_functions[];
extern const OSSL_DISPATCH digiprov_aes128ccm_functions[]; 
extern const OSSL_DISPATCH digiprov_aes192ccm_functions[];
extern const OSSL_DISPATCH digiprov_aes256ccm_functions[];

extern const OSSL_DISPATCH digiprov_aes256wrap_functions[];
extern const OSSL_DISPATCH digiprov_aes192wrap_functions[];
extern const OSSL_DISPATCH digiprov_aes128wrap_functions[];
extern const OSSL_DISPATCH digiprov_aes256wrappad_functions[];
extern const OSSL_DISPATCH digiprov_aes192wrappad_functions[];
extern const OSSL_DISPATCH digiprov_aes128wrappad_functions[];
extern const OSSL_DISPATCH digiprov_aes256wrapinv_functions[];
extern const OSSL_DISPATCH digiprov_aes192wrapinv_functions[];
extern const OSSL_DISPATCH digiprov_aes128wrapinv_functions[];
extern const OSSL_DISPATCH digiprov_aes256wrappadinv_functions[];
extern const OSSL_DISPATCH digiprov_aes192wrappadinv_functions[];
extern const OSSL_DISPATCH digiprov_aes128wrappadinv_functions[];

extern const OSSL_DISPATCH digiprov_des64ecb_functions[];
extern const OSSL_DISPATCH digiprov_des64cbc_functions[];
extern const OSSL_DISPATCH digiprov_tdes192ecb_functions[];
extern const OSSL_DISPATCH digiprov_tdes192cbc_functions[];
extern const OSSL_DISPATCH digiprov_tdes128ecb_functions[];
extern const OSSL_DISPATCH digiprov_tdes128cbc_functions[];

/*extern const OSSL_DISPATCH digiprov_blowfish128ecb_functions[]; */
extern const OSSL_DISPATCH digiprov_blowfish128cbc_functions[];
extern const OSSL_DISPATCH digiprov_rc4128ctr_functions[];
extern const OSSL_DISPATCH digiprov_rc440ctr_functions[];
extern const OSSL_DISPATCH digiprov_rc5128ecb_functions[];
extern const OSSL_DISPATCH digiprov_rc5128cbc_functions[];

extern const OSSL_DISPATCH digiprov_chacha20_functions[];
extern const OSSL_DISPATCH digiprov_chacha20_poly1305_functions[];

extern const OSSL_DISPATCH digiprov_dh_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_rsapss_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_ec_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_x25519_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_x448_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_ed25519_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_ed448_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_dsa_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_mac_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_cmac_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_mlkem512_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_mlkem768_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_mlkem1024_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_mldsa44_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_mldsa65_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_mldsa87_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_slhdsa_sha2_128f_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_slhdsa_sha2_128s_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_slhdsa_sha2_192f_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_slhdsa_sha2_192s_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_slhdsa_sha2_256f_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_slhdsa_sha2_256s_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_slhdsa_shake_128f_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_slhdsa_shake_128s_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_slhdsa_shake_192f_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_slhdsa_shake_192s_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_slhdsa_shake_256f_keymgmt_functions[];
extern const OSSL_DISPATCH digiprov_slhdsa_shake_256s_keymgmt_functions[];

extern const OSSL_DISPATCH digiprov_rsa_sig_functions[];
extern const OSSL_DISPATCH digiprov_ecdsa_functions[];
extern const OSSL_DISPATCH digiprov_ed25519_functions[];
extern const OSSL_DISPATCH digiprov_ed448_functions[];
extern const OSSL_DISPATCH digiprov_dsa_functions[];
extern const OSSL_DISPATCH digiprov_mac_hmac_signature_functions[];
extern const OSSL_DISPATCH digiprov_mac_cmac_signature_functions[];
extern const OSSL_DISPATCH digiprov_mac_poly1305_signature_functions[];
extern const OSSL_DISPATCH digiprov_pqc_signature_functions[];

extern const OSSL_DISPATCH digiprov_rsa_cipher_functions[];

extern const OSSL_DISPATCH digiprov_dh_keyexch_functions[];
extern const OSSL_DISPATCH digiprov_ecdh_keyexch_functions[];
extern const OSSL_DISPATCH digiprov_x25519_keyexch_functions[];
extern const OSSL_DISPATCH digiprov_x448_keyexch_functions[];

extern const OSSL_DISPATCH digiprov_pqc_kem_functions[];

extern const OSSL_DISPATCH digiprov_drbg_ctr_functions[];
extern const OSSL_DISPATCH digiprov_drbg_hash_functions[];

extern const OSSL_DISPATCH digiprov_nist_kdf_functions[];
extern const OSSL_DISPATCH digiprov_hmac_kdf_functions[];
extern const OSSL_DISPATCH digiprov_x963_kdf_functions[];
extern const OSSL_DISPATCH digiprov_pbkdf1_functions[];
extern const OSSL_DISPATCH digiprov_pbkdf2_functions[];

extern const OSSL_DISPATCH digiprov_der_to_tap_decoder_functions[];

#ifdef __cplusplus
}
#endif

#endif /* __DIGIPROV_HEADER__ */
