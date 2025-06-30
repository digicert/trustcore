/*
 * aesalgo_intel_ni.h
 *
 * AES Intel NI Implementation
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */


/*------------------------------------------------------------------*/

#ifndef __AESALGO_INTEL_NI_HEADER__
#define __AESALGO_INTEL_NI_HEADER__

#if ((defined(__ENABLE_MOCANA_AES_NI__)) || \
     (defined(__ENABLE_MOCANA_AES_NI_RUNTIME_CHECK__))) && \
     (!defined(__DISABLE_AES_CIPHERS__))

#ifdef __cplusplus
extern "C" {
#endif


#if (defined(__ENABLE_MOCANA_FIPS_MODULE__) && \
	 defined(__ENABLE_MOCANA_FIPS_FORCE_PAA_MODE__) && \
	 defined(__ENABLE_MOCANA_AES_NI_RUNTIME_CHECK__) )
/* For FIPS: Enable the ability to forcefully disable AES-NI support even if the process supports it. */
MOC_EXTERN  void reset_to_default_aes_instructions(void);
MOC_EXTERN  void force_disable_aes_instructions(void);
MOC_EXTERN  intBoolean is_force_disable_aes_instructions(void);

#endif

MOC_EXTERN intBoolean check_for_aes_instructions(void);

MOC_EXTERN sbyte4 aesNiKeySetupEnc(ubyte4 rk[/*4*(Nr + 1)*/], ubyte cipherKey[], sbyte4 keyBits);
MOC_EXTERN sbyte4 aesNiKeySetupDec(ubyte4 rk[/*4*(Nr + 1)*/], ubyte cipherKey[], sbyte4 keyBits);

MOC_EXTERN void aesNiEncrypt(ubyte4 rk[/*4*(Nr + 1)*/], sbyte4 Nr, ubyte* pt, ubyte* ct, ubyte4 numBlocks);
MOC_EXTERN void aesNiDecrypt(ubyte4 rk[/*4*(Nr + 1)*/], sbyte4 Nr, ubyte* ct, ubyte* pt, ubyte4 numBlocks);

MOC_EXTERN void aesNiEncDecCTR(ubyte4 rk[/*4*(Nr + 1)*/], sbyte4 Nr, ubyte* pt, ubyte* ct, ubyte4 numBlocks, ubyte* ic);

MOC_EXTERN void
aesNiEncryptCBC(ubyte4 rk[/*4*(Nr + 1)*/], sbyte4 Nr, ubyte* pt, ubyte* ct, ubyte4 numBlocks, ubyte* iv);

MOC_EXTERN void
aesNiDecryptCBC(ubyte4 rk[/*4*(Nr + 1)*/], sbyte4 Nr, ubyte* pt, ubyte* ct, ubyte4 numBlocks, ubyte* iv);

#ifdef __cplusplus
}
#endif

#endif /* defined(__ENABLE_MOCANA_AES_NI__) etc. */

#endif /* __AESALGO_INTEL_NI_HEADER__ */
