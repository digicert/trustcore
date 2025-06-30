/*
 * aesalgo.h
 *
 * AES Implementation
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

#ifndef __AESALGO_HEADER__
#define __AESALGO_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Wrapper function for encryption key setup.
 * @details This function is a wrapper to the encryption key setup 
 *          implementation. If AES-Ni is enabled (__ENABLE_MOCANA_AES_NI__),
 *          then this function will call the AES-Ni implementation of key
 *          setup for encryption. Otherwise, this function will call the 
 *          software implementation of key setup for encryption.
 *
 * @param pRoundKey  Round key to use for this encryption operation.
 * @param pCipherKey Key bits to use for this encryption operation.
 * @param keyBits    Length in bits of the key material.
 *
 * @return Returns the number of rounds associated with the key, either 10, 12, or 14.
 *
 * @par Flags
 * The following flags will effect the execution of this function:
 *   + \c \__ENABLE_MOCANA_AES_NI__
 *   + \c \__ENABLE_MOCANA_AES_NI_RUNTIME_CHECK__
 *   .
 */
MOC_EXTERN sbyte4 aesKeySetupEnc (
  ubyte4 pRoundKey[/*4*(Nr + 1)*/], 
  const ubyte pCipherKey[], 
  sbyte4 keyBits
  );

/**
 * @brief   Wrapper function for decryption key setup.
 * @details This function is a wrapper to the decryption key setup 
 *          implementation. If AES-Ni is enabled (__ENABLE_MOCANA_AES_NI__),
 *          then this function will call the AES-Ni implementation of key
 *          setup for decryption. Otherwise, this function will call the 
 *          software implementation of key setup for decryption.
 *
 * @param pRoundKey  Round key to use for this decryption operation.
 * @param pCipherKey Key bits to use for this decryption operation.
 * @param keyBits    Length in bits of the key material.
 *
 * @return Returns the number of rounds associated with the key, either 10, 12, or 14.
 *
 * @par Flags
 * The following flags will effect the execution of this function:
 *   + \c \__ENABLE_MOCANA_AES_NI__
 *   + \c \__ENABLE_MOCANA_AES_NI_RUNTIME_CHECK__
 *   .
 */
MOC_EXTERN sbyte4 aesKeySetupDec (
  ubyte4 pRoundKey[/*4*(Nr + 1)*/], 
  const ubyte pCipherKey[], 
  sbyte4 keyBits
  );

/**
 * @brief   Wrapper function for AES encryption.
 * @details This function is a wrapper to the AES encryption implementation. 
 *          If AES-Ni is enabled (__ENABLE_MOCANA_AES_NI__), then this function 
 *          will call the AES-Ni encryption implementation. Otherwise, this 
 *          function will call the software encryption implementation.
 *
 * @param pRoundKey  Round key to use for this encryption operation.
 * @param numRounds  Number of rounds for this operation.
 * @param pPlain     Plaintext block to be encrypted.
 * @param pCipher    Buffer that recieves the resulting ciphertext block.
 *
 * @par Flags
 * The following flags will effect the execution of this function:
 *   + \c \__ENABLE_MOCANA_AES_NI__
 *   + \c \__ENABLE_MOCANA_AES_NI_RUNTIME_CHECK__
 *   .
 */
MOC_EXTERN void aesEncrypt (
  ubyte4 pRoundKey[/*4*(Nr + 1)*/], 
  sbyte4 numRounds, 
  const ubyte pPlain[16], 
  ubyte pCipher[16]
  );

/**
 * @brief   Wrapper function for AES decryption.
 * @details This function is a wrapper to the AES decryption implementation. 
 *          If AES-Ni is enabled (__ENABLE_MOCANA_AES_NI__), then this function 
 *          will call the AES-Ni decryption implementation. Otherwise, this 
 *          function will call the software decryption implementation.
 *
 * @param pRoundKey  Round key to use for this decryption operation.
 * @param numRounds  Number of rounds for this operation.
 * @param pCipher    Ciphertext block to be decrypted.
 * @param pPlain     Buffer that recieves the resulting plaintext block.
 *
 * @par Flags
 * The following flags will effect the execution of this function:
 *   + \c \__ENABLE_MOCANA_AES_NI__
 *   + \c \__ENABLE_MOCANA_AES_NI_RUNTIME_CHECK__
 *   .
 */
MOC_EXTERN void aesDecrypt (
  ubyte4 pRoundKey[/*4*(Nr + 1)*/], 
  sbyte4 numRounds, 
  const ubyte pCipher[16], 
  ubyte pPlain[16]
  );

/*----------------------------------------------------------------------------*/

/**
 * @brief            Software implementation for encryption key setup.
 *
 * @param pRoundKey  Round key to use for this encryption operation.
 * @param pCipherKey Key bits to use for this encryption operation.
 * @param keyBits    Length in bits of the key material.
 *
 * @par Flags
 * To enable this function, the following flag must \b not be defined:
 *   + \c \__DISABLE_AES_SW_CIPHERS__
 *   .
 */
MOC_EXTERN sbyte4 aesSwKeySetupEnc (
  ubyte4 pRoundKey[/*4*(Nr + 1)*/], 
  const ubyte pCipherKey[], 
  sbyte4 keyBits
  );

/**
 * @brief            Software implementation for decryption key setup.
 *
 * @param pRoundKey  Round key to use for this decryption operation.
 * @param pCipherKey Key bits to use for this decryption operation.
 * @param keyBits    Length in bits of the key material.
 *
 * @par Flags
 * To enable this function, the following flag must \b not be defined:
 *   + \c \__DISABLE_AES_SW_CIPHERS__
 *   .
 */
MOC_EXTERN sbyte4 aesSwKeySetupDec (
  ubyte4 pRoundKey[/*4*(Nr + 1)*/], 
  const ubyte pCipherKey[], 
  sbyte4 keyBits
  );

/**
 * @brief     Software implementation of AES encryption.
 *
 * @param pRoundKey  Round key to use for this encryption operation.
 * @param numRounds  Number of rounds for this operation.
 * @param pPlain     Plaintext block to be encrypted.
 * @param pCipher    Buffer that recieves the resulting ciphertext block.
 *
 * @par Flags
 * To enable this function, the following flag must \b not be defined:
 *   + \c \__DISABLE_AES_SW_CIPHERS__
 *   .
 */
MOC_EXTERN void aesSwEncrypt (
  ubyte4 pRoundKey[/*4*(Nr + 1)*/], 
  sbyte4 numRounds, 
  const ubyte pPlain[16], 
  ubyte pCipher[16]
  );

/**
 * @brief     Software implementation of AES decryption.
 *
 * @param pRoundKey  Round key to use for this decryption operation.
 * @param numRounds  Number of rounds for this operation.
 * @param pCipher    Ciphertext block to be decrypted.
 * @param pPlain     Buffer that recieves the resulting plaintext block.
 *
 * @par Flags
 * To enable this function, the following flag must \b not be defined:
 *   + \c \__DISABLE_AES_SW_CIPHERS__
 *   .
 */
MOC_EXTERN void aesSwDecrypt (
  ubyte4 pRoundKey[/*4*(Nr + 1)*/], 
  sbyte4 numRounds, 
  const ubyte pCipher[16], 
  ubyte pPlain[16]
  );

#ifdef __cplusplus
}
#endif

#endif /* __AESALGO_HEADER__ */
