/*
 * arc2.h
 *
 * "alleged rc2" algorithm
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

/**
 * @file       arc2.h
 * @brief      Header file for the NanoCrypto RC2 Internal APIs.
 *
 * @details    This file contains the NanoCrypto RC2 Internal API methods.
 *
 * @flags      To enable the NanoCrypto RC2 functions, the following flag must be defined in moptions.h:
 *             + \c \__ENABLE_ARC2_CIPHERS__
 *
 *             Additionally, the following flag must \b not be defined:
 *             + \c \__ARC2_HARDWARE_CIPHER__
 *
 * @filedoc    arc2.h
 */

/*------------------------------------------------------------------*/

#ifndef __ARC2_H__
#define __ARC2_H__

#ifdef __cplusplus
extern "C" {
#endif


#define RC2_BLOCK_SIZE      (8)


/*------------------------------------------------------------------*/
#ifdef __ENABLE_ARC2_CIPHERS__
    
/**
 * @brief   Computes the rc2 key schedule.
 *
 * @details Computes the rc2 key schedule.
 *
 * @flags   To enable the NanoCrypto RC2 functions, the following flag must be defined
 *          + \c \__ENABLE_ARC2_CIPHERS__
 *
 * @param xkey  Will hold the resulting 128 bit key schedule.
 * @param key   Buffer holding the input key.
 * @param len   The length of the key in bytes.
 * @param bits  The requested effective key bits.
 *
 * @funcdoc     arc2.h
 */
MOC_EXTERN void rc2_keyschedule(ubyte2 xkey[64], const ubyte *key, ubyte4 len, ubyte4 bits);

/**
 * @brief   Encrypts a 64 bit block of data.
 *
 * @details Encrypts a 64 bit block of data.
 *
 * @flags   To enable the NanoCrypto RC2 functions, the following flag must be defined
 *          + \c \__ENABLE_ARC2_CIPHERS__
 *
 * @param xkey   The key schedule to be used to encrypt the data.
 * @param plain  Buffer holding the 64 bit (8 byte) block of data to be encrypted.
 * @param cipher Buffer that will hold the resulting 64 bits (8 bytes) of ciphertext.
 *
 * @funcdoc     arc2.h
 */
MOC_EXTERN void rc2_encrypt(const ubyte2 xkey[64], const ubyte *plain, ubyte *cipher);

/**
 * @brief   Decrypts a 64 bit block of data.
 *
 * @details Decrypts a 64 bit block of data.
 *
 * @flags   To enable the NanoCrypto RC2 functions, the following flag must be defined
 *          + \c \__ENABLE_ARC2_CIPHERS__
 *
 * @param xkey   The key schedule to be used to decrypt the data.
 * @param plain  Buffer that will hold the resulting 64 bits (8 bytes) of plaintext.
 * @param cipher Buffer holding the 64 bit (8 byte) block of data to be decrypted.
 *
 * @funcdoc     arc2.h
 */
MOC_EXTERN void rc2_decrypt(const ubyte2 xkey[64], ubyte *plain, const ubyte *cipher);
#endif

#ifdef __cplusplus
}
#endif

#endif
