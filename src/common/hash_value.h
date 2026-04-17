/*
 * hash_value.h
 *
 * Generate Hash Value Header
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 */

#ifndef __HASH_VALUE_HEADER__
#define __HASH_VALUE_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/** 
 * @brief    Computes a 32-bit hash value of a variable length key given in 4 byte words.
 * @details  Computes a 32-bit hash value of a variable length key given in 4 byte words. This
 *           is equivalent to Jenkin's hashlitte() on Little Endian machines and hashbig() on
 *           Big Endian machines. (See Jenkin's lookup3 methods).
 *
 * @param pHashKeyData      Pointer to the key to be hashed as a word buffer.
 * @param hashKeyDataLength The length of the key in 4-byte words. 
 * @param initialHashValue  The initial 32-bit hash-value specific to Jenkin's algorithm.
 * @param pRetHashValue     Contents will be set to the resulting 32-bit hash value.

 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS HASH_VALUE_hashWord(const ubyte4 *pHashKeyData, ubyte4 hashKeyDataLength, ubyte4 initialHashValue, ubyte4 *pRetHashValue);

/** 
 * @brief    Computes a 32-bit hash value of a variable length key given in an arbitary type.
 * @details  Computes a 32-bit hash value of a variable length key given in an arbitary type. This
 *           is equivalent to Jenkin's hashlitte() method. (See Jenkin's lookup3 methods).
 *
 * @param pHashKeyData      Pointer to the key to be hashed as an arbitrary type.
 * @param hashKeyDataLength The size or length of the key in bytes.
 * @param initialHashValue  The initial 32-bit hash-value specific to Jenkin's algorithm.
 * @param pRetHashValue     Contents will be set to the resulting 32-bit hash value.
 */
MOC_EXTERN void HASH_VALUE_hashGen(const void *pHashKeyData, ubyte4 hashKeyDataLength, ubyte4 initialHashValue, ubyte4 *pRetHashValue);

#ifdef __cplusplus
}
#endif

#endif /* __HASH_VALUE_HEADER__ */
