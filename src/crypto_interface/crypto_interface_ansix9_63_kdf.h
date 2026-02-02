/*
 * crypto_interface_ansix9_63_kdf.h
 *
 * Cryptographic Interface specification for ANSIX9_63-KDF.
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
 @file       crypto_interface_ansix9_63_kdf.h
 @brief      Cryptographic Interface header file for declaring ANSIX9_63-KDF functions.
 
 @filedoc    crypto_interface_ansix9_63_kdf.h
 */
#ifndef __CRYPTO_INTERFACE_ANSIX9_63_KDF_HEADER__
#define __CRYPTO_INTERFACE_ANSIX9_63_KDF_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Performs the ANSI x9.63 Key Derivation.
 *
 * @details Performs the ANSI x9.63 Key Derivation.
 *
 * @param pBulkHashAlgo  Pointer to a suite holding the function pointer hash methods to be used.
 * @param z              Buffer holding the input shared secret as a byte array.
 * @param zLength        The length of z in bytes.
 * @param sharedInfo     Optional. Buffer holding the shared info as a byte array.
 * @param sharedInfoLen  The length of the shared info in bytes.
 * @param retLen         The requested length of the derived key in bytes.
 * @param ret            Buffer that will hold the resulting derived key.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc crypto_interface_ansix9_63_kdf.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ANSIX963KDF_generate( 
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo* pBulkHashAlgo,
    ubyte* z, ubyte4 zLength,
    const ubyte* sharedInfo, ubyte4 sharedInfoLen,
    ubyte4 retLen, ubyte ret[/*retLen*/]);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_ANSIX9_63_KDF_HEADER__ */
