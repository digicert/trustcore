/*
 * ansix9_63_kdf.h
 *
 * ansi x9.63 Key Derivation Function
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
 *
 */

/**
 * @file       ansix9_63_kdf.h
 *
 * @brief      Header file for the NanoCrypto ANSI x9.63 Key Derivation APIs.
 *
 * @details    Header file for the NanoCrypto ANSI x9.63 Key Derivation APIs.
 *
 * @filedoc    ansix9_63_kdf.h
 */

#ifndef __ANSIX9_63_KDF_HEADER__
#define __ANSIX9_63_KDF_HEADER__

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
 * @funcdoc ansix9_63_kdf.h
 */
MOC_EXTERN MSTATUS ANSIX963KDF_generate( MOC_HASH(hwAccelDescr hwAccelCtx)
                        const BulkHashAlgo* pBulkHashAlgo,
                        ubyte* z, ubyte4 zLength,
                        const ubyte* sharedInfo, ubyte4 sharedInfoLen,
                        ubyte4 retLen, ubyte ret[/*retLen*/]);

#ifdef __cplusplus
}
#endif

#endif /* __ANSIX9_63_KDF_HEADER__*/

