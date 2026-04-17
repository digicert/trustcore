/*
 * cms_resign_priv.h
 *
 * CMS utility functions when resigning CMS data (see 'umresigner') - PRIVATE
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

#ifndef __CMS_RESIGN_PRIV_HEADER__
#define __CMS_RESIGN_PRIV_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/
#define NUM_ALGOS (6)  /* Number of supported signature algorithms */

/** An array holding data, that handles a memory pointer and the length of
 *  the stored data array.
 */
typedef struct CMS_RESIGN_Array
{
    ubyte* pData;
    ubyte4 dataLen;
} CMS_RESIGN_Array;

/*------------------------------------------------------------------*/

/** The context for saving & retrieving Resign signature/hash data.
 *
 */
typedef struct CMS_ResignData_I_CTX
{
    ubyte4             signatureBlockLen;
    ubyte*             psignatureBlock;
    ubyte4             signatureBlockAvail;  /* One-shot return of sig's, but need to free mem w/ Ctx. */

    ubyte4             extractedDataLen;
    ubyte*             pextractedData;

    const ubyte*       psignatureHashType_OID[NUM_ALGOS];
    ubyte4             oidCount;

    ubyte4             extractedCertsLen;
    ubyte*             pextractedCerts;

    ubyte4             numSignRaw;
    CMS_RESIGN_Array** pSignRawArray; /* [numSignRaw] */

    struct UMP_CMS_CTX*pUCtx;
    struct certStore*  pTrustStore;
} CMS_ResignData_I_CTX;

#ifdef __cplusplus
}
#endif

#endif /* __CMS_RESIGN_PRIV_HEADER__ */
