/*
 * cms_resign_priv.h
 *
 * CMS utility functions when resigning CMS data (see 'umresigner') - PRIVATE
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
