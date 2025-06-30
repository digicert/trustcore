/*
 * cms_resign_util.h
 *
 * CMS utility functions when resigning CMS data (see 'umresigner')
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

#ifndef __CMS_RESIGN_UTIL_HEADER__
#define __CMS_RESIGN_UTIL_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This structure is opaque, and should not be included in the API
 *           documentation.
 */
typedef void* CMS_ResignData_CTX;

/*------------------------------------------------------------------*/
/* Context internal memory ownership: Allocates and does a deep     */
/*  copy during set operations. get return pointers to caller, but  */
/*  internal memory is still owned by the Context and will be freed */
/*  during ReleaseContext                                           */
/*------------------------------------------------------------------*/
MOC_EXTERN MSTATUS
CMS_RESIGN_AcquireContext(CMS_ResignData_CTX *pCtx);

MOC_EXTERN void
CMS_RESIGN_ReleaseContext(CMS_ResignData_CTX *pCtx);

/*------------------------------------------------------------------*/
/* Extracted Data buffer. Allocated & copied during set.            */
/*  get operation returns ptr (w/out a copy)                        */
/*------------------------------------------------------------------*/
MOC_EXTERN MSTATUS
CMS_RESIGN_setExtractedData(CMS_ResignData_CTX ctx,
                            const ubyte        *pData,
                            ubyte4             dataLen);

MOC_EXTERN void
CMS_RESIGN_getExtractedData(CMS_ResignData_CTX ctx,
                            ubyte              **ppData,
                            ubyte4             *pDataLen);

/*------------------------------------------------------------------*/
/* Extracted Certificates buffer. Allocated & copied during set.    */
/*  get operation returns ptr (w/out a copy)                        */
/*------------------------------------------------------------------*/
MOC_EXTERN MSTATUS
CMS_RESIGN_setExtractedCertificates(CMS_ResignData_CTX ctx,
                                    const ubyte        *pData,
                                    ubyte4             dataLen);

MOC_EXTERN void
CMS_RESIGN_getExtractedCertificates(CMS_ResignData_CTX ctx,
                                    ubyte              **ppData,
                                    ubyte4             *pDataLen);

/*------------------------------------------------------------------*/
/* Extracted Signature buffer. Allocated & copied during set.       */
/*  get operation returns ptr (w/out a copy)                        */
/*  clear operation leaves memory existent (until Context Free)     */
/*------------------------------------------------------------------*/
MOC_EXTERN MSTATUS
CMS_RESIGN_setExtractedSignature(CMS_ResignData_CTX ctx,
                                 const ubyte        *pData,
                                 ubyte4             dataLen);

MOC_EXTERN void
CMS_RESIGN_getExtractedSignature(CMS_ResignData_CTX ctx,
                                 ubyte              **ppData,
                                 ubyte4             *pDataLen);

MOC_EXTERN void
CMS_RESIGN_clearExtractedSignature(CMS_ResignData_CTX ctx);

MOC_EXTERN void
CMS_RESIGN_addRawSignature(CMS_ResignData_CTX ctx,
                           const ubyte        *pData,
                           ubyte4             dataLen);

MOC_EXTERN void
CMS_RESIGN_getRawSignatures(CMS_ResignData_CTX ctx,
                            void               *pCMSCtx);

/*------------------------------------------------------------------*/
/* Hash-ID OID array. Array internally allocated, each ID in the    */
/*  OID array can be set individually and cleared to prevent        */
/*  duplicate inserts.                                              */
/*------------------------------------------------------------------*/
MOC_EXTERN MSTATUS
CMS_RESIGN_setExtractedSignatureHashType(CMS_ResignData_CTX ctx,
                                         ubyte4             hashType);

MOC_EXTERN int
CMS_RESIGN_getNumSigningAlgos(void);

MOC_EXTERN void
CMS_RESIGN_getExtractedSignature_OIDs(CMS_ResignData_CTX ctx,
                                      ubyte              ***ppOids);

MOC_EXTERN void
CMS_RESIGN_clearExtractedSignature_OID(CMS_ResignData_CTX ctx,
                                       ubyte4             index);

#ifdef __cplusplus
}
#endif

#endif /* __CMS_RESIGN_UTIL_HEADER__ */
