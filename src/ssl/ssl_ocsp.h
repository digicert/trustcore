/*
 * ssl_ocsp.h
 *
 * OCSP code to be used in SSL Extensions to support ocsp stapling
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

#ifndef __SSL_OCSP_HEADER__
#define __SSL_OCSP_HEADER__

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)

MOC_EXTERN MSTATUS SSL_OCSP_initContext(void** ppContext);

MOC_EXTERN MSTATUS SSL_OCSP_createResponderIdList(void* pOcspContext,
                                                  char** ppTrustedResponderCertPath,
                                                  ubyte4 trustedResponderCertCount,
                                                  ubyte** ppRetRespIdList,
                                                  ubyte4* pRetRespIdListLen);

MOC_EXTERN MSTATUS SSL_OCSP_createExtensionsList(extensions* pExts,
                                                 ubyte4 extCount,
                                                 ubyte** ppRetExtensionsList,
                                                 ubyte4* pRetExtensionListLen);

MOC_EXTERN MSTATUS SSL_OCSP_addCertificates(SSLSocket* pSSLSock);

MOC_EXTERN MSTATUS SSL_OCSP_getOcspResponse(SSLSocket* pSSLSock,
                                        const SizedBuffer *pCertificates,
                                        sbyte4 certificateCount,
                                        ocspStorePtr pOcspStore,
                                        ubyte** ppResponse,
                                        ubyte4* pRetResponseLen);

MOC_EXTERN MSTATUS SSL_OCSP_parseExtensions(ubyte* pExtensions,
                                            ubyte4 extLen,
                                            extensions** ppExts,
                                            ubyte4* pExtCount);

MOC_EXTERN MSTATUS SSL_OCSP_validateOcspResponse(SSLSocket* pSSLSock,
                                                 ubyte* pResponse,
                                                 ubyte4 responseLen);

MOC_EXTERN MSTATUS SSL_OCSP_addCertificateAndIssuer(SSLSocket* pSSLSock,
                                                    ubyte4 certChainIndex,
                                                    ValidationConfig *pConfig);

#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__ */
#endif /* __SSL_OCSP_HEADER__ */
