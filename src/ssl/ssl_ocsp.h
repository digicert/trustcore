/*
 * ssl_ocsp.h
 *
 * OCSP code to be used in SSL Extensions to support ocsp stapling
 *
 * Copyright Mocana Corp 2005-2011. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */


#ifndef __SSL_OCSP_HEADER__
#define __SSL_OCSP_HEADER__

#if defined(__ENABLE_MOCANA_OCSP_CLIENT__)

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

#endif /* __ENABLE_MOCANA_OCSP_CLIENT__ */
#endif /* __SSL_OCSP_HEADER__ */
