/*
 * pki_client_common.h
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

#ifndef __PKI_CLIENT_COMMON_HEADER__
#define __PKI_CLIENT_COMMON_HEADER__

struct requestAttributes;

typedef enum credentialType_e
{
    PKI_CLIENT_SHARED_SECRET,
    PKI_CLIENT_SIGNATURE
} credentialType;

typedef struct pki_client_ee_credentials_t
{
    certDistinguishedName * pClientName;
    credentialType          type;

#if defined(__ENABLE_MOCANA_CMP_CLIENT__) || defined(__ENABLE_MOCANA_SCEP_CLIENT__)
    union
    {
#ifdef __ENABLE_MOCANA_CMP_CLIENT__

        struct
        {
            ubyte *         pClientKID;
            ubyte4          clientKIDLen;
            ubyte *         pSharedSecret;
            ubyte4          secretLen;
        } sharedSecretParams;

        struct
        {
            ubyte *         pSignerCert;
            ubyte4          signerCertLen;
        } signerCertInfo;

#elif defined (__ENABLE_MOCANA_SCEP_CLIENT__)

        struct requestAttributes*  pScepRequestAttr;

#endif

    } cred;
#endif

} pki_client_ee_credentials;

typedef struct pki_pktStatistics_t
{
    ubyte8 sentPktCount;
    ubyte8 recvPktCount;
} pki_pktStatistics;

#endif /* __PKI_CLIENT_COMMON_HEADER__ */
