/**
 * @file  ike_cert.h
 * @brief IKE certificate processing.
 *
 * @details    IKE certificate validation function declarations.
 * @since      1.41
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
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


/*------------------------------------------------------------------*/
/* internal use only */

#ifndef __IKE_CERT_HEADER__
#define __IKE_CERT_HEADER__

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

struct AsymmetricKey;

typedef struct ikeCertDescr
{
    ubyte   *poCertificate;
    ubyte2  wCertLen;

    /* subject (DN) */
    ubyte   *poSubject;
    ubyte2  wSubjLen;

    ubyte   oIdType;    /* ID Payload type; see IKE_ID_T in "ike_defs.h" */
                        /* also see RFC4945, 3.1.
                           e.g.
                            ID_IPV4_ADDR
                            ID_IPV6_ADDR
                            ID_FQDN
                            ID_USER_FQDN
                            ID_DER_ASN1_DN
                        */

    /* leaf */
    struct AsymmetricKey *pxPrivKey;

    ubyte2  wAuthMtd;   /* [v1] */
    ubyte   oAuthMtd;   /* [v2] */
    ubyte   oSigAlgo;   /* [v2] RSA */

    /* ca */
    ubyte   *poPubKeyHash; /* [v2] */

} *IKE_certDescr;


/*------------------------------------------------------------------*/

struct ike_context;
struct certDescriptor;
struct certDistinguishedName;
struct ikePeerConfig;

extern MSTATUS  IKE_initCertCache(void);
extern MSTATUS  IKE_flushCertCache(void);

extern MSTATUS  IKE_certGetKey(struct ike_context* ctx, struct AsymmetricKey **ppKey);
extern void     IKE_certAssign(struct ike_context* ctx, ubyte* poIdHash, struct AsymmetricKey *pKey);
extern MSTATUS  IKE_certLookup(struct ike_context* ctx, ubyte* poIdHash, struct AsymmetricKey **ppKey);
extern void     IKE_certUnbind(struct ike_context* ctx);

extern MSTATUS  IKE_certSetChain(MOC_HASH(hwAccelDescr hwAccelCtx)
                                 struct certDescriptor certificates[], sbyte4 certNum,
                                 IKE_certDescr pCertChain, sbyte4 *pCertChainLen,
                                 struct ikePeerConfig *config,
                                 intBoolean bCopy, intBoolean bPrivate);
extern void     IKE_certUnsetChain(IKE_certDescr pCertChain, sbyte4 certChainLen);

extern MSTATUS  IKE_useCert(struct ike_context *ctx, ubyte2 wAuthMtd);
extern MSTATUS  IKE_getCertAuth(struct ike_context *ctx, ubyte oAuthMtd); /* [v2] peer authentication */

extern MSTATUS  IKE_certGetDN(ubyte *poDn, ubyte2 wDnLen, struct certDistinguishedName **ppxDN);


#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

#endif /* __IKE_CERT_HEADER__ */

