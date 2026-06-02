/**
 * @file  ike_xauth.h
 * @brief IKE XAUTH support.
 *
 * @details    IKEv1 XAUTH (Extended Authentication) definitions.
 * @since      3.0
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *    +   \c \__ENABLE_IKE_XAUTH__
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

#ifndef __IKE_XAUTH_HEADER__
#define __IKE_XAUTH_HEADER__

#if defined(__ENABLE_DIGICERT_IKE_SERVER__) && defined(__ENABLE_IKE_XAUTH__)

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

/* index of strings in IKE_XAUTH_requestData::data */
enum {
    e_xauth_request_user_name,
    e_xauth_request_password,
    e_xauth_request_passcode,
    e_xauth_request_message,
    e_xauth_request_challenge,
    e_xauth_request_domain,
    e_xauth_request_unused_1,
    e_xauth_request_next_pin,
    e_xauth_request_answer,
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    e_xauth_request_perp,
#endif
    e_xauth_request_total
};

/* request data is cached so that we can process User asynchronous response */
typedef struct IKE_XAUTH_requestData
{
    ubyte4  ikeSaId;        /* for IKE engine to find back the ikesa */
    sbyte4  ikeSaLoc;       /* for IKE engine to find back the ikesa */
    ubyte2  wCfgId;         /* required by IKE interface */
    ubyte   verMin, verMax, draft; /* Xauth draft version */
    ubyte2  authType;       /* authentication type */
    ubyte2  statusType;     /* ACK(STATUS) */
    ubyte2  passwordLen;    /* length of password: may not be a char string */
    ubyte2  challengeLen;   /* length of challenge: may not be a char string */
    sbyte*  data[e_xauth_request_total]; /* points to area of the buffer below */
    sbyte   strings[1];     /* buffer that contains all the strings */
} IKE_XAUTH_requestData;


/*------------------------------------------------------------------*/

struct ike_context;
struct ikesa;
struct p2xg;

extern void IKE_xauthLock(void);
extern void IKE_xauthUnlock(void);

extern MSTATUS IKE_xauthProcess(ubyte **ppoCfgAttrs, ubyte2 *pwCfgAttrsLen,
                                ubyte *poCfgType, ubyte2 wCfgId,
                                struct ikesa *pxSa);

extern MSTATUS IKE_xauthProcessReply(ubyte *poCfgAttrs, ubyte2 wCfgAttrsLen,
                                     struct ikesa *pxSa, struct p2xg *pxXg);

extern MSTATUS IKE_xauthAAAInit(struct ikesa *pxSa, struct ike_context *pxCtx);

#ifdef __IKE_MULTI_THREADED__
struct dpcXauthCB;
extern sbyte4 IKE_dpcXauthCallback(struct dpcXauthCB *cb, ubyte4 cbSize);
#endif


#ifdef __cplusplus
}
#endif

#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) && defined(__ENABLE_IKE_XAUTH__) */

#endif /* __IKE_XAUTH_HEADER__ */

