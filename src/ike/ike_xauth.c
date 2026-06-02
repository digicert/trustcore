/**
 * @file  ike_xauth.c
 * @brief IKE XAUTH (Extended Authentication) support.
 *
 * @details    IKEv1 XAUTH implementation for extended user authentication.
 * @since      3.0
 * @version    6.5.1 and later
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_IKE_XAUTH__
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

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_IKE_SERVER__) && defined(__ENABLE_IKE_XAUTH__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#ifdef __ENABLE_DIGICERT_OTP__
#include "../crypto/otp.h"
#endif
#include "../crypto/md5.h"
#include "../crypto/ca_mgmt.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ipsec/ipsec.h"
#include "../ike/ikesa.h"
#include "../ike/ike_state.h"
#include "../ike/ike_xauth.h"
#include "../ike/ike_utils.h"

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
#include "../crypto/crypto.h"
#include "../ike/ike_crypto.h"
#endif


/*------------------------------------------------------------------*/

extern IKE_MUTEX g_ikeMtx; /* For async callbacks into engine */


/*------------------------------------------------------------------*/

#ifdef __IKE_MULTI_THREADED__

union dpcData
{
    /* AAA callback */
    struct
    {
        ubyte oCfgType;
        ubyte2 wResult;
    } aaa;

    /* User callback */
    struct
    {
        ubyte *poCfgAttrs;
        ubyte2 wCfgAttrsLen;
    } user;
};

typedef struct dpcXauthCB
{
    struct dpcHdr hdr;
    IKE_XAUTH_requestData *pRequestData;
    sbyte4 type; /* 0==aaa, 1=user */
    union dpcData data;

} *IKE_DPC_XAUTH_CB;

#endif


/*------------------------------------------------------------------*/

typedef struct IKE_XAUTH_Attr
{
    ubyte2 type;
    ubyte2 valueLength;
    union
    {
        const ubyte *varValue;
        ubyte2 basicValue;
    } u;
} IKE_XAUTH_Attr;


/*------------------------------------------------------------------*/

static const ubyte *
IKE_xauthNextAttribute(const ubyte *pAttrs, IKE_XAUTH_Attr* pAttr)
{
    pAttr->type = ((*pAttrs++) << 8);
    pAttr->type |= (*pAttrs++);
    /* first bit indicate Type/Value otherwise Type/Length/Value */
    if (pAttr->type & 0x8000)
    {
        pAttr->type &= 0x7FFF;     /* clear out the first bit */
        pAttr->valueLength = 0;
        pAttr->u.basicValue  = ((*pAttrs++) << 8);
        pAttr->u.basicValue |= (*pAttrs++);
    }
    else
    {
        pAttr->valueLength = ((*pAttrs++) << 8);
        pAttr->valueLength |= (*pAttrs++);
        pAttr->u.varValue = pAttrs;
    }
    return pAttrs + pAttr->valueLength;
}


/*------------------------------------------------------------------*/

static MSTATUS
IKE_xauthNewUserRequestData(const ubyte *pCfgAttrs, sbyte4 attrsLen,
                            ubyte2 wCfgId, struct ikesa *pxSa,
                            IKE_XAUTH_requestData** ppNewData)
{
    /* This function parse the raw attributes and saves them in a
    IKE_XAUTH_requestData for further use */

    MSTATUS status = OK;
    IKE_XAUTH_requestData* pRequestData = 0;
    sbyte* pNext;
    IKE_XAUTH_Attr attr;
    sbyte4 len, totalLen;
    const ubyte *pAttrs;

    /* first loop to determine the length of strings */
    pAttrs = pCfgAttrs;
    len = attrsLen;

    totalLen = sizeof(IKE_XAUTH_requestData);
    while (len > 0)
    {
        pAttrs = IKE_xauthNextAttribute(pAttrs, &attr);
        len -= 4 + (sbyte4) attr.valueLength;
        if (len < 0)
        {
            status = ERR_IKE_BAD_LEN;
            goto exit;
        }

        switch (attr.type)
        {
        case XAUTH_USER_NAME:
        case XAUTH_USER_PASSWORD:
        case XAUTH_PASSCODE:
        case XAUTH_MESSAGE:
        case XAUTH_CHALLENGE:
        case XAUTH_DOMAIN:
        case XAUTH_NEXT_PIN:
        case XAUTH_ANSWER:
        case XAUTH_PRIVATE_VENDOR_EXT1:

        /* draft-ietf-ipsec-isakmp-xauth-01 */
        case XAUTH_USER_NAME_1:
        case XAUTH_USER_PASSWORD_1:
        case XAUTH_PASSCODE_1:
        case XAUTH_MESSAGE_1:
        case XAUTH_CHALLENGE_1:
        case XAUTH_DOMAIN_1:

        /* draft-ietf-ipsec-isakmp-xauth-02...05 */
        case XAUTH_USER_NAME_25:
        case XAUTH_USER_PASSWORD_25:
        case XAUTH_PASSCODE_25:
        case XAUTH_MESSAGE_25:
        case XAUTH_CHALLENGE_25:
        case XAUTH_DOMAIN_25:

#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
        case XAUTH_MOCANA_PERP:
#endif
            totalLen += attr.valueLength + 1;
            break;

        case XAUTH_STATUS:
        case XAUTH_STATUS_35:

        case XAUTH_TYPE:
        case XAUTH_TYPE_1:
        case XAUTH_TYPE_25:

        /* draft-ietf-ipsec-isakmp-xauth-03...04 */
        case XAUTH_REQ_NUMBER:

            break;

        default:
            status = ERR_IKE_XAUTH_BAD_ATTRIBUTE;
            goto exit;
        }
    }
    /* allocate the struct */
    pRequestData = (IKE_XAUTH_requestData *) MALLOC(totalLen);
    if (NULL == pRequestData)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte *)pRequestData, 0, sizeof(IKE_XAUTH_requestData));
    pRequestData->ikeSaId = pxSa->dwId;
    pRequestData->ikeSaLoc = pxSa->loc;
    pRequestData->wCfgId = wCfgId;
    pRequestData->verMax = 0xff;
    pRequestData->draft = pxSa->ikePeerConfig->xauthDraft;
    pRequestData->authType = XAUTH_TYPE_OPTIONAL; /* optional TYPE_GENERIC */

    /* second loop */
    pNext = pRequestData->strings;
    pAttrs = pCfgAttrs;
    len = attrsLen;
    while (len > 0)
    {
        ubyte2 type;
        ubyte verMin=0, verMax=0xff;

        pAttrs = IKE_xauthNextAttribute(pAttrs, &attr);
        len -= 4 + (sbyte4) attr.valueLength;
        if (len < 0)
        {
            status = ERR_IKE_BAD_LEN;
            goto exit;
        }

        /* check draft version */
        type = attr.type;
        switch (type)
        {
        case XAUTH_TYPE_1:
        case XAUTH_USER_NAME_1:
        case XAUTH_USER_PASSWORD_1:
        case XAUTH_PASSCODE_1:
        case XAUTH_MESSAGE_1:
        case XAUTH_CHALLENGE_1:
        case XAUTH_DOMAIN_1:
            verMin = verMax = 1;
            type = type + (ubyte2)(XAUTH_TYPE - XAUTH_TYPE_1);
            break;
        case XAUTH_TYPE_25:
        case XAUTH_USER_NAME_25:
        case XAUTH_USER_PASSWORD_25:
        case XAUTH_PASSCODE_25:
        case XAUTH_MESSAGE_25:
        case XAUTH_CHALLENGE_25:
        case XAUTH_DOMAIN_25:
            verMin = 2; verMax = 5;
            type = type + (ubyte2)(XAUTH_TYPE - XAUTH_TYPE_25);
            break;
        case XAUTH_STATUS_35:
            verMin = 3; verMax = 5;
            break;
        case XAUTH_REQ_NUMBER:
            verMin = 3; verMax = 4;
            break;
        case XAUTH_TYPE:
        case XAUTH_USER_NAME:
        case XAUTH_USER_PASSWORD:
        case XAUTH_PASSCODE:
        case XAUTH_MESSAGE:
        case XAUTH_CHALLENGE:
        case XAUTH_DOMAIN:
        case XAUTH_STATUS:
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
        case XAUTH_MOCANA_PERP:
#endif
        case XAUTH_PRIVATE_VENDOR_EXT1:
            verMin = 6; verMax = 0xff;
            break;
        case XAUTH_NEXT_PIN:
        case XAUTH_ANSWER:
            verMin = 7; verMax = 0xff;
            break;
        default:
            status = ERR_IKE_XAUTH_BAD_ATTRIBUTE;
            goto exit;
        }

        if (verMin > pRequestData->verMin)
            pRequestData->verMin = verMin;

        if (verMax < pRequestData->verMax)
            pRequestData->verMax = verMax;

        if (pRequestData->verMax < pRequestData->verMin)
        {
            status = ERR_IKE_XAUTH_DRAFT_VERSION;
            goto exit;
        }

        switch (type)
        {
        case XAUTH_TYPE:
            pRequestData->authType = attr.u.basicValue;
            break;

        /* for the challenge, it's not a string so store the length */
        case XAUTH_CHALLENGE:
        case XAUTH_USER_PASSWORD:
            if (XAUTH_USER_PASSWORD == type)
                pRequestData->passwordLen = attr.valueLength;
            else
                pRequestData->challengeLen = attr.valueLength;
            /* flows through */

        case XAUTH_USER_NAME:
        case XAUTH_PASSCODE:
        case XAUTH_MESSAGE:
        case XAUTH_DOMAIN:
        case XAUTH_NEXT_PIN:
        case XAUTH_ANSWER:
            pRequestData->data[type - XAUTH_USER_NAME] = pNext;
            DIGI_MEMCPY(pNext, attr.u.varValue, attr.valueLength);
            pNext += attr.valueLength;
            *pNext++ = 0; /* nul terminate */
            break;

#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
        case XAUTH_MOCANA_PERP:
            pRequestData->data[e_xauth_request_perp] = pNext;
            DIGI_MEMCPY( pNext, attr.u.varValue, attr.valueLength);
            pNext += attr.valueLength;
            *pNext++ = 0; /* nul terminate */
            break;
#endif
        case XAUTH_STATUS:
        case XAUTH_STATUS_35:
            pRequestData->statusType = type;
            break;

        case XAUTH_REQ_NUMBER:
        case XAUTH_PRIVATE_VENDOR_EXT1:
            break;

        default:
            status = ERR_IKE_XAUTH_BAD_ATTRIBUTE;
            goto exit;
        }
    }

    /* See "draft-ietf-ipsec-isakmp-xauth-06", 4.2, page 10:
       XAUTH_TYPE is optional and must match between REQUEST and REPLY.
     */
    if ((XAUTH_TYPE_OPTIONAL == pRequestData->authType) &&
        (6 > pRequestData->verMax))
    {
        pRequestData->authType = XAUTH_TYPE_GENERIC; /* default */
    }

    *ppNewData = pRequestData;
    pRequestData = 0;

exit:
    if (pRequestData)
    {
        FREE(pRequestData);
    }

    return status;
} /* IKE_xauthNewUserRequestData */


/*------------------------------------------------------------------*/

static ubyte *
IKE_xauthWriteAttrHeader(ubyte *pBuff, ubyte2 type, ubyte2 valueOrLen)
{
    *pBuff++ = (ubyte) (type >> 8);
    *pBuff++ = (ubyte) (type );
    *pBuff++ = (ubyte) (valueOrLen >> 8);
    *pBuff++ = (ubyte) (valueOrLen);
    return pBuff;
}


/*------------------------------------------------------------------*/

static ubyte *
IKE_xauthWriteAttrString(ubyte *pBuff, ubyte2 type, ubyte2 strLen,
                         const sbyte* pStr)
{
    pBuff = IKE_xauthWriteAttrHeader(pBuff, type, strLen);
    DIGI_MEMCPY(pBuff, pStr, strLen);
    return pBuff + strLen;
}


/*------------------------------------------------------------------*/

static MSTATUS
PackUserReplyData(ubyte **ppoCfgAttrs, ubyte2 *pwCfgAttrsLen,
                  ubyte2 authType, ubyte verMin, ubyte verMax,
                  const sbyte *pUsername,
                  const sbyte *pPassword, ubyte4 passwordLen,
                  const sbyte *pPasscode, const sbyte *pNextPin,
                  const sbyte *pAnswer
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                , const sbyte *pPerp
#endif
                  )
{
    MSTATUS status = OK;
    ubyte *pBuffer = 0;
    ubyte *pTemp;
    ubyte4 bufferLen = 0;
    ubyte4 usernameLen = 0, passcodeLen = 0,
           nextPinLen = 0, answerLen = 0;
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    ubyte4 perpLen = 0;
#endif
    ubyte2 attrType;

    if (XAUTH_TYPE_OPTIONAL != authType) /* optional since Draft 6 */
    {
        bufferLen += 4; /* basic length */
    }
    if (pUsername)
    {
        usernameLen = DIGI_STRLEN(pUsername);
        if (usernameLen > 0xFFFF)
        {
            status = ERR_IKE_XAUTH_USERNAME_LENGTH;
            goto exit;
        }
        bufferLen += usernameLen + 4;
    }
    if (pPassword)
    {
        if (passwordLen > 0xFFFF)
        {
            status = ERR_IKE_XAUTH_PASSWORD_LENGTH;
            goto exit;
        }
        bufferLen += passwordLen + 4;
    }
    if (pPasscode)
    {
        passcodeLen = DIGI_STRLEN(pPasscode);
        if (passcodeLen > 0xFFFF)
        {
            status = ERR_IKE_XAUTH_PASSWORD_LENGTH;
            goto exit;
        }
        bufferLen += passcodeLen + 4;
    }

    if (pNextPin)
    {
        nextPinLen = DIGI_STRLEN(pNextPin);
        if (nextPinLen > 0xFFFF)
        {
            status = ERR_IKE_XAUTH_NEXT_PIN_LENGTH;
            goto exit;
        }
        bufferLen += nextPinLen + 4;
    }

    if (pAnswer)
    {
        answerLen = DIGI_STRLEN(pAnswer);
        if (answerLen > 0xFFFF)
        {
            status = ERR_IKE_XAUTH_ANSWER_LENGTH;
            goto exit;
        }
        bufferLen += answerLen + 4;
    }
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    if (pPerp)
    {
        perpLen = DIGI_STRLEN(pPerp);
        if (perpLen > 0xFFFF)
        {
            status = ERR_IKE_XAUTH_PERP_LENGTH;
            goto exit;
        }
        bufferLen += perpLen + 4;
    }
#endif

    if (bufferLen > 0xFFFF)
    {
        status = ERR_IKE_XAUTH_USERDATA_LENGTH;
        goto exit;
    }

    pBuffer = (ubyte *) MALLOC(bufferLen);
    if (NULL == pBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* fill the buffer */
    pTemp = pBuffer;
    if (XAUTH_TYPE_OPTIONAL != authType) /* optional since Draft 6 */
    {
        if (1 == verMin)
            attrType = XAUTH_TYPE_1;
        else if ((ubyte)5 >= verMax)
            attrType = XAUTH_TYPE_25;
        else
            attrType = XAUTH_TYPE;

        pTemp = IKE_xauthWriteAttrHeader(pTemp, (0x8000 | attrType),
                                         authType);
    }
    if (pUsername)
    {
        if (1 == verMin)
            attrType = XAUTH_USER_NAME_1;
        else if ((ubyte)5 >= verMax)
            attrType = XAUTH_USER_NAME_25;
        else
            attrType = XAUTH_USER_NAME;

        pTemp = IKE_xauthWriteAttrString(pTemp, attrType,
                                         (ubyte2)usernameLen, pUsername);
    }
    if (pPassword)
    {
        if (1 == verMin)
            attrType = XAUTH_USER_PASSWORD_1;
        else if ((ubyte)5 >= verMax)
            attrType = XAUTH_USER_PASSWORD_25;
        else
            attrType = XAUTH_USER_PASSWORD;

        pTemp = IKE_xauthWriteAttrString(pTemp, attrType,
                                         (ubyte2)passwordLen, pPassword);
    }
    if (pPasscode)
    {
        if (1 == verMin)
            attrType = XAUTH_PASSCODE_1;
        else if ((ubyte)5 >= verMax)
            attrType = XAUTH_PASSCODE_25;
        else
            attrType = XAUTH_PASSCODE;

        pTemp = IKE_xauthWriteAttrString(pTemp, attrType,
                                         (ubyte2)passcodeLen, pPasscode);
    }
    if (pNextPin)
    {
        pTemp = IKE_xauthWriteAttrString(pTemp, XAUTH_NEXT_PIN,
                                         (ubyte2)nextPinLen, pNextPin);
    }
    if (pAnswer)
    {
        pTemp = IKE_xauthWriteAttrString(pTemp, XAUTH_ANSWER,
                                         (ubyte2)answerLen, pAnswer);
    }
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    if (pPerp)
    {
        pTemp = IKE_xauthWriteAttrString(pTemp, XAUTH_MOCANA_PERP,
                                         (ubyte2)perpLen, pPerp);
    }
#endif

    *ppoCfgAttrs = pBuffer;
    pBuffer = 0;
    *pwCfgAttrsLen = (ubyte2) bufferLen;

exit:
    if (pBuffer)
    {
        FREE(pBuffer);
    }

    return status;
} /* PackUserReplyData */


/*------------------------------------------------------------------*/

static MSTATUS
ProcessUserInput(ubyte **ppoCfgAttrs, ubyte2 *pwCfgAttrsLen,
                 IKE_XAUTH_requestData* pRequestData,
                 const sbyte *pUsername, const sbyte *pPassword,
                 const sbyte *pPassCode, const sbyte *pNextPin,
                 const sbyte *pAnswer
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
               , const sbyte *pPerp
#endif
                 )
{
    MSTATUS status = OK;

    MD5_CTX* pCtx = NULL;

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx = 0;
    if (OK > (status = IKE_getHwAccelChannel(&hwAccelCtx)))
        goto nocleanup;
#endif

    /* "draft-ietf-ipsec-isakmp-xauth-05", page 9:
       The XAUTH_TYPE in a REPLY MUST be identical to the XAUTH_TYPE in the
       REQUEST.

       "draft-ietf-ipsec-isakmp-xauth-06", 4.2, page 10:
       ...       If the XAUTH-TYPE was not present in the REQUEST, then it
       MUST NOT be present in the REPLY.
     */
    switch (pRequestData->authType)
    {
    case XAUTH_TYPE_RADIUS_CHAP:
        /* "draft-ietf-ipsec-isakmp-xauth-06", page 12:
           In order to use the CHAP functionality defined in [RADIUS], the
           XAUTH_TYPE MUST be set to RADIUS-CHAP.  For all other methods
           defined in [RADIUS] (i.e. PAP), the XAUTH_TYPE MUST be set to
           Generic.
         */
        if (pRequestData->challengeLen/* || ((ubyte)6 <= pRequestData->verMin)*/)

        /* what is the format of the CHAP challenge =
            a byte string or a character encoding of the bytes ?
            also the XAUTH draft computes the hash with id + challenge + secret whereas
            the Radius RFC specifies id + secret + challenge.  */
        /* "draft-beaulieu-ike-xauth-01", page 20: (ID+secret+challenge) */
        {
            sbyte chapRes[MD5_RESULT_SIZE + 1];

            if (OK > (status = MD5Alloc_m(MOC_HASH(hwAccelCtx) (BulkCtx *) &pCtx)))
                goto exit;

            if (OK > (status = MD5Init_m(MOC_HASH(hwAccelCtx) pCtx)))
                goto exit;

            /* whatever is on the stack */
            if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, (ubyte *)chapRes,
                                           1)))
            {
                goto exit;
            }

            if (((ubyte)6 <= pRequestData->verMin) &&
                ((ubyte)8 <= pRequestData->draft))
            {
                if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, (ubyte *)pPassword,
                                               DIGI_STRLEN(pPassword))))
                {
                    goto exit;
                }
                if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx,
                             (ubyte *) pRequestData->data[e_xauth_request_challenge],
                                               pRequestData->challengeLen)))
                {
                    goto exit;
                }
            }
            else
            {
                if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx,
                             (ubyte *) pRequestData->data[e_xauth_request_challenge],
                                               pRequestData->challengeLen)))
                {
                    goto exit;
                }

                if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCtx) pCtx, (ubyte *)pPassword,
                                               DIGI_STRLEN(pPassword))))
                {
                    goto exit;
                }
            }

            if (OK > (status = MD5Final_m(MOC_HASH(hwAccelCtx) pCtx, (ubyte *) chapRes+1)))
                goto exit;

            if (OK > (status = PackUserReplyData(ppoCfgAttrs, pwCfgAttrsLen,
                        pRequestData->authType,
                        pRequestData->verMin, pRequestData->verMax,
                        pUsername, chapRes, MD5_RESULT_SIZE + 1,
                        NULL, NULL, pAnswer
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                      , pPerp
#endif
                                                 )))
            {
                goto exit;
            }

            break;
        }
        /* fall through */

    case XAUTH_TYPE_OPTIONAL: /* optional since Draft 6 */
    case XAUTH_TYPE_GENERIC:
        /* package the userName and password into raw attributes and send
           them back to the engine

          "draft-beaulieu-ike-xauth-02", 6.2, page 10:
          ...                                  The XAUTH-CHALLENGE attribute
          MUST NOT be used when XAUTH-TYPE is set to generic.
         */
        if (OK > (status = PackUserReplyData(ppoCfgAttrs, pwCfgAttrsLen,
                        pRequestData->authType,
                        pRequestData->verMin, pRequestData->verMax,
                        pUsername, pPassword,
                        (pPassword ? DIGI_STRLEN(pPassword) : 0),
                        pPassCode, pNextPin, pAnswer
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                      , pPerp
#endif
                                             )))
        {
            goto exit;
        }
        break;

    case XAUTH_TYPE_OTP:
        {
#ifdef __ENABLE_DIGICERT_OTP__
            sbyte otpRes[OTP_STR_RESULT_SIZE];

            /* call the function; note that 'challenge' is in readable form */
            if (pRequestData->challengeLen)
            if (OK > (status = OTP_otpEx(MOC_HASH(hwAccelCtx)
                        pRequestData->data[e_xauth_request_challenge],
                        pPassword, otpRes)))
            {
                goto exit;
            }

            if (OK > (status = PackUserReplyData(ppoCfgAttrs, pwCfgAttrsLen,
                        pRequestData->authType,
                        pRequestData->verMin, pRequestData->verMax,
                        pUsername, (pRequestData->challengeLen ? otpRes : NULL),
                        (pRequestData->challengeLen ? DIGI_STRLEN(otpRes) : 0),
                        NULL, NULL, pAnswer
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                      , pPerp
#endif
                                                 )))
            {
                goto exit;
            }
#else
            status = ERR_IKE_XAUTH_UNSUPPORTED_AUTHENTICATION_TYPE;
            goto exit;
#endif
        }
        break;

    default:
        status = ERR_IKE_XAUTH_UNSUPPORTED_AUTHENTICATION_TYPE;
        goto exit;
        break;
    }

exit:
    if (NULL != pCtx)
    {
        MD5Free_m(MOC_HASH(hwAccelCtx) (BulkCtx *) &pCtx);
    }

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    IKE_releaseHwAccelChannel(&hwAccelCtx);

nocleanup:
#endif
    return status;
} /* ProcessUserInput */


/*------------------------------------------------------------------*/

#ifdef __IKE_MULTI_THREADED__
extern ikeSettings m_ikeSettings;
extern RTOS_RWLOCK m_ikeSaRwLock;
#endif

static MSTATUS
IKE_xauthGetXchg(IKE_XAUTH_requestData *pRequestData, ubyte oState,
#ifdef __IKE_MULTI_THREADED__
                 union dpcData *data,
#endif
                 IKESA *ppxSa, P2XG *ppxXg)
{
    MSTATUS status;

    IKESA pxSa = NULL;
    P2XG pxXg = NULL;
    sbyte4 i;

    if (OK > (status = IKE_getSaByLoc(pRequestData->ikeSaLoc, &pxSa)))
    {
        goto exit;
    }

    status = ERR_IKE_GETSA_FAIL;

    if (NULL == pxSa) goto exit; /* jic */

#ifdef __IKE_MULTI_THREADED__
    RTOS_rwLockWaitR(m_ikeSaRwLock);
#endif
    if (!IS_VALID(pxSa) || (pRequestData->ikeSaId != pxSa->dwId))
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        goto exit;
    }

    for (i=0; i < IKE_P2_MAX; i++, pxXg = NULL)
    {
        pxXg = &(pxSa->u.v1.p2Xg[i]);
        if (IS_VALID_XCHG(pxXg) &&
            (oState  == pxXg->oState) &&
            (pRequestData->wCfgId == pxXg->wCfgId))
        {
            break; /* found */
        }
    }

    if (NULL == pxXg)
    {
#ifdef __IKE_MULTI_THREADED__
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif
        goto exit;
    }

#ifdef __IKE_MULTI_THREADED__
    if (FALSE == RTOS_sameThreadId(RTOS_currentThreadId(), pxSa->tid))
    {
        /* relay this call to the proper thread */
        if (m_ikeSettings.funcPtrIkeThreadSend)
        {
            ubyte4 size = sizeof(struct dpcXauthCB);
            struct dpcXauthCB cb;
            cb.hdr.dpc_func = (IKE_dpcFunc)IKE_dpcXauthCallback;
            cb.hdr.dpc_len = (ubyte2)size;
            cb.pRequestData = pRequestData;
            cb.data = *data;
            cb.type = (STATE_CFG_I2xc == oState) ? 0 /* AAA */
                    : /*(STATE_CFG_R1 == oState)*/ 1; /* User */

            status = (MSTATUS)
            m_ikeSettings.funcPtrIkeThreadSend(pxSa->tid, (ubyte *)&cb, size);
            if (OK <= status) status = STATUS_IKE_PENDING; /* !!! */
        }
        else
        {
            status = ERR_IKE_CONFIG;
        }
        RTOS_rwLockReleaseR(m_ikeSaRwLock);
        goto exit;
    }

    RTOS_rwLockReleaseR(m_ikeSaRwLock);
#endif

    pxSa->merror = OK;
    pxXg->merror = OK;
    pxXg->x_flags &= ~(IKE_XCHG_FLAG_PENDING);

    *ppxSa = pxSa;
    *ppxXg = pxXg;

    status = OK;

exit:
    return status;
} /* IKE_xauthGetXchg */


/*------------------------------------------------------------------*/

extern void
IKE_xauthLock()
{
    IKE_LOCK_R;
    return;
} /* IKE_xauthLock */

extern void
IKE_xauthUnlock()
{
    IKE_UNLOCK_R;
    return;
} /* IKE_xauthUnlock */


/*------------------------------------------------------------------*/

static MSTATUS
XauthUserCallback(IKE_XAUTH_requestData *pRequestData,
                  ubyte *poCfgAttrs, ubyte2 wCfgAttrsLen)
{
    MSTATUS status;

    IKESA pxSa = NULL;
    P2XG pxXg = NULL;

    struct ike_context ctx = { NULL };

#ifdef __IKE_MULTI_THREADED__
    union dpcData data;
    data.user.poCfgAttrs = poCfgAttrs;
    data.user.wCfgAttrsLen = wCfgAttrsLen;
#endif

    IKE_xauthLock(); /* !!! */

    /* find pending exchange */
    if (OK > (status = IKE_xauthGetXchg(pRequestData, STATE_CFG_R1,
#ifdef __IKE_MULTI_THREADED__
                                        &data,
#endif
                                        &pxSa, &pxXg)))
    {
#ifdef __IKE_MULTI_THREADED__
        if (STATUS_IKE_PENDING == status)
        {
            pRequestData = NULL; /* !!! */
            poCfgAttrs = NULL;
        }
#endif
        goto exit;
    }

    /* send it to the IKE engine */
    pxXg->oCfgType = CFG_REPLY;

    if (NULL != pxXg->poCfgAttrs) /* jic */
    {
        FREE(pxXg->poCfgAttrs);
    }

    pxXg->poCfgAttrs = poCfgAttrs;
    pxXg->wCfgAttrsLen = wCfgAttrsLen;

    ctx.pxSa = pxSa;
    ctx.pxP2Xg = pxXg;
    status = IKE_xchgOut(&ctx);

    poCfgAttrs = NULL; /* will be freed by IKE */

exit:
    /* done with the IKE_XAUTH_requestData */
#ifdef __IKE_MULTI_THREADED__
    if (pRequestData)
#endif
    {
        FREE(pRequestData);
    }
    if (poCfgAttrs)
    {
        FREE(poCfgAttrs);
    }
    IKE_xauthUnlock();
    return status;
} /* XauthUserCallback */


/*------------------------------------------------------------------*/

static sbyte4
IKE_xauthUserCallback(void *connectionInstance,
                      const sbyte *userName, const sbyte *password,
                      const sbyte *passCode, const sbyte *nextPin,
                      const sbyte *answer
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                    , const sbyte *perp
#endif
                      )
{
    MSTATUS status;

    ubyte *poCfgAttrs = NULL;
    ubyte2 wCfgAttrsLen = 0;

    /* this is the function call after the user has provided the info */
    IKE_XAUTH_requestData* pRequestData;

    if (0 == connectionInstance)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pRequestData = (IKE_XAUTH_requestData *)connectionInstance;

    /* genereate the correct reply data */
    if (OK > (status = ProcessUserInput(&poCfgAttrs, &wCfgAttrsLen,
                                        pRequestData, userName,
                                        password, passCode, nextPin,
                                        answer
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                                      , perp
#endif
                                        )))
    {
        FREE(pRequestData);
        goto exit;
    }

    status = XauthUserCallback(pRequestData, poCfgAttrs, wCfgAttrsLen);

exit:
    return (sbyte4)status;
} /* IKE_xauthUserCallback */


/*------------------------------------------------------------------*/

static MSTATUS
IKE_xauthProcessSet(ubyte **ppoCfgAttrs, ubyte2 *pwCfgAttrsLen,
                    ubyte *poCfgType, ubyte2 wCfgId, struct ikesa *pxSa)
{
    MSTATUS status = OK;
    IKE_XAUTH_requestData *pRequestData = NULL; /* actually SET, not REQUEST */

    if (*pwCfgAttrsLen) /*attributes */
    {
        ikeSettings* is;

        if (OK > (status = IKE_xauthNewUserRequestData(*ppoCfgAttrs,
                                                       *pwCfgAttrsLen,
                                                       wCfgId, pxSa,
                                                       &pRequestData)))
        {
            goto exit;
        }

        /* call the user if there is a message */
        if (pRequestData->data[e_xauth_request_message])
        {
            is = IKE_ikeSettings();
            if (!is->funcPtrInteractWithUser)
            {
                status = ERR_IKE_XAUTH_NO_USER_FUNC;
                goto exit;
            }

            /* we don't provide callback possibilities since there's
               no data requested */
            if (OK > (status =
                      (MSTATUS) is->funcPtrInteractWithUser(pRequestData,
                                 NULL, NULL, NULL, NULL, NULL,
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                                 NULL,
#endif
                                 pRequestData->data[e_xauth_request_message],
                                 pRequestData->data[e_xauth_request_domain],
                                 NULL, pxSa->serverInstance)))
            {
                goto exit;
            }
        }

        if (pRequestData->statusType &&
            /* Draft 3 does not send back 'STATUS' attribute! */
            (3 < pRequestData->verMax))
        {
            ubyte *pBuffer = (ubyte *) MALLOC(4);
            if (NULL == pBuffer)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            IKE_xauthWriteAttrHeader(pBuffer,
                                     (0x8000 | pRequestData->statusType),
                                     0);
            *ppoCfgAttrs = pBuffer;
            *pwCfgAttrsLen = 4;
            *poCfgType = CFG_ACK;
            goto exit;
        }
    }

    *ppoCfgAttrs = NULL;
    *pwCfgAttrsLen = 0;
    *poCfgType = CFG_ACK;

exit:
    if (pRequestData)
    {
        FREE(pRequestData);
    }

    return status;
} /* IKE_xauthProcessSet */


/*------------------------------------------------------------------*/

static MSTATUS
IKE_xauthProcessRequest(ubyte **ppoCfgAttrs, ubyte2 *pwCfgAttrsLen,
                        ubyte *poCfgType, ubyte2 wCfgId, struct ikesa *pxSa,
                        XAUTH_userCallbackFun userCb)
{
    MSTATUS status = OK;
    IKE_XAUTH_requestData *pRequestData = NULL;

    if (*pwCfgAttrsLen) /*attributes */
    {
        ikeSettings* is;
        sbyte** ppUserName;
        sbyte** ppPassword;
        sbyte** ppPassCode;
        sbyte** ppNextPin;
        sbyte** ppAnswer;
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
        sbyte** ppPerp;
#endif
        if (OK > (status = IKE_xauthNewUserRequestData(*ppoCfgAttrs,
                                                       *pwCfgAttrsLen,
                                                       wCfgId, pxSa,
                                                       &pRequestData)))
        {
            goto exit;
        }

        /* call the user */
        is = IKE_ikeSettings();
        ppUserName = &pRequestData->data[e_xauth_request_user_name];
        ppPassword = &pRequestData->data[e_xauth_request_password];
        ppPassCode = &pRequestData->data[e_xauth_request_passcode];
        ppNextPin = &pRequestData->data[e_xauth_request_next_pin];
        ppAnswer = &pRequestData->data[e_xauth_request_answer];
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
        ppPerp = &pRequestData->data[e_xauth_request_perp];
#endif
        if (!is->funcPtrInteractWithUser)
        {
            status = ERR_IKE_XAUTH_NO_USER_FUNC;
            goto exit;
        }

        status = (MSTATUS) is->funcPtrInteractWithUser(pRequestData,
                    ppUserName, ppPassword, ppPassCode,
                    ppNextPin, ppAnswer,
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                    ppPerp,
#endif
                    pRequestData->data[e_xauth_request_message],
                    pRequestData->data[e_xauth_request_domain],
                    userCb, pxSa->serverInstance);
        if (OK <= status)
        {
            if (OK > (status = ProcessUserInput(ppoCfgAttrs, pwCfgAttrsLen,
                                                pRequestData, *ppUserName,
                                                *ppPassword, *ppPassCode,
                                                *ppNextPin, *ppAnswer
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                                              , *ppPerp
#endif
                                                )))
            {
                goto exit;
            }
            *poCfgType = CFG_REPLY;
        }
        else if (STATUS_IKE_PENDING == status)
        {
            pRequestData = NULL; /* so that it's not freed */
            goto exit;
        }
        else /* error */
        {
            goto exit;
        }
    }

exit:
    if (pRequestData)
    {
        FREE(pRequestData);
    }

    return status;
} /* IKE_xauthProcessRequest */


/*------------------------------------------------------------------*/

static MSTATUS
PackAAArequestData(ubyte **ppoCfgAttrs, ubyte2 *pwCfgAttrsLen,
                  IKE_XAUTH_requestData *pRequestData)
{
    MSTATUS status = OK;

    ubyte2 statusType = pRequestData->statusType;
    ubyte2 authType = pRequestData->authType;

    const sbyte* pUsername = pRequestData->data[e_xauth_request_user_name];
    const sbyte* pPassword = pRequestData->data[e_xauth_request_password];
    const sbyte* pPasscode = pRequestData->data[e_xauth_request_passcode];
    const sbyte* pNextPin  = pRequestData->data[e_xauth_request_next_pin];
    const sbyte* pMessage  = pRequestData->data[e_xauth_request_message];
    const sbyte* pDomain   = pRequestData->data[e_xauth_request_domain];
    const sbyte* pChallenge= pRequestData->data[e_xauth_request_challenge];
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    const sbyte* pPerp     = pRequestData->data[e_xauth_request_perp];
    ubyte4 perpLen = 0;
#endif
    ubyte4 usernameLen = 0,
           passwordLen = 0,
           passcodeLen = 0,
           nextPinLen = 0,
           messageLen = 0,
           domainLen = 0,
           challengeLen = pRequestData->challengeLen;

    ubyte *pBuffer = NULL;
    ubyte *pTemp;
    ubyte4 bufferLen = 0;

    if (statusType)
    {
        bufferLen += 4; /* basic length */
    }
    else if (XAUTH_TYPE_OPTIONAL != authType) /* optional since Draft 6 */
    {
        bufferLen += 4; /* basic length */
    }

    if (pUsername)
    {
        usernameLen = DIGI_STRLEN(pUsername);
        if (usernameLen > 0xFFFF)
        {
            status = ERR_IKE_XAUTH_USERNAME_LENGTH;
            goto exit;
        }
        bufferLen += usernameLen + 4;
    }
    if (pPassword)
    {
        passwordLen = DIGI_STRLEN(pPassword);
        if (passwordLen > 0xFFFF)
        {
            status = ERR_IKE_XAUTH_PASSWORD_LENGTH;
            goto exit;
        }
        bufferLen += passwordLen + 4;
    }
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    if (pPerp)
    {
        perpLen = DIGI_STRLEN(pPerp);
        if (perpLen > 0xFFFF)
        {
            status = ERR_IKE_XAUTH_PERP_LENGTH;
            goto exit;
        }
        bufferLen += perpLen + 4;
    }
#endif
    if (pPasscode)
    {
        passcodeLen = DIGI_STRLEN(pPasscode);
        if (passcodeLen > 0xFFFF)
        {
            status = ERR_IKE_XAUTH_PASSWORD_LENGTH;
            goto exit;
        }
        bufferLen += passcodeLen + 4;
    }
    if (pNextPin)
    {
        nextPinLen = DIGI_STRLEN(pNextPin);
        if (nextPinLen > 0xFFFF)
        {
            status = ERR_IKE_XAUTH_NEXT_PIN_LENGTH;
            goto exit;
        }
        bufferLen += nextPinLen + 4;
    }
    if (pMessage)
    {
        messageLen = DIGI_STRLEN(pMessage);
        if (messageLen > 0xFFFF)
        {
            status = ERR_IKE_XAUTH_MESSAGE_LENGTH;
            goto exit;
        }
        bufferLen += messageLen + 4;
    }
    if (pDomain)
    {
        domainLen = DIGI_STRLEN(pDomain);
        if (domainLen > 0xFFFF)
        {
            status = ERR_IKE_XAUTH_DOMAIN_LENGTH;
            goto exit;
        }
        bufferLen += domainLen + 4;
    }

    if (pChallenge)
    {
        bufferLen += challengeLen + 4;
    }

    if (bufferLen > 0xFFFF)
    {
        status = ERR_IKE_XAUTH_USERDATA_LENGTH;
        goto exit;
    }

    pBuffer = (ubyte *) MALLOC(bufferLen);
    if (NULL == pBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* fill the buffer */
    pTemp = pBuffer;

    if (statusType)
    {
        pTemp = IKE_xauthWriteAttrHeader(pTemp, (0x8000 | statusType),
                                         authType); /* overloaded */
    }
    else if (XAUTH_TYPE_OPTIONAL != authType) /* optional since Draft 6 */
    {
        pTemp = IKE_xauthWriteAttrHeader(pTemp, (0x8000 | XAUTH_TYPE),
                                         authType);
    }

    if (pUsername)
    {
        pTemp = IKE_xauthWriteAttrString(pTemp, XAUTH_USER_NAME,
                                         (ubyte2)usernameLen, pUsername);
    }
    if (pPassword)
    {
        pTemp = IKE_xauthWriteAttrString(pTemp, XAUTH_USER_PASSWORD,
                                         (ubyte2)passwordLen, pPassword);
    }
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    if (pPerp)
    {
        pTemp = IKE_xauthWriteAttrString(pTemp, XAUTH_MOCANA_PERP,
                                         (ubyte2)perpLen, pPerp);
    }
#endif
    if (pPasscode)
    {
        pTemp = IKE_xauthWriteAttrString(pTemp, XAUTH_PASSCODE,
                                         (ubyte2)passcodeLen, pPasscode);
    }
    if (pNextPin)
    {
        pTemp = IKE_xauthWriteAttrString(pTemp, XAUTH_NEXT_PIN,
                                         (ubyte2)nextPinLen, pNextPin);
    }
    if (pMessage)
    {
        pTemp = IKE_xauthWriteAttrString(pTemp, XAUTH_MESSAGE,
                                         (ubyte2)messageLen, pMessage);
    }
    if (pDomain)
    {
        pTemp = IKE_xauthWriteAttrString(pTemp, XAUTH_DOMAIN,
                                         (ubyte2)domainLen, pDomain);
    }
    if (pChallenge)
    {
        pTemp = IKE_xauthWriteAttrString(pTemp, XAUTH_CHALLENGE,
                                         (ubyte2)challengeLen, pChallenge);
    }

    *ppoCfgAttrs = pBuffer;
    pBuffer = NULL;
    *pwCfgAttrsLen = (ubyte2) bufferLen;

exit:
    if (pBuffer)
    {
        FREE(pBuffer);
    }

    return status;
} /* PackAAArequestData */


/*------------------------------------------------------------------*/

static MSTATUS
ProcessAAAresult(IKESA pxSa, ubyte2 wCfgId,
                 IKE_XAUTH_requestData *pRequestData, /* actually REPLY or new */
                 ubyte oCfgType, ubyte2 wResult, IKE_context pxCtx)
{
    MSTATUS status;

    ubyte *poCfgAttrs = NULL;
    ubyte2 wCfgAttrsLen = 0;

    P2XG pxXg = NULL;
    struct ike_context ctx = { NULL };

    if (NULL == pxCtx) pxCtx = &ctx;

    switch (oCfgType)
    {
    case CFG_SET :
        /* Need to build an CFG_SET, STATUS = OK or FAIL, based on AAA result */
        pRequestData->statusType = XAUTH_STATUS;

        /* overloading 'authType' for auth result! */
        if (XAUTH_STATUS_OK == wResult)
        {
            pRequestData->authType = XAUTH_STATUS_OK; /* Pass */
            pxSa->merror = OK; /* jic */
        }
        else
        {
            pRequestData->authType = XAUTH_STATUS_FAIL; /* Fail */
            pxSa->merror = ERR_IKE_XAUTH_FAILED;
        }
        break;

    case CFG_REQUEST :
        /* (Multiple) CFG_REQUEST/REPLY exchanges */
        pRequestData->statusType = 0; /* !!! */
        pRequestData->authType = wResult;
        break;

    default :
        status = ERR_IKE_XAUTH_INVALID_CFG_TYPE;
        goto exit;
    }

    /* genereate attributes for next CFG_{REQUEST|SET} */
    if (OK > (status = PackAAArequestData(&poCfgAttrs, &wCfgAttrsLen,
                                          pRequestData)))
    {
        goto exit;
    }

    /* new exchange with unique Message ID; for > draft-04 */
    if (OK > (status = IKE_newXchg(pxSa, 0, &pxXg)))
    {
        goto exit;
    }

    pxXg->oState       = (CFG_SET == oCfgType) ? STATE_CFG_I2x : STATE_CFG_I1x;
    pxXg->oCfgType     = oCfgType;
    pxXg->wCfgId       = wCfgId; /* same 'Configuration' ID */
    pxXg->poCfgAttrs   = poCfgAttrs;
    pxXg->wCfgAttrsLen = wCfgAttrsLen;

    debug_print("   ");
    debug_print_ike_cfgtype(oCfgType);
    if (wCfgId)
    {
        debug_print(" #");
        debug_int(wCfgId);
    }
    debug_printnl(NULL);
    debug_print_ike_cfg_attrs(poCfgAttrs, wCfgAttrsLen, (sbyte *)"    ", TRUE);

    /* send it to the IKE engine */
    pxCtx->pxSa = pxSa;
    pxCtx->pxP2Xg = pxXg;
    status = IKE_xchgOut(pxCtx);

    poCfgAttrs = NULL; /* will be freed by IKE */

exit:
    if (poCfgAttrs)
    {
        FREE(poCfgAttrs);
    }
    return status;
} /* ProcessAAAresult */


/*------------------------------------------------------------------*/

static MSTATUS
XauthAAACallback(IKE_XAUTH_requestData *pRequestData,
                 ubyte oCfgType, ubyte2 wResult)
{
    MSTATUS status;

    IKESA pxSa = NULL;
    P2XG pxXg = NULL;

#ifdef __IKE_MULTI_THREADED__
    union dpcData data;
    data.aaa.oCfgType = oCfgType;
    data.aaa.wResult = wResult;
#endif

    IKE_LOCK_R; /* !!! */

    /* find pending exchange */
    if (OK > (status = IKE_xauthGetXchg(pRequestData, STATE_CFG_I2xc,
#ifdef __IKE_MULTI_THREADED__
                                        &data,
#endif
                                        &pxSa, &pxXg)))
    {
#ifdef __IKE_MULTI_THREADED__
        if (STATUS_IKE_PENDING == status)
        {
            pRequestData = NULL; /* !!! */
        }
#endif
        goto exit;
    }

    /* initiate next exchange */
    if (OK <= (status = ProcessAAAresult(pxSa, pxXg->wCfgId, pRequestData,
                                         oCfgType, wResult, NULL)))
    {
        /* advance exchange to final state */
        pxXg->oState = STATE_CFG_Ixc;
    }

exit:
    if (NULL != pxXg)
    {
        /* delete exchange */
        IKE_delXchg(pxXg, pxSa, status);

        if (OK > status) /* error */
        {
            IKE_delSa(pxSa, TRUE, status);
        }
    }

    /* done with the IKE_XAUTH_requestData */
#ifdef __IKE_MULTI_THREADED__
    if (pRequestData)
#endif
    {
        FREE(pRequestData);
    }
    IKE_UNLOCK_R;
    return status;
} /* XauthAAACallback */


/*------------------------------------------------------------------*/

static sbyte4
IKE_xauthAAACallback(void *connectionInstance,
                     const sbyte *userName, const sbyte *password,
                     const sbyte *passCode, const sbyte *nextPin,
                     const sbyte *message, const sbyte *domain,
                     const sbyte *challenge, ubyte2 challengeLen,
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                     const sbyte *perp,
#endif
                     ubyte oCfgType, ubyte2 wResult)
{
    MSTATUS status;

    /* this is the function call after the AAA server has provided the info */
    IKE_XAUTH_requestData *pRequestData; /* actually REPLY */

    if (0 == connectionInstance)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pRequestData = (IKE_XAUTH_requestData *)connectionInstance;

    /* set attributes */
    pRequestData->data[e_xauth_request_user_name]   = (sbyte *)userName;
    pRequestData->data[e_xauth_request_password]    = (sbyte *)password;
    pRequestData->data[e_xauth_request_passcode]    = (sbyte *)passCode;
    pRequestData->data[e_xauth_request_next_pin]    = (sbyte *)nextPin;
    pRequestData->data[e_xauth_request_message]     = (sbyte *)message;
    pRequestData->data[e_xauth_request_domain]      = (sbyte *)domain;
    pRequestData->data[e_xauth_request_challenge]   = (sbyte *)challenge;
    pRequestData->challengeLen = challengeLen;
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    pRequestData->data[e_xauth_request_perp]        = (sbyte *)perp;
#endif

    status = XauthAAACallback(pRequestData, oCfgType, wResult);

exit:
    return (sbyte4)status;
} /* IKE_xauthAAACallback */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_xauthProcessReply(ubyte *poCfgAttrs, ubyte2 wCfgAttrsLen,
                      IKESA pxSa, P2XG pxXg)
{
    /* Note: For AAA only */
    MSTATUS status;

    IKE_XAUTH_requestData *pRequestData = NULL; /* actually REPLY, not REQUEST */

    ikeSettings *is;
    sbyte **ppUserName;
    sbyte **ppPassword;
    sbyte **ppPassCode;
    sbyte **ppMessage;
    sbyte **ppChallenge;
    sbyte **ppDomain;
    sbyte **ppNextPin;
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    sbyte **ppPerp;
#endif
    sbyte  *pAnswer;

    ubyte oCfgType = CFG_REPLY;
    ubyte2 wResult = 0;

    if (OK > (status = IKE_xauthNewUserRequestData(poCfgAttrs, wCfgAttrsLen,
                                                   pxXg->wCfgId, pxSa,
                                                   &pRequestData)))
    {
        goto exit;
    }

    if ((ubyte)6 > pRequestData->verMin)
    {
        /* draft-ietf-ipsec-isakmp-xauth-06 or higher */
        status = ERR_IKE_XAUTH_DRAFT_VERSION;
        goto exit;
    }

    /* See "draft-beaulieu-ike-xauth-02.txt" 5.
     "...                    or when the remote device sends a
      XAUTH_STATUS attribute in a REPLY message.  Please note that a
      remote device can not set XAUTH_STATUS to anything but FAIL."
     */
    if (pRequestData->statusType)
    {
        status = /* !!! */
        pxSa->merror = ERR_IKE_XAUTH_FAILED;
        goto exit;
    }

    /* call the AAA subsystem */
    is = IKE_ikeSettings();

    ppUserName = &pRequestData->data[e_xauth_request_user_name];
    ppPassword = &pRequestData->data[e_xauth_request_password];
    ppPassCode = &pRequestData->data[e_xauth_request_passcode];
    ppMessage  = &pRequestData->data[e_xauth_request_message];
    ppChallenge= &pRequestData->data[e_xauth_request_challenge];
    ppDomain   = &pRequestData->data[e_xauth_request_domain];
    ppNextPin  = &pRequestData->data[e_xauth_request_next_pin];
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    ppPerp     = &pRequestData->data[e_xauth_request_perp];
#endif
    pAnswer    = pRequestData->data[e_xauth_request_answer];

    if (!is->funcPtrInteractWithAAA)
    {
        status = ERR_IKE_XAUTH_NO_USER_FUNC;
        goto exit;
    }

    status = (MSTATUS) is->funcPtrInteractWithAAA(pRequestData,
                                                  pxXg->wCfgId,
                                                  ppUserName,
                                                  ppPassword,
                                                  pRequestData->passwordLen,
                                                  ppPassCode,
                                                  ppNextPin,
                                                  pAnswer,
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                                                  ppPerp,
#endif
                                                  ppMessage,
                                                  ppDomain,
                                                  ppChallenge,
                                                  &pRequestData->challengeLen,
                                                  &oCfgType,
                                                  &wResult,
                                                  IKE_xauthAAACallback,
                                                  pxSa->serverInstance);

    /* If not pending then AAA returned PASS/FAIL synchronously */
    if (OK > status)
    {
        if (STATUS_IKE_PENDING == status)
        {
            pxXg->x_flags |= IKE_XCHG_FLAG_PENDING;
            pxSa->merror = STATUS_IKE_PENDING;
            pRequestData = NULL; /* so that it's not freed */
        }
        goto exit;
    }

    /* initiate next exchange */
    status = ProcessAAAresult(pxSa, pxXg->wCfgId, pRequestData,
                              oCfgType, wResult, NULL);

exit:
    if (pRequestData)
    {
        FREE(pRequestData);
    }
    return status;
} /* IKE_xauthProcessReply */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_xauthAAAInit(IKESA pxSa, IKE_context pxCtx)
{
    MSTATUS status;

    ikeSettings *is = IKE_ikeSettings();

    IKE_XAUTH_requestData requestData = { 0 };
    sbyte **ppUserName = &requestData.data[e_xauth_request_user_name];
    sbyte **ppPassword = &requestData.data[e_xauth_request_password];
    sbyte **ppPassCode = &requestData.data[e_xauth_request_passcode];
    sbyte **ppMessage  = &requestData.data[e_xauth_request_message];
    sbyte **ppChallenge= &requestData.data[e_xauth_request_challenge];
    sbyte **ppDomain   = &requestData.data[e_xauth_request_domain];
    sbyte **ppNextPin  = &requestData.data[e_xauth_request_next_pin];
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
    sbyte **ppPerp     = &requestData.data[e_xauth_request_perp];
#endif
    ubyte2 wCfgId = (pxSa->u.v1.wCfgId)++;
    ubyte oCfgType = 0;
    ubyte2 wResult = 0;

    /* call the AAA subsystem */
    if (!is->funcPtrInteractWithAAA)
    {
        status = ERR_IKE_XAUTH_NO_USER_FUNC;
        goto exit;
    }

    requestData.ikeSaId = pxSa->dwId;
    requestData.ikeSaLoc = pxSa->loc;
    requestData.wCfgId = wCfgId;

    if (OK > (status = (MSTATUS)
                       is->funcPtrInteractWithAAA(&requestData,
                                                  wCfgId,
                                                  ppUserName,
                                                  ppPassword,
                                                  0,
                                                  ppPassCode,
                                                  ppNextPin,
                                                  NULL,
#ifdef __ENABLE_DIGICERT_XAUTH_PERP__
                                                  ppPerp,
#endif
                                                  ppMessage,
                                                  ppDomain,
                                                  ppChallenge,
                                                  &requestData.challengeLen,
                                                  &oCfgType,
                                                  &wResult,
                                                  NULL,
                                                  pxSa->serverInstance)))
    {
        goto exit;
    }

    /* initiate XAUTH exchange */
    status = ProcessAAAresult(pxSa, wCfgId, &requestData,
                              oCfgType, wResult, pxCtx);

exit:
    return status;
} /* IKE_xauthAAAInit */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_xauthProcess(ubyte **ppoCfgAttrs, ubyte2 *pwCfgAttrsLen,
                 ubyte *poCfgType, ubyte2 wCfgId, struct ikesa *pxSa)
{
    MSTATUS status;

    if (!ppoCfgAttrs || !pwCfgAttrsLen || !poCfgType || !pxSa)
        return ERR_NULL_POINTER;

    /* ppoCfgAttrs is pointing to the blob of ikeCfgAttrHdr;
    it must not be null if its length is > 0 */
    if (*pwCfgAttrsLen && !*ppoCfgAttrs)
        return ERR_NULL_POINTER;

    switch (*poCfgType)
    {
    case CFG_REQUEST:
        status = IKE_xauthProcessRequest(ppoCfgAttrs, pwCfgAttrsLen, poCfgType, wCfgId, pxSa,
                                         IKE_xauthUserCallback);
        break;

    case CFG_SET:
        status = IKE_xauthProcessSet(ppoCfgAttrs, pwCfgAttrsLen, poCfgType, wCfgId, pxSa);
        break;

    default:
        status = ERR_IKE_XAUTH_INVALID_CFG_TYPE;
        goto exit;
    }

exit:
    return status;
} /* IKE_xauthProcess */


/*------------------------------------------------------------------*/

#ifdef __IKE_MULTI_THREADED__
extern sbyte4
IKE_dpcXauthCallback(IKE_DPC_XAUTH_CB cb, ubyte4 cbSize)
{
    MSTATUS status = OK;

    if ((sizeof(struct dpcXauthCB) <= cbSize) &&
        (sizeof(struct dpcXauthCB) == cb->hdr.dpc_len) &&
        ((IKE_dpcFunc)IKE_dpcXauthCallback == cb->hdr.dpc_func) &&
        cb->pRequestData /* jic */)
    {
        if (0 == cb->type) /* AAA */
        {
            status = XauthAAACallback(cb->pRequestData,
                                      cb->data.aaa.oCfgType,
                                      cb->data.aaa.wResult);
        }
        else if (1 == cb->type) /* User */
        {
            status = XauthUserCallback(cb->pRequestData,
                                       cb->data.user.poCfgAttrs,
                                       cb->data.user.wCfgAttrsLen);
        }
    }
    return (sbyte4)status;
} /* IKE_dpcXauthAAACallback */
#endif


#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) && defined(__ENABLE_IKE_XAUTH__) */


