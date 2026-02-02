/*
 * http_client_auth.c
 *
 * HTTP Client Authentication
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_HTTP_CLIENT__) || defined(__ENABLE_DIGICERT_HTTPCC_SERVER__))

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/base64.h"
#include "../crypto/md5.h"
#include "../http/http_context.h"
#include "../http/http_common.h"
#include "../http/http.h"
#include "../http/http_auth.h"

#define BASICSTR    ((sbyte*)"Basic")
#define DIGESTSTR   ((sbyte*)"Digest")

/* Note: paramNames and paramNameStrs must be in the same order */
typedef enum
{
    REALM, DOMAIN, NONCE, OPAQUE, STALE, ALGORITHM, QOP,
    NC, CNONCE, USERNAME, URI, RESPONSE
} paramNames;

static sbyte* paramNameStrs[] = {
    (sbyte*)"realm", (sbyte*)"domain", (sbyte*)"nonce", (sbyte*)"opaque", (sbyte*)"stale", (sbyte*)"algorithm", (sbyte*)"qop",
    (sbyte*)"nc", (sbyte*)"cnonce", (sbyte*)"username", (sbyte*)"uri", (sbyte*)"response"
};

typedef struct paramValue
{
    ubyte* value;
    ubyte4 length;
} paramValue;

typedef struct paramValue *paramValuePTR;
static MSTATUS
releaseParamValues(paramValuePTR *ppParamValues);

/*------------------------------------------------------------------*/

static void getChallengeOrAuthorization(httpContext *pHttpContext, ubyte **ppChOrAuth, ubyte4* pChOrAuthLength)
{
    ubyte4 index, index1, index2;
    ubyte *headerBitmask;
    HTTP_stringDescr *headers;

    /* init */
    *ppChOrAuth = NULL;
    *pChOrAuthLength = 0;

    if (pHttpContext->roleType == HTTP_CLIENT)
    {
        index1 = WWWAuthenticate; index2 = ProxyAuthenticate;
        headerBitmask = pHttpContext->responseBitmask;
        headers = pHttpContext->responses;

    } else
    {
        index1 = Authorization; index2 = ProxyAuthorization;
        headerBitmask = pHttpContext->requestBitmask;
        headers = pHttpContext->requests;
    }
    if (headerBitmask[index1 / 8] & (1 << (index1 & 7)))
    {
        /* WWW_Authenticate or Authorization is defined */
        index = index1;
    }
    else if (headerBitmask[index2 / 8] & (1 << (index2 & 7)))
    {
        /* Proxy_Authenticate or ProxyAuthorization is defined */
        index = index2;
    }
    else
    {
        goto exit;
    }
    *ppChOrAuth = headers[index].pHttpString;
    *pChOrAuthLength = headers[index].httpStringLength;
exit:
    return;
}

/*------------------------------------------------------------------*/

static void getScheme(ubyte *pChallenge, ubyte4 challengeLength, httpAuthScheme *pScheme)
{
    if (HTTP_COMMON_subStringMatch(pChallenge, challengeLength, BASICSTR, DIGI_STRLEN(BASICSTR)))
    {
        *pScheme = BASIC;
    }
    else if (HTTP_COMMON_subStringMatch(pChallenge, challengeLength, DIGESTSTR, DIGI_STRLEN(DIGESTSTR)))
    {
        *pScheme = DIGEST;
    }
    else
    {
        *pScheme = UNKNOWN;
    }
}

/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_AUTH_generateBasicAuthorization(httpContext *pHttpContext,
                            ubyte *pUsername, ubyte4 userNameLength,
                            ubyte *pPassword, ubyte4 passwordLength,
                            ubyte **ppRetAuthString, ubyte4 *pRetAuthStringLength)
{
    MSTATUS status = OK;
    sbyte* schemeStr = BASICSTR;
    ubyte4 schemeStrLen = DIGI_STRLEN(BASICSTR);
    /* ywang: used *3 here. check how much bigger b64 encoding result will be */
    ubyte*  pString = MALLOC(schemeStrLen + 1 + (userNameLength + 1 + passwordLength)*3);
    ubyte* cred = NULL;
    ubyte4 credLen;

    if (NULL == pString)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pString, pUsername, userNameLength);
    pString[userNameLength] = ':';
    DIGI_MEMCPY(userNameLength + 1 + pString, pPassword, passwordLength);

    status = BASE64_encodeMessage(pString, userNameLength + 1 + passwordLength,
                                  &cred, &credLen);

    DIGI_MEMCPY(pString, schemeStr, schemeStrLen);
    DIGI_MEMCPY(pString+schemeStrLen, " ", 1);
    DIGI_MEMCPY(pString+schemeStrLen+1, cred, credLen);
    *ppRetAuthString = pString;
    *pRetAuthStringLength = schemeStrLen + 1 + credLen;
exit:
    pString = NULL;
    if (cred)
    {
        BASE64_freeMessage(&cred);
    }
    return status;
}

/*------------------------------------------------------------------*/
/* check name against paramNameStrs and return one paramNames */
static MSTATUS
checkName(ubyte* pData, ubyte4 length, ubyte4 *pName)
{
    MSTATUS status = OK;
    ubyte4 i;
    *pName = -1;
    for ( i = 0; i < sizeof(paramNameStrs)/sizeof(paramNameStrs[0]); i++)
    {
        if (HTTP_COMMON_subStringMatch(pData, length, paramNameStrs[i], DIGI_STRLEN(paramNameStrs[i])))
        {
            *pName = i;
            break;
        }
    }
    return status;
}

static MSTATUS
initParamValues(paramValuePTR **pppParamValues)
{
    MSTATUS status = OK;
    ubyte4 i;

    *pppParamValues = (paramValuePTR*)MALLOC(sizeof(paramValuePTR)*sizeof(paramNameStrs)/sizeof(ubyte*));
    if (!(*pppParamValues))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    for (i = 0; i < sizeof(paramNameStrs)/sizeof(ubyte*); i++)
    {
        (*pppParamValues)[i] = (paramValuePTR)MALLOC(sizeof(paramValue));
        if (!(*pppParamValues)[i])
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        /* initialize buffer */
        DIGI_MEMSET((ubyte*)(*pppParamValues)[i], 0, sizeof(paramValue));
    }
exit:
    if((OK > status) && *pppParamValues)
    {
        releaseParamValues(*pppParamValues);
        *pppParamValues = NULL;
    }
    return status;
}

static MSTATUS
releaseParamValues(paramValuePTR *ppParamValues)
{
    if (ppParamValues)
    {
        ubyte4 i;
        for (i = 0; i < sizeof(paramNameStrs)/sizeof(ubyte*); i++)
        {
            if (ppParamValues[i]->value)
            {
                FREE(ppParamValues[i]->value);
            }
            FREE(ppParamValues[i]);
        }
        FREE(ppParamValues);
    }
    return OK;
}

/*------------------------------------------------------------------*/
static MSTATUS
parseDigestParameters(ubyte* pChOrResp, ubyte4 chOrRespLength, paramValue **ppParamValues)
{
    MSTATUS status = OK;
    ubyte4 start = 0, length = 0;
    ubyte* pValue;
    ubyte4 name  = 0;
    ubyte4 offset = 0;
    sbyte ch;
    intBoolean expectName = TRUE;

    /* bypass scheme+" " */
    offset = offset + DIGI_STRLEN(DIGESTSTR) + 1;
    start = offset;
    /* parameters are a superset of digest-challenge and digest_response:
             digest-challenge  = 1#( realm | [ domain ] | nonce |
                          [ opaque ] |[ stale ] | [ algorithm ] |
                          [ qop-options ] | [auth-param] )
             digest-response  = 1#( username | realm | nonce | digest-uri
                       | response | [ algorithm ] | [cnonce] |
                       [opaque] | [message-qop] |
                           [nonce-count]  | [auth-param] )

    */
    while (offset < chOrRespLength)
    {
        ch = *(pChOrResp+offset);
        if (DIGI_ISLWS(ch))
        {
            if (length == 0)
            {
                start++;
            }
            else
            {
                length++;
            }
        }
        else if ( ch == '=' && expectName)
        {
            expectName = FALSE;
            checkName(pChOrResp+start, length, &name);
            start = offset + 1;
            length = 0;
        } else if ( (offset == chOrRespLength - 1) || (ch == ','))
        {
            ubyte4 quote = 0;
            expectName = TRUE;
            if (offset == chOrRespLength - 1 && ch != ',')
            {
                length++;
            }
            /* save value only for known and unset params */
            if (ppParamValues[name]->length > 0)
                continue;
            /* release memory when done with pParamValues;
             * if there are multiple values for qop, for instance,
             * we will only record and use the first one */
            /* 2 accounts for the quotes "" */
            if ( '\"' == *(pChOrResp+start))
            {
                quote = 2;
            }
            pValue = (ubyte*)MALLOC(length-quote);
            DIGI_MEMCPY(pValue, pChOrResp+start+ (quote? 1 : 0), length-quote);

            ppParamValues[name]->value = pValue;
            ppParamValues[name]->length = length-quote;

            start = offset + 1;
            length = 0;
        } else
        {
            /* either part of name or part of vlaue */
            length++;
        }
        offset++;
    }

    return status;
}

static MSTATUS
appendQuote(ubyte *pRetBuffer, ubyte4 *runningLength)
{
    DIGI_MEMCPY(pRetBuffer+(*runningLength), "\"", 1);
    *runningLength += 1;
    return OK;
}

static MSTATUS
appendParam(ubyte *pRetBuffer, ubyte4 *runningLength,
             const sbyte* name, ubyte4 nameLen,
             const ubyte* value, ubyte4 valueLen, intBoolean shouldQuote)
{
    DIGI_MEMCPY(pRetBuffer+(*runningLength), name, nameLen);
    *runningLength += nameLen;

    DIGI_MEMCPY(pRetBuffer+(*runningLength), "=", 1);
    *runningLength += 1;

    if (shouldQuote)
    {
        appendQuote(pRetBuffer, runningLength);
    }

    DIGI_MEMCPY(pRetBuffer+(*runningLength), value, valueLen);
    *runningLength += valueLen;

    if (shouldQuote)
    {
        appendQuote(pRetBuffer, runningLength);
    }

    return OK;
}

static MSTATUS
appendEnd(ubyte *pRetBuffer, ubyte4 *runningLength)
{
    DIGI_MEMCPY(pRetBuffer+(*runningLength), ", ", 2);
    *runningLength += 2;
    return OK;
}

static MSTATUS
appendSp(ubyte *pRetBuffer, ubyte4 *runningLength)
{
    DIGI_MEMCPY(pRetBuffer+(*runningLength), " ", 1);
    *runningLength += 1;
    return OK;
}

static void
convertDigestToString(ubyte* src, ubyte* dst)
{
    ubyte4 i;

    for (i = 0; i < MD5_DIGESTSIZE; i++)
    {
        dst[2 * i]       = returnHexDigit((ubyte4)((src[i] >> 4) & 0x0f));
        dst[1 + (2 * i)] = returnHexDigit((ubyte4)(src[i] & 0x0f));
    }
}

static MSTATUS
calculateDigest(httpContext *pHttpContext, paramValue **ppParamValues,
                             ubyte *pUserName, ubyte4 userNameLength,
                             ubyte *pPassword, ubyte4 passwordLength,
                             intBoolean isHA1,
                             ubyte *pDigest)
{
    MD5_CTX         md5Ctx;
    ubyte*          ha1, ha2[MD5_DIGESTSIZE], digest[MD5_DIGESTSIZE];
    ubyte           buf[2*MD5_DIGESTSIZE];
    hwAccelDescr    hwAccelCookie;
    MSTATUS         status = OK;

    MOC_UNUSED(hwAccelCookie);
    /* calculating request-digest */

    /* assuming qop is auth or auth-int
     request-digest  = <"> < KD ( H(A1),     unq(nonce-value)
                                          ":" nc-value
                                          ":" unq(cnonce-value)
                                          ":" unq(qop-value)
                                          ":" H(A2)
                                  ) <">
    when algorithm == MD5 or unspecified
    A1       = unq(username-value) ":" unq(realm-value) ":" passwd
    when qop == auth or unspecified
    A2       = Method ":" digest-uri-value
    when qop == auth-int
    A2       = Method ":" digest-uri-value ":" H(entity-body)
    */
    /* H(A1) for MD5 or unspecified algo */

    if (isHA1)
    {
        ha1 = pPassword;
    } else
    {
        if (NULL == (ha1 = MALLOC(MD5_DIGESTSIZE)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        if (OK > (status = MD5Init_m(MOC_HASH(hwAccelCookie) &md5Ctx)))
            goto exit;

        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, pUserName, userNameLength)))
            goto exit;

        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, (ubyte *)(":"), 1)))
            goto exit;

        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, ppParamValues[REALM]->value, ppParamValues[REALM]->length)))
            goto exit;

        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, (ubyte *)(":"), 1)))
            goto exit;

        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, pPassword, passwordLength)))
            goto exit;

        if (OK > (status = MD5Final_m(MOC_HASH(hwAccelCookie) &md5Ctx, ha1)))
            goto exit;
    }
    /* H(A2) */
    if (OK > (status = MD5Init_m(MOC_HASH(hwAccelCookie) &md5Ctx)))
        goto exit;

    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, (ubyte*)pHttpContext->pMethodDescr->pHttpMethodName, pHttpContext->pMethodDescr->httpMethodNameLength)))
        goto exit;

    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, (ubyte *)(":"), 1)))
        goto exit;

    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, (ubyte *)pHttpContext->pURI, DIGI_STRLEN(pHttpContext->pURI))))
        goto exit;

    /* no support for now
    if (qop == auth_int)
    {
        if (OK > (status = MD5Update_m(&md5Ctx, (ubyte *)(":"), 1)))
            goto exit;

        if (OK > (status = MD5Update_m(&md5Ctx, entityBodyDigest, entityBodyDigestLength)))
            goto exit;
    }
    */
    if (OK > (status = MD5Final_m(MOC_HASH(hwAccelCookie) &md5Ctx, ha2)))
        goto exit;

    /* calculate request-digest */

    if (OK > (status = MD5Init_m(MOC_HASH(hwAccelCookie) &md5Ctx)))
        goto exit;

    convertDigestToString(ha1, buf);

    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, buf, 2*MD5_DIGESTSIZE)))
        goto exit;

    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, (ubyte *)(":"), 1)))
        goto exit;

    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, ppParamValues[NONCE]->value, ppParamValues[NONCE]->length)))
        goto exit;

    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, (ubyte *)(":"), 1)))
        goto exit;
    if (ppParamValues[QOP]->length > 0)
    {
        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, ppParamValues[NC]->value, ppParamValues[NC]->length)))
            goto exit;

        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, (ubyte *)(":"), 1)))
            goto exit;

        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, ppParamValues[CNONCE]->value, ppParamValues[CNONCE]->length)))
            goto exit;

        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, (ubyte *)(":"), 1)))
            goto exit;

        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, ppParamValues[QOP]->value, ppParamValues[QOP]->length)))
            goto exit;

        if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, (ubyte *)(":"), 1)))
            goto exit;
    }
    convertDigestToString(ha2, buf);
    if (OK > (status = MD5Update_m(MOC_HASH(hwAccelCookie) &md5Ctx, buf, 2*MD5_DIGESTSIZE)))
        goto exit;

    if (OK > (status = MD5Final_m(MOC_HASH(hwAccelCookie) &md5Ctx, digest)))
        goto exit;

    /* finalize the request-digest */
    convertDigestToString(digest, pDigest);
exit:
    if (!isHA1 && ha1)
    {
        FREE(ha1);
    }
    return status;
    }

/*------------------------------------------------------------------*/

static MSTATUS
generateDigestAuthorization(httpContext *pHttpContext, paramValue **ppParamValues,
                             ubyte *pUserName, ubyte4 userNameLength,
                             ubyte *pPassword, ubyte4 passwordLength,
                             intBoolean isHA1,
                             ubyte **ppRetAuthString, ubyte4 *pRetAuthStringLength)
{
    sbyte* schemeString = DIGESTSTR;
    ubyte4 schemeStringLength = DIGI_STRLEN(DIGESTSTR);
    ubyte  digestBuffer[MD5_DIGESTSIZE*2];
    ubyte* pRetBuffer;
    MSTATUS status = ERR_MEM_ALLOC_FAIL;
    ubyte4 runningLength = 0;

    /* ywang: assuming 512 is enough. can we be more precise? */
    /* memory released by caller */
    if (NULL == (pRetBuffer = MALLOC(512)))
        goto exit;

    /* scheme */
    DIGI_MEMCPY(pRetBuffer, schemeString, schemeStringLength);
    runningLength = runningLength + schemeStringLength;
    appendSp(pRetBuffer, &runningLength);

    /* username */
    appendParam(pRetBuffer, &runningLength, paramNameStrs[USERNAME], DIGI_STRLEN(paramNameStrs[USERNAME]), pUserName, userNameLength, TRUE);
    appendEnd(pRetBuffer, &runningLength);

    /* realm */
    appendParam(pRetBuffer, &runningLength, paramNameStrs[REALM], DIGI_STRLEN(paramNameStrs[REALM]),
        ppParamValues[REALM]->value, ppParamValues[REALM]->length, TRUE);
    appendEnd(pRetBuffer, &runningLength);

    /* nonce */
    appendParam(pRetBuffer, &runningLength, paramNameStrs[NONCE], DIGI_STRLEN(paramNameStrs[NONCE]),
        ppParamValues[NONCE]->value, ppParamValues[NONCE]->length, TRUE);
    appendEnd(pRetBuffer, &runningLength);

    /* digest-uri */
    appendParam(pRetBuffer, &runningLength, paramNameStrs[URI], DIGI_STRLEN(paramNameStrs[URI]),
        (ubyte *)pHttpContext->pURI, DIGI_STRLEN(pHttpContext->pURI), TRUE);
    appendEnd(pRetBuffer, &runningLength);

    if (OK > (status = calculateDigest(pHttpContext, ppParamValues, pUserName, userNameLength, pPassword, passwordLength, isHA1, digestBuffer)))
        goto exit;

    /* response */
    appendParam(pRetBuffer, &runningLength, paramNameStrs[RESPONSE], DIGI_STRLEN(paramNameStrs[RESPONSE]),
        digestBuffer, 2*MD5_DIGESTSIZE, TRUE);

    if (ppParamValues[QOP]->length > 0)
    {
        appendEnd(pRetBuffer, &runningLength);

        /* cnonce value */
        appendParam(pRetBuffer, &runningLength, paramNameStrs[CNONCE], DIGI_STRLEN(paramNameStrs[CNONCE]),
            ppParamValues[CNONCE]->value, ppParamValues[CNONCE]->length, TRUE);
        appendEnd(pRetBuffer, &runningLength);

        /* nc value, no quote */
        appendParam(pRetBuffer, &runningLength, paramNameStrs[NC], DIGI_STRLEN(paramNameStrs[NC]),
            ppParamValues[NC]->value, ppParamValues[NC]->length, FALSE);
        appendEnd(pRetBuffer, &runningLength);

        /* qop value */
        appendParam(pRetBuffer, &runningLength, paramNameStrs[QOP], DIGI_STRLEN(paramNameStrs[QOP]),
            ppParamValues[QOP]->value, ppParamValues[QOP]->length, FALSE);
    }

    if (ppParamValues[OPAQUE]->length > 0)
    {
        appendEnd(pRetBuffer, &runningLength);
        appendParam(pRetBuffer, &runningLength, paramNameStrs[OPAQUE], DIGI_STRLEN(paramNameStrs[OPAQUE]),
            ppParamValues[OPAQUE]->value, ppParamValues[OPAQUE]->length, TRUE);
    }

    *pRetAuthStringLength = runningLength;
    *ppRetAuthString = pRetBuffer;
    pRetBuffer = NULL;

exit:
    if (status < OK && NULL != pRetBuffer)
        FREE(pRetBuffer);

    return status;
}


/*------------------------------------------------------------------*/
/* returns the index to either Authorization or Proxy-Authorization header
 * as well as the scheme + credential string */
extern MSTATUS
HTTP_AUTH_generateAuthorization(httpContext *pHttpContext, ubyte4 *pIndex,
                            ubyte **ppRetAuthString, ubyte4 *pRetAuthStringLength)
{
    MSTATUS status = OK;
    ubyte* pChallenge;
    ubyte4 challengeLength;
    ubyte *pUser, *pPassword;
    ubyte4 userLength, passwordLength;
    intBoolean isHA1 = FALSE;
    httpAuthScheme scheme;
    ubyte* pCredential = NULL;
    ubyte4 credentialLength = 0;
    paramValue **ppParamValues = NULL;

    if ((NULL == ppRetAuthString) || (NULL == pRetAuthStringLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    getChallengeOrAuthorization(pHttpContext, &pChallenge, &challengeLength);
    if (NULL == pChallenge)
    {
        status = ERR_HTTP;
        goto exit;
    }
    getScheme(pChallenge, challengeLength, &scheme);

    HTTP_httpSettings()->funcPtrPasswordPrompt(pHttpContext, pChallenge, challengeLength, &pUser, &userLength,
        &pPassword, &passwordLength, FALSE);

    /* authorization has index 14 and proxy-authorization 4 in mHttpRequests */
    (*pIndex) = 0;
    if (pHttpContext->requestBitmask[(*pIndex) / 8] & (1 << ((*pIndex) & 7)))
    {
        (*pIndex) = Authorization;
    }
    else
    {
        (*pIndex) = ProxyAuthorization;
    }

    switch (scheme)
    {
    case BASIC:
        HTTP_AUTH_generateBasicAuthorization(pHttpContext,
                            pUser, userLength,
                            pPassword, passwordLength,
                            &pCredential, &credentialLength);
        break;
    case DIGEST:
        /* parse the authentication info */
        if (OK > (status = initParamValues(&ppParamValues)))
        {
            goto exit;
        }
        parseDigestParameters(pChallenge, challengeLength, ppParamValues);

        if (ppParamValues[QOP]->length > 0)
        {
            /* if qop is defined, also define nc and cnonce */
            ppParamValues[NC]->value = (ubyte*)MALLOC(8);
            if (!ppParamValues[NC]->value)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            /* ywang: hard code for now  until we support persistent state */
            DIGI_MEMCPY(ppParamValues[NC]->value, "00000001", 8);
            ppParamValues[NC]->length = 8;

            /* use timestamp for cnonce */
            /* ywang: hardcode for now */
            ppParamValues[CNONCE]->value = (ubyte*)MALLOC(8);
            if (!ppParamValues[CNONCE]->value)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            /* ywang: hard code for now  until we support persistent state */
            DIGI_MEMCPY(ppParamValues[CNONCE]->value, "abcdefgh", 8);
            ppParamValues[CNONCE]->length = 8;
        }

        generateDigestAuthorization(pHttpContext, ppParamValues,
                            pUser, userLength,
                            pPassword, passwordLength,
                            isHA1,
                            &pCredential, &credentialLength);
        break;
    default:
        status = ERR_HTTP;
        goto exit;
    }

    *ppRetAuthString = pCredential;
    *pRetAuthStringLength = credentialLength;
    pCredential = NULL;
exit:
    if (NULL != pCredential)
    {
        FREE(pCredential);
    }

    /* release ppParamValues and all the non NULL values */
    releaseParamValues(ppParamValues);
    return status;
}

/* generate nonce: time-stamp H(time-stamp ":" ETag ":" private-key)*/
static MSTATUS
generateNonce(ubyte** ppNonce, ubyte4* pNonceLen)
{
    TimeDate        td;
    ubyte*          buf = NULL;
    ubyte           md5Output[MD5_DIGESTSIZE];
    hwAccelDescr    hwAccelCookie;
    MSTATUS         status = OK;

    MOC_UNUSED(hwAccelCookie);

    if (OK > (status = RTOS_timeGMT(&td)))
        goto exit;

    if (NULL == (buf = MALLOC(sizeof(td) + MD5_DIGESTSIZE)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMCPY(buf, &td, sizeof(td));
    if (OK > (status = MD5_completeDigest(MOC_HASH(hwAccelCookie) (ubyte*)&td, sizeof(td), md5Output)))
        goto exit;
    DIGI_MEMCPY(buf+sizeof(td), md5Output, MD5_DIGESTSIZE);
    status = BASE64_encodeMessage(buf, sizeof(td)+ MD5_DIGESTSIZE, ppNonce, pNonceLen);

exit:
    if (buf)
    {
        FREE(buf);
    }
    return status;
}

static MSTATUS
generateDigestChallenge(httpContext *pHttpContext,
                             ubyte *realm, ubyte4 realmLen,
                             ubyte *domain, ubyte4 domainLen,
                             ubyte *opaque, ubyte4 opaqueLen,
                             intBoolean stale,
                             ubyte **ppRetChString, ubyte4 *pRetChStringLength)
{
    MSTATUS status = OK;
    ubyte* chString;
    ubyte4 runningLength = 0;
    ubyte* nonce = NULL;
    ubyte4 nonceLen;

    /* ywang: hopefully 512 bytes is adequate */
    if (NULL == (chString = *ppRetChString = MALLOC(512)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(chString, DIGESTSTR, DIGI_STRLEN(DIGESTSTR));
    runningLength = DIGI_STRLEN(DIGESTSTR);
    appendSp(chString, &runningLength);
    appendParam(chString, &runningLength, paramNameStrs[REALM], DIGI_STRLEN(paramNameStrs[REALM]),
        realm, realmLen, TRUE);
    appendEnd(chString, &runningLength);
    if (domain && domainLen > 0)
    {
        appendParam(chString, &runningLength, paramNameStrs[DOMAIN], DIGI_STRLEN(paramNameStrs[DOMAIN]),
            domain, domainLen, TRUE);
        appendEnd(chString, &runningLength);
    }
    if (opaque && opaqueLen > 0)
    {
        appendParam(chString, &runningLength, paramNameStrs[OPAQUE], DIGI_STRLEN(paramNameStrs[OPAQUE]),
            opaque, opaqueLen, TRUE);
        appendEnd(chString, &runningLength);
    }

    if (stale)
    {
        appendParam(chString, &runningLength, paramNameStrs[STALE], DIGI_STRLEN(paramNameStrs[STALE]),
            (ubyte*)"true", 4, FALSE);
        appendEnd(chString, &runningLength);
    }

    /* algorithm; if not present, assumed to be MD5 */

    if (OK > (status = generateNonce(&nonce, &nonceLen)))
        goto exit;

    appendParam(chString, &runningLength, paramNameStrs[NONCE], DIGI_STRLEN(paramNameStrs[NONCE]),
        nonce, nonceLen, TRUE);
    appendEnd(chString, &runningLength);

    /* qop: auth-int not supported for now */
    appendParam(chString, &runningLength, paramNameStrs[QOP], DIGI_STRLEN(paramNameStrs[QOP]),
        (ubyte*)"auth", 4, FALSE);
    *pRetChStringLength = runningLength;
exit:
    chString = NULL;
    if (nonce)
    {
        FREE(nonce);
    }
    return status;
}


static MSTATUS
HTTP_AUTH_generateChallenge(httpContext *pHttpContext, intBoolean stale,
                            ubyte **ppRetChString, ubyte4 *pRetChStringLength)
{
    MSTATUS status = OK;
    ubyte4 scheme;
    ubyte* realm;
    ubyte4 realmLen;
    ubyte* domain;
    ubyte4 domainLen;
    ubyte* opaque;
    ubyte4 opaqueLen;
    ubyte* chString;
    sbyte* schemeString;
    ubyte4 schemeStringLength;
    ubyte4 runningLength = 0;
    /* scheme, realm, and possibly other params (domain, opaque for digest challenge) are provided by callback */
    HTTP_httpSettings()->funcPtrAuthChallenge(pHttpContext, &scheme, &realm, &realmLen,
                                              &domain, &domainLen, &opaque, &opaqueLen);
    switch (scheme)
    {
    case BASIC:
        schemeString = BASICSTR;
        schemeStringLength = DIGI_STRLEN(BASICSTR);
        /* last 2 for quote */
        if (NULL == (*ppRetChString = chString = MALLOC(schemeStringLength + 1 + 5 + 1 + realmLen+2)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(chString, schemeString, schemeStringLength);
        runningLength = schemeStringLength;
        appendSp(chString, &runningLength);
        appendParam(chString, &runningLength, paramNameStrs[REALM], DIGI_STRLEN(paramNameStrs[REALM]),
            realm, realmLen, TRUE);
        *pRetChStringLength = runningLength;
        break;
    case DIGEST:
        status = generateDigestChallenge(pHttpContext, realm, realmLen, domain, domainLen, opaque, opaqueLen, stale, ppRetChString, pRetChStringLength);
        break;
    default:
        status = ERR_HTTP_UNSUPPORTED_AUTH_SCHEME;
        goto exit;
    }

exit:
    chString = NULL;
    if (status < OK && ppRetChString)
    {
        *pRetChStringLength = 0;
        FREE(*ppRetChString);
    }

    return status;

}

/* if fail to validate authorization, generateChallenge */
extern MSTATUS
HTTP_AUTH_validateAuthorization(httpContext *pHttpContext, ubyte4 *pStatusCode)
{
    MSTATUS status;
    ubyte *pAuthorization;
    ubyte4 authorizationLength;
    httpAuthScheme scheme;
    intBoolean stale = FALSE;
    ubyte* realm = NULL;
    ubyte4 realmLen = 0;
    ubyte* passwd = NULL;
    ubyte4 passwdLen;
    intBoolean isHA1;
    ubyte *pRetChString = NULL;
    ubyte4 retChStringLength = 0;
    paramValuePTR *ppParamValues = NULL;
    ubyte4 isContinueFromBlock=0;
    getChallengeOrAuthorization(pHttpContext, &pAuthorization, &authorizationLength);
    if (!pAuthorization || authorizationLength <= 0)
    {
        goto genChallenge;
    }

    getScheme(pAuthorization, authorizationLength, &scheme);

    switch (scheme)
    {
        ubyte4 i;
        ubyte *userPass;
        ubyte4 userPassLen;
        ubyte* userName;
        ubyte4 userNameLen;
        ubyte* passwd1;
        ubyte4 passwd1Len;
        ubyte4 scheme1;
        ubyte digest[2*MD5_DIGESTSIZE];
        sbyte4 result;
    case BASIC:
        /* user-pass   = userid ":" password */
        if (OK > (status = BASE64_decodeMessage(pAuthorization+DIGI_STRLEN(BASICSTR)+1, authorizationLength-DIGI_STRLEN(BASICSTR)-1, &userPass, &userPassLen)))
            goto exit;

        /* get username part */
        for (i = 0; i < userPassLen; i++)
        {
            if (':' == *(userPass+i))
                break;
        }
        userName = userPass;
        userNameLen = i;
        passwd1 = userPass+i+1;
        passwd1Len = userPassLen - i - 1;
        /* retrieve password */
        status = HTTP_httpSettings()->funcPtrPasswordAuth(pHttpContext,
            userName, userNameLen,
            realm, realmLen,
            &scheme1,
            &passwd, &passwdLen,
            &isHA1,
            (sbyte4)isContinueFromBlock);
        if (OK > status)
            goto exit;

        if (scheme == scheme1 && passwd1Len == passwdLen)
        {
            DIGI_MEMCMP(passwd1, passwd, passwd1Len, &result);
        } else
        {
            result = -1;
        }
        if (OK > (status = BASE64_freeMessage(&userPass)))
            goto exit;
        if (result == 0) /* validated */
        {
            /* return authentication succeeded */
            status = HTTP_setUserAccessGroups(pHttpContext, 1);
            goto exit;
        }
        break;
    case DIGEST:
        if (OK > (status = initParamValues(&ppParamValues)))
        {
            goto exit;
        }
        if (OK > (status = parseDigestParameters(pAuthorization, authorizationLength, ppParamValues)))
            goto exit;

        userName = ppParamValues[USERNAME]->value;
        userNameLen = ppParamValues[USERNAME]->length;
        realm = ppParamValues[REALM]->value;
        realmLen = ppParamValues[REALM]->length;

        /* retrieve password (if isHA1 is true, password contains the H(A1) for digest auth) */
        status = HTTP_httpSettings()->funcPtrPasswordAuth(pHttpContext,
            userName, userNameLen,
            realm, realmLen,
            &scheme1,
            &passwd, &passwdLen,
            &isHA1,
            (sbyte4)isContinueFromBlock);
        if (OK > status)
            goto exit;

        if (scheme == scheme1)
        {
            /* calculate the digest and compare with request-digest */
            calculateDigest(pHttpContext, ppParamValues, userName, userNameLen, passwd, passwdLen, isHA1, digest);

            DIGI_MEMCMP(ppParamValues[RESPONSE]->value, digest, ppParamValues[RESPONSE]->length, &result);

            /* ywang: check nonce for staleness */

            if (result == 0) /* validated */
            {
                /* return authentication succeeded */
                status = HTTP_setUserAccessGroups(pHttpContext, 1);
                goto exit;
            }
        }
        break;
    default:
        status = ERR_HTTP; /* http unsupported auth scheme */
        goto exit;
    }

genChallenge:

    /* generate a challenge */
    if (OK > (status = HTTP_AUTH_generateChallenge(pHttpContext, stale,
                                                   &pRetChString, &retChStringLength)))
        goto exit;
    /* set challenge in header if invalidated */
    if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, WWWAuthenticate,
                                                     pRetChString, retChStringLength)))
        goto exit;
    /* status code */
    *pStatusCode = 401;

    /* ywang: what to do if status is blocking ??? */


exit:
    releaseParamValues(ppParamValues);
    if (pRetChString)
    {
        FREE(pRetChString);
    }
    return status;
}

#endif /* __ENABLE_DIGICERT_HTTP_CLIENT__ */

