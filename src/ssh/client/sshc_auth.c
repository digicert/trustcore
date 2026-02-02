/*
 * sshc_auth.c
 *
 * SSH Authentication Handler
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

#include "../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SSH_CLIENT__

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/debug_console.h"
#include "../../common/mem_pool.h"
#include "../../common/circ_buf.h"
#include "../../common/tree.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../crypto/dsa.h"
#include "../../crypto/sha1.h"

#ifndef __DISABLE_DIGICERT_SHA256__
#include "../../crypto/sha256.h"
#endif

#if ((!defined(__DISABLE_DIGICERT_SHA384__)) || (!defined(__DISABLE_DIGICERT_SHA512__)))
#include "../../crypto/sha512.h"
#endif

#include "../../crypto/rsa.h"
#include "../../crypto/dh.h"
#include "../../crypto/crypto.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"

#ifdef __ENABLE_DIGICERT_ECC__
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif

#include "../../common/sizedbuffer.h"
#include "../../crypto/cert_store.h"
#include "../../asn1/parseasn1.h"
#include "../../crypto/cert_chain.h"
#include "../../ssh/ssh_defs.h"
#include "../../ssh/client/sshc.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/client/sshc_context.h"
#include "../../ssh/client/sshc_in_mesg.h"
#include "../../ssh/client/sshc_out_mesg.h"
#include "../../ssh/client/sshc_client.h"
#include "../../ssh/client/sshc_session.h"
#include "../../ssh/client/sshc_filesys.h"
#include "../../ssh/client/sshc_ftp.h"
#include "../../ssh/client/sshc_trans.h"
#include "../../ssh/client/sshc_auth.h"
#include "../../ssh/client/sshc_str_house.h"
#include "../../ssh/client/sshc_utils.h"
#include "../../ssh/ssh_dss.h"
#include "../../ssh/ssh_rsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../../ssh/ssh_ecdsa.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_ecc.h"
#endif
#endif
#include "../../ssh/ssh_cert.h"
#include "../../harness/harness.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_rsa.h"
#include "../crypto_interface/crypto_interface_dsa.h"
#endif

#ifdef __ENABLE_DIGICERT_PQC__
#include "../../ssh/ssh_qs.h"
#endif
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
#include "../../ssh/ssh_hybrid.h"
#endif

/*------------------------------------------------------------------*/

#ifndef SSHC_NUM_AUTH_ATTEMPTS
#define SSHC_NUM_AUTH_ATTEMPTS      (3)
#endif


/*------------------------------------------------------------------*/

typedef struct
{
    sbyte*              pOptionName;
    ubyte4              optionNameLength;
    ubyte4              bitMask;

} authMethodDescr;


/*------------------------------------------------------------------*/

static authMethodDescr mAuthMethods[] =
{
    { (sbyte *)"publickey",             9, MOCANA_SSH_AUTH_PUBLIC_KEY },
    { (sbyte *)"password",              8, MOCANA_SSH_AUTH_PASSWORD   },
    { (sbyte *)"none",                  4, MOCANA_SSH_AUTH_NONE       },
    { (sbyte *)"keyboard-interactive", 20, MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE },
    { (sbyte *)"publickey",             9, MOCANA_SSH_AUTH_CERT }
};

#define AUTH_OPTION_PUBLICKEY_INDEX    0
#define AUTH_OPTION_PASSWORD_INDEX     1
#define AUTH_OPTION_NONE_INDEX         2
#define AUTH_OPTION_KEYBOARD_INDEX     3

#define NUM_AUTH_OPTIONS (sizeof(mAuthMethods)/sizeof(authMethodDescr))

/*------------------------------------------------------------------*/

typedef struct
{
    ubyte*              pNewMesg;
    ubyte4              newMesgLen;
    ubyte4              index;
    sshStringBuffer*    pUser;

} sshcAuthCommonArgs;


static const BulkHashAlgo NoSuite = { 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ht_none };

/* Define the hash algorithms used by DSA keys */
static const BulkHashAlgo SHA1Suite =
    { SHA1_RESULT_SIZE, SHA1_BLOCK_SIZE, SHA1_allocDigest, SHA1_freeDigest,
        (BulkCtxInitFunc)SHA1_initDigest, (BulkCtxUpdateFunc)SHA1_updateDigest, (BulkCtxFinalFunc)SHA1_finalDigest, NULL, NULL, NULL, ht_sha1 };


#ifndef __DISABLE_DIGICERT_SHA256__
static const BulkHashAlgo SHA256Suite =
    { SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest,
        (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, (BulkCtxFinalFunc)SHA256_finalDigest, NULL, NULL, NULL, ht_sha256 };
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
static const BulkHashAlgo SHA384Suite =
    { SHA384_RESULT_SIZE, SHA384_BLOCK_SIZE, SHA384_allocDigest, SHA384_freeDigest,
        (BulkCtxInitFunc)SHA384_initDigest, (BulkCtxUpdateFunc)SHA384_updateDigest, (BulkCtxFinalFunc)SHA384_finalDigest, NULL, NULL, NULL, ht_sha384 };
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
static const BulkHashAlgo SHA512Suite =
    { SHA512_RESULT_SIZE, SHA512_BLOCK_SIZE, SHA512_allocDigest, SHA512_freeDigest,
        (BulkCtxInitFunc)SHA512_initDigest, (BulkCtxUpdateFunc)SHA512_updateDigest, (BulkCtxFinalFunc)SHA512_finalDigest, NULL, NULL, NULL, ht_sha512 };
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_AUTH_SendUserAuthServiceRequest(sshClientContext *pContextSSH)
{
    ubyte*      pPayload = NULL;
    ubyte4      len;
    MSTATUS     status;

    if (NULL == pContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    len = sshc_userAuthService.stringLen + 1;
    if (NULL == (pPayload = MALLOC(len)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *pPayload = SSH_MSG_SERVICE_REQUEST;
    DIGI_MEMCPY(pPayload + 1, sshc_userAuthService.pString, sshc_userAuthService.stringLen);

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, pPayload, len, &len);

exit:
    if (NULL != pPayload)
        FREE(pPayload);

    return status;
} /* SSHC_AUTH_SendUserAuthServiceRequest */


/*------------------------------------------------------------------*/

extern sbyte *
SSHC_AUTH_authList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie)
{
    ubyte4 loop, count;
    sbyte* pRetOptionName = NULL;

    if (NUM_AUTH_OPTIONS <= index)
        goto exit;

    for (count = loop = 0; loop < NUM_AUTH_OPTIONS; loop++)
    {
        if (0 != (cookie & mAuthMethods[loop].bitMask))
        {
            if (count == index)
            {
                /* this code allows us to deal with holes in the list */
                *pRetStringLength = mAuthMethods[loop].optionNameLength;
                pRetOptionName = mAuthMethods[loop].pOptionName;
                break;
            }

            count++;
        }
    }

exit:
    return pRetOptionName;
} /* SSHC_AUTH_authList */


/*------------------------------------------------------------------*/

static MSTATUS
noneAuth(sshClientContext *pContextSSH, ubyte *pName, ubyte4 nameLen)
{
    ubyte*  pBuffer = NULL;
    ubyte4  buflen;
    ubyte4  bufIndex = 0;
    ubyte4  numBytesWritten = 0;
    MSTATUS status;

    buflen = 1 +
    4 + nameLen +
    sshc_connectService.stringLen +
    4 + mAuthMethods[AUTH_OPTION_NONE_INDEX].optionNameLength;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* byte SSH_MSG_USERAUTH_REQUEST */
    *pBuffer = SSH_MSG_USERAUTH_REQUEST;
    bufIndex++;

    /* string user name */
    if (0 > (status = SSH_STR_copyStringToPayload2(pBuffer, buflen, &bufIndex, pName, nameLen)))
        goto exit;

    /* string    service (we're only supporting "ssh-connection") */
    /* sshc_connectService.pString already contains the length bytes */
    DIGI_MEMCPY(pBuffer + bufIndex, sshc_connectService.pString, sshc_connectService.stringLen);
    bufIndex += sshc_connectService.stringLen;

    /* string "password" */


    if (0 > (status = SSH_STR_copyStringToPayload2(pBuffer, buflen, &bufIndex,
                                                   (ubyte *)mAuthMethods[AUTH_OPTION_NONE_INDEX].pOptionName,
                                                   mAuthMethods[AUTH_OPTION_NONE_INDEX].optionNameLength)))
        goto exit;

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, pBuffer, buflen,
                                       &numBytesWritten);
    /* verify write completed */
    if ((OK <= status) && (buflen != numBytesWritten))
        status = ERR_AUTH_MESG_FRAGMENTED;

exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

}

/*------------------------------------------------------------------*/

static MSTATUS
passwordAuth(sshClientContext *pContextSSH, ubyte *pName, ubyte4 nameLen)
{
    ubyte*  pBuffer = NULL;
    ubyte4  buflen;
    ubyte*  pPassword = NULL;
    ubyte4  passwordLength = 0;
    ubyte4  bufIndex = 0;
    ubyte4  numBytesWritten = 0;
    MSTATUS status;

    if (NULL == SSHC_sshClientSettings()->funcPtrRetrieveUserPassword)
    {
        status = ERR_AUTH_MISCONFIGURED;
        goto exit;
    }

    (SSHC_sshClientSettings()->funcPtrRetrieveUserPassword)(pContextSSH->connectionInstance, pName, nameLen, &pPassword, &passwordLength);

    buflen = 1 +
             4 + nameLen +
                 sshc_connectService.stringLen +
             4 + mAuthMethods[AUTH_OPTION_PASSWORD_INDEX].optionNameLength +
             1 +
             4 + passwordLength;

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* byte SSH_MSG_USERAUTH_REQUEST */
    *pBuffer = SSH_MSG_USERAUTH_REQUEST;
    bufIndex++;

    /* string user name */
    if (0 > (status = SSH_STR_copyStringToPayload2(pBuffer, buflen, &bufIndex, pName, nameLen)))
        goto exit;

    /* string    service (we're only supporting "ssh-connection") */
    /* sshc_connectService.pString already contains the length bytes */
    DIGI_MEMCPY(pBuffer + bufIndex, sshc_connectService.pString, sshc_connectService.stringLen);
    bufIndex += sshc_connectService.stringLen;

    /* string "password" */
    if (0 > (status = SSH_STR_copyStringToPayload2(pBuffer, buflen, &bufIndex,
                            (ubyte *)mAuthMethods[AUTH_OPTION_PASSWORD_INDEX].pOptionName,
                            mAuthMethods[AUTH_OPTION_PASSWORD_INDEX].optionNameLength)))
        goto exit;

    /* boolean   FALSE */
    *(pBuffer + bufIndex) = FALSE;
    bufIndex++;

    /* string    plaintext password (ISO-10646 UTF-8) */
    if (0 > (status = SSH_STR_copyStringToPayload2(pBuffer, buflen, &bufIndex,
                            pPassword, passwordLength)))
        goto exit;

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, pBuffer, buflen,
                                       &numBytesWritten);

    /* verify write completed */
    if ((OK <= status) && (buflen != numBytesWritten))
        status = ERR_AUTH_MESG_FRAGMENTED;


exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

} /* passwordAuth */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSH_AUTH_KEYBOARD_INTERACTIVE__
static MSTATUS
SSHC_AUTH_keyboardInteractiveAuth(sshClientContext *pContextSSH, ubyte *pName, ubyte4 nameLen)
{
    ubyte*  pBuffer = NULL;
    ubyte4  buflen;
    ubyte4  bufIndex = 0;
    ubyte4  numBytesWritten = 0;
    MSTATUS status;

    /*
     * Packet:
     *  byte      SSH_MSG_USERAUTH_REQUEST
     *  string    user name (ISO-10646 UTF-8, as defined in [RFC-3629])
     *  string    service name (US-ASCII)
     *  string    "keyboard-interactive" (US-ASCII)
     *  string    language tag (as defined in [RFC-3066])
     *  string    submethods (ISO-10646 UTF-8)
     *
     * language tag + submethods will be empty strings.
     * */
    buflen = 1 +
             4 + nameLen +
                 sshc_connectService.stringLen +
             4 + mAuthMethods[AUTH_OPTION_KEYBOARD_INDEX].optionNameLength +
             4 + 4; /* empty strings for language tag and submethods */

    if (NULL == (pBuffer = MALLOC(buflen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* byte SSH_MSG_USERAUTH_REQUEST */
    *pBuffer = SSH_MSG_USERAUTH_REQUEST;
    bufIndex++;

    /* string user name */
    if (0 > (status = SSH_STR_copyStringToPayload2(pBuffer, buflen, &bufIndex, pName, nameLen)))
        goto exit;

    /* string    service (we're only supporting "ssh-connection") */
    /* sshc_connectService.pString already contains the length bytes */
    DIGI_MEMCPY(pBuffer + bufIndex, sshc_connectService.pString, sshc_connectService.stringLen);
    bufIndex += sshc_connectService.stringLen;

    /* string "keyboard-interactive" */
    if (0 > (status = SSH_STR_copyStringToPayload2(pBuffer, buflen, &bufIndex,
                            (ubyte *)mAuthMethods[AUTH_OPTION_KEYBOARD_INDEX].pOptionName,
                            mAuthMethods[AUTH_OPTION_KEYBOARD_INDEX].optionNameLength)))
        goto exit;

    /* string    language tag (as defined in [RFC-3066]). */
    if (0 > (status = SSH_STR_copyStringToPayload2(pBuffer, buflen, &bufIndex,
                            (ubyte *)"", 0)))
        goto exit;

    /* string    submethods (ISO-10646 UTF-8). */
    if (0 > (status = SSH_STR_copyStringToPayload2(pBuffer, buflen, &bufIndex,
                            (ubyte *)"", 0)))
        goto exit;

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, pBuffer, buflen,
                                       &numBytesWritten);

    /* verify write completed */
    if ((OK <= status) && (buflen != numBytesWritten))
        status = ERR_AUTH_MESG_FRAGMENTED;


exit:
    if (NULL != pBuffer)
        FREE(pBuffer);

    return status;

}

/*
 * RFC 4256 3.2
 *  byte      SSH_MSG_USERAUTH_INFO_REQUEST
 *  string    name (ISO-10646 UTF-8)
 *  string    instruction (ISO-10646 UTF-8)
 *  string    language tag (as defined in [RFC-3066])
 *  int       num-prompts
 *  string    prompt[1] (ISO-10646 UTF-8)
 *  boolean   echo[1]
 *  ...
 *  string    prompt[num-prompts] (ISO-10646 UTF-8)
 *  boolean   echo[num-prompts]
 */
static MSTATUS decodeKeyInfoReq(ubyte *pInfoReqMsg, ubyte4 infoReqMsgLen,
    keyIntInfoReq* pRequest)
{
    MSTATUS status;
    keyIntPrompt *pNewPrompt;
    ubyte4 msgType;
    sbyte *pName = NULL;
    sbyte *pInstruction = NULL;
    ubyte4 languageTagLen = 0;
    ubyte4 index;
    ubyte4 i;

    if ((NULL == pInfoReqMsg) || (NULL == pRequest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    msgType = *pInfoReqMsg;
    if (SSH_MSG_USERAUTH_INFO_REQUEST != msgType)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    /* move past message type */
    index = 1;

    status = SSH_STR_copyStringFromPayload3(pInfoReqMsg, infoReqMsgLen, &index, (ubyte **)&pName);
    if(OK != status)
        goto exit;

    pRequest->pName = pName;
    pRequest->nameLen = DIGI_STRLEN(pName);

    status = SSH_STR_copyStringFromPayload3(pInfoReqMsg, infoReqMsgLen, &index, (ubyte **)&pInstruction);
    if(OK != status)
        goto exit;

    pRequest->pInstruction = pInstruction;
    pRequest->instructionLen = DIGI_STRLEN(pInstruction);

    if ((4 + index) > infoReqMsgLen)
    {
        status = ERR_SSH_UNEXPECTED_END_MESSAGE;
        goto exit;
    }

    /* get length of language tag */
    languageTagLen = DIGI_NTOHL(pInfoReqMsg + index);
    index += 4;

    /* unsupported. skip language tag. */
    index += languageTagLen;

    if ((4 + index) > infoReqMsgLen)
    {
        status = ERR_SSH_UNEXPECTED_END_MESSAGE;
        goto exit;
    }

    pRequest->numPrompts = DIGI_NTOHL(pInfoReqMsg + index);
    index += 4;

    for (i = 0; i < pRequest->numPrompts; i++)
    {
        if ((4 + index) > infoReqMsgLen)
        {
            status = ERR_SSH_UNEXPECTED_END_MESSAGE;
            goto exit;
        }

        status = DIGI_MALLOC((void **)&pNewPrompt, sizeof(*pNewPrompt));
        if(OK != status)
            goto exit;

        pNewPrompt->promptLen = DIGI_NTOHL(pInfoReqMsg + index);
        index += 4;

        if((pNewPrompt->promptLen + index) > infoReqMsgLen)
        {
            status = ERR_SSH_UNEXPECTED_END_MESSAGE;
            goto exit;
        }

        pNewPrompt->pPrompt = (sbyte *)(pInfoReqMsg + index);
        index += pNewPrompt->promptLen;

        pNewPrompt->echo = (pInfoReqMsg[index]);
        pRequest->prompts[i] = pNewPrompt;
        /* convert echo byte into null terminator */
        pInfoReqMsg[index] = '\0';
        index++;
    }

exit:
    if (OK != status)
        DIGI_MEMSET((ubyte *)pRequest, 0x00, sizeof(keyIntInfoReq));
    return status;
}

static MSTATUS releaseKeyInfoReq(keyIntInfoReq* pRequest)
{
    ubyte4 i;
    if(NULL == pRequest)
    {
        return ERR_NULL_POINTER;
    }

    if(NULL != pRequest->pName)
    {
        DIGI_FREE((void **)&pRequest->pName);
    }

    if(NULL != pRequest->pInstruction)
    {
        DIGI_FREE((void **)&pRequest->pInstruction);
    }

    for (i = 0; i < pRequest->numPrompts; i++)
    {
        DIGI_FREE((void **)&(pRequest->prompts[i]));
    }

    return OK;
}

/*
 * RFC 4256 3.4:
 *  byte      SSH_MSG_USERAUTH_INFO_RESPONSE
 *  int       num-responses
 *  string    response[1] (ISO-10646 UTF-8)
 *  ...
 *  string    response[num-responses] (ISO-10646 UTF-8)
 */
static MSTATUS sendKeyInfoResp(sshClientContext *pContextSSH, keyIntInfoResp* pResponse)
{
    MSTATUS status;
    ubyte *pPayload = NULL;
    ubyte4 numBytesToWrite;
    ubyte4 numBytesWritten;
    ubyte4 index;
    ubyte4 i;

    if((NULL == pContextSSH) || (NULL == pResponse))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* 1 byte for message type, 4 bytes for number of responses */
    numBytesToWrite = 1 + 4;

    for(i = 0; i < pResponse->numResponses; i++)
        numBytesToWrite += 4 + pResponse->responses[i]->responseLen;

    status = DIGI_MALLOC((void **)&pPayload, numBytesToWrite);
    if(OK != status)
        goto exit;

    index = 0;
    pPayload[index] = SSH_MSG_USERAUTH_INFO_RESPONSE;
    index++;

    status = SSHC_UTILS_setInteger(pPayload, numBytesToWrite, &index, pResponse->numResponses);
    if(OK != status)
        goto exit;

    for(i = 0; i < pResponse->numResponses; i++)
    {
        status = SSHC_UTILS_setInteger(pPayload, numBytesToWrite, &index, pResponse->responses[i]->responseLen);
        if(OK != status)
            goto exit;

        status = DIGI_MEMCPY(pPayload + index, pResponse->responses[i]->pResponse, pResponse->responses[i]->responseLen);
        if(OK != status)
            goto exit;
        index += pResponse->responses[i]->responseLen;
    }

    status = SSHC_OUT_MESG_sendMessage(pContextSSH, pPayload, numBytesToWrite, &numBytesWritten);
    if((OK != status) && (numBytesToWrite != numBytesWritten))
    {
        status = ERR_AUTH_MESG_FRAGMENTED;
    }

exit:
    if (NULL != pPayload)
        DIGI_FREE((void **)&pPayload);
    return status;
}

static MSTATUS SSHC_AUTH_processKeyboardInteractiveReq(sshClientContext *pContextSSH,
    ubyte *pInfoReqMsg, ubyte4 infoReqMsgLen)
{
    MSTATUS status;
    keyIntInfoReq infoReq;
    keyIntInfoResp infoResp;

    if ((NULL == pContextSSH) || (NULL == pInfoReqMsg))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&infoReq, 0x00, sizeof(keyIntInfoReq));
    status = decodeKeyInfoReq(pInfoReqMsg, infoReqMsgLen, &infoReq);
    if (OK != status)
        goto exit;

    /* Function pointer is required to process info request */
    if (NULL == SSHC_sshClientSettings()->funcPtrKeyIntAuthResp)
    {
        status = ERR_AUTH_MISCONFIGURED;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&infoResp, 0x00, sizeof(keyIntInfoResp));

    (SSHC_sshClientSettings()->funcPtrKeyIntAuthResp)(pContextSSH->connectionInstance,
        &infoReq, &infoResp);

    status = sendKeyInfoResp(pContextSSH, &infoResp);

exit:
    if (NULL !=  SSHC_sshClientSettings()->funcPtrReleaseKeyIntAuthResp)
    {
        SSHC_sshClientSettings()->funcPtrReleaseKeyIntAuthResp(
            pContextSSH->connectionInstance, &infoResp);
    }
    releaseKeyInfoReq(&infoReq);
    return status;
}
#endif /* __ENABLE_DIGICERT_SSH_AUTH_KEYBOARD_INTERACTIVE__ */


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_AUTH_generateHashOrMessage(sshClientContext *pContextSSH, BulkHashAlgo hashAlgo,
                                ubyte *pMessage, ubyte4 messageLen, ubyte **ppOutput,
                                ubyte4 *pOutputLen, ubyte4 keyType)
{
    MSTATUS     status = ERR_NULL_POINTER;
    BulkCtx     pHashContext;
    ubyte       length[4] = { 0 };
    ubyte       *pOutput = NULL;
    ubyte4      outputLen;

    if ((NULL == pContextSSH) || (NULL == pMessage) || (NULL == ppOutput))
        goto exit;

    *ppOutput = NULL;
    *pOutputLen = 0;

    /* For akt_ecc_ed, akt_qs, or akt_hybrid the digest does not need to be taken since the sign API
     * requires the full message to be provided.
     */
    if ((akt_dsa == (keyType & 0xff)) || (akt_rsa == (keyType & 0xff)) ||
        (akt_ecc == (keyType & 0xff)))
    {
        length[3] = (ubyte)pContextSSH->sessionIdLength;

        status = DIGI_MALLOC((void**)&pOutput, hashAlgo.digestSize);
        if (OK != status)
            goto exit;

        status = (hashAlgo.allocFunc)(MOC_HASH(pContextSSH->hwAccelCookie) &pHashContext);
        if (OK != status)
            goto exit;

        status = (hashAlgo.initFunc)(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext);
        if (OK != status)
            goto exit;

        status = (hashAlgo.updateFunc)(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, length, 4);
        if (OK != status)
            goto exit;

        status = (hashAlgo.updateFunc)(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, SSH_SESSION_ID(pContextSSH), (ubyte)pContextSSH->sessionIdLength);
        if (OK != status)
            goto exit;

        status = (hashAlgo.updateFunc)(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pMessage, messageLen);
        if (OK != status)
            goto exit;

        /* buffer is already allocated */
        status = (hashAlgo.finalFunc)(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pOutput);
        if (OK != status)
            goto exit;

        *ppOutput = pOutput;
        *pOutputLen = hashAlgo.digestSize;
        pOutput = NULL;
        (hashAlgo.freeFunc)(MOC_HASH(pContextSSH->hwAccelCookie) &pHashContext);
    }
    else if (akt_ecc_ed == (keyType & 0xff) || akt_qs == (keyType & 0xff) || akt_hybrid == (keyType & 0xff))
    {
        outputLen = 4 + (ubyte)pContextSSH->sessionIdLength + messageLen;

        status = DIGI_MALLOC((void**)&pOutput, outputLen);
        if (OK != status)
            goto exit;

        length[3] = (ubyte)pContextSSH->sessionIdLength;

        status = DIGI_MEMCPY(pOutput, length, 4);
        if (OK != status)
            goto exit;

        outputLen = 4;
        status = DIGI_MEMCPY(pOutput + outputLen, SSH_SESSION_ID(pContextSSH), pContextSSH->sessionIdLength);
        if (OK != status)
            goto exit;

        outputLen += pContextSSH->sessionIdLength;
        status = DIGI_MEMCPY(pOutput + outputLen, pMessage, messageLen);
        if (OK != status)
            goto exit;

        outputLen += messageLen;

        *ppOutput = pOutput;
        *pOutputLen = outputLen;
        pOutput = NULL;
    }

exit:
    if (NULL != pOutput)
    {
        DIGI_FREE((void**)&pOutput);
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSHC_AUTH_publicKeyAuth(MOC_ASYM(hwAccelDescr hwAccelCtx) sshClientContext *pContextSSH, ubyte *pName, ubyte4 nameLen, intBoolean generateSignature)
{
    sshStringBuffer*    pSignatureType  = NULL;     /* do not free: pointer to a statically allocated string. */
    AsymmetricKey       authKey;
    ubyte*              pKeyBlob        = NULL;
    ubyte*              pMessage        = NULL;
    ubyte*              pCertificate    = NULL;
    ubyte*              pSignature      = NULL;
    vlong*              pM              = NULL;
    vlong*              pVlongQueue     = NULL;
    ubyte4              keyBlobLength;
    ubyte4              messageLen;
    ubyte4              certificateLen;
    ubyte4              signatureLength = 0;
    ubyte4              modLength;
    ubyte4              index = 0;
    ubyte4              numBytesWritten = 0;
    MSTATUS             status;
    ubyte4              contextSize = sizeof(shaDescr);
    BulkHashAlgo        hashAlgo = SHA1Suite;
    ubyte4              bufLen = 0;
    ubyte4              remainingMesgLen = 0;
	ubyte*              mBuf = NULL;
#if (defined(__ENABLE_DIGICERT_PQC__))
    intBoolean          isCertificate = FALSE;
#endif

#if ((defined(__ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSH_CLIENT_CERT_AUTH__)))
    AsymmetricKey*      pKey = NULL;
    ubyte*              pDerCert      = NULL;
    ubyte4              derCertLength = 0;
    intBoolean          *pretIsFound = NULL;
    ubyte4              numCertificates = 1;
    ubyte4              authType = 0;
#endif

    /* retrieve our host key */
    if (OK > (status = CRYPTO_initAsymmetricKey(&authKey)))
        goto exit;

    if (NULL != SSHC_sshClientSettings()->funcPtrRetrieveNakedAuthKeys)
    {
        if (OK > (status = (MSTATUS)(SSHC_sshClientSettings()->funcPtrRetrieveNakedAuthKeys)(pContextSSH->connectionInstance,
                                                                                             &pKeyBlob, &keyBlobLength)))
        {
            goto exit;
        }
    }
#if ((defined(__ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSH_CLIENT_CERT_AUTH__)))
    else if (pContextSSH->pCertStore != NULL)
    {
        /* Retrieve the certificate if we have one in our cert store */
        if (OK > (status = CERT_STORE_findIdentityByTypeFirst(pContextSSH->pCertStore,
                                                              pContextSSH->pHostKeySuites->authType,
                                                              CERT_STORE_IDENTITY_TYPE_CERT_X509_V3,
                                                              (const AsymmetricKey **)&pKey,
                                                              (const ubyte **)&pDerCert, &derCertLength,
                                                              (void **)&pretIsFound)))
        {
            goto exit;
        }
        while((NULL == pKey) && (authType < CERT_STORE_AUTH_TYPE_ARRAY_SIZE))
        {
            if (OK > (status = CERT_STORE_findIdentityByTypeFirst(pContextSSH->pCertStore,
                                                                  authType,
                                                                  CERT_STORE_IDENTITY_TYPE_CERT_X509_V3,
                                                                  (const AsymmetricKey **)&pKey,
                                                                  (const ubyte **)&pDerCert, &derCertLength,
                                                                  (void **)&pretIsFound)))
            {
                goto exit;
            }
            authType++;
        }
#if (defined(__ENABLE_DIGICERT_PQC__))
        /* set this value for hybrid algorithms */
        isCertificate = TRUE;
#endif
    }
#endif

#if ((defined(__ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSH_CLIENT_CERT_AUTH__)))
    if ((NULL == pKeyBlob) && (NULL == pKey))
#else
    if (NULL == pKeyBlob)
#endif
    {
        /* send empty key */
        /* calculate length of SSH_MSG_USERAUTH_REQUEST message, including session identifier string */
        messageLen = 1 +
                     (4 + nameLen) +
                     sshc_connectService.stringLen +
                     1 +
                     sshc_authPublicKey.stringLen +
                     4 + 4; /* algo name + public key */

        /* allocate memory for SSH_MSG_USERAUTH_REQUEST message */
        if (NULL == (pMessage = MALLOC(messageLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMSET(pMessage, 0x00, messageLen);

        /* fill in SSH_MSG_USERAUTH_REQUEST message */
        *pMessage = SSH_MSG_USERAUTH_REQUEST;
        index++;

        /* user name */
        if (0 > (status = SSH_STR_copyStringToPayload2(pMessage, messageLen, &index, pName, nameLen)))
            goto exit;

        /* service (we're only supporting "ssh-connection") */
        if (OK > (status = SSH_STR_copyStringToPayload3(pMessage, messageLen, &index, &sshc_connectService)))
            goto exit;

        /* "publickey" */
        if (OK > (status = SSH_STR_copyStringToPayload3(pMessage, messageLen, &index, &sshc_authPublicKey)))
            goto exit;

        /* is signed? FALSE */
        *(pMessage + index) = FALSE;
        index++;

        if (OK > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, pMessage, messageLen, &numBytesWritten)))
            goto exit;

        /* verify write completed */
        if ((messageLen) != numBytesWritten)
            status = ERR_AUTH_MESG_FRAGMENTED;

        /* we are done, cleanup before return */
        goto exit;
    }

#if ((defined(__ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSH_CLIENT_CERT_AUTH__)))
    /* convert key blob to useful data structure */
    if (pKey == NULL)
    {
        status = CRYPTO_initAsymmetricKey(&authKey);
        if (OK != status)
            goto exit;

        status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pKeyBlob, keyBlobLength, NULL, &authKey);
        if (OK != status)
            goto exit;
    }
    else
    {
        authKey = *pKey;
    }
#else
    status = CRYPTO_initAsymmetricKey(&authKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) pKeyBlob, keyBlobLength, NULL, &authKey);
    if (OK != status)
        goto exit;

#endif

    if ((NULL != SSHC_sshClientSettings()->funcPtrReleaseNakedAuthKeys) && (NULL != pKeyBlob))
    {
        status = (MSTATUS)SSHC_sshClientSettings()->funcPtrReleaseNakedAuthKeys(pContextSSH->connectionInstance, &pKeyBlob);
        pKeyBlob = NULL;    /* prevent accidental double frees */

        if (OK > status)
            goto exit;
    }

    switch (authKey.type & 0xff)
    {
#if (defined(__ENABLE_DIGICERT_SSH_DSA_SUPPORT__))
        case akt_dsa:
        {

#ifndef __DISABLE_DIGICERT_SHA256__
			/**
			 * Current support for 2048 bit DSA assumes the N parameter
			 * is 256 bytes. We infer the key size by looking at the
			 * length of the P paremeter.
			 */

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_DSA_getCipherTextLength(MOC_DSA(pContextSSH->hwAccelCookie) authKey.key.pDSA, (sbyte4 *) &modLength);
#else
            status = DSA_getCipherTextLength(MOC_DSA(pContextSSH->hwAccelCookie) authKey.key.pDSA, (sbyte4 *) &modLength);
#endif
            if (OK != status)
                goto exit;

            if(2048 == 8*modLength)
            {
                contextSize = sizeof(sha256Descr);
                hashAlgo = SHA256Suite;
            }
#endif

            if (OK > (status = SSH_DSS_buildDssCertificate(MOC_DSA(pContextSSH->hwAccelCookie) &authKey, FALSE, &pCertificate, &certificateLen)))
                goto exit;

            if (TRUE == generateSignature)
                if (OK > (status = SSH_DSS_calcDssSignatureLength(&authKey, FALSE, &signatureLength,hashAlgo.digestSize)))
                    goto exit;

            pSignatureType = &sshc_dss_signature;

            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_SSH_RSA_SUPPORT__))
        case akt_rsa:
        {
            if (OK > (status = SSH_RSA_buildRsaCertificate(MOC_RSA(pContextSSH->hwAccelCookie) &authKey, FALSE, &pCertificate, &certificateLen)))
                goto exit;

            if (TRUE == generateSignature)
                if (OK > (status = SSH_RSA_calcRsaSignatureLength(MOC_RSA(pContextSSH->hwAccelCookie) &authKey, FALSE, &signatureLength)))
                    goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(MOC_RSA(pContextSSH->hwAccelCookie) (const RSAKey*)authKey.key.pRSA, (sbyte4 *) &modLength);
            if (OK != status)
                goto exit;
#else
            status = RSA_getCipherTextLength(MOC_RSA(pContextSSH->hwAccelCookie) (const RSAKey*)authKey.key.pRSA, (sbyte4 *) &modLength);
            if (OK != status)
                goto exit;
#endif

#if ((defined(__ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSH_CLIENT_CERT_AUTH__)))
            if (pDerCert != NULL)
            {
                /* Client authentication using a certificate */
#if (!defined(__DISABLE_DIGICERT_SHA256__))
                if (modLength * 8 >= 2048)
                {
                    hashAlgo       = SHA256Suite;
                    contextSize    = sizeof(sha256Descr);
                    pSignatureType = &sshc_rsa2048_cert_sign_signature;
                }
                else
#endif
                {
                    pSignatureType = &sshc_cert_sign_signature;
                }
            }
            else
#endif
            {
                if (modLength * 8 >= 2048)
                {
#if (!defined(__DISABLE_DIGICERT_SHA512__))
                    hashAlgo       = SHA512Suite;
                    contextSize    = sizeof(sha512Descr);
                    pSignatureType = &sshc_rsa2048sha512_signature;
#elif (!defined(__DISABLE_DIGICERT_SHA256__))
                    hashAlgo       = SHA256Suite;
                    contextSize    = sizeof(sha256Descr);
                    pSignatureType = &sshc_rsa2048sha256_signature;
#else
                    status = ERR_SSH_CONFIG;
                    goto exit;
#endif
                }
                else
                {
                    pSignatureType = &sshc_rsa_signature;
                }
            }
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_PQC__))
        case akt_qs:
        {
            status = SSH_QS_buildQsKey(&authKey, isCertificate, FALSE, &pCertificate, &certificateLen);
            if (OK != status)
                goto exit;

            if (TRUE == generateSignature)
            {
                status = SSH_QS_calcQsSignatureLength(&authKey, isCertificate, &signatureLength);
                if (OK != status)
                    goto exit;
            }
            
            status = SSH_QS_getQsAlgorithmName(authKey.pQsCtx->alg, isCertificate, &pSignatureType);
            if (OK != status)
                goto exit;

            break;
        }
#endif /* __ENABLE_DIGICERT_PQC__ */
#if (defined(__ENABLE_DIGICERT_PQC_COMPOSITE__))
        case akt_hybrid:
        {
            ECCKey *pECCKey = authKey.key.pECC;
            ubyte4 curveId;

            status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveId);
            if(OK != status)
                goto exit;
            switch (curveId)
            {
#if (!defined(__DISABLE_DIGICERT_SHA256__))
                case cid_EC_P256:
                    hashAlgo       = SHA256Suite;
                    break;
#endif
#if (!defined(__DISABLE_DIGICERT_SHA384__))
                case cid_EC_P384:
                    hashAlgo       = SHA384Suite;
                    break;
#endif
#if (!defined(__DISABLE_DIGICERT_SHA512__))
                case cid_EC_P521:
                    hashAlgo       = SHA512Suite;
                    break;
#endif
#if defined (__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
                case cid_EC_Ed25519:
                case cid_EC_Ed448:
                    hashAlgo       = NoSuite;
                    break;
#endif
                default:
                    status = ERR_BAD_KEY;
                    break;
            }
            if (OK != status)
                goto exit;
            
            status = SSH_HYBRID_buildHybridKey(MOC_ASYM(pContextSSH->hwAccelCookie) &authKey, isCertificate, FALSE, &pCertificate, &certificateLen);
            if (OK != status)
                goto exit;

            if (TRUE == generateSignature)
            {
                status = SSH_HYBRID_calcHybridSignatureLength(&authKey, isCertificate, &signatureLength);
                if (OK != status)
                    goto exit;
            }
            
            status = SSH_HYBRID_getHybridAlgorithmName(curveId, authKey.pQsCtx->alg, isCertificate, &pSignatureType);
            if (OK != status)
                goto exit;

            break;
        }
#endif /* __ENABLE_DIGICERT_PQC_COMPOSITE__ */
#if (defined(__ENABLE_DIGICERT_ECC__))
         case akt_ecc_ed:
         case akt_ecc:
         {
             ECCKey *pECCKey = authKey.key.pECC;
             ubyte4 curveId = 0;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
             status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveId);
             if(OK != status)
                 goto exit;
#else
             status = EC_getCurveIdFromKey(pECCKey, &curveId);
             if (OK != status)
                 goto exit;
#endif
            if (OK > (status = SSH_ECDSA_buildEcdsaCertificate(MOC_ECC(pContextSSH->hwAccelCookie) &authKey, FALSE, &pCertificate, &certificateLen)))
                goto exit;

            if (TRUE == generateSignature)
                if (OK > (status = SSH_ECDSA_calcEcdsaSignatureLength(&authKey, FALSE, &signatureLength)))
                    goto exit;

#if ((defined(__ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSH_CLIENT_CERT_AUTH__)))
            if (pDerCert != NULL)
            {
                switch (curveId)
                {
#if (!defined(__DISABLE_DIGICERT_SHA256__))
                    case cid_EC_P256:
                        hashAlgo       = SHA256Suite;
                        pSignatureType = &sshc_ecdsa_cert_signature_p256;
                        break;
#endif
#if (!defined(__DISABLE_DIGICERT_SHA384__))
                    case cid_EC_P384:
                        hashAlgo       = SHA384Suite;
                        pSignatureType = &sshc_ecdsa_cert_signature_p384;
                        break;
#endif
#if (!defined(__DISABLE_DIGICERT_SHA512__))
                    case cid_EC_P521:
                        hashAlgo       = SHA512Suite;
                        pSignatureType = &sshc_ecdsa_cert_signature_p521;
                        break;
#endif
                    case cid_EC_Ed25519:
                        hashAlgo       = NoSuite;
                        pSignatureType = &sshc_ecdsa_signature_ed25519;
                        break;
                    default:
                        status = ERR_BAD_KEY;
                        break;
                }
            }
            else
#endif /* __ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__ */
            {
                switch (curveId)
                {
#if (!defined(__DISABLE_DIGICERT_SHA256__))
                    case cid_EC_P256:
                        hashAlgo       = SHA256Suite;
                        pSignatureType = &sshc_ecdsa_signature_p256;
                        break;
#endif
#if (!defined(__DISABLE_DIGICERT_SHA384__))
                    case cid_EC_P384:
                        hashAlgo       = SHA384Suite;
                        pSignatureType = &sshc_ecdsa_signature_p384;
                        break;
#endif
#if (!defined(__DISABLE_DIGICERT_SHA512__))
                    case cid_EC_P521:
                        hashAlgo       = SHA512Suite;
                        pSignatureType = &sshc_ecdsa_signature_p521;
                        break;
#endif
                    case cid_EC_Ed25519:
                        hashAlgo       = NoSuite;
                        pSignatureType = &sshc_ecdsa_signature_ed25519;
                        break;
                    default:
                        status = ERR_BAD_KEY;
                        break;
                }
            }
            break;

        }
#endif/* __ENABLE_DIGICERT_ECC__ */
        default:
        {
            status = ERR_BAD_KEY_TYPE;
        }
    }
    if (OK > status)
        goto exit;

    if (NULL == pSignatureType)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* calculate length of SSH_MSG_USERAUTH_REQUEST message, including session identifier string */
    messageLen = 1 +
                 (4 + nameLen) +
                 sshc_connectService.stringLen +
                 1 +
                 sshc_authPublicKey.stringLen +
                 pSignatureType->stringLen;

#if ((defined(__ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSH_CLIENT_CERT_AUTH__)))
    if (pDerCert == NULL)
    {
        /* PublicKey based authentication */
        messageLen = messageLen + certificateLen;
    }
    else
    {
        /* Certificate based authentication */
        messageLen = messageLen + derCertLength + 4 + (4 * numCertificates) + (4 + 4 + pSignatureType->stringLen); /* Number of certificates, length of each certificate */
    }
#else
    /* PublicKey based authentication */
    messageLen = messageLen + certificateLen;
#endif

    /* allocate memory for SSH_MSG_USERAUTH_REQUEST message */
    if (NULL == (pMessage = MALLOC(messageLen + signatureLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* fill in SSH_MSG_USERAUTH_REQUEST message */
    *pMessage = SSH_MSG_USERAUTH_REQUEST;
    index++;

    /* user name */
    if (0 > (status = SSH_STR_copyStringToPayload2(pMessage, messageLen, &index, pName, nameLen)))
        goto exit;

    /* service (we're only supporting "ssh-connection") */
    if (OK > (status = SSH_STR_copyStringToPayload3(pMessage, messageLen, &index, &sshc_connectService)))
        goto exit;

    /* "publickey" */
    if (OK > (status = SSH_STR_copyStringToPayload3(pMessage, messageLen, &index, &sshc_authPublicKey)))
        goto exit;

    /* is signed? TRUE */
    *(pMessage + index) = generateSignature;
    index++;

    /* public key algorithm */
    if (OK > (status = SSH_STR_copyStringToPayload3(pMessage, messageLen, &index, pSignatureType)))
        goto exit;

#if ((defined(__ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSH_CLIENT_CERT_AUTH__)))
    if (pDerCert == NULL)
    {
        remainingMesgLen = certificateLen + index;
    }
    else
    {
        remainingMesgLen = derCertLength + index + 4 + pSignatureType->stringLen + 4 + 4 + 4;
    }
#else
    remainingMesgLen = certificateLen + index;
#endif


    if (messageLen != remainingMesgLen)
    {
        /* this should never happen */
        status = ERR_BUFFER_OVERFLOW;
        goto exit;
    }

#if ((defined(__ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSH_CLIENT_CERT_AUTH__)))
    if (pDerCert == NULL)
    {
        /* public key */
        if (0 > (status = DIGI_MEMCPY(index + pMessage, pCertificate, certificateLen)))
            goto exit;
    }
    else
    {
        ubyte4 i;

        /* total length does not include length field itself */
        ubyte4 totalLength = 4 + pSignatureType->stringLen + 4 + 4 + derCertLength + 4;

        /* write total length of the public key blob */
        pMessage[index + 0] = (ubyte)(totalLength >> 24);
        pMessage[index + 1] = (ubyte)(totalLength >> 16);
        pMessage[index + 2] = (ubyte)(totalLength >>  8);
        pMessage[index + 3] = (ubyte)(totalLength);

        index = index + 4;

        /* write pSignatureType */
        status = DIGI_MEMCPY(pMessage + index, pSignatureType->pString, pSignatureType->stringLen);
        if (OK != status)
            goto exit;

        index = index + pSignatureType->stringLen;

        /* Copy number of certificates */
        pMessage[index + 0] = (ubyte)(numCertificates >> 24);
        pMessage[index + 1] = (ubyte)(numCertificates >> 16);
        pMessage[index + 2] = (ubyte)(numCertificates >>  8);
        pMessage[index + 3] = (ubyte)(numCertificates);

        index = index + 4;

        for (i = 0; i < numCertificates; i++)
        {
            /* Copy length of certificate */
            pMessage[index + 0] = (ubyte)(derCertLength >> 24);
            pMessage[index + 1] = (ubyte)(derCertLength >> 16);
            pMessage[index + 2] = (ubyte)(derCertLength >>  8);
            pMessage[index + 3] = (ubyte)(derCertLength);

            index = index + 4;

            /* Copy the certificate */
            if (0 > (status = DIGI_MEMCPY(index + pMessage, pDerCert, derCertLength)))
                goto exit;

            index = index + derCertLength;
        }

        /* 4 bytes for OCSP response count need to be present */
        pMessage[index + 0] = 0;
        pMessage[index + 1] = 0;
        pMessage[index + 2] = 0;
        pMessage[index + 3] = 0;

        index = index + 4;
    }
#else
    /* public key */
    if (0 > (status = DIGI_MEMCPY(index + pMessage, pCertificate, certificateLen)))
        goto exit;
#endif

    if (TRUE == generateSignature)
    {
        status = SSHC_AUTH_generateHashOrMessage(pContextSSH, hashAlgo, pMessage, messageLen, &mBuf, &bufLen, authKey.type);
        if (OK != status)
            goto exit;

        /* sign m */
        switch (authKey.type & 0xff)
        {
#if (defined(__ENABLE_DIGICERT_SSH_DSA_SUPPORT__))
            case akt_dsa:
            {
                if (OK > (status = VLONG_vlongFromByteString(mBuf, hashAlgo.digestSize, &pM, &pVlongQueue)))
                    goto exit;

                status = SSH_DSS_buildDssSignature(MOC_DSA(pContextSSH->hwAccelCookie) &authKey, FALSE, pM,
                                                   &pSignature, &signatureLength, &pVlongQueue);
                break;
            }
#endif
#if (defined(__ENABLE_DIGICERT_SSH_RSA_SUPPORT__))
            case akt_rsa:
            {
                status = SSH_RSA_buildRsaSignature(MOC_RSA(pContextSSH->hwAccelCookie) &authKey, FALSE,
                                                   &pSignature, &signatureLength,
                                                   mBuf, hashAlgo.digestSize, pSignatureType->pString + 4,
                                                   pSignatureType->stringLen - 4);
                break;
            }
#endif
#if (defined(__ENABLE_DIGICERT_PQC__))
            case akt_qs:
            {
                status = SSH_QS_buildQsSignature(MOC_HASH(pContextSSH->hwAccelCookie) &authKey, isCertificate,
                                                 FALSE, mBuf, bufLen,
                                                 &pSignature, &signatureLength);
                break;
            }
#endif
#if (defined(__ENABLE_DIGICERT_PQC_COMPOSITE__))
            case akt_hybrid:
            {
                status = SSH_HYBRID_buildHybridSignature(MOC_ASYM(pContextSSH->hwAccelCookie) &authKey, isCertificate,
                                                        FALSE, mBuf, bufLen,
                                                        &pSignature, &signatureLength);
                break;
            }
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
            case akt_ecc_ed:
            case akt_ecc:
            {
                status = SSH_ECDSA_buildEcdsaSignatureEx(MOC_ECC(pContextSSH->hwAccelCookie) &authKey, hashAlgo.hashId,
                                                   mBuf, bufLen,
                                                   &pSignature, &signatureLength);
                break;
            }
#endif
            default:
            {
                status = ERR_BAD_KEY_TYPE;
            }
        }

        if (OK > status)
            goto exit;

        /* copy signature */
        DIGI_MEMCPY(pMessage + messageLen, pSignature, signatureLength);
    }

    if (OK > (status = SSHC_OUT_MESG_sendMessage(pContextSSH, pMessage, messageLen + signatureLength, &numBytesWritten)))
        goto exit;

    /* verify write completed */
    if ((messageLen + signatureLength) != numBytesWritten)
        status = ERR_AUTH_MESG_FRAGMENTED;

exit:
    if ((NULL != pKeyBlob) && (NULL != SSHC_sshClientSettings()->funcPtrReleaseNakedAuthKeys))
    {
        MSTATUS status1 = SSHC_sshClientSettings()->funcPtrReleaseNakedAuthKeys(pContextSSH->connectionInstance, &pKeyBlob);

        if (OK <= status)   /* we can only report one error */
            status = status1;
    }

    if (NULL != pMessage)
        FREE(pMessage);

    if (NULL != pCertificate)
        FREE(pCertificate);

    if (NULL != pSignature)
        DIGI_FREE((void**)&pSignature);

    if (NULL != mBuf)
        DIGI_FREE((void **) &mBuf);

#if ((defined(__ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSH_CLIENT_CERT_AUTH__)))
    if (pDerCert == NULL)
    {
        /* Need to free authKey here to avoid mem leaks */
        CRYPTO_uninitAsymmetricKey(&authKey, &pVlongQueue);
    }
#else
    CRYPTO_uninitAsymmetricKey(&authKey, &pVlongQueue);
#endif

    VLONG_freeVlong(&pM, 0);
    VLONG_freeVlongQueue(&pVlongQueue);

    return status;

} /* SSHC_AUTH_publicKeyAuth */

/*------------------------------------------------------------------*/
static MSTATUS
sshc_DoClientAuthenticate(MOC_ASYM(hwAccelDescr hwAccelCtx) sshClientContext *pContextSSH, sshStringBuffer *pAuthNameList,  ubyte receivedMessageCode)
{
    ubyte*           pName = NULL;
    ubyte4           nameLen = 0;
    ubyte4           method = 0;
    authMethodDescr* pDesc;
    ubyte4           i;
    sbyte*           pOptionName = NULL;
    /* default value of TRUE in case (funcPtrRetrieveUserAuthRequestInfoEx) isn't defined */
    intBoolean       generateSignature = TRUE; 
    MSTATUS          status;

    if (NULL != SSHC_sshClientSettings()->funcPtrRetrieveUserAuthRequestInfoEx)
    {
        (SSHC_sshClientSettings()->funcPtrRetrieveUserAuthRequestInfoEx)(pContextSSH->connectionInstance,
                                            receivedMessageCode, pContextSSH->authType,
                                            (NULL == pAuthNameList) ? NULL : pAuthNameList->pString,
                                            (NULL == pAuthNameList) ? 0 : pAuthNameList->stringLen,
                                                                &pName, &nameLen, &method, &generateSignature);
    }
    else if (NULL != SSHC_sshClientSettings()->funcPtrRetrieveUserAuthRequestInfo)
    {
        (SSHC_sshClientSettings()->funcPtrRetrieveUserAuthRequestInfo)(pContextSSH->connectionInstance,
                                            (NULL == pAuthNameList) ? NULL : pAuthNameList->pString,
                                            (NULL == pAuthNameList) ? 0 : pAuthNameList->stringLen,
                                                                &pName, &nameLen, &method);
    }

    if (NULL == pName)
        nameLen = 0;

    for (i = NUM_AUTH_OPTIONS, pDesc = mAuthMethods; 0 < i; i--, pDesc++)
    {
        if (pDesc->bitMask == method)
        {
            pOptionName      = pDesc->pOptionName;
            break;
        }
    }

    if (NULL == pOptionName)
    {
        status = ERR_SSH_CLIENT_AUTH_NO_METHOD;
        goto exit;
    }

    switch (method)
    {
        case MOCANA_SSH_AUTH_PUBLIC_KEY:
            if (OK > (status = SSHC_AUTH_publicKeyAuth(MOC_ASYM(hwAccelCtx) pContextSSH, pName, nameLen, generateSignature)))
                goto exit;
            break;

        case MOCANA_SSH_AUTH_PASSWORD:
            if (OK > (status = passwordAuth(pContextSSH, pName, nameLen)))
                goto exit;
            break;

#ifdef __ENABLE_DIGICERT_SSH_AUTH_KEYBOARD_INTERACTIVE__
        case MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE:
            if (OK > (status = SSHC_AUTH_keyboardInteractiveAuth(pContextSSH, pName, nameLen)))
                    goto exit;
            break;
#endif
        case MOCANA_SSH_AUTH_NONE:
            if(OK > (status = noneAuth(pContextSSH, pName, nameLen)))
                goto exit;
            break;
        case MOCANA_SSH_AUTH_CERT:
            if (OK > (status = SSHC_AUTH_publicKeyAuth(MOC_ASYM(hwAccelCtx) pContextSSH, pName, nameLen, generateSignature)))
                goto exit;
            break;

        default:
            status = ERR_SSH_CLIENT_AUTH_HANDLER;
            break;
    }

exit:
    if (OK >= status)
        pContextSSH->authType = method;

    return status;

} /* sshc_DoClientAuthenticate */


/*------------------------------------------------------------------*/

static MSTATUS
sshc_receiveAuthMessage(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    sshStringBuffer* pAuthNameList = NULL;
    ubyte4           bytesUsed = 0;
    sbyte4           compareValue = -1;
    MSTATUS          status = OK;
    ubyte4           msgType = *pNewMesg;
    hwAccelDescr     hwAccelCtx;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCtx)))
        goto nocleanup;

    switch (msgType)
    {
        case SSH_MSG_SERVICE_ACCEPT:  /* should this be over in sshc_trans??? */
        {
            pContextSSH->authType = 0;

            if ((newMesgLen != 1 + sshc_userAuthService.stringLen) ||
                (OK > (status = DIGI_MEMCMP(pNewMesg + 1, sshc_userAuthService.pString, sshc_userAuthService.stringLen, &compareValue))) )
            {
                goto exit;
            }

            if (0 == compareValue)  /* is "ssh-userauth" service request */
            {
                /* sucess, move on to client authentication */
                if (0 > (status = sshc_DoClientAuthenticate(MOC_ASYM(hwAccelCtx) pContextSSH, NULL, SSH_MSG_SERVICE_ACCEPT)))
                    goto exit;
            }

            break;
        }

        case SSH_MSG_USERAUTH_SUCCESS:
        {
            /* authentication succeeded change state */
            SSH_UPPER_STATE(pContextSSH) = kOpenState;

            if (NULL != SSHC_sshClientSettings()->funcPtrAuthOpen)
                (SSHC_sshClientSettings()->funcPtrAuthOpen)(CONNECTION_INSTANCE(pContextSSH));

            break;
        }

        case SSH_MSG_USERAUTH_BANNER:
        {
#ifdef __ENABLE_DIGICERT_SSH_AUTH_BANNER__
            ubyte4           length;
            if (NULL != SSHC_sshClientSettings()->funcPtrDisplayBanner)
            {
                length  = ((ubyte4)(*(pNewMesg+1)) << 24);
                length |= ((ubyte4)(*(pNewMesg+2)) << 16);
                length |= ((ubyte4)(*(pNewMesg+3)) << 8);
                length |= ((ubyte4)(*(pNewMesg+4)));

                SSHC_sshClientSettings()->funcPtrDisplayBanner(CONNECTION_INSTANCE(pContextSSH),
                                                pNewMesg+1+4, length, pNewMesg + 1 + 4 + length );
            }
#endif
            break;
        }

        case SSH_MSG_USERAUTH_FAILURE:
        {
            pContextSSH->authContext.authNumAttempts++;

            if (SSHC_sshClientSettings()->sshMaxAuthAttempts <= pContextSSH->authContext.authNumAttempts)
            {
                status = ERR_AUTH_FAILED;
                goto exit;
            }

            pNewMesg++;  /* move past message type */
            newMesgLen--;

            /* copy authentication name-list */
            if (OK > (status = SSH_STR_copyStringFromPayload2(pNewMesg, newMesgLen, &bytesUsed, &pAuthNameList)))
                goto exit;

            status = sshc_DoClientAuthenticate(MOC_ASYM(hwAccelCtx) pContextSSH, pAuthNameList, SSH_MSG_USERAUTH_FAILURE);

            break;
        }

        case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
        {
            /* SSH_MSG_USERAUTH_PASSWD_CHANGEREQ == SSH_MSG_USERAUTH_PK_OK */
            if ((MOCANA_SSH_AUTH_PUBLIC_KEY == pContextSSH->authType) ||
                (MOCANA_SSH_AUTH_CERT == pContextSSH->authType))
            {
                if (0 > (status = sshc_DoClientAuthenticate(pContextSSH, NULL, SSH_MSG_USERAUTH_PK_OK)))
                    goto exit;
            }
#ifdef __ENABLE_DIGICERT_SSH_AUTH_KEYBOARD_INTERACTIVE__
            else if(MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE == pContextSSH->authType)
            {
                /* SSH_MSG_USERAUTH_PASSWD_CHANGEREQ == SSH_MSG_USERAUTH_INFO_REQUEST */
                if (0 > (status = SSHC_AUTH_processKeyboardInteractiveReq(pContextSSH, pNewMesg, newMesgLen)))
                    goto exit;
            }
#endif
            else
            {
                status = ERR_AUTH_FAILED;
                break;
            }

            break;
        }
        default:
        {
            status = ERR_AUTH_FAILED;
            break;
        }
    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &hwAccelCtx);

    if (NULL != pAuthNameList)
        SSH_STR_freeStringBuffer(&pAuthNameList);

nocleanup:
    return status;

} /* sshc_receiveAuthMessage */

/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_AUTH_doProtocol(sshClientContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    MSTATUS              status = OK;

    switch (SSH_UPPER_STATE(pContextSSH))
    {
        case kAuthServiceRequest:
            /* in the client case this means we've gotten a response from the
             * server for OUR request */
        case kAuthReceiveMessage:
            status = sshc_receiveAuthMessage(pContextSSH, pNewMesg, newMesgLen);
            break;

        default:
            status = ERR_SSH_BAD_AUTH_RECEIVE_STATE;
            break;
    }

    return status;
} /* SSHC_AUTH_doProtocol */


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_AUTH_allocStructures(sshClientContext *pContextSSH)
{
    MSTATUS status = OK;

    if (NULL == pContextSSH)
        status = ERR_NULL_POINTER;
    else
    {
        AUTH_FAILURE_BUFFER(pContextSSH) = MALLOC(1 + sshc_authMethods.stringLen + 1);

        if (NULL == AUTH_FAILURE_BUFFER(pContextSSH))
            status = ERR_MEM_ALLOC_FAIL;
        else
        {
            /* fill the byte array for usage later */
            AUTH_FAILURE_BUFFER(pContextSSH)[0] = SSH_MSG_USERAUTH_FAILURE;
            DIGI_MEMCPY(&(AUTH_FAILURE_BUFFER(pContextSSH)[1]), sshc_authMethods.pString, sshc_authMethods.stringLen);
            AUTH_KEYINT_CONTEXT(pContextSSH).user         = NULL;
            AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest = NULL;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_AUTH_deallocStructures(sshClientContext *pContextSSH)
{
    MSTATUS status = OK;

    if ((NULL == pContextSSH) || (NULL == AUTH_FAILURE_BUFFER(pContextSSH)))
        status = ERR_NULL_POINTER;
    else
    {
        FREE(AUTH_FAILURE_BUFFER(pContextSSH));
        AUTH_FAILURE_BUFFER(pContextSSH) = NULL;

        SSH_STR_freeStringBuffer(&AUTH_KEYINT_CONTEXT(pContextSSH).user);
        if (NULL != AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest)
        {
            FREE(AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest);
            AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest = NULL;
        }
    }

    return status;
}



#endif /* __ENABLE_DIGICERT_SSH_CLIENT__ */
