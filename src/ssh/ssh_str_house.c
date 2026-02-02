/*
 * ssh_str_house.c
 *
 * SSH String Storehouse
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

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SSH_SERVER__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../ssh/ssh_str.h"
#include "../ssh/ssh_str_house.h"

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
 #ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
  #define MOCANA_SSH_STR_HOUSE_OPTIONS    44
 #else
  #define MOCANA_SSH_STR_HOUSE_OPTIONS    32
 #endif
#else
 #define MOCANA_SSH_STR_HOUSE_OPTIONS    20
#endif

/*------------------------------------------------------------------*/

/* external prototypes */
extern sbyte *SSH_TRANS_keyExList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie);
extern sbyte *SSH_TRANS_keyExListNoEcc(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie);
extern sbyte *SSH_TRANS_hostKeyList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie);
extern sbyte *SSH_TRANS_cipherList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie);
extern sbyte *SSH_TRANS_hmacList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie);
extern sbyte *SSH_AUTH_authList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie);


/*------------------------------------------------------------------*/

/* transport related ssh strings */
sshStringBuffer ssh_disconnectMesg;
sshStringBuffer ssh_disconnectAuthMesg;
sshStringBuffer ssh_languageTag;

/* key exchange related ssh strings */
sshStringBuffer ssh_kexMethods;
sshStringBuffer ssh_hostKeyMethods;
sshStringBuffer ssh_encC2SMethods;
sshStringBuffer ssh_encS2CMethods;
sshStringBuffer ssh_macC2SMethods;
sshStringBuffer ssh_macS2CMethods;
sshStringBuffer ssh_compC2SMethods;
sshStringBuffer ssh_compS2CMethods;
sshStringBuffer ssh_langC2SMethods;
sshStringBuffer ssh_langS2CMethods;

/* authentication related ssh strings */
sshStringBuffer ssh_dss_signature;
sshStringBuffer ssh_rsa_signature;
sshStringBuffer ssh_rsasha256_signature;
sshStringBuffer ssh_rsasha512_signature;
sshStringBuffer ssh_ecdsa_signature;
sshStringBuffer ssh_ecdsa_signature_p192;
sshStringBuffer ssh_ecdsa_signature_p224;
sshStringBuffer ssh_ecdsa_signature_p256;
sshStringBuffer ssh_ecdsa_signature_p384;
sshStringBuffer ssh_ecdsa_signature_p521;
sshStringBuffer ssh_ecdsa_signature_ed25519;
sshStringBuffer ssh_ecdsa_curve_p192;
sshStringBuffer ssh_ecdsa_curve_p224;
sshStringBuffer ssh_ecdsa_curve_p256;
sshStringBuffer ssh_ecdsa_curve_p384;
sshStringBuffer ssh_ecdsa_curve_p521;

#ifdef __ENABLE_DIGICERT_PQC__
sshStringBuffer ssh_mldsa44_signature;
sshStringBuffer ssh_mldsa65_signature;
sshStringBuffer ssh_mldsa87_signature;
#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
sshStringBuffer ssh_cert_mldsa44_signature;
sshStringBuffer ssh_cert_mldsa65_signature;
sshStringBuffer ssh_cert_mldsa87_signature;
#endif
#endif /* __ENABLE_DIGICERT_PQC__ */

#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
sshStringBuffer ssh_mldsa44_p256_signature;
sshStringBuffer ssh_mldsa65_p256_signature;
sshStringBuffer ssh_mldsa87_p384_signature;
sshStringBuffer ssh_mldsa44_ed25519_signature;
sshStringBuffer ssh_mldsa65_ed25519_signature;
sshStringBuffer ssh_mldsa87_ed448_signature;
#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
sshStringBuffer ssh_cert_mldsa44_p256_signature;
sshStringBuffer ssh_cert_mldsa65_p256_signature;
sshStringBuffer ssh_cert_mldsa87_p384_signature;
sshStringBuffer ssh_cert_mldsa44_ed25519_signature;
sshStringBuffer ssh_cert_mldsa65_ed25519_signature;
sshStringBuffer ssh_cert_mldsa87_ed448_signature;
#endif
#endif /* __ENABLE_DIGICERT_PQC_COMPOSITE__ */

sshStringBuffer ssh_rsa_sha1_signature;
sshStringBuffer ssh_rsa_cert_sign_signature;
sshStringBuffer ssh_rsa2048_cert_sign_signature;
sshStringBuffer ssh_rsasha256_cert_signature;
sshStringBuffer ssh_ecdsa_cert_signature_p192;
sshStringBuffer ssh_ecdsa_cert_signature_p224;
sshStringBuffer ssh_ecdsa_cert_signature_p256;
sshStringBuffer ssh_ecdsa_cert_signature_p384;
sshStringBuffer ssh_ecdsa_cert_signature_p521;
sshStringBuffer ssh_userAuthService;
sshStringBuffer ssh_connectService;
sshStringBuffer ssh_authMethods;

/* session related ssh strings */
sshStringBuffer ssh_sessionService;
sshStringBuffer ssh_forwardService;
sshStringBuffer ssh_cancelforwardService;
sshStringBuffer ssh_forwardedService;
sshStringBuffer ssh_directService;
sshStringBuffer ssh_channelUnknown;
sshStringBuffer ssh_resourceShort;
sshStringBuffer ssh_terminalType;
sshStringBuffer ssh_shellType;
sshStringBuffer ssh_execRequest;
sshStringBuffer ssh_subSystem;
sshStringBuffer ssh_windowChange;
sshStringBuffer ssh_breakOperation;

/* helper code */
#ifdef __ENABLE_DIGICERT_SSH_PING__
sshStringBuffer ssh_pingChannel;
#endif

/* scp related strings */
sshStringBuffer ssh_scpExec;


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_HOUSE_initStringBuffer(sshStringBuffer *p_sshStringBuffer, sbyte *pString)
{
    ubyte4  stringLength = 0;
    ubyte*  pStringBuf;
    MSTATUS status = OK;

    while ('\0' != pString[stringLength])
        stringLength++;

    if (NULL == (pStringBuf = p_sshStringBuffer->pString = MALLOC(4 + stringLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    p_sshStringBuffer->stringLen = 4 + stringLength;
    pStringBuf[0] = (ubyte)(stringLength >> 24);
    pStringBuf[1] = (ubyte)(stringLength >> 16);
    pStringBuf[2] = (ubyte)(stringLength >>  8);
    pStringBuf[3] = (ubyte)(stringLength);

    DIGI_MEMCPY(4 + pStringBuf, (ubyte *)pString, stringLength);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_HOUSE_createFromList(sshStringBuffer *p_sshStringBuffer, sbyte *(*callbackList)(ubyte4, ubyte4 *, ubyte4), ubyte4 cookie)
{
    ubyte4  index, stringLen, stringSize;
    sbyte*  pString;
    MSTATUS status = OK;

    /* calculate list length */
    for (stringLen = index = 0; (NULL != callbackList(index, &stringSize, cookie)); index++)
    {
        /* for comma or string terminator */
        stringLen += (stringSize + 1);
    }

    /* allocate buffer */
    if (NULL == (p_sshStringBuffer->pString = MALLOC(4 + stringLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* setup lengths */
    if (stringLen)
        stringLen--;

    p_sshStringBuffer->stringLen = 4 + stringLen;
    p_sshStringBuffer->pString[0] = (sbyte)(stringLen >> 24);
    p_sshStringBuffer->pString[1] = (sbyte)(stringLen >> 16);
    p_sshStringBuffer->pString[2] = (sbyte)(stringLen >>  8);
    p_sshStringBuffer->pString[3] = (sbyte)(stringLen);

    /* copy list strings into buffer */
    stringLen = 4;

    for (index = 0; (NULL != (pString = callbackList(index, &stringSize, cookie))); index++)
    {
        /* duplicate string */
        while ('\0' != *pString)
        {
            p_sshStringBuffer->pString[stringLen] = *pString;
            pString++;
            stringLen++;
        }

        /* add comma */
        p_sshStringBuffer->pString[stringLen] = ',';
        stringLen++;
    }

    /* we don't count this last byte */
    p_sshStringBuffer->pString[stringLen-1] = '\0';

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_HOUSE_createFromList1(sshStringBuffer *p_sshStringBuffer, sbyte4 iterations, sbyte *(*callbackList)(ubyte4, ubyte4 *, void *), void *pCookie)
{
    ubyte*  strings[MOCANA_SSH_STR_HOUSE_OPTIONS];
    sbyte4  index;
    ubyte4  stringLen, stringSize;
    sbyte*  pString;
    MSTATUS status = OK;

    if (MOCANA_SSH_STR_HOUSE_OPTIONS <= iterations)
    {
        status = ERR_SSH_CONFIG;
        goto exit;
    }

    /* calculate list length */
    for (stringLen = index = 0; index < iterations; index++)
    {
        if (NULL != (strings[index] = (ubyte *)callbackList(index, &stringSize, pCookie)))
        {
            /* for comma or string terminator */
            stringLen += (stringSize + 1);
        }
    }

    /* allocate buffer */
    if (NULL == (p_sshStringBuffer->pString = MALLOC(4 + stringLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* setup lengths */
    stringLen--;
    p_sshStringBuffer->stringLen = 4 + stringLen;
    p_sshStringBuffer->pString[0] = (sbyte)(stringLen >> 24);
    p_sshStringBuffer->pString[1] = (sbyte)(stringLen >> 16);
    p_sshStringBuffer->pString[2] = (sbyte)(stringLen >>  8);
    p_sshStringBuffer->pString[3] = (sbyte)(stringLen);

    /* copy list strings into buffer */
    stringLen = 4;

    for (index = 0; index < iterations; index++)
    {
        if (NULL == (pString = (sbyte *)strings[index]))
            continue;

        /* duplicate string */
        while ('\0' != *pString)
        {
            p_sshStringBuffer->pString[stringLen] = *pString;
            pString++;
            stringLen++;
        }

        /* add comma */
        p_sshStringBuffer->pString[stringLen] = ',';
        stringLen++;
    }

    /* we don't count this last byte */
    p_sshStringBuffer->pString[stringLen-1] = '\0';

exit:
    return status;

} /* SSH_STR_HOUSE_createFromList1 */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_HOUSE_initStringBuffers(void)
{
#define INIT_SSH_STRING_BUFFER(X,Y)    if (OK > (status = SSH_STR_HOUSE_initStringBuffer(X,Y))) goto exit

    MSTATUS status;

    INIT_SSH_STRING_BUFFER(&ssh_disconnectMesg, (sbyte *)"Logged out.");
    INIT_SSH_STRING_BUFFER(&ssh_disconnectAuthMesg, (sbyte *)"Too many authentication failures.");
    INIT_SSH_STRING_BUFFER(&ssh_languageTag, (sbyte *)"en");

    if (OK > (status = SSH_STR_HOUSE_createFromList(&ssh_kexMethods, SSH_TRANS_keyExList, 0))) goto exit;
    if (OK > (status = SSH_STR_HOUSE_createFromList(&ssh_hostKeyMethods, SSH_TRANS_hostKeyList, 0))) goto exit;
    if (OK > (status = SSH_STR_HOUSE_createFromList(&ssh_encC2SMethods, SSH_TRANS_cipherList, 0))) goto exit;
    if (OK > (status = SSH_STR_HOUSE_createFromList(&ssh_encS2CMethods, SSH_TRANS_cipherList, 0))) goto exit;
    if (OK > (status = SSH_STR_HOUSE_createFromList(&ssh_macC2SMethods, SSH_TRANS_hmacList, 0))) goto exit;
    if (OK > (status = SSH_STR_HOUSE_createFromList(&ssh_macS2CMethods, SSH_TRANS_hmacList, 0))) goto exit;
    INIT_SSH_STRING_BUFFER(&ssh_compC2SMethods, (sbyte *)"none");
    INIT_SSH_STRING_BUFFER(&ssh_compS2CMethods, (sbyte *)"none");
    INIT_SSH_STRING_BUFFER(&ssh_langC2SMethods, (sbyte *)"");
    INIT_SSH_STRING_BUFFER(&ssh_langS2CMethods, (sbyte *)"");

    INIT_SSH_STRING_BUFFER(&ssh_dss_signature, (sbyte *)"ssh-dss");
    INIT_SSH_STRING_BUFFER(&ssh_rsa_signature, (sbyte *)"ssh-rsa");
    INIT_SSH_STRING_BUFFER(&ssh_rsasha256_signature, (sbyte *)"rsa-sha2-256");
    INIT_SSH_STRING_BUFFER(&ssh_rsasha512_signature, (sbyte *)"rsa-sha2-512");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_signature, (sbyte *)"ecdsa-sha2");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_signature_p192, (sbyte *)"ecdsa-sha2-nistp192");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_signature_p224, (sbyte *)"ecdsa-sha2-nistp224");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_signature_p256, (sbyte *)"ecdsa-sha2-nistp256");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_signature_p384, (sbyte *)"ecdsa-sha2-nistp384");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_signature_p521, (sbyte *)"ecdsa-sha2-nistp521");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_signature_ed25519, (sbyte *)"ssh-ed25519");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_curve_p192, (sbyte *)"nistp192");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_curve_p224, (sbyte *)"nistp224");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_curve_p256, (sbyte *)"nistp256");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_curve_p384, (sbyte *)"nistp384");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_curve_p521, (sbyte *)"nistp521");
#ifdef __ENABLE_DIGICERT_PQC__
    INIT_SSH_STRING_BUFFER(&ssh_mldsa44_signature, (sbyte *)"ssh-mldsa44");
    INIT_SSH_STRING_BUFFER(&ssh_mldsa65_signature, (sbyte *)"ssh-mldsa65");
    INIT_SSH_STRING_BUFFER(&ssh_mldsa87_signature, (sbyte *)"ssh-mldsa87");
#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
    INIT_SSH_STRING_BUFFER(&ssh_cert_mldsa44_signature, (sbyte *)"x509v3-mldsa44");
    INIT_SSH_STRING_BUFFER(&ssh_cert_mldsa65_signature, (sbyte *)"x509v3-mldsa65");
    INIT_SSH_STRING_BUFFER(&ssh_cert_mldsa87_signature, (sbyte *)"x509v3-mldsa87");
#endif
#endif /* __ENABLE_DIGICERT_PQC__ */
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
    INIT_SSH_STRING_BUFFER(&ssh_mldsa44_p256_signature, (sbyte *)"ssh-mldsa44-es256");
    INIT_SSH_STRING_BUFFER(&ssh_mldsa65_p256_signature, (sbyte *)"ssh-mldsa65-es256");
    INIT_SSH_STRING_BUFFER(&ssh_mldsa87_p384_signature, (sbyte *)"ssh-mldsa87-es384");
    INIT_SSH_STRING_BUFFER(&ssh_mldsa44_ed25519_signature, (sbyte *)"ssh-mldsa44-ed25519");
    INIT_SSH_STRING_BUFFER(&ssh_mldsa65_ed25519_signature, (sbyte *)"ssh-mldsa65-ed25519");
    INIT_SSH_STRING_BUFFER(&ssh_mldsa87_ed448_signature, (sbyte *)"ssh-mldsa87-ed448");
#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
    INIT_SSH_STRING_BUFFER(&ssh_cert_mldsa44_p256_signature, (sbyte *)"x509v3-mldsa44-es256");
    INIT_SSH_STRING_BUFFER(&ssh_cert_mldsa65_p256_signature, (sbyte *)"x509v3-mldsa65-es256");
    INIT_SSH_STRING_BUFFER(&ssh_cert_mldsa87_p384_signature, (sbyte *)"x509v3-mldsa87-es384");
    INIT_SSH_STRING_BUFFER(&ssh_cert_mldsa44_ed25519_signature, (sbyte *)"x509v3-mldsa44-ed25519");
    INIT_SSH_STRING_BUFFER(&ssh_cert_mldsa65_ed25519_signature, (sbyte *)"x509v3-mldsa65-ed25519");
    INIT_SSH_STRING_BUFFER(&ssh_cert_mldsa87_ed448_signature, (sbyte *)"x509v3-mldsa87-ed448");
#endif
#endif /* __ENABLE_DIGICERT_PQC_COMPOSITE__ */
    INIT_SSH_STRING_BUFFER(&ssh_rsa_sha1_signature, (sbyte *)"rsa-sha1");
#ifdef __ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__
    INIT_SSH_STRING_BUFFER(&ssh_rsa_cert_sign_signature, (sbyte *)"x509v3-ssh-rsa");
    INIT_SSH_STRING_BUFFER(&ssh_rsa2048_cert_sign_signature, (sbyte *)"x509v3-rsa2048-sha256");
    INIT_SSH_STRING_BUFFER(&ssh_rsasha256_cert_signature, (sbyte *)"rsa2048-sha256");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_cert_signature_p192, (sbyte *)"x509v3-ecdsa-sha2-nistp192");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_cert_signature_p224, (sbyte *)"x509v3-ecdsa-sha2-nistp224");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_cert_signature_p256, (sbyte *)"x509v3-ecdsa-sha2-nistp256");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_cert_signature_p384, (sbyte *)"x509v3-ecdsa-sha2-nistp384");
    INIT_SSH_STRING_BUFFER(&ssh_ecdsa_cert_signature_p521, (sbyte *)"x509v3-ecdsa-sha2-nistp521");
#endif

    INIT_SSH_STRING_BUFFER(&ssh_userAuthService, (sbyte *)"ssh-userauth");
    INIT_SSH_STRING_BUFFER(&ssh_connectService, (sbyte *)"ssh-connection");
    if (OK > (status = SSH_STR_HOUSE_createFromList(&ssh_authMethods, SSH_AUTH_authList, 0xffffffff)))
        goto exit;

    INIT_SSH_STRING_BUFFER(&ssh_sessionService, (sbyte *)"session");
    INIT_SSH_STRING_BUFFER(&ssh_forwardService, (sbyte *)"tcpip-forward");
    INIT_SSH_STRING_BUFFER(&ssh_cancelforwardService, (sbyte *)"cancel-tcpip-forward");
    INIT_SSH_STRING_BUFFER(&ssh_forwardedService, (sbyte *)"forwarded-tcpip");
    INIT_SSH_STRING_BUFFER(&ssh_directService, (sbyte *)"direct-tcpip");
    INIT_SSH_STRING_BUFFER(&ssh_channelUnknown, (sbyte *)"Unknown channel type");
    INIT_SSH_STRING_BUFFER(&ssh_resourceShort, (sbyte *)"Server supports one session per SSH client");
    INIT_SSH_STRING_BUFFER(&ssh_terminalType, (sbyte *)"pty-req");
    INIT_SSH_STRING_BUFFER(&ssh_shellType, (sbyte *)"shell");
    INIT_SSH_STRING_BUFFER(&ssh_execRequest, (sbyte *)"exec");
    INIT_SSH_STRING_BUFFER(&ssh_subSystem, (sbyte *)"subsystem");
    INIT_SSH_STRING_BUFFER(&ssh_windowChange, (sbyte *)"window-change");
    INIT_SSH_STRING_BUFFER(&ssh_breakOperation, (sbyte *)"break");

#ifdef __ENABLE_DIGICERT_SSH_PING__
    INIT_SSH_STRING_BUFFER(&ssh_pingChannel, (sbyte *)"ping-mocana-com");
#endif

    INIT_SSH_STRING_BUFFER(&ssh_scpExec, (sbyte *)"exec");

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_HOUSE_freeStringBuffers(void)
{
#define FREE_SSH_STRING_BUFFER(X)    if (NULL != X.pString) { FREE(X.pString); X.pString = NULL; }

    FREE_SSH_STRING_BUFFER(ssh_disconnectMesg);
    FREE_SSH_STRING_BUFFER(ssh_disconnectAuthMesg);
    FREE_SSH_STRING_BUFFER(ssh_languageTag);

    FREE_SSH_STRING_BUFFER(ssh_kexMethods);
    FREE_SSH_STRING_BUFFER(ssh_hostKeyMethods);
    FREE_SSH_STRING_BUFFER(ssh_encC2SMethods);
    FREE_SSH_STRING_BUFFER(ssh_encS2CMethods);
    FREE_SSH_STRING_BUFFER(ssh_macC2SMethods);
    FREE_SSH_STRING_BUFFER(ssh_macS2CMethods);
    FREE_SSH_STRING_BUFFER(ssh_compC2SMethods);
    FREE_SSH_STRING_BUFFER(ssh_compS2CMethods);
    FREE_SSH_STRING_BUFFER(ssh_langC2SMethods);
    FREE_SSH_STRING_BUFFER(ssh_langS2CMethods);

    FREE_SSH_STRING_BUFFER(ssh_dss_signature);
    FREE_SSH_STRING_BUFFER(ssh_rsa_signature);
    FREE_SSH_STRING_BUFFER(ssh_rsasha256_signature);
    FREE_SSH_STRING_BUFFER(ssh_rsasha512_signature);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_signature);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_signature_p192);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_signature_p224);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_signature_p256);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_signature_p384);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_signature_p521);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_signature_ed25519);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_curve_p192);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_curve_p224);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_curve_p256);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_curve_p384);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_curve_p521);

#ifdef __ENABLE_DIGICERT_PQC__
    FREE_SSH_STRING_BUFFER(ssh_mldsa44_signature);
    FREE_SSH_STRING_BUFFER(ssh_mldsa65_signature);
    FREE_SSH_STRING_BUFFER(ssh_mldsa87_signature);
#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
    FREE_SSH_STRING_BUFFER(ssh_cert_mldsa44_signature);
    FREE_SSH_STRING_BUFFER(ssh_cert_mldsa65_signature);
    FREE_SSH_STRING_BUFFER(ssh_cert_mldsa87_signature);
#endif
#endif /* __ENABLE_DIGICERT_PQC__ */
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
    FREE_SSH_STRING_BUFFER(ssh_mldsa44_p256_signature);
    FREE_SSH_STRING_BUFFER(ssh_mldsa65_p256_signature);
    FREE_SSH_STRING_BUFFER(ssh_mldsa87_p384_signature);
    FREE_SSH_STRING_BUFFER(ssh_mldsa44_ed25519_signature);
    FREE_SSH_STRING_BUFFER(ssh_mldsa65_ed25519_signature);
    FREE_SSH_STRING_BUFFER(ssh_mldsa87_ed448_signature);
#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
    FREE_SSH_STRING_BUFFER(ssh_cert_mldsa44_p256_signature);
    FREE_SSH_STRING_BUFFER(ssh_cert_mldsa65_p256_signature);
    FREE_SSH_STRING_BUFFER(ssh_cert_mldsa87_p384_signature);
    FREE_SSH_STRING_BUFFER(ssh_cert_mldsa44_ed25519_signature);
    FREE_SSH_STRING_BUFFER(ssh_cert_mldsa65_ed25519_signature);
    FREE_SSH_STRING_BUFFER(ssh_cert_mldsa87_ed448_signature);
#endif
#endif /* __ENABLE_DIGICERT_PQC_COMPOSITE__ */
    FREE_SSH_STRING_BUFFER(ssh_rsa_sha1_signature);
    FREE_SSH_STRING_BUFFER(ssh_rsa_cert_sign_signature);
    FREE_SSH_STRING_BUFFER(ssh_rsa2048_cert_sign_signature);
    FREE_SSH_STRING_BUFFER(ssh_rsasha256_cert_signature);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_cert_signature_p192);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_cert_signature_p224);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_cert_signature_p256);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_cert_signature_p384);
    FREE_SSH_STRING_BUFFER(ssh_ecdsa_cert_signature_p521);
    FREE_SSH_STRING_BUFFER(ssh_userAuthService);
    FREE_SSH_STRING_BUFFER(ssh_connectService);
    FREE_SSH_STRING_BUFFER(ssh_authMethods);

    FREE_SSH_STRING_BUFFER(ssh_sessionService);
    FREE_SSH_STRING_BUFFER(ssh_forwardService);
    FREE_SSH_STRING_BUFFER(ssh_cancelforwardService);
    FREE_SSH_STRING_BUFFER(ssh_forwardedService);
    FREE_SSH_STRING_BUFFER(ssh_directService);
    FREE_SSH_STRING_BUFFER(ssh_channelUnknown);
    FREE_SSH_STRING_BUFFER(ssh_resourceShort);
    FREE_SSH_STRING_BUFFER(ssh_terminalType);
    FREE_SSH_STRING_BUFFER(ssh_shellType);
    FREE_SSH_STRING_BUFFER(ssh_execRequest);
    FREE_SSH_STRING_BUFFER(ssh_subSystem);
    FREE_SSH_STRING_BUFFER(ssh_windowChange);
    FREE_SSH_STRING_BUFFER(ssh_breakOperation);

#ifdef __ENABLE_DIGICERT_SSH_PING__
    FREE_SSH_STRING_BUFFER(ssh_pingChannel);
#endif

    FREE_SSH_STRING_BUFFER(ssh_scpExec);

    return OK;
}


#endif /* __ENABLE_DIGICERT_SSH_SERVER__ */


