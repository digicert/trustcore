/*
 * sshc_str_house.c
 *
 * SSHC String Storehouse
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

#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/client/sshc_str_house.h"


/*------------------------------------------------------------------*/

/* external prototypes */
extern sbyte *SSHC_TRANS_keyExList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie);
extern sbyte *SSHC_TRANS_hostKeyList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie);
extern sbyte *SSHC_TRANS_cipherList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie);
extern sbyte *SSHC_TRANS_hmacList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie);
extern sbyte *SSHC_AUTH_authList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie);


/*------------------------------------------------------------------*/

/* transport related ssh strings */
sshStringBuffer sshc_disconnectMesg;
sshStringBuffer sshc_languageTag;

/* key exchange related ssh strings */
sshStringBuffer sshc_kexMethods;
sshStringBuffer sshc_hostKeyMethods;
sshStringBuffer sshc_encC2SMethods;
sshStringBuffer sshc_encS2CMethods;
sshStringBuffer sshc_macC2SMethods;
sshStringBuffer sshc_macS2CMethods;
sshStringBuffer sshc_compC2SMethods;
sshStringBuffer sshc_compS2CMethods;
sshStringBuffer sshc_langC2SMethods;
sshStringBuffer sshc_langS2CMethods;

/* authentication related ssh strings */
sshStringBuffer sshc_dss_signature;
sshStringBuffer sshc_rsa_signature;
sshStringBuffer sshc_rsa2048sha256_signature;
sshStringBuffer sshc_rsa2048sha512_signature;
sshStringBuffer sshc_ecdsa_signature;
sshStringBuffer sshc_ecdsa_signature_p192;
sshStringBuffer sshc_ecdsa_signature_p224;
sshStringBuffer sshc_ecdsa_signature_p256;
sshStringBuffer sshc_ecdsa_signature_p384;
sshStringBuffer sshc_ecdsa_signature_p521;
sshStringBuffer sshc_ecdsa_signature_ed25519;
sshStringBuffer sshc_ecdsa_curve_p192;
sshStringBuffer sshc_ecdsa_curve_p224;
sshStringBuffer sshc_ecdsa_curve_p256;
sshStringBuffer sshc_ecdsa_curve_p384;
sshStringBuffer sshc_ecdsa_curve_p521;

#ifdef __ENABLE_DIGICERT_PQC__
sshStringBuffer sshc_mldsa44_signature;
sshStringBuffer sshc_mldsa65_signature;
sshStringBuffer sshc_mldsa87_signature;
#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
sshStringBuffer sshc_cert_mldsa44_signature;
sshStringBuffer sshc_cert_mldsa65_signature;
sshStringBuffer sshc_cert_mldsa87_signature;
#endif
#endif /* __ENABLE_DIGICERT_PQC__ */

#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
sshStringBuffer sshc_mldsa44_p256_signature;
sshStringBuffer sshc_mldsa65_p256_signature;
sshStringBuffer sshc_mldsa87_p384_signature;
sshStringBuffer sshc_mldsa44_ed25519_signature;
sshStringBuffer sshc_mldsa65_ed25519_signature;
sshStringBuffer sshc_mldsa87_ed448_signature;
#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
sshStringBuffer sshc_cert_mldsa44_p256_signature;
sshStringBuffer sshc_cert_mldsa65_p256_signature;
sshStringBuffer sshc_cert_mldsa87_p384_signature;
sshStringBuffer sshc_cert_mldsa44_ed25519_signature;
sshStringBuffer sshc_cert_mldsa65_ed25519_signature;
sshStringBuffer sshc_cert_mldsa87_ed448_signature;
#endif
#endif /* __ENABLE_DIGICERT_PQC_COMPOSITE__ */

sshStringBuffer sshc_cert_sign_signature;
sshStringBuffer sshc_rsa2048_cert_sign_signature;
sshStringBuffer sshc_rsa2048sha256_cert_signature;

sshStringBuffer sshc_ecdsa_cert_signature_p192;
sshStringBuffer sshc_ecdsa_cert_signature_p224;
sshStringBuffer sshc_ecdsa_cert_signature_p256;
sshStringBuffer sshc_ecdsa_cert_signature_p384;
sshStringBuffer sshc_ecdsa_cert_signature_p521;
sshStringBuffer sshc_ecdsasha256_signature;
sshStringBuffer sshc_ecdsasha384_signature;
sshStringBuffer sshc_ecdsasha512_signature;
sshStringBuffer sshc_userAuthService;
sshStringBuffer sshc_connectService;
sshStringBuffer sshc_authMethods;

/* session related ssh strings */
sshStringBuffer sshc_sessionService;
sshStringBuffer sshc_lpfSessionService;
sshStringBuffer sshc_rpfForwardService;
sshStringBuffer sshc_rpfCancelForwardService;
sshStringBuffer sshc_channelUnknown;
sshStringBuffer sshc_resourceShort;
sshStringBuffer sshc_ptyTerminal;
sshStringBuffer sshc_terminalEnv;
sshStringBuffer sshc_shellType;
sshStringBuffer sshc_subSystem;
sshStringBuffer sshc_windowChange;
sshStringBuffer sshc_breakOperation;

/* scp/sftp related strings */
sshStringBuffer sshc_sftpExec;

/* ssh authentication related strings */
sshStringBuffer sshc_authPassword;
sshStringBuffer sshc_authPublicKey;


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_STR_HOUSE_initStringBuffer(sshStringBuffer *p_sshStringBuffer, sbyte *pString)
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
SSHC_STR_HOUSE_createFromList(sshStringBuffer *p_sshStringBuffer, sbyte *(*callbackList)(ubyte4, ubyte4 *, ubyte4), ubyte4 cookie)
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
SSHC_STR_HOUSE_initStringBuffers(void)
{
#define INIT_SSH_STRING_BUFFER(X,Y)    if (OK > (status = SSHC_STR_HOUSE_initStringBuffer(X,Y))) goto exit

    MSTATUS status;

    INIT_SSH_STRING_BUFFER(&sshc_disconnectMesg, (sbyte *)"Logged out.");
    INIT_SSH_STRING_BUFFER(&sshc_languageTag, (sbyte *)"en");

    if (OK > (status = SSHC_STR_HOUSE_createFromList(&sshc_kexMethods, SSHC_TRANS_keyExList, 0))) goto exit;
    if (OK > (status = SSHC_STR_HOUSE_createFromList(&sshc_hostKeyMethods, SSHC_TRANS_hostKeyList, 0))) goto exit;
    if (OK > (status = SSHC_STR_HOUSE_createFromList(&sshc_encC2SMethods, SSHC_TRANS_cipherList, 0))) goto exit;
    if (OK > (status = SSHC_STR_HOUSE_createFromList(&sshc_encS2CMethods, SSHC_TRANS_cipherList, 0))) goto exit;
    if (OK > (status = SSHC_STR_HOUSE_createFromList(&sshc_macC2SMethods, SSHC_TRANS_hmacList, 0))) goto exit;
    if (OK > (status = SSHC_STR_HOUSE_createFromList(&sshc_macS2CMethods, SSHC_TRANS_hmacList, 0))) goto exit;
    INIT_SSH_STRING_BUFFER(&sshc_compC2SMethods, (sbyte *)"none");
    INIT_SSH_STRING_BUFFER(&sshc_compS2CMethods, (sbyte *)"none");
    INIT_SSH_STRING_BUFFER(&sshc_langC2SMethods, (sbyte *)"");
    INIT_SSH_STRING_BUFFER(&sshc_langS2CMethods, (sbyte *)"");

    INIT_SSH_STRING_BUFFER(&sshc_dss_signature, (sbyte *)"ssh-dss");
    INIT_SSH_STRING_BUFFER(&sshc_rsa_signature, (sbyte *)"ssh-rsa");
    INIT_SSH_STRING_BUFFER(&sshc_rsa2048sha256_signature, (sbyte *)"rsa-sha2-256");
    INIT_SSH_STRING_BUFFER(&sshc_rsa2048sha512_signature, (sbyte *)"rsa-sha2-512");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_signature, (sbyte *)"ecdsa-sha2");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_signature_p192, (sbyte *)"ecdsa-sha2-nistp192");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_signature_p224, (sbyte *)"ecdsa-sha2-nistp224");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_signature_p256, (sbyte *)"ecdsa-sha2-nistp256");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_signature_p384, (sbyte *)"ecdsa-sha2-nistp384");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_signature_p521, (sbyte *)"ecdsa-sha2-nistp521");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_signature_ed25519, (sbyte *)"ssh-ed25519");

    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_curve_p192, (sbyte *)"nistp192");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_curve_p224, (sbyte *)"nistp224");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_curve_p256, (sbyte *)"nistp256");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_curve_p384, (sbyte *)"nistp384");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_curve_p521, (sbyte *)"nistp521");

#ifdef __ENABLE_DIGICERT_PQC__
    INIT_SSH_STRING_BUFFER(&sshc_mldsa44_signature, (sbyte *)"ssh-mldsa44");
    INIT_SSH_STRING_BUFFER(&sshc_mldsa65_signature, (sbyte *)"ssh-mldsa65");
    INIT_SSH_STRING_BUFFER(&sshc_mldsa87_signature, (sbyte *)"ssh-mldsa87");
#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
    INIT_SSH_STRING_BUFFER(&sshc_cert_mldsa44_signature, (sbyte *)"x509v3-mldsa44");
    INIT_SSH_STRING_BUFFER(&sshc_cert_mldsa65_signature, (sbyte *)"x509v3-mldsa65");
    INIT_SSH_STRING_BUFFER(&sshc_cert_mldsa87_signature, (sbyte *)"x509v3-mldsa87");
#endif
#endif /* __ENABLE_DIGICERT_PQC__ */

#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
    INIT_SSH_STRING_BUFFER(&sshc_mldsa44_p256_signature, (sbyte *)"ssh-mldsa44-es256");
    INIT_SSH_STRING_BUFFER(&sshc_mldsa65_p256_signature, (sbyte *)"ssh-mldsa65-es256");
    INIT_SSH_STRING_BUFFER(&sshc_mldsa87_p384_signature, (sbyte *)"ssh-mldsa87-es384");
    INIT_SSH_STRING_BUFFER(&sshc_mldsa44_ed25519_signature, (sbyte *)"ssh-mldsa44-ed25519");
    INIT_SSH_STRING_BUFFER(&sshc_mldsa65_ed25519_signature, (sbyte *)"ssh-mldsa65-ed25519");
    INIT_SSH_STRING_BUFFER(&sshc_mldsa87_ed448_signature, (sbyte *)"ssh-mldsa87-ed448");
#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
    INIT_SSH_STRING_BUFFER(&sshc_cert_mldsa44_p256_signature, (sbyte *)"x509v3-mldsa44-es256");
    INIT_SSH_STRING_BUFFER(&sshc_cert_mldsa65_p256_signature, (sbyte *)"x509v3-mldsa65-es256");
    INIT_SSH_STRING_BUFFER(&sshc_cert_mldsa87_p384_signature, (sbyte *)"x509v3-mldsa87-es384");
    INIT_SSH_STRING_BUFFER(&sshc_cert_mldsa44_ed25519_signature, (sbyte *)"x509v3-mldsa44-ed25519");
    INIT_SSH_STRING_BUFFER(&sshc_cert_mldsa65_ed25519_signature, (sbyte *)"x509v3-mldsa65-ed25519");
    INIT_SSH_STRING_BUFFER(&sshc_cert_mldsa87_ed448_signature, (sbyte *)"x509v3-mldsa87-ed448");
#endif
#endif /* __ENABLE_DIGICERT_PQC_COMPOSITE__ */

#ifdef __ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__
    INIT_SSH_STRING_BUFFER(&sshc_cert_sign_signature, (sbyte *)"x509v3-ssh-rsa");
    INIT_SSH_STRING_BUFFER(&sshc_rsa2048_cert_sign_signature, (sbyte *)"x509v3-rsa2048-sha256");
    INIT_SSH_STRING_BUFFER(&sshc_rsa2048sha256_cert_signature, (sbyte *)"rsa2048-sha256");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_cert_signature_p192, (sbyte *)"x509v3-ecdsa-sha2-nistp192");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_cert_signature_p224, (sbyte *)"x509v3-ecdsa-sha2-nistp224");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_cert_signature_p256, (sbyte *)"x509v3-ecdsa-sha2-nistp256");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_cert_signature_p384, (sbyte *)"x509v3-ecdsa-sha2-nistp384");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsa_cert_signature_p521, (sbyte *)"x509v3-ecdsa-sha2-nistp521");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsasha256_signature, (sbyte *)"ecdsa-sha256");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsasha384_signature, (sbyte *)"ecdsa-sha384");
    INIT_SSH_STRING_BUFFER(&sshc_ecdsasha512_signature, (sbyte *)"ecdsa-sha512");
#else
    INIT_SSH_STRING_BUFFER(&sshc_cert_sign_signature, (sbyte *)"x509v3-sign-rsa-sha1");
#endif
    INIT_SSH_STRING_BUFFER(&sshc_userAuthService, (sbyte *)"ssh-userauth");
    INIT_SSH_STRING_BUFFER(&sshc_connectService, (sbyte *)"ssh-connection");
    if (OK > (status = SSHC_STR_HOUSE_createFromList(&sshc_authMethods, SSHC_AUTH_authList, 0xffffffff))) goto exit;

    INIT_SSH_STRING_BUFFER(&sshc_sessionService, (sbyte *)"session");
    INIT_SSH_STRING_BUFFER(&sshc_lpfSessionService, (sbyte *)"direct-tcpip");
    INIT_SSH_STRING_BUFFER(&sshc_rpfForwardService, (sbyte *)"tcpip-forward");
    INIT_SSH_STRING_BUFFER(&sshc_rpfCancelForwardService, (sbyte *)"cancel-tcpip-forward");
    INIT_SSH_STRING_BUFFER(&sshc_channelUnknown, (sbyte *)"Unknown channel type");
    INIT_SSH_STRING_BUFFER(&sshc_resourceShort, (sbyte *)"Server supports one session per SSH client");
    INIT_SSH_STRING_BUFFER(&sshc_ptyTerminal, (sbyte *)"pty-req");
    INIT_SSH_STRING_BUFFER(&sshc_terminalEnv, (sbyte *)"xterm");
    INIT_SSH_STRING_BUFFER(&sshc_shellType, (sbyte *)"shell");
    INIT_SSH_STRING_BUFFER(&sshc_subSystem, (sbyte *)"subsystem");
    INIT_SSH_STRING_BUFFER(&sshc_windowChange, (sbyte *)"window-change");
    INIT_SSH_STRING_BUFFER(&sshc_breakOperation, (sbyte *)"break");

    INIT_SSH_STRING_BUFFER(&sshc_sftpExec, (sbyte *)"sftp");

    INIT_SSH_STRING_BUFFER(&sshc_authPassword, (sbyte *)"password");
    INIT_SSH_STRING_BUFFER(&sshc_authPublicKey, (sbyte *)"publickey");

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSHC_STR_HOUSE_freeStringBuffers(void)
{
#define FREE_SSH_STRING_BUFFER(X)    if (NULL != X.pString) { FREE(X.pString); X.pString = NULL; }

    FREE_SSH_STRING_BUFFER(sshc_disconnectMesg);
    FREE_SSH_STRING_BUFFER(sshc_languageTag);

    FREE_SSH_STRING_BUFFER(sshc_kexMethods);
    FREE_SSH_STRING_BUFFER(sshc_hostKeyMethods);
    FREE_SSH_STRING_BUFFER(sshc_encC2SMethods);
    FREE_SSH_STRING_BUFFER(sshc_encS2CMethods);
    FREE_SSH_STRING_BUFFER(sshc_macC2SMethods);
    FREE_SSH_STRING_BUFFER(sshc_macS2CMethods);
    FREE_SSH_STRING_BUFFER(sshc_compC2SMethods);
    FREE_SSH_STRING_BUFFER(sshc_compS2CMethods);
    FREE_SSH_STRING_BUFFER(sshc_langC2SMethods);
    FREE_SSH_STRING_BUFFER(sshc_langS2CMethods);

    FREE_SSH_STRING_BUFFER(sshc_dss_signature);
    FREE_SSH_STRING_BUFFER(sshc_rsa_signature);
    FREE_SSH_STRING_BUFFER(sshc_rsa2048sha256_signature);
    FREE_SSH_STRING_BUFFER(sshc_rsa2048sha512_signature);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_signature);
    FREE_SSH_STRING_BUFFER(sshc_cert_sign_signature);
    FREE_SSH_STRING_BUFFER(sshc_rsa2048_cert_sign_signature);
    FREE_SSH_STRING_BUFFER(sshc_rsa2048sha256_cert_signature);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_cert_signature_p192);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_cert_signature_p224);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_cert_signature_p256);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_cert_signature_p384);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_cert_signature_p521);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_signature_p192);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_signature_p224);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_signature_p256);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_signature_p384);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_signature_p521);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_signature_ed25519);

    FREE_SSH_STRING_BUFFER(sshc_ecdsa_curve_p192);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_curve_p224);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_curve_p256);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_curve_p384);
    FREE_SSH_STRING_BUFFER(sshc_ecdsa_curve_p521);

#ifdef __ENABLE_DIGICERT_PQC__
    FREE_SSH_STRING_BUFFER(sshc_mldsa44_signature);
    FREE_SSH_STRING_BUFFER(sshc_mldsa65_signature);
    FREE_SSH_STRING_BUFFER(sshc_mldsa87_signature);
#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
    FREE_SSH_STRING_BUFFER(sshc_cert_mldsa44_signature);
    FREE_SSH_STRING_BUFFER(sshc_cert_mldsa65_signature);
    FREE_SSH_STRING_BUFFER(sshc_cert_mldsa87_signature);
#endif
#endif /* __ENABLE_DIGICERT_PQC__ */

#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
    FREE_SSH_STRING_BUFFER(sshc_mldsa44_p256_signature);
    FREE_SSH_STRING_BUFFER(sshc_mldsa65_p256_signature);
    FREE_SSH_STRING_BUFFER(sshc_mldsa87_p384_signature);
    FREE_SSH_STRING_BUFFER(sshc_mldsa44_ed25519_signature);
    FREE_SSH_STRING_BUFFER(sshc_mldsa65_ed25519_signature);
    FREE_SSH_STRING_BUFFER(sshc_mldsa87_ed448_signature);
#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
    FREE_SSH_STRING_BUFFER(sshc_cert_mldsa44_p256_signature);
    FREE_SSH_STRING_BUFFER(sshc_cert_mldsa65_p256_signature);
    FREE_SSH_STRING_BUFFER(sshc_cert_mldsa87_p384_signature);
    FREE_SSH_STRING_BUFFER(sshc_cert_mldsa44_ed25519_signature);
    FREE_SSH_STRING_BUFFER(sshc_cert_mldsa65_ed25519_signature);
    FREE_SSH_STRING_BUFFER(sshc_cert_mldsa87_ed448_signature);
#endif
#endif /* __ENABLE_DIGICERT_PQC_COMPOSITE__ */

    FREE_SSH_STRING_BUFFER(sshc_ecdsasha256_signature);
    FREE_SSH_STRING_BUFFER(sshc_ecdsasha384_signature);
    FREE_SSH_STRING_BUFFER(sshc_ecdsasha512_signature);
    FREE_SSH_STRING_BUFFER(sshc_userAuthService);
    FREE_SSH_STRING_BUFFER(sshc_connectService);
    FREE_SSH_STRING_BUFFER(sshc_authMethods);

    FREE_SSH_STRING_BUFFER(sshc_sessionService);
    FREE_SSH_STRING_BUFFER(sshc_lpfSessionService);
    FREE_SSH_STRING_BUFFER(sshc_rpfForwardService);
    FREE_SSH_STRING_BUFFER(sshc_rpfCancelForwardService);
    FREE_SSH_STRING_BUFFER(sshc_channelUnknown);
    FREE_SSH_STRING_BUFFER(sshc_resourceShort);
    FREE_SSH_STRING_BUFFER(sshc_ptyTerminal);
    FREE_SSH_STRING_BUFFER(sshc_terminalEnv);
    FREE_SSH_STRING_BUFFER(sshc_shellType);
    FREE_SSH_STRING_BUFFER(sshc_subSystem);
    FREE_SSH_STRING_BUFFER(sshc_windowChange);
    FREE_SSH_STRING_BUFFER(sshc_breakOperation);

    FREE_SSH_STRING_BUFFER(sshc_sftpExec);

    FREE_SSH_STRING_BUFFER(sshc_authPassword);
    FREE_SSH_STRING_BUFFER(sshc_authPublicKey);

    return OK;
}


#endif /* __ENABLE_DIGICERT_SSH_CLIENT__ */


