/*
 * ssh_auth.c
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
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

/* Doc Note: This file's functions are for DigiCert internal code use only, and should not
be included in the API documentation.
*/

#include "../common/moptions.h"

#ifdef __ENABLE_MOCANA_SSH_SERVER__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/mocana.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/mem_pool.h"
#include "../common/moc_stream.h"
#include "../common/sizedbuffer.h"
#include "../common/debug_console.h"
#include "../common/memory_debug.h"
#include "../crypto/crypto.h"
#include "../crypto/dsa.h"
#include "../crypto/rsa.h"
#include "../crypto/sha1.h"

#ifndef __DISABLE_MOCANA_SHA256__
#include "../crypto/sha256.h"
#endif

#if ((!defined(__DISABLE_MOCANA_SHA384__)) || (!defined(__DISABLE_MOCANA_SHA512__)))
#include "../crypto/sha512.h"
#endif

#include "../crypto/dh.h"
#ifdef __ENABLE_MOCANA_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/cert_store.h"
#include "../crypto/ca_mgmt.h"
#include "../ssh/ssh_defs.h"
#include "../ssh/ssh_str.h"
#include "../ssh/ssh_context.h"
#include "../ssh/ssh_auth.h"
#include "../ssh/ssh_out_mesg.h"
#include "../ssh/ssh_trans.h"
#include "../ssh/ssh_utils.h"
#include "../ssh/ssh_str_house.h"
#include "../ssh/ssh_dss.h"
#include "../ssh/ssh_rsa.h"
#ifdef __ENABLE_MOCANA_ECC__
#include "../ssh/ssh_ecdsa.h"
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_ecc.h"
#endif
#endif
#include "../ssh/ssh_cert.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../crypto/cert_chain.h"
#include "../ssh/ssh.h"
#include "../common/tree.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"

#ifdef __ENABLE_MOCANA_PQC__
#include "../ssh/ssh_hybrid.h"
#include "../ssh/ssh_qs.h"
#endif

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_dsa.h"
#endif

#ifdef __ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__
#define MAX_SSH_STRING_SIZE     8192
#else
#define MAX_SSH_STRING_SIZE     2048
#endif

/*------------------------------------------------------------------*/

/* prototypes */
extern sbyte *SSH_AUTH_authList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie);


/*------------------------------------------------------------------*/

#if 0
#define __DEBUG_SSH_AUTH__
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
    { (sbyte *)"publickey",             9, MOCANA_SSH_AUTH_PUBLIC_KEY           },
    { (sbyte *)"password",              8, MOCANA_SSH_AUTH_PASSWORD             },
    { (sbyte *)"none",                  4, MOCANA_SSH_AUTH_NONE                 },
    { (sbyte *)"keyboard-interactive", 20, MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE }
};

#define NUM_AUTH_OPTIONS (sizeof(mAuthMethods)/sizeof(authMethodDescr))
/*------------------------------------------------------------------*/
#define SSH_USERAUTH_BANNER_STRING "\n " \
"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! " \
"This is Mocana NanoSSH server!! " \
"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" \
"\n\n"
/*------------------------------------------------------------------*/

typedef struct
{
    ubyte*              pNewMesg;
    ubyte4              newMesgLen;
    ubyte4              index;
    sshStringBuffer*    pUser;

} sshAuthCommonArgs;

typedef struct
{
    sbyte* pDebugName;
    sshStringBuffer* pName;
    sshStringBuffer* pSignature;
    ubyte4           authType;
    ubyte4           hashLen;
    ubyte4           minAlgoDetail;
    ubyte4           maxAlgoDetail;
    ubyte4           identityType;
} authPubKeyDescr;


/*
 *  ------------------------------------------------------------------------------------------------
 *  | ALGORITHM NAME                | PUBLIC KEY FORMAT             | SIGNATURE FORMAT      | RFC  |
 *  ------------------------------------------------------------------------------------------------
 *  | x509v3-ssh-rsa                | x509v3-ssh-rsa                | ssh-rsa               | 6187 |
 *  | x509v3-rsa2048-sha256         | x509v3-rsa2048-sha256         | rsa2048-sha256        | 6187 |
 *  | x509v3-ecdsa-sha2-nistp256    | x509v3-ecdsa-sha2-nistp256    | ecdsa-sha2-nistp256   | 6187 |
 *  | x509v3-ecdsa-sha2-nistp384    | x509v3-ecdsa-sha2-nistp384    | ecdsa-sha2-nistp384   | 6187 |
 *  | x509v3-ecdsa-sha2-nistp521    | x509v3-ecdsa-sha2-nistp521    | ecdsa-sha2-nistp521   | 6187 |
 *  | ssh-dss                       | ssh-dss                       | ssh-dss               | 4253 |
 *  | ssh-rsa                       | ssh-rsa                       | ssh-rsa               | 4253 |
 *  | rsa-sha2-256                  | ssh-rsa                       | rsa-sha2-256          | 8332 |
 *  | rsa-sha2-512                  | ssh-rsa                       | rsa-sha2-512          | 8332 |
 *  | ecdsa-sha2-nistp256           | ecdsa-sha2-nistp256           | ecdsa-sha2-nistp256   | 5656 |
 *  | ecdsa-sha2-nistp384           | ecdsa-sha2-nistp384           | ecdsa-sha2-nistp384   | 5656 |
 *  | ecdsa-sha2-nistp521           | ecdsa-sha2-nistp521           | ecdsa-sha2-nistp521   | 5656 |
 *  | ssh-ed25519                   | ssh-ed25519                   | ssh-ed25519           | 8709 |
 *  ------------------------------------------------------------------------------------------------
 *  */
static authPubKeyDescr mAuthPubKeyMethods[] =
{
#ifdef __ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__
    /*RSA */
    { (sbyte *)"x509v3-ssh-rsa",               &ssh_rsa_cert_sign_signature,     &ssh_rsa_signature,            CERT_STORE_AUTH_TYPE_RSA,   SHA_HASH_RESULT_SIZE,   SSH_RSA_MIN_SIZE,    SSH_RSA_MAX_SIZE,    CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 },
#if (!defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"x509v3-rsa2048-sha256",        &ssh_rsa2048_cert_sign_signature, &ssh_rsasha256_cert_signature, CERT_STORE_AUTH_TYPE_RSA,   SHA256_RESULT_SIZE,     SSH_RSA_2048_SIZE,   SSH_RSA_2048_SIZE,   CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 },
#endif
    
    /* PQC */
#ifdef __ENABLE_MOCANA_PRE_DRAFT_PQC__
#if (defined(__ENABLE_MOCANA_PQC__))
    { (sbyte *)"x509v3-mldsa44",               &ssh_cert_mldsa44_signature, &ssh_cert_mldsa44_signature, CERT_STORE_AUTH_TYPE_QS, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 },
    { (sbyte *)"x509v3-mldsa65",               &ssh_cert_mldsa65_signature, &ssh_cert_mldsa65_signature, CERT_STORE_AUTH_TYPE_QS, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 },
    { (sbyte *)"x509v3-mldsa87",               &ssh_cert_mldsa87_signature, &ssh_cert_mldsa87_signature, CERT_STORE_AUTH_TYPE_QS, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 },
    
    /* COMPOSITE */
#if (defined(__ENABLE_MOCANA_ECC__))
#if (!defined(__DISABLE_MOCANA_ECC_P256__) && !defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"x509v3-mldsa44-es256",         &ssh_cert_mldsa44_p256_signature, &ssh_cert_mldsa44_p256_signature, CERT_STORE_AUTH_TYPE_HYBRID, SHA256_RESULT_SIZE, SSH_ECDSA_P256_SIZE, SSH_ECDSA_P256_SIZE, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 },
    { (sbyte *)"x509v3-mldsa65-es256",         &ssh_cert_mldsa65_p256_signature, &ssh_cert_mldsa65_p256_signature, CERT_STORE_AUTH_TYPE_HYBRID, SHA256_RESULT_SIZE, SSH_ECDSA_P256_SIZE, SSH_ECDSA_P256_SIZE, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 },      
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P384__) && !defined(__DISABLE_MOCANA_SHA384__))
    { (sbyte *)"x509v3-mldsa87-es384",         &ssh_cert_mldsa87_p384_signature, &ssh_cert_mldsa87_p384_signature, CERT_STORE_AUTH_TYPE_HYBRID, SHA384_RESULT_SIZE, SSH_ECDSA_P384_SIZE, SSH_ECDSA_P384_SIZE, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 },
#endif
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_25519__))
    { (sbyte *)"x509v3-mldsa44-ed25519",       &ssh_cert_mldsa44_ed25519_signature, &ssh_cert_mldsa44_ed25519_signature, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 },
    { (sbyte *)"x509v3-mldsa65-ed25519",       &ssh_cert_mldsa65_ed25519_signature, &ssh_cert_mldsa65_ed25519_signature, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 },
#endif
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_448__))
    { (sbyte *)"x509v3-mldsa87-ed448",         &ssh_cert_mldsa87_ed448_signature, &ssh_cert_mldsa87_ed448_signature, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 },
#endif
#endif /* __ENABLE_MOCANA_ECC__ */
#endif /* __ENABLE_MOCANA_PQC__ */
#endif /* __ENABLE_MOCANA_PRE_DRAFT_PQC__ */

    /* ECC */
#if (defined(__ENABLE_MOCANA_ECC__))
#if (!defined(__DISABLE_MOCANA_ECC_P256__) && !defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"x509v3-ecdsa-sha2-nistp256", &ssh_ecdsa_cert_signature_p256,   &ssh_ecdsa_signature_p256,   CERT_STORE_AUTH_TYPE_ECDSA, SHA256_RESULT_SIZE,     SSH_ECDSA_P256_SIZE, SSH_ECDSA_P256_SIZE, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P384__) && !defined(__DISABLE_MOCANA_SHA384__))
    { (sbyte *)"x509v3-ecdsa-sha2-nistp384", &ssh_ecdsa_cert_signature_p384,   &ssh_ecdsa_signature_p384,   CERT_STORE_AUTH_TYPE_ECDSA, SHA384_RESULT_SIZE,     SSH_ECDSA_P384_SIZE, SSH_ECDSA_P384_SIZE, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P521__) && !defined(__DISABLE_MOCANA_SHA512__))
    { (sbyte *)"x509v3-ecdsa-sha2-nistp521", &ssh_ecdsa_cert_signature_p521,   &ssh_ecdsa_signature_p521,   CERT_STORE_AUTH_TYPE_ECDSA, SHA512_RESULT_SIZE,     SSH_ECDSA_P521_SIZE, SSH_ECDSA_P521_SIZE, CERT_STORE_IDENTITY_TYPE_CERT_X509_V3 },
#endif
#endif /* __ENABLE_MOCANA_ECC__ */
#endif /*__ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__*/

    /* DSA */
#if (defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__))
    { (sbyte *)"ssh-dss",                      &ssh_dss_signature,              &ssh_dss_signature,           CERT_STORE_AUTH_TYPE_DSA,   SHA_HASH_RESULT_SIZE,   SSH_RFC_DSA_SIZE,    SSH_RFC_DSA_SIZE,    CERT_STORE_IDENTITY_TYPE_NAKED },
#endif
    
    /* RSA */
#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__))
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    { (sbyte *)"ssh-rsa",                      &ssh_rsa_signature,              &ssh_rsa_signature,           CERT_STORE_AUTH_TYPE_RSA,   SHA_HASH_RESULT_SIZE,   SSH_RSA_MIN_SIZE,    SSH_RSA_MAX_SIZE,    CERT_STORE_IDENTITY_TYPE_NAKED },
#endif /* __ENABLE_MOCANA_SSH_WEAK_CIPHERS__ */
#ifndef __DISABLE_MOCANA_SHA256__
    { (sbyte *)"rsa-sha2-256",                 &ssh_rsasha256_signature,        &ssh_rsasha256_signature,     CERT_STORE_AUTH_TYPE_RSA,   SHA256_RESULT_SIZE,     SSH_RSA_2048_SIZE,   SSH_RSA_2048_SIZE,   CERT_STORE_IDENTITY_TYPE_NAKED },
#endif
#ifndef __DISABLE_MOCANA_SHA512__
    { (sbyte *)"rsa-sha2-512",                 &ssh_rsasha512_signature,        &ssh_rsasha512_signature,     CERT_STORE_AUTH_TYPE_RSA,   SHA512_RESULT_SIZE,     SSH_RSA_2048_SIZE,   SSH_RSA_2048_SIZE,   CERT_STORE_IDENTITY_TYPE_NAKED },
#endif
#endif /* __ENABLE_MOCANA_SSH_RSA_SUPPORT__ */

    /* PQC */
#if (defined(__ENABLE_MOCANA_PQC__))
    { (sbyte *)"ssh-mldsa44",               &ssh_mldsa44_signature, &ssh_mldsa44_signature, CERT_STORE_AUTH_TYPE_QS, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED },
    { (sbyte *)"ssh-mldsa65",               &ssh_mldsa65_signature, &ssh_mldsa65_signature, CERT_STORE_AUTH_TYPE_QS, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED },
    { (sbyte *)"ssh-mldsa87",               &ssh_mldsa87_signature, &ssh_mldsa87_signature, CERT_STORE_AUTH_TYPE_QS, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED },
     
    /* COMPOSITE */
#if (defined(__ENABLE_MOCANA_ECC__))
#if (!defined(__DISABLE_MOCANA_ECC_P256__) && !defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"ssh-mldsa44-es256",         &ssh_mldsa44_p256_signature, &ssh_mldsa44_p256_signature, CERT_STORE_AUTH_TYPE_HYBRID, SHA256_RESULT_SIZE, SSH_ECDSA_P256_SIZE, SSH_ECDSA_P256_SIZE, CERT_STORE_IDENTITY_TYPE_NAKED },
    { (sbyte *)"ssh-mldsa65-es256",         &ssh_mldsa65_p256_signature, &ssh_mldsa65_p256_signature, CERT_STORE_AUTH_TYPE_HYBRID, SHA256_RESULT_SIZE, SSH_ECDSA_P256_SIZE, SSH_ECDSA_P256_SIZE, CERT_STORE_IDENTITY_TYPE_NAKED },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P384__) && !defined(__DISABLE_MOCANA_SHA384__))
    { (sbyte *)"ssh-mldsa87-es384",         &ssh_mldsa87_p384_signature, &ssh_mldsa87_p384_signature, CERT_STORE_AUTH_TYPE_HYBRID, SHA384_RESULT_SIZE, SSH_ECDSA_P384_SIZE, SSH_ECDSA_P384_SIZE, CERT_STORE_IDENTITY_TYPE_NAKED },
#endif
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_25519__))
    { (sbyte *)"ssh-mldsa44-ed25519",       &ssh_mldsa44_ed25519_signature, &ssh_mldsa44_ed25519_signature, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED },
    { (sbyte *)"ssh-mldsa65-ed25519",       &ssh_mldsa65_ed25519_signature, &ssh_mldsa65_ed25519_signature, CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED },
#endif
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_448__))
    { (sbyte *)"ssh-mldsa87-ed448",         &ssh_mldsa87_ed448_signature,   &ssh_mldsa87_ed448_signature,   CERT_STORE_AUTH_TYPE_HYBRID, 0, 0, 0, CERT_STORE_IDENTITY_TYPE_NAKED },
#endif
#endif /* __ENABLE_MOCANA_ECC__ */
#endif /* __ENABLE_MOCANA_PQC__ */

    /* ECC */
#if (defined(__ENABLE_MOCANA_ECC__))
#if (defined(__ENABLE_MOCANA_ECC_EDDSA_25519__) && !defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"ssh-ed25519",          &ssh_ecdsa_signature_ed25519,      &ssh_ecdsa_signature_ed25519,   CERT_STORE_AUTH_TYPE_EDDSA, SHA256_RESULT_SIZE,     SSH_ECDSA_P256_SIZE, SSH_ECDSA_P256_SIZE, CERT_STORE_IDENTITY_TYPE_NAKED },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P256__) && !defined(__DISABLE_MOCANA_SHA256__))
    { (sbyte *)"ecdsa-sha2-nistp256",          &ssh_ecdsa_signature_p256,      &ssh_ecdsa_signature_p256,   CERT_STORE_AUTH_TYPE_ECDSA, SHA256_RESULT_SIZE,     SSH_ECDSA_P256_SIZE, SSH_ECDSA_P256_SIZE, CERT_STORE_IDENTITY_TYPE_NAKED },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P384__) && !defined(__DISABLE_MOCANA_SHA384__))
    { (sbyte *)"ecdsa-sha2-nistp384",          &ssh_ecdsa_signature_p384,      &ssh_ecdsa_signature_p384,   CERT_STORE_AUTH_TYPE_ECDSA, SHA384_RESULT_SIZE,     SSH_ECDSA_P384_SIZE, SSH_ECDSA_P384_SIZE, CERT_STORE_IDENTITY_TYPE_NAKED },
#endif
#if (!defined(__DISABLE_MOCANA_ECC_P521__) && !defined(__DISABLE_MOCANA_SHA512__))
    { (sbyte *)"ecdsa-sha2-nistp521",          &ssh_ecdsa_signature_p521,      &ssh_ecdsa_signature_p521,   CERT_STORE_AUTH_TYPE_ECDSA, SHA512_RESULT_SIZE,     SSH_ECDSA_P521_SIZE, SSH_ECDSA_P521_SIZE, CERT_STORE_IDENTITY_TYPE_NAKED },
#endif
#endif /* __ENABLE_MOCANA_ECC__ */
    /*{ (sbyte *)"placeholder",           NULL,                              NULL,                         0,                        0,                           0,                 0,                 0,                                     }*/
};

#define NUM_AUTH_PUBKEY_OPTIONS ((sizeof(mAuthPubKeyMethods)/sizeof(authPubKeyDescr)) - 1)

static const BulkHashAlgo SHA1Suite =
    { SHA1_RESULT_SIZE, SHA1_BLOCK_SIZE, SHA1_allocDigest, SHA1_freeDigest,
        (BulkCtxInitFunc)SHA1_initDigest, (BulkCtxUpdateFunc)SHA1_updateDigest, (BulkCtxFinalFunc)SHA1_finalDigest, NULL, NULL, NULL, ht_sha1 };

#ifndef __DISABLE_MOCANA_SHA256__
static const BulkHashAlgo SHA256Suite =
    { SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest,
        (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, (BulkCtxFinalFunc)SHA256_finalDigest, NULL, NULL, NULL, ht_sha256 };
#endif

#ifndef __DISABLE_MOCANA_SHA384__
static const BulkHashAlgo SHA384Suite =
    { SHA384_RESULT_SIZE, SHA384_BLOCK_SIZE, SHA384_allocDigest, SHA384_freeDigest,
        (BulkCtxInitFunc)SHA384_initDigest, (BulkCtxUpdateFunc)SHA384_updateDigest, (BulkCtxFinalFunc)SHA384_finalDigest, NULL, NULL, NULL, ht_sha384 };
#endif

#ifndef __DISABLE_MOCANA_SHA512__
static const BulkHashAlgo SHA512Suite =
    { SHA512_RESULT_SIZE, SHA512_BLOCK_SIZE, SHA512_allocDigest, SHA512_freeDigest,
        (BulkCtxInitFunc)SHA512_initDigest, (BulkCtxUpdateFunc)SHA512_updateDigest, (BulkCtxFinalFunc)SHA512_finalDigest, NULL, NULL, NULL, ht_sha512 };
#endif

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RFC_8308__
/* 
 returns a a name-list structure containing all algorithms
 server accepts for client authentication
*/
extern sshStringBuffer* getPubKeyAuthAlgorithms()
{
    MSTATUS status;
    sbyte *pS = NULL;
    sbyte4 i;
    sbyte4 j;
    sbyte4 strLen;
    sshStringBuffer* pAlgorithms = NULL;

    strLen = 4; /* prefixed size */
    for(i = 0; i <= NUM_AUTH_PUBKEY_OPTIONS; i++)
    {
        /* algorithm name (without prefixed size) + comma */
        strLen += mAuthPubKeyMethods[i].pName->stringLen - 4 + 1;
    }

    strLen--; /* first element has no comma prefix */

    status = SSH_STR_makeStringBuffer(&pAlgorithms, strLen);
    if (OK != status)
        goto exit;

    pS = pAlgorithms->pString;

    pS[0] = ((strLen - 4) >> 24) & 0xff;
    pS[1] = ((strLen - 4) >> 16) & 0xff;
    pS[2] = ((strLen - 4) >>  8) & 0xff;
    pS[3] =  (strLen - 4) & 0xff;

    j = 4; /* index of pS to write next algorithm name */
    for(i = 0; i <= NUM_AUTH_PUBKEY_OPTIONS; i++)
    {
        /* algorithm name + comma, skip prefix size bytes */
        if (j > 4)
        {
            pS[j] = ',';
            j++;
        }

        status = MOC_MEMCPY((pS + j), mAuthPubKeyMethods[i].pName->pString + 4, 
                    mAuthPubKeyMethods[i].pName->stringLen - 4);
        if (OK != status)
            goto exit;

        j += (mAuthPubKeyMethods[i].pName->stringLen - 4);
    }

    pS[j] = '\0';

exit:

    if (OK != status)
    {
        MOC_FREE((void **) &pS);
        MOC_FREE((void **) &pAlgorithms);
    }

    return pAlgorithms;
}
#endif /* __DISABLE_DIGICERT_RFC_8308__ */

/*------------------------------------------------------------------*/

static MSTATUS
sendAuthFailure(sshContext *pContextSSH, byteBoolean partialAuth, sshStringBuffer* pAuthAdvertised)
{
    ubyte4  numBytesToWrite = 1 + pAuthAdvertised->stringLen + 1;
    ubyte4  numBytesWritten = 0;
    MSTATUS status;

    if (NULL == pContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((SSH_sshSettings()->sshMaxAuthAttempts) <= AUTH_FAILURE_ATTEMPTS(pContextSSH))
    {
        status = ERR_AUTH_FAILED;
        goto exit;
    }

    MOC_MEMCPY(1 + (AUTH_FAILURE_BUFFER(pContextSSH)), pAuthAdvertised->pString, pAuthAdvertised->stringLen);

    (AUTH_FAILURE_BUFFER(pContextSSH))[1 + pAuthAdvertised->stringLen] = partialAuth;

    status = SSH_OUT_MESG_sendMessage(pContextSSH,
                                      AUTH_FAILURE_BUFFER(pContextSSH), numBytesToWrite,
                                      &numBytesWritten);

    /* verify write completed */
    if ((OK <= status) && (numBytesToWrite != numBytesWritten))
        status = ERR_AUTH_MESG_FRAGMENTED;

exit:
    return status;

} /* sendAuthFailure */


/*------------------------------------------------------------------*/

static MSTATUS
sendAuthInfoRequest(sshContext *pContextSSH, keyIntInfoReq* pRequest)
{
    ubyte4              numBytesToWrite = 0;
    ubyte4              numBytesWritten = 0;
    sshStringBuffer     name;
    sshStringBuffer     instruction;
    sshStringBuffer     prompt;
    ubyte4              i;
    ubyte4              n;
    ubyte*              pPayload = NULL;
    MSTATUS             status;

    if (NULL == pContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    numBytesToWrite = 1 + 4 + pRequest->nameLen + 4 + pRequest->instructionLen + 4 + 4;

    for (n = 0; n < pRequest->numPrompts; n++)
        numBytesToWrite += 4 + pRequest->prompts[n]->promptLen + 1;

    if (NULL == (pPayload = MALLOC(numBytesToWrite)))
    {
        status = ERR_MEM_ALLOC_FAIL;
    }
    else
    {
        i = 0;

        pPayload[i] = SSH_MSG_USERAUTH_INFO_REQUEST;
        i += 1;

        name.stringLen= pRequest->nameLen;
        name.pString = (ubyte *)pRequest->pName;

        if (OK > (status = SSH_STR_copyStringToPayload(pPayload, numBytesToWrite, &i, &name)))
            goto exit;

        if (NULL == pRequest->pInstruction)
            instruction.stringLen = 0;

        instruction.stringLen = pRequest->instructionLen;
        instruction.pString = (ubyte *)pRequest->pInstruction;

        if (OK > (status = SSH_STR_copyStringToPayload(pPayload, numBytesToWrite, &i, &instruction)))
            goto exit;

        /* language tag has been deprecated */
        pPayload[i] = 0;    i++;
        pPayload[i] = 0;    i++;
        pPayload[i] = 0;    i++;
        pPayload[i] = 0;    i++;

        /* num prompts */
        pPayload[i] = (ubyte)(pRequest->numPrompts >> 24);  i++;
        pPayload[i] = (ubyte)(pRequest->numPrompts >> 16);  i++;
        pPayload[i] = (ubyte)(pRequest->numPrompts >> 8);   i++;
        pPayload[i] = (ubyte)(pRequest->numPrompts);        i++;

        for (n = 0; n < pRequest->numPrompts; n++)
        {
            prompt.stringLen = pRequest->prompts[n]->promptLen;
            prompt.pString = (ubyte *)pRequest->prompts[n]->pPrompt;

            if (OK > (status = SSH_STR_copyStringToPayload(pPayload, numBytesToWrite, &i, &prompt)))
            {
                goto exit;
            }

            pPayload[i] = (ubyte) pRequest->prompts[n]->echo;
            i += 1;
        }

        pContextSSH->authContext.authMethod = MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE;

        status = SSH_OUT_MESG_sendMessage(pContextSSH,
                                          pPayload, numBytesToWrite,
                                          &numBytesWritten);

        /* verify write completed */
        if ((OK <= status) && (numBytesToWrite != numBytesWritten))
            status = ERR_AUTH_MESG_FRAGMENTED;
    }

exit:
    if (NULL != pPayload)
        FREE(pPayload);

    return status;

} /* sendAuthInfoRequest */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_AUTH_allocStructures(sshContext *pContextSSH)
{
    MSTATUS status = OK;

    if (NULL == pContextSSH)
        status = ERR_NULL_POINTER;
    else
    {
        AUTH_FAILURE_BUFFER(pContextSSH) = MALLOC(1 + ssh_authMethods.stringLen + 1);

        if (NULL == AUTH_FAILURE_BUFFER(pContextSSH))
            status = ERR_MEM_ALLOC_FAIL;
        else
        {
            /* fill the byte array for usage later */
            AUTH_FAILURE_BUFFER(pContextSSH)[0] = SSH_MSG_USERAUTH_FAILURE;
            MOC_MEMCPY(&(AUTH_FAILURE_BUFFER(pContextSSH)[1]), ssh_authMethods.pString, ssh_authMethods.stringLen);
            AUTH_KEYINT_CONTEXT(pContextSSH).user         = NULL;
            AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest = NULL;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_AUTH_deallocStructures(sshContext *pContextSSH)
{
    MSTATUS status = OK;

    if (NULL == pContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != AUTH_FAILURE_BUFFER(pContextSSH))
    {
        FREE(AUTH_FAILURE_BUFFER(pContextSSH));
        AUTH_FAILURE_BUFFER(pContextSSH) = NULL;
    }

    SSH_STR_freeStringBuffer(&AUTH_KEYINT_CONTEXT(pContextSSH).user);

    if ((NULL != SSH_sshSettings()->funcPtrReleaseKeyIntReq) &&
        (NULL != AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest))
    {
        status = (SSH_sshSettings()->funcPtrReleaseKeyIntReq)
                  (CONNECTION_INSTANCE(pContextSSH),
                   AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest);
    }

    if (NULL != AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest)
    {
        FREE(AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest);
        AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest = NULL;
    }

exit:
    return status;

} /* SSH_AUTH_deallocStructures */


/*------------------------------------------------------------------*/

static MSTATUS
computeClientPubKeyHashBuffer(sshContext *pContextSSH, ubyte *pMesgData, ubyte4 mesgLen, ubyte **ppBufferToHash, ubyte4 *pBufferToHashLen, vlong **ppVlongQueue)
{
    ubyte               length[4];
    ubyte               *pBufferToHash = NULL;
    ubyte4              bufferToHashLen = 0;
    MSTATUS             status = ERR_NULL_POINTER;

    if ((NULL == ppBufferToHash) || (NULL == pBufferToHashLen))
        goto exit;

    *ppBufferToHash = NULL;
    *pBufferToHashLen = 0;

    status = MOC_MALLOC((void**)&pBufferToHash, 4 + pContextSSH->sessionIdLength + mesgLen);
    if (OK != status)
        goto exit;

    length[0] = 0;
    length[1] = 0;
    length[2] = 0;
    length[3] = (ubyte)pContextSSH->sessionIdLength;

    bufferToHashLen = 4;
    status = MOC_MEMCPY(pBufferToHash, length, bufferToHashLen);
    if (OK != status)
        goto exit;

    status = MOC_MEMCPY(pBufferToHash + bufferToHashLen, SSH_SESSION_ID(pContextSSH), pContextSSH->sessionIdLength);
    if (OK != status)
        goto exit;
    bufferToHashLen += pContextSSH->sessionIdLength;

    status = MOC_MEMCPY(pBufferToHash + bufferToHashLen, pMesgData, mesgLen);
    if (OK != status)
        goto exit;
    bufferToHashLen += mesgLen;

exit:
    if (OK == status)
    {
        *ppBufferToHash = pBufferToHash;
        *pBufferToHashLen = bufferToHashLen;
    }
    else
    {
        MOC_FREE((void**)&pBufferToHash);
    }
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
computeClientPubKeyHash(sshContext *pContextSSH, ubyte *pMesgData, ubyte4 mesgLen, vlong **ppM, ubyte *pShaOutput, vlong **ppVlongQueue, ubyte4 hashSize)
{
    ubyte       length[4];
    BulkCtx             pHashContext = NULL;
    BulkHashAlgo        hashAlgo = SHA1Suite;
    MSTATUS     status;

#ifndef __DISABLE_MOCANA_SHA256__
    if (SHA256_RESULT_SIZE == hashSize)
    {
        hashAlgo = SHA256Suite;
    }
#endif
#ifndef __DISABLE_MOCANA_SHA384__
    if (SHA384_RESULT_SIZE == hashSize)
    {
        hashAlgo = SHA384Suite;
    }
#endif
#ifndef __DISABLE_MOCANA_SHA512__
    if (SHA512_RESULT_SIZE == hashSize)
    {
        hashAlgo = SHA512Suite;
    }
#endif

    length[0] = 0;
    length[1] = 0;
    length[2] = 0;
    length[3] = (ubyte)pContextSSH->sessionIdLength;

    status = (hashAlgo.allocFunc)(MOC_HASH(pContextSSH->hwAccelCookie) &pHashContext);
    if (OK != status)
        goto exit;

    status = (hashAlgo.initFunc)(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext);
    if (OK != status)
        goto exit;

    status = (hashAlgo.updateFunc)(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, length, 4);
    if (OK != status)
        goto exit;

    if (OK > (status = (hashAlgo.updateFunc)(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, SSH_SESSION_ID(pContextSSH), pContextSSH->sessionIdLength)))
        goto exit;

    if (OK > (status = (hashAlgo.updateFunc)(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pMesgData, mesgLen)))
        goto exit;

    if (OK > (status = (hashAlgo.finalFunc)(MOC_HASH(pContextSSH->hwAccelCookie) pHashContext, pShaOutput)))
        goto exit;

    if (NULL != ppM)
    {
        DEBUG_RELABEL_MEMORY(*ppM);
        if (OK > (status = VLONG_vlongFromByteString(pShaOutput, hashSize , ppM, ppVlongQueue)))
            goto exit;
    }


exit:

    (hashAlgo.freeFunc)(MOC_HASH(pContextSSH->hwAccelCookie) &pHashContext);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
handleIncomingPubKeys(sshContext *pContextSSH, sshStringBuffer* pPublicKeyBlob, AsymmetricKey* pPublicKey,
                      intBoolean *pAcceptPubKeyType, vlong **ppVlongQueue)
{
    ubyte4              index;
    sbyte4              result;
    sshStringBuffer*    pKeyFormat = NULL;
    MSTATUS             status;

    if ((NULL == pPublicKeyBlob) || (NULL == pAcceptPubKeyType))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    index = 4;

    *pAcceptPubKeyType = FALSE;

    /* compare received pubkey w/ cached pubkey */
    if (OK > (status = SSH_STR_copyStringFromPayload(pPublicKeyBlob->pString,
                                                     pPublicKeyBlob->stringLen,
                                                     &index, &pKeyFormat)))
    {
        goto exit;
    }

    if ((NULL == pKeyFormat) || (NULL == pKeyFormat->pString))
    {
        status = ERR_SSH_MALFORMED_SIGNATURE;
        goto exit;
    }

#if (defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__))
    /* handle dss key format */
    if (OK > (status = MOC_MEMCMP(pKeyFormat->pString, ssh_dss_signature.pString, ssh_dss_signature.stringLen, &result)))
        goto exit;

    if (0 == result)
    {
        *pAcceptPubKeyType = TRUE;

        if (OK > (status = CRYPTO_createDSAKey(pPublicKey, ppVlongQueue)))
            goto exit;

        status = SSH_DSS_extractDssCertificate(MOC_ASYM(pContextSSH->hwAccelCookie) pPublicKeyBlob, pPublicKey, index, ppVlongQueue);

        goto exit;
    }
#endif

#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__))

    /* handle rsa key format */
#if (!defined(__DISABLE_MOCANA_SHA512__))
    if (OK > (status = MOC_MEMCMP(pKeyFormat->pString, ssh_rsasha512_signature.pString, ssh_rsasha512_signature.stringLen, &result)))
        goto exit;
#else
    if (OK > (status = MOC_MEMCMP(pKeyFormat->pString, ssh_rsasha256_signature.pString, ssh_rsasha256_signature.stringLen, &result)))
        goto exit;
#endif

    if (0 != result)
    {
        if (OK > (status = MOC_MEMCMP(pKeyFormat->pString, ssh_rsa_signature.pString, ssh_rsa_signature.stringLen, &result)))
            goto exit;
    }

    if (0 == result)
    {
        if (OK > (status = CRYPTO_createRSAKey(pPublicKey, ppVlongQueue)))
            goto exit;

        status = SSH_RSA_extractRsaCertificate(MOC_ASYM(pContextSSH->hwAccelCookie) pPublicKeyBlob, pPublicKey, index, ppVlongQueue);

        *pAcceptPubKeyType = TRUE;

        goto exit;
    }
#endif /* __ENABLE_MOCANA_SSH_RSA_SUPPORT__ */

#ifdef __ENABLE_MOCANA_ECC__

    /* handle ec key format */
    if (OK > (status = MOC_MEMCMP(pKeyFormat->pString + 4, (ubyte*)"ecdsa-sha2", 10, &result)))
        goto exit;

    if (0 == result)
    {
        if (OK > (status = SSH_ECDSA_extractEcdsaCertificate(MOC_ASYM(pContextSSH->hwAccelCookie) pPublicKeyBlob, pPublicKey, index, ppVlongQueue)))
        {
            goto exit;
        }
        *pAcceptPubKeyType = TRUE;

        goto exit;
    }
    else
    {
        if (OK > (status = MOC_MEMCMP(pKeyFormat->pString + 4, (ubyte*)"ssh-ed25519", 11, &result)))
            goto exit;

        if (0 == result)
        {
            if (OK > (status = SSH_ECDSA_extractEcdsaCertificate(MOC_ASYM(pContextSSH->hwAccelCookie) pPublicKeyBlob, pPublicKey, index, ppVlongQueue)))
            {
                goto exit;
            }
            *pAcceptPubKeyType = TRUE;

            goto exit;
        }
    }
#endif /* __ENABLE_MOCANA_ECC__ */

#ifdef __ENABLE_MOCANA_PQC__

    /* handle qs key format */
    status = SSH_QS_verifyAlgorithmName((const sshStringBuffer *) pKeyFormat, &result);
    if (OK == status && 0 == result)
    {
        status = SSH_QS_extractQsKey(MOC_HASH(pContextSSH->hwAccelCookie) pPublicKeyBlob, pPublicKey, index, ppVlongQueue);
        if (OK != status)
            goto exit;

        *pAcceptPubKeyType = TRUE;
        goto exit;
    }

#ifdef __ENABLE_MOCANA_ECC__

    /* handle hybrid key format */
    status = SSH_HYBRID_verifyAlgorithmName((const sshStringBuffer *) pKeyFormat, &result);
    if (OK == status && 0 == result)
    {
        status = SSH_HYBRID_extractHybridKey(MOC_ASYM(pContextSSH->hwAccelCookie) pPublicKeyBlob, pPublicKey, index, ppVlongQueue);
        if (OK != status)
            goto exit;

        *pAcceptPubKeyType = TRUE;
        goto exit;
    }
#endif /* __ENABLE_MOCANA_ECC__ */
#endif /* __ENABLE_MOCANA_PQC__ */

    /*!!!! add new method for certificate auth */

exit:
    SSH_STR_freeStringBuffer(&pKeyFormat);

    return status;

} /* handleIncomingPubKeys */


/*------------------------------------------------------------------*/

extern sbyte *
SSH_AUTH_authList(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie)
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
}


/*------------------------------------------------------------------*/

static sbyte4
findAuthChoice(sbyte *pAuthMethod, ubyte4 authMethodLength, ubyte4 bitMask)
{
    sbyte4  index = NUM_AUTH_OPTIONS - 1;
    sbyte4  memResult;

    while (0 <= index)
    {
        if ((0 != (mAuthMethods[index].bitMask & bitMask)) &&
            (authMethodLength == mAuthMethods[index].optionNameLength) &&
            (OK <= MOC_MEMCMP((ubyte *)pAuthMethod, (ubyte *)mAuthMethods[index].pOptionName, authMethodLength, &memResult)) &&
            (0 == memResult))
        {
            break;
        }

        index--;
    }

    return ((0 <= index) ? mAuthMethods[index].bitMask : 0);
}


/*------------------------------------------------------------------*/

static MSTATUS
receiveAuthServiceRequest(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    ubyte*              pPayload            = NULL;
    ubyte4              length;
    sbyte4              memCmpResult;
    MSTATUS             status = OK;

    AUTH_ADVERTISED_METHODS(pContextSSH) = 0xffffffff;

    if (NULL != SSH_sshSettings()->funcPtrGetAuthAdvertizedMethods)
        AUTH_ADVERTISED_METHODS(pContextSSH) = (SSH_sshSettings()->funcPtrGetAuthAdvertizedMethods)(CONNECTION_INSTANCE(pContextSSH));

    if (0 != (AUTH_ADVERTISED_METHODS(pContextSSH) &
              (MOCANA_SSH_AUTH_PUBLIC_KEY | MOCANA_SSH_AUTH_PASSWORD | MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE)))
    {
        if (OK > (status = SSH_STR_HOUSE_createFromList(&(AUTH_ADVERTISED(pContextSSH)), SSH_AUTH_authList, AUTH_ADVERTISED_METHODS(pContextSSH))))
            goto exit;
    }
    else
    {
        MOCANA_log((sbyte4)MOCANA_SSH, (sbyte4)LS_MAJOR, (sbyte *)"User unable to log in --- all SSH authentication methods disabled.");
        status = ERR_AUTH_MISCONFIGURED;
        goto exit;
    }

    if ((((ssh_userAuthService.stringLen + 1) != newMesgLen)                  ||
        (SSH_MSG_SERVICE_REQUEST != *pNewMesg))                               ||
        (OK > (status = MOC_MEMCMP(ssh_userAuthService.pString, pNewMesg + 1,
                               ssh_userAuthService.stringLen, &memCmpResult)) ||
        (0 != memCmpResult)))
    {
#ifdef __DEBUG_SSH_AUTH__
        DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("receiveAuthServiceRequest: bad service requested."));
#endif
        if (OK <= status)
            status = ERR_SSH_DISCONNECT_SERVICE_NOT_AVAILABLE;
        goto exit;
    }

    /* send SSH_MSG_SERVICE_ACCEPT message */
    if (NULL == (pPayload = MALLOC(ssh_userAuthService.stringLen + 1)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *pPayload = SSH_MSG_SERVICE_ACCEPT;
    MOC_MEMCPY(pPayload + 1, ssh_userAuthService.pString, ssh_userAuthService.stringLen);

    if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, pPayload, ssh_userAuthService.stringLen + 1, &length)))
        goto exit;

    FREE(pPayload); pPayload = NULL;

    if (ssh_userAuthService.stringLen + 1 != length)
    {
        status = ERR_PAYLOAD_TOO_LARGE;
        goto exit;
    }

exit:
    if (NULL != pPayload)
        FREE(pPayload);

    return status;

} /* receiveAuthServiceRequest */

static ubyte4
getHashSizeFromSignature(sshStringBuffer* pSignature)
{
    ubyte i;
    ubyte4 hashSize = SHA_HASH_RESULT_SIZE;
    sbyte4 result;
    MSTATUS status;

    for(i = 0; i <= NUM_AUTH_PUBKEY_OPTIONS; i++)
    {
        status = MOC_MEMCMP(pSignature->pString+4 /* for payload length */ , mAuthPubKeyMethods[i].pSignature->pString,
                                                 mAuthPubKeyMethods[i].pSignature->stringLen, &result);

        if((status == OK) && (result == 0))
        {
            hashSize = mAuthPubKeyMethods[i].hashLen;
            break;
        }
    }

    return hashSize;
}

/*------------------------------------------------------------------*/

static MSTATUS
SSH_AUTH_verifySignature(sshContext *pContextSSH, sshAuthCommonArgs *pAuthCommonArgs, sshStringBuffer* pSignature,
                         intBoolean *pIsGoodKeyType, intBoolean *pIsGoodSignature, AsymmetricKey *pPublicKey, vlong **ppVlongQueue)
{
    MSTATUS 	status;
    ubyte*  	pShaOutput = NULL;
    ubyte4  	hashSize   = SHA_HASH_RESULT_SIZE;/* Default use SHA1 */
    vlong*  	pM         = NULL;
#if (defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__)) && (!defined(__DISABLE_MOCANA_SHA256__))
    sbyte4      primeLen;
#endif

    /* Based on the RFC, the signature hash len is based on the signature algorithm name.
     */

    hashSize = getHashSizeFromSignature(pSignature);

    /* check the signature against incoming message */
    switch (pPublicKey->type)
    {
#if (defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__))
        case akt_dsa:
        {
#if (!defined(__DISABLE_MOCANA_SHA256__))
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_DSA_getCipherTextLength(MOC_DSA(pContextSSH->hwAccelCookie) pPublicKey->key.pDSA, &primeLen);
#else
            status = DSA_getCipherTextLength(MOC_DSA(pContextSSH->hwAccelCookie) pPublicKey->key.pDSA, &primeLen);
#endif
            if (OK != status)
                goto exit;

            if (2048 == 8*primeLen)
            {
                hashSize = SHA256_RESULT_SIZE;
            }
#endif
            pShaOutput = MALLOC(hashSize);
            if (NULL == pShaOutput)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            /* compute m */
            if (OK > (status = computeClientPubKeyHash(pContextSSH, pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen - pSignature->stringLen, &pM, pShaOutput, ppVlongQueue, hashSize)))
                goto exit;

            *pIsGoodKeyType = TRUE;

            status = SSH_DSS_verifyDssSignature(MOC_DSA(pContextSSH->hwAccelCookie) pPublicKey, TRUE, pM, pSignature, pIsGoodSignature, ppVlongQueue);

            break;
        }
#endif
#if (defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__))
        case akt_rsa:
        {
            *pIsGoodKeyType = TRUE;

            pShaOutput = MALLOC(hashSize);
            if (NULL == pShaOutput)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            /* compute m */
            if (OK > (status = computeClientPubKeyHash(pContextSSH, pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen - pSignature->stringLen, NULL, pShaOutput, ppVlongQueue, hashSize)))
                goto exit;

            status = SSH_RSA_verifyRsaSignature(MOC_RSA(pContextSSH->hwAccelCookie) pPublicKey, TRUE,
                                                pShaOutput, hashSize,
                                                pSignature, pIsGoodSignature,
                                                ppVlongQueue);
            break;
        }
#endif
#if (defined(__ENABLE_MOCANA_PQC__))
        case akt_qs:
        {
            *pIsGoodKeyType = TRUE;

            /* generate message to be signed, this will not generate hash */
            status = computeClientPubKeyHashBuffer(pContextSSH, pAuthCommonArgs->pNewMesg,
                                                   pAuthCommonArgs->newMesgLen - pSignature->stringLen,
                                                   &pShaOutput, &hashSize, ppVlongQueue);
            if (OK != status)
                goto exit;

            status = SSH_QS_verifyQsSignature(MOC_HASH(pContextSSH->hwAccelCookie) pPublicKey, TRUE, pShaOutput, hashSize,
                                              pSignature, pIsGoodSignature, ppVlongQueue);
            break;
        }
#endif /* __ENABLE_MOCANA_PQC__ */

#if defined(__ENABLE_MOCANA_PQC__) && defined(__ENABLE_MOCANA_ECC__)
        case akt_hybrid:
        {
            *pIsGoodKeyType = TRUE;

            /* generate message to be signed, this will not generate hash */
            status = computeClientPubKeyHashBuffer(pContextSSH, pAuthCommonArgs->pNewMesg,
                                                   pAuthCommonArgs->newMesgLen - pSignature->stringLen,
                                                   &pShaOutput, &hashSize, ppVlongQueue);
            if (OK != status)
                goto exit;

            status = SSH_HYBRID_verifyHybridSignature(MOC_ASYM(pContextSSH->hwAccelCookie) pPublicKey, TRUE, pShaOutput, hashSize,
                                                      pSignature, pIsGoodSignature, ppVlongQueue);
            break;

            *pIsGoodKeyType = TRUE;
        }
#endif

#if (defined(__ENABLE_MOCANA_ECC__))
        case akt_ecc_ed:
        case akt_ecc:
        {
            *pIsGoodKeyType = TRUE;
            ECCKey *pECCKey = pPublicKey->key.pECC;
            ubyte4 curveId = 0;

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveId);
            if(OK != status)
                goto exit;
#else
            status = EC_getCurveIdFromKey(pECCKey, &curveId);
            if(OK != status)
                goto exit;
#endif
            switch (curveId)
            {
#if (!defined(__DISABLE_MOCANA_SHA256__))
                case cid_EC_P256:
                    hashSize = SHA256_RESULT_SIZE;
                    break;
#endif
#if (!defined(__DISABLE_MOCANA_SHA384__))
                case cid_EC_P384:
                    hashSize = SHA384_RESULT_SIZE;
                    break;
#endif
#if (!defined(__DISABLE_MOCANA_SHA512__))
                case cid_EC_P521:
                    hashSize = SHA512_RESULT_SIZE;
                    break;
#endif
                default:/* We have already set size to sha1 */
                    break;
            }

            /* SSH does not support ED448, only ED25519 */
            if (curveId == cid_EC_Ed25519)
            {
                /* generate message to be signed, this will not generate hash */
                if (OK > (status = computeClientPubKeyHashBuffer(pContextSSH, pAuthCommonArgs->pNewMesg,
                                                           pAuthCommonArgs->newMesgLen - pSignature->stringLen,
                                                           &pShaOutput, &hashSize, ppVlongQueue)))
                {
                    goto exit;
                }

                /* pass message to hash and sign */
                status = SSH_ECDSA_verifyEdDSASignature(MOC_ECC(pContextSSH->hwAccelCookie) pPublicKey, ht_none,
                                                    pShaOutput, hashSize,
                                                    pSignature, pIsGoodSignature,
                                                    ppVlongQueue);
            }
            else
            {

                status = MOC_MALLOC((void **) &pShaOutput, hashSize);
                if (OK != status)
                    goto exit;

                /* generate message to be signed, this will generate hash */
                if (OK > (status = computeClientPubKeyHash(pContextSSH, pAuthCommonArgs->pNewMesg,
                                                           pAuthCommonArgs->newMesgLen - pSignature->stringLen,
                                                           NULL, pShaOutput, ppVlongQueue, hashSize)))
                {
                    goto exit;
                }

                /* pass message to hash and sign */
                status = SSH_ECDSA_verifyEcdsaSignature(MOC_ECC(pContextSSH->hwAccelCookie) pPublicKey, TRUE,
                                                    pShaOutput, hashSize,
                                                    pSignature, pIsGoodSignature,
                                                    ppVlongQueue);
            }
            break;

        }
#endif /* __ENABLE_MOCANA_ECC__ */
        default:
        {
            status = ERR_BAD_KEY_TYPE;
            break;
        }
    }

exit:
    if (NULL != pShaOutput)
        FREE(pShaOutput);

    VLONG_freeVlong(&pM, ppVlongQueue);

    return status;

} /* SSH_AUTH_verifySignature */


/*------------------------------------------------------------------*/

static MSTATUS findAuthenticationMethod(sshStringBuffer* pSignature, intBoolean *pFound)
{
    sbyte4  result;
    MSTATUS status = OK;
    ubyte4 i;

    *pFound = FALSE;
    for(i = 0; i <= NUM_AUTH_PUBKEY_OPTIONS; i++)
    {
        status = MOC_MEMCMP(pSignature->pString, mAuthPubKeyMethods[i].pName->pString,
                                                 mAuthPubKeyMethods[i].pName->stringLen, &result);

        if (OK != status)
            return status;

        if(result == 0)
        {
            *pFound = TRUE;
            break;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
getCertChainLengthSSH(const ubyte* pSSHCertChainBuf, ubyte4 sshCertChainBufLen, ubyte4 *pBufIndex, ubyte4 *pCertChainLength)
{
    MSTATUS status;
    ubyte4 indexCerts;
    ubyte4 certificateCount;
    ubyte4 totalLength;
    sbyte4 cmpRes;
    ubyte4 i;

    *pCertChainLength = *pBufIndex;

#ifdef __ENABLE_MOCANA_SSH_NO_PUBKEY_NAME__
    cmpRes = -1;
    /* 4 bytes total length, 4 bytes name length, 6 bytes x509v3 */
    if (14 < (sshCertChainBufLen - *pBufIndex))
    {
        status = MOC_MEMCMP(pSSHCertChainBuf + *pBufIndex + 8, (ubyte *)"x509v3", 6, &cmpRes);
        if (OK != status)
            goto exit;
    }

    if (0 == cmpRes)
#endif
    {
        /* total length of public key field */
        totalLength  = (ubyte4)pSSHCertChainBuf[(*pBufIndex)];   totalLength <<= 8;
        totalLength |= (ubyte4)pSSHCertChainBuf[(*pBufIndex)+1]; totalLength <<= 8;
        totalLength |= (ubyte4)pSSHCertChainBuf[(*pBufIndex)+2]; totalLength <<= 8;
        totalLength |= (ubyte4)pSSHCertChainBuf[(*pBufIndex)+3];
        *pBufIndex += 4;

        cmpRes = -1;
        for(i = 0; i <= NUM_AUTH_PUBKEY_OPTIONS; i++)
        {
            status = MOC_MEMCMP(pSSHCertChainBuf + *pBufIndex, mAuthPubKeyMethods[i].pName->pString,
                mAuthPubKeyMethods[i].pName->stringLen, &cmpRes);
            if (OK != status)
                goto exit;

            if(cmpRes == 0)
            {
                break;
            }
        }

        if (0 != cmpRes)
        {
            goto exit;
        }

        *pBufIndex += mAuthPubKeyMethods[i].pName->stringLen;
    }

    /* <uint32 certificate-count> */
    certificateCount  = (ubyte4)pSSHCertChainBuf[(*pBufIndex)];   certificateCount <<= 8;
    certificateCount |= (ubyte4)pSSHCertChainBuf[(*pBufIndex)+1]; certificateCount <<= 8;
    certificateCount |= (ubyte4)pSSHCertChainBuf[(*pBufIndex)+2]; certificateCount <<= 8;
    certificateCount |= (ubyte4)pSSHCertChainBuf[(*pBufIndex)+3];
    *pBufIndex += 4;

    for (indexCerts = 0; indexCerts < certificateCount; indexCerts++)
    {
        if (OK > (status = SSH_STR_walkStringInPayload(pSSHCertChainBuf, sshCertChainBufLen, pBufIndex)))
        {
            /* any string error, we convert to certificate error */
            status = ERR_SSH_PROTOCOL_PROCESS_CERTIFICATE;
            goto exit;
        }
    }

    *pCertChainLength = *pBufIndex - *pCertChainLength;

    if (0 == cmpRes)
    {
        *pCertChainLength = totalLength + 4;
    }
    else
    {
        *pCertChainLength = *pBufIndex - *pCertChainLength;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSH_AUTH_pubkeyAuth(sshContext *pContextSSH, sshAuthCommonArgs *pAuthCommonArgs)
{
    intBoolean          isAuth              = FALSE;
    intBoolean          isGoodSignature     = FALSE;
    sshStringBuffer*    pAuthAdvertised     = &(AUTH_ADVERTISED(pContextSSH));
    intBoolean          acceptPubKeyType    = FALSE;
    sshStringBuffer*    pPublicKeyAlgorithm = NULL;
    sshStringBuffer*    pPublicKeyBlob      = NULL;
    sshStringBuffer*    pCertificate        = NULL;
    sshStringBuffer*    pSignature          = NULL;
    AsymmetricKey       publicKey;
    ubyte*              pPayload            = NULL;
    ubyte*              pKeyBlob            = NULL;
    vlong*              pVlongQueue         = NULL;
    certChainPtr        pNewCertChain       = NULL;
    ubyte4              keyBlobLength;
    byteBoolean         hasSignature;
    ubyte4              length;
    MSTATUS             status;
    sbyte4              isX509V3            = 1;

#if ((defined(__ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__)))
    ValidationConfig    vc                  = {0};
    ubyte*              pLeafCert;
    ubyte4              leafCertLen;
#endif

    ubyte               *pPublicKeyBlobBuffer = NULL;
    ubyte4              publicKeyBlobBufferLength;
    intBoolean          algorithmFound = FALSE;

    if (OK > (status = CRYPTO_initAsymmetricKey(&publicKey)))
        return status;

    /* public key authentication */
    hasSignature = (byteBoolean)((0 == pAuthCommonArgs->pNewMesg[pAuthCommonArgs->index]) ? FALSE : TRUE);

    pAuthCommonArgs->index++;

#ifdef __DEBUG_SSH_AUTH__
    DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("SSH_AUTH_pubkeyAuth: informational - pubkey: handling pub algo."));
#endif

    if (OK > (status = SSH_STR_copyStringFromPayload(pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen, &(pAuthCommonArgs->index), &pPublicKeyAlgorithm)))
        goto exit;

    /* Check if client is using certificate to authenticate itself */
    /* 4 bytes = size, 6 bytes x509v3 */
    if (pPublicKeyAlgorithm->stringLen > 10)
    {
        if (OK > (status = MOC_MEMCMP(pPublicKeyAlgorithm->pString + 4, (const ubyte *)"x509v3", 6, &isX509V3)))
        {
            goto exit;
        }
    }

#ifdef __DEBUG_SSH_AUTH__
    DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("SSH_AUTH_pubkeyAuth: informational - pubkey: handling pub blob."));
#endif

    if (isX509V3 != 0)
    {
        if (OK > (status = SSH_STR_copyStringFromPayload(pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen, &(pAuthCommonArgs->index), &pPublicKeyBlob)))
            goto exit;

        pPublicKeyBlobBuffer = pPublicKeyBlob->pString;
        publicKeyBlobBufferLength = pPublicKeyBlob->stringLen;
#ifdef __DEBUG_SSH_AUTH__
        DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("SSH_AUTH_pubkeyAuth: informational - pubkey: hasSignature."));
#endif
    }
#if ((defined(__ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__)))
    else if ((isX509V3 == 0) && (FALSE == hasSignature))
    {
        pPublicKeyBlobBuffer = pAuthCommonArgs->pNewMesg + pAuthCommonArgs->index;
        if (OK > (status = getCertChainLengthSSH(pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen, &pAuthCommonArgs->index, &publicKeyBlobBufferLength)))
            goto exit;

#ifdef __DEBUG_SSH_AUTH__
        DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("SSH_AUTH_pubkeyAuth: informational - pubkey: hasSignature."));
#endif
    }
    else
    {
        ASN1_ITEMPTR    pRoot = 0;
        MemFile         mf;
        CStream         cs;

        sbyte4          cmpRes;
        ubyte4          ocspResponseCount = 0;
        ubyte4          indexOcsp;
        ubyte4          i;

#ifdef __ENABLE_MOCANA_SSH_NO_PUBKEY_NAME__
        cmpRes = -1;
        if (14 < (pAuthCommonArgs->newMesgLen - pAuthCommonArgs->index))
        {
            status = MOC_MEMCMP((const ubyte *)(pAuthCommonArgs->pNewMesg + pAuthCommonArgs->index + 8), (ubyte *)"x509v3", 6, &cmpRes);
            if (OK != status)
                goto exit;
        }

        if (0 == cmpRes)
#endif
        {
            /* move past length field of public key blob */
            pAuthCommonArgs->index += 4;
            cmpRes = -1;
            for(i = 0; i <= NUM_AUTH_PUBKEY_OPTIONS; i++)
            {
                status = MOC_MEMCMP(pAuthCommonArgs->pNewMesg + pAuthCommonArgs->index,
                    mAuthPubKeyMethods[i].pName->pString, mAuthPubKeyMethods[i].pName->stringLen, &cmpRes);
                if (OK != status)
                    goto exit;

                if(0 == cmpRes)
                {
                    break;
                }
            }

            if (0 != cmpRes)
            {
                status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised);
                goto exit;
            }

            pAuthCommonArgs->index += mAuthPubKeyMethods[i].pName->stringLen;
        }

        if (OK > (status = CERTCHAIN_createFromSSHEx(MOC_ASYM(pContextSSH->hwAccelCookie) &pNewCertChain, pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen, &pAuthCommonArgs->index, &SSH_STR_walkStringInPayload)))
            goto exit;

#ifndef __ENABLE_MOCANA_SSH_NO_PUBKEY_NAME__
        if (pAuthCommonArgs->newMesgLen < (4 + (pAuthCommonArgs->index)))
        {
            /* definitely needs to be more than 4 bytes... */
            status = ERR_SSH_PROTOCOL_PROCESS_CERTIFICATE;       /* gone past the end of the buffer */
            goto exit;
        }

        /* <uint32 certificate-count> */
        ocspResponseCount  = (ubyte4)pAuthCommonArgs->pNewMesg[(pAuthCommonArgs->index)];
        ocspResponseCount <<= 8;
        ocspResponseCount |= (ubyte4)pAuthCommonArgs->pNewMesg[(pAuthCommonArgs->index)+1];
        ocspResponseCount <<= 8;
        ocspResponseCount |= (ubyte4)pAuthCommonArgs->pNewMesg[(pAuthCommonArgs->index)+2];
        ocspResponseCount <<= 8;
        ocspResponseCount |= (ubyte4)pAuthCommonArgs->pNewMesg[(pAuthCommonArgs->index)+3];
        pAuthCommonArgs->index += 4;

        for (indexOcsp = 0; indexOcsp < ocspResponseCount; indexOcsp++)
        {
            if (OK > (status = SSH_STR_walkStringInPayload(pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen, &pAuthCommonArgs->index)))
            {
                /* any string error, we convert to certificate error */
                status = ERR_SSH_PROTOCOL_PROCESS_CERTIFICATE;
                goto exit;
            }
        }
#endif

        if (OK > (status = CERTCHAIN_getCertificate(pNewCertChain, 0, (const ubyte** )&pLeafCert, &leafCertLen)))
            goto exit;

        MF_attach(&mf, leafCertLen, pLeafCert);
        CS_AttachMemFile(&cs, &mf);

        if (OK > (status = ASN1_Parse(cs, &pRoot)))
        {
            goto exit;
        }

        vc.keyUsage = 1;                   /* verify key usage */
        vc.pCertStore = pContextSSH->pCertStore;  /* verify Trust Point */
        vc.commonName = NULL;

        status = CERTCHAIN_validate(MOC_ASYM(pContextSSH->hwAccelCookie) pNewCertChain, &vc) ;
        if (pRoot)
            TREE_DeleteTreeItem((TreeItem *) pRoot);

        /* call application api to validate the certificate status */
        if (NULL != SSH_sshSettings()->funcPtrCertStatus)
        {
            if(OK > (status = (SSH_sshSettings()->funcPtrCertStatus)
                            (CONNECTION_INSTANCE(pContextSSH),
                             (4 + pAuthCommonArgs->pUser->pString),
                            (pAuthCommonArgs->pUser->stringLen) - 4,
                           status, pLeafCert, leafCertLen, pNewCertChain,
                            vc.anchorCert, vc.anchorCertLen)))
            {
                goto exit ;
            }
        }
        else
        {
            if(OK > status )
                goto exit ;
        }
        if (OK > (status = CERTCHAIN_getKey(MOC_RSA(pContextSSH->hwAccelCookie) pNewCertChain, 0, &publicKey)))
        {
            goto exit;
        }

        /* Certificate is valid, so we have a valid publicKey */
        acceptPubKeyType = TRUE;

    }
#endif

    if (FALSE == hasSignature)
    {
        if (NULL == pPublicKeyBlobBuffer)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

#if ((defined(__ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__)))
        /* if we do not have an x509 certificate and this is a raw key, we want to give public key to application
         * isX509V3 == 0 means that we do have an X509 certificate. */
        if (isX509V3 != 0)
#endif
        {
            if (OK > (status = handleIncomingPubKeys(pContextSSH, pPublicKeyBlob, &publicKey, &acceptPubKeyType, &pVlongQueue)))
                goto exit;

            if (FALSE == acceptPubKeyType)
            {
                /* reply with  SSH_MSG_USERAUTH_FAILURE */
                status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised);
                goto exit;
            }

            if (OK > (status = CA_MGMT_makeKeyBlobEx(&publicKey, &pKeyBlob, &keyBlobLength)))
            {
    #ifdef __DEBUG_SSH_AUTH__
                DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("SSH_AUTH_pubkeyAuth: CA_MGMT_makeKeyBlobEx() failed."));
    #endif
                goto exit;
            }

            if (NULL != SSH_sshSettings()->funcPtrPubKeyAuth)
                isAuth = (SSH_sshSettings()->funcPtrPubKeyAuth)
                                (CONNECTION_INSTANCE(pContextSSH),
                                (4 + pAuthCommonArgs->pUser->pString),
                                (pAuthCommonArgs->pUser->stringLen) - 4,
                                pKeyBlob, keyBlobLength, publicKey.type);

            if (AUTH_PASS != isAuth)
            {
                /* reply with  SSH_MSG_USERAUTH_FAILURE */
                status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised);
                goto exit;
            }
        }

        status = findAuthenticationMethod(pPublicKeyAlgorithm, &algorithmFound);
        if (OK != status)
            goto exit;

        /*  RFC 4252 Section 7:
                    If the server does not support some algorithm,
            it MUST simply reject the request.

            The server MUST respond to this message with either
            SSH_MSG_USERAUTH_FAILURE or with the following:

                byte      SSH_MSG_USERAUTH_PK_OK
                string    public key algorithm name from the request
                string    public key blob from the request
         */
        if (FALSE == algorithmFound)
        {
            /* reply with  SSH_MSG_USERAUTH_FAILURE */
            status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised);
            goto exit;
        }

        /* reply with SSH_MSG_USERAUTH_PK_OK */
        if (NULL == (pPayload = MALLOC(1 + pPublicKeyAlgorithm->stringLen + publicKeyBlobBufferLength)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *pPayload = SSH_MSG_USERAUTH_PK_OK;
        MOC_MEMCPY(pPayload + 1, pPublicKeyAlgorithm->pString, pPublicKeyAlgorithm->stringLen);
        MOC_MEMCPY(pPayload + 1 + pPublicKeyAlgorithm->stringLen, pPublicKeyBlobBuffer, publicKeyBlobBufferLength);
        if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, pPayload, 1 + pPublicKeyAlgorithm->stringLen + publicKeyBlobBufferLength, &length))){
            DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("SSH_AUTH_pubkeyAuth: Sending PK_OK failed"));
            goto exit;
        }
        FREE(pPayload); pPayload = NULL;

        if ((1 + pPublicKeyAlgorithm->stringLen + publicKeyBlobBufferLength) != length)
            status = ERR_PAYLOAD_TOO_LARGE;

        goto exit;
    }

#ifdef __DEBUG_SSH_AUTH__
    DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("SSH_AUTH_pubkeyAuth: informational - pubkey: handle signature."));
#endif

    if (pNewCertChain == NULL)
    {
        /* handle the authentication message that has a public key included */
        if (OK > (status = SSH_STR_copyStringFromPayload(pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen, &(pAuthCommonArgs->index), &pSignature)))
            goto exit;

        if (OK > (status = handleIncomingPubKeys(pContextSSH, pPublicKeyBlob, &publicKey, &acceptPubKeyType, &pVlongQueue)))
            goto exit;

        if (FALSE == acceptPubKeyType)
        {
            status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised);
            goto exit;
        }
    }
#if ((defined(__ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__)) && (defined(__ENABLE_MOCANA_SSH_CLIENT_CERT_AUTH__)))
    else
    {
        /* handle the authentication message that has a certificate included */
        if (OK > (status = SSH_STR_copyStringFromPayload(pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen, &(pAuthCommonArgs->index), &pSignature)))
            goto exit;
    }
#endif

#ifdef __DEBUG_SSH_AUTH__
    DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("SSH_AUTH_pubkeyAuth: informational - pubkey: compute m."));
#endif

    if (OK > (status = SSH_AUTH_verifySignature(pContextSSH, pAuthCommonArgs, pSignature, &acceptPubKeyType, &isGoodSignature, &publicKey, &pVlongQueue)))
        goto exit;

    if (FALSE == acceptPubKeyType)
    {
        status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised);
        goto exit;
    }

#ifdef __DEBUG_SSH_AUTH__
    DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("handleAuthMessage: informational - pubkey: verify signature."));
#endif

    /* make internal key blob from incoming key blob */
    if (OK > (status = CA_MGMT_makeKeyBlobEx(&publicKey, &pKeyBlob, &keyBlobLength)))
    {
#ifdef __DEBUG_SSH_AUTH__
        DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("SSH_AUTH_pubkeyAuth: CA_MGMT_makeKeyBlobEx() failed."));
#endif
        goto exit;
    }

    /* callback to see, if user name is acceptable */
    isAuth = AUTH_FAIL;

#ifdef __DEBUG_SSH_AUTH__
    DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("SSH_AUTH_pubkeyAuth: informational - pubkey: callback verify."));
#endif

    if (TRUE == isGoodSignature)
    {
        if (NULL != SSH_sshSettings()->funcPtrPubKeyAuth)
            isAuth = (SSH_sshSettings()->funcPtrPubKeyAuth)
                            (CONNECTION_INSTANCE(pContextSSH),
                            (4 + pAuthCommonArgs->pUser->pString),
                            (pAuthCommonArgs->pUser->stringLen) - 4,
                            pKeyBlob, keyBlobLength, publicKey.type);
    }

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
    if (AUTH_WAIT == isAuth)
    {
        pContextSSH->waitEvent = kWaitingForAuth;
        pContextSSH->authContext.authMethod = MOCANA_SSH_AUTH_PUBLIC_KEY;
        goto exit;
    }
#endif

    /* the only acceptable result is TRUE(1), otherwise it's false */
    if (AUTH_PASS != (isAuth = ((AUTH_PASS == isAuth) ? AUTH_PASS : AUTH_FAIL)))
    {
#ifdef __DEBUG_SSH_AUTH__
        DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("SSH_AUTH_pubkeyAuth: public key authentication failed, continue."));
#endif
        /* authentication failed */
		AUTH_FAILURE_ATTEMPTS(pContextSSH)++;
        status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised);
        goto exit;
    }
    else
    {
        /* authentication succeeded change state */
        SSH_UPPER_STATE(pContextSSH) = kOpenState;
    }

exit:

    SSH_STR_freeStringBuffer(&pPublicKeyAlgorithm);
    SSH_STR_freeStringBuffer(&pPublicKeyBlob);
    SSH_STR_freeStringBuffer(&pSignature);
    SSH_STR_freeStringBuffer(&pCertificate);
    CRYPTO_uninitAsymmetricKey(&publicKey, 0);
    VLONG_freeVlongQueue(&pVlongQueue);

    if(pNewCertChain)
        CERTCHAIN_delete(&pNewCertChain);

    if (NULL != pPayload)
        FREE(pPayload);

    if (NULL != pKeyBlob)
        FREE(pKeyBlob);

    return status;

} /* SSH_AUTH_pubkeyAuth */


/*------------------------------------------------------------------*/

static MSTATUS
SSH_AUTH_passwordAuth(sshContext *pContextSSH, sshAuthCommonArgs *pAuthCommonArgs)
{
    sshStringBuffer*    pPassword           = NULL;
    intBoolean          isAuth;
    sshStringBuffer*    pAuthAdvertised     = &(AUTH_ADVERTISED(pContextSSH));
    MSTATUS             status;

    /* handle password authentication */
#ifdef __DEBUG_SSH_AUTH__
    DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("SSH_AUTH_passwordAuth: informational - password auth."));
#endif
    if (1 == pAuthCommonArgs->pNewMesg[pAuthCommonArgs->index])
    {
        /* sorry, we don't support password changes */
        if (OK > (status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised)))
            goto exit;

        goto end;
    }

    pAuthCommonArgs->index++;

    if (OK > (status = SSH_STR_copyStringFromPayload(pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen, &(pAuthCommonArgs->index), &pPassword)))
        goto exit;

    if (pAuthCommonArgs->index != pAuthCommonArgs->newMesgLen)
    {
        /* malformed auth message */
        if (OK > (status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised)))
            goto exit;

        goto end;
    }

    /* callback to see, if creditentials are acceptable */
    isAuth = AUTH_FAIL;

    if (NULL != SSH_sshSettings()->funcPtrPasswordAuth)
        isAuth = (SSH_sshSettings()->funcPtrPasswordAuth)
                             (CONNECTION_INSTANCE(pContextSSH),
                             (4 + pAuthCommonArgs->pUser->pString),
                             (pAuthCommonArgs->pUser->stringLen - 4),
                             (4 + pPassword->pString), pPassword->stringLen - 4);

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
    if (AUTH_WAIT == isAuth)
    {
        pContextSSH->waitEvent = kWaitingForAuth;
        pContextSSH->authContext.authMethod = MOCANA_SSH_AUTH_PASSWORD;
        goto end;
    }
#endif

    /* the only acceptable result is 1, otherwise it's false */
    if (AUTH_PASS != (isAuth = ((AUTH_PASS == isAuth) ? AUTH_PASS : AUTH_FAIL)))
    {
        /* authentication failed */
		AUTH_FAILURE_ATTEMPTS(pContextSSH)++;
        if (OK > (status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised)))
            goto exit;

        goto end;
    }
    else
    {
        /* authentication succeeded change state */
        SSH_UPPER_STATE(pContextSSH) = kOpenState;
    }

exit:
end:
    SSH_STR_freeStringBuffer(&pPassword);

    return status;

} /* SSH_AUTH_passwordAuth */


/*------------------------------------------------------------------*/

static MSTATUS
SSH_AUTH_noneAuth(sshContext *pContextSSH, sshAuthCommonArgs *pAuthCommonArgs)
{
    intBoolean          isAuth;
    sshStringBuffer*    pAuthAdvertised     = &(AUTH_ADVERTISED(pContextSSH));
    MSTATUS             status = OK;

    /* handle none authentication */
#ifdef __DEBUG_SSH_AUTH__
    DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("SSH_AUTH_noneAuth: informational - none auth."));
#endif

    if (pAuthCommonArgs->index != pAuthCommonArgs->newMesgLen)
    {
        /* malformed auth message */
        status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised);
        goto exit;
    }

    /* callback to see, if creditentials are acceptable */
    isAuth = AUTH_FAIL;

    if (NULL != SSH_sshSettings()->funcPtrNoneAuth)
        isAuth = (SSH_sshSettings()->funcPtrNoneAuth)
                             (CONNECTION_INSTANCE(pContextSSH),
                              (4 + pAuthCommonArgs->pUser->pString),
                              (pAuthCommonArgs->pUser->stringLen - 4));

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
    if (AUTH_WAIT == isAuth)
    {
        pContextSSH->waitEvent = kWaitingForAuth;
        pContextSSH->authContext.authMethod = MOCANA_SSH_AUTH_NONE;
        goto exit;
    }
#endif

    /* the only acceptable result is 1, otherwise it's false */
    if (AUTH_PASS != (isAuth = ((AUTH_PASS == isAuth) ? AUTH_PASS : AUTH_FAIL)))
    {
        /* authentication failed */
		AUTH_FAILURE_ATTEMPTS(pContextSSH)++;
        status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised);
    }
    else
    {
        /* authentication succeeded change state */
        SSH_UPPER_STATE(pContextSSH) = kOpenState;
    }

exit:
    return status;
} /* SSH_AUTH_noneAuth */


/*------------------------------------------------------------------*/

static MSTATUS
SSH_AUTH_interactiveKeyboardAuth(sshContext *pContextSSH, sshAuthCommonArgs *pAuthCommonArgs)
{
    sbyte4              isKeyboardAuth      = FALSE;
    sshStringBuffer*    pAuthAdvertised     = &(AUTH_ADVERTISED(pContextSSH));
    sshStringBuffer*    pLanguageTag        = NULL;
    sshStringBuffer*    pSubmethods         = NULL;
    MSTATUS             status;

#ifdef __DEBUG_SSH_AUTH__
    DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("SSH_AUTH_interactiveKeyboardAuth: info"));
#endif

    /* get the language tag */
    if (OK > (status = SSH_STR_copyStringFromPayload(pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen,
                                                     &pAuthCommonArgs->index, &pLanguageTag)))
    {
        goto exit;
    }

    /* get the sub methods */
    if (OK > (status = SSH_STR_copyStringFromPayload(pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen,
                                                     &pAuthCommonArgs->index, &pSubmethods)))
    {
        goto exit;
    }

    if (pAuthCommonArgs->index != pAuthCommonArgs->newMesgLen)
    {
        /* malformed auth message */
        status = ERR_SSH_UNEXPECTED_END_MESSAGE;
        goto exit;
    }

    /* callback to see, if keyboard interactive is acceptable */
    if (NULL == AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest)
    {
        if (NULL == (AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest = MALLOC(sizeof(keyIntInfoReq))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* out of courtesy clear out the buffer */
        MOC_MEMSET((ubyte*)(AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest), 0x00, sizeof(keyIntInfoReq));
    }

    isKeyboardAuth = AUTH_FAIL;

    if (NULL != SSH_sshSettings()->funcPtrKeyIntAuthReq)
    {
        status = (SSH_sshSettings()->funcPtrKeyIntAuthReq)
                          (CONNECTION_INSTANCE(pContextSSH),
                          (4 + pAuthCommonArgs->pUser->pString),
                          (pAuthCommonArgs->pUser->stringLen) - 4,
                          NULL,
                          AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest,
                          &isKeyboardAuth);
        if (OK != status)
            goto exit;
    }

    /* We have 3 possible results. 1 if the authentication is successful and nothing
       else is needed, 0 if the authentication failed, or -1 if the authentication
       needs more info */

    switch (isKeyboardAuth)
    {
        default:
        case AUTH_FAIL:
            /* authentication failed */
            AUTH_FAILURE_ATTEMPTS(pContextSSH)++;
            if (OK > (status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised)))
                goto exit;

            break;

        case AUTH_PASS:
            /* authentication succeeded change state */
            SSH_UPPER_STATE(pContextSSH) = kOpenState;
            break;

        case AUTH_FAIL_MORE:
            AUTH_FAILURE_ATTEMPTS(pContextSSH)++;   /*!-!-!-! fall-thru, intentional missing break */

        case AUTH_MORE:
            if (OK > (status = sendAuthInfoRequest(pContextSSH, AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest)))
                goto exit;

            SSH_STR_freeStringBuffer(&(AUTH_KEYINT_CONTEXT(pContextSSH).user));
            if (NULL != SSH_sshSettings()->funcPtrReleaseKeyIntReq)
            {
                status = (SSH_sshSettings()->funcPtrReleaseKeyIntReq)
                         (CONNECTION_INSTANCE(pContextSSH),
                         AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest);

                if (OK > status)
                    goto exit;
            }

            AUTH_KEYINT_CONTEXT(pContextSSH).user    = pAuthCommonArgs->pUser;
            pAuthCommonArgs->pUser                   = NULL;
            break;

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
        case AUTH_WAIT:
            /* update user name for future rounds */
            SSH_STR_freeStringBuffer(&(AUTH_KEYINT_CONTEXT(pContextSSH).user));
            AUTH_KEYINT_CONTEXT(pContextSSH).user    = pAuthCommonArgs->pUser;
            pAuthCommonArgs->pUser                   = NULL;

            pContextSSH->waitEvent = kWaitingForAuth;
            pContextSSH->authContext.authMethod = MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE;
            break;
#endif
    }

exit:
    SSH_STR_freeStringBuffer(&pLanguageTag);
    SSH_STR_freeStringBuffer(&pSubmethods);

    return status;

} /* SSH_AUTH_interactiveKeyboardAuth */


/*------------------------------------------------------------------*/

/* Validate that the message recieved has the following form:
 *      byte      SSH_MSG_USERAUTH_INFO_RESPONSE
 *      int       num-responses
 *      string    response[1] (ISO-10646 UTF-8)
 *      ...
 *      string    response[num-responses] (ISO-10646 UTF-8)
 * */
static intBoolean isValidInfoResponse(const sshAuthCommonArgs* pAuthCommonArgs)
{
    ubyte *pMsg;
    ubyte4 msgLen;
    ubyte4 numOfResp;
    ubyte4 respLen;
    ubyte4 index;
    ubyte4 i;

    if(NULL == pAuthCommonArgs)
    {
        return FALSE;
    }

    pMsg = pAuthCommonArgs->pNewMesg;
    msgLen = pAuthCommonArgs->newMesgLen;

    if (SSH_MSG_USERAUTH_INFO_RESPONSE != *pMsg)
    {
        return FALSE;
    }
    index = 1;

    if ((4 + index) > msgLen)
    {
        return FALSE;
    }

    numOfResp  = ((ubyte4)(pMsg[index] & 0xff) << 24); index++;
    numOfResp |= ((ubyte4)(pMsg[index] & 0xff) << 16); index++;
    numOfResp |= ((ubyte4)(pMsg[index] & 0xff) <<  8); index++;
    numOfResp |= ((ubyte4)(pMsg[index] & 0xff));       index++;

    if (numOfResp > AUTH_MAX_NUM_PROMPTS)
    {
        return FALSE;
    }

    for (i = 0; i < numOfResp; i ++)
    {
        if ((4 + index) > msgLen)
        {
            return FALSE;
        }
        respLen  = ((ubyte4)(pMsg[index] & 0xff) << 24); index++;
        respLen |= ((ubyte4)(pMsg[index] & 0xff) << 16); index++;
        respLen |= ((ubyte4)(pMsg[index] & 0xff) <<  8); index++;
        respLen |= ((ubyte4)(pMsg[index] & 0xff));       index++;

        if ((respLen + index) > msgLen)
        {
            return FALSE;
        }
        index += respLen;
    }

    if (index != msgLen)
    {
        /* we have not consumed the entire message */
        return FALSE;
    }

    return TRUE;
}


/*------------------------------------------------------------------*/

static MSTATUS
receiveAuthMessage(sshContext *pContextSSH, sshAuthCommonArgs* pAuthCommonArgs)
{
    sshStringBuffer*    pService            = NULL;
    sshStringBuffer*    pMethod             = NULL;
    sshStringBuffer*    pAuthAdvertised     = &(AUTH_ADVERTISED(pContextSSH));
    ubyte4              length;
    sbyte4              memCmpResult;
    ubyte               userAuthSuccess;
    sbyte4              isKeyboardAuth      = FALSE;
    ubyte4              numberOfResponses   = 0;
    ubyte4              n                   = 0;
    ubyte4              authChoice;
    MSTATUS             status              = OK;

    if ((SSH_sshSettings()->sshMaxAuthAttempts) <= AUTH_FAILURE_ATTEMPTS(pContextSSH))
    {
        status = ERR_AUTH_FAILED;
        goto exit;
    }

    /* we only accept passcode and publickey authentication */
    if (((SSH_MSG_USERAUTH_REQUEST != *(pAuthCommonArgs->pNewMesg)) &&
        (SSH_MSG_USERAUTH_INFO_RESPONSE != *(pAuthCommonArgs->pNewMesg))) ||
        (5 > pAuthCommonArgs->newMesgLen) )
    {
        status = ERR_AUTH_UNEXPECTED_MESG;
        goto exit;
    }

    pAuthCommonArgs->index = 1;

    if (SSH_MSG_USERAUTH_REQUEST == *pAuthCommonArgs->pNewMesg)
    {
        if (13 > pAuthCommonArgs->newMesgLen)
        {
            status = ERR_AUTH_UNEXPECTED_MESG;
            goto exit;
        }

        /* extract values from payload */
        if (OK > (status = SSH_STR_copyStringFromPayload(pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen, &pAuthCommonArgs->index, &pAuthCommonArgs->pUser)))
            goto exit;

        if (OK > (status = SSH_STR_copyStringFromPayload(pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen, &pAuthCommonArgs->index, &pService)))
            goto exit;

        if (OK > (status = SSH_STR_copyStringFromPayload(pAuthCommonArgs->pNewMesg, pAuthCommonArgs->newMesgLen, &pAuthCommonArgs->index, &pMethod)))
            goto exit;

        /* we only offer ssh-connection service, anything else causes a disconnect */
        if (OK > (status = MOC_MEMCMP(pService->pString, ssh_connectService.pString, ssh_connectService.stringLen, &memCmpResult)))
            goto exit;

        /* handle authentication methods */
        if (0 != memCmpResult)
        {
            status = ERR_SSH_DISCONNECT_SERVICE_NOT_AVAILABLE;
            goto exit;
        }

        /* verify the authentication method choice is available */
        if (0 == (authChoice = findAuthChoice((sbyte *)(4 + pMethod->pString), pMethod->stringLen - 4,
                                              AUTH_ADVERTISED_METHODS(pContextSSH)
                                              | MOCANA_SSH_AUTH_NONE)))
        {
            status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised);
            goto exit;
	}

        switch (authChoice)
        {
            case MOCANA_SSH_AUTH_PUBLIC_KEY:
                if (OK > (status = SSH_AUTH_pubkeyAuth(pContextSSH, pAuthCommonArgs)))
                    goto exit;
                break;
            case MOCANA_SSH_AUTH_PASSWORD:
                if (OK > (status = SSH_AUTH_passwordAuth(pContextSSH, pAuthCommonArgs)))
                    goto exit;
                break;
            case MOCANA_SSH_AUTH_NONE:
                if (OK > (status = SSH_AUTH_noneAuth(pContextSSH, pAuthCommonArgs)))
                    goto exit;
                break;
            case MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE:
                if (OK > (status = SSH_AUTH_interactiveKeyboardAuth(pContextSSH, pAuthCommonArgs)))
                    goto exit;
                break;
            default:
                status = ERR_AUTH_UNKNOWN_METHOD;
                goto exit;
        }
    }
    else /* handle SSH_MSG_USERAUTH_INFO_RESPONSE */
    {
        keyIntInfoResp      infoResponse;
        keyIntResp          *pNewResp = NULL;

        if (NULL == AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest)
        {
            /* error on bogus SSH_MSG_USERAUTH_INFO_REQUEST reply message */
            status = ERR_AUTH_UNEXPECTED_MESG;
            goto exit;
        }

        if (FALSE == isValidInfoResponse(pAuthCommonArgs))
        {
            status = ERR_SSH_UNEXPECTED_END_MESSAGE;
            goto exit;
        }

        MOC_MEMSET((ubyte*) &infoResponse, 0, sizeof(infoResponse));

        /* process an info response message */
        if ((4 + pAuthCommonArgs->index) > pAuthCommonArgs->newMesgLen)
        {
            status = ERR_SSH_UNEXPECTED_END_MESSAGE;
            goto exit;
        }

        numberOfResponses  = ((ubyte4)(pAuthCommonArgs->pNewMesg[pAuthCommonArgs->index] & 0xff) << 24);    pAuthCommonArgs->index++;
        numberOfResponses |= ((ubyte4)(pAuthCommonArgs->pNewMesg[pAuthCommonArgs->index] & 0xff) << 16);    pAuthCommonArgs->index++;
        numberOfResponses |= ((ubyte4)(pAuthCommonArgs->pNewMesg[pAuthCommonArgs->index] & 0xff) <<  8);    pAuthCommonArgs->index++;
        numberOfResponses |= ((ubyte4)(pAuthCommonArgs->pNewMesg[pAuthCommonArgs->index] & 0xff));          pAuthCommonArgs->index++;

        /* callback to see, if keyboard interactive response is acceptable */
        isKeyboardAuth = AUTH_FAIL;

        /* Ensure that we have an outstanding info request and that the number of responses
           is the same as the number of prompts and that we have a info response upcall
           to invoke and then invoke it */
        if ((NULL != AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest) &&
            (AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest->numPrompts == numberOfResponses) &&
            (NULL != SSH_sshSettings()->funcPtrKeyIntAuthReq))
        {
            /* Extract the responses from the message */
            MOC_MEMSET((ubyte*) &infoResponse, 0x00, sizeof(infoResponse));

            infoResponse.numResponses = numberOfResponses;
            MOC_MEMSET((ubyte*) infoResponse.responses, 0,
                    (sizeof(keyIntResp) * numberOfResponses));

            while ((OK == status) && (n < numberOfResponses))
            {
                if ((4 + pAuthCommonArgs->index) <= pAuthCommonArgs->newMesgLen)
                {
                    status = MOC_MALLOC((void **) &pNewResp, sizeof(*pNewResp));
                    if (OK == status)
                    {
                        pNewResp->responseLen  = ((ubyte4)(pAuthCommonArgs->pNewMesg[pAuthCommonArgs->index] & 0xff) << 24); pAuthCommonArgs->index++;
                        pNewResp->responseLen |= ((ubyte4)(pAuthCommonArgs->pNewMesg[pAuthCommonArgs->index] & 0xff) << 16); pAuthCommonArgs->index++;
                        pNewResp->responseLen |= ((ubyte4)(pAuthCommonArgs->pNewMesg[pAuthCommonArgs->index] & 0xff) <<  8); pAuthCommonArgs->index++;
                        pNewResp->responseLen |= ((ubyte4)(pAuthCommonArgs->pNewMesg[pAuthCommonArgs->index] & 0xff));       pAuthCommonArgs->index++;

                        if ((pNewResp->responseLen + pAuthCommonArgs->index) <= pAuthCommonArgs->newMesgLen)
                        {
                            pNewResp->pResponse = &(pAuthCommonArgs->pNewMesg[pAuthCommonArgs->index]);
                            pAuthCommonArgs->index += pNewResp->responseLen;

                            infoResponse.responses[n] = pNewResp;
                            n++;
                        }
                        else
                        {
                            MOC_FREE((void **) &pNewResp);
                            status = ERR_SSH_UNEXPECTED_END_MESSAGE;
                        }
                    }
                }
                else
                {
                    status = ERR_SSH_UNEXPECTED_END_MESSAGE;
                }
            }

            /*
             * If status != OK, there was an error parsing message. Invalid information response received.
             */
            if (OK == status)
            {
                status = (SSH_sshSettings()->funcPtrKeyIntAuthReq)
                                        (CONNECTION_INSTANCE(pContextSSH),
                                        AUTH_KEYINT_CONTEXT(pContextSSH).user->pString + 4,
                                        AUTH_KEYINT_CONTEXT(pContextSSH).user->stringLen - 4,
                                        &infoResponse, AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest, &isKeyboardAuth);
            }
            for (n = 0; n < infoResponse.numResponses; n++)
            {
                MOC_FREE((void **)&(infoResponse.responses[n]));
            }

            if (OK > status)
            {
                goto exit;
            }

            if (AUTH_MAX_NUM_PROMPTS < AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest->numPrompts)
            {
                /*!-!-!-! most likely callback overran array */
                DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("receiveAuthMessage: num prompts misconfigued."));
                status = ERR_AUTH_MISCONFIGURED_PROMPTS;
                goto exit;
            }
        }

        /* We have 3 possible results. 1 if the authentication is successful and nothing
           else is needed, 0 if the authentication failed, or 2 if the authentication
           needs more info */
        switch (isKeyboardAuth)
        {
            default:
            case AUTH_FAIL:
                /* authentication failed */
                AUTH_FAILURE_ATTEMPTS(pContextSSH)++;
                if (OK > (status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised)))
                    goto exit;
                break;

            case AUTH_PASS:
                /* authentication succeeded change state */
                SSH_UPPER_STATE(pContextSSH) = kOpenState;
                break;

            case AUTH_FAIL_MORE:
                AUTH_FAILURE_ATTEMPTS(pContextSSH)++;

            case AUTH_MORE:
                if (OK > (status = sendAuthInfoRequest(pContextSSH, AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest)))
                    goto exit;

                if (NULL != SSH_sshSettings()->funcPtrReleaseKeyIntReq)
                {
                    status = (SSH_sshSettings()->funcPtrReleaseKeyIntReq)
                    (CONNECTION_INSTANCE(pContextSSH),
                    AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest);
                }

                if (OK > status)
                    goto exit;
                break;

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__
            case AUTH_WAIT:
                pContextSSH->waitEvent = kWaitingForAuth;
                pContextSSH->authContext.authMethod = MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE;
                break;
#endif
        }
    }

    if (kOpenState == SSH_UPPER_STATE(pContextSSH))
    {
#ifdef __DEBUG_SSH_AUTH__
        DEBUG_PRINTNL(DEBUG_SSH_AUTH, (sbyte *)("receiveAuthMessage: authentication succeeded."));
#endif

        /* the user is in */
        if (OK > (status = SSH_TRANS_setMessageTimer(pContextSSH, SSH_sshSettings()->sshTimeOutDefaultOpenState)))
            goto exit;

        userAuthSuccess = SSH_MSG_USERAUTH_SUCCESS;
        if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, &userAuthSuccess, 1, &length)))
            goto exit;

        /* "channelState" should not be set here. */
        pContextSSH->sessionState.channelState = SESSION_OPEN;
    }

exit:
    SSH_STR_freeStringBuffer(&(pAuthCommonArgs->pUser));
    SSH_STR_freeStringBuffer(&pService);
    SSH_STR_freeStringBuffer(&pMethod);

#ifdef __DEBUG_SSH_AUTH__
    DEBUG_ERROR(DEBUG_SSH_AUTH, "receiveAuthMessage: status = ", status);
#endif

    return status;

} /* receiveAuthMessage */


/*------------------------------------------------------------------*/

#ifdef SSH_USERAUTH_BANNER_STRING
static MSTATUS
SSH_AUTH_sendBanner(sshContext *pContextSSH, const sbyte *pBannerStr)
{
    MSTATUS status;
    ubyte* pPayload = NULL;
    ubyte4 numBytesToWrite;
    ubyte4 strLength;
    ubyte4 length;
    ubyte4 i = 0;

    if (NULL == pBannerStr)
        return ERR_NULL_POINTER;

    strLength = MOC_STRLEN(pBannerStr);

    numBytesToWrite = 1 + 4 + strLength + 4;

    if (NULL == (pPayload = MALLOC(numBytesToWrite)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pPayload[0] = SSH_MSG_USERAUTH_BANNER;
    i = i + 1;

    pPayload[i] = (ubyte)(strLength >> 24);  i++;
    pPayload[i] = (ubyte)(strLength >> 16);  i++;
    pPayload[i] = (ubyte)(strLength >> 8);   i++;
    pPayload[i] = (ubyte)(strLength);        i++;

    MOC_MEMCPY(pPayload + i, pBannerStr, strLength);
    i = i + strLength;

    /* language tag has been deprecated */
    pPayload[i] = 0;    i++;
    pPayload[i] = 0;    i++;
    pPayload[i] = 0;    i++;
    pPayload[i] = 0;

    status = SSH_OUT_MESG_sendMessage(pContextSSH, pPayload, numBytesToWrite, &length);

    if ((0 <= status) && (numBytesToWrite != length))
        status = ERR_PAYLOAD_TOO_LARGE;

exit:
    if (NULL != pPayload)
        FREE(pPayload);

    return status;
}
#endif /* SSH_USERAUTH_BANNER_STRING */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_AUTH_doProtocol(sshContext *pContextSSH, ubyte *pNewMesg, ubyte4 newMesgLen)
{
    sshAuthCommonArgs   authCommonArgs;
    MSTATUS             status;

    authCommonArgs.pNewMesg   = pNewMesg;
    authCommonArgs.newMesgLen = newMesgLen;
    authCommonArgs.index      = 0;
    authCommonArgs.pUser      = NULL;

    switch (SSH_UPPER_STATE(pContextSSH))
    {
        case kAuthServiceRequest:
            if (OK > (status = receiveAuthServiceRequest(pContextSSH, pNewMesg, newMesgLen)))
                break;

            if (OK > (status = SSH_TRANS_setMessageTimer(pContextSSH, SSH_sshSettings()->sshTimeOutAuthentication)))
                break;

            SSH_UPPER_STATE(pContextSSH) = kAuthReceiveMessage;
            AUTH_FAILURE_ATTEMPTS(pContextSSH) = 0;

#ifdef SSH_USERAUTH_BANNER_STRING
            /* send banner */
            if(SSH_sshSettings()->pBannerString)
                status = SSH_AUTH_sendBanner(pContextSSH, SSH_sshSettings()->pBannerString);
            else
                status = SSH_AUTH_sendBanner(pContextSSH, (const sbyte *)SSH_USERAUTH_BANNER_STRING);
#endif

            break;

        case kAuthReceiveMessage:
            status = receiveAuthMessage(pContextSSH, &authCommonArgs);
            break;

        default:
            status = ERR_SSH_BAD_AUTH_RECEIVE_STATE;
            break;
    }

    return status;
}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__

extern MSTATUS
SSH_AUTH_continueAuthFromWait(sshContext *pContextSSH, sbyte4 authResult)
{
    sshStringBuffer*    pAuthAdvertised = &(AUTH_ADVERTISED(pContextSSH));
    ubyte4              length;
    ubyte               userAuthSuccess;
    MSTATUS             status          = OK;

    switch (authResult)
    {
        default:
        case AUTH_FAIL:
            /* authentication failed */
            AUTH_FAILURE_ATTEMPTS(pContextSSH)++;
            if (OK > (status = sendAuthFailure(pContextSSH, FALSE, pAuthAdvertised)))
                goto exit;

            break;

        case AUTH_PASS:
            /* authentication succeeded change state */
            SSH_UPPER_STATE(pContextSSH) = kOpenState;
            break;

        case AUTH_FAIL_MORE:
            AUTH_FAILURE_ATTEMPTS(pContextSSH)++;   /*!-!-!-! fall-thru, intentional missing break */

        case AUTH_MORE:
            /* if we get here, we expect the caller to have populated */
            /* AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest, since we passed that pointer on the previous call */

            if (OK > (status = sendAuthInfoRequest(pContextSSH, AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest)))
                goto exit;

            if (NULL != SSH_sshSettings()->funcPtrReleaseKeyIntReq)
            {
                status = (SSH_sshSettings()->funcPtrReleaseKeyIntReq)
                         (CONNECTION_INSTANCE(pContextSSH),
                         AUTH_KEYINT_CONTEXT(pContextSSH).pInfoRequest);

                if (OK > status)
                    goto exit;
            }
            break;

        case AUTH_WAIT:
            /* why call continue, only to wait */
            status = ERR_SSH_AUTH_DOUBLE_WAIT;
            break;
    }

    if (kOpenState == SSH_UPPER_STATE(pContextSSH))
    {
        /* the user is in */
        if (OK > (status = SSH_TRANS_setMessageTimer(pContextSSH, SSH_sshSettings()->sshTimeOutDefaultOpenState)))
            goto exit;

        userAuthSuccess = SSH_MSG_USERAUTH_SUCCESS;
        if (OK > (status = SSH_OUT_MESG_sendMessage(pContextSSH, &userAuthSuccess, 1, &length)))
            goto exit;

        pContextSSH->sessionState.channelState = SESSION_OPEN;
    }

exit:
    return status;
}

#endif /* __ENABLE_MOCANA_SSH_ASYNC_SERVER_API__ */

#endif /* __ENABLE_MOCANA_SSH_SERVER__ */
