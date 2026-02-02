/*
    ssl_cli_test_ecc.c


 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
*/


#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/moc_net.h"
#include "../../common/mocana.h"
#include "../../common/debug_console.h"
#include "../../common/mstdlib.h"
#include "../../common/sizedbuffer.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/crypto.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../crypto/rsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#endif
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/cert_chain.h"
#include "../../ssl/ssl.h"

#include "../../crypto/sha1.h"
#include "../../crypto/md5.h"
#include "../../common/mem_pool.h"
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#include "../../ssl/sslsock.h"

#include "../../../unit_tests/unittest.h"



/*------------------------------------------------------------------------*/

const sbyte* SSL_CLI_FindStr( const char* what, const sbyte* buffer,
                              sbyte4 bufferSize)
{
    sbyte4 i;
    sbyte4 whatLen;

    whatLen = DIGI_STRLEN((const sbyte*) what);
    i = 0;
    while( i < bufferSize - whatLen)
    {
        if (buffer[i] == *what)
        {
            sbyte4 cmpRes;
            DIGI_MEMCMP((ubyte *)(buffer + i), (const ubyte *)what, whatLen, &cmpRes);
            if (0 == cmpRes)
            {
                return buffer + i + whatLen;
            }
        }
        ++i;
    }
    return 0;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_VerifyOpenSSLReply(ubyte4 hint, const char* cipherName,
                               const char* versionStr,
                               const sbyte* buffer, sbyte4 bufferSize)
{
    int retVal = 0;
    const sbyte* found;


    /* look for "s_server" */
    found = SSL_CLI_FindStr("s_server", buffer, bufferSize);
    retVal += UNITTEST_VALIDPTR(hint, found);
    if (!found) goto exit;
    bufferSize -= (found - buffer);
    buffer = found;

    if (versionStr)
    {
        /* find "Protocol : <versionStr>" */
        found = SSL_CLI_FindStr("Protocol  : ", buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
        if (!found) goto exit;
        bufferSize -= (found - buffer);
        buffer = found;

        found = SSL_CLI_FindStr(versionStr, buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
        if (!found) goto exit;
    }

    /* cipher name are weird in OpenSSL: no test */

exit:

    return retVal;
}


/*------------------------------------------------------------------------*/

int SSL_CLI_VerifyMocanaReply(ubyte4 hint, const char* cipherName,
                           const char* resourceName, const char* versionStr,
                           const sbyte* buffer, sbyte4 bufferSize)
{
    int retVal = 0;
    sbyte4 cmpRes;
    const sbyte* found;
    int isSrp = cipherName ? (strstr( cipherName, "_SRP_")) : 0;
    char *pEnv = NULL;
    ubyte verifyMocanaServerResposne = 1;

    pEnv = getenv("ENABLE_OPENSSL_INTEROPERABILITY_TEST");
    if (pEnv != NULL)
    {
        if (1 == atoi(pEnv))
            verifyMocanaServerResposne = 0;
    }


    if (1 == verifyMocanaServerResposne)
    {
        /* look for "<body>Congratulations!" */
        found = SSL_CLI_FindStr("<body>Congratulations!", buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
        if (!found) return retVal;
        bufferSize -= (found - buffer);
        buffer = found;

        if (versionStr)
        {
            /* look for the ssl protocol */
            found = SSL_CLI_FindStr(versionStr, buffer, bufferSize);
            retVal += UNITTEST_VALIDPTR(hint, found);
        }

        if ( cipherName)
        {
            /* look for "cipherName</b>" */
            found = SSL_CLI_FindStr(cipherName, buffer, bufferSize);
            retVal += UNITTEST_VALIDPTR(hint, found);
        }

        retVal += UNITTEST_TRUE( hint, (bufferSize >= 3));
        DIGI_MEMCMP((ubyte *)found, (ubyte *)"</b>", 4, &cmpRes);
        retVal += UNITTEST_TRUE( hint, (cmpRes == 0));


        /* look for "resourceName</b> */
        found = SSL_CLI_FindStr(resourceName, buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);

        retVal += UNITTEST_TRUE( hint, (bufferSize >= 3));
        DIGI_MEMCMP((ubyte *)found, (ubyte *)"</b>", 4, &cmpRes);
        retVal += UNITTEST_TRUE( hint, (cmpRes == 0));


        if (isSrp)
        {
            /* look for identity */
            found = SSL_CLI_FindStr("<br>SRP Identity = scott</br>", buffer, bufferSize);
            retVal += UNITTEST_VALIDPTR(hint, found);
        }
        else
        {
            found = SSL_CLI_FindStr("<br>SRP Identity = </br>", buffer, bufferSize);
            retVal += UNITTEST_VALIDPTR(hint, found);
        }
    }

    return retVal;
}

/*------------------------------------------------------------------------*/

int SSL_CLI_VerifymbedReply(ubyte4 hint, const char* cipherName,
                            const char* versionStr,
                            const sbyte* buffer, sbyte4 bufferSize)
{
    int retVal = 0;
    const sbyte* found;
    char* s;
    char* mbdedCipherName = 0;

    if (cipherName)
    {
        /* replace all _ by - since this is what mbed uses */
        mbdedCipherName = strdup(cipherName);
        s = mbdedCipherName;
        while (*s)
        {
            if (*s == '_')
            {
                *s = '-';
            }
            ++s;
        }
    }

    /* look for "<body><h2>mbed TLS Test Server</h2>" */
    found = SSL_CLI_FindStr("<body><h2>mbed TLS Test Server</h2>",
                            buffer, bufferSize);
    retVal += UNITTEST_VALIDPTR(hint, found);
    if (!found) goto exit;
    bufferSize -= (found - buffer);
    buffer = found;

    if (mbdedCipherName)
    {
        /* look for "cipherName" */
        found = SSL_CLI_FindStr(mbdedCipherName, buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
        if (!found) goto exit;
        bufferSize -= (found - buffer);
        buffer = found;
    }

    if (versionStr)
    {
        /* ", protocol: " */
        found = SSL_CLI_FindStr(", protocol: ", buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
        if (!found) goto exit;
        bufferSize -= (found - buffer);
        buffer = found;

        /* look for "versionStr" */
        found = SSL_CLI_FindStr(versionStr, buffer, bufferSize);
        retVal += UNITTEST_VALIDPTR(hint, found);
        if (!found) goto exit;
        bufferSize -= (found - buffer);
        buffer = found;
    }

exit:
    free(mbdedCipherName);
    return retVal;
}

/*------------------------------------------------------------------------*/

/* this function is in its own file because it pokes in the SSLSocket structure */
int SSL_CLI_VerifyECCKeyCurve(int hint, const AsymmetricKey* pECCKey, enum tlsExtNamedCurves curve)
{
    int retVal = 0;
    PEllipticCurvePtr pCurve;

    retVal += UNITTEST_VALIDPTR(hint, pECCKey);
    if (retVal) goto exit;

    retVal += UNITTEST_INT(hint, pECCKey->type, akt_ecc);
    if (retVal) goto exit;

    pCurve = pECCKey->key.pECC->pCurve;
    switch (curve)
    {

#ifdef __ENABLE_DIGICERT_ECC_P192__
    case 0x401:
        retVal += UNITTEST_TRUE( hint, EC_compareEllipticCurves(EC_P192, pCurve));
        break;
    case tlsExtNamedCurves_secp192r1:
        retVal += UNITTEST_TRUE( hint, EC_compareEllipticCurves(EC_P192, pCurve));
        break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
    case tlsExtNamedCurves_secp224r1:
        retVal += UNITTEST_TRUE( hint, EC_compareEllipticCurves(EC_P224, pCurve));
        break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
    case tlsExtNamedCurves_secp256r1:
        retVal += UNITTEST_TRUE( hint, EC_compareEllipticCurves(EC_P256, pCurve));
        break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
    case tlsExtNamedCurves_secp384r1:
        retVal += UNITTEST_TRUE( hint, EC_compareEllipticCurves(EC_P384, pCurve));
        break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
    case tlsExtNamedCurves_secp521r1:
        retVal += UNITTEST_TRUE( hint, EC_compareEllipticCurves(EC_P521, pCurve));
        break;
#endif
    default:
         retVal += UNITTEST_TRUE(0, 0);
         break;
    }

exit:
    return retVal;
}


/*------------------------------------------------------------------------*/

/* this function is in its own file because it pokes in the SSLSocket structure */
int SSL_CLI_VerifyECDHECurve(int hint, sbyte4 connectionInstance, enum tlsExtNamedCurves curve)
{
    SSLSocket* pSSLSock;
    int retVal = 0;

    pSSLSock = (SSLSocket*) SSL_returnPtrToSSLSocket( connectionInstance);
    if ((pSSLSock != NULL) && (pSSLSock->ecdheKey.type != 0))
    {
        retVal = SSL_CLI_VerifyECCKeyCurve( hint, &pSSLSock->ecdheKey, curve);
    }

    return retVal;
}


/*------------------------------------------------------------------------*/

/* this function is in its own file because it pokes in the SSLSocket structure */
int SSL_CLI_VerifyPublicKeyCurve(int hint, sbyte4 connectionInstance, enum tlsExtNamedCurves curve)
{
    SSLSocket* pSSLSock;
    int retVal = 0;

    pSSLSock = (SSLSocket*) SSL_returnPtrToSSLSocket( connectionInstance);
    if ((pSSLSock != NULL) && (pSSLSock->handshakeKey.type != 0))
    {
        retVal = SSL_CLI_VerifyECCKeyCurve( hint, &pSSLSock->handshakeKey, curve);
    }

    return retVal;
}


/*------------------------------------------------------------------------*/

/* this function is in its own file because it pokes in the SSLSocket structure */
int SSL_CLI_GetLeafCertificate(int hint, sbyte4 connectionInstance,
                               const ubyte** leafCert, ubyte4* leafCertLen)
{
    SSLSocket* pSSLSock;

    pSSLSock = (SSLSocket*) SSL_returnPtrToSSLSocket(connectionInstance);

    return CERTCHAIN_getCertificate( pSSLSock->pCertChain, 0, leafCert, leafCertLen);
}
