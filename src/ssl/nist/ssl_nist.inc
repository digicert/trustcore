/*
 * ssl_nist.inc
 *
 * Functions for testing TLS 1.2 against SP 800-135
 *
 */

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__

#include "../../ssl/nist/ssl_nist.h"

/*-----------------------------------------------------------------------------------------------*/

static CipherSuiteInfo g_pCipherSuite;

MSTATUS setSSLSessionResume(SSLSocket *pSSLSock, E_SessionResumeType resumeType)
{
    if (NULL == pSSLSock)
    {
        return ERR_NULL_POINTER;
    }

    pSSLSock->sessionResume = resumeType;
    return OK;
}

MSTATUS setSSLPRFHashAlgo(SSLSocket *pSSLSock, ubyte hashAlgo)
{
    MSTATUS status;

    if (NULL == pSSLSock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    const CipherSuiteInfo *pCS = pSSLSock->pHandshakeCipherSuite;

    if (NULL == pCS)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* pCS is in read only memory, make a copy and use our non-const global ciphersuiteinfo */
    status = DIGI_MEMCPY((void *)&g_pCipherSuite, (void *)pCS, sizeof(CipherSuiteInfo));
    if (OK != status)
        goto exit;

    status = CRYPTO_getRSAHashAlgo(hashAlgo, (const BulkHashAlgo**)&g_pCipherSuite.pPRFHashAlgo);
    if (OK != status)
        goto exit;

    pSSLSock->pHandshakeCipherSuite = &g_pCipherSuite;

    /* Current support for SP 800-135 testing is for TLS 1.2 only */
    pSSLSock->sslMinorVersion = TLS12_MINORVERSION;

exit:
    return status;
}

MSTATUS setSSLKeyBlockLen(SSLSocket *pSSLSock, ubyte4 keyBlockLen)
{
    MSTATUS status;
    ubyte4 cipherListLen = 0;
    ubyte2 cipherId = 0;
    ubyte4 i = 0;
    ubyte found = 0;

    if (NULL == pSSLSock)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* List of cipher ids corresponding to key length. Note this list is
     * for TLS 1.2 only */
    switch(keyBlockLen)
    {
        case 40:
            cipherId = 0xC02B;
            break;
        
        case 56:
            cipherId = 0x0015;
            break;
        
        case 72:
            cipherId = 0xC02C;
            break;
        
        case 88:
            cipherId = 0xCCA9;
            break;
        
        case 96:
            cipherId = 0xC023;
            break;

        case 104:
            cipherId = 0xCC0A;
            break;

        case 128:
            cipherId = 0x006B;
            break;

        case 160:
            cipherId = 0xC024;
            break;

        default:
            status = ERR_INVALID_INPUT;
            break;
    }

    cipherListLen = sizeof(gCipherSuites) / sizeof(CipherSuiteInfo);
    for (i = 0; i < cipherListLen; i++)
    {
        if (cipherId == gCipherSuites[i].cipherSuiteId)
        {
            pSSLSock->pHandshakeCipherSuite = &gCipherSuites[i];
            found = 1;
            break;
        }
    }

    if (0 == found)
    {
        status = ERR_NOT_FOUND;
    }
    else
    {
        status = OK;
    }

exit:
    return status;
}

MSTATUS setSSLValue(SSLSocket *pSSLSock, ubyte type, ubyte *pValue, ubyte4 valueLen)
{
    MSTATUS status;

    if ( (NULL == pSSLSock) || (NULL == pValue) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch(type)
    {
        case sslClientRandom:
            {
                if (SSL_RANDOMSIZE != valueLen)
                {
                    status = ERR_BAD_LENGTH;
                    goto exit;
                }

                status = DIGI_MEMCPY (
                    (void *)START_RANDOM(pSSLSock), (const void *)pValue, SSL_RANDOMSIZE);

                break;
            }
            
        
        case sslServerRandom:
            {
                if (SSL_RANDOMSIZE != valueLen)
                {
                    status = ERR_BAD_LENGTH;
                    goto exit;
                }

                status = DIGI_MEMCPY (
                    (void *)START_RANDOM(pSSLSock) + SSL_RANDOMSIZE, 
                    (const void *)pValue, SSL_RANDOMSIZE);
                    
                break;
            }

        case sslMasterSecret:
            {
                status = DIGI_MEMCPY((void *)pSSLSock->pSecretAndRand, pValue, valueLen);
                break;
            }
        default:
            status = ERR_INVALID_INPUT;
            break;
    }

exit:
    return status;
}

MSTATUS getSSLValue(SSLSocket *pSSLSock, ubyte type, ubyte **ppValue, ubyte4 *pValueLen)
{
    MSTATUS status;
    ubyte *pTemp = NULL;
    ubyte4 tempLen = 0;
    const CipherSuiteInfo *pCS = NULL;

    if ( (NULL == pSSLSock) || (NULL == ppValue) || (NULL == pValueLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch(type)
    {
        case sslMasterSecret:
            {
                tempLen = SSL_MASTERSECRETSIZE;
                status = DIGI_MALLOC((void **)&pTemp, tempLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY((void *)pTemp, pSSLSock->pSecretAndRand, tempLen);
                if (OK != status)
                    goto exit;

                *ppValue = pTemp;
                pTemp = NULL;
                *pValueLen = tempLen;
                break;
            }
        case sslKeyBlock:
            {
                pCS = pSSLSock->pHandshakeCipherSuite;

                /* Use same length computation logic as SSL_SOCK_generateKeyMaterial */
                tempLen = 2 * (pCS->keySize +
                             IMPLICIT_IV_SIZE(pSSLSock->sslMinorVersion, pCS) +
                             pCS->pCipherAlgo->getFieldFunc(Hash_Size));

                status = DIGI_MALLOC((void **)&pTemp, tempLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY((void *)pTemp, pSSLSock->pMaterials, tempLen);
                if (OK != status)
                    goto exit;

                *ppValue = pTemp;
                pTemp = NULL;
                *pValueLen = tempLen;
                break;
            }
        default:
            status = ERR_INVALID_INPUT;
            break;
    }

exit:

    if (NULL != pTemp)
    {
        DIGI_FREE((void **)&pTemp);
    }

    return status;
}

MSTATUS generateMasterSecret(SSLSocket *pSSLSock,
                             const ubyte* pSecret, ubyte4 secretLen,
                             const ubyte* pLabelSeed, sbyte4 labelSeedLen,
                             ubyte* pResult, sbyte4 resultLen)
{
    return PRF(pSSLSock, pSecret, secretLen, pLabelSeed, labelSeedLen, pResult, resultLen);
}

#endif
