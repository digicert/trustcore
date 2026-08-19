/*
 * ssh_nist.inc
 *
 * Functions for testing SSH against SP 800-135
 *
 */

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__

#include "../../ssh/nist/ssh_nist.h"

/*-------------------------------------------------------------------------------------------------------------------*/

MSTATUS setSSHDesiredLengths(sshContext *pContextSSH, ubyte hashAlg, sbyte4 ivLen, sbyte4 keyLen, ubyte **ppOptions)
{
    MSTATUS status = OK;
    ubyte4 i;
    ubyte found = 0;
    ubyte *pOptions = NULL;
    ubyte digestLen = 0;

    if (NULL == pContextSSH)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pContextSSH->pKeyExSuiteInfo)
    {
        pContextSSH->pKeyExSuiteInfo = &mKeyExSuites[0];
    }

    switch(hashAlg)
    {
        case ht_sha1:
            digestLen = 20;
            pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo = &sshHandshakeSHA1;
            break;

        case ht_sha256:
            digestLen = 32;
            pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo = &sshHandshakeSHA256;
            break;
        
        case ht_sha384:
            digestLen = 48;
            pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo = &sshHandshakeSHA384;
            break;

        case ht_sha512:
            digestLen = 64;
            pContextSSH->pKeyExSuiteInfo->pHashHandshakeAlgo = &sshHandshakeSHA512;
            break;
        
        default:
            status = ERR_INVALID_INPUT;
            goto exit;
    }

    status = DIGI_CALLOC((void **)&pOptions, 1, 6);
    if (OK != status)
        goto exit;

    /* Make sure we only match the test ciphers */
    for (i = NUM_SSH_CIPHER_SUITES -1; i > 0; i--)
    {
        if ( (keyLen == mCipherSuites[i].keySize) &&
             (ivLen == mCipherSuites[i].ivSize) && 
             (11 == mCipherSuites[i].cipherNameLength) &&
             (0 == DIGI_STRCMP("test-cipher", mCipherSuites[i].pCipherName)))
        {
            pOptions[2] = (i+1);
            pOptions[3] = (i+1);
            found = 1;
            break;
        }
    }

    if (0 == found)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Find the HMAC suite matching the requested digest length */
    found = 0;
    for (i = 0; i < NUM_SSH_HMAC_SUITES; i++)
    {
        if (digestLen == mHmacSuites[i].hmacDigestLength)
        {
            pOptions[4] = (i+1);
            pOptions[5] = (i+1);
            found = 1;
            break;
        }
    }
    
    if (0 == found)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    *ppOptions = pOptions;
    pOptions = NULL;

exit:

    if (NULL != pOptions)
    {
        DIGI_FREE((void **)&pOptions);
    }

    return status;
}

MSTATUS setSSHValue(sshContext *pContextSSH, ubyte type, ubyte *pValue, ubyte4 valueLen)
{
    MSTATUS status = OK;

    if ( (NULL == pContextSSH) || (NULL == pValue) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch(type)
    {
        case sshK:
            {
                if (NULL != pContextSSH->sshKeyExCtx.pBytesSharedSecret)
                {
                    DIGI_FREE((void **)&pContextSSH->sshKeyExCtx.pBytesSharedSecret);
                }

                /* Input vector value comes as mpint bytes, SSH will internally convert
                 * from bytestring to mpint bytes during key derivation process. Convert
                 * from mpint to bytestring before storing */
                status = SSH_getByteStringFromMpintBytes (
                    pValue, valueLen, &pContextSSH->sshKeyExCtx.pBytesSharedSecret, 
                    &pContextSSH->sshKeyExCtx.bytesSharedSecretLen);
                if (OK != status)
                    goto exit;

                break;
            }

        case sshH:
            {
                if (NULL != pContextSSH->pHashH)
                {
                    DIGI_FREE((void **)&pContextSSH->pHashH);
                }

                status = DIGI_MALLOC((void **)&pContextSSH->pHashH, valueLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY (
                    (void *)pContextSSH->pHashH, pValue, valueLen);
                if (OK != status)
                    goto exit;

                /* There is no H len, it is the hash length */
                break;
            }

        case sshSessionId:
            {
                if (NULL != pContextSSH->pSessionId)
                {
                    DIGI_FREE((void **)&pContextSSH->pSessionId);
                }

                status = DIGI_MALLOC((void **)&pContextSSH->pSessionId, valueLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY (
                    (void *)pContextSSH->pSessionId, pValue, valueLen);
                if (OK != status)
                    goto exit;

                pContextSSH->sessionIdLength = valueLen;
                break;
            }
        
        default:
            status = ERR_INVALID_INPUT;
            break;
    }

exit:
    return status;
}

MSTATUS getSSHValue(sshContext *pContextSSH, ubyte *pOptions, ubyte type, ubyte **ppValue, ubyte4 *pValueLen)
{
    MSTATUS status = OK;
    ubyte *pTemp = NULL;
    ubyte4 tempLen = 0;
    SSH_CipherSuiteInfo *pCipherSuite = NULL;
    testCtx *pCtx = NULL;

    if ( (NULL == pContextSSH) || (NULL == pOptions) || (NULL == ppValue) || (NULL == pValueLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCipherSuite =  &(mCipherSuites[pOptions[2] - 1]);

    switch(type)
    {
        case sshCTSIV:
            {
                tempLen = pCipherSuite->ivSize;
                status = DIGI_MALLOC((void **)&pTemp, tempLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY((void *)pTemp, pContextSSH->decryptIV, tempLen);
                if (OK != status)
                    goto exit;

                *ppValue = pTemp;
                pTemp = NULL;
                *pValueLen = tempLen;
                break;
            }
        
        case sshSTCIV:
            {
                tempLen = pCipherSuite->ivSize;
                status = DIGI_MALLOC((void **)&pTemp, tempLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY((void *)pTemp, pContextSSH->encryptIV, tempLen);
                if (OK != status)
                    goto exit;

                *ppValue = pTemp;
                pTemp = NULL;
                *pValueLen = tempLen;
                break;
            }

        case sshEncrCTS:
            {
                /* Since we selected our dummy test cipher suite, we know what the
                 * internal context value is. Cast the context so we can get to the
                 * derived key value */
                pCtx = (testCtx *)pContextSSH->cryptDescrIn;

                tempLen = pCipherSuite->keySize;
                status = DIGI_MALLOC((void **)&pTemp, tempLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY((void *)pTemp, pCtx->pKey, tempLen);
                if (OK != status)
                    goto exit;

                *ppValue = pTemp;
                pTemp = NULL;
                *pValueLen = tempLen;
                break;
            }
        
        case sshEncrSTC:
            {
                /* Since we selected our dummy test cipher suite, we know what the
                 * internal context value is. Cast the context so we can get to the
                 * derived key value */
                pCtx = (testCtx *)pContextSSH->cryptDescrOut;

                tempLen = pCipherSuite->keySize;
                status = DIGI_MALLOC((void **)&pTemp, tempLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY((void *)pTemp, pCtx->pKey, tempLen);
                if (OK != status)
                    goto exit;

                *ppValue = pTemp;
                pTemp = NULL;
                *pValueLen = tempLen;
                break;
            }
        
        case sshIntegrityCTS:
            {
                tempLen = pContextSSH->integrityKeyLengthIn;
                status = DIGI_MALLOC((void **)&pTemp, tempLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY((void *)pTemp, pContextSSH->pIntegrityKeyIn, tempLen);
                if (OK != status)
                    goto exit;

                *ppValue = pTemp;
                pTemp = NULL;
                *pValueLen = tempLen;
                break;
            }
        
        case sshIntegritySTC:
            {
                tempLen = pContextSSH->integrityKeyLengthOut;
                status = DIGI_MALLOC((void **)&pTemp, tempLen);
                if (OK != status)
                    goto exit;

                status = DIGI_MEMCPY((void *)pTemp, pContextSSH->pIntegrityKeyOut, tempLen);
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

void freeSSHK(sshContext *pContextSSH)
{
    if (NULL != pContextSSH)
    {
        if (NULL != pContextSSH->sshKeyExCtx.pBytesSharedSecret)
        {
            DIGI_FREE((void **)&pContextSSH->sshKeyExCtx.pBytesSharedSecret);
        }
    }
}
#endif
