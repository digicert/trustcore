/*
 * win32_sync.c
 *
 * Win32 Hardware Acceleration Synchronous Adapter
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

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#if (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && defined(__ENABLE_WIN32_HARDWARE_ACCEL__))

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/debug_console.h"
#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/rsa.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../crypto/aes.h"
#include "../../crypto/nil.h"
#include "../../crypto/hmac.h"
#include "../../crypto/dh.h"

#if ((defined(__ENABLE_DIGICERT_SSH_SERVER__)) || (defined(__ENABLE_DIGICERT_SSH_CLIENT__)) )
#include "../../crypto/dsa.h"
#endif

#if ((defined(__ENABLE_DIGICERT_SSL_SERVER__)) || (defined(__ENABLE_DIGICERT_SSL_CLIENT__)) )
#include "../../crypto/ca_mgmt.h"
#endif

#define _WIN32_WINNT    0x400

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#define IPAD                    0x36
#define OPAD                    0x5c


/*------------------------------------------------------------------*/

typedef struct
{
    HCRYPTPROV hCryptProv;
    HCRYPTKEY  hPrivateKey;

} winCryptChannel;


/*------------------------------------------------------------------*/

static BYTE PrivateKeyWithExponentOfOne[] =
{
    0x07, 0x02, 0x00, 0x00, 0x00, 0xa4, 0x00, 0x00,
    0x52, 0x53, 0x41, 0x32, 0x00, 0x04, 0x00, 0x00,

    0x01, 0x00, 0x00, 0x00, 0xd1, 0x85, 0xeb, 0xa7,
    0x32, 0x12, 0x07, 0xfe, 0xfa, 0x66, 0xd3, 0xb5,
    0xea, 0xd0, 0x33, 0x51, 0x67, 0x09, 0x06, 0xd4,
    0xda, 0x58, 0x24, 0x20, 0x36, 0x04, 0xc0, 0xcf,
    0x76, 0x26, 0x29, 0xe5, 0xe7, 0xd9, 0xac, 0x95,
    0x14, 0xe8, 0x30, 0x73, 0x64, 0x7e, 0x76, 0x03,
    0x9e, 0x61, 0x1b, 0xfd, 0xa4, 0x25, 0x20, 0x56,
    0x93, 0xd7, 0x32, 0x62, 0xbf, 0x25, 0x54, 0x00,
    0xe7, 0x4b, 0x65, 0xfa, 0x43, 0x87, 0x6f, 0xfe,
    0x76, 0x3e, 0x93, 0x7b, 0xe4, 0x46, 0xfc, 0x57,
    0x84, 0xb2, 0x5a, 0x88, 0x23, 0x66, 0x0f, 0x9d,
    0xf3, 0x58, 0x1e, 0xd8, 0xa5, 0x22, 0xb6, 0x73,
    0x08, 0xbd, 0x43, 0xc9, 0x55, 0x35, 0x68, 0xee,
    0x41, 0x08, 0x48, 0xc2, 0xf2, 0x6c, 0x6d, 0x94,
    0xd5, 0x78, 0x2d, 0xfe, 0x59, 0xc9, 0x82, 0xd0,
    0x34, 0x91, 0x1e, 0xbc, 0x6e, 0x8e, 0x99, 0x3c,
    0x28, 0x15, 0x84, 0xb0, 0x9b, 0xed, 0xef, 0xe2,
    0xc8, 0xe4, 0xb8, 0xfa, 0xb9, 0xc3, 0x0a, 0xd7,
    0xec, 0x5c, 0x62, 0xd2, 0x93, 0x92, 0x30, 0x4d,
    0x0b, 0xc0, 0xc9, 0x5d, 0x4e, 0x78, 0xdf, 0x14,
    0x22, 0x13, 0xeb, 0x6e, 0x86, 0x71, 0x50, 0x06,
    0x06, 0x1c, 0x39, 0x01, 0xf8, 0x3a, 0x3a, 0x5a,
    0xc0, 0x6d, 0xd1, 0x83, 0x49, 0x27, 0xef, 0x49,
    0x90, 0x85, 0x69, 0xe1, 0xdb, 0x7d, 0x99, 0xec,
    0x0b, 0xd1, 0xe1, 0xe7, 0x03, 0x87, 0xdd, 0xae,
    0x64, 0xe5, 0xc5, 0x6c, 0xcd, 0xce, 0xb4, 0xac,
    0x7a, 0x53, 0x47, 0x9b, 0xb7, 0x8f, 0x51, 0xa9,
    0xda, 0xbc, 0x26, 0x4e, 0x9b, 0xb8, 0xd1, 0x94,
    0x5e, 0xb3, 0x60, 0x9b, 0xe5, 0x99, 0xd2, 0x30,
    0x0b, 0xfe, 0x92, 0x72, 0x6b, 0xdc, 0x9b, 0xa4,
    0xdc, 0xbd, 0x9b, 0x1c, 0x96, 0x11, 0xdc, 0x9f,
    0x42, 0xe1, 0x68, 0x6c, 0xd3, 0x9b, 0x97, 0xa9,
    0xb9, 0x10, 0xe0, 0xc2,

    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    0x2b, 0xbe, 0x57, 0xe5, 0x2b, 0x4d, 0xec, 0xb3,
    0xd5, 0x63, 0x4a, 0xca, 0xee, 0xdd, 0xb9, 0xb5,
    0xab, 0xa6, 0xff, 0x8b, 0x0f, 0x19, 0x74, 0x0a,
    0x81, 0xc5, 0x46, 0xa1, 0xcb, 0x8a, 0xb7, 0x42,
    0xb5, 0x1b, 0x15, 0x41, 0x46, 0x4c, 0xf2, 0xb0,
    0x92, 0x9e, 0xe2, 0x45, 0x5a, 0x33, 0x82, 0x14,
    0x2f, 0x2d, 0x5d, 0x55, 0xbf, 0x04, 0x61, 0x2a,
    0xde, 0x0f, 0x3d, 0x3e, 0x9c, 0xdb, 0x11, 0x31,

    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};


/*------------------------------------------------------------------*/

typedef struct
{
    ubyte key_state[260];
    int   key_state_flag;

} ctx_arc4_struct;


/*------------------------------------------------------------------*/

extern MSTATUS
HW_CRYPTO_WIN32_init(void)
{
    MSTATUS status = OK;

#if 0
    DWORD dwFlags = CRYPT_FIRST;

    if (!(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)))
    {
        status = ERR_HARDWARE_ACCEL_INIT;
        goto exit;
    }

    for(;;)
    {
        /* for each cipher... */

        do
        {
            dwSize = sizeof(ProvEnum);

            if (!(fResult = CryptGetProvParam(hProv, PP_ENUMALGS_EX, (LPBYTE)&ProvEnum, &dwSize, dwFlags))
                break;

            dwFlags = 0;

            if (ProvEnum.aiAlgid == dwAlgId)
                fFound = TRUE;

        }
        while (!fFound);

        if (!fFound)
        {
            /* disable unsupported cipher */
        }
    }

    status = OK;

exit:
#endif

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HW_CRYPTO_WIN32_uninit(void)
{
    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HW_CRYPTO_WIN32_openChannel(enum moduleNames moduleId, sbyte4 *pHwAccelCookie)
{
    winCryptChannel*    pWinCryptChannel = NULL;
    MSTATUS             status = ERR_HARDWARE_ACCEL_OPEN_SESSION;

    DEBUG_CONSOLE_printError(DEBUG_CRYPTO, "HW_CRYPTO_WIN32_openChannel: Mocana module = ", (sbyte4)moduleId);

    *pHwAccelCookie = 0;

    if (NULL == (pWinCryptChannel = MALLOC(sizeof(winCryptChannel))) )
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pWinCryptChannel, 0x00, sizeof(winCryptChannel));

    if (!(CryptAcquireContext(&(pWinCryptChannel->hCryptProv), NULL, NULL, PROV_RSA_AES /* PROV_RSA_SCHANNEL PROV_RSA_FULL*/, CRYPT_VERIFYCONTEXT)))
    {
        DEBUG_ERROR(DEBUG_CRYPTO, "HW_CRYPTO_WIN32_openChannel: failure at line = ", __LINE__);
        goto exit;
    }

    if (!CryptImportKey(pWinCryptChannel->hCryptProv, PrivateKeyWithExponentOfOne,
                        sizeof(PrivateKeyWithExponentOfOne),
                        0, 0, &(pWinCryptChannel->hPrivateKey)))
    {
        DEBUG_ERROR(DEBUG_CRYPTO, "HW_CRYPTO_WIN32_openChannel: failure at line = ", __LINE__);
        goto exit;
    }

    *pHwAccelCookie = (sbyte4)pWinCryptChannel;
    pWinCryptChannel = NULL;

    status = OK;

exit:
    if (pWinCryptChannel)
    {
        if (pWinCryptChannel->hCryptProv)
            CryptReleaseContext(pWinCryptChannel->hCryptProv, 0);

        if (pWinCryptChannel->hPrivateKey)
            CryptDestroyKey(pWinCryptChannel->hPrivateKey);

        FREE(pWinCryptChannel);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HW_CRYPTO_WIN32_closeChannel(enum moduleNames moduleId, sbyte4 *pHwAccelCookie)
{
    winCryptChannel*    pWinCryptChannel = (winCryptChannel *)(*pHwAccelCookie);
    MSTATUS             status = OK;

    DEBUG_CONSOLE_printError(DEBUG_CRYPTO, "HW_CRYPTO_WIN32_closeChannel: Mocana module = ", (sbyte4)moduleId);

    if (pWinCryptChannel)
    {
        if (pWinCryptChannel->hCryptProv)
            CryptReleaseContext(pWinCryptChannel->hCryptProv, 0);

        if (pWinCryptChannel->hPrivateKey)
            CryptDestroyKey(pWinCryptChannel->hPrivateKey);

        FREE(pWinCryptChannel);

        *pHwAccelCookie = 0;
    }
    else
    {
        status = ERR_HARDWARE_ACCEL_CLOSE_SESSION;
    }

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
createKey(HCRYPTPROV hCryptProv, HCRYPTKEY hPrivateKey, ALG_ID dwAlgId, ubyte *pKey, DWORD keyLen, HCRYPTKEY *hSessionKey)
{
    /* derived from http://support.microsoft.com/default.aspx?scid=kb;en-us;228786 */
    LPBYTE              pbSessionBlob = NULL;
    DWORD               dwSessionBlob;
    DWORD               dwSize;
    DWORD               n;
    DWORD               dwPublicKeySize;
    DWORD               dwProvSessionKeySize;
    ALG_ID              dwPrivKeyAlg;
    LPBYTE              pbPtr;
    HCRYPTKEY           hTempKey = 0;
    MSTATUS             status = ERR_HARDWARE_ACCEL_KEY_CREATION;

    /* We have to get the key size(including padding) from an HCRYPTKEY handle.*/
    /* PP_ENUMALGS_EX contains the key size without the padding so we can't use it. */
    if (!(CryptGenKey(hCryptProv, dwAlgId, 0, &hTempKey)))
    {
        DEBUG_ERROR(DEBUG_CRYPTO, "createKey: failure at line = ", __LINE__);
        goto exit;
    }

    dwSize  = sizeof(DWORD);
    if (!(CryptGetKeyParam(hTempKey, KP_KEYLEN, (LPBYTE)&dwProvSessionKeySize, &dwSize, 0)))
    {
        DEBUG_ERROR(DEBUG_CRYPTO, "createKey: failure at line = ", __LINE__);
        goto exit;
    }

    CryptDestroyKey(hTempKey);
    hTempKey = 0;

    /* should never happen, our key is too big */
    if ((keyLen * 8) > dwProvSessionKeySize)
    {
        DEBUG_ERROR(DEBUG_CRYPTO, "createKey: failure at line = ", __LINE__);
        goto exit;
    }

    /* get private key's algorithm */
    dwSize = sizeof(ALG_ID);
    if (!(CryptGetKeyParam(hPrivateKey, KP_ALGID, (LPBYTE)&dwPrivKeyAlg, &dwSize, 0)))
    {
        DEBUG_ERROR(DEBUG_CRYPTO, "createKey: failure at line = ", __LINE__);
        goto exit;
    }

    /* get private key's length in bits */
    dwSize = sizeof(DWORD);
    if (!(CryptGetKeyParam(hPrivateKey, KP_KEYLEN, (LPBYTE)&dwPublicKeySize, &dwSize, 0)))
    {
        DEBUG_ERROR(DEBUG_CRYPTO, "createKey: failure at line = ", __LINE__);
        goto exit;
    }

    /* calculate simple blob's length */
    dwSessionBlob = (dwPublicKeySize/8) + sizeof(ALG_ID) + sizeof(BLOBHEADER);

    /* allocate simple blob buffer */
    pbSessionBlob = (LPBYTE)LocalAlloc(LPTR, dwSessionBlob);

    if (!pbSessionBlob)
    {
        DEBUG_ERROR(DEBUG_CRYPTO, "createKey: failure at line = ", __LINE__);
        goto exit;
    }

    pbPtr = pbSessionBlob;

    /* SIMPLEBLOB Format is documented in SDK */
    /* Copy header to buffer */
    ((BLOBHEADER *)pbPtr)->bType = SIMPLEBLOB;
    ((BLOBHEADER *)pbPtr)->bVersion = 2;
    ((BLOBHEADER *)pbPtr)->reserved = 0;
    ((BLOBHEADER *)pbPtr)->aiKeyAlg = dwAlgId;
    pbPtr += sizeof(BLOBHEADER);

    /* Copy private key algorithm to buffer */
    *((DWORD *)pbPtr) = dwPrivKeyAlg;
    pbPtr += sizeof(ALG_ID);

    /* Place the key material in reverse order */
    for (n = 0; n < keyLen; n++)
    {
        pbPtr[n] = pKey[keyLen-n-1];
    }

    /* 3 is for the first reserved byte after the key material + the 2 reserved bytes at the end. */
    dwSize = dwSessionBlob - (sizeof(ALG_ID) + sizeof(BLOBHEADER) + keyLen + 3);
    pbPtr += (keyLen+1);

    /* Generate random data for the rest of the buffer (except that last two bytes) */
    if (!(CryptGenRandom(hCryptProv, dwSize, pbPtr)))
    {
        DEBUG_ERROR(DEBUG_CRYPTO, "createKey: failure at line = ", __LINE__);
        goto exit;
    }

    /* make sure none of the bytes are zero */
    for (n = 0; n < dwSize; n++)
    {
        if (0 == pbPtr[n])
            pbPtr[n] = 1;
    }

    pbSessionBlob[dwSessionBlob - 2] = 2;

    if (!(CryptImportKey(hCryptProv, pbSessionBlob , dwSessionBlob, hPrivateKey, CRYPT_EXPORTABLE, hSessionKey)))
    {
        DEBUG_ERROR(DEBUG_CRYPTO, "createKey: failure at line = ", __LINE__);
        goto exit;
    }

    status = OK;

exit:
    if (hTempKey)
        CryptDestroyKey(hTempKey);

    if (pbSessionBlob)
        LocalFree(pbSessionBlob);

    return status;
}


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_AES_CIPHERS__) && defined(__AES_HARDWARE_CIPHER__))
extern BulkCtx
CreateAESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    winCryptChannel*    pWinCryptChannel = (winCryptChannel*)hwAccelCtx;
    HCRYPTKEY           hSessionKey      = 0;
    BulkCtx             result           = NULL;
    ALG_ID              aesCipher;
    MOC_UNUSED(encrypt);

    switch (keyLength)
    {
        case 16:    /* 16 * 8 = 128-bits */
        {
            aesCipher = CALG_AES_128;
            break;
        }

        case 24:    /* 24 * 8 = 192-bits */
        {
            aesCipher = CALG_AES_192;
            break;
        }

        case 32:    /* 32 * 8 = 256-bits */
        {
            aesCipher = CALG_AES_256;
            break;
        }

        default:
        {
            /* ERR_AES_BAD_KEY_LENGTH */
            goto exit;
        }
    }

    if (OK > createKey(pWinCryptChannel->hCryptProv, pWinCryptChannel->hPrivateKey, aesCipher, keyMaterial, keyLength, &hSessionKey))
        goto exit;

    result  = (BulkCtx)hSessionKey;
    hSessionKey = 0;

exit:
    if (hSessionKey)
        CryptDestroyKey(hSessionKey);

    return result;

} /* CreateAESCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
DeleteAESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    HCRYPTKEY hPubKey = (HCRYPTKEY)(*ctx);
    MSTATUS   status  = OK;
    MOC_UNUSED(hwAccelCtx);

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    hPubKey = (HCRYPTKEY)(*ctx);

    if ((hPubKey) && (CryptDestroyKey(hPubKey)))
    {
        *ctx = NULL;
        status = OK;
    }

exit:
    return status;

} /* DeleteAESCtx */


/*------------------------------------------------------------------*/

extern MSTATUS
DoAES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    HCRYPTKEY hKey   = (HCRYPTKEY)ctx;
    MSTATUS   status = OK;
    MOC_UNUSED(hwAccelCtx);

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 != (dataLength % AES_BLOCK_SIZE))
    {
        status = ERR_AES_BAD_LENGTH;
        goto exit;
    }

    /* set the iv */
    if (!CryptSetKeyParam(hKey, KP_IV, (BYTE *)iv, 0))
    {
        status = ERR_HARDWARE_ACCEL_IV_FAIL;
        goto exit;
    }

    /* setup next call's iv */
    if (!encrypt)
        DIGI_MEMCPY(iv, &(data[dataLength - AES_BLOCK_SIZE]), AES_BLOCK_SIZE);

    if (encrypt)
    {
        if (!CryptEncrypt(hKey, 0, FALSE, 0, data, (DWORD *)&dataLength, (DWORD)dataLength))
            status = ERR_AES_CIPHER_FAILED;
    }
    else
    {
        if (!CryptDecrypt(hKey, 0, FALSE, 0, data, (DWORD *)&dataLength))
            status = ERR_AES_CIPHER_FAILED;
    }

    /* setup next call's iv */
    if (encrypt)
        DIGI_MEMCPY(iv, &(data[dataLength - AES_BLOCK_SIZE]), AES_BLOCK_SIZE);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, "DoAES: cipher failed, error = ", status);
#endif

exit:
    return status;

} /* DoAES */
#endif /* (!defined(__DISABLE_AES_CIPHERS__) && defined(__AES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern BulkCtx
CreateDESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    winCryptChannel*    pWinCryptChannel = (winCryptChannel *)hwAccelCtx;
    HCRYPTKEY           hSessionKey  = 0;
    BulkCtx             result       = NULL;
    MOC_UNUSED(encrypt);

    if (DES_KEY_LENGTH != keyLength)
    {
        /* ERR_DES_BAD_KEY_LENGTH */
        goto exit;
    }

    if (OK > createKey(pWinCryptChannel->hCryptProv, pWinCryptChannel->hPrivateKey, CALG_DES, keyMaterial, keyLength, &hSessionKey))
        goto exit;

    result  = (BulkCtx)hSessionKey;
    hSessionKey = 0;

exit:
    if (hSessionKey)
        CryptDestroyKey(hSessionKey);

    return result;

} /* CreateDESCtx */
#endif /* (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern MSTATUS
DeleteDESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    HCRYPTKEY hPubKey = (HCRYPTKEY)(*ctx);
    MSTATUS   status  = OK;
    MOC_UNUSED(hwAccelCtx);

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    hPubKey = (HCRYPTKEY)(*ctx);

    if ((hPubKey) && (CryptDestroyKey(hPubKey)))
    {
        *ctx = NULL;
        status = OK;
    }

exit:
    return status;

} /* DeleteDESCtx */
#endif /* (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__))
extern MSTATUS
DoDES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    HCRYPTKEY  hKey         = (HCRYPTKEY)ctx;
    MSTATUS    status       = OK;
    MOC_UNUSED(hwAccelCtx);

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 != (dataLength % DES_BLOCK_SIZE))
    {
        status = ERR_DES_BAD_LENGTH;
        goto exit;
    }

    /* set the iv */
    if (!CryptSetKeyParam(hKey, KP_IV, (BYTE *)iv, 0))
    {
        status = ERR_HARDWARE_ACCEL_IV_FAIL;
        goto exit;
    }

    /* setup next call's iv */
    if (!encrypt)
        DIGI_MEMCPY(iv, &(data[dataLength - DES_BLOCK_SIZE]), DES_BLOCK_SIZE);

    if (encrypt)
    {
        if (!CryptEncrypt(hKey, 0, FALSE, 0, data, (DWORD *)&dataLength, (DWORD)dataLength))
            status = ERR_DES_CIPHER_FAILED;
    }
    else
    {
        if (!CryptDecrypt(hKey, 0, FALSE, 0, data, (DWORD *)&dataLength))
            status = ERR_DES_CIPHER_FAILED;
    }

    /* setup next call's iv */
    if (encrypt)
        DIGI_MEMCPY(iv, &(data[dataLength - DES_BLOCK_SIZE]), DES_BLOCK_SIZE);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, "DoDES: cipher failed, error = ", status);
#endif

exit:
    return status;

} /* DoDES */
#endif /* (defined(__ENABLE_DES_CIPHER__) && defined(__DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_3DES_CIPHERS__) && defined(__3DES_HARDWARE_CIPHER__))
extern BulkCtx
Create3DESCtx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    winCryptChannel*    pWinCryptChannel = (winCryptChannel *)hwAccelCtx;
    HCRYPTKEY           hSessionKey      = 0;
    BulkCtx             result           = NULL;
    MOC_UNUSED(encrypt);

    if (THREE_DES_KEY_LENGTH != keyLength)
    {
        /* ERR_DES_BAD_KEY_LENGTH */
        goto exit;
    }

    if (OK > createKey(pWinCryptChannel->hCryptProv, pWinCryptChannel->hPrivateKey, CALG_3DES, keyMaterial, keyLength, &hSessionKey))
        goto exit;

    result  = (BulkCtx)hSessionKey;
    hSessionKey = 0;

exit:
    if (hSessionKey)
        CryptDestroyKey(hSessionKey);

    return result;

} /* Create3DESCtx */
#endif /* (!defined(__DISABLE_3DES_CIPHERS__) && defined(__3DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_3DES_CIPHERS__) && defined(__3DES_HARDWARE_CIPHER__))
extern MSTATUS
Delete3DESCtx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    HCRYPTKEY hPubKey = (HCRYPTKEY)(*ctx);
    MSTATUS   status  = OK;
    MOC_UNUSED(hwAccelCtx);

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    hPubKey = (HCRYPTKEY)(*ctx);

    if ((hPubKey) && (CryptDestroyKey(hPubKey)))
    {
        *ctx = NULL;
        status = OK;
    }

exit:
    return status;

} /* Delete3DESCtx */
#endif /* (!defined(__DISABLE_3DES_CIPHERS__) && defined(__3DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_3DES_CIPHERS__) && defined(__3DES_HARDWARE_CIPHER__))
extern MSTATUS
Do3DES(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    HCRYPTKEY  hKey         = (HCRYPTKEY)ctx;
    MSTATUS    status = OK;
    MOC_UNUSED(hwAccelCtx);

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 != (dataLength % THREE_DES_BLOCK_SIZE))
    {
        status = ERR_3DES_BAD_LENGTH;
        goto exit;
    }

    /* set the iv */
    if (!CryptSetKeyParam(hKey, KP_IV, (BYTE *)iv, 0))
    {
        status = ERR_HARDWARE_ACCEL_IV_FAIL;
        goto exit;
    }

    /* setup next call's iv */
    if (!encrypt)
        DIGI_MEMCPY(iv, &(data[dataLength - THREE_DES_BLOCK_SIZE]), THREE_DES_BLOCK_SIZE);

    if (encrypt)
    {
        if (!CryptEncrypt(hKey, 0, FALSE, 0, data, (DWORD *)&dataLength, (DWORD)dataLength))
            status = ERR_3DES_CIPHER_FAILED;
    }
    else
    {
        if (!CryptDecrypt(hKey, 0, FALSE, 0, data, (DWORD *)&dataLength))
            status = ERR_3DES_CIPHER_FAILED;
    }

    /* setup next call's iv */
    if (encrypt)
        DIGI_MEMCPY(iv, &(data[dataLength - THREE_DES_BLOCK_SIZE]), THREE_DES_BLOCK_SIZE);

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, "Do3DES: cipher failed, error = ", status);
#endif

exit:
    return status;

} /* Do3DES */
#endif /* (!defined(__DISABLE_3DES_CIPHERS__) && defined(__3DES_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_ARC4_CIPHERS__) && defined(__ARC4_HARDWARE_CIPHER__))
extern BulkCtx
CreateRC4Ctx(hwAccelDescr hwAccelCtx, ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt)
{
    winCryptChannel*    pWinCryptChannel = (winCryptChannel*)hwAccelCtx;
    HCRYPTKEY           hSessionKey      = 0;
    BulkCtx             result           = NULL;
    MOC_UNUSED(encrypt);

    if (OK > createKey(pWinCryptChannel->hCryptProv, pWinCryptChannel->hPrivateKey, CALG_RC4, keyMaterial, keyLength, &hSessionKey))
        goto exit;

    result  = (BulkCtx)hSessionKey;
    hSessionKey = 0;

exit:
    if (hSessionKey)
        CryptDestroyKey(hSessionKey);

    return result;

} /* CreateRC4Ctx */
#endif /* (!defined(__DISABLE_ARC4_CIPHERS__) && defined(__ARC4_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_ARC4_CIPHERS__) && defined(__ARC4_HARDWARE_CIPHER__))
extern MSTATUS
DeleteRC4Ctx(hwAccelDescr hwAccelCtx, BulkCtx* ctx)
{
    HCRYPTKEY hPubKey = (HCRYPTKEY)(*ctx);
    MSTATUS   status  = OK;
    MOC_UNUSED(hwAccelCtx);

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    hPubKey = (HCRYPTKEY)(*ctx);

    if ((hPubKey) && (CryptDestroyKey(hPubKey)))
    {
        *ctx = NULL;
        status = OK;
    }

exit:
    return status;

} /* DeleteRC4Ctx */
#endif /* (!defined(__DISABLE_ARC4_CIPHERS__) && defined(__ARC4_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_ARC4_CIPHERS__) && defined(__ARC4_HARDWARE_CIPHER__))
extern MSTATUS
DoRC4(hwAccelDescr hwAccelCtx, BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv)
{
    HCRYPTKEY  hKey         = (HCRYPTKEY)ctx;
    MSTATUS    status = OK;
    MOC_UNUSED(hwAccelCtx);
    MOC_UNUSED(encrypt);
    MOC_UNUSED(iv);

    if (NULL == ctx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* encrypt and decrypt should be the same for RC4 */
    if (!CryptEncrypt(hKey, 0, FALSE, 0, data, (DWORD *)&dataLength, (DWORD)dataLength))
        status = ERR_3DES_CIPHER_FAILED;

#ifdef __ENABLE_ALL_DEBUGGING__
    if (OK > status)
        DEBUG_ERROR(DEBUG_SSL_TRANSPORT, "DoRC4: cipher failed, error = ", status);
#endif

exit:
    return status;

} /* DoRC4 */
#endif /* (!defined(__DISABLE_ARC4_CIPHERS__) && defined(__ARC4_HARDWARE_CIPHER__)) */


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_acquireContext(randomContext **pp_randomContext)
{
    return OK;
}
#endif /* __DISABLE_DIGICERT_RNG__ */


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_releaseContext(randomContext **pp_randomContext)
{
    return OK;
}
#endif /* __DISABLE_DIGICERT_RNG__ */


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_addEntropyBit(randomContext *pRandomContext, ubyte entropyBit)
{
    /* do nothing */
    return OK;
}
#endif /* __DISABLE_DIGICERT_RNG__ */


/*------------------------------------------------------------------*/

#ifdef __DISABLE_DIGICERT_RNG__
extern MSTATUS
RANDOM_numberGenerator(randomContext *pRandomContext, ubyte *pBuffer, sbyte4 bufSize)
{
    return OK;
}
#endif /* __DISABLE_DIGICERT_RNG__ */


/*------------------------------------------------------------------*/

#ifdef __PRIME_GEN_HARDWARE__
extern MSTATUS
PRIME_generateSizedPrime(randomContext *pRandomContext, vlong **ppRetPrime, ubyte4 numBitsLong)
{
    return OK;

} /* PRIME_generateSizedPrime */
#endif /* __PRIME_GEN_HARDWARE__ */


/*------------------------------------------------------------------*/

#ifdef __MD5_ONE_STEP_HARDWARE_HASH__
extern MSTATUS
MD5_completeDigest(hwAccelDescr hwAccelCtx, ubyte *pData, ubyte4 dataLen, ubyte *pMdOutput)
{
    return OK;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __SHA1_ONE_STEP_HARDWARE_HASH__
extern MSTATUS
SHA1_completeDigest(hwAccelDescr hwAccelCtx, ubyte *pData, ubyte4 dataLen, ubyte *pShaOutput)
{
    return OK;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __HMAC_MD5_HARDWARE_HASH__
extern MSTATUS
HMAC_MD5(hwAccelDescr hwAccelCtx, ubyte* key, sbyte4 keyLen, ubyte* text, sbyte4 textLen,
         ubyte* textOpt, sbyte4 textOptLen, ubyte result[MD5_DIGESTSIZE])
{
    return OK;
}
#endif /* __HMAC_MD5_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __HMAC_SHA1_HARDWARE_HASH__
/* compute the HMAC output using SHA1 the textOpt can be null */
extern MSTATUS
HMAC_SHA1(hwAccelDescr hwAccelCtx, ubyte* key, sbyte4 keyLen, ubyte* text, sbyte4 textLen,
          ubyte* textOpt, sbyte4 textOptLen, ubyte result[SHA_HASH_RESULT_SIZE])
{
    return OK;

} /* HMAC_SHA1 */
#endif /* __HMAC_SHA1_HARDWARE_HASH__ */


/*------------------------------------------------------------------*/

#ifdef __VLONG_MOD_OPERATOR_HARDWARE_ACCELERATOR__
extern MSTATUS
VLONG_operatorModSignedVlongs(hwAccelDescr hwAccelCtx, vlong* a, vlong* n, vlong **ppC)
{
    return OK;

} /* VLONG_operatorModSignedVlongs */
#endif


/*------------------------------------------------------------------*/

#ifdef __VLONG_MODINV_OPERATOR_HARDWARE_ACCELERATOR__
extern MSTATUS
VLONG_modularInverse(hwAccelDescr hwAccelCtx, vlong *b, vlong *n, vlong **ppT)
{
    return OK;

} /* VLONG_modularInverse */
#endif


/*------------------------------------------------------------------*/

#ifdef __VLONG_MODEXP_OPERATOR_HARDWARE_ACCELERATOR__
extern MSTATUS
VLONG_modexp(hwAccelDescr hwAccelCtx, vlong *a, vlong *e, vlong *n, vlong **ppResult)
{
    return OK;

} /* VLONG_modexp */
#endif

#endif /* (defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) && defined(__ENABLE_WIN32_HARDWARE_ACCEL__)) */



