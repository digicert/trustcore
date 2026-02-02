/*
 * crypto_interface_ecc_unit_test.c
 *
 * Expanded Unit test for ECC
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
#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/ecc.h"
#include "../../crypto_interface/crypto_interface_priv.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/mocasymkeys/mocsw/commonecc.h"
#include "../../asn1/parseasn1.h"
#include "../../asn1/mocasn1.h"
#include "../../crypto/pkcs_key.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "crypto_interface_tap_example.h"
#include "../cryptointerface.h"
#include "../../crypto/mocasymkeys/tap/ecctap.h"
#include "../../crypto_interface/crypto_interface_ecc_tap.h"
#include "../../crypto_interface/crypto_interface_tap.h"
#endif

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

#define __DEBUG_VECTORS__

#ifdef __DEBUG_VECTORS__
#include <stdio.h>

static int gCurrentVector = 0;
static int gTestCurve = 0;

/* Use these macros to output which vector number is failing.
 Make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) if ( UNITTEST_STATUS(b, c) ) {printf("for vector index %d in gTestVector_p%d\n", gCurrentVector, gTestCurve); retVal++;}
#define UNITTEST_VECTOR_INT( b, c, d) if ( UNITTEST_INT(b, c, d) ) {printf("for vector index %d in gTestVector_p%d\n", gCurrentVector, gTestCurve); retVal++;}

#else

/* Still make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) retVal += UNITTEST_STATUS(b, c);
#define UNITTEST_VECTOR_INT( b, c, d) retVal += UNITTEST_INT(b, c, d);

#endif

typedef enum TestVectorType
{
    testKeys,
    verifyKey,
    generateKeyPair,
    sign,
    signMsg,
    verify,
    verifyMsg,
    sharedSecret

} TestVectorType;

typedef struct TestVector
{
    char *pInput1;
    char *pInput2;
    char *pInput3;
    char *pInput4;
    char *pInput5;
    sbyte4 input6;
    TestVectorType type;

} TestVector;

#ifndef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__

#ifdef __ENABLE_DIGICERT_ECC_P192__
#include "primeec_data_192_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P224__
#include "primeec_data_224_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P256__
#include "primeec_data_256_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P384__
#include "primeec_data_384_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P521__
#include "primeec_data_521_inc.h"
#endif

#else

#ifdef __ENABLE_DIGICERT_ECC_P192_MBED__
#include "primeec_data_192_inc.h"
#endif

#ifdef __ENABLE_DIGICERT_ECC_P224_MBED__
#include "primeec_data_224_inc.h"
#endif

#if defined(__ENABLE_DIGICERT_ECC_P256_MBED__) || defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
#include "primeec_data_256_inc.h"
#endif

#ifdef __ENABLE_DIGICERT_ECC_P384_MBED__
#include "primeec_data_384_inc.h"
#endif

#ifdef __ENABLE_DIGICERT_ECC_P521_MBED__
#include "primeec_data_521_inc.h"
#endif

#endif /* __ENABLE_DIGICERT_MBED_KEY_OPERATORS__ */

/* Global variables so the "fake RNG" callback method will have access as what to return */
static ubyte gpNonce[72] = {0};
static ubyte4 gNonceLen = 0;

/*
 Method to copy a byte array representing a Big Endian integer to the gpNonce
 global variable in the correct format for creation of a PFE form point.
 */
static MSTATUS copyRNGdata(ubyte *pRngData, ubyte4 rngDataLen, ubyte4 curveWords){

    MSTATUS status = OK;
    int i;
#ifdef __ENABLE_DIGICERT_64_BIT__
    const ubyte4 wordSize = 8;
#else
    const ubyte4 wordSize = 4;
#endif

#ifdef MOC_BIG_ENDIAN
    ubyte swap = 0x00;
    int j;
#endif

    /* The ECC code adds 1 to the raw result of the RNG, so subtract one here */
    /* in order to compensate, start with the last byte. */
    i = rngDataLen - 1;
    pRngData[i]--;

    /* keep borrowing if needbe */
    while (0xFF == pRngData[i] && i > 0)
    {
        i--;
        pRngData[i]--;
    }

    /* copy the rng data to the global variable so the callback method has access to it
       it'll be copied into a PFE directly so take into account word size and endianness */

    /* First just reverse to Little Endian bytewise and zero pad the end */

    for (i = 0; i < rngDataLen; ++i)
    {
        gpNonce[i] = pRngData[rngDataLen - i - 1];
    }

    if (rngDataLen < (ubyte4) (curveWords * wordSize))
    {
        /* zero pad */
        status = DIGI_MEMSET(gpNonce + rngDataLen, 0x00, curveWords * wordSize - rngDataLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            return status;
    }

    /* if platform stores a pf_unit Little Endian then we are done, else ... */

#ifdef MOC_BIG_ENDIAN

    /* reverse each pf_unit that will be formed from within the byte array gpNonce */

    for (i = 0; i < curveWords; ++i)
    {
        for (j = 0; j < wordSize/2; ++j)
        {
            swap = gpNonce[wordSize*i + j];
            gpNonce[wordSize*i + j] = gpNonce[wordSize*i + wordSize - j - 1];
            gpNonce[wordSize*i + wordSize - j - 1] = swap;
        }
    }
#endif

    /* set the global length */
    gNonceLen = (ubyte4) (curveWords * wordSize);

    return status;
}

#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
static MSTATUS copyRNGdataMBed(ubyte *pRngData, ubyte4 rngDataLen, ubyte4 curveId)
{
    MSTATUS status;
    ubyte4 elementByteLen = 24; /* P192 */
    ubyte4 shift = 0;

    switch(curveId)
    {
        case cid_EC_P224:

            elementByteLen = 28;
            break;

        case cid_EC_P256:

            elementByteLen = 32;
            break;

        case cid_EC_P384:

            elementByteLen = 48;
            break;

        case cid_EC_P521:

            elementByteLen = 66;
            shift = 7;
            break;
    }

    /* We need an elementByteLen Big Endian integer */
    if (rngDataLen < elementByteLen)
    {
        status = DIGI_MEMSET(gpNonce, 0x00, elementByteLen - rngDataLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            return status;
    }
    else if (rngDataLen > elementByteLen)
    {   /* bad test vector, force error */
        UNITTEST_INT(__MOC_LINE__, -1, 0);
        return -1;
    }

    status = DIGI_MEMCPY(gpNonce + elementByteLen - rngDataLen, pRngData, rngDataLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        return status;

    /* For P521 the mbed operator will shift the nonce right 7 bits, so we pre-shift left 7 bits*/
    if (shift)
    {
        int i;

        for (i = 0; i < elementByteLen - 1; ++i)
        {
            gpNonce[i] = (gpNonce[i] << shift) | (gpNonce[i+1] >> (8-shift));
        }
        gpNonce[elementByteLen - 1] <<= shift;
    }

    gNonceLen = elementByteLen;

    return status;
}
#endif /* __ENABLE_DIGICERT_MBED_KEY_OPERATORS__ */

/*
 A fake random number generator callBack method. It just write to the buffer
 the value of the global variable gpNonce. gpNonce is big enough for all curves,
 but we need to take into account the Endianness of the platforms pf_unit type.
 */
static sbyte4 rngCallback(void *rngFunArg, ubyte4 length, ubyte *pBuffer)
{
    MSTATUS status = OK;
    byteBoolean *pUsed = (byteBoolean *) rngFunArg;

    if ( (NULL != pUsed) && (TRUE == *pUsed) )
    {
        status = RANDOM_numberGenerator(g_pRandomContext, pBuffer, length);
        UNITTEST_STATUS(__MOC_LINE__, status);
    }
    else
    {
        if (length > gNonceLen) /* uh oh, force error */
        {
            UNITTEST_STATUS(__MOC_LINE__, -1);
            return -1;
        }

        status = DIGI_MEMCPY(pBuffer, gpNonce, length);
        UNITTEST_STATUS(__MOC_LINE__, status);

        if (NULL != pUsed)
            *pUsed = TRUE;
    }

    return (sbyte4) status;
}


static int buildEccDeserializationFormat1 (
    ubyte *pPriv,
    ubyte4 privLen,
    ubyte *pPub,
    ubyte4 pubLen,
    ubyte **ppBuffer,
    ubyte4 *pBufferLen
    )
{
    MSTATUS status;
    ubyte version = 0;
    ubyte4 curveId = 0;
    ubyte4 curveOidLen = 0;
    ubyte pCurveOid[MOP_MAX_ECC_CURVE_OID_LEN];
    ubyte *pPubVal = NULL;
    MAsn1Element *pArray = NULL;
    MAsn1TypeAndCount pTemplate[5] = {
        { MASN1_TYPE_SEQUENCE, 4 },
            { MASN1_TYPE_INTEGER, 0 },
            { MASN1_TYPE_OCTET_STRING, 0 },
            { MASN1_TYPE_OID | MASN1_EXPLICIT, 0 },
            { MASN1_TYPE_BIT_STRING | MASN1_EXPLICIT | 1, 0 },
    };

    status = MAsn1CreateElementArray (
        pTemplate, 5, MASN1_FNCT_ENCODE, NULL, &pArray);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    switch(pubLen)
    {
        case 49:
            curveId = cid_EC_P192;
            break;

        case 57:
            curveId = cid_EC_P224;
            break;

        case 65:
            curveId = cid_EC_P256;
            break;

        case 97:
            curveId = cid_EC_P384;
            break;

        case 133:
            curveId = cid_EC_P521;
            break;

        default:
        {
            status = ERR_INVALID_ARG;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    status = GetCurveOid(curveId, pCurveOid, MOP_MAX_ECC_CURVE_OID_LEN, &curveOidLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&pPubVal, pubLen + 1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pPubVal[0] = 0;

    status = DIGI_MEMCPY(pPubVal + 1, pPub, pubLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    version = 1;
    pArray[1].value.pValue = &version;
    pArray[1].valueLen = 1;
    pArray[1].state = MASN1_STATE_SET_COMPLETE;
    pArray[2].value.pValue = pPriv;
    pArray[2].valueLen = privLen;
    pArray[2].state = MASN1_STATE_SET_COMPLETE;
    pArray[3].value.pValue = pCurveOid + 2;
    pArray[3].valueLen = curveOidLen - 2;
    pArray[3].state = MASN1_STATE_SET_COMPLETE;
    pArray[4].value.pValue = pPubVal;
    pArray[4].valueLen = pubLen + 1;
    pArray[4].state = MASN1_STATE_SET_COMPLETE;

    status = MAsn1Encode (pArray, NULL, 0, pBufferLen);
    if (OK == status)
      status = ERR_INVALID_INPUT;
    if (ERR_BUFFER_TOO_SMALL != status)
      goto exit;

    status = DIGI_MALLOC ((void **)ppBuffer, *pBufferLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = MAsn1Encode (pArray, *ppBuffer, *pBufferLen, pBufferLen);
    UNITTEST_STATUS(__MOC_LINE__, status);

exit:

    if (NULL != pArray)
    {
        MAsn1FreeElementArray (&pArray);
    }
    if (NULL != pPubVal)
    {
        DIGI_FREE((void **)&pPubVal);
    }

    return status;
}

static int buildEccDeserializationFormat2 (
    ubyte *pPriv,
    ubyte4 privLen,
    ubyte *pPub,
    ubyte4 pubLen,
    ubyte **ppBuffer,
    ubyte4 *pBufferLen
    )
{
    MSTATUS status;
    ubyte version = 0;
    ubyte4 curveId = 0;
    ubyte4 curveOidLen = 0;
    ubyte pCurveOid[MOP_MAX_ECC_CURVE_OID_LEN];
    ubyte pKeyOid[MOP_ECC_KEY_OID_LEN] = {MOP_ECC_KEY_OID};
    ubyte *pPubVal = NULL;
    ubyte *pKeyEncoding = NULL;
    ubyte4 keyEncodingLen = 0;
    ubyte *pAlgId = NULL;
    ubyte4 algIdLen = 0;
    MAsn1Element *pArray = NULL;
    MAsn1Element *pAlgArray = NULL;
    MAsn1TypeAndCount pTemplate[5] = {
        { MASN1_TYPE_SEQUENCE, 4 },
            { MASN1_TYPE_INTEGER, 0 },
            { MASN1_TYPE_OCTET_STRING, 0 },
            { MASN1_TYPE_OID | MASN1_EXPLICIT, 0 },
            { MASN1_TYPE_BIT_STRING | MASN1_EXPLICIT | 1, 0 },
    };
    MAsn1TypeAndCount pAlgTemplate[3] = {
        { MASN1_TYPE_SEQUENCE, 2 },
            { MASN1_TYPE_OID, 0 },
            { MASN1_TYPE_OID, 0 }
    };

    status = MAsn1CreateElementArray (
        pTemplate, 5, MASN1_FNCT_ENCODE, NULL, &pArray);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    switch(pubLen)
    {
        case 49:
            curveId = cid_EC_P192;
            break;

        case 57:
            curveId = cid_EC_P224;
            break;

        case 65:
            curveId = cid_EC_P256;
            break;

        case 97:
            curveId = cid_EC_P384;
            break;

        case 133:
            curveId = cid_EC_P521;
            break;

        default:
        {
            status = ERR_INVALID_ARG;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    status = GetCurveOid(curveId, pCurveOid, MOP_MAX_ECC_CURVE_OID_LEN, &curveOidLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&pPubVal, pubLen + 1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pPubVal[0] = 0;

    status = DIGI_MEMCPY(pPubVal + 1, pPub, pubLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    version = 1;
    pArray[1].value.pValue = &version;
    pArray[1].valueLen = 1;
    pArray[1].state = MASN1_STATE_SET_COMPLETE;
    pArray[2].value.pValue = pPriv;
    pArray[2].valueLen = privLen;
    pArray[2].state = MASN1_STATE_SET_COMPLETE;
    pArray[3].value.pValue = pCurveOid + 2;
    pArray[3].valueLen = curveOidLen - 2;
    pArray[3].state = MASN1_STATE_SET_COMPLETE;
    pArray[4].value.pValue = pPubVal;
    pArray[4].valueLen = pubLen + 1;
    pArray[4].state = MASN1_STATE_SET_COMPLETE;

    status = MAsn1Encode (pArray, NULL, 0, &keyEncodingLen);
    if (OK == status)
      status = ERR_INVALID_INPUT;
    if (ERR_BUFFER_TOO_SMALL != status)
      goto exit;

    status = DIGI_MALLOC ((void **)&pKeyEncoding, keyEncodingLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = MAsn1Encode (pArray, pKeyEncoding, keyEncodingLen, &keyEncodingLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = MAsn1CreateElementArray (
        pAlgTemplate, 3, MASN1_FNCT_ENCODE, NULL, &pAlgArray);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pAlgArray[1].value.pValue = pKeyOid + 2;
    pAlgArray[1].valueLen = MOP_ECC_KEY_OID_LEN - 2;
    pAlgArray[1].state = MASN1_STATE_SET_COMPLETE;
    pAlgArray[2].value.pValue = pCurveOid + 2;
    pAlgArray[2].valueLen = curveOidLen - 2;
    pAlgArray[2].state = MASN1_STATE_SET_COMPLETE;

    status = MAsn1Encode (pAlgArray, NULL, 0, &algIdLen);
    if (OK == status)
      status = ERR_INVALID_INPUT;
    if (ERR_BUFFER_TOO_SMALL != status)
      goto exit;

    status = DIGI_MALLOC ((void **)&pAlgId, algIdLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = MAsn1Encode (pAlgArray, pAlgId, algIdLen, &algIdLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_makeKeyInfo (
        TRUE, pAlgId, algIdLen, pKeyEncoding, keyEncodingLen, ppBuffer, pBufferLen);
    UNITTEST_STATUS(__MOC_LINE__, status);

exit:

    if (NULL != pArray)
    {
        MAsn1FreeElementArray (&pArray);
    }
    if (NULL != pAlgArray)
    {
        MAsn1FreeElementArray (&pAlgArray);
    }
    if (NULL != pPubVal)
    {
        DIGI_FREE((void **)&pPubVal);
    }
    if (NULL != pKeyEncoding)
    {
        DIGI_FREE((void **)&pKeyEncoding);
    }
    if (NULL != pAlgId)
    {
        DIGI_FREE((void **)&pAlgId);
    }

    return status;
}

static int buildEccDeserializationFormat3 (
    ubyte *pPriv,
    ubyte4 privLen,
    ubyte *pPub,
    ubyte4 pubLen,
    ubyte **ppBuffer,
    ubyte4 *pBufferLen
    )
{
    MSTATUS status;
    ubyte version = 0;
    ubyte4 curveId = 0;
    ubyte4 curveOidLen = 0;
    ubyte pCurveOid[MOP_MAX_ECC_CURVE_OID_LEN];
    ubyte pKeyOid[MOP_ECC_KEY_OID_LEN] = {MOP_ECC_KEY_OID};
    ubyte *pPubVal = NULL;
    ubyte *pKeyEncoding = NULL;
    ubyte4 keyEncodingLen = 0;
    ubyte *pAlgId = NULL;
    ubyte4 algIdLen = 0;
    MAsn1Element *pArray = NULL;
    MAsn1Element *pAlgArray = NULL;
    MAsn1TypeAndCount pTemplate[5] = {
        { MASN1_TYPE_SEQUENCE, 4 },
            { MASN1_TYPE_INTEGER, 0 },
            { MASN1_TYPE_OCTET_STRING, 0 },
            { MASN1_TYPE_OID | MASN1_EXPLICIT | MASN1_OPTIONAL, 0 },
            { MASN1_TYPE_BIT_STRING | MASN1_EXPLICIT | 1, 0 },
    };
    MAsn1TypeAndCount pAlgTemplate[3] = {
        { MASN1_TYPE_SEQUENCE, 2 },
            { MASN1_TYPE_OID, 0 },
            { MASN1_TYPE_OID, 0 }
    };

    status = MAsn1CreateElementArray (
        pTemplate, 5, MASN1_FNCT_ENCODE, NULL, &pArray);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    switch(pubLen)
    {
        case 49:
            curveId = cid_EC_P192;
            break;

        case 57:
            curveId = cid_EC_P224;
            break;

        case 65:
            curveId = cid_EC_P256;
            break;

        case 97:
            curveId = cid_EC_P384;
            break;

        case 133:
            curveId = cid_EC_P521;
            break;

        default:
        {
            status = ERR_INVALID_ARG;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    status = GetCurveOid(curveId, pCurveOid, MOP_MAX_ECC_CURVE_OID_LEN, &curveOidLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&pPubVal, pubLen + 1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pPubVal[0] = 0;

    status = DIGI_MEMCPY(pPubVal + 1, pPub, pubLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    version = 1;
    pArray[1].value.pValue = &version;
    pArray[1].valueLen = 1;
    pArray[1].state = MASN1_STATE_SET_COMPLETE;
    pArray[2].value.pValue = pPriv;
    pArray[2].valueLen = privLen;
    pArray[2].state = MASN1_STATE_SET_COMPLETE;
    pArray[4].value.pValue = pPubVal;
    pArray[4].valueLen = pubLen + 1;
    pArray[4].state = MASN1_STATE_SET_COMPLETE;

    status = MAsn1Encode (pArray, NULL, 0, &keyEncodingLen);
    if (OK == status)
      status = ERR_INVALID_INPUT;
    if (ERR_BUFFER_TOO_SMALL != status)
      goto exit;

    status = DIGI_MALLOC ((void **)&pKeyEncoding, keyEncodingLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = MAsn1Encode (pArray, pKeyEncoding, keyEncodingLen, &keyEncodingLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = MAsn1CreateElementArray (
        pAlgTemplate, 3, MASN1_FNCT_ENCODE, NULL, &pAlgArray);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pAlgArray[1].value.pValue = pKeyOid + 2;
    pAlgArray[1].valueLen = MOP_ECC_KEY_OID_LEN - 2;
    pAlgArray[1].state = MASN1_STATE_SET_COMPLETE;
    pAlgArray[2].value.pValue = pCurveOid + 2;
    pAlgArray[2].valueLen = curveOidLen - 2;
    pAlgArray[2].state = MASN1_STATE_SET_COMPLETE;

    status = MAsn1Encode (pAlgArray, NULL, 0, &algIdLen);
    if (OK == status)
      status = ERR_INVALID_INPUT;
    if (ERR_BUFFER_TOO_SMALL != status)
      goto exit;

    status = DIGI_MALLOC ((void **)&pAlgId, algIdLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = MAsn1Encode (pAlgArray, pAlgId, algIdLen, &algIdLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_makeKeyInfo (
        TRUE, pAlgId, algIdLen, pKeyEncoding, keyEncodingLen, ppBuffer, pBufferLen);
    UNITTEST_STATUS(__MOC_LINE__, status);

exit:

    if (NULL != pArray)
    {
        MAsn1FreeElementArray (&pArray);
    }
    if (NULL != pAlgArray)
    {
        MAsn1FreeElementArray (&pAlgArray);
    }
    if (NULL != pPubVal)
    {
        DIGI_FREE((void **)&pPubVal);
    }
    if (NULL != pKeyEncoding)
    {
        DIGI_FREE((void **)&pKeyEncoding);
    }
    if (NULL != pAlgId)
    {
        DIGI_FREE((void **)&pAlgId);
    }

    return status;
}

static int buildEccDeserializationFormat4 (
    ubyte *pPriv,
    ubyte4 privLen,
    ubyte *pPub,
    ubyte4 pubLen,
    ubyte **ppBuffer,
    ubyte4 *pBufferLen
    )
{
    MSTATUS status;
    ubyte version = 0;
    ubyte4 curveId = 0;
    ubyte4 curveOidLen = 0;
    ubyte pCurveOid[MOP_MAX_ECC_CURVE_OID_LEN];
    ubyte pKeyOid[MOP_ECC_KEY_OID_LEN] = {MOP_ECC_KEY_OID};
    ubyte *pPubVal = NULL;
    ubyte *pKeyEncoding = NULL;
    ubyte4 keyEncodingLen = 0;
    ubyte *pAlgId = NULL;
    ubyte4 algIdLen = 0;
    MAsn1Element *pArray = NULL;
    MAsn1Element *pAlgArray = NULL;
    MAsn1TypeAndCount pTemplate[5] = {
        { MASN1_TYPE_SEQUENCE, 4 },
            { MASN1_TYPE_INTEGER, 0 },
            { MASN1_TYPE_OCTET_STRING, 0 },
            { MASN1_TYPE_OID | MASN1_EXPLICIT, 0 },
            { MASN1_TYPE_BIT_STRING | MASN1_EXPLICIT | 1, 0 },
    };
    MAsn1TypeAndCount pAlgTemplate[3] = {
        { MASN1_TYPE_SEQUENCE, 2 },
            { MASN1_TYPE_OID, 0 },
            { MASN1_TYPE_NULL, 0 }
    };

    status = MAsn1CreateElementArray (
        pTemplate, 5, MASN1_FNCT_ENCODE, NULL, &pArray);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    switch(pubLen)
    {
        case 49:
            curveId = cid_EC_P192;
            break;

        case 57:
            curveId = cid_EC_P224;
            break;

        case 65:
            curveId = cid_EC_P256;
            break;

        case 97:
            curveId = cid_EC_P384;
            break;

        case 133:
            curveId = cid_EC_P521;
            break;

        default:
        {
            status = ERR_INVALID_ARG;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }

    status = GetCurveOid(curveId, pCurveOid, MOP_MAX_ECC_CURVE_OID_LEN, &curveOidLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **)&pPubVal, pubLen + 1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pPubVal[0] = 0;

    status = DIGI_MEMCPY(pPubVal + 1, pPub, pubLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    version = 1;
    pArray[1].value.pValue = &version;
    pArray[1].valueLen = 1;
    pArray[1].state = MASN1_STATE_SET_COMPLETE;
    pArray[2].value.pValue = pPriv;
    pArray[2].valueLen = privLen;
    pArray[2].state = MASN1_STATE_SET_COMPLETE;
    pArray[3].value.pValue = pCurveOid + 2;
    pArray[3].valueLen = curveOidLen - 2;
    pArray[3].state = MASN1_STATE_SET_COMPLETE;
    pArray[4].value.pValue = pPubVal;
    pArray[4].valueLen = pubLen + 1;
    pArray[4].state = MASN1_STATE_SET_COMPLETE;

    status = MAsn1Encode (pArray, NULL, 0, &keyEncodingLen);
    if (OK == status)
      status = ERR_INVALID_INPUT;
    if (ERR_BUFFER_TOO_SMALL != status)
      goto exit;

    status = DIGI_MALLOC ((void **)&pKeyEncoding, keyEncodingLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = MAsn1Encode (pArray, pKeyEncoding, keyEncodingLen, &keyEncodingLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = MAsn1CreateElementArray (
        pAlgTemplate, 3, MASN1_FNCT_ENCODE, NULL, &pAlgArray);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pAlgArray[1].value.pValue = pKeyOid + 2;
    pAlgArray[1].valueLen = MOP_ECC_KEY_OID_LEN - 2;
    pAlgArray[1].state = MASN1_STATE_SET_COMPLETE;
    /*pAlgArray[2].value.pValue = pCurveOid + 2;
      pAlgArray[2].valueLen = curveOidLen - 2; */
    pAlgArray[2].state = MASN1_STATE_SET_COMPLETE;

    status = MAsn1Encode (pAlgArray, NULL, 0, &algIdLen);
    if (OK == status)
      status = ERR_INVALID_INPUT;
    if (ERR_BUFFER_TOO_SMALL != status)
      goto exit;

    status = DIGI_MALLOC ((void **)&pAlgId, algIdLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = MAsn1Encode (pAlgArray, pAlgId, algIdLen, &algIdLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_makeKeyInfo (
        TRUE, pAlgId, algIdLen, pKeyEncoding, keyEncodingLen, ppBuffer, pBufferLen);
    UNITTEST_STATUS(__MOC_LINE__, status);

exit:

    if (NULL != pArray)
    {
        MAsn1FreeElementArray (&pArray);
    }
    if (NULL != pAlgArray)
    {
        MAsn1FreeElementArray (&pAlgArray);
    }
    if (NULL != pPubVal)
    {
        DIGI_FREE((void **)&pPubVal);
    }
    if (NULL != pKeyEncoding)
    {
        DIGI_FREE((void **)&pKeyEncoding);
    }
    if (NULL != pAlgId)
    {
        DIGI_FREE((void **)&pAlgId);
    }

    return status;
}

static int testEccDeserializationFormat(ECCKey *pKey, ubyte *pSerial, ubyte4 serialLen, ubyte testPkcs8)
{
    MSTATUS status;
    byteBoolean cmp = FALSE;
    AsymmetricKey asymKey = {0};

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pSerial, serialLen, NULL, &asymKey);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey, asymKey.key.pECC, &cmp);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (TRUE != cmp)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (TRUE == testPkcs8)
    {
        status = PKCS_getPKCS8KeyEx ( MOC_HW(gpHwAccelCtx)
            (const ubyte *)pSerial, serialLen, NULL, 0, &asymKey);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey, asymKey.key.pECC, &cmp);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        if (TRUE != cmp)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
        }

        status = CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

exit:

    if (OK != status)
    {
        CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
    }
    if (NULL != pSerial)
    {
        DIGI_FREE((void **)&pSerial);
    }

    return status;
}

static int testEccDeserializationFormats(ubyte4 curveId)
{
    MSTATUS status = OK;
    byteBoolean cmp = FALSE;
    ECCKey *pKey = NULL;
    AsymmetricKey asymKey;
    MEccKeyTemplate keyTemplate = { 0 };
    ubyte *pSerial = NULL;
    ubyte4 serialLen = 0;

    status = EC_generateKeyPairAlloc(MOC_ECC(gpHwAccelCtx) curveId, &pKey, RANDOM_rngFun, g_pRandomContext);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) pKey, &keyTemplate, MOC_GET_PRIVATE_KEY_DATA);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = buildEccDeserializationFormat1 (
        keyTemplate.pPrivateKey, keyTemplate.privateKeyLen, keyTemplate.pPublicKey,
        keyTemplate.publicKeyLen, &pSerial, &serialLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = testEccDeserializationFormat(pKey, pSerial, serialLen, FALSE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = buildEccDeserializationFormat2 (
        keyTemplate.pPrivateKey, keyTemplate.privateKeyLen, keyTemplate.pPublicKey,
        keyTemplate.publicKeyLen, &pSerial, &serialLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = testEccDeserializationFormat(pKey, pSerial, serialLen, TRUE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = buildEccDeserializationFormat3 (
        keyTemplate.pPrivateKey, keyTemplate.privateKeyLen, keyTemplate.pPublicKey,
        keyTemplate.publicKeyLen, &pSerial, &serialLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = testEccDeserializationFormat(pKey, pSerial, serialLen, TRUE);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = buildEccDeserializationFormat4 (
        keyTemplate.pPrivateKey, keyTemplate.privateKeyLen, keyTemplate.pPublicKey,
        keyTemplate.publicKeyLen, &pSerial, &serialLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = testEccDeserializationFormat(pKey, pSerial, serialLen, TRUE);
    UNITTEST_STATUS(__MOC_LINE__, status);

exit:

    EC_freeKeyTemplate(pKey, &keyTemplate);

    if (NULL != pKey)
    {
        EC_deleteKeyEx(&pKey);
    }

    return status;
}


/*
 this serializes a private key in pkcs8 form but not within an algorithm identifier block, ie...

 SEQUENCE (4 elem)
  Integer 1
  Octet String (the private scalar)
  Object Identifier (the curve oid)
  Bit String (the public compressed key)

 pPriv is expected to be 0x00 padded to the usual curve order size in bytes. We use the pubLen to determine
 which curve the key belongs to.
 */
static int alternateSerializeKeyAlloc(ubyte *pPriv, ubyte4 privLen, ubyte *pPub, ubyte4 pubLen, ubyte **ppBuffer, ubyte4 *pBufferLen)
{
    MSTATUS status;
    int retVal = 0;
    ubyte *pBuffer = NULL;
    ubyte *pPtr = NULL;
    ubyte4 serLen;

    ubyte pOid192[MOP_ECC_CURVE_P192_OID_LEN] = {MOP_ECC_CURVE_P192_OID};
    ubyte pOid224[MOP_ECC_CURVE_P224_OID_LEN] = {MOP_ECC_CURVE_P224_OID};

    ubyte *pOid = NULL;
    ubyte4 oidLen = 0;

#define MOC_ECC_PUBLEN_P192 49
#define MOC_ECC_PUBLEN_P224 57
#define MOC_ECC_PUBLEN_P256 65
#define MOC_ECC_PUBLEN_P384 97
#define MOC_ECC_PUBLEN_P521 133

    switch (pubLen)
    {
        case MOC_ECC_PUBLEN_P192:

            oidLen = MOP_ECC_CURVE_P192_OID_LEN;
            pOid = pOid192;
            break;

        case MOC_ECC_PUBLEN_P224:

            oidLen = MOP_ECC_CURVE_P224_OID_LEN;
            pOid = pOid224;
            break;

        case MOC_ECC_PUBLEN_P256:

            oidLen = MOP_ECC_CURVE_P192_OID_LEN;
            pOid = pOid192;
            pOid[oidLen - 1] = MOP_ECC_CURVE_P256_BYTE;
            break;

        case MOC_ECC_PUBLEN_P384:

            oidLen = MOP_ECC_CURVE_P224_OID_LEN;
            pOid = pOid224;
            pOid[oidLen - 1] = MOP_ECC_CURVE_P384_BYTE;
            break;

        case MOC_ECC_PUBLEN_P521:

            oidLen = MOP_ECC_CURVE_P224_OID_LEN;
            pOid = pOid224;
            pOid[oidLen - 1] = MOP_ECC_CURVE_P521_BYTE;
            break;
    }

    serLen = 14 + privLen + pubLen + oidLen;

    if (MOC_ECC_PUBLEN_P384 == pubLen)
        serLen++;
    else if (MOC_ECC_PUBLEN_P521 == pubLen)
        serLen += 3;

    status = DIGI_MALLOC((void **) &pBuffer, serLen);
    if (OK != status)
        goto exit;

    pPtr = pBuffer;
    *pPtr = 0x30;
    pPtr++;

    if (MOC_ECC_PUBLEN_P384 == pubLen || MOC_ECC_PUBLEN_P521 == pubLen)
    {
        *pPtr = 0x81;
        pPtr++;
    }

    if (MOC_ECC_PUBLEN_P384 == pubLen || MOC_ECC_PUBLEN_P521 == pubLen)
        *pPtr = (ubyte) (serLen - 3);
    else
        *pPtr = (ubyte) (serLen - 2);

    pPtr[1] = 0x02;
    pPtr[2] = 0x01;
    pPtr[3] = 0x01;
    pPtr[4] = 0x04;
    pPtr[5] = (ubyte) privLen;

    pPtr += 6;
    status = DIGI_MEMCPY(pPtr, pPriv, privLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pPtr += privLen;

    pPtr[0] = 0xa0;
    pPtr[1] = (ubyte) oidLen;

    pPtr += 2;

    status = DIGI_MEMCPY(pPtr, pOid, oidLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pPtr += oidLen;

    *pPtr = 0xa1;
    pPtr++;
    if (MOC_ECC_PUBLEN_P521 == pubLen)
    {
        *pPtr = 0x81;
        pPtr++;

        *pPtr = (ubyte) (2*privLen + 5);
        pPtr++;
    }
    else
    {
        *pPtr = (ubyte) (2*privLen + 4);
        pPtr++;
    }

    *pPtr = 0x03;
    pPtr++;
    if (MOC_ECC_PUBLEN_P521 == pubLen)
    {
        *pPtr = 0x81;
        pPtr++;
    }

    *pPtr = (ubyte) (2*privLen + 2);
    pPtr++;

    *pPtr = 0x00;
    pPtr++;

    status = DIGI_MEMCPY(pPtr, pPub, pubLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    *ppBuffer = pBuffer; pBuffer = NULL;
    *pBufferLen = serLen;

exit:

    if (NULL != pBuffer)
    {
        DIGI_FREE((void **) &pBuffer);
    }

    return retVal;
}

/*
 tests EC_setKeyParametersEx, EC_newPublicKeyFromByteString, EC_writePublicKeyToBuffer, EC_writePublicKeyToBufferAlloc
       EC_getKeyParametersAlloc, EC_cloneKeyEx, SerializeEccKeyAlloc, DeserializeEccKey, and if pKey2 != NULL EC_equalKeyEx
 */
static int testKeyMethods(ECCKey *pKey1, ECCKey *pKey2, ubyte *pPrivateKey, ubyte4 rawPrivLen, ubyte *pPublicKey, ubyte4 pubLen, byteBoolean expectedEquality)
{
    MSTATUS status = OK;
    int retVal = 0;
    byteBoolean result;
    sbyte4 compare;
    ubyte4 curveId;

    ubyte pPaddedPriv[66] = {0}; /* big enough for any curve */
    ubyte4 expectedPrivLen;

    ECCKey *pNewKey = NULL;
    MEccKeyTemplate template = {0};
    ubyte *pBuffer = NULL;
    ubyte4 bufLen;

    /* SerializeEccKeyAlloc and DeserializeEccKey is tested through an AsymmetricKey and function pointer to KeySerializeEcc */
    AsymmetricKey asymKey1 = {0};
    AsymmetricKey asymKey2 = {0};
    MKeySerialize pSupported[1] =
    {
        KeySerializeEcc
    };

    status = EC_getCurveIdFromKey(pKey1, &curveId);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = EC_getElementByteStringLen(pKey1, &expectedPrivLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* if we have a private key, zero pad it to the correct size (for testing expected values) */
    if (NULL != pPrivateKey)
    {
        status = DIGI_MEMCPY(pPaddedPriv + expectedPrivLen - rawPrivLen, pPrivateKey, rawPrivLen);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
    }

    /*
     EC_setKeyParametersEx already called for pKey1 since the vectors for these tests
     all have public keys. We test the other methods to confirm we set the correct values.

     Test EC_newPublicKeyFromByteString
     */
    status = EC_newPublicKeyFromByteString(MOC_ECC(gpHwAccelCtx) curveId, &pNewKey, pPublicKey, pubLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Compare via EC_equalKeyEx which only compares public keys */
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pNewKey, pKey1, &result);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) result, (int) TRUE);

    /* Test EC_writePublicKeyToBufferAlloc */
    status = EC_writePublicKeyToBufferAlloc(MOC_ECC(gpHwAccelCtx) pNewKey, &pBuffer, &bufLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, bufLen, pubLen);

    /* Compare to the public key, note this checks the validity of the encoding since pPublicKey is encoded too with 0x04 start */
    status = DIGI_MEMCMP(pBuffer, pPublicKey, pubLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

    /* Zero the buffer for the next test */
    status = DIGI_MEMSET(pBuffer, 0x00, bufLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Test EC_writePublicKeyToBuffer */
    status = EC_writePublicKeyToBuffer(MOC_ECC(gpHwAccelCtx) pNewKey, pBuffer, bufLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = DIGI_MEMCMP(pBuffer, pPublicKey, pubLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

    /* free nNewKey and pBuffer for future tests */
    if (NULL != pNewKey)
    {
        status = EC_deleteKeyEx(&pNewKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pBuffer)
    {
        status = DIGI_FREE((void **) &pBuffer);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    /* Test EC_getKeyParametersAlloc for a private key (if applicable) and the again for public keys. */
    if (NULL != pPrivateKey)
    {
        status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) pKey1, &template, MOC_GET_PRIVATE_KEY_DATA);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        /* Compare the parameters */
        UNITTEST_VECTOR_INT(__MOC_LINE__, template.privateKeyLen, expectedPrivLen);
        UNITTEST_VECTOR_INT(__MOC_LINE__, template.publicKeyLen, pubLen);

        status = DIGI_MEMCMP(template.pPrivateKey, pPaddedPriv, expectedPrivLen, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

        status = DIGI_MEMCMP(template.pPublicKey, pPublicKey, pubLen, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

        /* free pTemplate so we can test again with MOC_GET_PUBLIC_KEY_DATA */
        status = EC_freeKeyTemplate(pKey1, &template);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) pKey1, &template, MOC_GET_PUBLIC_KEY_DATA);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Compare the parameters */
    UNITTEST_VECTOR_INT(__MOC_LINE__, template.publicKeyLen, pubLen);

    status = DIGI_MEMCMP(template.pPublicKey, pPublicKey, pubLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

    /* private key should not be set */
    UNITTEST_VECTOR_INT(__MOC_LINE__, template.privateKeyLen, 0);
    if (NULL != template.pPrivateKey)
    {   /* force error */
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, -1);
    }

    /* Now test EC_cloneKeyEx */
    status = EC_cloneKeyEx(MOC_ECC(gpHwAccelCtx) &pNewKey, pKey1);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pNewKey, pKey1, &result);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) result, (int) TRUE);

#if !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
    /* status of pKey doesn't matter since PRIMEFIELD_match won't even be linked in for mbed case */
    if (NULL != pPrivateKey)
    {
       /* Reach inside to compare private keys too if applicable */
        result = PRIMEFIELD_match(pNewKey->pCurve->pPF, pNewKey->k, pKey1->k);
        UNITTEST_VECTOR_INT(__MOC_LINE__, (int) result, (int) TRUE);
    }
#endif

    /*
     Test SerializeEccKeyAlloc and DeserializeEccKey as function pointers via AssymetricKeys
     First test format private/publicKeyInfoDer. Use the copy of pKey1 via pNewKey.
     */
    status = CRYPTO_initAsymmetricKey(&asymKey1);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&asymKey2);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_loadAsymmetricKey(&asymKey1, akt_ecc, (void **)&pNewKey);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (NULL != pPrivateKey)
        status = CRYPTO_serializeKey (MOC_ASYM(gpHwAccelCtx) &asymKey1, pSupported, 1, privateKeyInfoDer, &pBuffer, &bufLen);
    else
        status = CRYPTO_serializeKey (MOC_ASYM(gpHwAccelCtx) &asymKey1, pSupported, 1, publicKeyInfoDer, &pBuffer, &bufLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeKey (MOC_ASYM(gpHwAccelCtx) pBuffer, bufLen, pSupported, 1, &asymKey2);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Compare the (public) key of the deserialized key with the original */
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) asymKey2.key.pECC, pKey1, &result);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) result, (int) TRUE);

    /* free pBuffer for further tests */
    status = DIGI_FREE((void **) &pBuffer);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);


#if !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
    /* pKey->enabled doesn't matter since PRIMEFIELD_match won't even be linked in for mbed case */
    if (NULL != pPrivateKey)
    {
        /* Also compare the private keys (we'll have to reach inside the asymKey2) */
        status = PRIMEFIELD_getAsByteString(asymKey2.key.pECC->pCurve->pPF, asymKey2.key.pECC->k, &pBuffer, (sbyte4 *) &bufLen);
        UNITTEST_VECTOR_INT(__MOC_LINE__, bufLen, expectedPrivLen);

        status = DIGI_MEMCMP(pBuffer, pPaddedPriv, expectedPrivLen, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

        /* free pBuffer for further tests */
        status = DIGI_FREE((void **) &pBuffer);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
#endif

    /* uninit asymKey2 for further tests */
    status = CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);

    /* Now test format mocanaBlobVersion2 */

    status = CRYPTO_initAsymmetricKey(&asymKey2);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_serializeKey (MOC_ASYM(gpHwAccelCtx) &asymKey1, pSupported, 1, mocanaBlobVersion2, &pBuffer, &bufLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeKey (MOC_ASYM(gpHwAccelCtx) pBuffer, bufLen, pSupported, 1, &asymKey2);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Compare the (public) key of the deserialized key with the original */
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) asymKey2.key.pECC, pKey1, &result);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) result, (int) TRUE);

    /* free pBuffer for further tests */
    status = DIGI_FREE((void **) &pBuffer);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);

#if !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
    if (NULL != pPrivateKey)
    {
        /* Also compare the private keys (we'll have to reach inside the asymKey2) */
        status = PRIMEFIELD_getAsByteString(asymKey2.key.pECC->pCurve->pPF, asymKey2.key.pECC->k, &pBuffer, (sbyte4 *) &bufLen);
        UNITTEST_VECTOR_INT(__MOC_LINE__, bufLen, expectedPrivLen);

        status = DIGI_MEMCMP(pBuffer, pPaddedPriv, expectedPrivLen, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

        /* free pBuffer for further tests */
        status = DIGI_FREE((void **) &pBuffer);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
#endif

    /* uninit asymKey2 for further tests */
    status = CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);

    /* Now test format private/publicKeyPem */
    status = CRYPTO_initAsymmetricKey(&asymKey2);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    if (NULL != pPrivateKey)
        status = CRYPTO_serializeKey (MOC_ASYM(gpHwAccelCtx) &asymKey1, pSupported, 1, privateKeyPem, &pBuffer, &bufLen);
    else
        status = CRYPTO_serializeKey (MOC_ASYM(gpHwAccelCtx) &asymKey1, pSupported, 1, publicKeyPem, &pBuffer, &bufLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeKey (MOC_ASYM(gpHwAccelCtx) pBuffer, bufLen, pSupported, 1, &asymKey2);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Compare the (public) key of the deserialized key with the original */
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) asymKey2.key.pECC, pKey1, &result);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) result, (int) TRUE);

    /* free pBuffer for further tests */
    status = DIGI_FREE((void **) &pBuffer);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);

#if !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
    if (NULL != pPrivateKey)
    {
        /* Also compare the private keys (we'll have to reach inside the asymKey2) */
        status = PRIMEFIELD_getAsByteString(asymKey2.key.pECC->pCurve->pPF, asymKey2.key.pECC->k, &pBuffer, (sbyte4 *) &bufLen);
        UNITTEST_VECTOR_INT(__MOC_LINE__, bufLen, expectedPrivLen);

        status = DIGI_MEMCMP(pBuffer, pPaddedPriv, expectedPrivLen, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

        /* free pBuffer for further tests */
        status = DIGI_FREE((void **) &pBuffer);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
#endif

    /* uninit asymKey2 for further tests */
    status = CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);

    if (NULL != pPrivateKey)
    {
        /*
         Test deserializing the private key in its own asn1 form,
         ie not wrapped with an algorithm identifier, first serialize */
        retVal += alternateSerializeKeyAlloc(pPaddedPriv, expectedPrivLen, pPublicKey, pubLen, &pBuffer, &bufLen);

        /* Now deserialize */
        status = CRYPTO_deserializeKey (MOC_ASYM(gpHwAccelCtx) pBuffer, bufLen, pSupported, 1, &asymKey2);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        /* Compare the (public) key of the deserialized key with the original public key */
        status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) asymKey2.key.pECC, pKey1, &result);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        UNITTEST_VECTOR_INT(__MOC_LINE__, (int) result, (int) TRUE);

#if !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)

        /* free pBuffer for further tests */
        status = DIGI_FREE((void **) &pBuffer);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);

        /* Also compare the private keys (we'll have to reach inside the asymKey2) */
        status = PRIMEFIELD_getAsByteString(asymKey2.key.pECC->pCurve->pPF, asymKey2.key.pECC->k, &pBuffer, (sbyte4 *) &bufLen);
        UNITTEST_VECTOR_INT(__MOC_LINE__, bufLen, expectedPrivLen);

        status = DIGI_MEMCMP(pBuffer, pPaddedPriv, expectedPrivLen, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
#endif

        /* uninit asymKey2 for further tests */
        status = CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    /* Test deserializing nonstandard public key form, just treat the public key as a serialization */
    status = CRYPTO_deserializeKey (MOC_ASYM(gpHwAccelCtx) pPublicKey, pubLen, pSupported, 1, &asymKey2);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Compare the (public) key of the deserialized key with the original public key */
    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) asymKey2.key.pECC, pKey1, &result);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) result, (int) TRUE);

    /* further test of EC_equalKeyEx */
    if (NULL != pKey2)
    {
        status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey1, pKey2, &result);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        UNITTEST_VECTOR_INT(__MOC_LINE__, (int) result, (int) expectedEquality);

#if !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        /* corrupt pKey2 and check again */
        pKey2->Qy->units[0] = 0;

        status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey1, pKey2, &result);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        UNITTEST_VECTOR_INT(__MOC_LINE__, (int) result, (int) FALSE);
#endif
    }

exit:

    status = EC_freeKeyTemplate(pKey1, &template);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);

    if (asymKey1.type)
    {
        status = CRYPTO_uninitAsymmetricKey(&asymKey1, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    if (asymKey2.type)
    {
        status = CRYPTO_uninitAsymmetricKey(&asymKey2, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pBuffer)
    {
        status = DIGI_FREE((void **) &pBuffer);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pNewKey)
    {
        status = EC_deleteKeyEx(&pNewKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}


/* Tests that pPubKey goes with pPrivKey. We also test EC_verifyPublicKeyEx */
static int testVerifyKey(ECCKey *pPrivKey, ECCKey *pPubKey, sbyte4 expectedResult)
{
    MSTATUS status = OK;
    int retVal = 0;
    byteBoolean verify;

    status = EC_verifyKeyPairEx(MOC_ECC(gpHwAccelCtx) pPrivKey, pPubKey, &verify);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) verify, (int) expectedResult);

    /* Now test EC_verifyPublicKeyEx */
    status = EC_verifyPublicKeyEx(MOC_ECC(gpHwAccelCtx) pPubKey, &verify);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* All vectors for this test have a valid public key */
    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) verify, (int) TRUE);

#if !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
    /* Reach inside and corrupt the public key as to get an incorrect validation */
    pPubKey->Qy->units[0] = 0;
    status = EC_verifyPublicKeyEx(MOC_ECC(gpHwAccelCtx) pPubKey, &verify);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) verify, (int) FALSE);
#endif

    /* For mbed operators we test EC_verifyPublicKeyEx a single time in the error cases tests */
exit:

    return retVal;
}


/* Test EC_generateKeyPairEx and EC_generateKeyPairAlloc */
static int testGenerateKeyPair(ubyte4 curveId, ECCKey *pExpectedKey)
{
    MSTATUS status = OK;
    int retVal = 0;
    byteBoolean match, used;

    ECCKey *pKey = NULL;

    status = EC_newKeyEx(curveId, &pKey);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    used = FALSE;
    status = EC_generateKeyPairEx(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, &used);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey, pExpectedKey, &match);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) match, (int) TRUE);

    status = EC_deleteKeyEx(&pKey);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Now test EC_generateKeyPairAlloc */
    used = FALSE;
    status = EC_generateKeyPairAlloc(MOC_ECC(gpHwAccelCtx) curveId, &pKey, rngCallback, &used);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey, pExpectedKey, &match);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) match, (int) TRUE);

exit:

    if (NULL != pKey)
    {
        status = EC_deleteKeyEx(&pKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}


/* Tests ECDSA_signDigest */
static int testDsaSign(ECCKey *pKey, ubyte *pHash, ubyte4 hashLen, ubyte *pExpectededSignature, ubyte4 expectedSignatureLen)
{
    MSTATUS status = OK;
    int retVal = 0;

    sbyte4 compare;
    byteBoolean used;

    ubyte pSignature[132] = {0}; /* big enough for any of our curves */
    ubyte4 sigLen = 0;

    /* test getting the proper buffer length */
    used = FALSE;
    status = ECDSA_signDigest(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, &used, pHash, hashLen, NULL, 0, &sigLen);
    UNITTEST_VECTOR_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);

    /* is SigLen correct */
    UNITTEST_VECTOR_INT(__MOC_LINE__, sigLen, expectedSignatureLen);

    /* test Sign */
    used = FALSE;
    status = ECDSA_signDigest(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, &used, pHash, hashLen, pSignature, sizeof(pSignature), &sigLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* is SigLen still correct */
    UNITTEST_VECTOR_INT(__MOC_LINE__, sigLen, expectedSignatureLen);

    /* test we got the expected result */
    status = DIGI_MEMCMP(pSignature, pExpectededSignature, sigLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

exit:

    return retVal;
}


/* Tests ECDSA_signMessage */
static int testDsaSignMessage(ECCKey *pKey, ubyte hashAlgo, ubyte *pMsg, ubyte4 msgLen, ubyte *pExpectededSignature, ubyte4 expectedSignatureLen)
{
    MSTATUS status = OK;
    int retVal = 0;

    sbyte4 compare;
    byteBoolean used;

    ubyte pSignature[132] = {0}; /* big enough for any of our curves */
    ubyte4 sigLen = 0;

    /* test getting the proper buffer length */
    used = FALSE;
    status = ECDSA_signMessage(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, &used, hashAlgo, pMsg, msgLen, NULL, 0, &sigLen, NULL);
    UNITTEST_VECTOR_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);

    /* is SigLen correct */
    UNITTEST_VECTOR_INT(__MOC_LINE__, sigLen, expectedSignatureLen);

    /* test Sign */
    used = FALSE;
    status = ECDSA_signMessage(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, &used, hashAlgo, pMsg, msgLen, pSignature, sizeof(pSignature), &sigLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* is SigLen still correct */
    UNITTEST_VECTOR_INT(__MOC_LINE__, sigLen, expectedSignatureLen);

    /* test we got the expected result */
    status = DIGI_MEMCMP(pSignature, pExpectededSignature, sigLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

exit:

    return retVal;
}


/* Tests ECDSA_verifySignatureDigest */
static int testDsaVerify(ECCKey *pKey, ubyte *pHash, ubyte4 hashLen, ubyte *pR, ubyte4 rLen, ubyte *pS, ubyte4 sLen, ubyte4 expectedFailures, intBoolean notP256)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 verifyFailures;

#if defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)

    /* mbed verifyFailures should be 4 for all of our test vectors */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled && 0 != expectedFailures)
    {
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (notP256)
#endif
            expectedFailures = 4;
    }
#endif

    /* test ECDSA_verifySignature */
    status = ECDSA_verifySignatureDigest(MOC_ECC(gpHwAccelCtx) pKey, pHash, hashLen, pR, rLen, pS, sLen, &verifyFailures);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) verifyFailures, (int) expectedFailures);

exit:

    return retVal;
}


/* Tests ECDSA_verifyMessage */
static int testDsaVerifyMessage(ECCKey *pKey, ubyte hashAlgo, ubyte *pMsg, ubyte4 msgLen, ubyte *pSignature, ubyte4 sigLen, ubyte4 expectedFailures, intBoolean notP256)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 verifyFailures;

#if defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)

    /* mbed verifyFailures should be 4 for all of our test vectors */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled && 0 != expectedFailures)
    {
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (notP256) /* hack wasy to tell if it's not P256 */
#endif
            expectedFailures = 4;
    }
#endif

    /* test ECDSA_verifySignature */
    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, hashAlgo, pMsg, msgLen, pSignature, sigLen, &verifyFailures, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) verifyFailures, (int) expectedFailures);

exit:

    return retVal;
}

/* Tests ECDSA_initVerify, ECDSA_updateVerify, ECDSA_finalVerify */
static int testDsaVerifyMessageEVP(ECCKey *pKey, ubyte hashAlgo, ubyte *pMsg, ubyte4 msgLen, ubyte *pSignature, ubyte4 sigLen, ubyte4 expectedFailures)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 verifyFailures;

    ECDSA_CTX ecdsaCtx = {0};

#if defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)

    /* mbed verifyFailures should be 4 for all of our test vectors */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled && 0 != expectedFailures)
    {
            expectedFailures = 4;
    }
#endif

    /* test ECDSA_initVerify */
    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, pKey, hashAlgo, pSignature, sigLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /*
     test ECDSA_updateVerify. Message buffering is handled by the hash algorithm and
     should be properly tested there. Sufficient to test just one call to ECDSA_updateVerify.
     */
    status = ECDSA_updateVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, pMsg, msgLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* test ECDSA_finalVerify */
    status = ECDSA_finalVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, &verifyFailures, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) verifyFailures, (int) expectedFailures);

exit:

    return retVal;
}


/* Tests both ECDH_generateSharedSecretFromPublicByteString and ECDH_generateSharedSecretFromKeys */
static int testGenerateSharedSecret(ECCKey *pKey, ubyte *pPublicKey, ubyte4 publicKeyLen, sbyte4 flag, ubyte *pExpectedSS, ubyte4 expectedSSLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;
    ECCKey *pOthersPublicKey = NULL;
    ubyte4 curveId;

    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;

#if defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) || defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
    /* mbed just returns the x coordinate. If flag is 0 change the expected SS to be just x */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled && !flag)
        expectedSSLen /= 2;
#endif

    /* First test ECDH_generateSharedSecretFromPublicByteString */
    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pKey, pPublicKey, publicKeyLen, &pSS, &ssLen, flag, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, ssLen, expectedSSLen);
    status = DIGI_MEMCMP(pSS, pExpectedSS, ssLen, &compare);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

    status = DIGI_FREE((void **) &pSS);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Now test ECDH_generateSharedSecretFromKeys */
    status = EC_getCurveIdFromKey(pKey, &curveId);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_newKeyEx(curveId, &pOthersPublicKey);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pOthersPublicKey, pPublicKey, publicKeyLen, NULL, 0);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = ECDH_generateSharedSecretFromKeys(MOC_ECC(gpHwAccelCtx) pKey, pOthersPublicKey, &pSS, &ssLen, flag, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, ssLen, expectedSSLen);
    status = DIGI_MEMCMP(pSS, pExpectedSS, ssLen, &compare);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pSS)
    {
        status = DIGI_FREE((void **) &pSS);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pOthersPublicKey)
    {
        status = EC_deleteKeyEx(&pOthersPublicKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

/* Tests EC_getCurveIdFromKey, EC_getElementByteStringLen, and EC_getPointByteStringLenEx */
static int testSimpleGetMethods(ubyte4 expectedCurveId)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 curveId;
    ubyte4 len;
    ubyte4 expectedElementLen = 66; /* p521 default */
    ubyte4 expectedPointLen;

    ECCKey *pKey = NULL;

    switch(expectedCurveId)
    {
        case cid_EC_P192:

            expectedElementLen = 24;
            break;

        case cid_EC_P224:

            expectedElementLen = 28;
            break;

        case cid_EC_P256:

            expectedElementLen = 32;
            break;

        case cid_EC_P384:

            expectedElementLen = 48;
            break;
    }
    expectedPointLen = 2*expectedElementLen + 1;

    /* All tests will start with the first two inputs consisting of a private (if applicable) and public key */
    status = EC_newKeyEx(expectedCurveId, &pKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_getCurveIdFromKey(pKey, &curveId);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, curveId, expectedCurveId);

    status = EC_getElementByteStringLen (pKey, &len);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, len, expectedElementLen);

    status = EC_getPointByteStringLenEx (pKey, &len);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(__MOC_LINE__, len, expectedPointLen);

exit:

    if (NULL != pKey)
    {
        status = EC_deleteKeyEx(&pKey);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}


static int knownAnswerTest(TestVector *pTestVector, ubyte4 curveId, ubyte *pPoint, ubyte4 pointLen)
{
    MSTATUS status = OK;
    int retVal = 0;

    ECCKey *pKey1 = NULL;
    ECCKey *pKey2 = NULL;

    ubyte *pInput1 = NULL;
    ubyte4 input1Len = 0;
    ubyte *pInput2 = NULL;
    ubyte4 input2Len = 0;
    ubyte *pInput3 = NULL;
    ubyte4 input3Len = 0;
    ubyte *pInput4 = NULL;
    ubyte4 input4Len = 0;
    ubyte *pInput5 = NULL;
    ubyte4 input5Len = 0;

    sbyte4 input6 = pTestVector->input6;
    TestVectorType type = pTestVector->type;
    ubyte hashAlgo = 0;

    /* set the vectors from the test vector */
    if (pTestVector->pInput1 != NULL)
    {
        input1Len = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pInput1, &pInput1);
    }
    if (pTestVector->pInput2 != NULL)
    {
        input2Len = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pInput2, &pInput2);
    }
    if (pTestVector->pInput3 != NULL)
    {
        input3Len = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pInput3, &pInput3);
    }
    if (pTestVector->pInput4 != NULL)
    {
        input4Len = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pInput4, &pInput4);
    }
    if (verifyMsg != type)
    {
        if (pTestVector->pInput5 != NULL)
        {
            input5Len = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pInput5, &pInput5);
        }
    }
    else  /* We hide the hashAlgo in pInput5, Sigh, don't want to add a new ubyte field just for verifyMsg vectors */
    {
        hashAlgo = (ubyte)((uintptr) pTestVector->pInput5);
    }

    /* All tests will start with the first two inputs consisting of a private (if applicable) and public key */
    status = EC_newKeyEx(curveId, &pKey1);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* for these tests we only need a private key */
    if (sign == type || signMsg == type || sharedSecret == type)
    {
        status = EC_setPrivateKeyEx(MOC_ECC(gpHwAccelCtx) pKey1, pInput1, input1Len);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    else
    {
        status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey1, pInput2, input2Len, pInput1, input1Len);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (OK != status)
        goto exit;

    switch(type)
    {
        case testKeys:
        case verifyKey:

            if (NULL != pInput4)
            {
                /* create an auxiliary key */
                status = EC_newKeyEx(curveId, &pKey2);
                UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
                if (OK != status)
                    goto exit;

                /* All auxiliary keys have a public key, just use EC_setKeyParametersEx */
                status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey2, pInput4, input4Len, pInput3, input3Len);
                UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
                if (OK != status)
                    goto exit;
            }

            if (testKeys == type)
                retVal += testKeyMethods(pKey1, pKey2, pInput1, input1Len, pInput2, input2Len, (byteBoolean) input6);
            else
                retVal += testVerifyKey(pKey1, pKey2, (byteBoolean) input6);
            break;

        case generateKeyPair:
        case sign:
        case signMsg:

            /*
             copy the nonce to the global variable for use in the "fake" RNG
             We do get the number of element words from the expected key pKey1
             */
#if defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) || defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
            if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey1->enabled)
            {
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
                if (cid_EC_P256 == curveId)
                {
#ifdef __ENABLE_DIGICERT_64_BIT__
                    status = copyRNGdata(pInput3, input3Len, 4); /* fixed for P256 */
#else
                    status = copyRNGdata(pInput3, input3Len, 8);
#endif
                }
                else
#endif
                {
#if defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
                    status = copyRNGdataMBed(pInput3, input3Len, curveId);
#else
                    status = copyRNGdata(pInput3, input3Len, pKey1->pCurve->pPF->n);
#endif
                }
            }
            else
#endif
                status = copyRNGdata(pInput3, input3Len, pKey1->pCurve->pPF->n);


            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if(OK != status)
                goto exit;

            if (generateKeyPair == type)
                retVal += testGenerateKeyPair(curveId, pKey1);
            else if (sign == type)
                retVal += testDsaSign(pKey1, pInput4, input4Len, pInput5, input5Len);
            else /* signMsg == type */
                retVal += testDsaSignMessage(pKey1, (ubyte) input6, pInput4, input4Len, pInput5, input5Len);
            break;

        case verify:
            retVal += testDsaVerify(pKey1, pInput3, input3Len, pInput4, input4Len, pInput5, input5Len, (ubyte4) input6, cid_EC_P256 != curveId);
            break;

        case verifyMsg:
            retVal += testDsaVerifyMessage(pKey1, hashAlgo, pInput3, input3Len, pInput4, input4Len, (ubyte4) input6, cid_EC_P256 != curveId);
#if defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) || defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
            if (CRYPTO_INTERFACE_ALGO_ENABLED != pKey1->enabled)
#endif
                retVal += testDsaVerifyMessageEVP(pKey1, hashAlgo, pInput3, input3Len, pInput4, input4Len, (ubyte4) input6);
            break;

        case sharedSecret:
            retVal += testGenerateSharedSecret(pKey1, pInput3, input3Len, input6, pInput4, input4Len);
            break;

        default:
            break;
    }

exit:

    if(NULL != pInput1)
    {
        status = DIGI_FREE((void **) &pInput1);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pInput2)
    {
        status = DIGI_FREE((void **) &pInput2);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    if(NULL != pInput3)
    {
        status = DIGI_FREE((void **) &pInput3);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    if(NULL != pInput4)
    {
        status = DIGI_FREE((void **) &pInput4);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    if(NULL != pInput5)
    {
        status = DIGI_FREE((void **) &pInput5);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pKey1)
    {
        status = EC_deleteKeyEx(&pKey1);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pKey2)
    {
        status = EC_deleteKeyEx(&pKey2);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

static int testErrorCases(ubyte4 curveId, ubyte *pPrime, ubyte4 primeLen, ubyte *pPoint, ubyte4 pointLen)
{
    int retVal = 0;
    MSTATUS status = OK;

    ECCKey *pKey = NULL;
    ECCKey *pKey2 = NULL;
    ECCKey *pKey3 = NULL;
    ECCKey keyUnalloc = {0};
    MEccKeyTemplate template = {0};

    ECDSA_CTX ecdsaCtx = {0};

    byteBoolean res;

    ubyte pScalarBuffer[66] = {0};    /* big enough for all curves */
    ubyte4 coordByteLen = pointLen/2; /* will round down to the correct value */
    ubyte pInvalidPoint[141] = {0};   /* big enough for all curve signatures */
    ubyte4 wrongCurve = (cid_EC_P192 == curveId ? cid_EC_P256 : cid_EC_P192);

    ubyte *pHash = pScalarBuffer;     /* re use buffers as no actual computations will be done */
    ubyte4 hashLen = 20;
    ubyte *pSignature = pInvalidPoint;
    ubyte4 sigBufferLen = pointLen - 1;
    ubyte4 sigLen;

    ubyte *pR = pSignature;      /* re-use the first half of pSignature */
    ubyte *pS = pSignature + 66; /* re-use the second half of pSignature */

    ubyte4 verifyFailures;

    ubyte *pSS = NULL;
    ubyte4 ssLen;

    /******* EC_newKeyEx *******/

    status = EC_newKeyEx(curveId, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_newKeyEx(99, &pKey);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNSUPPORTED_CURVE);

    /* Properly allocate pKey and pKey2 for further tests */
    status = EC_newKeyEx(curveId, &pKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    status = EC_newKeyEx(curveId, &pKey2);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    /******* EC_getCurveIdFromKey *******/

    status = EC_getCurveIdFromKey(NULL, &ssLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_getCurveIdFromKey(pKey, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_getCurveIdFromKey(&keyUnalloc, &ssLen);
    retVal += UNITTEST_TRUE(__MOC_LINE__, status);

    /******* EC_getElementByteStringLen *******/

    status = EC_getElementByteStringLen(NULL, &ssLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_getElementByteStringLen(pKey, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_getElementByteStringLen(&keyUnalloc, &ssLen);
    retVal += UNITTEST_TRUE(__MOC_LINE__, status);

    /******* EC_getPointByteStringLenEx *******/

    status = EC_getPointByteStringLenEx(NULL, &ssLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_getPointByteStringLenEx(pKey, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_getPointByteStringLenEx(&keyUnalloc, &ssLen);
    retVal += UNITTEST_TRUE(__MOC_LINE__, status);

    /******* EC_cloneKeyEx *******/

    status = EC_cloneKeyEx(MOC_ECC(gpHwAccelCtx) NULL, pKey2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_cloneKeyEx(MOC_ECC(gpHwAccelCtx) &pKey, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* EC_equalKeyEx *******/

    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) NULL, pKey2, &res);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey, NULL, &res);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey, pKey2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) &keyUnalloc, pKey2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_equalKeyEx(MOC_ECC(gpHwAccelCtx) pKey, &keyUnalloc, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* EC_setKeyParametersEx *******/

    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) NULL, pPoint, pointLen, pScalarBuffer, coordByteLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, NULL, pointLen, NULL, coordByteLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* Note: scalar validation is handled before the point validation, make scalar nonzero */
    pScalarBuffer[0] = 0x80;

    /* The following calls are valid for mbed */
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pKey->enabled)
#endif
    {
        status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, NULL, pointLen, NULL, coordByteLen);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

        /* scalar length too big */
        status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen, pScalarBuffer, coordByteLen + 1);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);

        /* scalar of 0 TO DO UNCOMMENT IF disallowed, Add test of scalar = n if appropriate */

        /* status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pPoint, 2*coordByteLen + 1, pScalarBuffer, coordByteLen);
         retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);*/

        /* Note: we allow scalars bigger than n (and do not reduce mod n). We do not allow a scalar of p or larger */
        status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen, pPrime, primeLen);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);
    }

    /* point length too small */

    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pPoint, 0, NULL, 0);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);
        else
#endif
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen - 1, NULL, 0);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    /* point length too big */
    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen + 1, NULL, 0);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    /* inproperly encoded point */

    status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pInvalidPoint, pointLen, NULL, 0);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_UNSUPPORTED_PT_REPRESENTATION);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_UNSUPPORTED_PT_REPRESENTATION);

    /* The following calls are valid for mbed (ie they don't validate points) */

#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED != pKey->enabled)
#endif
    {
        /* point (0,0) which is not on any of our curves */
        pInvalidPoint[0] = 0x04;
        status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pInvalidPoint, pointLen, NULL, 0);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FALSE);

        /* point with second coord invalid, p or larger */
        status = DIGI_MEMCPY(pInvalidPoint + 1 + coordByteLen, pPrime, primeLen);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pInvalidPoint, pointLen, NULL, 0);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);

        /* point with first coord invalid, p or larger */

        status = DIGI_MEMCPY(pInvalidPoint + 1, pPrime, primeLen);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pInvalidPoint, pointLen, NULL, 0);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);
    }

    /******* EC_newPublicKeyFromByteString *******/

    status = EC_newPublicKeyFromByteString(MOC_ECC(gpHwAccelCtx) curveId, NULL, pPoint, pointLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_newPublicKeyFromByteString(MOC_ECC(gpHwAccelCtx) curveId, &pKey3, NULL, pointLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_newPublicKeyFromByteString(MOC_ECC(gpHwAccelCtx) 99, &pKey3, pPoint, pointLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNSUPPORTED_CURVE);

    status = EC_newPublicKeyFromByteString(MOC_ECC(gpHwAccelCtx) curveId, &pKey3, pPoint, 0);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    status = EC_newPublicKeyFromByteString(MOC_ECC(gpHwAccelCtx) curveId, &pKey3, pPoint, pointLen - 1);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    status = EC_newPublicKeyFromByteString(MOC_ECC(gpHwAccelCtx) curveId, &pKey3, pPoint, pointLen + 1);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    pInvalidPoint[0] = 0x00;
    status = EC_newPublicKeyFromByteString(MOC_ECC(gpHwAccelCtx) curveId, &pKey3, pInvalidPoint, pointLen);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_UNSUPPORTED_PT_REPRESENTATION);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_UNSUPPORTED_PT_REPRESENTATION);

    pInvalidPoint[0] = 0x04;
#if !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
    /* valid call for mbded */
    status = EC_newPublicKeyFromByteString(MOC_ECC(gpHwAccelCtx) curveId, &pKey3, pInvalidPoint, pointLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);
#endif

    /******* EC_writePublicKeyToBuffer *******/

    status = EC_writePublicKeyToBuffer(MOC_ECC(gpHwAccelCtx) NULL, pInvalidPoint, pointLen); /* re-use pInvalidPoint buffer var */
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_writePublicKeyToBuffer(MOC_ECC(gpHwAccelCtx) pKey, NULL, pointLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_writePublicKeyToBuffer(MOC_ECC(gpHwAccelCtx) &keyUnalloc, pInvalidPoint, pointLen);
    retVal += UNITTEST_TRUE(__MOC_LINE__, status);

    /******* EC_writePublicKeyToBufferAlloc *******/

    status = EC_writePublicKeyToBufferAlloc(MOC_ECC(gpHwAccelCtx) NULL, &pSS, &ssLen);   /* re-use pSS and ssLen vars */
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_writePublicKeyToBufferAlloc(MOC_ECC(gpHwAccelCtx) pKey, NULL, &ssLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_writePublicKeyToBufferAlloc(MOC_ECC(gpHwAccelCtx) pKey, &pSS, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_writePublicKeyToBufferAlloc(MOC_ECC(gpHwAccelCtx) &keyUnalloc, &pSS, &ssLen);
    retVal += UNITTEST_TRUE(__MOC_LINE__, status);

    /******* EC_getKeyParametersAlloc *******/

    status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) NULL, &template, MOC_GET_PRIVATE_KEY_DATA);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) pKey, NULL, MOC_GET_PRIVATE_KEY_DATA);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) &keyUnalloc, NULL, MOC_GET_PRIVATE_KEY_DATA);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    /* Properly setKeyParams for later tests */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen, NULL, 0);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);

        status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) pKey, &template, MOC_GET_PRIVATE_KEY_DATA);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_KEY_IS_NOT_PRIVATE);
    }
#endif
    status = EC_getKeyParametersAlloc(MOC_ECC(gpHwAccelCtx) pKey, &template, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /******* EC_verifyKeyPairEx *******/

    status = EC_verifyKeyPairEx(MOC_ECC(gpHwAccelCtx) NULL, pKey, &res);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_verifyKeyPairEx(MOC_ECC(gpHwAccelCtx) pKey, pKey2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_verifyKeyPairEx(MOC_ECC(gpHwAccelCtx) &keyUnalloc, pKey2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* NULL pPublic key is allowed as then it'll verify the public portion of the pPrivateKey */

    /******* EC_verifyPublicKeyEx *******/

    status = EC_verifyPublicKeyEx(MOC_ECC(gpHwAccelCtx) NULL, &res);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_verifyPublicKeyEx(MOC_ECC(gpHwAccelCtx) pKey, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_verifyPublicKeyEx(MOC_ECC(gpHwAccelCtx) &keyUnalloc, NULL);
   retVal += UNITTEST_TRUE(__MOC_LINE__, status);

    /*
     verifying a point that is not on the curve is in the above
     test of EC_verifyPublicKeyEx for old style APIs. For mbed it is here
     */
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        pInvalidPoint[0] = 0x04;

#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 != curveId)
        {
#endif
            status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pInvalidPoint, pointLen, NULL, 0);
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            if(OK != status)
                goto exit;

            status = EC_verifyPublicKeyEx(MOC_ECC(gpHwAccelCtx) pKey, &res);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if(OK != status)
                goto exit;

            UNITTEST_VECTOR_INT(__MOC_LINE__, (int) res, (int) FALSE);
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        }
#endif
    }
#endif

    /******* EC_generateKeyPairEx *******/

    status = EC_generateKeyPairEx(MOC_ECC(gpHwAccelCtx) NULL, rngCallback, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_generateKeyPairEx(MOC_ECC(gpHwAccelCtx) pKey3, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_generateKeyPairEx(MOC_ECC(gpHwAccelCtx) &keyUnalloc, NULL, NULL);
    retVal += UNITTEST_TRUE(__MOC_LINE__, status);

    /******* EC_generateKeyPairAlloc *******/

    status = EC_generateKeyPairAlloc(MOC_ECC(gpHwAccelCtx) curveId, NULL, rngCallback, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_generateKeyPairAlloc(MOC_ECC(gpHwAccelCtx) curveId, &pKey3, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_generateKeyPairAlloc(MOC_ECC(gpHwAccelCtx) 99, &pKey3, rngCallback, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNSUPPORTED_CURVE);

    /******* ECDSA_signDigest *******/

#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    /* Properly setKeyParams for later tests */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 != curveId)
        {
#endif
            status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen, pPrime, primeLen);
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        }
#endif
    }
    else
#endif
        pKey->privateKey = TRUE;

    status = ECDSA_signDigest(MOC_ECC(gpHwAccelCtx) NULL, rngCallback, NULL, pHash, hashLen, pSignature, sigBufferLen, &sigLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_signDigest(MOC_ECC(gpHwAccelCtx) pKey, NULL, NULL, pHash, hashLen, pSignature, sigBufferLen, &sigLen);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_signDigest(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, NULL, hashLen, pSignature, sigBufferLen, &sigLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* for null pSignature we get back the buffer size in sigLen */
    status = ECDSA_signDigest(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, pHash, hashLen, NULL, sigBufferLen, &sigLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);

    /* check that it's correct */
    retVal += UNITTEST_INT(__MOC_LINE__, sigLen, sigBufferLen);

    status = ECDSA_signDigest(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, pHash, hashLen, pSignature, sigBufferLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_signDigest(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, pHash, hashLen, pSignature, sigBufferLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_signDigest(MOC_ECC(gpHwAccelCtx) &keyUnalloc, rngCallback, NULL, pHash, hashLen, pSignature, sigBufferLen, &sigLen);
    retVal += UNITTEST_TRUE(__MOC_LINE__, status);

#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    /* Set to a public key */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen, NULL, 0);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);

        status = ECDSA_signDigest(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, pHash, hashLen, pSignature, sigBufferLen, &sigLen);
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
        else
#endif
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 != curveId)
        {
#endif
            status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen, pPrime, primeLen);
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        }
#endif   
    }
    else
    {
#else
    pKey->privateKey = FALSE;
    status = ECDSA_signDigest(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, pHash, hashLen, pSignature, sigBufferLen, &sigLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_KEY_TYPE);
    pKey->privateKey = TRUE;
#endif
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    }
#endif

    /******* ECDSA_verifySignatureDigest *******/

    status = ECDSA_verifySignatureDigest(MOC_ECC(gpHwAccelCtx) NULL, pHash, hashLen, pR, coordByteLen, pS, coordByteLen, &verifyFailures);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignatureDigest(MOC_ECC(gpHwAccelCtx) pKey, NULL, hashLen, pR, coordByteLen, pS, coordByteLen, &verifyFailures);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignatureDigest(MOC_ECC(gpHwAccelCtx) pKey, pHash, hashLen, NULL, coordByteLen, pS, coordByteLen, &verifyFailures);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignatureDigest(MOC_ECC(gpHwAccelCtx) pKey, pHash, hashLen, pR, coordByteLen, NULL, coordByteLen, &verifyFailures);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignatureDigest(MOC_ECC(gpHwAccelCtx) pKey, pHash, hashLen, pR, coordByteLen, pS, coordByteLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignatureDigest(MOC_ECC(gpHwAccelCtx) &keyUnalloc, pHash, hashLen, pR, coordByteLen, pS, coordByteLen, &verifyFailures);
    retVal += UNITTEST_TRUE(__MOC_LINE__, status);

    /* invalid r,s parameters are tested in the test vectors */

#if !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)

    /******* ECDSA_signMessage *******/

    /* re-use the pHash buffer to represent the message */
    status = ECDSA_signMessage(MOC_ECC(gpHwAccelCtx) NULL, rngCallback, NULL, ht_sha256, pHash, hashLen, pSignature, sigBufferLen, &sigLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_signMessage(MOC_ECC(gpHwAccelCtx) pKey, NULL, NULL, ht_sha256, pHash, hashLen, pSignature, sigBufferLen, &sigLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_signMessage(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, ht_sha256, NULL, hashLen, pSignature, sigBufferLen, &sigLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* for null pSignature we get back the buffer size in sigLen */
    status = ECDSA_signMessage(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, ht_sha256, pHash, hashLen, NULL, sigBufferLen, &sigLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);

    /* check that it's correct */
    retVal += UNITTEST_INT(__MOC_LINE__, sigLen, sigBufferLen);

    status = ECDSA_signMessage(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, ht_sha256, pHash, hashLen, pSignature, sigBufferLen, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_signMessage(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, ht_sha256, pHash, hashLen, pSignature, sigBufferLen, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_signMessage(MOC_ECC(gpHwAccelCtx) &keyUnalloc, rngCallback, NULL, ht_sha256, pHash, hashLen, pSignature, sigBufferLen, &sigLen, NULL);
    retVal += UNITTEST_TRUE(__MOC_LINE__, status);

    /* invalid hash algorithm */
    status = ECDSA_signMessage(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, ht_shake256 + 1, pHash, hashLen, pSignature, sigBufferLen, &sigLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_HASH_ALGO);

    pKey->privateKey = FALSE;
    status = ECDSA_signMessage(MOC_ECC(gpHwAccelCtx) pKey, rngCallback, NULL, ht_sha256, pHash, hashLen, pSignature, sigBufferLen, &sigLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_KEY_TYPE);
    pKey->privateKey = TRUE;

    /******* ECDSA_verifyMessage *******/

    /* re-use the pHash buffer to represent the message */
    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) NULL, ht_sha256, pHash, hashLen, pSignature, sigBufferLen, &verifyFailures, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, ht_sha256, NULL, hashLen, pSignature, sigBufferLen, &verifyFailures, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, ht_sha256, pHash, hashLen, NULL, sigBufferLen, &verifyFailures, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, ht_sha256, pHash, hashLen, pSignature, sigBufferLen, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) &keyUnalloc, ht_sha256, pHash, hashLen, pSignature, sigBufferLen, &verifyFailures, NULL);
    retVal += UNITTEST_TRUE(__MOC_LINE__, status);

    /* invalid sig size */
    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, ht_sha256, pHash, hashLen, pSignature, 0, &verifyFailures, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);

    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, ht_sha256, pHash, hashLen, pSignature, 1, &verifyFailures, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);

    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, ht_sha256, pHash, hashLen, pSignature, sigBufferLen - 1, &verifyFailures, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);

    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, ht_sha256, pHash, hashLen, pSignature, sigBufferLen + 1, &verifyFailures, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);

    /* invalid hash algo */
    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, ht_shake256 + 1, pHash, hashLen, pSignature, sigBufferLen, &verifyFailures, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_HASH_ALGO);

    /* invalid signatures are tested in the test vectors */

    /******* ECDSA_initVerify *******/

    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) NULL, pKey, ht_sha256, pSignature, sigBufferLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, NULL, ht_sha256, pSignature, sigBufferLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, pKey, ht_sha256, NULL, sigBufferLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, &keyUnalloc, ht_sha256, pSignature, sigBufferLen, NULL);
    retVal += UNITTEST_TRUE(__MOC_LINE__, status);

    /* invalid sig size */
    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, pKey, ht_sha256, pSignature, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);

    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, pKey, ht_sha256, pSignature, 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);

    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, pKey, ht_sha256, pSignature, sigBufferLen - 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);

    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, pKey, ht_sha256, pSignature, sigBufferLen + 1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);

    /* invalid hash algo */
    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, pKey, ht_shake256 + 1, pSignature, sigBufferLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_HASH_ALGO);

    /******* ECDSA_updateVerify *******/

    /* re-use the pHash buffer to represent the message */
    status = ECDSA_updateVerify(MOC_ECC(gpHwAccelCtx) NULL, pHash, hashLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_updateVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, NULL, hashLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* uninit context has to show up as ERR_NULL_POINTER since there will be no key */
    status = ECDSA_updateVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, pHash, hashLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* ECDSA_finalVerify *******/

    status = ECDSA_finalVerify(MOC_ECC(gpHwAccelCtx) NULL, &verifyFailures, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_finalVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* uninit context has to show up as ERR_NULL_POINTER since there will be no key */
    status = ECDSA_finalVerify(MOC_ECC(gpHwAccelCtx) &ecdsaCtx, &verifyFailures, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

#endif /* __ENABLE_DIGICERT_MBED_KEY_OPERATORS__ */

    /******* ECDH_generateSharedSecretFromKeys *******/

#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    /* set to a private key */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 != curveId)
        {
#endif
            status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen, pPrime, primeLen);
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        }
#endif
    }
    else
#endif
        pKey->privateKey = TRUE;

    status = ECDH_generateSharedSecretFromKeys(MOC_ECC(gpHwAccelCtx) NULL, pKey2, &pSS, &ssLen, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecretFromKeys(MOC_ECC(gpHwAccelCtx) pKey, NULL, &pSS, &ssLen, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecretFromKeys(MOC_ECC(gpHwAccelCtx) pKey, pKey2, NULL, &ssLen, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecretFromKeys(MOC_ECC(gpHwAccelCtx) pKey, pKey2, &pSS, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecretFromKeys(MOC_ECC(gpHwAccelCtx) &keyUnalloc, pKey2, &pSS, &ssLen, 0, NULL);
    retVal += UNITTEST_TRUE(__MOC_LINE__, status);

    status = ECDH_generateSharedSecretFromKeys(MOC_ECC(gpHwAccelCtx) pKey, &keyUnalloc, &pSS, &ssLen, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

#if !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
    /* Only if the other curve is enabled do we test for ERR_EC_DIFFERENT_CURVE */
    status = EC_newKeyEx(wrongCurve, &pKey3);
    if (status == OK)
    {
        status = ECDH_generateSharedSecretFromKeys(MOC_ECC(gpHwAccelCtx) pKey, pKey3, &pSS, &ssLen, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_DIFFERENT_CURVE);
    }
#endif

#if defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) || defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        /* Set to a public key */
        status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen, NULL, 0);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);

        status = ECDH_generateSharedSecretFromKeys(MOC_ECC(gpHwAccelCtx) pKey, pKey2, &pSS, &ssLen, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 != curveId)
        {
#endif
            /* set to a private key */
            status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen, pPrime, primeLen);
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        }
#endif
    }
    else
    {
#else
    pKey->privateKey = FALSE;
    status = ECDH_generateSharedSecretFromKeys(MOC_ECC(gpHwAccelCtx) pKey, pKey2, &pSS, &ssLen, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_KEY_TYPE);
    pKey->privateKey = TRUE;
#endif
#if defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) || defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
    }
#endif

    /******* ECDH_generateSharedSecretFromPublicByteString *******/

    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) NULL, pPoint, pointLen, &pSS, &ssLen, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pKey, NULL, pointLen, &pSS, &ssLen, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen, NULL, &ssLen, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen, &pSS, NULL, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) &keyUnalloc, pPoint, pointLen, &pSS, &ssLen, 0, NULL);
    retVal += UNITTEST_TRUE(__MOC_LINE__, status);

    /* point (public key) length too small */
    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pKey, pPoint, 0, &pSS, &ssLen, 0, NULL);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen - 1, &pSS, &ssLen, 0, NULL);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    /* point (public key) length too big */
    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pKey, pPoint, pointLen + 1, &pSS, &ssLen, 0, NULL);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    /* inproperly encoded point (public key) */
    pInvalidPoint[0] = 0x01;
    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pKey, pInvalidPoint, pointLen, &pSS, &ssLen, 0, NULL);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_UNSUPPORTED_PT_REPRESENTATION);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_UNSUPPORTED_PT_REPRESENTATION);

    /* point (public key) (0,0) which is not on any of our curves */
    pInvalidPoint[0] = 0x04;
    status = DIGI_MEMSET(pInvalidPoint + 1, 0x00, pointLen - 1);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pKey, pInvalidPoint, pointLen, &pSS, &ssLen, 0, NULL);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FALSE);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FALSE);

    /* point (public key) with second coord invalid, p or larger */
    status = DIGI_MEMCPY(pInvalidPoint + 1 + coordByteLen, pPrime, primeLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pKey, pInvalidPoint, pointLen, &pSS, &ssLen, 0, NULL);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);

    /* point (public key) with first coord invalid, p or larger */
    status = DIGI_MEMCPY(pInvalidPoint + 1, pPrime, primeLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pKey, pInvalidPoint, pointLen, &pSS, &ssLen, 0, NULL);
#ifdef __ENABLE_DIGICERT_MBED_KEY_OPERATORS__
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
#if !defined(__ENABLE_DIGICERT_ECC_P256_MBED__) && defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)
        if (cid_EC_P256 == curveId)
            retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);
        else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_MBED_FAILURE);
    else
#endif
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);

    /******* EC_freeKeyTemplate *******/

    /* NULLs are allowed as an no-op, no error cases */

    /******* EC_deleteKeyEx *******/

    status = EC_deleteKeyEx(NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* a key that was never allocated */
    status = EC_deleteKeyEx(&pKey);

    /* a key that was/is no longer allocated */
    status = EC_deleteKeyEx(&pKey);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

exit:

    /* pSS should never have been allocated */
    if (NULL != pSS)
    { /* force error */
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1);
        status = DIGI_FREE((void **) &pSS);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pKey)
    {
        status = EC_deleteKeyEx(&pKey);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pKey2)
    {
        status = EC_deleteKeyEx(&pKey2);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pKey3)
    {
        status = EC_deleteKeyEx(&pKey3);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

#ifdef __ENABLE_DIGICERT_TAP__
static int testSignVerifyTap(ubyte4 modNum, ubyte4 curveId, ubyte hashAlg, byteBoolean testDeferredUnload)
{
    AsymmetricKey key = {0};
    ECCKey *pNewKey = NULL, *pPubKey = NULL;
    MEccTapKeyGenArgs eccTapArgs = {0};
    int retVal = 0;
    MSTATUS status = 0;
    ubyte4 i = 0;

    ubyte pInput[100] = {0}; /* also big enough for any sigest size */
    ubyte4 inputLen = 100;
    ubyte pSig[132] = {0}; /* big enough for any key size */
    ubyte4 sigLen = 0;
    ubyte4 vStatus = 1;
    TAP_SIG_SCHEME sigScheme = 0;

    ubyte pInput2[100] = {0xff, 0xee, 0xdd}; /* also big enough for any sigest size */
    ubyte pSig2[132] = {0}; /* big enough for any key size */
    ubyte4 sig2Len = 0;

    TAP_KeyHandle keyHandle = 0;
    TAP_TokenHandle tokenHandle = 0;

#ifdef __ENABLE_DIGICERT_TPM2__
    AsymmetricKey tempKey = {0};
    ubyte *pSerializedKey = NULL;
    ubyte4 serializedKeyLen = 0;
#endif

    for (i = 0; i < sizeof(pInput); ++i)
    {
        pInput[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    status = CRYPTO_initAsymmetricKey(&key);
    retVal += UNITTEST_STATUS(curveId, status);
    if (OK != status)
        goto exit;

    switch (hashAlg)
    {
        case ht_none:

            switch (curveId)
            {
                case cid_EC_P192:
                    inputLen = 20;
                    break;

                case cid_EC_P224:
                    inputLen = 28;
                    break;

                case cid_EC_P256:
                    inputLen = 32;
                    break;

                case cid_EC_P384:
                    inputLen = 48;
                    break;

                case cid_EC_P521:
                    inputLen = 64;
                    break;
            }
            sigScheme = TAP_SIG_SCHEME_NONE;
            break;

        case ht_sha1:
            sigScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
            break;

        case ht_sha224:
            sigScheme = TAP_SIG_SCHEME_ECDSA_SHA224;
            break;

        case ht_sha256:
            sigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
            break;

        case ht_sha384:
            sigScheme = TAP_SIG_SCHEME_ECDSA_SHA384;
            break;
    
        case ht_sha512:
            sigScheme = TAP_SIG_SCHEME_ECDSA_SHA512;
            break;

    }

    /* eccTapArgs.algKeyInfo.eccInfo.curveId will be set internally by CRYPTO_INTERFACE_EC_generateKeyPairAlloc */

    eccTapArgs.keyUsage = TAP_KEY_USAGE_SIGNING;
    eccTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(modNum);
    eccTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(modNum);
    eccTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(modNum);
    eccTapArgs.algKeyInfo.eccInfo.sigScheme = sigScheme;

    status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(MOC_ECC(gpHwAccelCtx) curveId, (void **) &pNewKey, RANDOM_rngFun, g_pRandomContext, akt_tap_ecc, &eccTapArgs);
    retVal += UNITTEST_STATUS(curveId, status);
    if (OK != status)
        goto exit;

    /* TPM2 requires key to be serialized before it can be used... */
#ifdef __ENABLE_DIGICERT_TPM2__
    tempKey.type = akt_tap_ecc;
    tempKey.key.pECC = pNewKey;

    status = CRYPTO_serializeAsymKey(
        &tempKey, mocanaBlobVersion2, &pSerializedKey, &serializedKeyLen);
    retVal += UNITTEST_STATUS(curveId, status);
    if (OK != status)
        goto exit;

    (void) DIGI_FREE((void **) &pSerializedKey);
#endif

    status = CRYPTO_loadAsymmetricKey(&key, akt_tap_ecc, (void **) &pNewKey);
    retVal += UNITTEST_STATUS(curveId, status);
    if (OK != status)
        goto exit;

    if (testDeferredUnload)
    {
        status = CRYPTO_INTERFACE_TAP_AsymDeferUnload (&key, TRUE);
        retVal += UNITTEST_STATUS(curveId, status);
        if (OK != status)
            goto exit;
    }

    if (ht_none == hashAlg)
    {
        status = CRYPTO_INTERFACE_ECDSA_signDigestAux (MOC_ECC(gpHwAccelCtx) key.key.pECC, RANDOM_rngFun, g_pRandomContext, pInput, inputLen, pSig, sizeof(pSig), &sigLen);
        retVal += UNITTEST_STATUS(curveId, status);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = CRYPTO_INTERFACE_ECDSA_signMessageExt (MOC_ECC(gpHwAccelCtx) key.key.pECC, RANDOM_rngFun, g_pRandomContext, hashAlg, pInput, inputLen, pSig, sizeof(pSig), &sigLen, NULL);
        retVal += UNITTEST_STATUS(curveId, status);
        if (OK != status)
            goto exit;
    }

    if (testDeferredUnload)
    {
        /* Sign another digest with the same key just to test*/
        TAP_KeyHandle keyHandle2 = 0;
        TAP_TokenHandle tokenHandle2 = 0;

        if (ht_none == hashAlg)
        {
            status = CRYPTO_INTERFACE_ECDSA_signDigestAux (MOC_ECC(gpHwAccelCtx) key.key.pECC, RANDOM_rngFun, g_pRandomContext, 
                                                           pInput2, inputLen, pSig2, sizeof(pSig2), &sig2Len);
            retVal += UNITTEST_STATUS(curveId, status);
            if (OK != status)
                goto exit;

        }
        else
        {
            status = CRYPTO_INTERFACE_ECDSA_signMessageExt (MOC_ECC(gpHwAccelCtx) key.key.pECC, RANDOM_rngFun, g_pRandomContext, hashAlg, 
                                                            pInput2, inputLen, pSig2, sizeof(pSig2), &sig2Len, NULL);
            retVal += UNITTEST_STATUS(curveId, status);
            if (OK != status)
                goto exit;
        }

        status = CRYPTO_INTERFACE_TAP_EccGetKeyInfo(key.key.pECC, MOC_ASYM_KEY_TYPE_PRIVATE, &tokenHandle, &keyHandle);
        retVal += UNITTEST_STATUS(curveId, status);
        if (OK != status)
            goto exit;

        /* Also test the CRYPTO_INTERFACE_TAP_AsymGetKeyInfo API */

        status = CRYPTO_INTERFACE_TAP_AsymGetKeyInfo(&key, MOC_ASYM_KEY_TYPE_PRIVATE, &tokenHandle2, &keyHandle2);
        retVal += UNITTEST_STATUS(curveId, status);
        if (OK != status)
            goto exit;

        if (tokenHandle2 != tokenHandle)
        {
            retVal += UNITTEST_STATUS(curveId, -1);
        }

        if (keyHandle2 != keyHandle)
        {
            retVal += UNITTEST_STATUS(curveId, -1);
        }
    }

    status = CRYPTO_INTERFACE_getECCPublicKey(&key, &pPubKey);
    retVal += UNITTEST_STATUS(curveId, status);
    if (OK != status)
        goto exit;

    if (ht_none == hashAlg)
    {
        status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux (MOC_ECC(gpHwAccelCtx) pPubKey, pInput, inputLen,
                                                                pSig, sigLen/2, pSig + sigLen/2, sigLen/2, &vStatus);
        retVal += UNITTEST_STATUS(curveId, status);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt (MOC_ECC(gpHwAccelCtx) pPubKey, hashAlg, pInput, inputLen, 
                                                          pSig, sigLen, &vStatus, NULL);
        retVal += UNITTEST_STATUS(curveId, status);
        if (OK != status)
            goto exit;
    }

    retVal += UNITTEST_INT(curveId, vStatus, 0);

    if (testDeferredUnload)
    {
        if (ht_none == hashAlg)
        {
            status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux (MOC_ECC(gpHwAccelCtx) pPubKey, pInput2, inputLen,
                                                                    pSig2, sig2Len/2, pSig2 + sig2Len/2, sig2Len/2, &vStatus);
            retVal += UNITTEST_STATUS(curveId, status);
            if (OK != status)
                goto exit;
        }
        else
        {
            status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt (MOC_ECC(gpHwAccelCtx) pPubKey, hashAlg, pInput2, inputLen, 
                                                              pSig2, sig2Len, &vStatus, NULL);
            retVal += UNITTEST_STATUS(curveId, status);
            if (OK != status)
                goto exit;
        }

        retVal += UNITTEST_INT(curveId, vStatus, 0);
    }

exit:

    (void) CRYPTO_uninitAsymmetricKey(&key, NULL);

    if (NULL != pNewKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pNewKey);
    }

    if (NULL != pPubKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pPubKey);
    }

    if (0 != keyHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapKey(TAP_EXAMPLE_getTapContext(modNum), tokenHandle, keyHandle);
        retVal += UNITTEST_STATUS(curveId, status);
    }

    if (0 != tokenHandle)
    {
        status = CRYPTO_INTERFACE_unloadTapToken(TAP_EXAMPLE_getTapContext(modNum), tokenHandle);
        retVal += UNITTEST_STATUS(curveId, status);
    }

    return retVal;
}

#if defined(__ENABLE_DIGICERT_UNITTEST_CI_TAP_PRINT__)

#include "../../src/common/mfmgmt.h"

static void testSignVerifyTapPrintSingle(
    FileDescriptor pFile, ubyte4 modNum, TAP_KEY_USAGE keyUsage, TAP_SIG_SCHEME sigScheme, ubyte4 curveId)
{
    ubyte *pKeyUsage = "Undetermined";
    ubyte *pSigScheme = "Undetermined";
    ubyte *pCurveId = "Undetermined";
    ubyte *pDigest = NULL;
    MEccTapKeyGenArgs eccTapArgs = {0};
    AsymmetricKey key = {0};
    ECCKey *pNewKey = NULL, *pPubKey = NULL;;
    ubyte pInput[100] = {0}; /* also big enough for any digest size */
    ubyte4 inputLen = 100;
    ubyte pSig[132] = {0}; /* big enough for any key size */
    ubyte4 sigLen = 0;
    ubyte4 vStatus = 1;
    MSTATUS status = 0;

    ubyte pInput2[100] = {0xff, 0xee, 0xdd}; /* also big enough for any digest size */
    ubyte pSig2[132] = {0}; /* big enough for any key size */
    ubyte4 sig2Len = 0;

    ubyte4 i;
    ubyte pHashAlgs[] = {
        ht_sha1,
        ht_sha224,
        ht_sha256,
        ht_sha384,
        ht_sha512
    };

#ifdef __ENABLE_DIGICERT_TPM2__
    AsymmetricKey tempKey = {0};
    ubyte *pSerializedKey = NULL;
    ubyte4 serializedKeyLen = 0;
#endif

    switch (keyUsage)
    {
        case TAP_KEY_USAGE_UNDEFINED:
            pKeyUsage = "TAP_KEY_USAGE_UNDEFINED";
            break;
        case TAP_KEY_USAGE_SIGNING:
            pKeyUsage = "TAP_KEY_USAGE_SIGNING";
            break;
        case TAP_KEY_USAGE_DECRYPT:
            pKeyUsage = "TAP_KEY_USAGE_DECRYPT";
            break;
        case TAP_KEY_USAGE_GENERAL:
            pKeyUsage = "TAP_KEY_USAGE_GENERAL";
            break;
        case TAP_KEY_USAGE_ATTESTATION:
            pKeyUsage = "TAP_KEY_USAGE_ATTESTATION";
            break;
        case TAP_KEY_USAGE_STORAGE:
            pKeyUsage = "TAP_KEY_USAGE_STORAGE";
            break;
    }

    switch (sigScheme)
    {
        case TAP_SIG_SCHEME_NONE:
            pSigScheme = "TAP_SIG_SCHEME_NONE";
            break;
        case TAP_SIG_SCHEME_ECDSA_SHA1:
            pSigScheme = "TAP_SIG_SCHEME_ECDSA_SHA1";
            break;
        case TAP_SIG_SCHEME_ECDSA_SHA224:
            pSigScheme = "TAP_SIG_SCHEME_ECDSA_SHA224";
            break;
        case TAP_SIG_SCHEME_ECDSA_SHA256:
            pSigScheme = "TAP_SIG_SCHEME_ECDSA_SHA256";
            break;
        case TAP_SIG_SCHEME_ECDSA_SHA384:
            pSigScheme = "TAP_SIG_SCHEME_ECDSA_SHA384";
            break;
        case TAP_SIG_SCHEME_ECDSA_SHA512:
            pSigScheme = "TAP_SIG_SCHEME_ECDSA_SHA512";
            break;
    }

    switch (curveId)
    {
        case cid_EC_P192:
            pCurveId = "cid_EC_P192";
            break;
        case cid_EC_P224:
            pCurveId = "cid_EC_P224";
            break;
        case cid_EC_P256:
            pCurveId = "cid_EC_P256";
            break;
        case cid_EC_P384:
            pCurveId = "cid_EC_P384";
            break;
        case cid_EC_P521:
            pCurveId = "cid_EC_P521";
            break;
    }

    FMGMT_fprintf(pFile, "|%-30s|%-30s|%-30s|\n",
            pKeyUsage,
            pSigScheme,
            pCurveId);

    eccTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(modNum);
    eccTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(modNum);
    eccTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(modNum);
    eccTapArgs.keyUsage = keyUsage;
    eccTapArgs.algKeyInfo.eccInfo.sigScheme = sigScheme;

    status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(
        MOC_ECC(gpHwAccelCtx) curveId, (void **) &pNewKey, RANDOM_rngFun,
        g_pRandomContext, akt_tap_ecc, &eccTapArgs);
    if (OK != status)
    {
        FMGMT_fprintf(pFile, "Key Creation - Failed to generate key\n");
        goto exit;
    }

    /* TPM2 requires key to be serialized before it can be used... */
#ifdef __ENABLE_DIGICERT_TPM2__
    tempKey.type = akt_tap_ecc;
    tempKey.key.pECC = pNewKey;

    status = CRYPTO_serializeAsymKey(
        &tempKey, mocanaBlobVersion2, &pSerializedKey, &serializedKeyLen);
    if (OK != status)
    {
        FMGMT_fprintf(pFile, "Key Creation - Failed to serialize key\n");
        goto exit;
    }

    (void) DIGI_FREE((void **) &pSerializedKey);
#endif

    status = CRYPTO_loadAsymmetricKey(&key, akt_tap_ecc, (void **) &pNewKey);
    if (OK != status)
    {
        FMGMT_fprintf(pFile, "Key Creation - Failed to load key\n");
        goto exit;
    }

    status = CRYPTO_INTERFACE_getECCPublicKey(&key, &pPubKey);
    if (OK != status)
    {
        FMGMT_fprintf(pFile, "Key Creation - Failed to get public key\n");
        goto exit;
    }

    FMGMT_fprintf(pFile, "Key Creation - Passed\n");

    switch (curveId)
    {
        case cid_EC_P192:
            inputLen = 20;
            break;

        case cid_EC_P224:
            inputLen = 28;
            break;

        case cid_EC_P256:
            inputLen = 32;
            break;

        case cid_EC_P384:
            inputLen = 48;
            break;

        case cid_EC_P521:
            inputLen = 64;
            break;
    }

    status = CRYPTO_INTERFACE_ECDSA_signDigestAux(
        MOC_ECC(gpHwAccelCtx) key.key.pECC, RANDOM_rngFun, g_pRandomContext,
        pInput, inputLen, pSig, sizeof(pSig), &sigLen);
    if (OK == status)
    {
        FMGMT_fprintf(pFile, "Sign Digest - Passed\n");

        status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux(
            MOC_ECC(gpHwAccelCtx) pPubKey, pInput, inputLen, pSig, sigLen/2,
            pSig + sigLen/2, sigLen/2, &vStatus);
        if (OK == status && OK == vStatus)
        {
            FMGMT_fprintf(pFile, "Verify Digest - Passed\n");
        }
        else
        {
            FMGMT_fprintf(pFile, "Verify Digest - Failed\n");
        }
    }
    else
    {
        FMGMT_fprintf(pFile, "Sign Digest - Failed\n");
    }

    inputLen = 100;
    for (i = 0; i < COUNTOF(pHashAlgs); i++)
    {
        switch (pHashAlgs[i])
        {
            case ht_sha1:
                pDigest = "SHA-1";
                break;
            case ht_sha224:
                pDigest = "SHA-224";
                break;
            case ht_sha256:
                pDigest = "SHA-256";
                break;
            case ht_sha384:
                pDigest = "SHA-384";
                break;
            case ht_sha512:
                pDigest = "SHA-512";
                break;
        }

        status = CRYPTO_INTERFACE_ECDSA_signMessageExt(
            MOC_ECC(gpHwAccelCtx) key.key.pECC, RANDOM_rngFun, g_pRandomContext,
            pHashAlgs[i], pInput, inputLen, pSig, sizeof(pSig), &sigLen, NULL);
        if (OK == status)
        {
            FMGMT_fprintf(pFile, "Sign Message (%s) - Passed\n", pDigest);

            status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt(
                MOC_ECC(gpHwAccelCtx) pPubKey, pHashAlgs[i], pInput, inputLen,
                pSig, sigLen, &vStatus, NULL);
            if (OK == status && OK == vStatus)
            {
                FMGMT_fprintf(pFile, "Verify Message (%s) - Passed\n", pDigest);
            }
            else
            {
                FMGMT_fprintf(pFile, "Verify Message (%s) - Failed\n", pDigest);
            }
        }
        else
        {
            FMGMT_fprintf(pFile, "Sign Message (%s) - Failed\n", pDigest);
        }
    }

exit:

    (void) CRYPTO_uninitAsymmetricKey(&key, NULL);

    if (NULL != pNewKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pNewKey);
    }

    if (NULL != pPubKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pPubKey);
    }

    return;
}

static void testSignVerifyTapPrint(ubyte4 modNum)
{
    FileDescriptor pFile = NULL;
    ubyte4 i, j, k;
    TAP_KEY_USAGE pKeyUsages[] = {
        TAP_KEY_USAGE_UNDEFINED,
        TAP_KEY_USAGE_SIGNING,
        TAP_KEY_USAGE_DECRYPT,
        TAP_KEY_USAGE_GENERAL,
        TAP_KEY_USAGE_ATTESTATION,
        TAP_KEY_USAGE_STORAGE
    };
    TAP_SIG_SCHEME pSigScheme[] = {
        TAP_SIG_SCHEME_NONE,
        TAP_SIG_SCHEME_ECDSA_SHA1,
        TAP_SIG_SCHEME_ECDSA_SHA224,
        TAP_SIG_SCHEME_ECDSA_SHA256,
        TAP_SIG_SCHEME_ECDSA_SHA384,
        TAP_SIG_SCHEME_ECDSA_SHA512
    };
    ubyte4 pCurveIds[] = {
        cid_EC_P192,
        cid_EC_P224,
        cid_EC_P256,
        cid_EC_P384,
        cid_EC_P521
    };

    FMGMT_fopen("tap_ecc_key_features.txt", "w", &pFile);

    printf("Testing TAP Capabilities for module: %d\n", modNum);
    printf("====================================================\n");
    printf("|%-30s|%-30s|%-30s|\n",
            "TAP_KEY_USAGE",
            "TAP_SIG_SCHEME",
            "EC Curve ID");
    for (i = 0; i < COUNTOF(pKeyUsages); i++)
    {
        for (j = 0; j < COUNTOF(pSigScheme); j++)
        {
            for (k = 0; k < COUNTOF(pCurveIds); k++)
            {
                testSignVerifyTapPrintSingle(pFile, modNum, pKeyUsages[i], pSigScheme[j], pCurveIds[k]);
            }
        }
    }

exit:

    FMGMT_fclose(&pFile);

    return;
}

#endif /* __ENABLE_DIGICERT_UNITTEST_CI_TAP_PRINT__ */

#ifdef __ENABLE_DIGICERT_GET_KEY_BY_ID_TESTS__
static int testGetKeyById(ubyte4 modNum, ubyte4 curveId, ubyte *pId, ubyte4 idLen)
{
    AsymmetricKey key = {0};
    ECCKey *pPubKey = NULL;
    int retVal = 0;
    MSTATUS status = 0;
    ubyte4 i = 0;

    ubyte pDigest[64] = {0}; /* big enough for any sigest size */
    ubyte4 digestLen = 0;
    ubyte pSig[132] = {0}; /* big enough for any key size */
    ubyte4 sigLen = 0;
    ubyte4 vStatus = 1;

    TAP_KeyInfo keyInfo = {0};
    keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
    keyInfo.algKeyInfo.eccInfo.sigScheme  = TAP_SIG_SCHEME_NONE;

    ubyte *pSerializedKey = NULL;
    ubyte4 serializedKeyLen = 0;

    for (i = 0; i < sizeof(pDigest); ++i)
    {
        pDigest[i] = (ubyte) ((17 * (i + 1)) & 0xff);
    }

    status = CRYPTO_initAsymmetricKey(&key);
    retVal += UNITTEST_STATUS(curveId, status);
    if (OK != status)
        goto exit;

    switch (curveId)
    {
        case cid_EC_P192:
            digestLen = 20;
            break;

        case cid_EC_P224:
            digestLen = 28;
            break;

        case cid_EC_P256:
            digestLen = 32;
            break;

        case cid_EC_P384:
            digestLen = 48;
            break;

        case cid_EC_P521:
            digestLen = 64;
            break;
    }

    status = CRYPTO_INTERFACE_TAP_serializeKeyById(TAP_EXAMPLE_getTapContext(modNum), 
                                                   TAP_EXAMPLE_getEntityCredentialList(modNum), 
                                                   TAP_EXAMPLE_getCredentialList(modNum),
                                                   &keyInfo, (ubyte *) pId, idLen, mocanaBlobVersion2, 
                                                   &pSerializedKey, &serializedKeyLen);
    retVal += UNITTEST_STATUS(curveId, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(gpHwAccelCtx) pSerializedKey, serializedKeyLen, NULL, &key);
    retVal += UNITTEST_STATUS(curveId, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_ECDSA_signDigestAux (MOC_ECC(gpHwAccelCtx) key.key.pECC, RANDOM_rngFun, g_pRandomContext, pDigest, digestLen, pSig, sizeof(pSig), &sigLen);
    retVal += UNITTEST_STATUS(curveId, status);
    if (OK != status)
        goto exit;
 
    status = CRYPTO_INTERFACE_getECCPublicKey(&key, &pPubKey);
    retVal += UNITTEST_STATUS(curveId, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux (MOC_ECC(gpHwAccelCtx) pPubKey, pDigest, digestLen,
                                                              pSig, sigLen/2, pSig + sigLen/2, sigLen/2, &vStatus);
    retVal += UNITTEST_STATUS(curveId, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(curveId, vStatus, 0);

exit:
   
    if (NULL != pSerializedKey)
    {
        (void) DIGI_FREE((void** ) &pSerializedKey);
    }

    (void) CRYPTO_uninitAsymmetricKey(&key, NULL);

    if (NULL != pPubKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pPubKey);
    }

    return retVal;
}
#endif /* __ENABLE_DIGICERT_GET_KEY_BY_ID_TESTS__ */
#endif /* __ENABLE_DIGICERT_TAP__ */

int crypto_interface_ecc_unit_test_init()
{

    MSTATUS status = ERR_NULL_POINTER;
    int retVal = 0;
    int i,j;

    InitMocanaSetupInfo setupInfo = {
        .MocSymRandOperator = NULL,
        .pOperatorInfo = NULL,
        /**********************************************************
         *************** DO NOT USE MOC_NO_AUTOSEED ***************
         ***************** in any production code. ****************
         **********************************************************/
        .flags = MOC_NO_AUTOSEED,
        .pStaticMem = NULL,
        .staticMemSize = 0,
        .pDigestOperators = NULL,
        .digestOperatorCount = 0,
        .pSymOperators = NULL,
        .symOperatorCount = 0,
        .pKeyOperators = NULL,
        .keyOperatorCount = 0
    };

/* Config files like pkcs_smp.conf have to match the module numbers given in the list below */
#if defined(__ENABLE_DIGICERT_GET_KEY_BY_ID_TESTS__) && defined(__ENABLE_DIGICERT_DIGICERT_SSM__) && defined(__ENABLE_DIGICERT_SOFTHSM_TEST_SET__)
    ubyte4 pModNums[2] = {1, 2};
    ubyte4 numMods = 2;
#else
    ubyte4 pModNums[1] = {1};
    ubyte4 numMods = 1;
#endif

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

#if ( defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && defined(__ENABLE_DIGICERT_ECC_P192_MBED__) ) \
 || ( !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && defined(__ENABLE_DIGICERT_ECC_P192__) )

    /* Test P192 */
    status = testEccDeserializationFormats(cid_EC_P192);
    if (OK != status)
    {
        retVal++;
    }

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 192;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p192); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p192+i, cid_EC_P192, gpP_192_Point, sizeof(gpP_192_Point));
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

    retVal += testSimpleGetMethods(cid_EC_P192);

    retVal += testErrorCases(cid_EC_P192, gpP_192, (ubyte4) sizeof(gpP_192), gpP_192_Point, sizeof(gpP_192_Point));

#endif /* Test P192  */

#if ( defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && defined(__ENABLE_DIGICERT_ECC_P224_MBED__) ) \
 || ( !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__DISABLE_DIGICERT_ECC_P224__) )

    /* Test P224 */
    status = testEccDeserializationFormats(cid_EC_P224);
    if (OK != status)
    {
        retVal++;
    }

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 224;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p224); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p224+i, cid_EC_P224, gpP_224_Point, sizeof(gpP_224_Point));
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

    retVal += testErrorCases(cid_EC_P224, gpP_224, (ubyte4) sizeof(gpP_224), gpP_224_Point, sizeof(gpP_224_Point));

#endif /* Test P224 */

#if ( defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && defined(__ENABLE_DIGICERT_ECC_P256_MBED__) ) \
 || ( !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__DISABLE_DIGICERT_ECC_P256__) ) \
 || defined(__ENABLE_DIGICERT_ECC_P256_OPERATOR__)

    /* Test P256 */
    status = testEccDeserializationFormats(cid_EC_P256);
    if (OK != status)
    {
        retVal++;
    }

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 256;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p256); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p256+i, cid_EC_P256, gpP_256_Point, sizeof(gpP_256_Point));
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

    retVal += testErrorCases(cid_EC_P256, gpP_256, (ubyte4) sizeof(gpP_256), gpP_256_Point, sizeof(gpP_256_Point));

#endif /* Test P256 */

#if ( defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && defined(__ENABLE_DIGICERT_ECC_P384_MBED__) ) \
 || ( !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__DISABLE_DIGICERT_ECC_P384__) )

    /* Test P384 */
    status = testEccDeserializationFormats(cid_EC_P384);
    if (OK != status)
    {
        retVal++;
    }

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 384;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p384); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p384+i, cid_EC_P384, gpP_384_Point, sizeof(gpP_384_Point));
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

    retVal += testErrorCases(cid_EC_P384, gpP_384, (ubyte4) sizeof(gpP_384), gpP_384_Point, sizeof(gpP_384_Point));

#endif /* Test P384 */

#if ( defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && defined(__ENABLE_DIGICERT_ECC_P521_MBED__) ) \
 || ( !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) && !defined(__DISABLE_DIGICERT_ECC_P521__) )

    /* Test P521 */
    status = testEccDeserializationFormats(cid_EC_P521);
    if (OK != status)
    {
        retVal++;
    }

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 521;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p521); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p521+i, cid_EC_P521, gpP_521_Point, sizeof(gpP_521_Point));
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

    retVal += testErrorCases(cid_EC_P521, gpP_521, (ubyte4) sizeof(gpP_521), gpP_521_Point, sizeof(gpP_521_Point));

#endif /* Test P521 */

#ifdef __ENABLE_DIGICERT_TAP__
    status = TAP_EXAMPLE_init(pModNums, numMods);
    if (OK != status)
    {
        retVal += 1;
        goto exit;
    }

    for (j = 0; j < numMods; j++)
    {

#ifndef __ENABLE_DIGICERT_TAP_EXTERN__
        if (2 == pModNums[j])
        {

            status = CRYPTO_INTERFACE_registerTapCtxCallback(TAP_EXAMPLE_getCtx2);
            retVal += UNITTEST_STATUS(0, status);
            if (OK != status)
                goto exit;
        }
#endif

#if defined(__ENABLE_DIGICERT_UNITTEST_CI_TAP_PRINT__)
        testSignVerifyTapPrint(pModNums[j]);
#endif

#if defined(__ENABLE_DIGICERT_CLOUDHSM_TEST_SET__) && !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
        /* CloudHSM only support P256 and P384 for Sign/Verify ops */
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_none, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha256, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_none, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_sha384, FALSE);

        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_none, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha256, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_none, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_sha384, TRUE);
#elif defined(__ENABLE_DIGICERT_TPM2__)
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha256, FALSE);
   /*   As of now tpm2's hash is fixed based on the curve
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha384, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha512, FALSE);
   */
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha256, TRUE);
   /*   retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha384, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha512, TRUE);
   */
#elif !defined(__ENABLE_DIGICERT_DIGICERT_SSM__)
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P192, ht_none, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P192, ht_sha1, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P192, ht_sha224, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P192, ht_sha256, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P192, ht_sha384, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P192, ht_sha512, FALSE);
        
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P224, ht_none, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P224, ht_sha1, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P224, ht_sha224, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P224, ht_sha256, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P224, ht_sha384, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P224, ht_sha512, FALSE);

        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_none, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha1, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha224, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha256, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha384, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha512, FALSE);

        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_none, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_sha1, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_sha224, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_sha256, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_sha384, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_sha512, FALSE);

        retVal += testSignVerifyTap(pModNums[j], cid_EC_P521, ht_none, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P521, ht_sha1, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P521, ht_sha224, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P521, ht_sha256, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P521, ht_sha384, FALSE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P521, ht_sha512, FALSE);

        retVal += testSignVerifyTap(pModNums[j], cid_EC_P192, ht_none, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P192, ht_sha1, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P192, ht_sha224, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P192, ht_sha256, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P192, ht_sha384, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P192, ht_sha512, TRUE);
        
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P224, ht_none, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P224, ht_sha1, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P224, ht_sha224, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P224, ht_sha256, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P224, ht_sha384, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P224, ht_sha512, TRUE);

        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_none, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha1, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha224, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha256, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha384, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P256, ht_sha512, TRUE);

        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_none, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_sha1, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_sha224, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_sha256, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_sha384, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P384, ht_sha512, TRUE);

        retVal += testSignVerifyTap(pModNums[j], cid_EC_P521, ht_none, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P521, ht_sha1, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P521, ht_sha224, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P521, ht_sha256, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P521, ht_sha384, TRUE);
        retVal += testSignVerifyTap(pModNums[j], cid_EC_P521, ht_sha512, TRUE);
#endif
    }

#ifdef __ENABLE_DIGICERT_GET_KEY_BY_ID_TESTS__
#ifdef __ENABLE_DIGICERT_SOFTHSM_TEST_SET__
    {
        /* To enable these tests, define the above flag, and keys need to be generated with appropriate IDs. For example
           using the OpenSC pkcs11-tool, run...

pkcs11-tool --module=/usr/local/lib/softhsm/libsofthsm2.so --token-label myToken --login --pin 0000 --keypairgen --mechanism ECDSA-KEY-PAIR-GEN --key-type EC:secp192r1 --usage-sign --label mykey --id 0192
pkcs11-tool --module=/usr/local/lib/softhsm/libsofthsm2.so --token-label myToken --login --pin 0000 --keypairgen --mechanism ECDSA-KEY-PAIR-GEN --key-type EC:secp224r1 --usage-sign --label mykey --id 24
pkcs11-tool --module=/usr/local/lib/softhsm/libsofthsm2.so --token-label myToken --login --pin 0000 --keypairgen --mechanism ECDSA-KEY-PAIR-GEN --key-type EC:secp256r1 --usage-sign --label mykey --id 0256
pkcs11-tool --module=/usr/local/lib/softhsm/libsofthsm2.so --token-label myToken --login --pin 0000 --keypairgen --mechanism ECDSA-KEY-PAIR-GEN --key-type EC:secp384r1 --usage-sign --label mykey --id 0384aabbccddeeff
pkcs11-tool --module=/usr/local/lib/softhsm/libsofthsm2.so --token-label myToken --login --pin 0000 --keypairgen --mechanism ECDSA-KEY-PAIR-GEN --key-type EC:secp521r1 --usage-sign --label mykey --id 0521aabbccddeeff1234

        */
        ubyte pId_192[2] = {0x01, 0x92};
        ubyte pId_224[1] = {0x24};
        ubyte pId_256[2] = {0x02, 0x56};
        ubyte pId_384[8] = {0x03, 0x84, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
        ubyte pId_521[10] = {0x05, 0x21, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x12, 0x34};

        retVal += testGetKeyById(1, cid_EC_P192, pId_192, sizeof(pId_192));
        retVal += testGetKeyById(1, cid_EC_P224, pId_224, sizeof(pId_224));
        retVal += testGetKeyById(1, cid_EC_P256, pId_256, sizeof(pId_256));
        retVal += testGetKeyById(1, cid_EC_P384, pId_384, sizeof(pId_384));
        retVal += testGetKeyById(1, cid_EC_P521, pId_521, sizeof(pId_521));
    }
#endif
#ifdef __ENABLE_DIGICERT_DIGICERT_SSM__
    /* To enable these tests, define the above flags, and make sure there exists key pairs with the following ID */
    {
        ubyte pIddgct_256[37] = "87a3c1bd-e482-4bed-ae9d-8b93bfe396f8";

        status = CRYPTO_INTERFACE_registerTapCtxCallback(TAP_EXAMPLE_getCtx2);
        retVal += UNITTEST_STATUS(0, status);
        if (OK != status)
            goto exit;

        retVal += testGetKeyById(2, cid_EC_P256, pIddgct_256, 36);
    }
#endif
#endif /* __ENABLE_DIGICERT_GET_KEY_BY_ID_TESTS__ */
#endif /* __ENABLE_DIGICERT_TAP__ */

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

#ifdef __ENABLE_DIGICERT_TAP__
    TAP_EXAMPLE_clean();
#endif

    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);

    DBG_DUMP
    return retVal;
}
