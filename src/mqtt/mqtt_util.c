/*
 * mqtt_util.c
 *
 * MQTT utility methods
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

#ifdef __ENABLE_MQTT_CLIENT__

#include "mqtt_client.h"
#include "mqtt_client_priv.h"

#define MAX_VARIABLE_BYTE_INT       (268435455)

/* Encodes variable byte integer according to MQTT v5.0 Spec Section 1.5.5
 *
 *   do
 *      encodedByte = X MOD 128
 *      X = X DIV 128
 *      // if there are more data to encode, set the top bit of this byte
 *      if (X > 0)
 *         encodedByte = encodedByte OR 128
 *      endif
 *      'output' encodedByte
 *   while (X > 0)
 *
 * where X is the integer to encode
 */
MSTATUS MQTT_encodeVariableByteInt(ubyte4 val, ubyte pRes[4], ubyte *pBytesUsed)
{
    MSTATUS status;
    ubyte encodedByte;
    ubyte bytesEncoded = 0;

    if (val > MAX_VARIABLE_BYTE_INT)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if (NULL != pRes)
    {
        do
        {
            /* encodedByte = X MOD 128 */
            encodedByte = val & 0x7F;
            /* X = X DIV 128 */
            val = val >> 7;
            if (val > 0)
                encodedByte |= 0x80;

            pRes[bytesEncoded++] = encodedByte;

        } while (val > 0);
    }
    else
    {
        /* Only need to calculate the number of bytes the encoding requires */
        if (val < 16384)
        {
            if (val < 128)
                bytesEncoded = 1;
            else
                bytesEncoded = 2;
        }
        else
        {
            if (val < 2097152)
                bytesEncoded = 3;
            else
                bytesEncoded = 4;
        }
    }

    *pBytesUsed = bytesEncoded;
    status = OK;

exit:

    return status;
}

/*
 * Encodes variable byte integer according to MQTT v5.0 Spec Section 1.5.5
 *
 * multiplier = 1
 * 
 * value = 0
 * 
 * do
 * 
 *    encodedByte = 'next byte from stream'
 * 
 *    value += (encodedByte AND 127) * multiplier
 * 
 *    if (multiplier > 128*128*128)
 * 
 *       throw Error(Malformed Variable Byte Integer)
 * 
 *    multiplier *= 128
 * 
 * while ((encodedByte AND 128) != 0)*/
MSTATUS MQTT_decodeVariableByteInt(
    ubyte *pBuf, ubyte4 bufLen, ubyte4 *pVal, ubyte *pNumBytesUsed)
{
    MSTATUS status;
    ubyte4 multiplier = 1;
    ubyte4 value = 0;
    ubyte encoded = 0;
    ubyte numBytes = 0;

    if ( (NULL == pBuf) || (NULL == pVal) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    do
    {
        if (bufLen < 1)
        {
            status = ERR_MQTT_MALFORMED_PACKET;
            goto exit;
        }
        encoded = *pBuf;
        pBuf++;
        numBytes++;
        bufLen--;
        value += (encoded & 127) * multiplier;
        if (multiplier > 128*128*128)
        {
            status = ERR_UNKNOWN_DATA;
            goto exit;
        }

        multiplier *= 128;
    }
    while((encoded & 128) != 0);

    status = OK;
    if (NULL != pNumBytesUsed)
    {
        *pNumBytesUsed = numBytes;
    }
    
    *pVal = value;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

byteBoolean isValidUtf8(ubyte *pData, ubyte4 dataLen)
{
    byteBoolean isValid = FALSE;

    (void) UTF8_validateEncoding(pData, dataLen, &isValid);

    return isValid;
}

/*----------------------------------------------------------------------------*/


#endif