/*
 * utf8.c
 *
 * Code for handling UTF-8 values
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

#include "../common/utf8.h"

typedef struct
{
    int numBytes;
    struct
    {
        ubyte lowerLimit;
        ubyte upperLimit;
    } limits[4];
} Utf8Range;

static Utf8Range validRanges[] = 
{
    {1, { {0x00, 0x7F} } },
    {2, { {0xC2, 0xDF}, {0x80, 0xBF} } },
    {3, { {0xE0, 0xE0}, {0xA0, 0xBF}, {0x80, 0xBF} } }, /* E0 {80-9F} is not shortest encoding sequence */
    {3, { {0xE1, 0xEC}, {0x80, 0xBF}, {0x80, 0xBF} } }, /* Everything up to ED */
    {3, { {0xED, 0xED}, {0x80, 0x9F}, {0x80, 0xBF} } }, /* ED A0 is start of excluded range U+D800-U+DFFF */
    {3, { {0xEE, 0xEF}, {0x80, 0xBF}, {0x80, 0xBF} } }, /* U+E000 - U+7FFF */
    {4, { {0xF0, 0xF0}, {0x90, 0xBF}, {0x80, 0xBF}, {0x80, 0xBF} } }, /* F0 {80-9F} is not shortest encoding sequence */
    {4, { {0xF1, 0xF3}, {0x80, 0xBF}, {0x80, 0xBF}, {0x80, 0xBF} } },
    {4, { {0xF4, 0xF4}, {0x80, 0x8F}, {0x80, 0xBF}, {0x80, 0xBF} } }, /* F4 {90-FF} is reserved for utf-16 */

};

#define NUM_RANGES 9

extern MSTATUS UTF8_validateEncoding(
    ubyte *pData,
    ubyte4 dataLen,
    byteBoolean *pIsValid)
{
    MSTATUS status = OK;
    /* Assume 2 byte length because then we only have to check for 1, 3 and 4 byte lengths, which are all
     * on 4 bit boundaries. */
    ubyte numBytes = 2;
    ubyte valid = FALSE;
    ubyte i = 0;
    ubyte j = 0;
    ubyte b = 0;
    ubyte *pIter = pData;

    if (NULL == pData || NULL == pIsValid)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pIsValid = FALSE;

    do
    {
        /* Determine number of bytes in encoding */
        numBytes = 2;
        b = *pIter;
        if ((b & 0x80) == 0x00)
        {
            numBytes = 1;
        }
        else if ((b & 0xF0) == 0xF0)
        {
            numBytes = 4;
        }
        else if ((b & 0xE0) == 0xE0)
        {
            numBytes = 3;
        }

        if (numBytes > dataLen)
        {
            goto exit;
        }

        /* Search the known valid ranges */
        for (i = 0; i < NUM_RANGES; i++)
        {
            if (validRanges[i].numBytes == numBytes)
            {
                valid = TRUE;
                for (j = 0; j < numBytes; j++)
                {
                    if ( (pIter[j] < validRanges[i].limits[j].lowerLimit) ||
                         (pIter[j] > validRanges[i].limits[j].upperLimit) )
                    {
                        valid = FALSE;
                        break;
                    }
                }
            }

            if (TRUE == valid)
                break;
        }

        if (FALSE == valid)
        {
            goto exit;
        }

        pIter += numBytes;
        dataLen -= numBytes;

    } while (dataLen > 0);

    *pIsValid = TRUE;

exit:

    return status;
}