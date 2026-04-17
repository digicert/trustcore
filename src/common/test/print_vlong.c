/*
 * print_vlong.c
 *
 * include this file to print the value of a vlong in a unittest log
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 */

/*---------------------------------------------------------------------------*/

/* make sure it's not compiled on its own by the test monkey
   but only when included by another file */
#if defined(__VLONG_HEADER__) && defined(__UNITTEST_HEADER__)

#define HEXCHAR(n) ((n < 0xA)? (n + '0'): (n - 10 + 'A'))

static void
print_vlong(const char* msg, const vlong* v)
{
    MSTATUS status;
    ubyte* buffer = NULL;
    sbyte4 bufferLen;
    sbyte4 i,j;
    sbyte outputBuffer[80];

    status = VLONG_byteStringFromVlong(v, NULL, &bufferLen);
    if (OK != status)
        goto exit;

    buffer = MALLOC( bufferLen+1);
    if ( !buffer)
        goto exit;

    status = VLONG_byteStringFromVlong(v, buffer, &bufferLen);
    if (OK != status)
        goto exit;

    unittest_write(msg);

    j = 0;
    for (i=0; i < bufferLen; ++i)
    {
        ubyte b, n;
        if ( j >= 70)
        {
            outputBuffer[j] = 0;
            unittest_write(outputBuffer);
            unittest_write("\n");
            j = 0;
        }

        b = buffer[i];

        n = (( b >> 4) & 0xF);
        outputBuffer[j++] = HEXCHAR(n);
        n = (b & 0xF);
        outputBuffer[j++] = HEXCHAR(n);
    }

    outputBuffer[j] = 0;
    unittest_write(outputBuffer);
    unittest_write("\n");

exit:
    
    if (NULL != buffer)
        (void) FREE(buffer);
}


#endif /* defined(__VLONG_HEADER__) && defined(__UNITTEST_HEADER__) */
