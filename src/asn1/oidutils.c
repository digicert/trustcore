/*
 * oidutil.c
 *
 * OID utilities
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

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"

#include "../asn1/oidutils.h"


/*------------------------------------------------------------------*/

/*  Encode an integer using the OID encoding scheme
    the buffer must be large enough 32 bits /7 + 1 -> 5 bytes.
    The function returns the number of bytes used in the buffer.
*/
static ubyte4 EncodeOIDValue( ubyte4 value, ubyte* buffer)
{
    /* encode as 7 bit octets, the first bit is set to 1 for all octets
      except the last where it is set to 0 */
    /* pass 1 -> just put all the 7 bit octets in the buffer */
    ubyte4 k, j, i = 0;
    do
    {
       buffer[i++] = (ubyte) (value & 0x7F); /*7 bits*/
       value >>= 7;
    }
    while ( value );

    /* pass 2 reverse the octets */
    j = 0;  k = i-1;
    while ( j < k)
    {
        ubyte tmp = buffer[j];
        buffer[j] = buffer[k];
        buffer[k] = tmp;
        j++; k--;
    }
    /* pass 3 set high bit on octets except the last*/
    for (j = 0; j < i-1; ++j)
    {
        buffer[j] |= 0x80;
    }
    return i;
}


/*------------------------------------------------------------------*/

extern MSTATUS
BEREncodeOID( const sbyte* oidStr, byteBoolean* wildCard, ubyte** oid)
{
    ubyte scratch[30]; /* 30 should be more than enough 6 fields in the OID */
    ubyte4 value = 0;  /* current value to encode */
    ubyte4 offset = 0; /* current offset in the scratch buffer */
    sbyte first = 1;   /* flag used because the first two fields are encoded
                            as one */

    if (NULL == oidStr || NULL == wildCard || NULL == oid)
    {
        return ERR_NULL_POINTER;
    }

    *wildCard = 0;

    while (*oidStr)
    {
        /* check for wild char */
        if ('*' == *oidStr)
        {
            *wildCard = 1;
            break; /* done, ignore the rest */
        }
        /* add value -- only important for first 2 fields
         all these tricks because the first two values are encoded as one */
        value += DIGI_ATOL( oidStr, &oidStr);

        if (first)
        {
            first = 0;
            value *= 40;
        }
        else
        {
           offset += EncodeOIDValue( value, scratch + offset);
           value = 0; /* reset value */
        }

        if ( 0== *oidStr)
        {
            /* do nothing end of string */
        }
        else if ('.' == *oidStr)
        {
            ++oidStr;  /* jump over decimal separator */
        }
        else
        {
            /* error in format */
            return ERR_INVALID_ARG;
        }
    }

    *oid = (ubyte*) MALLOC( offset + 2);
    if (!(*oid))
    {
        return ERR_MEM_ALLOC_FAIL;
    }
    (*oid)[0] = 0x06;         /* OID */
    (*oid)[1] = (ubyte)offset;        /* size */
    DIGI_MEMCPY((*oid)+2, scratch, offset);

    return OK;
}


/*------------------------------------------------------------------*/

#ifdef __TESTOID__
/* TEST CODE BELOW */
#include <stdio.h>

int TestEncodedOID( char *s, char* expected)
{
    ubyte* oid = 0;
    ubyte4 i;
    int retVal;
    byteBoolean w;
    sbyte* generated = 0;

    printf("%s -> \n", s);
    printf("%s expected\n", expected);
    if (OK > BEREncodeOID(s, &w, &oid))
    {
        return 1;
    }
    for (i = 0; i < oid[1]+2; ++i)
    {
        printf("%02X ", oid[i]);
    }
    printf(" generated\n\n");

    /* string comparison */
    generated = (sbyte*) MALLOC( (oid[i] + 2) * 3);
    if (!generated)
    {
        if (oid) FREE( oid);
        return 1;
    }

    for (i = 0; i < oid[1]+2; ++i)
    {
        sprintf(generated + i * 3, "%02X ", oid[i]);
    }

    retVal = DIGI_STRCMP( (ubyte*) generated, (ubyte*) expected);

exit:

    FREE(generated);
    FREE(oid);
    return (0 == retVal) ? 0 : 1;
}

int OIDTests()
{
    /* note space at end for expected value -> cf. code TestEncodedOID*/
    int retVal = TestEncodedOID("1.2.840.113549.1.9.16.0.5", "06 0B 2A 86 48 86 F7 0D 01 09 10 00 05 ");
    retVal += TestEncodedOID("1.3.36.8.7.1.22", "06 06 2B 24 08 07 01 16 ");
    retVal += TestEncodedOID("2.16.840.1.113719.1.2.8.132", "06 0C 60 86 48 01 86 F8 37 01 02 08 81 04 ");
    /* pkcs7 data */
    retVal += TestEncodedOID("1.2.840.113549.1.7.1", "06 09 2A 86 48 86 F7 0D 01 07 01 ");
    /* pkcs7 signed data */
    retVal += TestEncodedOID("1.2.840.113549.1.7.2", "06 09 2A 86 48 86 F7 0D 01 07 02 ");

    /* wild chars */
    retVal += TestEncodedOID("1.3.36.8.7.1.*", "06 05 2B 24 08 07 01 ");
    retVal += TestEncodedOID("2.16.840.1.113719.1.2.8.*", "06 0A 60 86 48 01 86 F8 37 01 02 08 ");
    /* pkcs7 data */
    retVal += TestEncodedOID("1.2.840.113549.1.7.*", "06 08 2A 86 48 86 F7 0D 01 07 ");
    /* pkcs7 signed data */
    retVal += TestEncodedOID("1.2.840.113549.1.7.*", "06 08 2A 86 48 86 F7 0D 01 07 ");
    return retVal;
}

#endif

