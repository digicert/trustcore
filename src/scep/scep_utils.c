/**
 * @file  scep_utils.c
 * @brief SCEP -- Simple Certificate Enrollment Protocol Utilities
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.
 *
 */
#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_SCEP_CLIENT__))

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../asn1/oiddefs.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/crypto.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/pkcs10.h"

/*---------------------------------------------------------------------------*/

/* the numbers come from last octet of OID */
typedef struct oidToDescriptor
{
    const ubyte* oid;
    sbyte* desc; /* NULL terminated string */
    ubyte4 len;
} oidToDescriptor;

/* has to maintain same order as nameType; value comes from http://www.iana.org/assignments/ldap-parameters */
oidToDescriptor nameStr[] =
{
    {commonName_OID, (sbyte*)"cn", 2},
    {countryName_OID, (sbyte*)"c", 1},
    {localityName_OID, (sbyte*)"L", 1},
    {stateOrProvinceName_OID, (sbyte*)"st", 2},
    {organizationName_OID, (sbyte*)"o", 1},
    {organizationalUnitName_OID, (sbyte*)"ou", 2},
    {pkcs9_emailAddress_OID, (sbyte*)"mail", 4}
};
#define NUM_NAMESTR    (sizeof(nameStr)/sizeof(oidToDescriptor))

/*---------------------------------------------------------------------------*/

extern MSTATUS
SCEP_UTILS_integerToString(ubyte *number, ubyte4 numberLen, sbyte* pBuf, ubyte4 bufLen)
{
    MSTATUS status = OK;
    ubyte4 i;

    if (numberLen > bufLen + 1)
    {
        status = ERR_SCEP; /* shouldn't happen */
        goto exit;
    }

    for (i = 0; i < numberLen; i++)
    {
        sbyte ch1 = (number[i] & 0xF0) >> 4;
        sbyte ch2 = number[i] & 0x0F;
        if (ch1 < 0x0a)
        {
            *(pBuf+i*2) = '0' + ch1;
        } else
        {
            *(pBuf+i*2) = 'a' + (ch1 - 0x0a);
        }
        if (ch2 < 0x0a)
        {
            *(pBuf+i*2 + 1) = '0' + ch2;
        } else
        {
            *(pBuf+i*2 + 1) = 'a' + (ch2- 0x0a);
        }
    }
    *(pBuf+numberLen*2) = '\0';
exit:
    return status;
}

#endif /*#if (defined(__ENABLE_DIGICERT_SCEP_CLIENT__)) */
