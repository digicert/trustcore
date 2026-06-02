/**
 * @file  eap_avp.c
 * @brief EAP AVP handling implementation
 *
 * @details    Attribute-Value Pair processing
 * @flags      Compilation flags required:
 *     To enable this file's functions, one of the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__
 *     +   \c \__ENABLE_DIGICERT_EAP_AUTH__
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
 *
 */

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../crypto/md5.h"
#include "../common/redblack.h"
#include "../common/timer.h"
#include "../eap/eap.h"
#include "../eap/eap_auth.h"
#include "../eap/eap_md5.h"
#include "../eap/eap_session.h"
#include "../eap/eap_avp.h"


/*------------------------------------------------------------------*/

extern MSTATUS
AVP_getAttributeByType(ubyte *pPkt, ubyte4 pktLen, ubyte4 type,
                       ubyte *pFlags, ubyte4 *pVendorId,
                       ubyte **ppValue, ubyte4 *pLength)
{
    ubyte*  p;
    ubyte*  ptr;
    ubyte*  opl;
    ubyte4  len;
    ubyte4  temp;
    sbyte4  status = ERR_NOT_FOUND;

    *ppValue = NULL;
    *pLength = 0;
    *pFlags = 0;
    *pVendorId = 0;

    if (NULL == pPkt)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    p = pPkt;
    opl = p + pktLen;

    while (p < opl)
    {
        ptr = p + AVP_LENGTH_OFFSET;
        len = *ptr++;
        len = (len << 8) + *ptr++;
        len = (len << 8) + *ptr++;

        if (len < AVP_MIN_LEN)
        {
            status = ERR_BAD_LENGTH;
            break;
        }

        if (type == *p)
        {
            *pFlags = *((ubyte4 *)(p + AVP_FLAGS_OFFSET));
            if (*pFlags & AVP_VENDOR_ID_FLAG)
            {
                /* Vendor Id is present */
                *pLength = len - AVP_CODE_PLUS_FLAGS_PLUS_LEN_SIZE
                               - AVP_VENDOR_ID_FIELD_SIZE;
                *ppValue = p + AVP_WITH_VENDOR_ID_DATA_OFFSET;
                ptr = p + AVP_VENDOR_ID_OFFSET;
                temp = *ptr++;
                temp = (temp << 8) + *ptr++;
                temp = (temp << 8) + *ptr++;
                temp = (temp << 8) + *ptr++;
                *pVendorId = temp;
            }
            else
            {
                *pLength = len - AVP_CODE_PLUS_FLAGS_PLUS_LEN_SIZE;
                *ppValue = p + AVP_DATA_OFFSET;
            }
            status = OK;
            break;
        }

        p += len;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
AVP_getAttributeByIndex(ubyte *pPkt, ubyte4 pktLen, ubyte index,
                        ubyte4 *pType, ubyte *pFlags, ubyte4 *pVendorId,
                        ubyte **ppValue, ubyte4 *pLength)
{
    ubyte*  p;
    ubyte*  ptr;
    ubyte*  opl;
    ubyte4  len;
    ubyte4  temp;
    ubyte4  i = 0;
    MSTATUS status = ERR_NOT_FOUND;

    *pType = 0;
    *ppValue = NULL;
    *pLength = 0;
    *pFlags = 0;
    *pVendorId = 0;

    if (NULL == pPkt)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    p = pPkt;
    opl = p + pktLen;

    while (p < opl)
    {
        ptr = p + AVP_LENGTH_OFFSET;
        len = *ptr++;
        len = (len << 8) + *ptr++;
        len = (len << 8) + *ptr++;

        if (len < AVP_MIN_LEN)
        {
            status = ERR_BAD_LENGTH;
            break;
        }

        if (i == index)
        {
            temp = *p++;
            temp = (temp << 8) + *p++;
            temp = (temp << 8) + *p++;
            temp = (temp << 8) + *p++;
            *pType = temp;

            *pFlags = *((ubyte *)(p));
            if (*pFlags & AVP_VENDOR_ID_FLAG)
            {
                /* Vendor Id is present */
                *pLength = len - AVP_CODE_PLUS_FLAGS_PLUS_LEN_SIZE
                               - AVP_VENDOR_ID_FIELD_SIZE;
                *ppValue = p + AVP_WITH_VENDOR_ID_DATA_OFFSET - 4;
                ptr = p + AVP_VENDOR_ID_OFFSET - 4;
                temp = *ptr++;
                temp = (temp << 8) + *ptr++;
                temp = (temp << 8) + *ptr++;
                temp = (temp << 8) + *ptr++;
                *pVendorId = temp;
            }
            else
            {
                *pLength = len - AVP_CODE_PLUS_FLAGS_PLUS_LEN_SIZE;
                *ppValue = p + AVP_DATA_OFFSET - 4;
            }
            status = OK;
            break;
        }

        if (len % 4)
            len += 4 - (len % 4);

        p += len;
        i++;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern sbyte4
AVP_appendAttribute(ubyte *pBuf, ubyte4 type, ubyte flags, ubyte4 vendorId,
                       ubyte *pData, ubyte4 dataLength, ubyte4 *length)
{
    sbyte4    status;
    ubyte*    p;
    ubyte4    len;
    ubyte     i;
    ubyte     temp;

    if ((NULL == pBuf) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == type) || (0 == dataLength))
    {
        status = ERR_EAP_AVP_BAD_PARAM;
        goto exit;
    }

    p = pBuf;

    *p++ = (ubyte)(type >> 24);
    *p++ = (ubyte)(type >> 16);
    *p++ = (ubyte)(type >> 8);
    *p++ = (ubyte)(type);

    len = dataLength + AVP_CODE_PLUS_FLAGS_PLUS_LEN_SIZE;

    if(vendorId)
    {
        len += AVP_VENDOR_ID_FIELD_SIZE;
        flags |= AVP_VENDOR_ID_FLAG;
    }

    *p++ = (ubyte)(flags);

    *p++ = (ubyte)(len >> 16);
    *p++ = (ubyte)(len >> 8);
    *p++ = (ubyte)(len);

    if(vendorId)
    {
        *p++ = (ubyte)(vendorId >> 24);
        *p++ = (ubyte)(vendorId >> 16);
        *p++ = (ubyte)(vendorId >> 8);
        *p++ = (ubyte)(vendorId);
    }

    DIGI_MEMCPY(p, pData, dataLength);
    p += dataLength;
    temp = len % 4;
    if(temp != 0)
    {
        temp = 4 - temp;
        /* Pad with 0s to a 4 byte boundary */
        for(i = 0; i < temp; i++)
        {
            *p++ = 0;
        }
    }

    *length = (ubyte4)(p - pBuf);

    status = OK;

 exit:
    return status;
}

#endif /* defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__) */
