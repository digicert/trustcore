/*
 * cms_aux.c
 *
 * CMS Auxiliary routines
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

#include "../common/moptions.h"
#ifdef __ENABLE_DIGICERT_CMS__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../crypto/crypto.h"
#include "../crypto/rsa.h"
#include "../crypto/dsa.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../harness/harness.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/des.h"
#include "../crypto/aes.h"
#include "../crypto/three_des.h"
#include "../crypto/arc4.h"
#include "../crypto/rc4algo.h"
#include "../crypto/arc2.h"
#include "../crypto/rc2algo.h"
#include "../crypto/aes_keywrap.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../crypto/pkcs_common.h"
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"
#include "../crypto/ansix9_63_kdf.h"
#include "../crypto/pkcs7.h"

#include "../crypto/cms.h"
#include "../crypto/cms_aux.h"

typedef struct OIDToName
{
    const ubyte* oid;
    const char* name;
} OIDToName;

static OIDToName mAlgoOIDToNames[] =
{
    { aes128CBC_OID, "AES 128 CBC" },
    { aes192CBC_OID, "AES 192 CBC" },
    { aes256CBC_OID, "AES 256 CBC" },
    { desEDE3CBC_OID, "3DES CBC" },
    { rc4_OID, "RC4" },
    { desCBC_OID, "DES CBC" },
    { rc2CBC_OID, "RC2 CBC" },
};

extern WalkerStep CMS_Sig_signerInfoToReceiptRequestWalkInstructions[]; /* in cms.inc */

/*-------------------------------------------------------------------------*/

extern MSTATUS
CMS_AUX_getReceiptRequest( ASN1_ITEMPTR pSignerInfo, CStream cs,
                           ASN1_ITEMPTR* ppReceiptRequest)
{
    MSTATUS status;

    if (!pSignerInfo || !ppReceiptRequest)
        return ERR_NULL_POINTER;

    if (OK > ( status = ASN1_WalkTree(pSignerInfo, cs,
             CMS_Sig_signerInfoToReceiptRequestWalkInstructions,
             ppReceiptRequest)))
    {
        goto exit;
    }

exit:

    return status;
}


/*-------------------------------------------------------------------------*/

static MSTATUS
CMS_AUX_getSequenceOfGeneralNames( ASN1_ITEMPTR pSeq, CStream cs,
                                  const ubyte*** res, sbyte4* num)
{
    ASN1_ITEMPTR pTemp, pTag;
    ubyte** data = 0;
    ubyte* d;
    ubyte** p;
    ubyte4 numStr = 0;
    ubyte4 totalStrLen = 0;
    MSTATUS status = OK;

    *num = 0;
    /* count the number of rfc822 children, i.e. SEQUENCE with a [1] child */
    pTemp = ASN1_FIRST_CHILD( pSeq);
    while (pTemp)
    {
        ASN1_GoToTag( pTemp, 1, &pTag);
        if (pTag)
        {
            numStr++;
            totalStrLen += pTag->length + 1; /* Null terminator */
        }

        pTemp = ASN1_NEXT_SIBLING(pTemp);
    }

    data = (ubyte**) MALLOC( (numStr * (sizeof(ubyte *))) + totalStrLen);
    if (!data)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    p = data; /* initialize name pointer */
    /* where we will copy the string */
    d = (ubyte*) (data + numStr);
    pTemp = ASN1_FIRST_CHILD( pSeq);
    while (pTemp)
    {
        ASN1_GoToTag( pTemp, 1, &pTag);
        if (pTag)
        {
            *p++ = d;
            CS_seek(cs, pTag->dataOffset, MOCANA_SEEK_SET);
            CS_read( d, pTag->length, 1, cs);
            d += pTag->length;
            *d++ = 0x00; /* Null terminator */
        }

        pTemp = ASN1_NEXT_SIBLING(pTemp);
    }

    *num = numStr;
    *res = (const ubyte**) data;
    data = 0;

exit:

    if (data)
    {
        FREE( data);
    }
    return status;
}


/*-------------------------------------------------------------------------*/

extern MSTATUS
CMS_AUX_getReceiptRequestFrom( ASN1_ITEMPTR pReceiptRequest, CStream cs,
                                const ubyte*** from, sbyte4* num)
{
    MSTATUS status;
    ubyte4 tag;
    ubyte value;
    ASN1_ITEMPTR pTemp;

    if (!pReceiptRequest || !from || !num)
    {
        return ERR_NULL_POINTER;
    }

    if (OK > ( status = ASN1_GetNthChild(pReceiptRequest, 2, &pTemp)))
    {
        goto exit;
    }

    /* what tag is it ? */
    if (OK > ( status = ASN1_GetTag( pTemp, &tag)))
    {
        goto exit;
    }

    switch (tag)
    {
    case 0:
        /* value of the tag is an integer 0 or 1  i.e. length = 1*/
        if (pTemp->length != 1)
        {
            status = ERR_PKCS7_INVALID_ITEM_VALUE;
            goto exit;
        }
        CS_seek( cs, pTemp->dataOffset, MOCANA_SEEK_SET);
        if (OK > (status = CS_getc( cs, &value)))
        {
            goto exit;
        }
        if ( 0 == value) /* all */
        {
            *num  = -1;
        }
        else if ( 1 == value) /* first tier */
        {
            *num = 0;
        }
        else
        {
            status = ERR_PKCS7_INVALID_ITEM_VALUE;
            goto exit;
        }
        break;

    case 1:
        /* SEQUENCE of GeneralNames */
        if (OK > ( status =
                CMS_AUX_getSequenceOfGeneralNames(pTemp, cs, from, num)))
        {
            goto exit;
        }
        break;

    default:
        status = ERR_PKCS7_INVALID_TAG_VALUE;
        goto exit;
        break;
    }

exit:

    return status;
}


/*-------------------------------------------------------------------------*/

extern MSTATUS
CMS_AUX_getReceiptRequestTo( ASN1_ITEMPTR pReceiptRequest, CStream cs,
                                const ubyte*** to, sbyte4* num)
{
    MSTATUS status;
    ASN1_ITEMPTR pTemp;

    if (!pReceiptRequest || !to || !num)
    {
        return ERR_NULL_POINTER;
    }

    if (OK > ( status = ASN1_GetNthChild(pReceiptRequest, 3, &pTemp)))
    {
        goto exit;
    }

    if (OK > ( status = ASN1_VerifyType(pTemp, SEQUENCE)))
    {
        goto exit;
    }

    /* SEQUENCE of GeneralNames */
    if (OK > ( status =
            CMS_AUX_getSequenceOfGeneralNames(pTemp, cs, to, num)))
    {
        goto exit;
    }

exit:

    return status;
}


/*-------------------------------------------------------------------------*/

extern MSTATUS
CMS_AUX_getAttribute( ASN1_ITEMPTR pSignerInfo, CStream cs,
                      const ubyte* attributeTypeOID,
                      intBoolean signedAttr,
                      ASN1_ITEMPTR *ppAttribute)
{
    MSTATUS status;
    WalkerStep signerInfoToAttributeWalkInstructions[] =
    {
        { GoToTag, 0, 0},
        { GoChildWithOID, 0, 0},
        { GoNextSibling, 0, 0 },
        { VerifyType, MOC_SET, 0 },
        { GoFirstChild, 0, 0 },
        { Complete, 0, 0}
    };

   /* Reinitialize signerInfoToAttributeWalkInstructions[] to avoid
    * Diab compiler error (dcc:1486): initializer that is a brace-enclosed
    * list may contain only constant expressions
    */
   signerInfoToAttributeWalkInstructions[0].extra1 = signedAttr? 0 : 1;
   signerInfoToAttributeWalkInstructions[1].extra2 = attributeTypeOID;

    if (!pSignerInfo || !attributeTypeOID || !ppAttribute)
        return ERR_NULL_POINTER;

    if (OK > ( status = ASN1_WalkTree(pSignerInfo, cs,
                                    signerInfoToAttributeWalkInstructions,
                                    ppAttribute)))
    {
        goto exit;
    }

exit:

    return status;
}


/*-------------------------------------------------------------------------*/

extern MSTATUS
CMS_AUX_getAttributeValue( ASN1_ITEMPTR pSignerInfo, CStream cs,
                              const ubyte* attributeTypeOID,
                              intBoolean signedAttr,
                              ubyte** ppAttributeValue,
                              ubyte4* pAttributeValueLen)
{
    MSTATUS status;
    ASN1_ITEMPTR pItem;
    ubyte* pAttributeValue = 0;
    ubyte4 attributeValueLen;

    /* other pointers tested by CMS_AUX_getAttribute */
    if (!ppAttributeValue || !pAttributeValueLen)
        return ERR_NULL_POINTER;

    if (OK > ( status = CMS_AUX_getAttribute( pSignerInfo, cs,
                                               attributeTypeOID, signedAttr,
                                               &pItem)))
    {
        goto exit;
    }

    attributeValueLen = pItem->length;
    if ( attributeValueLen)
    {
        pAttributeValue = MALLOC( attributeValueLen);
        if (!pAttributeValue)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        CS_seek( cs, pItem->dataOffset, MOCANA_SEEK_SET);
        if (1 != CS_read( pAttributeValue, attributeValueLen, 1, cs))
        {
            status = ERR_FILE_READ_FAILED;
            goto exit;
        }
    }

    *ppAttributeValue = pAttributeValue;
    pAttributeValue = 0;
    *pAttributeValueLen = attributeValueLen;

exit:

    FREE( pAttributeValue);

    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
CMS_AUX_getAlgoName( const ubyte* algoOID, const char** ppAlgoName)
{
    ubyte4 i;

    if (!algoOID || !ppAlgoName)
    {
        return ERR_NULL_POINTER;
    }

    /* linear search should be enough */
    for (i = 0; i < COUNTOF(mAlgoOIDToNames); ++i)
    {
        if ( EqualOID( algoOID, mAlgoOIDToNames[i].oid))
        {
            *ppAlgoName = mAlgoOIDToNames[i].name;
            return OK;
        }
    }

    return ERR_FALSE;
}

#endif /* __ENABLE_DIGICERT_CMS__ */
