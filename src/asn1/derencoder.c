/*
 * derencoder.c
 *
 * DER Encoding
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
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memory_debug.h"
#include "../common/vlong.h"
#include "../asn1/parseasn1.h"
#include "../asn1/derencoder.h"

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_ALL_OPERATIONS__))

enum { E_DER_ITEM_NORMAL, E_DER_ITEM_OPAQUE, E_DER_ITEM_UNDEF_LENGTH };

typedef struct DER_ITEM
{
    TreeItem        treeItem;       /* tree infrastructure */
    ubyte           itemType;       /* NORMAL, OPAQUE, UNDEF_LENGTH */
    ubyte*          pASNBuffer;     /* offset in buffer once written */
    ubyte4          asnBufferLen;   /* size in buffer once written */
    ubyte4          valueLen;       /* length, i.e. the length of the value below -- for opaque, whole length */
    ubyte4          childLen;       /* length of the subtree below (NORMAL) */
    const ubyte*    value;          /* value, i.e. the data itself -- for opaque, all ASN.1. */
    ubyte           type;           /* type or tag. 1 byte for now (NORMAL) */
    ubyte           valueCopy[MAX_DER_STORAGE];      /* stored value (for convenience) (NORMAL) */
} DER_ITEM;


/*------ dtor function used when the tree item owns the data ----------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_CORE__))

static void
DER_ReleaseOwnedData( TreeItem* pThis)
{
    DER_ITEMPTR pDERItem = (DER_ITEMPTR) pThis;
    if ( pDERItem && pDERItem->value)
    {
        FREE(((ubyte*)(pDERItem->value)));
    }
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_ADD_ELEMENT__))

static void AddItemToParent( DER_ITEMPTR pParent, DER_ITEMPTR pNewChild)
{
    if (E_DER_ITEM_UNDEF_LENGTH == pParent->itemType)
    {
        pParent->type |= CONSTRUCTED; /* set the constructed bit on the BER parent */
    }
    TREE_AppendChild((TreeItem*) pParent, (TreeItem*) pNewChild);
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_ADD_ELEMENT__))

extern MSTATUS
DER_AddItem( DER_ITEMPTR pParent, ubyte type, ubyte4 length,
                          const ubyte* value, DER_ITEMPTR* ppNewDERItem)
{
    DER_ITEMPTR     pNewItem = 0;

    /* either pParent or ppNewDerITEM can be null but not both */
    if ( 0 == pParent && 0 == ppNewDERItem)
    {
        return ERR_INVALID_ARG;
    }

    /* an opaque Item can't have children */
    if (pParent && E_DER_ITEM_OPAQUE == pParent->itemType)
    {
        return ERR_DER_ENCODER_OPAQUE;
    }

    pNewItem = (DER_ITEMPTR) TREE_MakeNewTreeItem( sizeof(DER_ITEM));
    if ( 0 == pNewItem)
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    DEBUG_RELABEL_MEMORY(pNewItem);

    pNewItem->itemType = E_DER_ITEM_NORMAL;
    pNewItem->type = type;
    pNewItem->valueLen = length;
    pNewItem->value = value;
    pNewItem->pASNBuffer = 0;
    pNewItem->childLen = 0;
    pNewItem->asnBufferLen = 0;

    if ( pParent)
    {
        AddItemToParent(pParent, pNewItem);
    }

    if (ppNewDERItem)
    {
        *ppNewDERItem = pNewItem;
    }

    return OK;
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_SETTERS__))

extern MSTATUS
DER_SetItemData( DER_ITEMPTR pItem, ubyte4 length, const ubyte* value)
{
    if (!pItem)
    {
        return ERR_NULL_POINTER;
    }

    /* free owned data if any */
    if ( DER_ReleaseOwnedData == pItem->treeItem.m_dtorFun )
    {
        DER_ReleaseOwnedData( &pItem->treeItem);
    }

    pItem->value = value;
    pItem->valueLen = length;
    pItem->pASNBuffer = 0;
    pItem->asnBufferLen = 0;
    return OK;
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_ADD_ELEMENT__))

extern MSTATUS
DER_AddItemCopyData( DER_ITEMPTR pParent, ubyte type, ubyte4 length,
                                  const ubyte* pValue,
                                  DER_ITEMPTR* ppNewDERItem)
{
    MSTATUS status;
    DER_ITEMPTR pLocal; /* use a local since ppNewDERItem can be NULL */

    if (!pValue)
    {
        return ERR_NULL_POINTER;
    }

    if (length > MAX_DER_STORAGE)
    {
        ubyte* pData = NULL;
        if(OK > (status = MOC_MALLOC((void**) &pData, length)))
        {
            return status;
        }

        if (OK > (status = DER_AddItemOwnData(pParent, type, length, &pData, &pLocal)))
        {
            return status;
        }
    }
    else
    {
        if (OK > (status = DER_AddItem(pParent, type, length, NULL, &pLocal)))
        {
            return status;
        }

        /* store the data in the DER Item */
        /* points the value to the item storage */
        pLocal->value = pLocal->valueCopy;
    }

    MOC_MEMCPY((ubyte*)pLocal->value, pValue, length);

    /* return ppNewDERItem if necessary */
    if (ppNewDERItem)
    {
        *ppNewDERItem = pLocal;
    }

    return OK;
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_ADD_ELEMENT__))

extern MSTATUS
DER_AddItemOwnData( DER_ITEMPTR pParent, ubyte type, ubyte4 length,
                        ubyte** pValue, DER_ITEMPTR* ppNewDERItem)
{
    MSTATUS status;
    DER_ITEMPTR pLocal; /* use a local since ppNewDERItem can be NULL */

    if (!pValue || !*pValue)
    {
        return ERR_NULL_POINTER;
    }

    if (OK > (status = DER_AddItem( pParent, type, length, *pValue, &pLocal)))
    {
        return status;
    }

    /* assign the dtor */
    pLocal->treeItem.m_dtorFun = DER_ReleaseOwnedData;
    /* record ownership transfer */
    *pValue = 0;

    /* return ppNewDERItem if necessary */
    if (ppNewDERItem)
    {
        *ppNewDERItem = pLocal;
    }

    return OK;
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_CORE__))

static MSTATUS
DER_EncodeDateElement( ubyte* buffer, ubyte value)
{
    /* specialized routine that will always output 2 bytes for the value */
    if ( value > 100) return ERR_INVALID_ARG;

    *buffer++ = (value / 10) + '0';
    *buffer = (value % 10) + '0';
    return OK;
}

#endif


/*---------------------------------------------------------------------------*/

#if ((!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_CORE__)) && \
     (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_ADD_ELEMENT__)))

extern MSTATUS
DER_AddTime( DER_ITEMPTR pParent, const TimeDate* td, DER_ITEMPTR* ppNewDERItem)
{
    MSTATUS status = OK;
    ubyte* encode = 0;
    sbyte4 year;
    ubyte* next;
    ubyte4 buffSize = 16;
    ubyte asn1Type = GENERALIZEDTIME;

    encode = (ubyte*) MALLOC(buffSize);
    if (!encode)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    year = td->m_year + 1970;
    if (year < 2050)
    {
        asn1Type = UTCTIME;
        year -= ( year >= 2000) ? 2000 : 1900;
        if (OK > ( status = DER_EncodeDateElement( encode,  year)))
            goto exit;
        next = encode + 2;
    }
    else
    {
        next = (ubyte *)MOC_LTOA(year, (sbyte *)encode, buffSize);
    }

    DER_EncodeDateElement(next, td->m_month);
    DER_EncodeDateElement(next+=2, td->m_day);
    DER_EncodeDateElement(next+=2, td->m_hour);
    DER_EncodeDateElement(next+=2, td->m_minute);
    DER_EncodeDateElement(next+=2, td->m_second);
    next += 2;
    *next++ = 'Z';

    if (OK > ( status = DER_AddItemOwnData( pParent, asn1Type,
                                           (ubyte4) (next - encode),
                                            &encode, ppNewDERItem)))
    {
        goto exit;
    }

exit:

    FREE(encode);

    return status;
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_ADD_ELEMENT__))

extern MSTATUS
DER_AddBitString( DER_ITEMPTR pParent, ubyte4 length,
                  const ubyte* value, DER_ITEMPTR* ppNewDERItem)
{
    MSTATUS status;
    ubyte* reversedBits = NULL;
    ubyte4 i;
    static sbyte sLookupTrailingZeroBits[] = { 8,0,1,-1,2,4,-1,7,3,6,5};

    if (!value)
    {
        return ERR_NULL_POINTER;
    }
    /* determine the real length */
    while ( length && 0 == value[length-1])
    {
        --length;
    }

    if ( 0 == length)
    {
        ubyte data[MAX_DER_STORAGE] = {0};
        /* trivial case: add a single null octet */
        return DER_AddItemCopyData( pParent, BITSTRING, 1, data, ppNewDERItem);
    }
    /* allocate a buffer to reverse the bits */
    reversedBits = (ubyte*) MALLOC( length + 1);
    if ( !reversedBits)
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    /* reverse the bits */
    for ( i = 0; i < length; ++i)
    {
        /* http://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith32Bits */
        ubyte b = value[i];
        reversedBits[i+1] = (ubyte)(((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16);
    }
    /* count the number of right-most (traling) 0 bits in the last byte using John Reiser method */
    reversedBits[0] = sLookupTrailingZeroBits[((reversedBits[length]) & (-reversedBits[length])) % 11];

    if ( OK > ( status = DER_AddItemOwnData( pParent, BITSTRING, length + 1,
                        &reversedBits, ppNewDERItem)))
    {
        goto exit;
    }

exit:

    if ( reversedBits)
    {
        FREE( reversedBits);
    }
    return status;
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_ADD_ELEMENT__))

extern MSTATUS
DER_AddBERItem(  DER_ITEMPTR pParent, ubyte type, DER_ITEMPTR* ppNewDERItem)
{
    DER_ITEMPTR     pNewItem = 0;

    /* an opaque Item can't have children and only a BER item can have other
    BER child */
    if (pParent && E_DER_ITEM_UNDEF_LENGTH != pParent->itemType)
    {
        return ERR_DER_PARENT_NOT_BER;
    }

    pNewItem = (DER_ITEMPTR) TREE_MakeNewTreeItem( sizeof(DER_ITEM));
    if ( 0 == pNewItem)
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    DEBUG_RELABEL_MEMORY(pNewItem);

    pNewItem->itemType = E_DER_ITEM_UNDEF_LENGTH;
    pNewItem->type = type;
    pNewItem->valueLen = 0;
    pNewItem->value = 0;
    pNewItem->pASNBuffer = 0;
    pNewItem->childLen = 0;
    pNewItem->asnBufferLen = 0;

    if ( pParent)
    {
        AddItemToParent(pParent, pNewItem);
    }

    if (ppNewDERItem)
    {
        *ppNewDERItem = pNewItem;
    }

    return OK;
}

#endif 

/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_ADD_ELEMENT__))

extern MSTATUS
DER_AddDERBuffer( DER_ITEMPTR pParent, ubyte4 length, const ubyte* value,
                 DER_ITEMPTR* ppNewDERItem)
{
    DER_ITEMPTR     pNewItem = 0;

    /* pParent cannot be null and value cannot be NULL or zero length */
    if ( !pParent || !value || !length)
    {
        return ERR_INVALID_ARG;
    }

    /* an opaque Item can't have children */
    if (E_DER_ITEM_OPAQUE == pParent->itemType)
    {
        return ERR_DER_ENCODER_OPAQUE;
    }

    pNewItem = (DER_ITEMPTR) TREE_MakeNewTreeItem( sizeof(DER_ITEM));
    if ( 0 == pNewItem)
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    DEBUG_RELABEL_MEMORY(pNewItem);

    pNewItem->itemType = E_DER_ITEM_OPAQUE;
    pNewItem->type = value[0];
    pNewItem->valueLen = length;
    pNewItem->value = value;
    pNewItem->pASNBuffer = 0;
    pNewItem->childLen = 0;
    pNewItem->asnBufferLen = 0;

    /* here we could check that the parent has the constructed bit set */
    if ( pParent)
    {
        AddItemToParent(pParent, pNewItem);
    }

    if (ppNewDERItem)
    {
        *ppNewDERItem = pNewItem;
    }

    return OK;
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_ADD_ELEMENT__))

extern MSTATUS
DER_AddDERBufferOwn( DER_ITEMPTR pParent, ubyte4 length,
                     const ubyte** pValue, DER_ITEMPTR* ppNewDERItem)
{
    MSTATUS status;
    DER_ITEMPTR pLocal; /* use a local since ppNewDERItem can be NULL */

    if (!pValue || !*pValue)
    {
        return ERR_NULL_POINTER;
    }

    if (OK > (status = DER_AddDERBuffer( pParent, length, *pValue, &pLocal)))
    {
        return status;
    }

    /* assign the dtor */
    pLocal->treeItem.m_dtorFun = DER_ReleaseOwnedData;
    /* record ownership transfer */
    *pValue = 0;

    /* return ppNewDERItem if necessary */
    if (ppNewDERItem)
    {
        *ppNewDERItem = pLocal;
    }

    return OK;
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_GETTERS__))

extern MSTATUS
DER_GetIntegerEncodingOffset( ubyte4 length, const ubyte* pLeadZero,
                             ubyte4* offset)
{
    ubyte4 skipped;
    if ( !pLeadZero || !offset)
    {
        return ERR_NULL_POINTER;
    }
    /* check that the first byte is a leading zero */
    if ( 0 == length || *pLeadZero)
    {
        return ERR_INVALID_ARG;
    }
    /* remove all leading zeroes unless the first non zero byte is > 0x7F
    or this is the last byte */
    skipped = 0;
    while ( 0 == *pLeadZero && skipped < length-1)
    {
        if ( pLeadZero[1] > 0x7f)
        {
            break; /* keep the leading zero */
        }
        ++pLeadZero; /* advance to the next < 0x7f */
        ++skipped;
    }
    *offset = skipped;
    return OK;
}

#endif


/*---------------------------------------------------------------------------*/

#if ((!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_ADD_ELEMENT__)) && \
     (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_GETTERS__)))

extern MSTATUS
DER_AddInteger( DER_ITEMPTR pParent, ubyte4 length,
               const ubyte* pLeadZero, DER_ITEMPTR* ppNewDerItem)
{
    MSTATUS status;
    ubyte4 offset;

    if ( OK > ( status = DER_GetIntegerEncodingOffset( length, pLeadZero, &offset)))
        return status;

    return DER_AddItem( pParent, INTEGER, length - offset, pLeadZero + offset, ppNewDerItem);
}

extern MSTATUS
DER_AddIntegerCopyData( DER_ITEMPTR pParent, ubyte4 length,
                       const ubyte* pLeadZero, DER_ITEMPTR* ppNewDerItem)
{
    MSTATUS status;
    ubyte4 offset;

    if ( OK > ( status = DER_GetIntegerEncodingOffset( length, pLeadZero, &offset)))
        return status;

    return DER_AddItemCopyData( pParent, INTEGER, length - offset, pLeadZero + offset, ppNewDerItem);
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_ADD_ELEMENT__))

extern MSTATUS
DER_AddIntegerEx( DER_ITEMPTR pParent, ubyte4 value, DER_ITEMPTR* ppNewDerItem)
{
    MSTATUS status;
    ubyte  leadZero[5];
    ubyte4 offset = 0;

    leadZero[0] = 0;
    leadZero[1] = (ubyte)((value) >> 24);
    leadZero[2] = (ubyte)((value) >> 16);
    leadZero[3] = (ubyte)((value)>>  8);
    leadZero[4] = (ubyte)(value);

    if ( OK > ( status = DER_GetIntegerEncodingOffset( 5, leadZero, &offset)))
        return status;

    return DER_AddItemCopyData( pParent, INTEGER, 5 - offset,
                                leadZero + offset, ppNewDerItem);
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_ADD_ELEMENT__))

extern MSTATUS DER_AddVlongInteger (
  DER_ITEMPTR pParent,
  vlong *pValue,
  DER_ITEMPTR *ppNewDERItem
  )
{
  MSTATUS status;
  ubyte addByte;
  sbyte4 numLen;
  ubyte4 extra;
  ubyte *pBuf = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pParent) && (NULL == ppNewDERItem) )
    goto exit;

  if (NULL == pValue)
    goto exit;

  /* How big is the integer?
   */
  numLen = (sbyte4)VLONG_bitLength (pValue);

  if (numLen == 0)
    numLen = 1;

  /* Is the msBit set? If numLen / 8 leaves no remainder, then it is.
   * e.g. bit len = 8 -> msBit set
   *      bit len = 1024 -> msBit set
   *      bit len = 2041 -> msBit not set
   * If the number is negative and the msBit is set, we don't add an extra byte.
   * If the number is negative and the msBit is not set, we add an extra byte.
   * If the number is positive and the msBit is set, we add an extra byte.
   * If the number is positive and the msBit is not set, we don't add an extra byte.
   *
   * This initializes the extra to 0 (no extra byte). If the bit is set, add an
   * extra byte.
   * If the number turns out to be negative, change extra.
   */
  extra = 0;
  addByte = 0;
  if (0 == (numLen & 7))
    extra = 1;

  if (TRUE == pValue->negative)
  {
    addByte = 0xff;
    extra = extra ^ 1;
  }

  /* Allocate a space big enough to hold the integer, plus the extra byte.
   */
  numLen = (numLen + 7) / 8;

  status = MOC_MALLOC ((void **)&pBuf, (ubyte4)(numLen + extra));
  if (OK != status)
    goto exit;

  /* If we have an extra byte, put the result one byte along. If there is no
   * extra, place it at the beginning.
   */
  status = VLONG_byteStringFromVlong (pValue, pBuf + extra, &numLen);
  if (OK != status)
    goto exit;

  if (0 != extra)
    pBuf[0] = addByte;

  /* The number begins at pBuf + offset. If there's no extra byte, the length is
   * numLen. If there is, it's numLen + 1. So the total length is
   * numLen + (1 - offset).
   * Because we want the ASN1 structure to own the data, we call AddItemOwnData.
   * There's no AddIntegerOwnData, which is why we have to figure out the leading
   * byte.
   */
  status = DER_AddItemOwnData (
    pParent, INTEGER, numLen + extra, &pBuf, ppNewDERItem);

exit:

  if (NULL != pBuf)
  {
    MOC_FREE ((void **)&pBuf);
  }

  return (status);
}

#endif


/*---------------------------------------------------------------------------*/

#if(!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_GETTERS__))

extern MSTATUS
DER_GetSerializedDataPtr( DER_ITEMPTR pRoot, ubyte** pBuffer)
{
    ubyte* pDataPtr;

    if ( !pRoot || !pBuffer)
    {
        return ERR_NULL_POINTER;
    }

    /* no access to the data part if the item is OPAQUE */
    if ( E_DER_ITEM_OPAQUE == pRoot->itemType)
    {
        return ERR_DER_ENCODER_OPAQUE;
    }

    if (!pRoot->pASNBuffer)
    {
        return ERR_DER_ENCODER_NOT_SERIALIZED;
    }

    pDataPtr = pRoot->pASNBuffer;
    pDataPtr += pRoot->asnBufferLen;
    pDataPtr -= pRoot->valueLen + pRoot->childLen;
    *pBuffer = pDataPtr;
    return OK;
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_CORE__))

extern MSTATUS
DER_FinalizeBERItems( DER_ITEMPTR pRoot)
{
    MSTATUS status = OK;

    if ( !pRoot)
    {
        return ERR_NULL_POINTER;
    }

    /* only a E_DER_ITEM_UNDEF_LENGTH item can have
    E_DER_ITEM_UNDEF_LENGTH children */
    if ( E_DER_ITEM_UNDEF_LENGTH == pRoot->itemType)
    {
        /* look if the last child is EOC */
        DER_ITEMPTR pCurrChild = DER_FIRST_CHILD( pRoot);
        DER_ITEMPTR pLastChild = NULL;

        while (pCurrChild)
        {
            pLastChild = pCurrChild;

            if (OK > ( status =  DER_FinalizeBERItems( pCurrChild)))
            {
                return status;
            }

            pCurrChild = DER_NEXT_SIBLING( pCurrChild);
        }

        /* if there's no last child or it's not EOC then add EOC */
        if (!pLastChild || EOC != pLastChild->type)
        {
            status = DER_AddItem( pRoot, EOC, 0, NULL, NULL);
        }
    }

    return status;
}

#endif 


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_GETTERS__))

extern MSTATUS
DER_GetLength( DER_ITEMPTR pRoot, ubyte4* pTotalLength)
{
    MSTATUS status = OK;
    DER_ITEMPTR pCurrChild = 0, pLastChild = 0;
    ubyte4 totalLen = 0;

    if (0 == pRoot || 0 == pTotalLength)
    {
        return ERR_NULL_POINTER;
    }

    /* opaque item are easy! */
    if ( E_DER_ITEM_OPAQUE == pRoot->itemType)
    {
        *pTotalLength = pRoot->valueLen;
        return OK;
    }

    /* reset */
    pRoot->childLen = 0;

    pCurrChild = DER_FIRST_CHILD( pRoot);
    /* sum the length of the children */
    while (pCurrChild && OK <= status)
    {
        ubyte4 childLen;

        pLastChild = pCurrChild;
        status = DER_GetLength( pCurrChild, &childLen);
        pRoot->childLen += childLen;
        pCurrChild = DER_NEXT_SIBLING( pCurrChild);
    }

    totalLen = pRoot->valueLen + pRoot->childLen;

    if ( E_DER_ITEM_UNDEF_LENGTH == pRoot->itemType)
    {
        ++totalLen; /* length is always 0 (1 byte) */
        /* check if the last child exists and is EOC */
        if (!pLastChild || EOC != pLastChild->type)
        {
            /* this will stop the recursion */
            status = ERR_DER_BER_NOT_TERMINATED;
        }
    }
    else
    {
        if (totalLen <= 127)
        {
            ++totalLen;
        }
        else
        {
            ubyte4 tmp = totalLen;
            totalLen += 2;
            while ( tmp >>= 8)
            {
                ++totalLen;
            }
        }
    }

    /* assume a single byte tag */
    ++totalLen;
    *pTotalLength = totalLen;

    return status;
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_SERIALIZE__))

static ubyte*
DER_SerializeAux( DER_ITEMPTR pRoot, ubyte* buffer, DER_ITEMPTR* pStop)
{
    DER_ITEMPTR pCurrChild = 0, pLastChild = 0;
    ubyte4 totalLen;

    pRoot->pASNBuffer = buffer;

    switch (pRoot->itemType)
    {
        case E_DER_ITEM_NORMAL:

            /* write tag */
            *buffer++ = pRoot->type;
            /* write length */
            totalLen = pRoot->valueLen + pRoot->childLen;
            if ( totalLen <= 127)
            {
                *buffer++ = (ubyte) totalLen;
            }
            else
            {
                ubyte numLenBytes = 0;
                ubyte4 tmp = totalLen;
                do
                {
                    ++numLenBytes;
                } while ( tmp >>= 8);
                *buffer++ = (0x80 | numLenBytes);
                switch (numLenBytes)
                {
                case 4:
                    *buffer++ = (ubyte) (totalLen >> 24);
                case 3:
                    *buffer++ = (ubyte) (totalLen >> 16);
                case 2:
                    *buffer++ = (ubyte) (totalLen >> 8);
                case 1:
                    *buffer++ = (ubyte) (totalLen);
                    break;
                }
            }
            break;

        case E_DER_ITEM_UNDEF_LENGTH:
            /* write tag */
            *buffer++ = pRoot->type;
            /* write length */
            *buffer++ = LEN_XTND;
            break;

        default:
            break;
    }

    /* write value first */
    if ( pRoot->valueLen)
    {
        if ( pRoot->value)
        {
            MOC_MEMCPY( buffer, pRoot->value, (sbyte4) pRoot->valueLen);
        }
        buffer += pRoot->valueLen;
    }

    /* then write children (we can have both (BITSTRING encapsulating )
        no need to filter for E_DER_ITEM_OPAQUE, we make sure they have
        no children */
    pCurrChild = DER_FIRST_CHILD( pRoot);
    while (pCurrChild && !(*pStop))
    {
        pLastChild = pCurrChild;

        buffer = DER_SerializeAux( pCurrChild, buffer, pStop);
        pCurrChild = DER_NEXT_SIBLING( pCurrChild);
    }

    if ( !(*pStop) && E_DER_ITEM_UNDEF_LENGTH == pRoot->itemType)
    {
        if (!pLastChild || EOC != pLastChild->type)
        {
            *pStop = (pLastChild) ? pLastChild : pRoot;
        }
    }

    pRoot->asnBufferLen = (ubyte4)(buffer - pRoot->pASNBuffer);

    return buffer;
}

#endif


/*---------------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_SERIALIZE__))

static ubyte*
DER_SerializeAux2( DER_ITEMPTR pRoot, ubyte* buffer, sbyte4* pOffset, DER_ITEMPTR* pStop)
{
    DER_ITEMPTR pCurrChild = 0, pLastChild = 0;
    ubyte4 totalLen;
    sbyte4 consumed = 0;

    if (*pOffset <= 0)
    {
         return DER_SerializeAux( pRoot, buffer, pStop);
    }

    pRoot->pASNBuffer = buffer;

    switch (pRoot->itemType)
    {
        case E_DER_ITEM_NORMAL:

            /* write tag */
            ++consumed;
            /* write length */
            totalLen = pRoot->valueLen + pRoot->childLen;
            if ( totalLen <= 127)
            {
                ++consumed;
            }
            else
            {
                ubyte4 tmp = totalLen;
                do
                {
                    ++consumed;
                } while ( tmp >>= 8);
                ++consumed;
            }
            break;

        case E_DER_ITEM_UNDEF_LENGTH:
            consumed += 2;
            break;

        default:
            break;
    }

    /* write value first */
    if ( pRoot->valueLen)
    {
        consumed += pRoot->valueLen;
    }

    /* then write children (we can have both (BITSTRING encapsulating )
        no need to filter for E_DER_ITEM_OPAQUE, we make sure they have
        no children */
    pCurrChild = DER_FIRST_CHILD( pRoot);
    *pOffset -= consumed;
    consumed = 0;
    while (pCurrChild && !(*pStop))
    {
        pLastChild = pCurrChild;

        buffer = DER_SerializeAux2( pCurrChild, buffer, pOffset, pStop);
        pCurrChild = DER_NEXT_SIBLING( pCurrChild);
    }

    if ( !(*pStop) && E_DER_ITEM_UNDEF_LENGTH == pRoot->itemType)
    {
        if (!pLastChild || EOC != pLastChild->type)
        {
            *pStop = (pLastChild) ? pLastChild : pRoot;
        }
    }

    pRoot->asnBufferLen = (ubyte4)(buffer - pRoot->pASNBuffer);

    return buffer;
}

#endif


/*---------------------------------------------------------------------------*/

#if ((!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_SERIALIZE__)) && \
     (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_GETTERS__)))

extern MSTATUS
DER_SerializeInto( DER_ITEMPTR pRoot, ubyte* buffer, ubyte4* bufferLength)
{
    MSTATUS status = OK;
    ubyte4 totalLen;

    if ( !pRoot || !buffer || !bufferLength)
    {
        return ERR_NULL_POINTER;
    }

    /* make sure we have enough space also recomputes lengths */
    if ( OK > (status = DER_GetLength( pRoot, &totalLen)))
    {
        if (ERR_DER_BER_NOT_TERMINATED != status)
        {
            return status;
        }
    }

    if ( totalLen > *bufferLength)
    {
        status = ERR_BUFFER_OVERFLOW;
    }
    else
    {
        DER_ITEMPTR pLast = 0;
        DER_SerializeAux( pRoot, buffer, &pLast);
        status = OK;
    }

    *bufferLength = totalLen; /*indicate the used/required length*/
    return status;
}

#endif


/*---------------------------------------------------------------------------*/

#if ((!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_SERIALIZE__)) && \
     (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_GETTERS__)))

extern MSTATUS
DER_SerializeIntoOffset( DER_ITEMPTR pRoot, sbyte4 offset,
                        ubyte* buffer, ubyte4* bufferLength)
{
    MSTATUS status = OK;
    ubyte4 totalLen;

    if ( !pRoot || !buffer || !bufferLength)
    {
        return ERR_NULL_POINTER;
    }

    /* make sure we have enough space also recomputes lengths */
    if ( OK > (status = DER_GetLength( pRoot, &totalLen)))
    {
        if (ERR_DER_BER_NOT_TERMINATED != status)
        {
            return status;
        }
    }

    if ( totalLen > offset + *bufferLength )
    {
        status = ERR_BUFFER_OVERFLOW;
    }
    else
    {
        DER_ITEMPTR pLast = 0;
        sbyte4 offsetCopy = offset;
        DER_SerializeAux2( pRoot, buffer, &offsetCopy, &pLast);
        if (offset < 0)
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }
        status = OK;
    }

    *bufferLength = totalLen - offset; /*indicate the used/required length*/

exit:
    return status;
}

#endif


/*---------------------------------------------------------------------------*/

#if ((!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_SERIALIZE__)) && \
     (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_GETTERS__)))

extern MSTATUS
DER_Serialize( DER_ITEMPTR pRoot, ubyte** pBuffer, ubyte4* pBufferLength)
{
    MSTATUS status = OK;
    ubyte4 totalLen;
    ubyte* newBuffer;
    DER_ITEMPTR pLast;

    if ( !pRoot || !pBuffer || !pBufferLength)
    {
        return ERR_NULL_POINTER;
    }

    /* computes length */
    if ( OK > (status = DER_GetLength( pRoot, &totalLen)))
    {
        if (ERR_DER_BER_NOT_TERMINATED != status)
        {
            return status;
        }
    }

    newBuffer = (ubyte*) MALLOC(totalLen);
    if ( 0 == newBuffer)
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    pLast = 0;
    DER_SerializeAux( pRoot, newBuffer, &pLast);

    *pBuffer = newBuffer;
    *pBufferLength = totalLen;

    return OK;
}

#endif


/*---------------------------------------------------------------------------*/

#if ((!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_SERIALIZE__)) && \
     (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_GETTERS__)))

extern MSTATUS
DER_SerializeOffset( DER_ITEMPTR pRoot, sbyte4 offset, ubyte** pBuffer, ubyte4* pBufferLength)
{
    MSTATUS status = OK;
    ubyte4 totalLen;
    sbyte4 offsetCopy;
    ubyte* newBuffer;
    DER_ITEMPTR pLast;

    if ( !pRoot || !pBuffer || !pBufferLength)
    {
        return ERR_NULL_POINTER;
    }

    /* computes length */
    if ( OK > (status = DER_GetLength( pRoot, &totalLen)))
    {
        if (ERR_DER_BER_NOT_TERMINATED != status)
        {
            return status;
        }
    }

    status = OK;
    if ((sbyte4) totalLen == offset)
    {
        *pBuffer = 0;
        *pBufferLength = 0;
        goto exit;
    }

    newBuffer = (ubyte*) MALLOC(totalLen - offset);
    if ( 0 == newBuffer)
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    pLast = 0;
    offsetCopy = offset;
    DER_SerializeAux2( pRoot, newBuffer, &offsetCopy, &pLast);
    if (offsetCopy < 0)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    *pBuffer = newBuffer;
    *pBufferLength = totalLen - offset;

exit:
    return status;
}

#endif


/*-----------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_GETTERS__))

extern MSTATUS
DER_GetASNBufferInfo( DER_ITEMPTR pItem, ubyte** ppBuffer, ubyte4* pDataLen)
{
    if ( !pItem || !ppBuffer || !pDataLen)
        return ERR_NULL_POINTER;

    *ppBuffer = pItem->pASNBuffer;
    *pDataLen = pItem->asnBufferLen;

    return OK;
}

#endif 


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_CORE__))

extern MSTATUS
DER_StoreAlgoOID( DER_ITEMPTR pRoot, const ubyte* oid,
                 intBoolean addNullTag)
{
    DER_ITEMPTR pSequence;
    MSTATUS status;

    if ( OK > ( status = DER_AddSequence( pRoot, &pSequence)))
        return status;

    if ( OK > ( status = DER_AddOID( pSequence, oid, NULL)))
        return status;

    if  (addNullTag && OK > ( status = DER_AddItem( pSequence, NULLTAG, 0, NULL, NULL)))
        return status;

    return OK;
}

#endif


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_ADD_ELEMENT__))

MOC_EXTERN MSTATUS
DER_AddASN1Item( DER_ITEMPTR pParent, ASN1_ITEMPTR pItem, CStream cs,
                 DER_ITEMPTR* ppNewDERItem)
{
    MSTATUS status;
    ubyte *copyBuff = 0;

    if (!pItem)
    {
        return ERR_NULL_POINTER;
    }

    copyBuff = (ubyte*) MALLOC( pItem->length);
    if (! copyBuff)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > ( status = CS_seek( cs, pItem->dataOffset, MOCANA_SEEK_SET)))
        goto exit;

    if (1 != CS_read( copyBuff, pItem->length, 1, cs) )
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    if ( OK > (status = DER_AddItemOwnData( pParent, pItem->id|pItem->tag,
                                        pItem->length, &copyBuff, ppNewDERItem)))
    {
        goto exit;
    }

exit:

    if (copyBuff)
    {
        FREE(copyBuff);
    }

    return status;
}

#endif


/*------------------------------------------------------------------*/

#if(!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_CORE__))

MOC_EXTERN MSTATUS
DER_SwitchType( DER_ITEMPTR pParent, ubyte newType)
{
    if (!pParent)
        return ERR_NULL_POINTER;

    pParent->type = newType;
    return OK;
}

#endif 


/*------------------------------------------------------------------*/

#if (!defined(__DISABLE_MOCANA_ASN1_DER_ENCODE_CORE__))

MOC_EXTERN MSTATUS
DER_Free( DER_ITEMPTR pRoot)
{
    return TREE_DeleteTreeItem((TreeItem*)pRoot);
}

#endif


/*------------------------------------------------------------------*/

#endif /* __DISABLE_MOCANA_ASN1_DER_ENCODE_ALL_OPERATIONS__) */
