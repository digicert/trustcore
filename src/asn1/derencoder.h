/*
 * derencoder.h
 *
 * DER Encoding of ASN.1
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

#ifndef __DERENCODER_HEADER__
#define __DERENCODER_HEADER__

#include "../common/mrtos.h"

#ifndef __PARSEASN1_H__
#error derencoder.h must be included after parseasn1.h
#endif

/*------------------------------------------------------------------*/
#define MAX_DER_STORAGE (5) /* 5 is useful to store INTEGER */

struct DER_ITEM;
struct vlong;

typedef struct DER_ITEM *DER_ITEMPTR;

/* useful macros */
#define DER_FIRST_CHILD(a)  ((DER_ITEMPTR) (((TreeItem*)(a))->m_pFirstChild))
#define DER_NEXT_SIBLING(a) ((DER_ITEMPTR) (((TreeItem*)(a))->m_pNextSibling))
#define DER_PARENT(a)       ((DER_ITEMPTR) (((TreeItem*)(a))->m_pParent))

/* add a new DER_ITEM to an existing tree or create a new tree
if pParent is NULL */
MOC_EXTERN MSTATUS DER_AddItem( DER_ITEMPTR pParent, ubyte type, ubyte4 length,
                          const ubyte* value, DER_ITEMPTR* ppNewDERItem);
/* this version stores the data in the tree item (max MAX_DER_STORAGE bytes) */
MOC_EXTERN MSTATUS DER_AddItemCopyData( DER_ITEMPTR pParent, ubyte type, ubyte4 length,
                                    const ubyte *pValue, DER_ITEMPTR* ppNewDERItem);
/* this version transfers data ownership to the tree item */
MOC_EXTERN MSTATUS DER_AddItemOwnData( DER_ITEMPTR pParent, ubyte type, ubyte4 length,
                                    ubyte** value, DER_ITEMPTR* ppNewDERItem);

/* add a BER encoded item -- i.e. terminated with EOC */
MOC_EXTERN MSTATUS DER_AddBERItem(  DER_ITEMPTR pParent, ubyte type,
                                    DER_ITEMPTR* ppNewDERItem);

/* adds an INTEGER -- adding a DER encoded integer is a surprisingly complex
operation because a leading zero byte must be added if the first significant
byte is < 0x7F ( negative) and leading zero bytes must be removed unless
of course the previous rules apply -- this function should be called with
the buffer passed as argument pointing to a zero byte */
MOC_EXTERN MSTATUS DER_AddInteger( DER_ITEMPTR pParent, ubyte4 length,
                              const ubyte* pLeadZero, DER_ITEMPTR* ppNewDerItem);

MOC_EXTERN MSTATUS DER_AddIntegerCopyData( DER_ITEMPTR pParent, ubyte4 length,
                       const ubyte* pLeadZero, DER_ITEMPTR* ppNewDerItem);

/* simpler method for WORD length integer ( versions, etc.. ) */
MOC_EXTERN MSTATUS DER_AddIntegerEx( DER_ITEMPTR pParent, ubyte4 value,
                                        DER_ITEMPTR* ppNewDerItem);

/* Add a vlong as an INTEGER.
 * <p>This function will convert the vlong into canonical form, then add that
 * value to the pParent as an INTEGER.
 * <p>This is simply a convenience function because plenty of times it is
 * necessary to "convert" a vlong into an INTEGER inside an encoding.
 * <p>Note that a vlong is signed. If the value is marked as positive, the value
 * will be added as a positive INTEGER, and added as negative if marked as
 * negative.
 */
MOC_EXTERN MSTATUS DER_AddVlongInteger (
  DER_ITEMPTR pParent,
  vlong *pValue,
  DER_ITEMPTR* ppNewDERItem
  );

/* similar to above -- but return the offset in the buffer that should be used
as the start of the buffer --- use this for SetItemData (cf. Ecc signatures) */
MOC_EXTERN MSTATUS DER_GetIntegerEncodingOffset(ubyte4 length, const ubyte* pLeadZero, ubyte4* offset);

/* adds a BITSTRING */
MOC_EXTERN MSTATUS DER_AddBitString(DER_ITEMPTR pParent, ubyte4 length,
                                    const ubyte* value, DER_ITEMPTR* ppNewDERItem);

/* add time, either UTCTime or GeneralizedTime depending on the value of TimeDate arg */
MOC_EXTERN MSTATUS DER_AddTime(DER_ITEMPTR pParent, const TimeDate* td,
                                DER_ITEMPTR* ppNewDERItem);

/* adds a whole DER encoded buffer to the parent */
MOC_EXTERN MSTATUS DER_AddDERBuffer(DER_ITEMPTR pParent, ubyte4 length,
                                const ubyte* value, DER_ITEMPTR* ppNewDERItem);

/* adds a whole DER encoded buffer to the parent, ownership transferred */
MOC_EXTERN MSTATUS DER_AddDERBufferOwn(DER_ITEMPTR pParent, ubyte4 length,
                                const ubyte** value, DER_ITEMPTR* ppNewDERItem);

/* adds EOC if none to all the BER items */
MOC_EXTERN MSTATUS DER_FinalizeBERItems(DER_ITEMPTR pParent);

/* get the total length necessary to DER Encode */
MOC_EXTERN MSTATUS DER_GetLength(DER_ITEMPTR pRoot, ubyte4* pTotalLength);
/* do the DER encoding in the specified buffer of size bufferLength */
MOC_EXTERN MSTATUS DER_SerializeInto(DER_ITEMPTR pRoot, ubyte* buffer, ubyte4* bufferLength);
/* do the DER encoding inside a newly generated buffer */
MOC_EXTERN MSTATUS DER_Serialize(DER_ITEMPTR pRoot, ubyte** pBuffer, ubyte4* pBufferLength);

/* do the DER encoding in the specified buffer of size bufferLength */
MOC_EXTERN MSTATUS DER_SerializeIntoOffset(DER_ITEMPTR pRoot, sbyte4 offset,
                                           ubyte* buffer, ubyte4* bufferLength);
/* do the DER encoding inside a newly generated buffer */
MOC_EXTERN MSTATUS DER_SerializeOffset(DER_ITEMPTR pRoot, sbyte4 offset,
                                        ubyte** pBuffer, ubyte4* pBufferLength);

/* get the pointer to the serialized data */
MOC_EXTERN MSTATUS DER_GetSerializedDataPtr(DER_ITEMPTR pRoot, ubyte** pBuffer);

/* advanced function */
MOC_EXTERN MSTATUS DER_GetASNBufferInfo(DER_ITEMPTR pItem, ubyte** ppBuffer, ubyte4* pDataLen);

/* advanced function */
MOC_EXTERN MSTATUS DER_SetItemData(DER_ITEMPTR pItem, ubyte4 length, const ubyte* value);

/* reusable functions */
/* add a sequence consisting of OID followed by NULL */
MOC_EXTERN MSTATUS DER_StoreAlgoOID(DER_ITEMPTR pRoot, const ubyte* oid, intBoolean addNullParam);
MOC_EXTERN MSTATUS DER_StoreAlgoOIDownData(DER_ITEMPTR pRoot, ubyte4 oidLen, ubyte **ppOid, intBoolean addNullTag);

/* copy an ASN1 Item to the parent */
MOC_EXTERN MSTATUS DER_AddASN1Item(DER_ITEMPTR pParent, ASN1_ITEMPTR pItem, CStream cs,
                                    DER_ITEMPTR* ppNewDERItem);

MOC_EXTERN MSTATUS DER_SwitchType(DER_ITEMPTR pParent, ubyte newType);

MOC_EXTERN MSTATUS DER_Free(DER_ITEMPTR pRoot);

/* helper macros */
#define DER_AddSequence( pParent, ppNewDERItem) \
    DER_AddItem( pParent, (CONSTRUCTED|SEQUENCE), 0, 0, ppNewDERItem)

#define DER_AddSet( pParent, ppNewDERItem) \
    DER_AddItem( pParent, (CONSTRUCTED|MOC_SET), 0, 0, ppNewDERItem)

#define DER_AddTag( pParent, tagValue, ppNewDERItem) \
    DER_AddItem( pParent, (CONSTRUCTED|CONTEXT|tagValue), 0, 0, ppNewDERItem)

#define DER_AddOID( pParent, oid, ppNewDERItem) \
    DER_AddItem( pParent, OID, oid[0], oid+1, ppNewDERItem)


#define DER_AddBERSequence( pParent, ppNewDERItem) \
    DER_AddBERItem( pParent, (CONSTRUCTED|SEQUENCE), ppNewDERItem)

#define DER_AddBERSet( pParent, ppNewDERItem) \
    DER_AddBERItem( pParent, (CONSTRUCTED|MOC_SET), ppNewDERItem)

#define DER_AddBERTag( pParent, tagValue, ppNewDERItem) \
    DER_AddBERItem( pParent, (CONSTRUCTED|CONTEXT|tagValue), ppNewDERItem)


#endif /* #ifndef __DERENCODER_HEADER__ */
