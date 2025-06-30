/*
 * mocasn1.h
 *
 * Declarations of data types and functions that perform DER encoding and
 * decoding using the template-based ASN.1 engine from Mocana.
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
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mrtos.h"
#include "../common/mem_part.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../crypto/hw_accel.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"

#ifndef __MOCASN1_H__
#define __MOCASN1_H__

#ifdef __cplusplus
extern "C" {
#endif

/*  0x80000000    OPTIONAL
 *  0x40000000    DEFAULT
 *  0x20000000    EXPLICIT
 *  0x10000000    IMPLICIT
 *
 *  0x08000000    unused
 *
 *  0x04000000    ANY_TIME
 *  0x02000000    ENCODED
 *  0x01000000    OF
 *
 *  0x00010000 to
 *  0x00310000    tags
 *
 *  0x00008000    can be indefinite
 *  0x00004000    UNKNOWN_OF
 *  0x00002000    UNKNOWN_VALUE
 *  0x00001000    NO_VALUE
 *  0x00000800    SKIP, for NO_VALUE_SKIP
 *
 *  0x00000700    not used
 *
 *  0x0000000F    For IMPLICIT/EXPLICIT
 *
 *  0x0fff0000    TYPE_MASK (includes tag, ENCODED, OF, ANY_TIME)
 *  0x04ff0000    TAG_MASK (includes tag, ANY_TIME)
 */

#define MASN1_TYPE_MASK          0x0fff0000
/* Mask off the tag, but also allow for the ANY_TIME bit.
 */
#define MASN1_TAG_MASK           0x04ff0000
#define MASN1_TYPE_SHIFT_COUNT   16

#define MASN1_TYPE_NONE          0x00000000
#define MASN1_TYPE_BOOLEAN       0x00010000
#define MASN1_TYPE_INTEGER       0x00020000
#define MASN1_TYPE_BIT_STRING    0x00030000
#define MASN1_TYPE_OCTET_STRING  0x00040000
#define MASN1_TYPE_NULL          0x00050000
#define MASN1_TYPE_OID           0x00060000
#define MASN1_TYPE_UTF8_STRING   0x000C0000
#define MASN1_TYPE_PRINT_STRING  0x00130000
#define MASN1_TYPE_IA5_STRING    0x00160000
#define MASN1_TYPE_UTC_TIME      0x00170000
#define MASN1_TYPE_GEN_TIME      0x00180000
#define MASN1_TYPE_BMP_STRING    0x001E0000

/* Use this TYPE if the Element can be UTCTime or GeneralizedTime. For example, a
 * cert contains Validity, which is a choice between UTC and Gen Times.
 * When encoding, this type will use UTCTime for dates of 2049 or earlier, and
 * GenTime for dates of 2050 and later.
 */
#define MASN1_TYPE_ANY_TIME      0x04000000
#define MASN1_TYPE_ANY_TIME_TAG  0x00000400
#define MASN1_TYPE_UTC_TIME_TAG  0x00000017
#define MASN1_TYPE_GEN_TIME_TAG  0x00000018

#define MASN1_TYPE_INDEF_BIT     0x00000020

#define MASN1_TYPE_OF            0x01000000
#define MASN1_TYPE_SEQUENCE      0x00300000
#define MASN1_TYPE_SEQUENCE_OF   (MASN1_TYPE_SEQUENCE | MASN1_TYPE_OF)
#define MASN1_TYPE_SET           0x00310000
#define MASN1_TYPE_SET_OF        (MASN1_TYPE_SET | MASN1_TYPE_OF)

#define MASN1_CONSTRUCTED_MASK   0x00200000

#define MASN1_TYPE_ENCODED       0x02000000

/* Set this bit on types, other than constructed, that can be indefinite.
 */
#define MASN1_TYPE_INDEF_ALLOWED 0x00008000

#define MASN1_SPECIAL_MASK       0xF00000FF

/* Forward referencing.
 */
struct MAsn1OfTemplate;
struct MAsn1Element;
struct MAsn1OfEntry;

/** This is what an ASN.1 Element is. It contains information necessary to encode
 * data or else the information about encoded data after decoding.
 * <p>Note that this is not a link list. The pNext is not the next in a link
 * list, it is the next Element in the encoding. Sometimes the next Element is
 * pCurrent + 1, but if pCurrent is constructed, the next Element is after the
 * sub Elements. That is, once you finish with an Element (which might mean
 * completing sub Elements), which is the next one on which to operate. For
 * example,
 * <pre>
 * <code>
 *    SEQ {
 *      OID,
 *      SEQ {
 *        INT,
 *        OCT },
 *      UTF8 }
 *
 *   An array of Elements will be
 *     SEQ     0    next is NULL
 *      OID    1    next is 2
 *      SEQ    2    next is 5
 *       INT   3    next is 4
 *       OCT   4    next is 5
 *      UTF    5    next is NULL
 * </code>
 * </pre>
 * <p>Note that you can't determine the last entry based on the next. That is, a
 * NULL next doesn't necessarily mean that this is the last in an array.
 * <p>You will almost certainly not build the MAsn1Element struct yourself (you
 * will call MAsn1CreateElementArray), but you need to know about the fields of
 * this struct. You might set some values when encoding and you will definitiely
 * read some values after decoding.
 * <p>When encoding, you can set the value.pValue, valueLen, and state fields
 * (you should call the special functions to set Elements without touching the
 * fields). There is one case where you might OR in a value to the type field.
 * You should set no other field. When decoding you will likely read the
 * value.pValue, valueLen, encoding.pEncoding, encodingLen, and state fields.
 * There will likely be no reason to read any others.
 * <p>When encoding, for non-constructed types (not SEQUENCE, SET) the ASN.1 code
 * will look at the value.pValue field for the actual data to encode. You can
 * either set those values yourself or call a Set function (such as
 * MAsn1SetInteger) (you should call the set functions). Note that a Set function
 * will probably copy a reference.
 * <p>If an encoding and value are not to be written out (it is OPTIONAL and the
 * option is not exercised or DEFAULT and the actual value is the default), then
 * make sure valueLen is 0, or better yet, call MAsn1SetValueLenSpecial with
 * MASN1_NO_VALUE. You can OR in MASN1_NO_VALUE to the type field (but you should
 * call the SetValueLenSpecial function). This is the only case where you will
 * touch that field. And remember, you OR it in, you don't set it. Do not OR in
 * NO_VALUE unless the Element is OPTIONAL or DEFAULT.
 * <p>If the type is constructed (SET or SEQUENCE) and OPTIONAL, to specify there
 * is no data, call the SetValueLenSpecaila function or OR in the MASN1_NO_VALUE
 * bit to the type field. With SET and SEQUENCE, the valueLen field is the number
 * of sub elements, not the data length, so don't set that to indicate no value,
 * you must OR in the NO_VALUE bit, or preferably call the SetValueLenSpecial
 * function.
 * <p>If the Type is BOOLEAN, call MAsn1SetBoolean. If the element is a DEFAULT,
 * and the value is to be the default value, then you will set the special flag
 * and simply not call SetBoolean.
 * <p>If the Type is UTCTime or GeneralizedTime, you can call MAsn1SetTime which
 * will convert the time represented as TimeDate into a byte array.
 * <p>If the Type is INTEGER, you can call MAsn1SetInteger, which has the option
 * of setting the value as an sbyte4. You can set the integer using a canonical
 * value (set value.pValue to the address containing the canonical integer), but
 * with INTEGER there is a possible leading octet, so if you don't want to deal
 * with that, use the Set function. There is also MAsn1SetIntegerFromVlong.
 * <p>If the type is anything else, when encoding, you can call MAsn1StValue (the
 * preferred method) or set value.pValue and valueLen to the data to encode. Note
 * that you are copying a reference to the buffer. Also, if you set the
 * value.pValue yourself or use SetValue, the ASN.1 engine does not check the
 * validity of input (e.g. is a byte array being set inside an Element designated
 * a UTF8String really a valid UTF8String?) Check to see if there are any
 * "outside" routines to verify validity.
 * <p>If you set the value.pValue field yourself, you must set the state field to
 * indicate whether all the data or only a portion has been added. See the
 * MASN1_STATE #defines for possible states. Calling the Set functions is better
 * because they will set the sate properly.
 * <p>After decoding, check the value.pValue and valueLen fields to find the
 * actual data from the encoding that is the V of TLV for this element. The value
 * will point to the data inside the encoding where the data begins. That is, it
 * is making a reference to the data, not copying the data.
 * <p>After decoding, the encoding field will point to the TLV of this element,
 * and encodingLen will be the total length (the length of TLV, not just V).
 * <p>NOTE! Looking at the pValue and pEncoding fields is valid only for that
 * call. That is, if you call DecodeUpdate, the result is the state at that call.
 * The next call to Update will possibly overwrite the fields. In fact, if using
 * DecodeUpdate, there's a good chance pEncoding will be wrong.
 * <p>If the decoded data is to be "converted" (e.g. a BOOLEAN into intBoolean or
 * an INTEGER to a sbyte4, or UTCTime to TimeDate), that will be a separate call.
 * <p>Note that there are variations on this theme for the Encoded type, and also
 * for specific ASN.1 atomic types such as BIT STRING and INTEGER. See the
 * documentation for each Type and the ASN.1 Engine "User's Guide" for more
 * information on the variations.
 * <p>The pBuf can contain an EXPLICIT || tag || extra byte, where the extra byte
 * might be unused bits or a prepended integer value. It might also contain the
 * actual value in the case of a BOOLEAN, an INTEGER passed in as an sbyte4, or a
 * Time if passed in as TimeDate.
 */
typedef struct
{
  ubyte4                     type;
  struct MAsn1Element       *pNext;
  union {
    ubyte                   *pValue;
    struct MAsn1OfTemplate  *pOfTemplate;
  } value;
  ubyte4                     valueLen;
  union {
    ubyte4                   remaining;
    ubyte                   *pEncoding;
  } encoding;
  ubyte4                     encodingLen;
  ubyte2                     state;
  ubyte2                     bitStringLast;
  ubyte2                     bufFlag;
  ubyte2                     bufLen;
  union {
    ubyte                   *pBuf;
    ubyte4                   remaining;
  } buffer;
} MAsn1Element;

#define MASN1_STATE_NONE                  0

/* The state is not a bit field, but if this bit is set in the state, the element
 * is indefinite. This is used for decoding.
 * Make sure no state that is not INDEF uses this bit.
 * Make sure each state that is INDEF sets this bit.
 * We want the state values to be increasing as more is decoded. We have a number
 * of pairs of states that are the same except one is INDEF. All the DECODE
 * states are in the 0x0f00 bits. We can then have an INDEF state that is the
 * same value as the non-INDEF state, but with the INDEF bit set. In this way,
 * each non-INDEF and INDEF state value is greater than the previous, but less
 * than the next, yet they are distinct.
 */
#define MASN1_STATE_DECODE_INDEF          0x0020
/* This is for when we are in the middle of reading an indefinite. This is
 * generally used to distinguish between tag reading states.
 */
#define MASN1_STATE_INDEF_CURRENT         (MASN1_STATE_DECODE_INDEF|0x0010)
/* This bit will be set if we are decoding an ENCODED and the length is
 * indefinite.
 */
#define MASN1_STATE_DECODE_INDEF_ENCODED  0x0040

/* If this bit is set, the data is being encoded indefinite.
 * This allows all encode values to be increasing in value.
 */
#define MASN1_STATE_ENCODE_INDEF          0x0001
#define MASN1_STATE_ENCODE_MASK           0x000E

/* Have set the length, but not the data.
 */
#define MASN1_STATE_SET_LEN               0x0002
/* Have set some of the data, but not all.
 * This means there is data to be written out.
 */
#define MASN1_STATE_SET_PARTIAL           0x0004
/* Have set all the data.
 * This means there is data to be written out.
 */
#define MASN1_STATE_SET_COMPLETE          0x0006
/* Have written out the tag and len.
 */
#define MASN1_STATE_ENCODE_TAG_LEN        0x0008
/* Have written out some of the encoding.
 */
#define MASN1_STATE_ENCODE_PARTIAL        0x000A
/* Have written out the entire encoding of this Element.
 */
#define MASN1_STATE_ENCODE_COMPLETE       0x000C

/* Have set some of the data, but not all, and we don't know the total length so
 * this will be indefinite.
 * This means there is data to be written out.
 */
#define MASN1_STATE_SET_PARTIAL_INDEF \
     (MASN1_STATE_SET_PARTIAL|MASN1_STATE_ENCODE_INDEF)
/* Have set all the data but we never knew the total length, so this will be
 * indefinite.
 * This means there is data to be written out.
 */
#define MASN1_STATE_SET_COMPLETE_INDEF \
    (MASN1_STATE_SET_COMPLETE|MASN1_STATE_ENCODE_INDEF)

/* Have written out the tag and len and the len is indefinite.
 */
#define MASN1_STATE_ENCODE_TAG_LEN_INDEF  \
    (MASN1_STATE_ENCODE_TAG_LEN|MASN1_STATE_ENCODE_INDEF)
/* Have written out some of the encoding and the length is indefinite.
 */
#define MASN1_STATE_ENCODE_PARTIAL_INDEF  \
    (MASN1_STATE_ENCODE_PARTIAL|MASN1_STATE_ENCODE_INDEF)
/* We have written out all the data for an indefinite. This means we need to
 * write out the trailing 00 00.
 */
#define MASN_STATE_ENCODE_DATA_INDEF      (0x000A|MASN1_STATE_ENCODE_INDEF)

/* Have decoded the EXPLICIT tag.
 */
#define MASN1_STATE_DECODE_TAGX           0x0100
/* Have decoded the length len, the number of bytes that make up the length, of
 * the EXPLICIT.
 */
#define MASN1_STATE_DECODE_LEN_LENX       0x0200
/* Have decoded some of the length octets of the EXPLICIT.
 */
#define MASN1_STATE_DECODE_PARTIAL_LENX   0x0300
/* Have decoded the length of the EXPLICIT.
 */
#define MASN1_STATE_DECODE_LENX           0x0400
/* Have decoded the length of the EXPLICIT and it is indefinite.
 */
#define MASN1_STATE_DECODE_LENX_INDEF \
     (MASN1_STATE_DECODE_LENX|MASN1_STATE_DECODE_INDEF)

#define MASN1_STATE_DECODE_START          0x0500
/* Have decoded the tag.
 */
#define MASN1_STATE_DECODE_TAG            0x0600
/* Have decoded the tag and it is indefinite. Some tags change when the length is
 * indefinite (e.g. OCTET STRING 0x for definite length, 24 for indefinite).
 * Others don't change (e.g. SEQUENCE). But if a tag has changed we need to know
 * that we are expecting indefinite length.
 * For example, if the tag is 0x24, then we have decoded the TAG_INDEF and we
 * will be looking for 0x80 as the length.
 */
#define MASN1_STATE_DECODE_TAG_INDEF \
      (MASN1_STATE_DECODE_TAG|MASN1_STATE_DECODE_INDEF)
/* Have decoded a tag underneath an indefinite. For example, if we decoded 24 80,
 * we will expect to see 04 len. And we did see 04 len. So we need to indicate we
 * are in the middle of an indefinite length, but we now have a regular tag.
 */
#define MASN1_STATE_DECODE_INDEF_TAG \
      (MASN1_STATE_DECODE_TAG|MASN1_STATE_INDEF_CURRENT)
/* Have decoded the length len, the number of bytes that make up the length.
 */
#define MASN1_STATE_DECODE_LEN_LEN        0x0700
/* Have decoded the length len underneath an indefinite.
 */
#define MASN1_STATE_DECODE_INDEF_LEN_LEN  \
    (MASN1_STATE_DECODE_LEN_LEN|MASN1_STATE_INDEF_CURRENT)
/* Have decoded some of the length octets.
 */
#define MASN1_STATE_DECODE_PARTIAL_LEN    0x0800
/* Have decoded the length len underneath an indefinite.
 */
#define MASN1_STATE_DECODE_INDEF_PARTIAL_LEN  \
    (MASN1_STATE_DECODE_PARTIAL_LEN|MASN1_STATE_INDEF_CURRENT)
/* Have decoded the length.
 */
#define MASN1_STATE_DECODE_LEN            0x0900
/* Have decoded the length len underneath an indefinite.
 */
#define MASN1_STATE_DECODE_INDEF_LEN      \
    (MASN1_STATE_DECODE_LEN|MASN1_STATE_INDEF_CURRENT)
/* Have decoded the length and it is indefinite.
 */
#define MASN1_STATE_DECODE_LEN_INDEF \
      (MASN1_STATE_DECODE_LEN|MASN1_STATE_DECODE_INDEF)
/* Have decoded some of the value.
 */
#define MASN1_STATE_DECODE_PARTIAL        0x0A00
/* Have decoded some of the indefinite value. We know there is more data, and
 * when this block of indefinite ends, we will need to check the next tag for
 * more data or 00 meaning the end of the data.
 */
#define MASN1_STATE_DECODE_PARTIAL_INDEF \
  (MASN1_STATE_DECODE_PARTIAL|MASN1_STATE_DECODE_INDEF)
/* Have decoded an indefinite block. Next we will look for another tag (another
 * indefinite block) or 00 00.
 */
#define MASN1_STATE_DECODE_INDEF_BLOCK    (0x0B00|MASN1_STATE_DECODE_INDEF)
/* Have decoded everything in an indefinite, and have read the first 00 byte
 * indicating the end of an indefinite.
 */
#define MASN1_STATE_DECODE_INDEF_00_1     (0x0C00|MASN1_STATE_DECODE_INDEF)
/* Have decoded everything in an indefinite, and have read the second 00 byte
 * indicating the end of an indefinite.
 */
#define MASN1_STATE_DECODE_INDEF_00_2     (0x0D00|MASN1_STATE_DECODE_INDEF)
/* Have decoded everything for this Element.
 */
#define MASN1_STATE_DECODE_COMPLETE       0x0F00
/* Have decoded everything for this Element, which was indefinite.
 */
#define MASN1_STATE_DECODE_COMPLETE_INDEF \
 (MASN1_STATE_DECODE_COMPLETE|MASN1_STATE_DECODE_INDEF)

/* The value when we've decoded the EXPLICIT tag and length, and discovered that
 * the length is indefinite.
 * We're going to need to pass all the data other than the EXPLICIT tag and
 * length to the DataReturn function.
 */
#define MASN1_STATE_DECODE_INDEF_ENCODED_LENX \
    (MASN1_STATE_DECODE_INDEF_ENCODED|0x1000)
/* We've decoded a tag and we know it is indefinite. This happens when we have an
 * EXPLICIT with indefinite length encoding.
 * This state means the tag has been passed to the DataReturn function.
 */
#define MASN1_STATE_DECODE_INDEF_ENCODED_TAG \
    (MASN1_STATE_DECODE_INDEF_ENCODED|0x2000)
/* We've decoded a length and discovered that it is indefinite. This means we
 * decoded the tag but didn't know it was indefinite yet. For example, a SEQUENCE
 * was indefinite, so the tag didn't change, so we didn't know it was indefinite.
 * Hence, we did not pass the tag to the DataReturn function (hence the NO_TAG).
 * We also have not passed the length octet (the 0x80 indefinite length) to the
 * DataReturn callback).
 */
#define MASN1_STATE_DECODE_INDEF_ENCODED_LEN_NO_TAG \
    (MASN1_STATE_DECODE_INDEF_ENCODED|0x3000)
/* We've decoded a length and it is indefinite, but we also knew that it was
 * going to be indefinite (either because the tag said so or we had an EXPLICIT
 * indefinite), and we have already passed the tag to the DataReturn callback.
 */
#define MASN1_STATE_DECODE_INDEF_ENCODED_LEN \
    (MASN1_STATE_DECODE_INDEF_ENCODED|0x4000)
/* We're in the middle of decoding an indefinite ENCODED, and we have decoded a
 * tag for some contents. That tag hass been passed to the DataReturn callback.
 */
#define MASN1_STATE_DECODE_INDEF_ENCODED_SUB_TAG \
    (MASN1_STATE_DECODE_INDEF_ENCODED|0x5000)
/* We're in the middle of decoding an indefinite ENCODED, and we have decoded the
 * first length octet and it was 0x80. We have passed this octet to the
 * DataReturn callback, and we now expect the next octet to be a tag.
 */
#define MASN1_STATE_DECODE_INDEF_ENCODED_SUB_INDEF_LEN \
    (MASN1_STATE_DECODE_INDEF_ENCODED|0x6000)
/* We're in the middle of decoding an indefinite ENCODED, and we have decoded the
 * first length octet and it was > 0x80, so we know the length of the length. We
 * have passed this octet to the DataReturn callback.
 */
#define MASN1_STATE_DECODE_INDEF_ENCODED_SUB_LEN_LEN \
    (MASN1_STATE_DECODE_INDEF_ENCODED|0x7000)
/* We're in the middle of decoding an indefinite ENCODED, and we have decoded the
 * some of the length octets and have passed them to the DataReturn callback.
 */
#define MASN1_STATE_DECODE_INDEF_ENCODED_SUB_PARTIAL_LEN \
    (MASN1_STATE_DECODE_INDEF_ENCODED|0x8000)
/* We're in the middle of decoding an indefinite ENCODED, and we have decoded the
 * length octets and have passed them to the DataReturn callback.
 */
#define MASN1_STATE_DECODE_INDEF_ENCODED_SUB_LEN \
    (MASN1_STATE_DECODE_INDEF_ENCODED|0x9000)
/* We're in the middle of decoding an indefinite ENCODED, and we have decoded
 * some of the actual data and have passed them to the DataReturn callback.
 * For example, we decoded 24 80 04 10 01 02 03, but we know there are 13 more
 * bytes for the 04 10.
 */
#define MASN1_STATE_DECODE_INDEF_ENCODED_SUB_PARTIAL \
    (MASN1_STATE_DECODE_INDEF_ENCODED|0xA000)
/* We're in the middle of decoding an indefinite ENCODED, and we have decoded
 * some of the actual data and have passed them to the DataReturn callback.
 * For example, we decoded 24 80 04 03 01 02 03.
 */
#define MASN1_STATE_DECODE_INDEF_ENCODED_SUB_DATA \
    (MASN1_STATE_DECODE_INDEF_ENCODED|0xB000)
/* We're in the middle of decoding an indefinite ENCODED, and we have decoded the
 * first 00 octet of an 00 00, and have passed it to the DataReturn callback if
 * needed.
 */
#define MASN1_STATE_DECODE_INDEF_ENCODED_SUB_00_1 \
    (MASN1_STATE_DECODE_INDEF_ENCODED|0xC000)
/* We're in the middle of decoding an indefinite ENCODED, and we have decoded the
 * second 00 octet of an 00 00, and have passed it to the DataReturn callback if
 * needed.
 */
#define MASN1_STATE_DECODE_INDEF_ENCODED_SUB_00_2 \
    (MASN1_STATE_DECODE_INDEF_ENCODED|0xD000)

/* Note that when we are completely done with an ENCODED that was indefinite
 * length, we will set the state to MASN1_STATE_DECODE_COMPLETE_INDEF.
 */

/* These are the values in the bufFlag
 *   0xf000   For decode: the number of trailing 00 00 pairs we are looking for.
 *            If an Element can be indefinite, but is not, this will be 0.
 *            If an Element is not EXPLICIT and indef, this will be 1 (0x1000)
 *            If an Element is EXPLICIT and both the EXP and tag are indef, this
 *            will be 2 (0x2000)
 *   0x0800   Encode: We have checked for DER and it passes.
 *   0x0400   Encode: If set, the next write will complete this Element.
 *   0x0200   Decode: regular tag is indefinite
 *   0x0100   Decode: EXPLICIT tag is indefinite
 *   0x0080   unused
 *   0x0040   Decode: the Element is indefinite
 *   0x0020   Encode: we have init for indefinite
 *   0x0010   this Element is built for indefinite
 *   0x0008   this Element is built for Decode
 *   0x0004   this Element is built for Encode
 *   0x0002   this Element is the last one
 *   0x0001   free flag: free the pBuf?
 */

#define MASN1_BUF_FLAG_ZERO_COUNT_MASK    0xF000
#define MASN1_BUF_FLAG_ZERO_COUNT_SHIFT   12

#define MASN1_BUF_FLAG_NO_FREE            0x0000
/* If this bit is set in the bufFlag, then pBuf points to allocated memory that
 * must be freed separately.
 */
#define MASN1_BUF_FLAG_FREE               0x0001
/* If this bit is set in the bufFlag, then this Element is the last in the array.
 */
#define MASN1_BUF_FLAG_LAST               0x0002

/* If this bit is set in the bufFlag, then this Element is built to encode.
 */
#define MASN1_BUF_FLAG_ENCODE             0x0004
/* If this bit is set in the bufFlag, then this Element is built to decode.
 */
#define MASN1_BUF_FLAG_DECODE             0x0008
/* If this bit is set in the bufFlag, then this Element is built for indefinite.
 */
#define MASN1_BUF_FLAG_ENCODE_INDEF       (0x0010|MASN1_BUF_FLAG_ENCODE)
/* If this bit is set in the bufFlag, then this Element has been init to encode
 * indefinite.
 */
#define MASN1_BUF_FLAG_ENCODE_INDEF_INIT  0x0020
/* Set this bit to indicate we have checked this Element for encoding DER and it
 * passed (it is set so that it will encode DER).
 */
#define MASN1_BUF_FLAG_DER_CHECK          0x0800
/* Set this bit to indicate that the next write will complete the Element. It is
 * used in computing required len.
 */
#define MASN1_BUF_FLAG_WILL_COMPLETE      0x0400

/* These are bits used by indefinite decode.
 */
/* This bit is set as soon as we know an Element is indefinite. If this bit is
 * set, we know to continue the process a little differently (call Data callback
 * or look for another tag).
 */
#define MASN1_BUF_FLAG_INDEF              0x0040
/* Set this bit if the Element is EXPLICIT and the EXPLICIT was indefinite.
 */
#define MASN1_BUF_FLAG_INDEF_EXP          0x0100
/* Set this bit if the regular tag is indefinite (whether or not there is
 * EXPLICIT).
 */
#define MASN1_BUF_FLAG_INDEF_TAG          0x0200

/** This is the function signature of a callback. When the function
 * MAsn1DecodeIndefiniteUpdate encounters indefinite length data, it will decode
 * it and call the callback passed in. That is, the caller must supply a function
 * to process indefinite length data.
 * <p>See the comments for MAsn1DecodeIndefiniteUpdate for more information on
 * indefinite length encoding.
 * <p>The function that implements this typedef will process the given data based
 * on the given element. That is, while the ASN.1 engine was decoding the given
 * element, it encountered indefinite length. It was able to read dataLen bytes
 * and is returning those bytes to the caller. The caller can copy these bytes
 * into a new buffer, write them to a file, or whatever it wants.
 * <p>It is possible that more than one element contains indefinite length data.
 * To know which data is being returned, check the MAsn1Element. You can look at
 * the type to see what the tag is, or compare it to the elements in the template
 * you originally built. Often there is only one element in an ASN.1 definition
 * that can have indefinite data, so sometimes it is not necessary to determine
 * which element is reading the data.
 * <p>The pCallbackInfo is whatever the caller passed as the pCallbackInfo in the
 * call to MAsn1DecodeIndefiniteUpdateFlag. This is whatever the callback needs in
 * order to complete the task. It might be a file handle, it could be a pointer
 * to a buffer, it could be a struct containing several units of information.
 */
typedef MSTATUS (*IndefiniteLengthDataReturn) (
  void *pCallbackInfo,
  ubyte *pData,
  ubyte4 dataLen,
  MAsn1Element *pElement
  );

/** This is the signature of an OfFunction. It is the function that can perform
 * operations needed by SEQUENCE OF and SET OF.
 * <p>For most types, most operations are very similar (or exactly the same). But
 * there are some intricacies with SET OF and SEQUENCE OF. That takes more code.
 * So we don't want to load that code unless it is really needed. All OF code is
 * referenced by this function (it actually is the conduit through which the OF
 * code is called), so when you make a reference to the OfFunction, you load the
 * code. You make a reference to the OfFunction when you create the Element array
 * if one of the elements is an OF.
 * <p>An Of function is the typical Operator function, taking the Entry in
 * question, an operation (a flag indicating what you want it to do), and input
 * and output data (each operation defines what the input and output is).
 * <p>The possible values of an operation are the MASN1_OF_ values #defined
 * later. Each OF operation will also document the format of the input and output
 * information.
 */
typedef MSTATUS (*MOfFunction) (
  struct MAsn1OfEntry *pEntry,
  ubyte4 operation,
  void *pInput,
  void *pOutput
  );

/* An OF can have an indefinite number of entries. This represents one entry.
 * <p>When encoding or decoding, the ASN.1 engine will build a link list of all
 * the entries.
 * <p>Because the contents of an OF can be only one element (although that
 * element can be a SEQUENCE or SET), each entry in the link list is one element.
 * <p>You should never build one yourself. The ASN.1 engine will build these when
 * you call MAsn1CreateElementArray or MAsn1CopyAddOfEntry.
 * <p>If you have a SEQUENCE OF or SET OF, that means there could be 0, 1, 2, or
 * virtually any number of entries. Because we can't know in advance how many
 * entries there will be, we need a technique to hold variable counts of entries.
 * This is that technique.
 * <p>When you build the original array (see MAsn1CreateElementArray) you wil
 * specify the contents of the OF. The ASN.1 engine will build the first Entry.
 * That is index 0.
 * <p>When encoding, you will set the Elements in the original template with the
 * data for the first entry. Then, if there are more entries, you call
 * MAsn1CopyAddOfEntry to get a new template and set that one with the next data.
 * <p>When decoding, you build the array normally, but after the data has been
 * decoded, you can call MAsn1GetOfElementAtIndex to get all the entries that
 * were decoded. The ASN.1 engine will have built as many new Entries as it
 * needed to accomodata the data it encountered.
 * <p>Note that a SET OF or SEQUENCE OF can contain only one type. For example, a
 * SEQUENCE definition can contain two different types, but a SEQUENCE OF can
 * contain only one type.
 * <pre>
 * <code>
 *   correct:  SEQUENCE {
 *               OID,
 *               OCTET STRING }
 *
 *   wrong:    SEQUENCE OF {
 *               OID,
 *               OCTET STRING }
 *
 *   correct   SEQUENCE OF {
 *               OID }
 *
 *   correct:  SEQUENCE OF {
 *               SEQUENCE {
 *                 OID,
 *                 OCTET STRING } }
 * </code>
 * </pre>
 * <p>The entryFlag will contain information needed by the ASN.1 engine. It will
 * contain flags to indicate whether the Entry and/or the Element therein need to
 * be freed separately.
 * <p>See also the documentation for MAsn1CopyAddOfEntry.
 */
typedef struct MAsn1OfEntry
{
  MAsn1Element            *pElement;
  ubyte4                   entryFlag;
  struct MAsn1OfEntry     *pNext;
} MAsn1OfEntry;

/* Or in this bit to MAsn1OfEntry.entryFlag to indicate that the pElement in the
 * OfEntry needs to be freed by the engine.
 */
#define MASN1_OF_FREE_ELEMENT  0x00000001
/* Or in this bit to MAsn1OfEntry.entryFlag to indicate that the OfEntry itself
 * needs to be freed by the engine.
 */
#define MASN1_OF_FREE_ENTRY    0x00000010

/* This is what is stored inside an MAsn1Element when a type is an OF.
 * <p>The Element will contain the OfFunction, the next Element in the array, and
 * a pointer to the first element in the link list.
 * <p>When an OF Element is created, an OfTemplate is also created, along with
 * the first Entry.
 */
typedef struct MAsn1OfTemplate
{
  MOfFunction              OfFunction;
  struct MAsn1Element     *pNext;
  MAsn1OfEntry             entry;
} MAsn1OfTemplate;

/* The operation arg for an OfFunction when the function is to free the memory
 * the OF allocated during its operations.
 * <p>This means to free this Entry AND any other entries in the link list.
 * <p>The pInputInfo is NULL.
 * <p>The pOutputInfo is NULL.
 */
#define MASN1_OF_FREE         1

/* The operation arg for an OfFunction when the function is to encode the sub
 * elements of the OF.
 * <p>This means write out the TLV of each entry in the link list.
 * <p>The pInputInfo is a pointer to MAsn1OfEncodeInput.
 * <p>The pOutputInfo is a pointer to MAsn1OfEncodeOutput.
 */
#define MASN1_OF_ENCODE       2

/* The operation arg for an OfFunction when the function is to decode the sub
 * elements of the OF.
 * <p>This means read TLV of each entry in the link list.
 * <p>The pInputInfo is a pointer to MAsn1OfDecodeInput.
 * <p>The pOutputInfo is a pointer to MAsn1OfDecodeOutput.
 */
#define MASN1_OF_DECODE       4

/* The operation arg for an OfFunction when the function is to initialize an
 * Element for encoding.
 * <p>See MAsn1EncodeInit.
 * <p>The pInputInfo is NULL
 * <p>The pOutputInfo is a pointer to MAsn1OfEncodeInitOutput
 */
#define MASN1_OF_ENCODE_INIT  8

/* This is the input info passed to the OfFunction when the operation is ENCODE.
 */
typedef struct
{
  ubyte          *pEncoding;
  ubyte4          bufferSize;
  ubyte4         *pEncodingLen;
  ubyte4          computeFlag;
} MAsn1OfEncodeInput;

/* This is the output info passed to the OfFunction when the operation is ENCODE.
 */
typedef struct
{
  intBoolean     *pIsComplete;
  MAsn1Element  **ppNextElement;
} MAsn1OfEncodeOutput;

/* This is the input info passed to the OfFunction when the operation is DECODE.
 */
typedef struct
{
  MAsn1Element                *pOfElement;
  ubyte                       *pEncoding;
  ubyte4                       encodingLen;
  ubyte4                       decodeFlag;
  IndefiniteLengthDataReturn   DataReturn;
  void                        *pCallbackInfo;
} MAsn1OfDecodeInput;

/* This is the output info passed to the OfFunction when the operation is DECODE.
 */
typedef struct
{
  ubyte4         *pBytesRead;
} MAsn1OfDecodeOutput;

/* This is the output info passed to the OfFunction when the operation is
 * HAS_DATA.
 */
typedef struct
{
  ubyte4          initFlag;
  intBoolean     *pIsPartialSet;
  ubyte4         *pSubLen;
  MAsn1Element  **ppNextElement;
} MAsn1OfEncodeInitOutput;

/** In order to do anything with the ASN.1 engine, you need to build an
 * MAsn1Element array (which can be of length 1). But to build an MAsn1Element
 * array, you first need to build an MAsn1TypeAndCount array that represents the
 * ASN.1 definition.
 * <p>In order to build an MAsn1TypeAndCount, you must know what to set the
 * fields.
 * <p>You set the tagSpecial to be the OR of the MASN1_TYPE_ and special
 * instructions. The MASN1_TYPE_ values are defined above, they are the "atomic"
 * types of ASN.1 such as BOOLEAN, INTEGER, SEQUENCE, UTF8String, and so on. The
 * special instructions are EXPLICIT, IMPLICIT, OPTIONAL, and DEFAULT.
 */

/** OR in this value to the tagSpecial field in an MAsn1TypeAndCount struct if
 * the definition specifies EXPLICIT. When defined as EXPLICIT, the definition
 * will also have a number in square brackets. You OR in this value with that
 * number.
 * <p>For example:
 * <pre>
 * <code>
 *    // If the definiton is something like this:
 *    //   ...
 *    //   version   [1] EXPLICIT INTEGER DEFAULT 2,
 *    //   ...
 *    // you would set the tagSpecial field like this
 *    element[4].tagSpecial =
 *      MASN1_TYPE_INTEGER | MASN1_EXPLICIT | MASN1_DEFAULT | 1;
 * </code>
 * </pre>
 * <p>Note that the number in the square brackets was ORed into the value. In
 * this case, the INTEGER is DEFAULT and is the number 2. That means if the value
 * is 2, don't write it out in the encoding. Or when decoding, if there's nothing
 * there for the INTEGER, the value is 2. You do not specify the default value
 * when building the data structs.
 * <p>Note also that in an ASN.1 definition, if there is a square bracket but no
 * EXPLICIT or IMPLICIT, the element is EXPLICIT. For example,
 * <pre>
 * <code>
 *    // If the definiton is something like this:
 *    //   ...
 *    //   digestOid   [4] OPTIONAL,
 *    //   ...
 *    // you would set the tagSpecial field like this
 *    element[4].tagSpecial =
 *      MASN1_TYPE_OID | MASN1_EXPLICIT | MASN1_OPTIONAL | 4;
 * </code>
 * </pre>
 */
#define MASN1_EXPLICIT             0x20000000

/** OR in this value to the tagSpecial field in an MAsn1TypeAndCount struct if
 * the definition specifies IMPLICIT. When defined as IMPLICIT, the definition
 * will also have a number in square brackets. You OR in this value with that
 * number.
 * <p>For example:
 * <pre>
 * <code>
 *    // If the definiton is something like this:
 *    //   ...
 *    //   pubVal   [0] IMPLICIT INTEGER OPTIONAL,
 *    //   ...
 *    // you would set the tagSpecial field like this
 *    element[4].tagSpecial =
 *      MASN1_TYPE_INTEGER | MASN1_IMPLICIT | MASN1_OPTIONAL | 0;
 * </code>
 * </pre>
 */
#define MASN1_IMPLICIT             0x10000000

/** OR in this value to the tagSpecial field in an MAsn1TypeAndCount struct if
 * the definition specifies OPTIONAL.
 * <p>For example:
 * <pre>
 * <code>
 *    // If the definiton is something like this:
 *    //   ...
 *    //   pubVal   [1] IMPLICIT OCTET STRING OPTIONAL,
 *    //   ...
 *    // you would set the tagSpecial field like this
 *    element[4].tagSpecial =
 *      MASN1_TYPE_OCTET_STRING | MASN1_IMPLICIT | MASN1_OPTIONAL | 1;
 * </code>
 * </pre>
 * <p>It is possible to set an ENCODED Element to OPTIONAL, but when decoding,
 * that will work only if it is the last component of a SEQUENCE or SET. For
 * example, an algorithm identifier is the following.
 * <pre>
 * <code>
 *    SEQUENCE {
 *      algorithm  OID,
 *      parameters ANY defined by OID }
 * </code>
 * </pre>
 * <p>If there are no params, the ANY can be 05 00 or 30 00 or simply nothing. If
 * you are decoding and there are no params at all, then the decoder will
 * recognize that there are no bytes left and will do nothing. But if there had
 * been something after the params, then the Encoded would have simply picked up
 * that next thing.
 */
#define MASN1_OPTIONAL             0x80000000

/** OR in this value to the tagSpecial field in an MAsn1TypeAndCount struct if
 * the definition specifies DEFAULT.
 * <p>For example:
 * <pre>
 * <code>
 *    // If the definiton is something like this:
 *    //   ...
 *    //   isCritical   BOOLEAN DEFAULT TRUE,
 *    //   ...
 *    // you would set the tagSpecial field like this
 *    element[2].tagSpecial = MASN1_BOOLEAN | MASN1_DEFAULT;
 * </code>
 * </pre>
 * <p>Note that you do not OR in the default value. You only OR in the DEFAULT
 * and any other special instructions (such as EXPLICIT).
 * <p>When encoding a default, it is the caller's responsibility to know whether
 * the value to encode is the default value or not. If it is the default value,
 * you leave the value.pValue field NULL (or don't call a Set function). The
 * Operator will see that there is no data to write out, but also see that the
 * element is default, so no data is allowed.
 * <p>When decoding a default, the Operator will return data if it is there, but
 * NULL if there is not (and know that because the element is default, it is
 * acceptable to have no data). It is the caller's responsibility to determine
 * what the default value is if the Operator returns a NULL value.
 */
#define MASN1_DEFAULT              0x40000000

/** OR in this value to the type field in an MAsn1Element struct before encoding
 * to specify that an Element is not to be written. This is for OPTIONAL and
 * DEFAULT. It is the only way to specify no value for a SEQUENCE or SET.
 * <p>NOTE!!! You will almost certainly not OR in this value of tagSpecial when
 * building the TypeAndCount defintion array. This is to be used before encoding
 * when you determine if an Element is to be encoded or not.
 * <p>If a component is defined as OPTIONAL or DEFAULT, before encoding, you must
 * determine if there is something there or not. If not, there are two ways to
 * let the encoder know not to write out the element. First, simply make sure the
 * value.pValue and valueLen fields are NULL and 0. The second way is to set this
 * bit in the special field.
 * <p>However, a SEQUENCE or SET does not use the value.pValue field. Hence, you
 * cannot specify that a SEQUENCE or SET that is OPTIONAL or DEFAULT should not
 * be written out by making that field NULL. Therefore, if you have a SEQUENCE or
 * SET Element, and it is OPTIONAL or DEFAULT, and the data is to be left out
 * (the option is not exercised or the value is the default value), then you must
 * set this bit.
 * <p>For an Element that is not SET or SEQUENCE, you can specify no value by
 * either setting the NO_VALUE bit or by simply making sure the value.pValue
 * field is NULL.
 * <p>If you set the NO_VALUE bit and not the OPTIONAL or DEFAULT bits, then the
 * encoder will write out tag 00 (e.g. 04 00 for an empty OCTET STRING). Note
 * that some types are not allowed to have no data (e.g. INTEGER).
 * <p>Note that this bit is not used by the decoder. If a SEQUENCE or SET is
 * OPTIONAL or DEFAULT, and no value is in the encoded data, then the
 * encoding.pEncoding and encodingLen fields will be NULL and 0. For other
 * Elements, the value.pValue and encoding.pEncoding fields will be NULL.
 */
#define MASN1_NO_VALUE             0x00001000

/* Internal. This tells a sub Element to skip encoding because the parent
 * constructed (SEQ or SET) is OPTIONAL and not taken.
 */
#define MASN1_NO_VALUE_SKIP        0x00001800

/** OR in this value to indicate that an entry has no value at the moment, but it
 * might later on. This is for indefinite encoding.
 */
#define MASN1_UNKNOWN_VALUE        0x00002000
/** OR in this value to indicate that an OF entry has no value at the moment, but
 * it will later on. This is for indefinite encoding.
 */
#define MASN1_UNKNOWN_OF           0x00004000

#define MASN1_CLEAR_UNKNOWN_VALUE  0x00000800
#define MASN1_CLEAR_UNKNOWN_OF     0x00000400
#define MASN1_VALUE_TYPE_MASK      0x00007000

/** This is the type of each entry in an ASN.1 definition, or template.
 * <p>When you specify a definition to encode or decode, you build an array of
 * these structs. Each entry represents one element of the ASN.1 definition.
 * <p>You set tagSpecial to the tag and any special info about the entry, such as
 * EXPLICIT or OPTIONAL. The values must be an OR of the MASN1_TYPE_ flags and
 * special flags defined above (MASN1_EXPLICIT, MASN1_IMPLICIT, etc.).
 * <p>If the type is SEQUENCE or SET, you specify the number of sub elements in
 * the count field. For all other types, set that value to 0. Note that for
 * SEQUENCE OF and SET OF, the count is always 1 and so it is not necessary to
 * set that value, but you can if you want.
 * <p>For example,
 * <pre>
 * <code>
 *     // For the definition
 *     //   SEQUENCE {
 *     //     INTEGER,
 *     //     OBJECT IDENTIFIER,
 *     //     OCTET STRING }
 *     //
 *     MAsn1TypeAndCount pTemplate[4] = {
 *       { MASN1_TYPE_SEQUENCE, 3 },
 *         { MASN1_TYPE_INTEGER, 0 },
 *         { MASN1_TYPE_OID, 0 },
 *         { MASN1_TYPE_OCTET_STRING, 0 },
 *     };
 *
 *     // For the defintion
 *     //   SEQUENCE {
 *     //     INTEGER,
 *     //     SEQUENCE {
 *     //       BOOLEAN DEFAULT TRUE,
 *     //       <something, write or read something already encoded> },
 *     //     BIT STRING }
 *     MAsn1TypeAndCount pTemplate[6] = {
 *       { MASN1_TYPE_SEQUENCE, 3 },
 *         { MASN1_TYPE_INTEGER, 0 },
 *         { MASN1_TYPE_SEQUENCE, 2 },
 *           { MASN1_TYPE_BOOLEAN | MASN1_DEFAULT, 0 },
 *           { MASN1_TYPE_ENCODED, 0 },
 *         { MASN_TYPE_BIT_STRING, 0 }
 *     };
 * </code>
 * </pre>
 * <p>Notice that you put together the array in the order they appear in the
 * definition. In the second example, the first sequence is going to know that it
 * has three sub elements: INTEGER, SEQUENCE, BIT STRING. The second sequence has
 * two sub elements: BOOLEAN and ENCODED.
 */
typedef struct
{
  ubyte4    tagSpecial;
  ubyte4    count;
} MAsn1TypeAndCount;

/** Create a new Element array from a definition.
 * <p>This funtion will allocate memory for the array, set it to an initial state
 * based on the definition, and return the new array.
 * <p>You must call MAsn1FreeElementArray when you are done with it.
 * <p>The caller builds a definition by creating an array of MAsn1TypeAndCount
 * structs. Each entry in that array indicates what the corresponding Element is
 * to be. For example,
 * <pre>
 * <code>
 *     MAsn1Element pArray = NULL;
 *
 *     // For the defintion
 *     //   SEQUENCE {
 *     //     INTEGER,
 *     //     SEQUENCE {
 *     //       BOOLEAN DEFAULT TRUE,
 *     //       <something, write or read something already encoded> },
 *     //     BIT STRING }
 *     MAsn1TypeAndCount pTemplate[6] = {
 *       { MASN1_TYPE_SEQUENCE, 3 },
 *         { MASN1_TYPE_INTEGER, 0 },
 *         { MASN1_TYPE_SEQUENCE, 2 },
 *           { MASN1_TYPE_BOOLEAN | MASN1_DEFAULT, 0 },
 *           { MASN1_TYPE_ENCODED, 0 },
 *         { MASN_TYPE_BIT_STRING, 0 }
 *     };
 *
 *     status = MAsn1CreateElementArray (
 *       pTemplate, 6, MASN1_FNCT_ENCODE, NULL, &pArray);
 *
 *        . . .
 *
 *     MAsn1FreeElementArray (&pArray);
 * </code>
 * </pre>
 * <p>See also the documentation for MAsn1TypeAndCount.
 * <p>After creating the Element array, pArray[index] will be the Element built
 * to enocde or decode the data defined by pTemplate[index]. For example, in the
 * above sample, pArray[0] would be the Element for the outer SEQUENCE, and
 * pArray[3] would be the element for the BOOLEAN inside the inner SEQUENCE.
 * <p>You also pass in a flag indicating what you want to use the array for:
 * MASN1_FNCT_ENCODE or MASN1_FNCT_DECODE. The reason for this is to save memory
 * when decoding. If the ASN.1 engine knows the array will be used to decode, it
 * can allocate fewer bytes. If you pass in ENCODE, the array will be able to
 * decode, but if you pass in DECODE, the array will not be able to encode.
 * <p>If one of the Elements is an OF (SEQUENCE OF or SET OF), you must also pass
 * in the OfFunction: Masn1OfFunction. The reason for this is just to be able to
 * keep code size down. The code to handle an OF is extensive, and if you don't
 * ever use an OF in your definitions, then you don't want to load it. In this
 * way, if you are loading code by reference (that is, linking code in if it is
 * referenced, usually from a static library), you only reference the Of code if
 * you really use it.
 *
 * @param pDefinition The ASN.1 definition to build, represented as an array of
 * type/count pairs.
 * @param definitionCount The number of entries in the definition.
 * @param asn1Fnct What the array is being built for, MASN1_FNCT_ENCODE or
 * MASN1_FNCT_DECODE.
 * @param OfFunction Pass in Masn1OfFunction if any of the entries in the
 * definition is an OF (SEQUENCE_OF or SET_OF).
 * @param ppNewArray The address where the function will deposit the created
 * Element array.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1CreateElementArray (
  MAsn1TypeAndCount *pDefinition,
  ubyte4 definitionCount,
  ubyte4 asn1Fnct,
  MOfFunction OfFunction,
  MAsn1Element **ppNewArray
  );

/** Pass this value as the asn1Fnct arg in MAsn1CreateElementArray if you are
 * building an array to be used to encode.
 */
#define MASN1_FNCT_ENCODE         MASN1_BUF_FLAG_ENCODE

/** Pass this value as the asn1Fnct arg in MAsn1CreateElementArray if you are
 * building an array to be used to encode and will be using the indefinite length
 * encoding functions.
 */
#define MASN1_FNCT_ENCODE_INDEF   MASN1_BUF_FLAG_ENCODE_INDEF

/** Pass this value as the asn1Fnct arg in MAsn1CreateElementArray if you are
 * building an array to be used to decode.
 * <p>Note! If you use this arg, the array will not be able to encode (you will
 * get an error). If you build to decode, the function will allocate a little
 * less memory than when built to encode.
 */
#define MASN1_FNCT_DECODE         MASN1_BUF_FLAG_DECODE

/** Free an Element array created by MAsn1CreateElementArray.
 * <p>The caller passes in the address of an array. The function will go to that
 * address, free the array it finds there (or do nothing if there is none), and
 * set the address to NULL.
 *
 * @param ppArray The address where the function will find the array to free.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1FreeElementArray (
  MAsn1Element **ppArray
  );

/** Implements MOfFunction.
 */
MOC_EXTERN MSTATUS MAsn1OfFunction (
  struct MAsn1OfEntry *pEntry,
  ubyte4 operation,
  void *pInput,
  void *pOutput
  );

/** Implements MOfFunction.
 */
MOC_EXTERN MSTATUS MAsn1OfIndefFunction (
  struct MAsn1OfEntry *pEntry,
  ubyte4 operation,
  void *pInput,
  void *pOutput
  );

/* Free the Element in this Entry, and/or then the Entry itself, depending on the
 * entryFlag.
 * <p>Then move on to the next in the link list.
 */
MOC_EXTERN MSTATUS MAsn1OfFree (
  MAsn1OfEntry *pEntry
  );

/** This function will find the Type of the OF Element, copy it, and add it to
 * the OF Element.
 * <p>When encoding, you will specify the contents of a SET OF or SEQUENCE OF in
 * the definition (the TypeAndCount array). That will be the first entry in the
 * OF. But if you have more entries to add, call this function to have the engine
 * build a new Element (or Element array).
 * <p>If the pOfElement you pass in is not actually OF, the function will return
 * an error.
 * <p>The caller passes in an address of an MAsn1Element *, and the function will
 * deposit the Element built. The Element built will still be loaded into
 * pElement, it's just that you now have access to it as well. That is, there is
 * a new Element created and the engine owns it, you have a reference to it.
 * <p>Suppose the definition is this:
 * <pre>
 * <code>
 *    SEQUENCE {
 *      version        INTEGER,
 *      digestParams   DigestParams }
 *
 *    DigestParams ::= SET OF DigestParam
 *
 *    DigestParam ::= SEQUENCE {
 *      algorithm   OID,
 *      digestLen   INTEGER }
 *
 *  This is
 *    SEQUENCE {
 *      INTEGER,
 *      SET OF {
 *        SEQUENCE {
 *          OID,
 *          INTEGER } } }
 * </code>
 * </pre>
 * <p>You would build the original TypeAndCount and array like this.
 * <pre>
 * <code>
 *     MAsn1TypeAndCount pTemplate[6] = {
 *       { ASN1_TYPE_SEQUENCE, 2 }
 *         { ASN1_TYPE_INTEGER, 0 },
 *         { ASN1_TYPE_SET_OF, 1 },
 *           { ASN1_TYPE_SEQUENCE, 2 },
 *             {ASN1_TYPE_OID, 0 },
 *             {ASN1_TYPE_INTEGER, 0 },
 *     };
 *
 *     status = MAsn1CreateElementArray (
 *       pTemplate, 6, MASN1_FNCT_ENCODE, NULL, &pArray);

 * </code>
 * </pre>
 * <p>Suppose you had two DigestParams to set. You would set the first entry
 * using pArray.
 * <pre>
 * <code>
 *     status = MAsn1SetValue (pArray + 4, pSomeOid, someOidLen);
 *
 *     status = MAsn1SetInteger (pArray + 5, NULL, 0, 0, someDigestLen);
 * </code>
 * </pre>
 * <p>Now when you want to add a new entry to the SET OF, call CopyAdd. Then set
 * the Elements in this new array. Note that the function will return one
 * Element, but the truth is, it is an array, an array that is the same
 * definition as the contents of the OF.
 * <pre>
 * <code>
 *     status = MAsn1CopyAddOfEntry (pArray + 2, &pGetElement);
 *
 *     status = MAsn1SetValue (pGetElement + 1, pSomeOtherOid, someOtherOidLen);
 *
 *     status = MAsn1SetInteger (pGetElement + 2, NULL, 0, 0, someOtherDigestLen);
 * </code>
 * </pre>
 * <p>Notice the indices of the Element array from the CopyAdd. That function
 * builds an array for the contents of the OF, not the entire encoding.
 * <p>If you create a SET OF or SEQUENCE OF and never set the original contents
 * Element (or Element array), and never call Add, then the encoder will write
 * out 30 00 or 31 00. Remember, a SET OF or SEQUENCE OF can have 0 entries.
 * <p>When decoding, the engine will use the original definition to read the
 * first entry in the OF. If there are any more entries, the engine itself will
 * create the new entries and add them. You do not need to add them, you will
 * only retrieve them (see MAsn1GetOfElementAtIndex).
 *
 * @param pOfElement The OF Element to which we are adding.
 * @param ppNewElement The address where the function will deposit a pointer to
 * the newly created Element that was added to the OF Element.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1CopyAddOfEntry (
  MAsn1Element *pOfElement,
  MAsn1Element **ppNewElement
  );

/** Compare two templates. They are the same if there are the same types and if
 * constructed, the same sub element setup. No other fields in the Elements are
 * examined (e.g. this does not check to see if they have the same encoding).
 * <p>If the two are the same, the function sets *pCmpResult to 0 (similar to
 * memcmp), and also returns the number of actual Elements in the template. If
 * they are not the same, then it sets *pCmpResult to a non-zero value and
 * *pCount to 0.
 * <p>The function also returns the next Element in each array. For a
 * non-constructed Element, the next one is one immediately following it. For a
 * constructed Element, the next one is the Element immediately after the
 * contents.
 * <p>If the type is not a SET or SEQUENCE, then the count is 1. Note that if
 * they type is ENCODED, they compare the same.
 * <p>If the type is a SET or SEQUENCE, then the count is 1 plus the number of
 * Elements in the pSubArray, plus the number of Elements in any pSubArray of any
 * SET or SEQUENCE in any other Element encountered.
 * <p>For example, if the type is OCTET_STRING, then the count will be 1.
 * <p>If the template is based on this definition
 * <pre>
 * <code>
 *   SEQUENCE {
 *     OID,
 *     SEQUENCE {
 *       SEQUENCE {
 *         GenTime,
 *         INTEGER },
 *       UTF8String } }
 * </code>
 * </pre>
 * <p>then the count will be 7. Note also that the next Element will be the
 * Element after the UTF8 string. That can be NULL.
 * <p>If there is a SET OF or SEQUENCE OF, then the function will not count the
 * number of Entries in each OF. A SET OF or SEQUENCE OF will have a single Type
 * that is its contents. Yet it can have 0, 1, or more actual entries. As long as
 * that one Type (or constructed and all its sub types) is the same, regardless
 * of how many instance of that Type, they still compare equal.
 *
 * @param pElement1 One of the Elements to compare.
 * @param pElement2 The other Element to compare.
 * @param ppNext1 The address where the function will deposit the next Element
 * after Element1 (if Element1 is constructed, this will not be the Element
 * immediately following).
 * @param ppNext2 The address where the function will deposit the next Element
 * after Element2 (if Element2 is constructed, this will not be the Element
 * immediately following).
 * @param pCount The address where the function will deposit the count of
 * Elements in the template. If they are different, the count will be 0.
 * @param pCmpResult The address where the function will deposit the result of
 * the comparison, 0 for equal and non-zero for not equal (similar to memcmp).
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1CompareTemplates (
  MAsn1Element *pElement1,
  MAsn1Element *pElement2,
  MAsn1Element **ppNext1,
  MAsn1Element **ppNext2,
  ubyte4 *pCount,
  sbyte4 *pCmpResult
  );

/** If the pElement is a SEQUENCE OF or SET OF, there is a list of Elements that
 * make up the contents. It is actually a link list.
 * <p>This function will get the Element at the index given.
 * <p>The function will go to the address given by ppNextElement and deposit a
 * reference to the Element. If there is no Element for the index given, it will
 * deposit a NULL (and return OK, so if the function succeeds, check the result
 * to see if there really is an element at the index given).
 * <p>If pElement is not SEQUENCE OF or SET OF, then the function will simply set
 * *ppNextElement to NULL and return OK.
 *
 * @param pElement The Of Element for which we want a sub Element.
 * @param index The index of the Element requested.
 * @param ppNextElement The address where the function will deposit a reference
 * to the requested Element.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1GetOfElementAtIndex (
  MAsn1Element *pElement,
  ubyte4 index,
  MAsn1Element **ppNextElement
  );

/** Call this to set any Element with data. This function will simply copy a
 * reference to the pValue passed in (it will not allocate a new buffer and
 * memcpy the data).
 * <p>You should use this function always, rather than trying to set the fields
 * of pElement yourself. More than just setting fields and state are involved.
 * <p>If you are encoding in indefinite length, you must call a Set function, you
 * must not simply set the fields inside pElement yourself.
 * <p>Generally you would use this only for OCTET STRING or UTF8String, because
 * you want to use the specific Set functions for other types.
 * <p>Note that you do not use this function to add some of the data when
 * encoding by parts (see MAsn1EncodeUpdate). For that you must use MAsn1AddData.
 * This function is for setting an Element when you have all the data at once.
 * You do not use this function after calling MAsn1SetValueLen, even if it turned
 * out you had all the data in one buffer.
 *
 * @param pElement The element to set.
 * @param pValue The byte array that will be the value.
 * @param valueLen The length, in bytes, of the byte array.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1SetValue (
  MAsn1Element *pElement,
  const ubyte  *pValue,
  ubyte4       valueLen
  );

/** Set an Element with a length, but not the data yet. This is for when you are
 * encoding by parts (see MAsn1EncodeUpdate).
 * <p>If you want to encode by parts, you must know in advance the total length
 * of the data and you must set it using this function. Note that with BER
 * encoding, you can encode without knowing in advance how long the data will be.
 * It is called indefinite length. However, this engine performs only DER and
 * hence only definite length.
 * <p>Remember, this is the total amount of data you will add, not the amount you
 * will add as the first part.
 * <p>After you set the Element with the length, call MAsn1AddData to add new
 * data to encode.
 *
 * @param pElement The element to set.
 * @param valueLen The total length, in octets, of the data that will be added
 * later on.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1SetValueLen (
  MAsn1Element *pElement,
  ubyte4 valueLen
  );

/** For encoding: set an Element with one of these flags:
 * <pre>
 * <code>
 *   MASN1_NO_VALUE
 *   MASN1_UNKNOWN_VALUE
 *   MASN1_CLEAR_UNKNOWN_VALUE
 *
 *   MASN1_UNKNOWN_OF
 *   MASN1_CLEAR_UNKNOWN_OF
 * </code>
 * </pre>
 * <p>For NO_VALUE, this specifies that there will be no value and to encode
 * accordingly. For an OPTIONAL or DEFAULT, that means don't encode. For
 * something other than OPTIONAL or DEFAULT, that means encoding tag 00. This is
 * valid for constructed (SEQ, SET) or OF (SEQ OF, SET OF) as well as simple
 * (INTEGER, OCTET STRING, etc.).
 * <p>UNKNOWN_VALUE is really for encoding OPTIONAL and indefinite, or
 * SET/SEQUENCE [OF] and you don't know whether there will be data or not. Once
 * you know, you can add the data or call this function again with NO_VALUE.
 * <p>Note! If you set UNKNOWN_VALUE, that Element will not do any work until you
 * set with NO_VALUE (you now know that there will be no value) or
 * CLEAR_UNKNOWN_VALUE (you know there will be a value).
 * <p>When encoding, the code will write out whatever it can for an Element, and
 * with indefinite, if it does not have data, it will still write out the tag 80.
 * But if you set an Element with this flag, the encoding code will stop at this
 * Element. It will not write anything until the Element is set with NO_VALUE or
 * CLEAR_UNKNOWN_VALUE (another call to MAsn1SetValueLenSpecial). Calling with
 * NO_VALUE will also clear the UNKNOWN_VALUE.
 * <p>After you call with CLEAR_UNKNOWN_VALUE, the encoder will know to write out
 * the tag and len, but will not write out any data until you load the data (e.g.
 * MAsn1SetValueLen or MAsn1SetValue, or MAsn1AddIndefiniteData).
 * <p>You can call this function with CLEAR before or after setting the Element
 * with a value.
 * <p>If you use MASN1_UNKNOWN_VALUE, the Element must be one that allows
 * indefinite, the original creation was for ENCODE_INDEF, and the encode
 * function used must be MAsn1EncodeIndefiniteUpdate.
 * <p>UNKNOWN_OF is for OF Elements (SEQ OF, SET OF) when you know there will be
 * data but don't know how much. This tells the encoder to write out what it can
 * (likely a tag 80 for the OF and any sub Elements), but don't complete the OF,
 * wait for more information or the CLEAR_UNKNOWN_OF.
 * <p>For example, here is a possible call sequence.
 * <pre>
 * <code>
 *    SetSpecial (OfElement, UNKNOWN_VALUE);
 *    EncodeIndefUpdate (); // Write up to the OF, don't write
 *                          // out anything for the OF.
 *    SetSpecial (OfElement, UNKNOWN_OF);
 *    EncodeIndefUpdate (); // Write out 31 80, we know something will
 *                          // be written out but we have no data yet.
 *    SetValue (OfElement + 1, data);
 *    EncodeIndefUpdate (); // Write out as much of the the first entry
 *                          // of the OF as possible.
 *    CopyAddOf (OfElement, &newEntry);
 *    SetValue (newEntry, data);
 *    EncodeIndefUpdate (); // Write out as much of the the first two
 *                          // entries of the OF as possible.
 *    CopyAddOf (OfElement, &newEntry);
 *    SetValue (newEntry, data);
 *    EncodeIndefUpdate (); // Write out as much of the the first three
 *                          // entries of the OF as possible.
 *    SetSpecial (OfElement, CLEAR_UNKNOWN_OF);
 *    EncodeIndefUpdate (); // Finish writing the OF, this will include
 *                          // the closing 00 00.
 * </code>
 * </pre>
 * <p>If you don't call SetSpecialLen, the encoder will try to encode everything
 * it sees and make decisions based on the contents. That might very well be
 * exactly what you want it to do, but with this function, you will have more
 * control over what gets written out and when.
 * <p>After setting with UNKNOWN_OF, setting with CLEAR_UNKNOWN_VALUE and
 * CLEAR_UNKNOWN_OF will both work to indicate everything about the OF is known.
 * <p>If you set with UNKNOWN_OF, never set any data, and later on call
 * NO_VALUE, you are likely to get 31 80 00 00 or 31 00. If the Element is
 * OPTIONAL, that is wrong. So only set UNKNOWN_OF only when you know that there
 * will indeed be databut you don't know how much.
 *
 * @param pElement The Element to set.
 * @param flag either MASN1_NO_VALUE, MASN1_UNKNOWN_VALUE,
 * MASN1_CLEAR_UNKNOWN_VALUE, MASN1_UNKNOWN_OF, or MASN1_CLEAR_UNKNOWN_OF
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1SetValueLenSpecial (
  MAsn1Element *pElement,
  ubyte4 flag
  );

/** Add more data to be encoded.
 * <p>When encoding by parts (see MAsn1EncodeUpdate), you set the length first,
 * then add data. You call this as many times as necessary until you have added
 * all the data.
 * <p>Remember, you must first call SetValueLen with the total length of the
 * data. Then you call AddData multiple times, where the sum of all the valueLen
 * args passed to AddData is the total length passed into SetValueLen.
 * <p>This function looks at and adjusts the Element's state field. It knows what
 * has happened last and knows whether it is legal to add new data. For example,
 * you cannot Call AddData twice in a row. The function expects that the last
 * function that did anything to the Elment was either SetValueLen or
 * EncodeUpdate.
 *
 * @param pElement The element to set.
 * @param pNewData The byte array that contains the data to add.
 * @param newDataLen The length, in bytes, of the data to add.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1AddData (
  MAsn1Element *pElement,
  const ubyte  *pNewData,
  ubyte4       newDataLen
  );

/** This is similar to MAsn1AddData, except it is used to add more data to an
 * Element that can be indefinite length. It is used with
 * MAsn1EncodeIndefiniteUpdate.
 * <p>It is not necessary to first set the length (MAsn1SetValueLen) of the
 * Element before adding data using this function and encoding with
 * EncodeIndefiniteUpdate.
 * <p>Pass in FALSE for isComplete if the data being added is not the last to be
 * added. With the last block of input data that will be added, pass in TRUE.
 * <p>It is permissible to pass in all the data with isComplete as FALSE, then
 * make one last call to AddIndefiniteData with NULL/0 for the data and TRUE as
 * the isComplete arg.
 * <p>If a switch from the 'indefinite' format to a 'definite' format should be
 * disallowed when a single data block is added (without using the 'two calls' method
 * described above), pass as isComplete the value 'MASN1_BUF_FLAG_ENCODE_INDEF'.
 * It also represents 'TRUE' but as integer it signals to this function to stay
 * with the indefinite length format.
 * <p>Note that not all Elements can take in indefinite data. It is permissible
 * to call this function on Elements built with the following types.
 * <pre>
 * <code>
 *    MASN1_TYPE_BIT_STRING
 *    MASN1_TYPE_OCTET_STRING
 *    MASN1_TYPE_UTF8_STRING
 *    MASN1_TYPE_PRINT_STRING
 *    MASN1_TYPE_IA5_STRING
 *    MASN1_TYPE_BMP_STRING
 * </code>
 * </pre>
 *
 * @param pElement The element to set.
 * @param pNewData The byte array that contains the data to add.
 * @param newDataLen The length, in bytes, of the data to add.
 * @param isComplete If TRUE, this is the last of the data that will be added. If
 * FALSE, there will be more data to come.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1AddIndefiniteData (
  MAsn1Element *pElement,
  const ubyte  *pNewData,
  ubyte4       newDataLen,
  intBoolean   isComplete
  );

/** Call this function to set the value inside an MASN1_TYPE_BOOLEAN.
 * <p>It's possible to simply set value.pValue to the address of a single byte,
 * either 0xFF (TRUE) or 0x00 (FALSE). But this is provided as a convenience if
 * you have the value to encode as an intBoolean.
 * <p>Note that after decoding, the value.pValue field will point to the data
 * inside the encoding where the data begins. There is no routine to convert that
 * single byte to an intBoolean.
 *
 * @param pBooleanElement The element to set.
 * @param boolValue The intBoolean value to use.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1SetBoolean (
  MAsn1Element *pBooleanElement,
  intBoolean boolValue
  );

/** Call this function to set the value inside an MASN1_TYPE_INTEGER element.
 * <p>If you have the value as a canonical integer, but don't want to deal with
 * the issue of the most significant bit and leading byte, just call this
 * function.
 * <p>If the pCanonicalInt is not NULL, this function will treat the data at that
 * address as a canonical integer of length intLen. Set the isPositive arg to
 * TRUE if the number is supposed to be positive. Set it to FALSE if it is to be
 * negative.
 * <p>If pCanonicalInt is NULL, then the function will ignore the intLen and
 * isPositive arguments and load the intValue. This is for when you have the
 * integer as an sbyte4. The function will treat the number as a signed integer.
 * So if you want to set the value to be -1, you must pass in 0xffffffff. You do
 * not pass in 0x00000001 with isPositive to FALSE. Remember, the function
 * ignores the isPositive arg if pCanonicalInt is NULL.
 * <p>If you want to encode any value >= 2,147,483,648, you cannot encode it
 * using intValue. That value is 0x80000000, and if you pass it in as an sbyte4,
 * the function will treat it as a negative number.
 *
 * @param pIntegerElement The element to set.
 * @param pCanonicalInt The integer in canonical form, or NULL if you want to
 * pass in the integer as an sbyte4.
 * @param intLen If pCanonicalInt is not NULL, this is the length, in bytes of
 * that value. If pCanonicalInt is NULL, the function ignores this arg.
 * @param isPositive If pCanonicalInt is not NULL, this specifies if the value is
 * to be positive (TRUE) or negative (FALSE). If pCanonicalInt is NULL, the
 * function ignores this arg.
 * @param intValue If pCanonicalInt is NULL, this is the value the function will
 * set the element to.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1SetInteger (
  MAsn1Element *pIntegerElement,
  ubyte *pCanonicalInt,
  ubyte4 intLen,
  intBoolean isPositive,
  sbyte4 intValue
  );

/** This function will set the Element to be an MASN1_TYPE_INTEGER with the value
 * coming from the given vlong.
 * <p>If the vlong arg is NULL, the function will just set the type and return
 * OK. This is because an INTEGER might be OPTIONAL. But if the value of the
 * vlong is 0, the function will set the value to be 0.
 *
 * @param pIntegerElement The element to set.
 * @param pIntVal The integer as a vlong.
 * @param isPositive This specifies if the value is to be positive (TRUE) or
 * negative (FALSE).
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1SetIntegerFromVlong (
  MAsn1Element *pIntegerElement,
  vlong *pIntVal,
  intBoolean isPositive
  );

/** Call this function to set the value inside an MASN1_TYPE_BIT_STRING.
 * <p>A BIT STRING is encoded a bit differently than other types. After the TL
 * (tag and len), the V (value) begins with an unused bits octet. After that is
 * the actual value. Furthermore, in some cases, the trailing octet can be
 * omitted (if all zeroes). Finally, the last octet can be different than the
 * actual data passed in.
 * <p>If you don't want to deal with that insanity, use this function.
 * <p>The unused bits octet is functionally equivalent to a pad length. Because a
 * BIT STRING is an arbitrary collection of bits, it is certainly possible that
 * any one collection is not a multiple of 8. Because the only way to encode data
 * is with octets that are a multiple of 8, a BIT STRING must be written out as a
 * multiple of 8 bits. If the actual data is a collection of bits, the count of
 * which is not a multiple of 8, the encoding rules specifies padding. Because
 * the padding bits are not to be used by the reader, they are called unused bits.
 * <p>If you want, you can simply set value.pValue to a byte array. However, the
 * ASN.1 engine will assume that the first octet is the unused bits octet. And it
 * will not truncate the last octet if necessary. Hence, if you don't want to
 * deal with the intricacies of BIT STRING, call this function.
 * <p>For this function, there are two kinds of BIT STRINGS: "Named" and
 * "Unnamed". A Named BIT STRING is one where a definition of a set of bits is
 * given where each bit is given a specific meaning, with each meaning named. The
 * number of bits in the BIT STRING (what you pass as the bitCount arg) is the
 * number of bits defined. For example, in X.509, there is the KeyUsage
 * extension, which has this definition.
 * <pre>
 * <code>
 *    KeyUsage ::= BIT STRING {
 *      digitalSignature        (0),
 *      nonRepudiation          (1),
 *      keyEncipherment         (2),
 *      dataEncipherment        (3),
 *      keyAgreement            (4),
 *      keyCertSign             (5),
 *      cRLSign                 (6),
 *      encipherOnly            (7),
 *      decipherOnly            (8) }
 * </code>
 * </pre>
 * <p>The Named BIT STRING has a definition that specifies what each bit in which
 * position means. The "left most" bit is number 0, the next one to the right is
 * number 1, and so on. In this case, you build a byte array with the most
 * significant bit being the 0 bit. Pass in the byte array and length along with
 * the number of bits (for example, KeyUsage has 9 bits defined, so will be a
 * byte array of length 2 with a bitCount of 9).
 * <p>Note that you cannot simply point to the address of a ubyte4 as a ubyte *.
 * Because of endianness, the byte order of a ubyte4 might not be simply the most
 * significant byte on the "left" and so on. You might want to do something like
 * this:
 * <pre>
 * <code>
 *    ubyte4 bitVal;
 *    ubyte bitValBytes[2];
 *
 *    // Set the bits in bitVal. Let's say there are 9 bits.
 *    // Now "convert it to a byte array.
 *    bitValBytes[0] = (ubyte)(bitVal >> 24);
 *    bitValBytes[1] = (ubyte)(bitVal >> 16);
 * </code>
 * </pre>
 * <p>Your code might keep track of the bits in a ubyte4, OR'ing in each value, 0
 * or 1, as they are specified. If so, you should convert the ubyte4 to a byte
 * array. The easiest way to handle this would be to make sure bit 0 in the Named
 * BIT STRING is defined as the 0x80000000 bit in the ubyte4, the next is
 * 0x40000000, and so on.
 * <p>An Unnamed BIT STRING is almost always functionally equivalent to a byte
 * array. For example, in X.509, there are these definitions.
 * <pre>
 * <code>
 *    SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm            AlgorithmIdentifier,
 *      subjectPublicKey     BIT STRING  }
 *
 *    Certificate  ::=  SEQUENCE  {
 *      tbsCertificate       TBSCertificate,
 *      signatureAlgorithm   AlgorithmIdentifier,
 *      signature            BIT STRING  }
 * </code>
 * </pre>
 * <p>In these cases, the actual public key (the DER encoding of the specific key
 * data such as RSAPublicKey or DSAPublicKey) and signature (with RSA just a
 * canonical integer or DSA the DER encoding of r and s) are values for which
 * every bit is part of the data, so there are no unused bits.
 * <p>When you call this function, pass in the data as a byte array, but also
 * specify the number of bits. This function will determine the pad length and
 * write out the appropriate unused bits octet. It will also write out the
 * appropriate pad bits (all 0 bits).
 * <p>You also pass in a flag indicating whether the data is a Named BIT STRING
 * or not. If it is not a Named BIT STRING (isNamed is FALSE), then the bitCount
 * should be dataLen * 8, and the function will know that it must not strip any
 * trailing octets, even if there is one or more octets of all zero.
 * <p>Note that if you pass in an Unnamed BIT STRING and the bitCount is not a
 * multiple of 8, this function will return an error. The bitCount might be
 * (dataLen - n) * 8, for some integer n (not all the bytes in pData will be
 * used), but for this function the bitCount must be a multiple of 8.
 * <p>If you set the isNamed flag to TRUE, then the function will know to
 * determine a pad length, and also know that it can omit any trailing octets if
 * they are 00 (and adjust the unused bits value appropriately. It is possible
 * that the length is 1 (the only V octet is unused bits and it is 0), if all the
 * bits of an Named BIT STRING are all 0.
 * <p>Note that you must pass in at least (bitCount + 7) / 8 bytes of data. That
 * is, even if the bits are all 0, you must pass in at least bitCount bits. If
 * dataLen * 8 is less than bitCount, this function will return an error.
 * <p>The byte array can be longer than necessary, because the function will know
 * to write out only the necessary octets. So you could have a ubyte4 collect the
 * bits. then convert it to a byte array of length 4 (depending on the endianness
 * of the platform, it could be simply passing in the address of the ubyte4).
 * Even if the dataLen is 4, if the bitCount is 9, the function will know to use
 * only 2 bytes, and might even omit byte number 1 if the bit at position 8 is 0.
 * <p>Note that reading a Named BIT STRING now becomes complicated as well. The
 * decoding function will simply return the address inside the encoding where the
 * value begins, and its length. That first byte is the unused bits octet, then
 * the actual data follows. If you are expecting 2 octets of actual data and get
 * only one, your code will have to know to interpret that to mean the last bits
 * are all 0.
 *
 * @param pBitStringElement The element to set.
 * @param isNamed If TRUE, this is to encode a Named BIT STRING.
 * @param pData The BIT STRING data.
 * @param dataLen The length, in bytes, of the data.
 * @param bitCount The number of bits in the bit string. If this is not a Named
 * BIT STRING, it will almost certainly be dataLen * 8.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1SetBitString (
  MAsn1Element *pBitStringElement,
  intBoolean isNamed,
  ubyte *pData,
  ubyte4 dataLen,
  ubyte4 bitCount
  );

/** Call this function to set the value inside an MASN1_TYPE_UTC_TIME or
 * MASN1_TYPE_GEN_TIME element, if the value of the time to encode is
 * represented as a TimeDate.
 * <p>If you have the time already encoded (a byte array), then just set the
 * value.pValue field.
 * <p>Note that after decoding, the value.pValue field will point to the data
 * inside the encoding where the data begins. You can call
 * DATETIME_convertFromValidityString2 to convert to TimeDate.
 *
 * @param pTimeElement The element to set.
 * @param pTime The TimeDate value to use.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1SetTime (
  MAsn1Element *pTimeElement,
  TimeDate *pTime
  );

/** Call this function to set the value inside an MASN1_TYPE_ENCODED.
 * <p>When you use the ENCODED type, the Encode function will simply "memcpy" the
 * data you pass in. If you simply set the type and value.pValue fields, there is
 * very few checks on the validity of that data.
 * <p>If you call this function to set the Element with ENCODED data, it will
 * verify that the first byte is a valid tag and the length octet or octets
 * accurately describe the dataLen.
 * <p>For example, if the first byte of the pData is 0x65, the function will
 * return an error. If the dataLen is 22, but the second byte of pData is 0x51
 * (decimal 81), this function will return an error.
 * <p>You can build an Encoded with EXPLICIT. In that case, when encoding, the
 * engine will write out an EXPLICIT tag and length, then memcpy the encoded data
 * passed in. When decoding, it will verify the EXPLICIT tag and set value.pValue
 * to the place in the encoding where the data after the EXPLICIT tag begins.
 * <p>If you have EXPLICITly tagged data already encoded, and don't need the
 * engine to add that tag, don't set the EXPLICIT flag in the tagSepcial field
 * when creating the template.
 *
 * @param pEncodedElement The element to set.
 * @param pData The data that will be copied into the overall encoding.
 * @param dataLen The length, in bytes, of the data.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1SetEncoded (
  MAsn1Element *pEncodedElement,
  ubyte *pData,
  ubyte4 dataLen
  );

/** DER encode the data represented by the Element.
 * <p>This function encodes one Element. If the Element passed in is a SEQUENCE
 * or SET, the function will encode this element and the sub array inside.
 * <p>This function encodes the entire value, it cannot encode by parts. So each
 * sub array element must be properly set.
 * <p>If the buffer is not big enough to hold the entire encoding, the function
 * will return ERR_BUFFER_TOO_SMALL and set *pEncodingLen to the size needed. you
 * can call this with a NULL output buffer just to get the size needed.
 *
 * @param pElement The Element to encode.
 * @param pEncoding The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pEncodingLen The address where the function will deposit the length, in
 * bytes, of the encoding (the number of bytes placed into the output buffer or
 * the size required).
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1Encode (
  MAsn1Element *pElement,
  ubyte *pEncoding,
  ubyte4 bufferSize,
  ubyte4 *pEncodingLen
  );

/** This is the same as MAsn1Encode except it will allocate memory to hold the
 * encoding.
 * <p>The function will simply call MAsn1Encode with NULL output in order to get
 * the size needed, allocate memory, and call Encode again.
 * <p>This is here just to save space. Rather than have 100 Encode with NULL,
 * MALLOC, Encode combinations throughout the code, just use this routine.
 * <p>The caller must free the memory using MOC_FREE.
 *
 * @param pElement The Element to encode.
 * @param ppEncoding The address where the function will deposit the buffer
 * containing the result.
 * @param pEncodingLen The address where the function will deposit the length, in
 * bytes, of the encoding.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1EncodeAlloc (
  MAsn1Element *pElement,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/** Encode by parts, or stream the encoding.
 * <p>This will produce the DER encoding. If the Elements are not set to allow
 * DER, then this function will return an error. Generally, this is to be used
 * when you have one Element of a type that has a lot of data that can be broken
 * up, and you know the length in advance.
 * <p>This will return whatever encoding the engine can compute. If not all the
 * data has been set or added in the Elements that make up the template, you can
 * call EncodeUpdate to produce as much of the encoding as has been determined.
 * <p>Note that the function does not produce as much output as the caller
 * requests. Rather, you pass in a buffer big enough to handle whatever the
 * encoder can compute, and the encoder will return everything it is able to
 * compute at the moment. If you want, call this function twice, first with a
 * NULL output buffer, just to get the size, allocate (or realloc) a buffer of
 * the needed size, then call again with the buffer.
 * <p>You call Update multiple times when you have one or more elements for which
 * you have broken up the data. Say you have something with an OCTET STRING, and
 * the data of that OCTET STRING is megabytes long. So rather than allocate a
 * single buffer many megabytes big and encode, you can build the enocoding up to
 * the OCTET STRING, then call MAsn1AddData with some of the data, call the
 * EncodeUpdate function with this partial data, and stream the result (i.e.
 * write it out to a file, send it over the wire, or whatever you plan to do with
 * the data). Next, call AddData again and so on until you have added all the
 * data. Once all the data has been added, the next EncodeUpdate will write out
 * the last of the OCTET STRING and then anything that follows it. If you have
 * set all the following Elements with all their data, you will get the rest of
 * the encoding. If some other Element is only partially set, do the Add,
 * EncodeUpdate, stream process again.
 * <p>Note that you pass in the original MAsn1Element always. For example,
 * suppose you have an Element array for
 * <pre>
 * <code>
 *   SEQUENCE {
 *     OID,
 *     OCTET_STRING,
 *     BIT STRING }
 * </code>
 * </pre>
 * <p>You have the OID and BIT STRING already set, but you want to break the
 * OCTET STRING into parts.
 * <p>You have created an MAsn1Element array of size 4 (from a TypeAndCount
 * array). Call this pArray (pArray[0] is the SEQUENCE, pArray[1] is the OID, and
 * so on).
 * <p>Call MAsn1SetValueLen with the length of the OCTET STRING. That is, you
 * must know in advance the length of the data, although you do not need to input
 * all the data at once. The engine will now know how to build the tag and length
 * octets.
 * <pre>
 * <code>
 *    status = MAsn1SetValueLen (pArray + 2, totalLen);
 * </code>
 * </pre>
 * <p>The first time you call EncodeUpdate, you pass in pArray. You're
 * encoding the SEQUENCE, which will necessitate encoding its sub-elements.
 * <pre>
 * <code>
 *   status = MAsn1EncodeUpdate (
 *     pArray, pBuffer, bufferSize, &updateLen, &isComplete);
 * </code>
 * </pre>
 * <p>That call will be able to determine the lengths of everything, but will
 * only be able to encode the SEQ tag and len, the full OID (TLV), and the OCTET
 * STRING's tag and length. That's what the output will be (note that you cannot
 * give the Encode function a buffer and say, "write out what you can in that
 * space." No, the encoder will write out everything it can, or if the buffer is
 * not big enough, it will return ERR_BUFFER_TOO_SMALL).
 * <p>After that first call, you add data to the OCTET STRING element (pArray[2])
 * and call EncodeUpdate again. You still pass in pArray. You're still encoding
 * the SEQUENCE. Even though the data from the SEQUENCE (TL) and OID (TLV) have
 * been written out, and the encoder will actually be encoding the OCTET STRING
 * (pArray + 2), you still pass in pArray.
 * <pre>
 * <code>
 *    status = Masn1AddData (pArray + 2, pPartialData, partialDataLen);
 *
 *    status = MAsn1EncodeUpdate (
 *      pArray, pBuffer, bufferSize, &updataLen, &isComplete);
 *
 *    status = Masn1AddData (pArray + 2, pNewData, newDataLen);
 *
 *    status = MAsn1EncodeUpdate (
 *      pArray, pBuffer, bufferSize, &updataLen, &isComplete);
 * </code>
 * </pre>
 * <p>You also pass in the address of an intBoolean. The function will set it to
 * FALSE if it determines that it has not completed the encoding. If it finishes
 * the encoding, it will set *pIsComplete to TRUE. You will likely know when you
 * should be completely done (because you will know when you have no more data to
 * Add), but this is a value you can use to know you no longer need to call
 * EncodeUpdate.
 *
 * @param pElement The Element to encode.
 * @param pEncoding The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pEncodingLen The address where the function will deposit the length, in
 * bytes, of the encoding (the number of bytes placed into the output buffer or
 * the size required).
 * @param pIsComplete The address where the function will deposit TRUE if the
 * encoding is done (no more output) or FALSE if the encoder is expecting more
 * data.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1EncodeUpdate (
  MAsn1Element *pElement,
  ubyte *pEncoding,
  ubyte4 bufferSize,
  ubyte4 *pEncodingLen,
  intBoolean *pIsComplete
  );

/** Encode by parts, or stream the encoding. Indefinite length is allowed.
 * <p>It is possible you are encoding something for which you do not have all the
 * data. Furthermore, you do not know in advance how long that data will be.
 * <p>NOTE! Some standards do not allow indefinite length. For example, the X.509
 * standard says a certificate must be DER encoded, which does not allow
 * indefinite length. Before you encode something using indefinite length, verify
 * that it is allowed.
 * <p>This function will use definite length if it can, and indefinite length
 * only if an Element allows indefinite length and the total length is not known.
 * The following ASN.1 tyes can be indefinite.
 * <pre>
 * <code>
 *    SET
 *    SEQUENCE
 *    BIT STRING
 *    OCTET STRING
 *    UTF8String
 *    PrintableString
 *    IA5String
 *    BMPString
 * </code>
 * </pre>
 * <p>Note that the function does not produce as much output as the caller
 * requests. Rather, you pass in a buffer big enough to handle whatever the
 * encoder can compute, and the encoder will return everything it is able to
 * compute at the moment. If you want, call this function twice, first with a
 * NULL output buffer, just to get the size, allocate (or realloc) a buffer of
 * the needed size, then call again with the buffer.
 * <p>You call Update multiple times when you have one or more elements for which
 * you have broken up the data. Say you have something with an OCTET STRING, and
 * the data of that OCTET STRING is megabytes long. So rather than allocate a
 * single buffer many megabytes big and encode, you can build the enocoding up to
 * the OCTET STRING, then call MAsn1AddIndefiniteData with some of the data, call
 * the EncodeIndefiniteUpdate function with this partial data, and stream the result (i.e.
 * write it out to a file, send it over the wire, or whatever you plan to do with
 * the data). Next, call AddData again and so on until you have added all the
 * data. Once all the data has been added, the next EncodeUpdate will write out
 * the last of the OCTET STRING and then anything that follows it. If you have
 * set all the following Elements with all their data, you will get the rest of
 * the encoding. If some other Element is only partially set, do the Add,
 * EncodeUpdate, stream process again.
 * <p>Note that you pass in the original MAsn1Element always. For example,
 * suppose you have an Element array for
 * <pre>
 * <code>
 *   SEQUENCE {
 *     OID,
 *     OCTET_STRING,
 *     BIT STRING }
 * </code>
 * </pre>
 * <p>You have the OID and BIT STRING already set, but you want to break the
 * OCTET STRING into parts.
 * <p>You have created an MAsn1Element array of size 4 (from a TypeAndCount
 * array). Call this pArray (pArray[0] is the SEQUENCE, pArray[1] is the OID, and
 * so on).
 * <p>If you call MAsn1SetValueLen with the length of the OCTET STRING first, the
 * Encoder will be able to use definite length (the function
 * EncodeIndefiniteLength will encode definite length DER if it can).
 * <p>But if you do not know in advance how long the OCTET STRING will be, you
 * will simply not call SetValueLen.
 * <p>The first time you call EncodeIndefiniteUpdate, you pass in pArray. You're
 * encoding the SEQUENCE, which will necessitate encoding its sub-elements.
 * <pre>
 * <code>
 *   status = MAsn1EncodeIndefiniteUpdate (
 *     pArray, pBuffer, bufferSize, &updateLen, &isComplete);
 * </code>
 * </pre>
 * <p>That call will be able to determine the lengths of the OID and BIT STRING,
 * but not the OCTET STRING and hence not the SEQUENCE. It will be able to write
 * out the SEQ tag and len (which will be 30 80), the full OID, and the OCTET
 * STRING tag and len (which will be 24 80). Note that you cannot give the Encode
 * function a buffer and say, "write out what you can in that space." No, the
 * encoder will write out everything it can, or if the buffer is not big enough,
 * it will return ERR_BUFFER_TOO_SMALL.
 * <p>After that first call, you add data to the OCTET STRING element (pArray[2])
 * and call EncodeUpdate again. You still pass in pArray. You're still encoding
 * the SEQUENCE. Even though the data from the SEQUENCE (TL) and OID (TLV) have
 * been written out, and the encoder will actually be encoding the OCTET STRING
 * (pArray + 2), you still pass in pArray.
 * <pre>
 * <code>
 *    status = Masn1AddIndefiniteData (
 *      pArray + 2, pPartialData, partialDataLen, FALSE);
 *
 *    status = MAsn1EncodeIndefiniteUpdate (
 *      pArray, pBuffer, bufferSize, &updataLen, &isComplete);
 *
 *    status = Masn1AddIndefiniteData (
 *      pArray + 2, pNewData, newDataLen, FALSE);
 *
 *    status = MAsn1EncodeIndefiniteUpdate (
 *      pArray, pBuffer, bufferSize, &updataLen, &isComplete);
 *
 *    // When there's no more data to add, call AddIndefiniteData with TRUE for
 *    // isComplete.
 *    status = Masn1AddIndefiniteData (pArray + 2, NULL, 0, TRUE);
 *
 *    status = MAsn1EncodeIndefiniteUpdate (
 *      pArray, pBuffer, bufferSize, &updataLen, &isComplete);
 * </code>
 * </pre>
 * <p>You also pass in the address of an intBoolean. The function will set it to
 * FALSE if it determines that it has not completed the encoding. If it finishes
 * the encoding, it will set *pIsComplete to TRUE. You will likely know when you
 * should be completely done (because you will know when you have no more data to
 * Add), but this is a value you can use to know you no longer need to call
 * EncodeUpdate.
 *
 * @param pElement The Element to encode.
 * @param pEncoding The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pEncodingLen The address where the function will deposit the length, in
 * bytes, of the encoding (the number of bytes placed into the output buffer or
 * the size required).
 * @param pIsComplete The address where the function will deposit TRUE if the
 * encoding is done (no more output) or FALSE if the encoder is expecting more
 * data.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1EncodeIndefiniteUpdate (
  MAsn1Element *pElement,
  ubyte *pEncoding,
  ubyte4 bufferSize,
  ubyte4 *pEncodingLen,
  intBoolean *pIsComplete
  );

/* A version of the function that does less arg checking, used for recursion.
 * <p>NOTE! This does not check the buffer size, it simply outputs data to the
 * pEncoding buffer. Hence, do not call this unless you know the buffer is big
 * enough. How do you know? Call MAsn1EncodeIndefiniteUpdate.
 */
MOC_EXTERN MSTATUS MAsn1EncodeIndefUpdate (
  MAsn1Element *pElement,
  ubyte *pEncoding,
  ubyte4 bufferSize,
  ubyte4 *pEncodingLen,
  intBoolean *pIsComplete
  );

/** DER decode. The function will expect the encoding to follow the template
 * represented by the Element array. This expects the entire encoding. It cannot
 * decode by parts.
 * <p>This function decodes one Element. If the Element passed in is a SEQUENCE
 * or SET, the function will decode this element and the subArray inside.
 * <p>This function will decode DER, not BER. For example, it cannot read
 * indefinite length. To read indefinite length, call MAsn1DecodeIndefiniteUpdateFlag.
 * <p>If this call encounters indefinite length, it will return an error. This
 * is useful because sometimes standards specify that data be DER encoded (e.g.
 * see X.509) in order to guarantee that a message digest is computed on specific
 * data.
 * <p>The caller passes in the encoding and the maximum length. It is possible
 * that the buffer contains the full encoding along with some trailing data. The
 * function will only read as much of the encoding as required by the template.
 * It will report the number of bytes it read at the address given by pBytesRead.
 * <p>Upon completion, the value.pValue field in the non-SEQUENCE/non-SET entries
 * will point to the address inside the encoding where the actual V of TLV begins
 * and valueLen will give the length of that vlaue. Furthermore, the encoding
 * field will point to the TLV and the encodingLen will be the total length of
 * the TLV.
 * <p>If the type is a BOOLEAN, INTEGER, or Time, then you might want to convert
 * the value. That is, you will have the result as a byte array. You might want
 * it as an intBoolean, sbyte4, or DateTime. There might be functions that can
 * convert the byte array to your desired format.
 * <p>For SEQUENCE and SET, upon completion, the encoding field will point to
 * the TLV and the encodingLen will report the total length of TLV.
 *
 * @param pEncoding The DER encoding to decode.
 * @param encodingLen The length, in bytes, of the encoding.
 * @param pElement The Element to decode.
 * @param pBytesRead The address where the function will deposit the number of
 * bytes read.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1Decode (
  const ubyte  *pEncoding,
  ubyte4       encodingLen,
  MAsn1Element *pElement,
  ubyte4       *pBytesRead
  );

/** Decode by parts, or stream the decoding.
 * <p>This will read whatever data it is given, and set the Element (and sub
 * elements with whatever information it can.
 * <p>This function will decode DER, not BER. For example, it cannot read
 * indefinite length. To read indefinite length, call MAsn1DecodeIndefiniteUpdateFlag.
 * <p>If this call encounters iindefinite length, it will return an error. This
 * is useful because sometimes standards specify that data be DER encoded (e.g.
 * see X.509) in order to guarantee that a message digest is computed on specific
 * data.
 * <p>The caller indicates whether this is the last of the encoding or not (the
 * decodeFlag arg). If this data is the last call (there is no more data, no
 * further calls to Update), pass MASN1_DECODE_LAST_CALL (this is #defined to 1).
 * If there will be more data (more calls), pass MASN1_DECODE_UPDATE (this is
 * #defined to 0). This is generally needed for definitions where the last
 * Element in an encoding is OPTIONAL. The decoder will not know whether the
 * option was not taken (there is no data) or the data simply has not been passed
 * in yet, until it knows there will be no more data.
 * <p>You can pass 0 (MASN1_DECODE_UPDATE) for all calls, and if the decoder can
 * complete the process it will. The only problem will be if you ever have a
 * definition with the last Element being OPTIONAL.
 * <p>NOTE! The "bookkeeping" with DecodeUpdate is much more complicated. Make
 * sure you know what you are doing before using this feature.
 * <p>After calling this function, some or all of the Elements that make up the
 * definition will be updated. The update might be to the state only, so check
 * the state after a call to determine if there is anything in an Element to
 * process. For example, suppose you have an OCTET STRING at pArray[5]. After
 * calling DecodeUpdate, check pArray[5].state.
 * <pre>
 * <code>
 *   MASN1_STATE_NONE                  The decoder has not encountered any part
 *                                     of the TLV of the Element.
 *
 *   MASN1_STATE_DECODE_TAGX           With any of these states, you know that
 *   MASN1_STATE_DECODE_LEN_LENX       the decoder has not encountered any of
 *   MASN1_STATE_DECODE_PARTIAL_LENX   value octets. There is no data to copy
 *   MASN1_STATE_DECODE_LENX           or read.
 *   MASN1_STATE_DECODE_TAG
 *   MASN1_STATE_DECODE_LEN_LEN
 *   MASN1_STATE_DECODE_PARTIAL_LEN
 *   MASN1_STATE_DECODE_LEN
 *
 *   MASN1_STATE_DECODE_PARTIAL        The decoder has encountered some of the
 *                                     value of this Element. The value.pValue
 *                                     field will point to the currently read
 *                                     data.
 *
 *   MASN1_STATE_DECODE_COMPLETE       The decoder has encountered all of the
 *                                     value. The value.pValue field will point
 *                                     to the last part of the data.
 * </code>
 * </pre>
 * <p>If the DecodeUpdate function encounters some of the value (the V of TLV)
 * for an Element, it will set value.pValue to point to where, in the encoding
 * provided, the new data begins. This means that a call to DecodeUpdate can
 * overwrite an existing pointer. After each call to DecodeUpdate, you must find
 * any new data and copy or process it. Pointers that, after the previous call to
 * DecodeUpdate, were addresses of data to copy or process might no longer be
 * valid.
 * <p>If the function determines that all the data that can be read has been
 * read, it will set *pIsComplete to TRUE.
 *
 * @param pEncoding The DER encoding to decode.
 * @param encodingLen The length, in bytes, of the encoding.
 * @param decodeFlag Pass in 0 (MASN1_DECODE_UPDATE) for any Update call, but you
 * can also pass in 1 (MASN1_DECODE_LAST_CALL, note that it must be 1, not simply
 * non-zero) if you know that this will be the last Update call, the last of the
 * input data.
 * @param pElement The Element to decode.
 * @param pBytesRead The address where the function will deposit the number of
 * bytes read.
 * @param pIsComplete The address where the function will deposit a TRUE if all
 * the data of the encoding has been read, or FALSE if there is more data
 * expected.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1DecodeUpdateFlag (
  ubyte *pEncoding,
  ubyte4 encodingLen,
  ubyte4 decodeFlag,
  MAsn1Element *pElement,
  ubyte4 *pBytesRead,
  intBoolean *pIsComplete
  );

/** Backward compatible version.
 *  This function behaves like the previous implementation by using the decode
 *  flag value 'MASN1_DECODE_UPDATE' while calling the new implementation.
 */
MOC_EXTERN MSTATUS MAsn1DecodeUpdate (
  ubyte *pEncoding,
  ubyte4 encodingLen,
  MAsn1Element *pElement,
  ubyte4 *pBytesRead,
  intBoolean *pIsComplete
  );

/** Decode by parts, or stream the decoding. If any of the data is indefinite
 * length, this function will be able to read it.
 * <p>This will read whatever data it is given, and set the Element (and sub
 * elements) with whatever information it can.
 * <p>The caller indicates whether this is the last of the encoding or not (the
 * decodeFlag arg). If this data is the last call (there is no more data, no
 * further calls to Update), pass MASN1_DECODE_LAST_CALL (this is #defined to 1).
 * If there will be more data (more calls), pass MASN1_DECODE_UPDATE (this is
 * #defined to 0). This is generally needed for definitions where the last
 * Element in an encoding is OPTIONAL. The decoder will not know whether the
 * option was not taken (there is no data) or the data simply has not been passed
 * in yet, until it knows there will be no more data.
 * <p>You can pass 0 (MASN1_DECODE_UPDATE) for all calls, and if the decoder can
 * complete the process it will. The only problem will be if you ever have a
 * definition with the last Element being OPTIONAL.
 * <p>If the function encounters any indefinite length data, it will call the
 * DataReturn callback provided by the caller. Normally, you would look in the
 * element itself to see the decoded data (e.g. look at pElement->value.pValue),
 * but with this function, the data might not be in the element itself, but where
 * the callback directs it. Hence, after decoding, the value.pValue and valueLen
 * fields are meaningless. Do not look at them for any information.
 * <p>The reason the function cannot simply point to the data in the encoding is
 * that indefinite length data can have tags in the middle. In other words, it
 * might not be contiguous. For example, compare these two encodings of an OCTET
 * STRING:
 * <pre>
 * <code>
 *    definite length:
 *      04 10 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10
 *
 *    indefinite length
 *      24 80 04 06 01 02 03 04 05 06 04 03 07 08 09 04 07 0A 0B 0C 0D 0E 0F 10
 *
 *    or look at them parsed
 *      04 10
 *         01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10
 *
 *      24 80
 *         04 06
 *            01 02 03 04 05 06
 *         04 03
 *            07 08 09
 *         04 07
 *            0A 0B 0C 0D 0E 0F 10
 * </code>
 * </pre>
 * <p>Let's say the address of the initial tag is 1000. Then in the definite
 * length encoding, the data is at address 1002 and is 16 bytes long. But in the
 * indefinite length encoding, the data is at three locataions: 1004 and 6 bytes,
 * 1012 and 3 bytes, and 1017 and 7 bytes. There is no one single byte array we
 * can point to that is the data.
 * <p>There are types (such as INTEGER) that are not allowed to be indefinite.
 * The data for these types will be returned normally, namely in the Element
 * itself. It is certainly possible that an element that could be indefinite
 * (such as OCTET STRING) is not indefinite. In that case, the data will be
 * returned normally, in the Element, not through the callback.
 * <p>NOTE! The "bookkeeping" with DecodeIndefiniteUpdate is very complicated.
 * Make sure you know what you are doing before using this feature. The biggest
 * complication is that some data will be returned in the Element, other data
 * might be returned in the Element or it might be returned using the callback.
 * You need to check the state after each call to Update to determine what has
 * happened.
 * <p>After calling this function, some or all of the Elements that make up the
 * definition will be updated. The update might be to the state only, so check
 * the state after a call to determine if there is anything in an Element to
 * process. For example, suppose you have an OCTET STRING at pArray[5]. After
 * calling DecodeUpdate, check pArray[5].state.
 * <pre>
 * <code>
 *   MASN1_STATE_NONE                  The decoder has not encountered any part
 *                                     of the TLV of the Element.
 *
 *   MASN1_STATE_DECODE_TAGX           With any of these states, you know that
 *   MASN1_STATE_DECODE_LEN_LENX       the decoder has not encountered any of
 *   MASN1_STATE_DECODE_PARTIAL_LENX   value octets. There is no data to copy
 *   MASN1_STATE_DECODE_LENX           or read.
 *   MASN1_STATE_DECODE_LENX_INDEF
 *   MASN1_STATE_DECODE_TAG
 *   MASN1_STATE_DECODE_TAG_INDEF
 *   MASN1_STATE_DECODE_LEN_LEN
 *   MASN1_STATE_DECODE_PARTIAL_LEN
 *   MASN1_STATE_DECODE_LEN
 *   MASN1_STATE_DECODE_LEN_INDEF
 *
 *   MASN1_STATE_DECODE_PARTIAL        The decoder has encountered some of the
 *                                     value of this Element. The value.pValue
 *                                     field will point to the currently read
 *                                     data.
 *
 *   MASN1_STATE_DECODE_PARTIAL_INDEF  The decoder has encountered some of the
 *                                     value of this element and that data was
 *                                     given to the Data callback.
 *
 *   MASN1_STATE_DECODE_INDEF_BLOCK    The decoder has completed reading a block
 *                                     of indefinite data. We don't know yet if
 *                                     there will be another block of data or if
 *                                     the next bytes will be 00 00.
 *
 *   MASN1_STATE_DECODE_COMPLETE       The decoder has encountered all of the
 *                                     value. The value.pValue field will point
 *                                     to the last part of the data.
 *
 *   MASN1_STATE_DECODE_COMPLETE_INDEF The decoder has encountered all of the
 *                                     value and it has all ben given to the
 *                                     Data callback.
 * </code>
 * </pre>
 * <p>If the DecodeIndefiniteUpdate function encounters some of the value (the V
 * of TLV) for an Element that is not indefinite, it will set value.pValue to
 * point to where, in the encoding provided, the new data begins. This means that
 * a call to DecodeIndefiniteUpdate can overwrite an existing pointer. After each
 * call to DecodeUpdate, you must find any new data and copy or process it.
 * Pointers that, after the previous call to DecodeIndefiniteUpdate, were
 * addresses of data to copy or process might no longer be valid.
 * <p>If the function determines that all the data that can be read has been
 * read, it will set *pIsComplete to TRUE.
 * <p>If the function encounters a TLV where the L is 0x80 (indefinite length),
 * it will decode as much data as it can and pass that data to the DataReturn
 * function passed in. It will also pass to this function the pCallbackInfo it
 * was given. This could be a file handle (if the data is to be written to a
 * file, a buffer into which the data is to be placed, or whatever).
 * <p>Note that this can read indefinite length, which is an aspect of BER
 * encoding, but there is no guarantee that it will be able to read other BER
 * constructs (that differ from DER), although it might.
 *
 * @param pEncoding The encoding to decode.
 * @param encodingLen The length, in bytes, of the encoding.
 * @param decodeFlag Pass in 0 (MASN1_DECODE_UPDATE) for any Update call, but you
 * can also pass in 1 (MASN1_DECODE_LAST_CALL, note that it must be 1, not simply
 * non-zero) if you know that this will be the last Update call, the last of the
 * input data.
 * @param pElement The Element to decode.
 * @param DataReturn The function that can process any indefinite length data.
 * @param pCallbackInfo Any info the callback will need in order to perform its
 * operations.
 * @param pBytesRead The address where the function will deposit the number of
 * bytes read.
 * @param pIsComplete The address where the function will deposit a TRUE if all
 * the data of the encoding has been read, or FALSE if there is more data
 * expected.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1DecodeIndefiniteUpdateFlag (
  const ubyte *pEncoding,
  ubyte4 encodingLen,
  ubyte4 decodeFlag,
  MAsn1Element *pElement,
  IndefiniteLengthDataReturn DataReturn,
  void *pCallbackInfo,
  ubyte4 *pBytesRead,
  intBoolean *pIsComplete
  );

 /** Backward compatible version.
  *  This function behaves like the previous implementation by using the decode
  *  flag value 'MASN1_DECODE_UPDATE' while calling the new implementation.
  */
 MOC_EXTERN MSTATUS MAsn1DecodeIndefiniteUpdate (
   const ubyte *pEncoding,
   ubyte4 encodingLen,
   MAsn1Element *pElement,
   IndefiniteLengthDataReturn DataReturn,
   void *pCallbackInfo,
   ubyte4 *pBytesRead,
   intBoolean *pIsComplete
   );

#define MASN1_DECODE_UPDATE     0x0000
#define MASN1_DECODE_LAST_CALL  0x0001

#define MASN1_DECODE_NO_INDEF   0x1000

/** This will set Element's buf with tag and len. The length can be indefinite.
 * <p>If the function can determine that the length is knowable, it will set the
 * tag and length, with the actual length, not indefinite.
 * <p>If the length is not knowable, it will try to set the tag and length to
 * indefinite.
 * <p>This function will determine if the Element's type is allowed to be
 * indefinite.
 * <p>The function will also determine IMPLICIT and EXPLICIT.
 * <p>If indefinite, it will also determine if the tag needs to be changed (e.g.
 * OCTET STRING in indefinite goes from 04 to 24).
 * <p>The flag is either 0, MASN1_NO_VALUE, MASN_NO_VALUE_SKIP,
 * MASN1_UNKNOWN_VALUE, or MASN1_UNKNOWN_OF. If 0, look at pElement->type to
 * determine whether this is to be encoded or not (OPTIONAL or DEFAULT), or if
 * there is a value or if the value is UNKNOWN.
 * <p>If the flag is NO_VALUE, then the Element will not be written out if
 * OPTIONAL or DEFAULT or written out with length 00 if not.
 * <p>If the flag is NO_VALUE_SKIP, don't write it out  no matter what (it is
 * likely this is a sub Element of a SEQ or SET that is OPTIONAL and not taken).
 * <p>If UNKNOW_VALUE, don't do anything yet, we don't know if anything will be
 * there.
 * <p>If UNKNOWN_OF, this is the sub Element of an OF, and we will write out the
 * sub Elements, so just treat this normally.
 * <p>The function returns a boolean to indicate whether the next write will
 * complete the Element or not.
 * <p>The function also returns the full encoding length of the Element if known.
 * If the Element is going to be indefinite length, there's no way of knowing yet
 * how long the total encoding will be. But if it is not indefinite, the function
 * will be able to determine how long it will be. If so, it returns that length.
 * This is the entire TLV. If it can't determine the length, it returns 0.
 * <p>Note that for efficiency, this function does not check the args, make sure
 * you pass valid pointers.
 *
 * @param pElement The element for which we are computing the tag and length.
 * @param flag either 0, MASN1_NO_VALUE, MASN1_NO_VALUE_SKIP,
 * MASN1_UNKNOWN_VALUE, or MASN1_UNKNOWN_OF.
 * @param pIsComplete The address where the function will deposit a TRUE if the
 * next write will complete the Element, FALSE otherwise.
 * @param pEncodingLen The address where the function will deposit the full
 * encoding length of this Element if known. If not known, it will be set to 0.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS MAsn1ComputeTagAndLenIndef (
  MAsn1Element *pElement,
  ubyte4 flag,
  intBoolean *pIsComplete,
  ubyte4 *pEncodingLen
  );

/* Supports MAsn1ComputeTagAndLenIndef.
 * Write out the tag and len octets to pBuf + bufLen. In other words, it appends
 * the tag and len.
 * If the type arg is 0, this uses pElement->type.
 * The reason for this is so we can write out the real tag from an indef. E.g.,
 * suppose we have EXPLICIT OCTET with indefinite, the tag will be
 *   A0 80 24 80
 * But when we want to write out actual data, we want
 *   04 len
 * If this is the first write, we'll want
 *   A0 80 24 80 04 len
 * So this function can be called by someone writing the opening tag or a
 * subsequent tag.
 * This will write out the EXPLICIT tag and len as well, if necessary.
 * This will determine the actual tag if IMPLICIT.
 * If indefFlag is not 0, then this will write out tag 80. If EXPLICIT, it will
 * write out eTag 80 tag 80.
 * This does not check the NO_VALUE bit, it simply writes out the tag and len.
 * This does not change the state.
 */
MOC_EXTERN MSTATUS MAsn1TagAndLenIndef (
  ubyte4 type,
  MAsn1Element *pElement,
  ubyte4 valueLen,
  ubyte4 indefFlag
  );

/* Determine how much space this Element will need to write output.
 * Return TRUE at *pIsComplete if the next write will complete the Element.
 * It's possible the Element has already been written out, in which case the
 * function will return 0 at *pSpaceRequired and TRUE at *pIsComplete.
 */
MOC_EXTERN MSTATUS MAsn1ComputeRequiredLenIndef (
  MAsn1Element *pElement,
  ubyte4 *pSpaceRequired,
  intBoolean *pIsComplete
  );

#ifdef __cplusplus
}
#endif

#endif /* __MOCASN1_H__ */
