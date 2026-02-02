/*
 * parseasn1.h
 *
 * Definitions of functions that build and read various ASN.1 constructs.
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

#ifndef __PARSEASN1_H__
#define __PARSEASN1_H__

#include "../common/absstream.h"
#include "../common/tree.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Tag classes */

#define CLASS_MASK      0xC0    /* Bits 8 and 7 */
#define UNIVERSAL       0x00    /* 0 = Universal (defined by ITU X.680) */
#define APPLICATION     0x40    /* 1 = Application */
#define CONTEXT         0x80    /* 2 = Context-specific */
#define PRIVATE         0xC0    /* 3 = Private */

/* Encoding type */

#define FORM_MASK       0x20    /* Bit 6 */
#define PRIMITIVE       0x00    /* 0 = primitive */
#define CONSTRUCTED     0x20    /* 1 = constructed */

/* Universal tags */

#define TAG_MASK        0x1F    /* Bits 5 - 1 */
#define EOC             0x00    /*  0: End-of-contents octets */
#define BOOLEAN         0x01    /*  1: Boolean */
#define INTEGER         0x02    /*  2: Integer */
#define BITSTRING       0x03    /*  3: Bit string */
#define OCTETSTRING     0x04    /*  4: Byte string */
#define NULLTAG         0x05    /*  5: NULL */
#define OID             0x06    /*  6: Object Identifier */
#define OBJDESCRIPTOR   0x07    /*  7: Object Descriptor */
#define EXTERNAL        0x08    /*  8: External */
#define REAL            0x09    /*  9: Real */
#define ENUMERATED      0x0A    /* 10: Enumerated */
#define EMBEDDED_PDV    0x0B    /* 11: Embedded Presentation Data Value */
#define UTF8STRING      0x0C    /* 12: UTF8 string */
#define SEQUENCE        0x10    /* 16: Sequence/sequence of */
#ifdef MOC_SET
#undef  MOC_SET
#endif
#define MOC_SET         0x11    /* 17: Set/set of */
#define NUMERICSTRING   0x12    /* 18: Numeric string */
#define PRINTABLESTRING 0x13    /* 19: Printable string (ASCII subset) */
#define T61STRING       0x14    /* 20: T61/Teletex string */
#define VIDEOTEXSTRING  0x15    /* 21: Videotex string */
#define IA5STRING       0x16    /* 22: IA5/ASCII string */
#define UTCTIME         0x17    /* 23: UTC time */
#define GENERALIZEDTIME 0x18    /* 24: Generalized time */
#define GRAPHICSTRING   0x19    /* 25: Graphic string */
#define VISIBLESTRING   0x1A    /* 26: Visible string (ASCII subset) */
#define GENERALSTRING   0x1B    /* 27: General string */
#define UNIVERSALSTRING 0x1C    /* 28: Universal string */
#define BMPSTRING       0x1E    /* 30: Basic Multilingual Plane/Unicode string */

/* Length encoding */

#define LEN_XTND  0x80          /* Indefinite or long form */
#define LEN_MASK  0x7F          /* Bits 7 - 1 */

/* Structure to hold info on an ASN.1 item */

/* BIT STRING : dataOffset points to beginning of bits not unused bits
                and length points to size of bitstring (without unused bits) */
#define ASN1_HEADER_MAX_SIZE (9)

#define ASN1_ITEM MOC_ASN1_ITEM

typedef struct ASN1_ITEM {
    TreeItem    treeItem;           /* Infrastructure for tree */
    ubyte4      id;                 /* Tag class + primitive/constructed */
    ubyte4      tag;                /* Tag */
    ubyte4      length;             /* Data length */
    ubyte4      headerSize;         /* Size of tag+length */
    sbyte4      dataOffset;          /* position of data in the stream */
    union
    {
        byteBoolean m_boolVal;      /* BOOLEAN */
        ubyte4      m_intVal;       /* INTEGER, ENUMERATED */
        ubyte       m_unusedBits;   /* BIT STRING */
    } data;

    byteBoolean indefinite;         /* Item has indefinite length */
    byteBoolean encapsulates;       /* encapsulates something */
} ASN1_ITEM, *ASN1_ITEMPTR;

/* useful macros */
#define ASN1_FIRST_CHILD(a)     ((ASN1_ITEMPTR) ((a)->treeItem.m_pFirstChild))
#define ASN1_NEXT_SIBLING(a)    ((ASN1_ITEMPTR) ((a)->treeItem.m_pNextSibling))
#define ASN1_PARENT(a)          ((ASN1_ITEMPTR) ((a)->treeItem.m_pParent))

#define ASN1_CONSTRUCTED(a)     (CONSTRUCTED == ((a)->id & FORM_MASK))
#define ASN1_PRIMITIVE(a)       (PRIMITIVE == ((a)->id & FORM_MASK))

/* function to follow progress of the parsing -- called every time a new ASN.1 item
is added to the tree */
typedef void (*ProgressFun)(ASN1_ITEMPTR newAddedItem, CStream s, void* arg);

/* exported routines */
MOC_EXTERN MSTATUS ASN1_GetNthChild(ASN1_ITEM* parent, ubyte4 n, ASN1_ITEM** ppChild);
MOC_EXTERN MSTATUS ASN1_GetChildWithOID(ASN1_ITEM* parent, CStream s, const ubyte* whichOID,
                               ASN1_ITEM** ppChild);
MOC_EXTERN MSTATUS ASN1_GetChildWithTag( ASN1_ITEM* parent, ubyte4 tag, ASN1_ITEM** ppChild);
MOC_EXTERN MSTATUS ASN1_GetTag( ASN1_ITEM* pItem, ubyte4 *pTag);
MOC_EXTERN MSTATUS ASN1_GoToTag(ASN1_ITEM* parent, ubyte4 tag, ASN1_ITEM** ppTag);
MOC_EXTERN MSTATUS ASN1_VerifyOID( ASN1_ITEM* pItem, CStream s, const ubyte* whichOID);
MOC_EXTERN MSTATUS ASN1_VerifyType(ASN1_ITEM* pCurrent, ubyte4 type);
MOC_EXTERN MSTATUS ASN1_VerifyTag(ASN1_ITEM* pCurrent, ubyte4 tag);
MOC_EXTERN MSTATUS ASN1_VerifyInteger(ASN1_ITEM* pCurrent, ubyte4 n);
MOC_EXTERN MSTATUS ASN1_VerifyOIDRoot( ASN1_ITEM* pItem, CStream s, const ubyte* whichOID,
                                  ubyte* subType);
MOC_EXTERN MSTATUS ASN1_VerifyOIDStart( ASN1_ITEM* pItem, CStream s, const ubyte* whichOID);
MOC_EXTERN MSTATUS ASN1_CompareItems( ASN1_ITEM* pItem1, CStream s1, ASN1_ITEM* pItem2, CStream s2);
MOC_EXTERN MSTATUS ASN1_getBitStringBit( ASN1_ITEM* pBitString, CStream s, ubyte4 bitNum,
                                        byteBoolean* bitVal);

MOC_EXTERN MSTATUS ASN1_Parse(CStream s, ASN1_ITEM** rootItem);
MOC_EXTERN MSTATUS ASN1_ParseEx(CStream s, ASN1_ITEM** rootItem, ProgressFun progressFun,
                            void* cbArg);

/* resumable ASN.1 parsing */
/* parser state */
typedef struct ASN1_ParseState
{
    ASN1_ITEM*              rootNode;
    ASN1_ITEM*              parentNode;
    sbyte4                  stackDepth;
    sbyte4                  filePos;
} ASN1_ParseState;

MOC_EXTERN MSTATUS ASN1_InitParseState( ASN1_ParseState* pState);

MOC_EXTERN MSTATUS ASN1_ParseASN1State(CStream as, ASN1_ParseState* pState,
                    ProgressFun progressFun, void* cbArg);

/* undocumented */
MOC_EXTERN ASN1_ITEMPTR ASN1_GetNextSiblingFromPartialParse(
                                    const ASN1_ParseState* pState,
                                    ASN1_ITEMPTR pSibling, CStream cs);

/* undocumented */
MOC_EXTERN ASN1_ITEMPTR ASN1_GetFirstChildFromPartialParse(
                                    const ASN1_ParseState* pState,
                                    ASN1_ITEMPTR pParent, CStream cs);

/* undocumented */
MOC_EXTERN ubyte4 ASN1_GetData( const ASN1_ParseState* pState, CStream cs,
                               ubyte4 streamSize, ASN1_ITEMPTR pItem,
                               ubyte4* pOffset, const ubyte* src, ubyte* dest);


/* verify item ( constructed) is complete */
MOC_EXTERN MSTATUS ASN1_IsItemComplete( const ASN1_ParseState* pState,
                                       const ASN1_ITEM *item,
                                       CStream s, intBoolean* complete);

/* API to search and retrieve based on OIDs. The whichOID parameter is a string
with the format "a.b.c.d". The last number can be set to * in which case the
remaining part of the OID will not be matched. The return value is a NULL terminated
array of the ASN1_ITEMs of type OID that match the OID parameter. The array must
be FREEed when no longer needed by the caller. An array consisting of a single
NULL value is returned if no match was found */
MOC_EXTERN MSTATUS ASN1_OIDSearch( ASN1_ITEMPTR pItem, CStream s, const sbyte* whichOID,
                                ASN1_ITEMPTR **ppResults);

/** Read the length of the ASN.1 encoding.
 * <p>This function returns the length of the encoding. This length includes
 * the tag and length bytes themselves. This function will not validate the tag
 * itself. The caller must pass in a pointer which starts at the tag byte. This
 * function will not calculate the length for indefinite encodings. The function
 * will also return an error if the length exceeds 0x84. The caller must also
 * specify what the expected tag is. If the tag does not match with the expected
 * tag then an error will be thrown
 *
 * @param expectedTag   The expected tag value. If this does not match the tag
 *                      in the encoding then an error will be thrown.
 * @param pDerEncoding  A pointer to the start of a ASN.1 DER encoded value.
 * @param pEncodingLen  The address where the function will deposit the length.
 */
MOC_EXTERN MSTATUS ASN1_getTagLen(
    ubyte expectedTag, ubyte *pDerEncoding, ubyte4 *pEncodingLen);

/** Read the tag and length bytes.
 * <p>This function simply returns the tag, the length, and how many bytes make up
 * the tag and length. It makes no distinction between constructed (e.g. SEQ,
 * SET) and "regular" (e.g. OID, OCTET STRING). If the tag is BIT STRING, it
 * returns the tag and length length, not including the unused bits.
 * <p>If the tag is EXPLICIT, it reads the EXPLICIT tag only.
 * <p>The derEncodingLen arg is the length of the DER encoding beginning at the
 * first byte of the buffer, presumably a tag. The function will determine if the
 * buffer is big enough to hold an encoding with the given length. That is, the
 * function will make sure there is enough data to get the tag and length, and
 * then determine if the derEncodingLen is big enough to hold the TLV of the TL
 * just parsed.
 * <p>NOTE! If the encodingLen is not big enough for the tag and len, the error
 * will be ERR_ASN_INVALID_DATA. If the function is able to read the tag and len
 * but the encodingLen is not big enough for the length given, it will return
 * ERR_BUFFER_OVERFLOW. It will compute the result and you will get the answer,
 * but you will also get the error. Hence, if you want to just read a tag and len
 * and not worry about whether the buffer is big enough, call the function and
 * consider OK or BUFFER_OVERFLOW valid results.
 * <p>If the length is the single indefinite length octet (0x80), the function
 * returns -1 for the length. It will not be able to determine if the buffer is
 * big enough, but immediately following an indefinite length is a another tag.
 * <p>For example, look at the following two DER encodings
 * <pre>
 * <code>
 *   buf1, len = 17: 30 0F 06 05 02 86 48 01 02 04 06 01 02 03 04 05 06
 *
 *   readTagAndLen (buf1, 17)     -> tag = 0x30, len = 15, tlLen = 2
 *   readTagAndLen (buf1 + 2, 15) -> tag = 0x06, len = 5,  tlLen = 2
 *   readTagAndLen (buf1 + 9, 8)  -> tag = 0x04, len = 6,  tlLen = 2
 *
 *   After the caller made the first call, they knew (or determined based on the
 *   tag result of the first call) that to move on to the next tag, just skip the
 *   tag and len of the SEQUENCE.
 *   After the caller made the second call, they knew to move len + 2 bytes
 *   further to get to the next tag.
 *
 *   buf2, len = 13: 30 82 01 01 02 01 01 30 80 04 10 01 02
 *
 *   readTagAndLen (buf2, 13)     -> error, function can read tag and len, but
 *                                   len is 257, and buffer is only 13 bytes.
 *
 *   buf2, len = 280: 30 82 01 01 02 01 01 30 80 04 10 01 02 . . .
 *
 *   readTagAndLen (buf2, 280)      -> tag = 0x30, len = 257, tlLen = 4
 *   readTagAndLen (buf2 + 4, 276)  -> tag = 0x02, len = 1,   tlLen = 2
 *   readTagAndLen (buf2 + 7, 273)  -> tag = 0x30, len = -1,  tlLen = 2
 *   readTagAndLen (buf2 + 9, 271)  -> tag = 0x04, len = 16,  tlLen = 2
 *
 *   The function returned an answer for the first case, even though there were
 *   more bytes in the buffer than indicated by they length of the SEQUENCE.
 * </code>
 * </pre>
 * <p>If the function encounters a TL that is obviously wrong (e.g. 30 A9), then
 * the function will return an error. If the length cannot fit in a signed,
 * 4-byte integer (e.g. 85 01 ff ff ff ff, or even 84 ff ff ff ff), then the
 * function will return an error. If the buffer is not big enough (e.g. a
 * derEncodingLen of 3 and a derEncoding of 30 83 01), the function will return
 * an error.
 * <p>Note that the argument pTheLen is a pointer to a signed integer, because
 * that might return -1 for indefinite length.
 *
 * @param pDerEncoding The encoding to read.
 * @param derEncodingLen The length, in bytes, of the buffer. This might be the
 * length of the DER encoding, but the function will not expect it to be.
 * @param pTheTag The address where the function will deposit the tag.
 * @param pTheLen The address where the function will deposit the length.
 * @param pTagAndLenLen The address where the function will deposit the number of
 * bytes that make up the tag and length bytes.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ASN1_readTagAndLen (
  const ubyte *pDerEncoding,
  ubyte4      derEncodingLen,
  ubyte4      *pTheTag,
  sbyte4      *pTheLen,
  ubyte4      *pTagAndLenLen
  );

/** This utility function will compare two object identifiers. It checks to see
 * if Check is the same as Target.
 * <p>You have an expected OID, Target, and want to see if the one you were
 * given, Check, is that. For example, you have an OID of a digest algorithm from
 * a message. You want to check if it is SHA-256. So pass in the SHA-256 OID as
 * the Target and the one from the message as pCheck. Or put another way, Target
 * is the known OID and Check is the unknown, the one you're trying to determine.
 * <p>The caller passes in OIDs or AlgIds. The function will find the OIDs and
 * compare the two. So either TargetOID or CheckOID can be an OID or an algId, in
 * any combination.
 * <p>NOTE! This works only with an OID or AlgId. An OID is 06 len -OID- and
 * algId is SEQUENCE { OID, params }
 * <p>The caller passes in the target OID and the OID to compare to. If they are
 * the same, the function sets pCmpResult to 0. If not, it is set to a nonzero
 * value.
 * <p>It is possible that the comparison needs to be made on all but the last
 * byte of the OID. In that case, pass a valid address for the arg pLastByte. If
 * that arg is NULL, the function will compare all bytes. If that arg is not
 * NULL, the function will compare all but the last byte, and return the last
 * byte (cast as a ubyte4) at the address given. It will return the last byte of
 * the pCheckOid.
 * <p>Even if you don't want to check the last byte, pass in the full length.
 * That is, if the OID is 06 09 <something>, then the total OID is 11 bytes. You
 * pass in 11 as the length.
 *
 * @param pTargetOID The known OID.
 * @param targetLen The length, in bytes, of the target.
 * @param pCheckOID The unknown OID, is this OID the same as the target?
 * @param checkLen The length, in bytes, of the CheckOID.
 * @param pLastByte If NULL, function compares all OID bytes. If not NULL, the
 * function compares all but the last byte and returns the last byte of pCheckOID
 * at this address.
 * @param pCmpResult The address where the function will deposit the result, 0
 * for the same, nonzero for different.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ASN1_compareOID (
  const ubyte *pTargetOID,
  ubyte4      targetLen,
  const ubyte *pCheckOID,
  ubyte4      checkLen,
  ubyte4      *pLastByte,
  sbyte4      *pCmpResult
  );

/** "Convert" an OID or AlgId into an akt_ flag.
 * <p>The caller supplies an OID or AlgId. The function will see if the OID
 * matches an OID for a key. If it matches, set *pKeyAlg to the appropriate akt_
 * flag (defined in mss/src/crypto/ca_mgmt.h, such as akt_rsa or akt_ecc).
 * <p>Note that this checks OID/algId for keys only, not signature or encrpytion
 * algorithms.
 * <p>If the function cannot match it to a key OID, then it sets *pKeyAlg to
 * akt_undefined.
 *
 * @param pKeyOid The OID or AlgId to convert.
 * @param oidLen The length, in bytes, of the OID or AlgId.
 * @param pKeyAlg The address where the function will deposit the flag.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ASN1_getKeyFlagFromOid (
  ubyte *pKeyOid,
  ubyte4 oidLen,
  ubyte4 *pKeyAlg
  );

/** "Convert" an OID or AlgId into an akt_ flag.
 * <p>The caller supplies an OID or AlgId. The function will see if the OID
 * matches an OID for a public key algorithm. If it matches, set *pAlg to the
 * appropriate akt_ flag (defined in mss/src/crypto/ca_mgmt.h, such as akt_rsa or
 * akt_ecc).
 * <p>Note that this checks OID/algId for signature or encrpytion algorithms
 * only, not keys.
 * <p>If the function cannot match it to an OID, then it sets *pAlg to
 * akt_undefined.
 *
 * @param pAlgOid The OID or AlgId to convert.
 * @param oidLen The length, in bytes, of the OID or AlgId.
 * @param pAlg The address where the function will deposit the flag.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ASN1_getPublicKeyAlgFlagFromOid (
  ubyte *pAlgOid,
  ubyte4 oidLen,
  ubyte4 *pAlg
  );

/** "Convert" an OID or AlgId into an ht_ flag.
 * <p>The caller supplies an OID or AlgId. The function will see if the OID
 * matches an OID for a digest algorithm. If it matches, set *pDigestAlg to the
 * appropriate ht_ flag (defined in mss/src/crypto/crypto.h, such as ht_sha1 or
 * ht_sha256).
 * <p>Note that this checks OID/algId for digests only, not signature algorithms.
 * Also, it only supports the SHA algorithms (not MD2, 4, or 5).
 * <p>If the function cannot match it to a digest OID, then it sets *pDigestAlg
 * to ht_none.
 *
 * @param pDigestOid The OID or AlgId to convert.
 * @param oidLen The length, in bytes, of the OID or AlgId.
 * @param pDigestAlg The address where the function will deposit the flag.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ASN1_getDigestFlagFromOid (
  const ubyte *pDigestOid,
  ubyte4      oidLen,
  ubyte4      *pDigestAlg
  );

/** Get the digest algId from a signature algId.
 * <p>The signature algId will contain an OID that specifies a digest algorithm,
 * or else it contains parameters that include the algId of the digest. This
 * function will determine the algorithm and return the algId.
 * <p>The caller passes in a buffer into which the function will place the
 * result. The buffer can be MOP_MAX_DIGEST_ALG_ID_LEN big.
 * <p>The function will return the address inside the algId where the OID begins.
 * This will be the entire OID, including the tag and len octets. This can be
 * NULL, in which case the function will return only the AlgId.
 * <p>The function will also return the digest length, if requested. For example,
 * if the algorithm is ht_sha224, the function will return 28 at the address
 * pDigestLen.
 * <p>If the function cannot match a signature algId to a digest, it will return
 * an error.
 *
 * @param pSigAlgId The signature algorithm identifier.
 * @param sigAlgIdLen The length, in bytes, of the the sig AlgId.
 * @param pDigestAlgId The caller-supplied buffer into which the function will
 * place the result.
 * @param bufferSize The size, in bytes, of the buffer.
 * @param pDigestAlgIdLen The address where the function will deposit the length,
 * in bytes, of the AlgId.
 * @param ppDigestOid If not NULL, the address where the function will deposit
 * the pointer to the OID (this is the address inside the algId where the OID
 * begins).
 * @param pDigestOidLen If not NULL, the address where the function will deposit
 * the length, in bytes, of the OID.
 * @param pDigestLen If not NULL, the address where the function will depsosit
 * the length, in bytes, of a digest of this algorithm.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ASN1_getDigestFromSigAlgId (
  ubyte *pSigAlgId,
  ubyte4 sigAlgIdLen,
  ubyte *pDigestAlgId,
  ubyte4 bufferSize,
  ubyte4 *pDigestAlgIdLen,
  ubyte **ppDigestOid,
  ubyte4 *pDigestOidLen,
  ubyte4 *pDigestLen
  );

/** Given a flag indicating the digest algorithm (one of the ht_ values defined
 * in mss/src/crypto/crypto.h, such as ht_sha1 or ht_sha256), return the AlgId.
 * <p>The caller passes in a buffer into which the function will place the
 * result. The buffer can be MOP_MAX_DIGEST_ALG_ID_LEN big.
 * <p>The function will return the address inside the algId where the OID begins.
 * This will be the entire OID, including the tag and len octets. This can be
 * NULL, in which case the function will return only the AlgId.
 * <p>The function will also return the digest length, if requested. For example,
 * if the algorithm is ht_sha224, the function will return 28 at the address
 * pDigestLen.
 *
 * @param digestAlg The ht_ flag
 * @param pDigestAlgId The caller-supplied buffer into which the function will
 * place the result.
 * @param bufferSize The size, in bytes, of the buffer.
 * @param pDigestAlgIdLen The address where the function will deposit the length,
 * in bytes, of the AlgId.
 * @param ppDigestOid If not NULL, the address where the function will deposit
 * the pointer to the OID (this is the address inside the algId where the OID
 * begins).
 * @param pDigestOidLen If not NULL, the address where the function will deposit
 * the length, in bytes, of the OID.
 * @param pDigestLen If not NULL, the address where the function will depsosit
 * the length, in bytes, of a digest of this algorithm.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ASN1_getDigestAlgIdFromFlag (
  ubyte4 digestAlg,
  ubyte *pDigestAlgId,
  ubyte4 bufferSize,
  ubyte4 *pDigestAlgIdLen,
  ubyte **ppDigestOid,
  ubyte4 *pDigestOidLen,
  ubyte4 *pDigestLen
  );

/** Create DigestInfo from a digest and its algorithm.
 * <p>The caller passes in a message digest and specifies the algorithm using the
 * digestAlg arg. That is one of the ht_ values defined in crypto.h (ht_sha1,
 * ht_sha256, etc.).
 * <p>The function will allocate memory and set it with DigestInfo. The caller
 * must free that memory using DIGI_FREE.
 * <pre>
 * <code>
 *   DigestInfo ::= SEQENCE {
 *     algId,
 *     OCTET STRING }
 * </code>
 * </pre>
 *
 * @param pDigest The message digest to encode.
 * @param digestLen The length, in bytes, of the digest.
 * @param digestAlg An ht_ value specifying the algorithm.
 * @param ppDigestInfo The address where the function will deposit a pointer to
 * the allocated memory holding the DigestInfo.
 * @param pDigestInfoLen The address where the function will deposit the length,
 * in bytes, of the Digestinfo.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ASN1_buildDigestInfoAlloc (
  const ubyte *pDigest,
  ubyte4      digestLen,
  ubyte4      digestAlg,
  ubyte       **ppDigestInfo,
  ubyte4      *pDigestInfoLen
  );

/** Parse DigestInfo, returning a pointer to the digest, a pointer to the OID,
 * and a flag indicating the algorithm.
 * <p>DigestInfo is the following.
 * <pre>
 * <code>
 *   DigestInfo ::= SEQENCE {
 *     algId,
 *     OCTET STRING }
 * </code>
 * </pre>
 * <p>This function will determine which algorithm the DigestInfo is and set
 * *pDigestAlg to one of the ht_ values defined in crypto/crypto.h, such as
 * ht_sha1 or ht_sha256. If the algorithm is unknown, it sets *pDigestAlg to 0.
 * <p>The function will also determine where, in the input buffer, the actual
 * OID and digest data start and how long they are. It will set *ppOid to the
 * address inside pDigestInfo and *ppDigest to the address inside pDigestInfo
 * where the OID and digest start. This function does not allocate memory, it
 * simply determines the addresses where the OID and digest are.
 * <p>The OID will be the actual value of the OID, it does not include the tag
 * and len.
 * <p>Declare variables to be of type ubyte *, pass in their addresses, and the
 * function will go to those addresses and deposit pointers to the OID and
 * digest. For example,
 * <pre>
 * <code>
 *   MSTATUS status;
 *   ubyte4 oidLen, digestLen, digestAlg;
 *   ubyte *pOid, *pDigest;
 *
 *   status = ASN1_parseDigestInfo (
 *     pDigestInfo, digestInfoLen, &pOid, &oidLen, &pDigest, &digestLen,
 *     &digestAlg);
 *
 *   // Suppose the address pDigestInfo is 4000.
 *   // Upon return, pOid would be something like 4006, with oidLen = 9,
 *   // pDigest would be something like 4019, digestLen would be 32,
 *   // and digestAlg would be ht_sha256.
 * </code>
 * </pre>
 *
 * @param pDigestInfo The data to parse.
 * @param digestInfoLen The length, in bytes, of the digestInfo.
 * @param ppOid The address where the function will deposit the address,
 * inside pDigestInfo, where the actual OID data begins.
 * @param pOidLen The address where the function will deposit the length, in
 * bytes, of the OID.
 * @param ppDigest The address where the function will deposit the address,
 * inside pDigestInfo, where the actual digest data begins.
 * @param pDigestLen The address where the function will deposit the length, in
 * bytes, of the digest.
 * @param pDigestAlg The address where the function will deposit the flag
 * indicating the digest algorithm.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ASN1_parseDigestInfo (
  ubyte *pDigestInfo,
  ubyte4 digestInfoLen,
  ubyte **ppOid,
  ubyte4 *pOidLen,
  ubyte **ppDigest,
  ubyte4 *pDigestLen,
  ubyte4 *pDigestAlg
  );

/* The DSA and ECDSA signature is
 * <pre>
 * <code>
 *   SEQ {
 *     r  INTEGER,
 *     s  INTEGER }
 * </code>
 * </pre>
 * <p>This function will convert the input data to canonical integers and build
 * the DER encoding.
 * <p>The caller supplies the buffer into which the result will be placed.
 * <p>The caller passes in the r and s values as arrays of integers. The caller
 * also passes in the size of each integer. Only 4 and 8 are currently supported
 * as the integer size. The array must be from lsWord to msWord. That is, the
 * least significant word at index 0, and the most significant word at index
 * arrayLen - 1.
 * <p>The caller will pass in the arrays, the pointers cast to void *. The
 * function will dereference the pointer to the correct type based on the intSize.
 *
 * @param pRVal The r of the signature.
 * @param rLen The number of words in pRVal
 * @param pSVal The s of the signature.
 * @param sLen The number of words in pSVal
 * @param intSize The size of each integer in the array (4 or 8, ubyte4 or
 * ubyte8).
 * @param pSignature The buffer into which the function will place the result.
 * @param bufferSize The size, in bytes, of the output buffer.
 * @param pSignatureLen The address where the function will deposit the length of
 * the signature (if the buffer is too small, it is the length needed).
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ASN1_buildDsaSignature (
  void *pRVal,
  ubyte4 rLen,
  void *pSVal,
  ubyte4 sLen,
  ubyte4 intSize,
  ubyte *pSignature,
  ubyte4 bufferSize,
  ubyte4 *pSignatureLen
  );

/* The DSA and ECDSA signature is
 * <pre>
 * <code>
 *   SEQ {
 *     r  INTEGER,
 *     s  INTEGER }
 * </code>
 * </pre>
 * <p>This function will verify that the encoding is correct, then return the r
 * and s values. The function will not allocate memory, it will return the address
 * inside pSignature where the values begin.
 *
 * @param pSignature The data to parse.
 * @param signatureLen The length, in bytes, of the signature.
 * @param ppRVal The address where the function will deposit the address,
 * inside pSignature, where the r value data begins.
 * @param pRValLen The address where the function will deposit the length, in
 * bytes, of the r value.
 * @param ppSVal The address where the function will deposit the address,
 * inside pSignature, where the s value data begins.
 * @param pSValLen The address where the function will deposit the length, in
 * bytes, of the s value.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ASN1_parseDsaSignature (
  ubyte *pSignature,
  ubyte4 signatureLen,
  ubyte **ppRVal,
  ubyte4 *pRValLen,
  ubyte **ppSVal,
  ubyte4 *pSValLen
  );

/* This function will parse the AlgId, returning the OID and params.
 * <p>The function will not allocate memory, simply return the addresses inside
 * the algId where the elements begin.
 * <p>The OID will be the actual value of the OID, it does not include the tag
 * and len.
 * <p>The function does not parse the params, it just returns the entire
 * encoding. So if the params are SEQ { something }, the return starts at the 30.
 * The length is the full length, including the length of the tag and len. For
 * example, if the params are 04 10 x x...x, then the length will be 18 (the tag
 * is one byte, the length octet is another byte, that's 2, then the value is 16
 * bytes, for a total of 18. If there are no params, ppParams will be NULL and
 * pParamsLen will be 0. The params might be 05 00, or 30 00, in which case the
 * length will be 2.
 * <p>This function does not check the args. It is the responsibility of the
 * caller not to make mistakes.
 */
MOC_EXTERN MSTATUS ASN1_parseAlgId (
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte **ppOid,
  ubyte4 *pOidLen,
  ubyte **ppParams,
  ubyte4 *pParamsLen
  );

/** Validate the encoding of an ASN.1 value.
 * <p>This function will validate the encoding of an ASN.1 value. It will check
 * the encoding based on the type passed in. The type is one of the ASN.1
 * tags, such as PRINTABLESTRING.
 *
 * @param type         The ASN.1 type of the value to validate. This is one of the
 *                     ASN.1 tags, such as PRINTABLESTRING.
 * @param pEncoding    A pointer to the start of the encoding.
 * @param encodingLen  The length, in bytes, of the encoding.
 * @param pIsValid     The address where the function will deposit a flag
 *                     indicating whether the encoding is valid or not. If the
 *                     encoding is valid, the flag will be set to TRUE, otherwise
 *                     it will be set to FALSE.
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS ASN1_validateEncoding(
    ubyte type,
    ubyte *pEncoding,
    ubyte4 encodingLen,
    byteBoolean *pIsValid);

/* The following section contains a number of Algorithm Identifiers. This will
 * make it easier to build arrays containing the OIDs.
 */

/* This is the OID for an unknown digest. The only use case for this is
 * when interfacing with OpenSSL. OpenSSL does not provide the digest algorithm
 * that was used to get the digest. Since we require that the user passes in a
 * DER encoded digest to our signature operations, we have to DER encode the
 * OpenSSL digest but we can't input an OID into there. Since we can't figure
 * out the OID just by looking at the digest and digest length we make it
 * unknown.
 */
#define MOP_UNKNOWN_OID_LEN 2
#define MOP_UNKNOWN_OID \
  0x06, 0x00
#define MOP_UNKNOWN_ALG_ID_LEN MOP_UNKNOWN_OID_LEN + 4
#define MOP_UNKNOWN_ALG_ID \
    0x30, MOP_UNKNOWN_OID_LEN + 2, \
    MOP_UNKNOWN_OID, \
    0x05, 0x00

/* This is the OID and AlgId for HMAC with SHA-1. The last byte of the OID
 * changes to 8, 9, 10, or 11, for SHA-224, 256, 384, 512.
 */
#define MOP_HMAC_OID_LEN 10
#define MOP_HMAC_OID \
    0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07
#define MOP_HMAC_ALG_ID_LEN  14
#define MOP_HMAC_ALG_ID \
    0x30, MOP_HMAC_OID_LEN + 2, \
    MOP_HMAC_OID, \
    0x05, 0x00

#define MOP_HMAC_OID_OFFSET 2
#define MOP_HMAC_OID_LAST_BYTE_OFFSET 11
#define MOP_HMAC_SHA1_LAST_BYTE   7
#define MOP_HMAC_SHA224_LAST_BYTE 8
#define MOP_HMAC_SHA256_LAST_BYTE 9
#define MOP_HMAC_SHA384_LAST_BYTE 10
#define MOP_HMAC_SHA512_LAST_BYTE 11

/* How many digest AlgIds do we currently support?
 */
#define MOC_DIGEST_ALGID_COUNT  5
#define MOC_DIGEST_FLAG_LIST \
    ht_sha1, ht_sha224, ht_sha256, ht_sha384, ht_sha512
#define MOC_DIGEST_LEN_LIST \
    20, 28, 32, 48, 64

#define MOP_SHA1_OID_LEN 7
#define MOP_SHA1_OID \
    0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A
#define MOP_SHA1_ALG_ID_LEN  MOP_SHA1_OID_LEN + 4
#define MOP_SHA1_ALG_ID \
    0x30, MOP_SHA1_OID_LEN + 2, \
    MOP_SHA1_OID, \
    0x05, 0x00
#define MOP_SHA1_OID_OFFSET 2

#define MOP_SHA224_LAST_BYTE 4
#define MOP_SHA256_LAST_BYTE 1
#define MOP_SHA384_LAST_BYTE 2
#define MOP_SHA512_LAST_BYTE 3

#define MOP_SHA3_224_LAST_BYTE 7
#define MOP_SHA3_256_LAST_BYTE 8
#define MOP_SHA3_384_LAST_BYTE 9
#define MOP_SHA3_512_LAST_BYTE 10
#define MOP_SHAKE128_LAST_BYTE 11
#define MOP_SHAKE256_LAST_BYTE 12

#define MOP_SHA224_OID_LEN 11
#define MOP_SHA224_OID \
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04
#define MOP_SHA224_ALG_ID_LEN MOP_SHA224_OID_LEN + 4
#define MOP_SHA224_ALG_ID \
    0x30, MOP_SHA224_OID_LEN + 2, \
    MOP_SHA224_OID, \
    0x05, 0x00
#define MOP_SHA224_OID_OFFSET 2

#define MOP_SHA256_OID_LEN 11
#define MOP_SHA256_OID \
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
#define MOP_SHA256_ALG_ID_LEN MOP_SHA256_OID_LEN + 4
#define MOP_SHA256_ALG_ID \
    0x30, MOP_SHA256_OID_LEN + 2, \
    MOP_SHA256_OID, \
    0x05, 0x00
#define MOP_SHA256_OID_OFFSET 2

#define MOP_SHA384_OID_LEN 11
#define MOP_SHA384_OID \
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
#define MOP_SHA384_ALG_ID_LEN MOP_SHA384_OID_LEN + 4
#define MOP_SHA384_ALG_ID \
    0x30, MOP_SHA384_OID_LEN + 2, \
    MOP_SHA384_OID, \
    0x05, 0x00
#define MOP_SHA384_OID_OFFSET 2

#define MOP_SHA512_OID_LEN 11
#define MOP_SHA512_OID \
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
#define MOP_SHA512_ALG_ID_LEN MOP_SHA512_OID_LEN + 4
#define MOP_SHA512_ALG_ID \
    0x30, MOP_SHA512_OID_LEN + 2, \
    MOP_SHA512_OID, \
    0x05, 0x00
#define MOP_SHA512_OID_OFFSET 2

/* MD2 OID
 *   1.2.840.113549.2.2
 *
 * Source
 *   http://www.alvestrand.no/objectid/1.2.840.113549.2.2.html
 */
#define MOP_MD2_OID_LEN 10
#define MOP_MD2_OID \
    0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x02
#define MOP_MD2_ALG_ID_LEN MOP_MD2_OID_LEN + 4
#define MOP_MD2_ALG_ID \
    0x30, MOP_MD2_OID_LEN + 2, \
    MOP_MD2_OID, \
    0x05, 0x00
#define MOP_MD2_OID_OFFSET 2
#define MOP_MD2_ALGID_LAST_BYTE_OFFSET MOP_MD2_OID_LEN + 1
#define MOP_MD2_LAST_BYTE  2

/* MD4 OID
 *   1.2.840.113549.2.4
 *
 * Source
 *   http://www.alvestrand.no/objectid/1.2.840.113549.2.4.html
 */
#define MOP_MD4_OID_LEN 10
#define MOP_MD4_OID \
    0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x04
#define MOP_MD4_ALG_ID_LEN MOP_MD4_OID_LEN + 4
#define MOP_MD4_ALG_ID \
    0x30, MOP_MD4_OID_LEN + 2, \
    MOP_MD4_OID, \
    0x05, 0x00
#define MOP_MD4_LAST_BYTE  4

#define MOP_MD5_OID_LEN 10
#define MOP_MD5_OID \
    0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05
#define MOP_MD5_ALG_ID_LEN MOP_MD5_OID_LEN + 4
#define MOP_MD5_ALG_ID \
    0x30, MOP_MD5_OID_LEN + 2, \
    MOP_MD5_OID, \
    0x05, 0x00
#define MOP_MD5_LAST_BYTE  5

/* RIPEMD 160 OID
 *   1.3.36.3.2.1
 *
 * Source
 *   http://oid-info.com/get/1.3.36.3.2.1
 */
#define MOP_RIPEMD160_OID_LEN 7
#define MOP_RIPEMD160_OID \
    0x06, 0x05, 0x2B, 0x24, 0x03, 0x02, 0x01
#define MOP_RIPEMD160_ALG_ID_LEN MOP_RIPEMD160_OID_LEN + 4
#define MOP_RIPEMD160_ALG_ID \
  0x30, MOP_RIPEMD160_OID_LEN + 2, \
  MOP_RIPEMD160_OID, \
  0x05, 0x00

/* If we add another digest algorithm, make sure this is updated if needed.
 */
#define MOP_MAX_DIGEST_ALG_ID_LEN 15

/* The RC5-CBC AlgId is
 *   30 len
 *      OID,
 *      SEQ {
 *        INT version,
 *        INT rounds,
 *        INT blockSize,
 *        OCTET STRING OPTIONAL initVector }
 * There are two RC5-CBC OIDs: no pad and with pad. The difference in OIDs is the
 * last byte.
 * The version is version 1 which is defined as 0x10 (decimal 16).
 * The rounds count is 0x08 to 0x7f (decimal 8 to 127).
 * The block size is 0x40 or 0x00 80 (decimal 64 or 128).
 * If there is no init vector, then the implementation is to use a block of 00
 * bytes as the IV.
 * Because of the variability of the algId (one byte or 2 for the block size, IV
 * or not), there is no "universal" byte array, it must be computed on the fly.
 */
#define MOP_RC5_CBC_PAD_OID_LEN 10
#define MOP_RC5_CBC_PAD_OID \
    0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x09
#define MOP_RC5_CBC_NO_PAD_BYTE  8
#define MOP_RC5_CBC_PAD_BYTE     9

#define MOP_ARC2_CBC_OID_LEN 10
#define MOP_ARC2_CBC_OID \
    0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x02

#define MOP_ARC4_OID_LEN 10
#define MOP_ARC4_OID \
    0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x04

/* Oid for PKCS5 V1 PBE, we only support SHA1-RC2 */
#define MOP_PKCS5_PBE_V1_OID_LEN 11
#define MOP_PKCS5_PBE_V1_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0B
#define MOP_PKCS5_PBE_V1_LAST_BYTE 0x0B

/* Oid for PKCS5 V2 PBE */
#define MOP_PKCS5_PBE_V2_OID_LEN 11
#define MOP_PKCS5_PBE_V2_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D
#define MOP_PKCS5_PBE_V2_LAST_BYTE 0x0D

/* Oid for PKCS5 PBKDF2 */
#define MOP_PKCS5_PBKDF2_OID_LEN 11
#define MOP_PKCS5_PBKDF2_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C

/* dhSinglePass-stdDH-sha1kdf-scheme
 */
#define MOP_DH_SP_SHA1_KDF_OID_LEN 11
#define MOP_DH_SP_SHA1_KDF_OID \
    0x06, 0x09, 0x2b, 0x81, 0x05, 0x10, 0x86, 0x48, 0x3f, 0x00, 0x02

/* dhSinglePass-stdDH-sha256kdf-scheme
 */
#define MOP_DH_SP_SHA224_KDF_OID_LEN 8
#define MOP_DH_SP_SHA224_KDF_OID \
    0x06, 0x06, 0x2b, 0x81, 0x04, 0x01, 0x0b, 0x00
#define MOP_SH_SP_SHA256_LAST_BYTE 0x01
#define MOP_SH_SP_SHA384_LAST_BYTE 0x02
#define MOP_SH_SP_SHA512_LAST_BYTE 0x03

/* The AES-CBC AlgId is
 *   30 len
 *     OID,
 *     OCTET STRING
 *
 * where the OID is either AES-CBC 128, AES-CBC 192, or AES-CBC 256
 * and the OCTET STRING is the init vector which is always 16 bytes.
 * So this #define will build an algID with space for the IV, but the caller must
 * fill in the actual IV.
 */
#define MOP_AES_CBC_OID_LEN 11
#define MOP_AES_CBC_OID \
    0x06, 0x09, \
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a
#define MOP_AES_CBC_ALG_ID_LEN 31
/* The IV in this construct MUST be 00 00 ... 00!
 */
#define MOP_AES_CBC_ALG_ID \
    0x30, MOP_AES_CBC_OID_LEN + 18, \
    MOP_AES_CBC_OID, \
    0x04, 0x10, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define MOP_AES_CBC_OID_LAST_BYTE_OFFSET 12
#define MOP_AES_CBC_INIT_VECTOR_OFFSET 15
#define MOP_AES_CBC_128_BYTE 0x02
#define MOP_AES_CBC_192_BYTE 0x16
#define MOP_AES_CBC_256_BYTE 0x2A

#define MOP_AES_OFB_OID_LEN 11
#define MOP_AES_OFB_OID \
    0x06, 0x09, \
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2B
#define MOP_AES_OFB_ALG_ID_LEN 31
#define MOP_AES_OFB_ALG_ID \
    0x30, MOP_AES_OFB_OID_LEN + 18, \
    MOP_AES_OFB_OID, \
    0x04, 0x10, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define MOP_AES_OFB_OID_LAST_BYTE_OFFSET 12
#define MOP_AES_OFB_INIT_VECTOR_OFFSET 15
#define MOP_AES_OFB_128_BYTE 0x03
#define MOP_AES_OFB_192_BYTE 0x17
#define MOP_AES_OFB_256_BYTE 0x2B

#define MOP_AES_CFB_OID_LEN 11
#define MOP_AES_CFB_OID \
    0x06, 0x09, \
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2C
#define MOP_AES_CFB_ALG_ID_LEN 31
#define MOP_AES_CFB_ALG_ID \
    0x30, MOP_AES_CFB_OID_LEN + 18, \
    MOP_AES_CFB_OID, \
    0x04, 0x10, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define MOP_AES_CFB_OID_LAST_BYTE_OFFSET 12
#define MOP_AES_CFB_INIT_VECTOR_OFFSET 15
#define MOP_AES_CFB_128_BYTE 0x04
#define MOP_AES_CFB_192_BYTE 0x18
#define MOP_AES_CFB_256_BYTE 0x2C

/* The AES-ECB AlgId is
 *   30 len
 *     OID,
 *     NULL
 *
 * where the OID is either AES-ECB 128, AES-ECB 192, or AES-ECB 256.
 */
#define MOP_AES_ECB_OID_LEN 11
#define MOP_AES_ECB_OID \
    0x06, 0x09, \
    0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x29
#define MOP_AES_ECB_ALG_ID_LEN 15
#define MOP_AES_ECB_ALG_ID \
    0x30, MOP_AES_ECB_OID_LEN + 2, \
    MOP_AES_ECB_OID, \
    0x05, 0x00
#define MOP_AES_ECB_OID_LAST_BYTE_OFFSET 12
#define MOP_AES_ECB_128_BYTE 0x01
#define MOP_AES_ECB_192_BYTE 0x15
#define MOP_AES_ECB_256_BYTE 0x29

#define MOP_AES_GCM_DEFAULT_TAG_LEN  12
#define MOP_AES_GCM_OID_LEN 11
#define MOP_AES_GCM_OID \
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2E
#define MOP_AES_GCM_128_BYTE 0x06
#define MOP_AES_GCM_192_BYTE 0x1A
#define MOP_AES_GCM_256_BYTE 0x2E

#define MOP_AES_CCM_OID_LEN 11
#define MOP_AES_CCM_OID \
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x07
#define MOP_AES_CCM_128_BYTE 0x07
#define MOP_AES_CCM_192_BYTE 0x1B
#define MOP_AES_CCM_256_BYTE 0x2F

#define MOP_AES_KEY_WRAP_OID_LEN 11
#define MOP_AES_KEY_WRAP_OID \
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05
#define MOP_AES_KEY_WRAP_128_BYTE 0x05
#define MOP_AES_KEY_WRAP_192_BYTE 0x19
#define MOP_AES_KEY_WRAP_256_BYTE 0x2D

#define MOP_AES_KEY_WRAP_PAD_OID_LEN 11
#define MOP_AES_KEY_WRAP_PAD_OID \
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x08
#define MOP_AES_KEY_WRAP_PAD_128_BYTE 0x08
#define MOP_AES_KEY_WRAP_PAD_192_BYTE 0x1C
#define MOP_AES_KEY_WRAP_PAD_256_BYTE 0x30

#define MOP_TDES_CBC_PAD_OID_LEN 10
#define MOP_TDES_CBC_PAD_OID \
    0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07

#define MOP_DES_CBC_PAD_OID_LEN 7
#define MOP_DES_CBC_PAD_OID \
    0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x07

#define MOP_BLOWFISH_ECB_OID_LEN 11
#define MOP_BLOWFISH_ECB_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x01

#define MOP_BLOWFISH_CBC_OID_LEN 11
#define MOP_BLOWFISH_CBC_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x02

#define MOP_CAST128_CBC_OID_LEN 11
#define MOP_CAST128_CBC_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF6, 0x7D, 0x07, 0x42, 0x0A

#define MOP_CHACHA_20_POLY_1305_AEAD_OID_LEN 13
#define MOP_CHACHA_20_POLY_1305_AEAD_OID \
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x12

/* RSA encryption: There are two OIDs, one for P1.5 and the other for OAEP. They
 * are actually the same thing except for the last byte.
 */
#define MOP_RSA_P1_ENC_OID_LEN 11
#define MOP_RSA_P1_ENC_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
#define MOP_RSA_P1_ENC_ALG_ID_LEN MOP_RSA_P1_ENC_OID_LEN + 4
#define MOP_RSA_P1_ENC_ALG_ID \
    0x30, MOP_RSA_P1_ENC_OID_LEN + 2, \
    MOP_RSA_P1_ENC_OID, \
    0x05, 0x00
#define MOP_RSA_P1_OID_LAST_BYTE_OFFSET  MOP_RSA_P1_ENC_OID_LEN + 1
#define MOP_RSA_P1_PARAMS_TAG_OFFSET     MOP_RSA_P1_ENC_OID_LEN + 2
#define MOP_RSA_P1_5_BYTE                1
#define MOP_RSA_OAEP_BYTE                7
#define MOP_RSA_PARAMS_TAG_NULL          5
#define MOP_RSA_PARAMS_TAG_NO_PARAMS     0x30

#define MOP_RSA_TAP_OID_LEN 11
#define MOP_RSA_TAP_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x01
#define MOP_RSA_TAP_ALG_ID_LEN MOP_RSA_TAP_OID_LEN + 4
#define MOP_RSA_TAP_ALG_ID \
    0x30, MOP_RSA_TAP_OID_LEN + 2, \
    MOP_RSA_TAP_OID, \
    0x05, 0x00

/* TAP password protected keys will have an OID with last byte 
 * masked by the 3rd bit from the left, ie 0x20,
 * compared to that alg's oid. The index is the last byte withing
 * the alg, id, so 3rd to last byte or index 12.
 */
#define MOP_TAP_PW_MASK 0x20
#define MOP_TAP_PW_OID_INDEX 12

/* RSA signing. There are two OIDs, SHA-x with RSA and RSA-PSS. They differ in
 * only the last byte.
 */
#define MOP_RSA_SHA1_P1_OID_LEN 11
#define MOP_RSA_SHA1_P1_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05
#define MOP_RSA_SHA1_P1_ALG_ID_LEN MOP_RSA_SHA1_P1_OID_LEN + 4
#define MOP_RSA_SHA1_P1_ALG_ID \
    0x30, MOP_RSA_SHA1_P1_OID_LEN + 2, \
    MOP_RSA_SHA1_P1_OID, \
    0x05, 0x00
#define MOP_RSA_SHA_P1_OID_LAST_BYTE_OFFSET 12
#define MOP_RSA_SHA1_BYTE    5
#define MOP_RSA_SHA224_BYTE 14
#define MOP_RSA_SHA256_BYTE 11
#define MOP_RSA_SHA384_BYTE 12
#define MOP_RSA_SHA512_BYTE 13
#define MOP_RSA_PSS_BYTE    10
#define MOP_RSA_MD2_BYTE     2
#define MOP_RSA_MD5_BYTE     4

#define MOP_RSA_PSS_OID_LEN 11
#define MOP_RSA_PSS_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A

#define MOP_RSA_PSS_ALG_ID_LEN MOP_RSA_PSS_OID_LEN + 2
#define MOP_RSA_PSS_ALG_ID \
    0x30, MOP_RSA_PSS_OID_LEN, \
    MOP_RSA_PSS_OID

#define MOP_PSOURCE_SPECIFIED_OID_LEN 11
#define MOP_PSOURCE_SPECIFIED_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x09

#define MOP_MGF1_OID_LEN 11
#define MOP_MGF1_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08

#define MOP_DH_OID_LEN 9
#define MOP_DH_OID \
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01

#define MOP_DSA_OID_LEN 9
#define MOP_DSA_OID \
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01

#define MOP_DSA_SHA1_ALG_ID_LEN 11
#define MOP_DSA_SHA1_ALG_ID \
    0x30, 0x09, \
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03
#define MOP_DSA_SHA1_BYTE      3

#define MOP_DSA_SHA224_ALG_ID_LEN 13
#define MOP_DSA_SHA224_ALG_ID \
    0x30, 0x0B, \
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x01
#define MOP_DSA_SHA224_BYTE    1
#define MOP_DSA_SHA256_BYTE    2

#define MOP_ECDSA_SHA1_ALG_ID_LEN 11
#define MOP_ECDSA_SHA1_ALG_ID \
    0x30, 0x09, \
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01
#define MOP_ECDSA_SHA1_BYTE      1

#define MOP_ECDSA_SHA224_ALG_ID_LEN 12
#define MOP_ECDSA_SHA224_ALG_ID \
    0x30, 0x0A, \
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x01
#define MOP_ECDSA_SHA224_BYTE    1
#define MOP_ECDSA_SHA256_BYTE    2
#define MOP_ECDSA_SHA384_BYTE    3
#define MOP_ECDSA_SHA512_BYTE    4

#define MOP_ECC_KEY_OID_LEN 9
#define MOP_ECC_KEY_OID \
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01

/* This is the curve OID for P192.
 * Change the last byte and it is P256.
 */
#define MOP_ECC_CURVE_P192_OID_LEN 10
#define MOP_ECC_CURVE_P192_OID \
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01
#define MOP_ECC_CURVE_P192_BYTE 1
#define MOP_ECC_CURVE_P256_BYTE 7

/* This is the curve OID for P224.
 * Change the last byte and it is P384 or P521.
 */
#define MOP_ECC_CURVE_P224_OID_LEN 7
#define MOP_ECC_CURVE_P224_OID \
    0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21
#define MOP_ECC_CURVE_P224_BYTE 0x21
#define MOP_ECC_CURVE_P384_BYTE 0x22
#define MOP_ECC_CURVE_P521_BYTE 0x23

/* This is the curve OID for EDDH 25519.
 * Change the last byte and it is EDDH 448 or EDDSA 25519/448.
 */
#define MOP_ECC_CURVE_EDDH_25519_OID_LEN 5
#define MOP_ECC_CURVE_EDDH_25519_OID \
    0x06, 0x03, 0x2B, 0x65, 0x6E
#define MOP_ECC_CURVE_EDDH_448_BYTE    0x6F
#define MOP_ECC_CURVE_EDDSA_25519_BYTE 0x70
#define MOP_ECC_CURVE_EDDSA_448_BYTE   0x71

#define MOP_MAX_ECC_CURVE_OID_LEN MOP_ECC_CURVE_P192_OID_LEN

/* This is the OID for ANSI X9.62 field type prime */
#define MOP_ECC_FIELD_TYPE_PRIME_OID_LEN 9
#define MOP_ECC_FIELD_TYPE_PRIME_OID \
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x01, 0x01

#define MOP_TPM_12_RSA_KEY_OID_LEN  12
#define MOP_TPM_12_RSA_KEY_OID \
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x12, 0x01, 0x01
#define MOP_TPM_12_RSA_KEY_ALG_ID_LEN MOP_TPM_12_RSA_KEY_OID_LEN + 4
#define MOP_TPM_12_RSA_KEY_ALG_ID \
    0x30, MOP_TPM_12_RSA_KEY_OID_LEN + 2, \
    MOP_TPM_12_RSA_KEY_OID, \
    0x05, 0x00

#define MOP_RSA_TAP_KEY_OID_LEN  12
#define MOP_RSA_TAP_KEY_OID \
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x12, 0x01, 0x01
#define MOP_RSA_TAP_KEY_ALG_ID_LEN MOP_RSA_TAP_KEY_OID_LEN + 4
#define MOP_RSA_TAP_KEY_ALG_ID \
    0x30, MOP_RSA_TAP_KEY_OID_LEN + 2, \
    MOP_RSA_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_ECC_TAP_KEY_OID_LEN 11
#define MOP_ECC_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x02
#define MOP_ECC_TAP_KEY_ALG_ID_LEN MOP_ECC_TAP_KEY_OID_LEN + 4
#define MOP_ECC_TAP_KEY_ALG_ID \
    0x30, MOP_ECC_TAP_KEY_OID_LEN + 2, \
    MOP_ECC_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_AES_TAP_KEY_OID_LEN 11
#define MOP_AES_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x04
#define MOP_AES_TAP_KEY_ALG_ID_LEN MOP_AES_TAP_KEY_OID_LEN + 4
#define MOP_AES_TAP_KEY_ALG_ID \
    0x30, MOP_AES_TAP_KEY_OID_LEN + 2, \
    MOP_AES_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_AES_ECB_TAP_KEY_OID_LEN 11
#define MOP_AES_ECB_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x05
#define MOP_AES_ECB_TAP_KEY_ALG_ID_LEN MOP_AES_ECB_TAP_KEY_OID_LEN + 4
#define MOP_AES_ECB_TAP_KEY_ALG_ID \
    0x30, MOP_AES_ECB_TAP_KEY_OID_LEN + 2, \
    MOP_AES_ECB_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_AES_CBC_TAP_KEY_OID_LEN 11
#define MOP_AES_CBC_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x06
#define MOP_AES_CBC_TAP_KEY_ALG_ID_LEN MOP_AES_CBC_TAP_KEY_OID_LEN + 4
#define MOP_AES_CBC_TAP_KEY_ALG_ID \
    0x30, MOP_AES_CBC_TAP_KEY_OID_LEN + 2, \
    MOP_AES_CBC_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_AES_CFB_TAP_KEY_OID_LEN 11
#define MOP_AES_CFB_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x07
#define MOP_AES_CFB_TAP_KEY_ALG_ID_LEN MOP_AES_CFB_TAP_KEY_OID_LEN + 4
#define MOP_AES_CFB_TAP_KEY_ALG_ID \
    0x30, MOP_AES_CFB_TAP_KEY_OID_LEN + 2, \
    MOP_AES_CFB_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_AES_OFB_TAP_KEY_OID_LEN 11
#define MOP_AES_OFB_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x08
#define MOP_AES_OFB_TAP_KEY_ALG_ID_LEN MOP_AES_OFB_TAP_KEY_OID_LEN + 4
#define MOP_AES_OFB_TAP_KEY_ALG_ID \
    0x30, MOP_AES_OFB_TAP_KEY_OID_LEN + 2, \
    MOP_AES_OFB_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_AES_CTR_TAP_KEY_OID_LEN 11
#define MOP_AES_CTR_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x09
#define MOP_AES_CTR_TAP_KEY_ALG_ID_LEN MOP_AES_CTR_TAP_KEY_OID_LEN + 4
#define MOP_AES_CTR_TAP_KEY_ALG_ID \
    0x30, MOP_AES_CTR_TAP_KEY_OID_LEN + 2, \
    MOP_AES_CTR_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_AES_GCM_TAP_KEY_OID_LEN 11
#define MOP_AES_GCM_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x0a
#define MOP_AES_GCM_TAP_KEY_ALG_ID_LEN MOP_AES_GCM_TAP_KEY_OID_LEN + 4
#define MOP_AES_GCM_TAP_KEY_ALG_ID \
    0x30, MOP_AES_GCM_TAP_KEY_OID_LEN + 2, \
    MOP_AES_GCM_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_DES_TAP_KEY_OID_LEN 11
#define MOP_DES_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x0b
#define MOP_DES_TAP_KEY_ALG_ID_LEN MOP_DES_TAP_KEY_OID_LEN + 4
#define MOP_DES_TAP_KEY_ALG_ID \
    0x30, MOP_DES_TAP_KEY_OID_LEN + 2, \
    MOP_DES_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_DES_ECB_TAP_KEY_OID_LEN 11
#define MOP_DES_ECB_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x0c
#define MOP_DES_ECB_TAP_KEY_ALG_ID_LEN MOP_DES_ECB_TAP_KEY_OID_LEN + 4
#define MOP_DES_ECB_TAP_KEY_ALG_ID \
    0x30, MOP_DES_ECB_TAP_KEY_OID_LEN + 2, \
    MOP_DES_ECB_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_DES_CBC_TAP_KEY_OID_LEN 11
#define MOP_DES_CBC_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x0d
#define MOP_DES_CBC_TAP_KEY_ALG_ID_LEN MOP_DES_CBC_TAP_KEY_OID_LEN + 4
#define MOP_DES_CBC_TAP_KEY_ALG_ID \
    0x30, MOP_DES_CBC_TAP_KEY_OID_LEN + 2, \
    MOP_DES_CBC_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_TDES_TAP_KEY_OID_LEN 11
#define MOP_TDES_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x0e
#define MOP_TDES_TAP_KEY_ALG_ID_LEN MOP_TDES_TAP_KEY_OID_LEN + 4
#define MOP_TDES_TAP_KEY_ALG_ID \
    0x30, MOP_TDES_TAP_KEY_OID_LEN + 2, \
    MOP_TDES_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_TDES_ECB_TAP_KEY_OID_LEN 11
#define MOP_TDES_ECB_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x0f
#define MOP_TDES_ECB_TAP_KEY_ALG_ID_LEN MOP_TDES_ECB_TAP_KEY_OID_LEN + 4
#define MOP_TDES_ECB_TAP_KEY_ALG_ID \
    0x30, MOP_TDES_ECB_TAP_KEY_OID_LEN + 2, \
    MOP_TDES_ECB_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_TDES_CBC_TAP_KEY_OID_LEN 11
#define MOP_TDES_CBC_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x10
#define MOP_TDES_CBC_TAP_KEY_ALG_ID_LEN MOP_TDES_CBC_TAP_KEY_OID_LEN + 4
#define MOP_TDES_CBC_TAP_KEY_ALG_ID \
    0x30, MOP_TDES_CBC_TAP_KEY_OID_LEN + 2, \
    MOP_TDES_CBC_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_HMAC_TAP_KEY_OID_LEN 11
#define MOP_HMAC_TAP_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x11
#define MOP_HMAC_TAP_KEY_ALG_ID_LEN MOP_HMAC_TAP_KEY_OID_LEN + 4
#define MOP_HMAC_TAP_KEY_ALG_ID \
    0x30, MOP_HMAC_TAP_KEY_OID_LEN + 2, \
    MOP_HMAC_TAP_KEY_OID, \
    0x05, 0x00

#define MOP_SECURE_STORAGE_KEY_OID_LEN 11
#define MOP_SECURE_STORAGE_KEY_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xF0, 0x55, 0x13, 0x1F
#define MOP_SECURE_STORAGE_KEY_ALG_ID_LEN MOP_SECURE_STORAGE_KEY_OID_LEN + 4
#define MOP_SECURE_STORAGE_KEY_ALG_ID \
    0x30, MOP_SECURE_STORAGE_KEY_OID_LEN + 2, \
    MOP_SECURE_STORAGE_KEY_OID, \
    0x05, 0x00

#define MOP_COUNTRY_NAME_OID_LEN 5
#define MOP_COUNTRY_NAME_OID  \
    0x06, 0x03, 0x55, 0x04, 0x06

#define MOP_STATE_PROVINCE_NAME_OID_LEN 5
#define MOP_STATE_PROVINCE_NAME_OID \
    0x06, 0x03, 0x55, 0x04, 0x08

#define MOP_LOCALITY_NAME_OID_LEN 5
#define MOP_LOCALITY_NAME_OID \
    0x06, 0x03, 0x55, 0x04, 0x07

#define MOP_COMMON_NAME_OID_LEN 5
#define MOP_COMMON_NAME_OID \
    0x06, 0x03, 0x55, 0x04, 0x03

#define MOP_ORGANIZATION_NAME_OID_LEN 5
#define MOP_ORGANIZATION_NAME_OID \
    0x06, 0x03, 0x55, 0x04, 0x0A

#define MOP_ORGANIZATIONAL_UNIT_NAME_OID_LEN 5
#define MOP_ORGANIZATIONAL_UNIT_NAME_OID \
    0x06, 0x03, 0x55, 0x04, 0x0B

#define MOP_STREET_ADDRESS_NAME_OID_LEN 5
#define MOP_STREET_ADDRESS_NAME_OID \
  0x06, 0x03, 0x55, 0x04, 0x09

#define MOP_BUSINESS_CATEGORY_NAME_OID_LEN 5
#define MOP_BUSINESS_CATEGORY_NAME_OID \
  0x06, 0x03, 0x55, 0x04, 0x0F

#define MOP_POSTAL_CODE_NAME_OID_LEN 5
#define MOP_POSTAL_CODE_NAME_OID \
  0x06, 0x03, 0x55, 0x04, 0x11

#define MOP_SERIAL_NUMBER_NAME_OID_LEN 5
#define MOP_SERIAL_NUMBER_NAME_OID \
  0x06, 0x03, 0x55, 0x04, 0x05

#define MOP_EMAIL_ADDRESS_NAME_OID_LEN 11
#define MOP_EMAIL_ADDRESS_NAME_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01

#define MOP_PKCS9_UNSTRUCTURED_NAME_OID_LEN 11
#define MOP_PKCS9_UNSTRUCTURED_NAME_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x02

#define MOP_USER_ID_NAME_OID_LEN 12
#define MOP_USER_ID_NAME_OID \
    0x06, 0x0A, 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01

#define MOP_DOMAIN_COMPNENT_NAME_OID_LEN 12
#define MOP_DOMAIN_COMPNENT_NAME_OID \
    0x06, 0x0A, 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19

#define MOP_JI_LOCALITY_NAME_OID_LEN 13
#define MOP_JI_LOCALITY_NAME_OID \
    0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, \
    0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, 0x01

#define MOP_JI_STATE_PROVINCE_NAME_OID_LEN 13
#define MOP_JI_STATE_PROVINCE_NAME_OID \
    0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, \
    0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, 0x02

#define MOP_JI_COUNTRY_NAME_OID_LEN 13
#define MOP_JI_COUNTRY_NAME_OID \
    0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, \
    0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, 0x03

#define MOP_BASIC_CONSTRAINTS_OID_LEN 5
#define MOP_BASIC_CONSTRAINTS_OID \
    0x06, 0x03, 0x55, 0x1D, 0x13

#define MOP_KEY_USAGE_OID_LEN 5
#define MOP_KEY_USAGE_OID \
    0x06, 0x03, 0x55, 0x1D, 0x0F

#define MOP_AUTH_KEY_ID_OID_LEN 5
#define MOP_AUTH_KEY_ID_OID \
    0x06, 0x03, 0x55, 0x1D, 0x23

#define MOP_SUBJECT_KEY_ID_OID_LEN 5
#define MOP_SUBJECT_KEY_ID_OID \
    0x06, 0x03, 0x55, 0x1D, 0x0E

#define MOP_CERT_TEMPLATE_NAME_OID_LEN 11
#define MOP_CERT_TEMPLATE_NAME_OID \
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02

#define MOP_EXT_REQ_OID_LEN 11
#define MOP_EXT_REQ_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E

#define MOP_CHALLENGE_PASS_OID_LEN 11
#define MOP_CHALLENGE_PASS_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x07

#define MOP_CONTENT_TYPE_ATTR_OID_LEN 11
#define MOP_CONTENT_TYPE_ATTR_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03

#define MOP_DIGEST_ATTR_OID_LEN 11
#define MOP_DIGEST_ATTR_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04

#define MOP_SIGN_TIME_ATTR_OID_LEN 11
#define MOP_SIGN_TIME_ATTR_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05

#define MOP_CMS_DATA_OID_LEN 11
#define MOP_CMS_DATA_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01
#define MOP_CMS_DATA_OID_LAST_BYTE  0x01

#define MOP_CMS_SIGNED_DATA_OID_LEN 11
#define MOP_CMS_SIGNED_DATA_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02
#define MOP_CMS_SIGNED_DATA_OID_LAST_BYTE  0x02

#define MOP_CMS_ENV_DATA_OID_LEN 11
#define MOP_CMS_ENV_DATA_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03
#define MOP_CMS_ENV_DATA_OID_LAST_BYTE 0x03

#define MOP_P7_SIG_ENV_DATA_OID_LEN 11
#define MOP_P7_SIG_ENV_DATA_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x04
#define MOP_CMS_SIG_ENV_DATA_OID_LAST_BYTE 0x04

#define MOP_CMS_DIG_DATA_OID_LEN 11
#define MOP_CMS_DIG_DATA_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x05
#define MOP_CMS_DIG_DATA_OID_LASTBYTE 0x05

#define MOP_CMS_ENC_DATA_OID_LEN 11
#define MOP_CMS_ENC_DATA_OID \
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06
#define MOP_CMS_ENC_DATA_OID_LAST_BYTE 0x06

#define MOP_CMS_AUTH_DATA_OID_LEN 13
#define MOP_CMS_AUTH_DATA_OID \
    0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x02

/* The max of all CMS/PKCS 7 message type OIDs is there so someone can just use a
 * ubyte[size] as opposed to allocateing memory.,
 */
#define MOC_CMS_MAX_TYPE_OID_LEN  MOP_CMS_AUTH_DATA_OID_LEN

#ifdef __cplusplus
}
#endif

#endif
