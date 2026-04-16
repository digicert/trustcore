/*
 * crypto_seg.h
 *
 * Cryptographic Methods for Mocana Segments Header File
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


/*------------------------------------------------------------------*/

#if (!(defined(__CRYPTO_SEG_HEADER__)))

/* prototypes */
MOC_EXTERN MSTATUS CRYPTO_SEG_md5_updateDigest(MOC_HASH(hwAccelDescr hwAccelCtx) MD5_CTX *pContext, poolHeaderDescr *pPoolMahCellDescr, const mocSegDescr *pSrcSegment, ubyte4 offset, ubyte4 dataLen, intBoolean *pRetIsComplete);
MOC_EXTERN MSTATUS CRYPTO_SEG_sha1_updateDigest(MOC_HASH(hwAccelDescr hwAccelCtx) shaDescr *p_shaContext, poolHeaderDescr *pPoolMahCellDescr, const mocSegDescr *pSrcSegment, ubyte4 offset, ubyte4 dataLen, intBoolean *pRetIsComplete);

MOC_EXTERN MSTATUS CRYPTO_SEG_cryptoOp(MOC_SYM(hwAccelDescr hwAccelCtx) BulkEncryptionAlgo* pBEA,
                      void* pSymCipherCtx, ubyte* pCipherIV, ubyte4 cipherIVLength,
                      poolHeaderDescr *pPoolMahCellDescr, mocSegDescr *pSrcSegment,
                      ubyte4 offset, ubyte4 dataLen, ubyte4 encrypt);


#endif
