/*
 * crypto_seg.h
 *
 * Cryptographic Methods for Mocana Segments Header File
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
