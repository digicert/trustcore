/**
 * @file  ipsec_crypto.h
 * @brief NanoSec IPsec cryptography suites header.
 *
 * @details    This file contains IPsec cryptographic algorithm definitions and declarations.
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
/* internal use only */

#ifndef __IPSEC_CRYPTO_HEADER__
#define __IPSEC_CRYPTO_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

typedef struct SADB_hmacSuiteInfo
{
    ubyte       oAuthAlgo;          /* hash algorithm ID */
    ubyte2      wDigestOrgLen;      /* original message digest length */
    ubyte2      wIcvLen;            /* ICV (integrity check value) length in packet */
    ubyte2      wKeyLen;            /* authentication key length (in bytes) */

    MSTATUS (*hmacFunc)(MOC_HASH(hwAccelDescr hwAccelCtx)
                        const ubyte* key, sbyte4 keyLen,
                        const ubyte* text, sbyte4 textLen, ubyte result[]);
} SADB_hmacSuiteInfo;


/*------------------------------------------------------------------*/

struct BulkEncryptionAlgo;
struct AeadAlgo;

typedef struct SADB_cipherSuiteInfo
{
    ubyte       oEncrAlgo;          /* encryption algorithm ID */

    ubyte2      wIvLen;             /* length of IV (initialization vector) */
    ubyte2      wKeyLen;            /* encryption key length (in bytes, minimum) */
    ubyte2      wKeyLenEnd;         /* encryption key length (in bytes, maximum) */

    ubyte       oNonceLen;          /* e.g. aes-gcm/gmac 'salt' or aes-ctr nonce */
    struct AeadAlgo *pAeadAlgo;     /* AEAD algo */
    intBoolean  bAeadNull;

    const struct BulkEncryptionAlgo *
                pBEAlgo;            /* the encryption functions */
} SADB_cipherSuiteInfo;


/*------------------------------------------------------------------*/

MOC_EXTERN SADB_hmacSuiteInfo *IPSEC_hmacSuite(ubyte oAuthAlgo);
MOC_EXTERN SADB_cipherSuiteInfo *IPSEC_cipherSuite(ubyte oEncrAlgo,
                                               ubyte oAeadIcvLen,
                                               ubyte2 wKeyLen, ubyte2 *pwKeyLen);
MOC_EXTERN SADB_cipherSuiteInfo *IPSEC_getCipherSuite(sbyte4 i);
MOC_EXTERN SADB_hmacSuiteInfo* IPSEC_getHmacSuite(sbyte4 i);

MOC_EXTERN sbyte4 IPSEC_getMaxCipherSuites(void);
MOC_EXTERN sbyte4 IPSEC_getMaxHmacSuites(void);


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS IPSEC_cryptoInit(void);
MOC_EXTERN MSTATUS IPSEC_cryptoUninit(void);

#if defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__)
MOC_EXTERN MSTATUS IPSEC_getHwAccelChannel(hwAccelDescr *pHwAccelCtx, intBoolean bIn);
MOC_EXTERN MSTATUS IPSEC_releaseHwAccelChannel(hwAccelDescr *pHwAccelCtx);
#endif

#ifdef __IPSEC_SINGLE_PASS_SUPPORT__
MOC_EXTERN ubyte4 IPSEC_getSinglePassType(SADB_cipherSuiteInfo *pCipherSuite, SADB_hmacSuiteInfo *pHmacSuite, intBoolean bIn);
#endif


#ifdef __cplusplus
}
#endif

#endif /* __IPSEC_CRYPTO_HEADER__ */

