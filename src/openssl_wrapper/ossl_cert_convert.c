/*
 * ossl_cert_convert.c
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <string.h>
#ifndef __RTOS_WIN32__
#include <unistd.h>
#endif

#include <openssl/opensslconf.h>

/* 
 * VxWorks has the following 3 files in a different directory
 */
#ifdef __RTOS_VXWORKS__
#include <openssl/x509.h>
#include <openssl/pem.h>
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include <internal/evp_int.h>
#include <rsa/rsa_locl.h>
#include <dsa/dsa_locl.h>
#include <openssl/err.h>
#include <ec/ec_lcl.h>
#else  /* !__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#include <err.h>
#include <ec_lcl.h>
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#else  /* ! __RTOS_VXWORKS__ */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#if OPENSSL_VERSION_NUMBER < 0x010101060
#include "crypto/rsa/rsa_locl.h"
#include "crypto/dsa/dsa_locl.h"
#else
#include "crypto/rsa/rsa_local.h"
#include "crypto/dsa/dsa_local.h"
#endif
#include "openssl/x509.h"
#if OPENSSL_VERSION_NUMBER < 0x010101060
#include "crypto/include/internal/evp_int.h"
#else
#include "include/crypto/evp.h"
#endif
#include "openssl/pem.h"
#include "openssl/err.h"
#else  /*  ! __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#include "crypto/x509/x509.h"
#include "crypto/pem/pem.h"
#include "crypto/err/err.h"
#endif  /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#if OPENSSL_VERSION_NUMBER < 0x010101060
#include <crypto/ec/ec_lcl.h>
#else
#include <crypto/ec/ec_local.h>
#endif
#endif  /* __RTOS_VXWORKS__ */

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/absstream.h"
#include "../common/sizedbuffer.h"
#include "../common/mstdlib.h"
#include "../crypto/crypto.h"
#include "../crypto/rsa.h"
#include "../crypto/dsa.h"
#include "../crypto/dh.h"
#include "../crypto/des.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/md2.h"
#include "../crypto/md4.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/primefld_priv.h"
#include "../crypto/primeec_priv.h"
#include "openssl_shim.h"
#include "../crypto/keyblob.h"
#include "../crypto/three_des.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ecb.h"
#include "../common/tree.h"
#include "../crypto/cert_store.h"
#include "../asn1/oiddefs.h"

#include "../crypto/hw_accel.h"

#include "ossl_types.h"

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && defined(__ENABLE_DIGICERT_TAP__)
void DIGI_EVP_maskCred(ubyte *pIn, ubyte4 inLen);
static sbyte *pMaskedCredentials = NULL;
static sbyte4 maskedCredentialsLen;

/*  creates a new entry in extendedDataEntries, and returns index of where it is stored.
    return -1 if no more space available. */
static sbyte4 ossl_setCredentials(
    enum dataType type,
    enum dataEncoding format,
    sbyte *pBuffer,
    sbyte4 bufferLen)
{
    sbyte *pNewBuffer = NULL;
    MOC_UNUSED(type);
    MOC_UNUSED(format);

    if ((NULL == pBuffer) || (0 >= bufferLen))
        return -1;

    pNewBuffer = OSSL_MALLOC(bufferLen);
    if (NULL == pNewBuffer)
        return -1;
    
    DIGI_EVP_maskCred((ubyte *) pBuffer, bufferLen); /* mask credentials */
    memcpy(pNewBuffer, pBuffer, bufferLen);

    if (NULL != pMaskedCredentials)
        OSSL_FREE(pMaskedCredentials);

    pMaskedCredentials = pNewBuffer;
    maskedCredentialsLen = bufferLen;

    return 0;
}

static sbyte4 ossl_getCredentials(sbyte4 identifier,
    enum dataType *pType,
    enum dataEncoding *pFormat,
    sbyte **ppBuffer,
    sbyte4 *pBufferLen)
{
    sbyte *pCredentials;
    MOC_UNUSED(identifier);

    if ((NULL == ppBuffer) || (NULL == pBufferLen))
        return -1;

    pCredentials = OSSL_MALLOC(maskedCredentialsLen);
    if (NULL == pCredentials)
        return -1;

    memcpy(pCredentials, pMaskedCredentials, maskedCredentialsLen);
    DIGI_EVP_maskCred((ubyte *)pCredentials, maskedCredentialsLen); /* unmask credentials */

    *ppBuffer = pCredentials;
    *pBufferLen = maskedCredentialsLen;

    if (NULL != pType)
    {
        *pType = DATA_TYPE_PASSWORD;
    }

    if (NULL != pFormat)
    {
        *pFormat = DATA_ENCODE_BYTE_BUFFER;
    }

    return 0;
}

extern void ossl_clearCredentials(void)
{
    if (NULL != pMaskedCredentials)
        OSSL_FREE(pMaskedCredentials);
    pMaskedCredentials = NULL;
    maskedCredentialsLen = 0;
}
#endif /* __ENABLE_DIGICERT_TAP__ */

extern int dsaExAppDataIndex;
extern int rsaExAppDataIndex;
extern int eccExAppDataIndex;

static int
osslX509ToSizedBuffer(X509 *x, OSSL_X509_LIST *chain, OSSL_SizedBuffer *pSBuf, int numSBufs)
{
     int		derLen, i;
     unsigned char    * to;

     derLen 	= i2d_X509(x, NULL);
     if (0 > derLen)
     {
         goto exit;
     }
     if (0 > OSSL_SB_Allocate(pSBuf, derLen)) {
	  goto exit;
     }
     to		= pSBuf[0].data;
     derLen 	= i2d_X509(x, &to);
     --numSBufs;
     for (i = 0; i < numSBufs; ++i)
     {
	  x		= chain->certs[i];
	  derLen 	= i2d_X509(x, NULL);
      if (0 > derLen)
      {
          return -1;
      }
	  if (OK > OSSL_SB_Allocate(&pSBuf[i+1], derLen))
	       goto exit;
	  to		= pSBuf[i+1].data;
	  i2d_X509(x, &to);
     }
     return 0;
exit:
     for (i = 0; i < numSBufs; ++i) {
	  if (0 == OSSL_SB_Free(&pSBuf[i]))
	       break;
     }
     return -1;
}

static int
ossl_PkeyToBlob(EVP_PKEY *pkey, u_int8_t **ppKeyBlob, unsigned int *len)
{
     RSA	      * ossl_rsa;
     DSA	      * ossl_dsa;
     OSSL_RSAParams	ORP;
     OSSL_DSAParams	ODP;
     int		rval = -1;
#if (defined (__ENABLE_DIGICERT_ECC__))
     BN_CTX    	      * ctx = NULL;
     BIGNUM 	      * pubkey_bn = NULL;
     EC_KEY           * ossl_eckey;
     OSSL_ECCParams OEP;
     OSSL_ECCURVE_TYPE	cname;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
     ECX_KEY  *pOSSLECXKey = NULL;
     size_t edKeyLen = 0;
#endif
#endif
     switch(pkey->type) {
     case EVP_PKEY_RSA:
	  memset((void *)&ORP, 0, sizeof(ORP));
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
	  ossl_rsa	= (RSA*)pkey->keydata; /* Pointer to OpenSSL RSA struc */
#else
	  ossl_rsa	= pkey->pkey.rsa; /* Pointer to OpenSSL RSA struc */
#endif
	  /* convert N */
	  ORP.lenN = BN_num_bytes(ossl_rsa->n);
	  ORP.pN = OSSL_MALLOC(ORP.lenN);
	  memset(ORP.pN, 0x0, ORP.lenN);
	  BN_bn2bin(ossl_rsa->n, ORP.pN);
	  /* convert E */
	  ORP.lenE = BN_num_bytes(ossl_rsa->e);
	  ORP.pE = OSSL_MALLOC(ORP.lenE);
	  memset(ORP.pE, 0x0, ORP.lenE);
	  BN_bn2bin(ossl_rsa->e, ORP.pE);
	  /* convert P */
	  if (ossl_rsa->p) {
	       ORP.lenP = BN_num_bytes(ossl_rsa->p);
	       ORP.pP = OSSL_MALLOC(ORP.lenP);
	       memset(ORP.pP, 0x0, ORP.lenP);
	       BN_bn2bin(ossl_rsa->p, ORP.pP);
	  }
	  /* convert Q */
	  if (ossl_rsa->q) {
	       ORP.lenQ = BN_num_bytes(ossl_rsa->q);
	       ORP.pQ = OSSL_MALLOC(ORP.lenQ);
	       memset(ORP.pQ, 0x0, ORP.lenQ);
	       BN_bn2bin(ossl_rsa->q, ORP.pQ);
	  }
	  rval = NSSL_CHK_CALL(rsaParamsToKeyBlob, &ORP, (void **) ppKeyBlob, len);
	  OSSL_RSAParamsFree(&ORP);
	  break;
     case EVP_PKEY_DSA:
	  memset((void *)&ODP, 0, sizeof(ODP));
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
	  ossl_dsa	= (DSA*)pkey->keydata; /* Pointer to OpenSSL DSA struc */
#else
	  ossl_dsa	= pkey->pkey.dsa; /* Pointer to OpenSSL DSA struc */
#endif
	  /* convert p */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
	  ODP.lenP = BN_num_bytes(ossl_dsa->params.p);
#else
	  ODP.lenP = BN_num_bytes(ossl_dsa->p);
#endif
	  ODP.pP = OSSL_MALLOC(ODP.lenP);
	  memset((void *)ODP.pP, 0x0, ODP.lenP);
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
	  BN_bn2bin(ossl_dsa->params.p, ODP.pP);
	  /* convert q */
	  ODP.lenQ = BN_num_bytes(ossl_dsa->params.q);
#else
	  BN_bn2bin(ossl_dsa->p, ODP.pP);
	  /* convert q */
	  ODP.lenQ = BN_num_bytes(ossl_dsa->q);
#endif
	  ODP.pQ = OSSL_MALLOC(ODP.lenQ);
	  memset((void *)ODP.pQ, 0x0, ODP.lenQ);
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
	  BN_bn2bin(ossl_dsa->params.q, ODP.pQ);
	  /* convert g */
	  ODP.lenG = BN_num_bytes(ossl_dsa->params.g);
#else
	  BN_bn2bin(ossl_dsa->q, ODP.pQ);
	  /* convert g */
	  ODP.lenG = BN_num_bytes(ossl_dsa->g);
#endif
	  ODP.pG = OSSL_MALLOC(ODP.lenG);
	  memset((void *)ODP.pG, 0x0, ODP.lenG);
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
	  BN_bn2bin(ossl_dsa->params.g, ODP.pG);
#else
	  BN_bn2bin(ossl_dsa->g, ODP.pG);
#endif
	  if (ossl_dsa->priv_key) {
	       /* convert priv_key */
	       ODP.lenX = BN_num_bytes(ossl_dsa->priv_key);
	       ODP.pX = OSSL_MALLOC(ODP.lenX);
	       memset((void *)ODP.pX, 0x0, ODP.lenX);
	       BN_bn2bin(ossl_dsa->priv_key, ODP.pX);
	       rval = NSSL_CHK_CALL(dsaParamsToKeyBlob, &ODP, (void **) ppKeyBlob, len);
	  } else {
	       /* convert pub_key */
	       ODP.lenY = BN_num_bytes(ossl_dsa->pub_key);
	       ODP.pY = OSSL_MALLOC(ODP.lenY);
	       memset((void *)ODP.pY, 0x0, ODP.lenY);
	       BN_bn2bin(ossl_dsa->pub_key, ODP.pY);
	       rval = NSSL_CHK_CALL(dsaParamsToKeyBlob, &ODP, (void **) ppKeyBlob, len);
	  }
	  OSSL_DSAParamsFree(&ODP);
	  break;
#if (defined (__ENABLE_DIGICERT_ECC__))
     case EVP_PKEY_EC:
	  memset((void *)&OEP, 0, sizeof(OEP));
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
	  ossl_eckey 	= (EC_KEY*)pkey->keydata;
#else
	  ossl_eckey 	= pkey->pkey.ec;
#endif
	  switch(ossl_eckey->group->curve_name) {
	  case NID_X9_62_prime192v1:
	       cname = ossl_prime192v1;
	       break;
	  case NID_secp224r1:
	       cname = ossl_secp224r1;
	       break;
	  case NID_X9_62_prime256v1:
	       cname = ossl_prime256v1;
	       break;
	  case NID_secp384r1:
	       cname = ossl_secp384r1;
	       break;
	  case NID_secp521r1:
	       cname = ossl_secp521r1;
	       break;
	  default:
	       return -1;
	  }
	  OEP.curve_name	= cname;
	  ctx 		= BN_CTX_new();
	  pubkey_bn 	= EC_POINT_point2bn(ossl_eckey->group, ossl_eckey->pub_key,
					    POINT_CONVERSION_UNCOMPRESSED, NULL, ctx);
	  OEP.lenPub	= BN_num_bytes(pubkey_bn);
	  OEP.pPub 	= OSSL_MALLOC(OEP.lenPub);
	  memset((void *)OEP.pPub, 0x0, OEP.lenPub);
	  BN_bn2bin(pubkey_bn, OEP.pPub);
	  BN_free(pubkey_bn);
	  BN_CTX_free(ctx);
	  if (ossl_eckey->priv_key) {
	       OEP.lenPriv 	= BN_num_bytes(ossl_eckey->priv_key);
	       OEP.pPriv 	= OSSL_MALLOC(OEP.lenPriv);
	       memset((void *)OEP.pPriv, 0x0, OEP.lenPriv);
	       BN_bn2bin(ossl_eckey->priv_key, OEP.pPriv);
	  }
	  rval = NSSL_CHK_CALL(eccParamsToKeyBlob, &OEP, (void **)ppKeyBlob, len);
	  OSSL_ECCParamsFree(&OEP);
	  break;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    case EVP_PKEY_ED25519:
        memset((void *)&OEP, 0, sizeof(OEP));
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        pOSSLECXKey = (ECX_KEY*)pkey->keydata;
#else
        pOSSLECXKey = pkey->pkey.ecx;
#endif
        OEP.curve_name = ossl_eddsa_25519;

        /* Copy the public key */
        if (1 != EVP_PKEY_get_raw_public_key(pkey, NULL, &edKeyLen))
            return -1;

        OEP.lenPub = edKeyLen;
        OEP.pPub = OSSL_CALLOC(OEP.lenPub, 1);

        if (1 != EVP_PKEY_get_raw_public_key(pkey, OEP.pPub, &edKeyLen))
            return -1;

        /* Copy the private key */
        if (pOSSLECXKey->privkey != NULL)
        {
            if (1 != EVP_PKEY_get_raw_private_key(pkey, NULL, &edKeyLen))
            return -1;

            OEP.lenPriv = edKeyLen;
            OEP.pPriv = OSSL_CALLOC(OEP.lenPriv, 1);

            if (1 != EVP_PKEY_get_raw_private_key(pkey, OEP.pPriv, &edKeyLen))
                return -1;
        }
	    rval = NSSL_CHK_CALL(eccParamsToKeyBlob, &OEP, (void **)ppKeyBlob, len);
	    OSSL_ECCParamsFree(&OEP);
        break;

    case EVP_PKEY_ED448:
        memset((void *)&OEP, 0, sizeof(OEP));
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        pOSSLECXKey = (ECX_KEY*)pkey->keydata;
#else
        pOSSLECXKey = pkey->pkey.ecx;
#endif
        OEP.curve_name = ossl_eddsa_448;
        /* Copy the public key */
        if (1 != EVP_PKEY_get_raw_public_key(pkey, NULL, &edKeyLen))
            return -1;

        OEP.lenPub = edKeyLen;
        OEP.pPub = OSSL_CALLOC(OEP.lenPub, 1);

        if (1 != EVP_PKEY_get_raw_public_key(pkey, OEP.pPub, &edKeyLen))
            return -1;

        /* Copy the private key */
        if (pOSSLECXKey->privkey != NULL)
        {
            if (1 != EVP_PKEY_get_raw_private_key(pkey, NULL, &edKeyLen))
            return -1;

            OEP.lenPriv = edKeyLen;
            OEP.pPriv = OSSL_CALLOC(OEP.lenPriv, 1);

            if (1 != EVP_PKEY_get_raw_private_key(pkey, OEP.pPriv, &edKeyLen))
                return -1;
        }
	    rval = NSSL_CHK_CALL(eccParamsToKeyBlob, &OEP, (void **)ppKeyBlob, len);
	    OSSL_ECCParamsFree(&OEP);
        break;
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#endif /* __ENABLE_DIGICERT_ECC__ */
     default:
	  break;
     }
     return rval;
}


extern int
ossl_CERT_STORE_addGenericIdentity(SSL_CTX *ctx, EVP_PKEY *pkey)
{
    unsigned char* pRetKeyBlob = NULL;
    unsigned int   retKeyLength = 0;
    int	rval = -1, certCount = 0 , i, sz;
    OSSL_SizedBuffer * pSBuf = NULL;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && defined(__ENABLE_DIGICERT_TAP__)
    AsymmetricKey asymKey;
    MOC_EVP_KEY_DATA *pkbi = NULL;
#else
    OSSL_KeyBlobInfo *pkbi = NULL;
#endif

    if (NULL == ctx->pCertStore)
    {
        if (OK > (rval = NSSL_CHK_CALL(createCertStore, &ctx->pCertStore)))
        {
           goto exit;
        }
    }

    certCount = 1 + ctx->cert_x509_list.count;
    sz = certCount*sizeof(OSSL_SizedBuffer);
    
    if (NULL == (pSBuf = OSSL_MALLOC(sz)))
        goto exit;

    memset(pSBuf, 0, sz);
    if (OK > (rval = osslX509ToSizedBuffer(ctx->cert_x509,
                                           &ctx->cert_x509_list,
                                           pSBuf, certCount)))
    {
        goto exit;
    }

    switch (pkey->type)
    {
        case EVP_PKEY_DSA:
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            pkbi = DSA_get_ex_data(pkey->keydata, dsaExAppDataIndex);
#else
            pkbi = DSA_get_ex_data(pkey->pkey.dsa, dsaExAppDataIndex);
#endif
            break;
        case EVP_PKEY_RSA:
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            pkbi = RSA_get_ex_data(pkey->keydata, moc_get_rsa_ex_app_data());
#else
            pkbi = RSA_get_ex_data(pkey->pkey.rsa, rsaExAppDataIndex);
#endif
            break;
#if (defined(__ENABLE_DIGICERT_ECC__))
        case EVP_PKEY_EC:
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            pkbi = EC_KEY_get_ex_data(pkey->keydata, moc_get_ecc_ex_app_data());
#elif defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
            pkbi = EC_KEY_get_ex_data(pkey->pkey.ec, eccExAppDataIndex);
#else
            pkbi = ECDSA_get_ex_data(pkey->pkey.ec, eccExAppDataIndex);
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
            break;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        /* No extended data for ED Keys */
        case EVP_PKEY_ED25519:
        case EVP_PKEY_ED448:
            break;
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#endif /* __ENABLE_DIGICERT_ECC__ */
        default:
            /* unsupported type */
            goto exit;

    } /* end switch */
    if (NULL != pkbi)
    {
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#if defined(__ENABLE_DIGICERT_TAP__)
        /* Attempt to deserialize the key data. This will attempt to deserialize
         * the data blob as a TAP key. If it is unsuccessful then attempt to
         * use the array of function pointers to deserialize the key as a
         * software key.
         */
        rval = NSSL_CHK_CALL(initAsymmetricKey, &asymKey);
        if (0 != rval)
        {
            goto exit;
        }

        if (NULL != pkbi->pCred)
        {
            DIGI_EVP_maskCred(pkbi->pCred, pkbi->credLen);
            rval = NSSL_CHK_CALL(deserializeAsymKeyWithCreds, pkbi->pContents, pkbi->contentsLen,
                                    pkbi->pCred, pkbi->credLen, &asymKey);
            /* done with credential, re-mask it*/
            DIGI_EVP_maskCred(pkbi->pCred, pkbi->credLen);
            if (0 != rval)
                goto exit;
        }
        else
        {
            rval = NSSL_CHK_CALL(deserializeAsymKey, pkbi->pContents, pkbi->contentsLen, &asymKey);
            if (0 != rval)
            {
                NSSL_CHK_CALL(uninitAsymmetricKey, &asymKey);
                goto exit;
            }
        }

        rval = NSSL_CHK_CALL(serializeAsymKeyAlloc, &asymKey,
            &(pRetKeyBlob), &(retKeyLength));
        if (NULL != pkbi->pCred)
        {
            /* Loaded asymKey using deserializeAsymKeyWithCreds,
             * unload TAP key before freeing */
            NSSL_CHK_CALL(tapUnloadKey, &asymKey);
        }
        NSSL_CHK_CALL(uninitAsymmetricKey, &asymKey);
        if (0 != rval)
            goto exit;
#else
        rval = -6017; /* ERR_NOT IMPLEMENTED */
        goto exit;
#endif /* __ENABLE_DIGICERT_TAP__ */
#else
        pRetKeyBlob = pkbi->pKeyBlob; pkbi->pKeyBlob = NULL;
        retKeyLength = pkbi->keyBlobLength;
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
    }

    if (pRetKeyBlob == NULL)
    {
        rval = ossl_PkeyToBlob(pkey, &pRetKeyBlob, &retKeyLength);
    }

    if(OK > rval)
        goto exit;

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && defined(__ENABLE_DIGICERT_TAP__)
    if ((NULL != pkbi) && (NULL != pkbi->pCred))
    {
        DIGI_EVP_maskCred(pkbi->pCred, pkbi->credLen); /* unmask */
        rval = ossl_setCredentials(0, 0, (sbyte *) pkbi->pCred, pkbi->credLen);
        DIGI_EVP_maskCred(pkbi->pCred, pkbi->credLen); /* done with credentials, re-mask */
        if (OK > rval)
            goto exit;

        rval = NSSL_CHK_CALL(addIdenCertChainExtData, ctx->pCertStore,
                         pSBuf, certCount,
                         pRetKeyBlob, retKeyLength,
                         ctx->pKeyAlias, ctx->keyAliasLength,
                         ossl_getCredentials, 0);
    }
    else
#endif
    {
        rval = NSSL_CHK_CALL(addIdenCertChain, ctx->pCertStore,
                         pSBuf, certCount,
                         pRetKeyBlob, retKeyLength,
                         ctx->pKeyAlias, ctx->keyAliasLength);
    }
exit:
    if (pSBuf)
    {
        for (i=0; i < certCount; ++i)
        {
           OSSL_SB_Free(&pSBuf[i]);
        }
        OSSL_FREE(pSBuf);
    }

    if (NULL != pRetKeyBlob)
    {
        NSSL_CHK_CALL(mocFree, (void **) &pRetKeyBlob);
    }

    /* allocated when tap keys were serialized as above */
    if (pkbi)
    {
        switch (pkey->type)
        {
            case EVP_PKEY_DSA:
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                DSA_set_ex_data(pkey->keydata, dsaExAppDataIndex, NULL);
#else
                DSA_set_ex_data(pkey->pkey.dsa, dsaExAppDataIndex, NULL);
#endif
                break;
            case EVP_PKEY_RSA:
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                RSA_set_ex_data(pkey->keydata, moc_get_rsa_ex_app_data(), NULL);
#else
                RSA_set_ex_data(pkey->pkey.rsa, rsaExAppDataIndex, NULL);
#endif
                break;
            case EVP_PKEY_EC:
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                EC_KEY_set_ex_data(pkey->keydata, moc_get_ecc_ex_app_data(), NULL);
#elif defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
                EC_KEY_set_ex_data(pkey->pkey.ec, eccExAppDataIndex, NULL);
#else
                ECDSA_set_ex_data(pkey->pkey.ec, eccExAppDataIndex, NULL);
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
                break;
            default:
                break;
        }
        /* the blob itself is freed above, now just free the container */
        DIGI_PKEY_EX_DATA_free(NULL, pkbi, NULL, 0, 0, NULL);
    }

    return rval;
}

static int
osslX509CertToSizedBuffer(X509 *x, SizedBuffer *pSBuf)
{
    int		derLen;
    unsigned char    *to;

    derLen 	= i2d_X509(x, NULL);
    if (0 > derLen)
    {
        return -1;
    }

    if (OK != NSSL_CHK_CALL(mocMalloc, (void **) &(pSBuf->data), derLen))
    {
        return -1;
    }

    pSBuf->length = (ubyte4) derLen;

    to		= pSBuf[0].data;
    derLen 	= i2d_X509(x, &to);
    return 0;
}


extern int
osslGetCertAndKey(X509 *pCert, EVP_PKEY *pKey, X509 *pCACert,
                  SizedBuffer **ppRetCert, ubyte4 *pRetNumCerts,
                  ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLen,
                  ubyte **ppRetCACert, ubyte4 *pRetCACertLen)
{
    int retValue = 0;

    if (pCert != NULL)
    {
        *pRetNumCerts = 1;/* We have only 1 certificate */

        if (OK > (retValue = osslX509CertToSizedBuffer(pCert, *ppRetCert)))
        {
            retValue = -1;
            goto exit;
        }
    }

    if (pKey != NULL)
    {
        *ppRetKeyBlob = NULL;
        if (OK > (retValue = ossl_PkeyToBlob(pKey, ppRetKeyBlob, pRetKeyBlobLen)))
        {
            retValue = -1;
            goto exit;
        }
    }

    if (pCACert != NULL)
    {
        *pRetCACertLen = i2d_X509(pCACert, ppRetCACert);
    }

exit:
    return retValue;
}
