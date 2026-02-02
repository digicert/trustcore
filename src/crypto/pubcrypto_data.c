/*
 * pubcrypto_data.c
 *
 * General Public Crypto Operations
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

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#include "../common/random.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/ecc.h"
#include "../crypto/ca_mgmt.h"
#endif
#include "../crypto/crypto.h"
#include "../asn1/oiddefs.h"

#include "../crypto/pubcrypto_data.h"

#ifdef __ENABLE_DIGICERT_PQC__
#include "../crypto_interface/crypto_interface_qs_composite.h"
#endif

extern MSTATUS CRYPTO_getHashAlgoOID( ubyte rsaAlgoId,
                                     const ubyte** pHashAlgoOID)
{
    MSTATUS status = OK;

    switch (rsaAlgoId)
    {
        case md5withRSAEncryption:
            *pHashAlgoOID = md5_OID;
            break;

        case sha1withRSAEncryption:
            *pHashAlgoOID = sha1_OID;
            break;

        case sha256withRSAEncryption:
            *pHashAlgoOID = sha256_OID;
            break;

        case sha384withRSAEncryption:
            *pHashAlgoOID = sha384_OID;
            break;

        case sha512withRSAEncryption:
            *pHashAlgoOID = sha512_OID;
            break;

        case sha224withRSAEncryption:
            *pHashAlgoOID = sha224_OID;
            break;

#ifdef __ENABLE_DIGICERT_SHA3__
        case ht_sha3_224:
            *pHashAlgoOID = sha3_224_OID;
            break;

        case ht_sha3_256:
            *pHashAlgoOID = sha3_256_OID;
            break;

        case ht_sha3_384:
            *pHashAlgoOID = sha3_384_OID;
            break;

        case ht_sha3_512:
            *pHashAlgoOID = sha3_512_OID;
            break;

        case ht_shake128:
            *pHashAlgoOID = shake128_OID;
            break;

        case ht_shake256:
            *pHashAlgoOID = shake256_OID;
            break;
#endif

        default:
            status = ERR_INVALID_ARG;
            break;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
CRYPTO_getRSAHashAlgoOID( ubyte rsaAlgoId, ubyte rsaAlgoOID[/* 1 + MAX_SIG_OID_LEN */])
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if (NULL == rsaAlgoOID)
    goto exit;

  /* Special case.
   */
  if (sha1_with_no_sig == rsaAlgoId)
  {
    status = DIGI_MEMCPY (
      rsaAlgoOID, noSignature_OID, (ubyte4)(noSignature_OID[0]) + 1);
    goto exit;
  }

  status = ERR_INVALID_ARG;
  switch(rsaAlgoId)
  {
      case md5withRSAEncryption:
      case sha1withRSAEncryption:
      case sha224withRSAEncryption:
      case sha256withRSAEncryption:
      case sha384withRSAEncryption:
      case sha512withRSAEncryption:
        break;

      default:
        goto exit;
  }

  /* build the PKCS1 OID */
  status = DIGI_MEMCPY (rsaAlgoOID, pkcs1_OID, 1 + PKCS1_OID_LEN);
  if (OK != status)
    goto exit;

  /* add the suffix */
  ++rsaAlgoOID[0];
  rsaAlgoOID[1+PKCS1_OID_LEN] = rsaAlgoId;

exit:

  return (status);
}


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DSA__))
extern MSTATUS
CRYPTO_getDSAHashAlgoOID( ubyte dsaAlgoId, ubyte dsaAlgoOID[/* 1 + MAX_SIG_OID_LEN */])
{
    MSTATUS status = OK;
    ubyte subType = 0;
    if (!dsaAlgoOID)
        return ERR_NULL_POINTER;

    switch (dsaAlgoId)
    {
    case ht_sha1:
        DIGI_MEMCPY( dsaAlgoOID, dsaWithSHA1_OID, 1 + dsaWithSHA1_OID[0]);
        goto exit;

    case ht_sha224:
        subType = 1;
        break;

    case ht_sha256:
        subType = 2;
        break;

    case ht_sha384:
        subType = 3;
        break;

    case ht_sha512:
        subType = 4;
        break;

    default:
        status = ERR_CERT_UNSUPPORTED_SIGNATURE_ALGO;
        goto exit;
    }

    DIGI_MEMCPY(dsaAlgoOID, dsaWithSHA2_OID, 1 + dsaWithSHA2_OID[0]);
    ++dsaAlgoOID[0];
    dsaAlgoOID[ dsaAlgoOID[0]] = subType;

exit:

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ECC__))
extern MSTATUS
CRYPTO_getECDSAHashAlgoOID( ubyte rsaAlgoId, ubyte ecdsaAlgoOID[/* 1 + MAX_SIG_OID_LEN */])
{
    MSTATUS status = OK;
    ubyte subType = 0;
    if (!ecdsaAlgoOID)
        return ERR_NULL_POINTER;

    switch (rsaAlgoId)
    {
    case ht_sha1:
        DIGI_MEMCPY( ecdsaAlgoOID, ecdsaWithSHA1_OID, 1 + ecdsaWithSHA1_OID[0]);
        goto exit;

    case ht_sha224:
        subType = 1;
        break;

    case ht_sha256:
        subType = 2;
        break;

    case ht_sha384:
        subType = 3;
        break;

    case ht_sha512:
        subType = 4;
        break;

    default:
        status = ERR_CERT_UNSUPPORTED_SIGNATURE_ALGO;
        goto exit;
    }

    DIGI_MEMCPY(ecdsaAlgoOID, ecdsaWithSHA2_OID, 1 + ecdsaWithSHA2_OID[0]);
    ++ecdsaAlgoOID[0];
    ecdsaAlgoOID[ ecdsaAlgoOID[0]] = subType;

exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
extern MSTATUS CRYPTO_getEDDSAAlgoOID(ECCKey *pECCKey, ubyte eddsaAlgoOID[/* 1 + MAX_SIG_OID_LEN */])
{
    MSTATUS status;
    ubyte4 eccCurveId;

    status = EC_getCurveIdFromKey(pECCKey, &eccCurveId);
    if (OK != status)
        goto exit;

    if (cid_EC_Ed25519 == eccCurveId)
    {
        DIGI_MEMCPY(eddsaAlgoOID, ed25519sig_OID, 1 + ed25519sig_OID[0]);
    }
    else if (cid_EC_Ed448 == eccCurveId)
    {
        DIGI_MEMCPY(eddsaAlgoOID, ed448sig_OID, 1 + ed448sig_OID[0]);
    }
    else
    {
        status = ERR_EC_UNSUPPORTED_CURVE;
    }

exit:

    return status;
}
#endif

MSTATUS CRYPTO_getECCurveOID( const ECCKey* pECCKey, const ubyte** pCurveOID)
{
    MSTATUS status;
    ubyte4 eccCurveId;

    status = EC_getCurveIdFromKey((ECCKey *) pECCKey, &eccCurveId);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_ECC_P192__
    if ( cid_EC_P192 == eccCurveId)
    {
        *pCurveOID = secp192r1_OID;
    }
    else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
    if ( cid_EC_P224 == eccCurveId)
    {
        *pCurveOID = secp224r1_OID;
    }
    else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
    if ( cid_EC_P256 == eccCurveId)
    {
        *pCurveOID = secp256r1_OID;
    }
    else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
    if ( cid_EC_P384 == eccCurveId)
    {
        *pCurveOID = secp384r1_OID;
    }
    else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
    if ( cid_EC_P521 == eccCurveId)
    {
        *pCurveOID = secp521r1_OID;
    }
    else
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
    if ( cid_EC_Ed25519 == eccCurveId)
    {
        *pCurveOID = ed25519sig_OID;
    }
    else
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
    if ( cid_EC_Ed448 == eccCurveId)
    {
        *pCurveOID = ed448sig_OID;
    }
    else
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
    if ( cid_EC_X25519 == eccCurveId)
    {
        *pCurveOID = ecdh25519_OID;
    }
    else
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
    if ( cid_EC_X448 == eccCurveId)
    {
        *pCurveOID = ecdh448_OID;
    }
    else
#endif
    {
        *pCurveOID = 0;
        return ERR_EC_UNSUPPORTED_CURVE;
    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_ECC__ */

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__

/* gets the last byte of the domain string */
static sbyte4 CRYPTO_getCompositeOidByte(ubyte4 clAlg, ubyte4 qsAlg)
{
    sbyte4 retVal = -1;

    switch(qsAlg)
    {
        case cid_PQC_MLDSA_44:
           
            switch(clAlg)
            {
                case cid_RSA_2048_PSS:
                    retVal = 60;
                    break;
                case cid_RSA_2048_PKCS15:
                    retVal = 61;
                    break;
                case cid_EC_Ed25519:
                    retVal = 62;
                    break;
                case cid_EC_P256:
                    retVal = 63;
                    break;                 
                default:
                    goto exit;
            }
            break;

        case cid_PQC_MLDSA_65:

            switch(clAlg)
            {
                case cid_RSA_3072_PSS:
                    retVal = 64;
                    break;
                case cid_RSA_3072_PKCS15:
                    retVal = 65;
                    break;
                case cid_RSA_4096_PSS:
                    retVal = 66;
                    break;
                case cid_RSA_4096_PKCS15:
                    retVal = 67;
                    break;
                case cid_EC_P256:
                    retVal = 68;
                    break;
                case cid_EC_P384:
                    retVal = 69;
                    break;
                case cid_EC_Ed25519:
                    retVal = 71;
                    break;                  
                default:
                    goto exit;
            }
            break;

        case cid_PQC_MLDSA_87:

            switch(clAlg)
            {
                case cid_EC_P384:
                    retVal = 72;
                    break;
                case cid_EC_Ed448:
                    retVal = 74;
                    break;
                case cid_RSA_4096_PSS:
                    retVal = 75;
                    break;               
                default:
                    goto exit;
            }
            break;
        
        default:
            goto exit;
    }

exit:

    return retVal;
} 

/*---------------------------------------------------------------------------*/

/* Inverse of the above method, gets the algs from the last oid byte */
MOC_EXTERN MSTATUS CRYPTO_getCompositeAlgs(ubyte oidByte, ubyte4 *pClAlg, ubyte4 *pQsAlg)
{
    ubyte4 clAlg;
    ubyte4 qsAlg;

    /* last byte as per Section 7.1 of draft */
    switch (oidByte)
    {
        case 60:
            clAlg = cid_RSA_2048_PSS;
            qsAlg = cid_PQC_MLDSA_44;
            break;

        case 61:
            clAlg = cid_RSA_2048_PKCS15;
            qsAlg = cid_PQC_MLDSA_44;
            break;

        case 62:
            clAlg = cid_EC_Ed25519;
            qsAlg = cid_PQC_MLDSA_44;
            break;

        case 63:
            clAlg = cid_EC_P256;
            qsAlg = cid_PQC_MLDSA_44;
            break;

        case 64:
            clAlg = cid_RSA_3072_PSS;
            qsAlg = cid_PQC_MLDSA_65;
            break;

        case 65:
            clAlg = cid_RSA_3072_PKCS15;
            qsAlg = cid_PQC_MLDSA_65;
            break;
        
        case 66:
            clAlg = cid_RSA_4096_PSS;
            qsAlg = cid_PQC_MLDSA_65;
            break;

        case 67:
            clAlg = cid_RSA_4096_PKCS15;
            qsAlg = cid_PQC_MLDSA_65;
            break;

        case 68:
            clAlg = cid_EC_P256;
            qsAlg = cid_PQC_MLDSA_65;
            break;

        case 69:
            clAlg = cid_EC_P384;
            qsAlg = cid_PQC_MLDSA_65;
            break;

        /* case 70: brainpool, not supported */
        case 71:
            clAlg = cid_EC_Ed25519;
            qsAlg = cid_PQC_MLDSA_65;
            break;

        case 72:
            clAlg = cid_EC_P384;
            qsAlg = cid_PQC_MLDSA_87;
            break;

        /* case 73: brainpool, not supported */
        case 74:
            clAlg = cid_EC_Ed448;
            qsAlg = cid_PQC_MLDSA_87;
            break;

        case 75:
            clAlg = cid_RSA_4096_PSS;
            qsAlg = cid_PQC_MLDSA_87;
            break;

        default:
            return ERR_INVALID_ARG;
    }

    if (NULL != pClAlg)
        *pClAlg = clAlg;

    if (NULL != pQsAlg)
        *pQsAlg = qsAlg;

    return OK;
}

/*---------------------------------------------------------------------------*/

/* works for hybrid or pure qs. Enter clAlgId = 0 for pure qs. ppOid gets set to buffer with NO oidLen byte */
extern MSTATUS CRYPTO_getAlgoOIDAlloc(ubyte4 clAlgId, ubyte4 qsAlgId, ubyte **ppOid, ubyte4 *pOidLen)
{
    MSTATUS status = OK;
    ubyte *pOid = NULL;
    ubyte oid[MAX_PQC_OID_LEN];

    if (NULL == ppOid || NULL == pOidLen)
        return ERR_NULL_POINTER;

    if (0 != clAlgId)
    {
        /* first copy the oid with the initial length byte */
        status = CRYPTO_getHybridAlgoOID(clAlgId, qsAlgId, oid); 
    }
    else
    {
        status = CRYPTO_getQsAlgoOID(qsAlgId, oid);
    }
    if (OK != status)
        goto exit;  

    /* copy starting after the length byte */
    status = DIGI_MALLOC_MEMCPY((void **) &pOid, oid[0], oid + 1, oid[0]);
    if (OK != status)
        goto exit;

    *ppOid = pOid; pOid = NULL;
    *pOidLen = (ubyte4) oid[0];

exit:
    
    if (NULL != pOid)
    {
        (void) DIGI_FREE((void **) &pOid); /* no need to zero, the copy is last thing that can fail */
    }

    (void) DIGI_MEMSET(oid, 0x00, MAX_PQC_OID_LEN);
    
    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_getQsAlgoOID(ubyte4 qsAlgId, ubyte oid[/* MAX_PQC_OID_LEN */])
{
    if (qsAlgId >= cid_PQC_MLDSA_44 && qsAlgId <= cid_PQC_SLHDSA_SHAKE_256F)
    {
        ubyte oidLen = pure_pqc_sig_OID[0] + 1; /* get the array length and add one for the last byte */
        oid[0] = oidLen; /* set new total length */
        (void) DIGI_MEMCPY(oid + 1, pure_pqc_sig_OID + 1, (ubyte4) oidLen - 1);
        oid[oidLen] = (ubyte) qsAlgId;  /* oid is oidLen + 1 in length. qsAlgId is the correct byte */
    }
    else if (cid_PQC_FNDSA_512 == qsAlgId)
    {
        (void) DIGI_MEMCPY(oid, fndsa_512_OID, fndsa_512_OID[0] + 1);        
    }
    else if (cid_PQC_FNDSA_1024 == qsAlgId)
    {
        (void) DIGI_MEMCPY(oid, fndsa_1024_OID, fndsa_1024_OID[0] + 1);        
    }
    else
    {
        return ERR_INVALID_INPUT;
    }

    return OK;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_getHybridAlgoOID(ubyte4 clAlgId, ubyte4 qsAlgId, ubyte oid[/* MAX_PQC_OID_LEN */])
{
    ubyte oidLen = 0;

    /* following call will return -1 if an invalid alg combination */
    sbyte4 byte = CRYPTO_getCompositeOidByte(clAlgId, qsAlgId);
    if (byte < 0)
    {
        return ERR_INVALID_INPUT;
    }
    
    oidLen = mldsa_composite_OID[0] + 1; /* get the array length and add one for the last byte */
    oid[0] = oidLen; /* set new total length */
    (void) DIGI_MEMCPY(oid + 1, mldsa_composite_OID + 1, (ubyte4) oidLen - 1);
    oid[oidLen] = (ubyte) byte; /* oid is oidLen + 1 in length */
 
    return OK;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_getQsAlgoFromOID(ubyte *pOid, ubyte4 oidLen, ubyte4 *pQsAlgIdEx)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 compare = -1;
    ubyte4 qsAlg = 0;

    if (NULL == pOid)
        goto exit;

    if (NULL != pQsAlgIdEx)
        *pQsAlgIdEx = 0;

    status = ERR_CERT_UNRECOGNIZED_OID;

    /* mldsa or slhdsa have same length */
    if (oidLen == ((ubyte4) pure_pqc_sig_OID[0] + 1))
    {
        /* compare all but the last byte */
        (void) DIGI_MEMCMP(pOid, pure_pqc_sig_OID + 1 /* skip length byte */, oidLen - 1, &compare);    
        if (compare)
        {
            goto exit; /* status still ERR_CERT_UNRECOGNIZED_OID */
        }
        
        /* make sure last byte is in proper range for a PQC alg */
        if (pOid[oidLen - 1] >= cid_PQC_MLDSA_44 && pOid[oidLen - 1] <= cid_PQC_SLHDSA_SHAKE_256F)
        {
            qsAlg = (ubyte4) pOid[oidLen - 1];
        }
        else
        {
            goto exit; /* status still ERR_CERT_UNRECOGNIZED_OID */
        }
    }
    else if (oidLen == fndsa_512_OID[0])
    {
        /* compare all but the last byte */
        (void) DIGI_MEMCMP(pOid, fndsa_512_OID + 1 /* skip length byte */, oidLen - 1, &compare);    
        if (compare)
        {
            goto exit; /* status still ERR_CERT_UNRECOGNIZED_OID */
        }

        if (pOid[oidLen - 1] == fndsa_512_OID[oidLen])
        {
            qsAlg = cid_PQC_FNDSA_512;
        }
        else if (pOid[oidLen - 1] == fndsa_1024_OID[oidLen])
        {
            qsAlg = cid_PQC_FNDSA_1024;
        }
        else
        {
            goto exit; /* status still ERR_CERT_UNRECOGNIZED_OID */
        }
    }
    else
    {
        goto exit; /* status still ERR_CERT_UNRECOGNIZED_OID */
    }

    status = OK;

    if (NULL != pQsAlgIdEx)
        *pQsAlgIdEx = qsAlg;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_getHybridCurveAlgoFromOID(ubyte *pOid, ubyte4 oidLen, ubyte4 *pClAlgId, ubyte4 *pQsAlgId)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 expOidLen = 0;
    sbyte4 compare = -1;

    if (NULL == pOid) /* other input pointers validated in below call to CRYPTO_INTERFACE_QS_getAlgs */
        goto exit;

    /* All OID's should begin the same as mldsa_composite_OID minus the last byte. */
    expOidLen = mldsa_composite_OID[0] + 1; /* get the length byte, add one for the last byte */

    status = ERR_CERT_UNRECOGNIZED_OID;
    if (oidLen != expOidLen)
        goto exit;

    (void) DIGI_MEMCMP(pOid, mldsa_composite_OID + 1 /* skip length byte */, oidLen - 1, &compare);

    if (compare)
    {
        goto exit; /* status still ERR_CERT_UNRECOGNIZED_OID */
    }

    status = CRYPTO_getCompositeAlgs(pOid[oidLen - 1], pClAlgId, pQsAlgId);
    
exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_PQC__ */
