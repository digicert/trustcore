/*
 * key_utils.c
 *
 * KEY_UTILS Initialization
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

#ifdef __ENABLE_DIGICERT_KEY_UTILS__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mocana.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../crypto/hw_accel.h"

#include "../crypto/key_utils.h"
#include "../crypto/pem_key.h"

#include "../common/random.h"
#include "../common/vlong.h"


#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../asn1/parseasn1.h"
#include "../asn1/ASN1TreeWalker.h"
#ifdef __ENABLE_DIGICERT_DSA__
#include "../crypto/dsa.h"
#endif

#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif

#include "../crypto/crypto.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../common/base64.h"
#include "../crypto/rsa.h"


static MSTATUS
KEY_UTILS_getDSAKey(MOC_DSA(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 pDataLength, AsymmetricKey *pKey)
{
   MSTATUS         status;
   CStream         cs;
   MemFile         mf;
   DSAKey*         pDsaKey;
   sbyte4          i = 0;
   ASN1_ITEMPTR    pRoot = NULL;
   ASN1_ITEMPTR    pSequence = NULL;
   ASN1_ITEMPTR    pDummy = NULL;
   ASN1_ITEMPTR    pKeyComponent;
   MDsaKeyTemplate keyData = {0};

   static WalkerStep DsaDerWalkInstructions[] =
   {
      { GoFirstChild, 0, 0},
      { VerifyType, SEQUENCE, 0},
      { GoFirstChild, 0, 0},          /* version */
      { VerifyInteger, 0, 0},         /* verify version is 0 */
      { GoNextSibling, 0, 0 },        /* p */
      { GoNextSibling, 0, 0 },        /* q */
      { GoNextSibling, 0, 0 },        /* g */
      { GoNextSibling, 0, 0 },        /* public key: y */
      /* { GoNextSibling, 0, 0 }, */  /* private key: x */
      { Complete, 0, 0}
   };


   /* parse DER file */
   MF_attach( &mf, pDataLength, (ubyte*) pData);
   CS_AttachMemFile( &cs, &mf);

   if ( OK > (status = ASN1_Parse(cs, &pRoot)))
        goto exit;

   status = ERR_ASN_INVALID_DATA;

   /* verify DSA DER infomation */
   if ( OK >  ASN1_WalkTree( pRoot, cs, DsaDerWalkInstructions, &pDummy))
      goto exit;

   if (NULL == pDummy)
      goto exit;

   if (OK > CRYPTO_createDSAKey (pKey, NULL))
      goto exit;

   pDsaKey = pKey->key.pDSA;

   pSequence = ASN1_FIRST_CHILD( pRoot);

   /* skip version */
   pKeyComponent = ASN1_FIRST_CHILD( pSequence);

   while ( (i < NUM_DSA_VLONG) && (NULL != (pKeyComponent = ASN1_NEXT_SIBLING( pKeyComponent))) )
   {
      switch(i)
      {
         case 0:
            keyData.pP = (ubyte *) pData + pKeyComponent->dataOffset;
            keyData.pLen = pKeyComponent->length;
            break;

         case 1:
            keyData.pQ = (ubyte *) pData + pKeyComponent->dataOffset;
            keyData.qLen = pKeyComponent->length;
            break;

         case 2:
            keyData.pG = (ubyte *) pData + pKeyComponent->dataOffset;
            keyData.gLen = pKeyComponent->length;
            break;

         case 3:
            keyData.pY = (ubyte *) pData + pKeyComponent->dataOffset;
            keyData.yLen = pKeyComponent->length;
            break;

         case 4:
            keyData.pX = (ubyte *) pData + pKeyComponent->dataOffset;
            keyData.xLen = pKeyComponent->length;
            break;
      }
      i++;
   }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
   status = CRYPTO_INTERFACE_DSA_setKeyParametersAux(MOC_DSA(hwAccelCtx) pDsaKey, &keyData);
#else
   status = DSA_setKeyParametersAux(MOC_DSA(hwAccelCtx) pDsaKey, &keyData);
#endif
   if (OK != status)
      goto exit;

exit:

   if ( pRoot)
   {
      TREE_DeleteTreeItem((TreeItem*) pRoot);
   }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
   CRYPTO_INTERFACE_DSA_freeKeyTemplate(pDsaKey, &keyData);
#else
   DSA_freeKeyTemplate(pDsaKey, &keyData);
#endif

   return status;
}
static MSTATUS
KEY_UTILS_convertDsaKeyDER(MOC_DSA(hwAccelDescr hwAccelCtx) ubyte *pDerDsaKey, ubyte4 derDsaKeyLength,
                         ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength )
{
   AsymmetricKey   key = {0};
   MSTATUS         status;

   /* check input */
   if ((NULL == pDerDsaKey) || (NULL == ppRetKeyBlob) || (NULL == pRetKeyBlobLength))
   {
      status = ERR_NULL_POINTER;
      goto exit;
   }

   if (OK > (status = CRYPTO_initAsymmetricKey(&key)))
      return status;

   status = KEY_UTILS_getDSAKey(MOC_DSA(hwAccelCtx) pDerDsaKey, derDsaKeyLength, &key);

   if (OK > status)
      goto exit;

   status = CA_MGMT_makeKeyBlobEx(&key, ppRetKeyBlob, pRetKeyBlobLength);

exit:
   CRYPTO_uninitAsymmetricKey(&key, NULL);

   return (sbyte4)status;

}

extern MSTATUS
KEY_UTILS_convertDsaKeyPEM(MOC_DSA(hwAccelDescr hwAccelCtx) ubyte *pPemRsaKey, ubyte4 pemRsaKeyLength,
                         ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength )
{
   ubyte*      pDerRsaKey = 0;
   ubyte4      derRsaKeyLength;
   MSTATUS     status;

   /* check input */
   if ((NULL == pPemRsaKey) || (NULL == ppRetKeyBlob) || (NULL == pRetKeyBlobLength))
   {
      status = ERR_NULL_POINTER;
      goto exit;
   }

   /* decode the base64 encoded message */
   if (OK > (status = CA_MGMT_decodeCertificate(pPemRsaKey, pemRsaKeyLength, &pDerRsaKey, &derRsaKeyLength)))
      goto exit;

   status = KEY_UTILS_convertDsaKeyDER(MOC_DSA(hwAccelCtx) pDerRsaKey, derRsaKeyLength, ppRetKeyBlob, pRetKeyBlobLength);

exit:
   if (NULL != pDerRsaKey)
      FREE(pDerRsaKey);

   return (sbyte4)status;
}

MOC_EXTERN void
KEY_UTILS_PEMKeyIsEncrypted(ubyte *pPrivKey, ubyte4 privKeyLength, ubyte4 *retVal)
{
   ubyte4 i = 0;

   *retVal = FALSE;

   while( (i + 9) < privKeyLength && 90 > i) /*while the index of where "i" is, plus the length of "ENCRYPTED" is less than total length*/
   {                                         /*Also stops checking after a certain about of characters*/

      /*Following statement just checks for the word 'ENCRYPTED' throughout the whole file. If desired, cutoff can be made by*/
      /*checking the value of "i" in the above*/
      if( 'E' == pPrivKey[i] && 'N' == pPrivKey[i+1] && 'C' == pPrivKey[i+2] && 'R' == pPrivKey[i+3] &&
         'Y' == pPrivKey[i+4] && 'P' == pPrivKey[i+5] && 'T' == pPrivKey[i+6] && 'E' == pPrivKey[i+7] && 'D' == pPrivKey[i+8] )
      {
         *retVal = TRUE;
         break;
      }

      i++;
   }

}


MOC_EXTERN MSTATUS
KEY_UTILS_CreateKeyBlobFromPEM(MOC_DSA(hwAccelDescr hwAccelCtx) ubyte *passphrase,
                               ubyte *pPrivKey, ubyte4 privKeyLength,
                               ubyte **pRetKeyBlob, ubyte4 *pRetKeyBlobLength,
                               ubyte4 *retVal)
{
   MSTATUS status = OK;
   ubyte* convertedKey = NULL;
   ubyte4 convertedKeyLen = 0;
   ubyte4 passwordLen = 0;
   ubyte4 pass_exists = 0;
   ubyte4 encrypted;
   ubyte4 i;
   ubyte keyType = 0; /*1 for RSA, 2 for DSA*/

   if( NULL != passphrase )
      passwordLen = DIGI_STRLEN((sbyte*) passphrase);

   *retVal = FALSE;

   KEY_UTILS_PEMKeyIsEncrypted(pPrivKey, privKeyLength, &encrypted); /*Checks to see if key is encrypted */

   if( NULL != passphrase && encrypted)  /*If it is encrypted and password exists, then attempt decoding */
   {
      if( OK > (status = PEM_getPrivateKey(pPrivKey, privKeyLength, passphrase, passwordLen, &convertedKey, &convertedKeyLen)) ) /*Returns a der format*/
         goto exit;
      pass_exists = 10;
   }
   else if ( NULL == passphrase && encrypted ) /*If key is encrypted but no password exists, throw error and leave the function */
   {
      status = ERR_BAD_KEY;
      goto exit;
   }

   /*The options that remain is the key not being encrypted, in which case, password does not matter*/

   for( i = 0; (36 < privKeyLength) && (i + 3) < 36 && (0 == keyType); i++) /*36 is the amount of characters for the first line*/
   {
      if( 'R' == pPrivKey[i] && 'S' == pPrivKey[i+1] && 'A' == pPrivKey[i+2] ) /*Checking to see if RSA can be found in header*/
      {
          keyType = 1;
      }
      if( 'D' == pPrivKey[i] && 'S' == pPrivKey[i+1] && 'A' == pPrivKey[i+2] ) /*Checking to see if DSA can be found in header*/
      {
         keyType = 2;
      }
   }

   switch(keyType + pass_exists)
   {
      case 1: /*if no password exists but key is RSA*/
      {
         if( OK > (status = CA_MGMT_convertKeyPEM(pPrivKey, privKeyLength, pRetKeyBlob, pRetKeyBlobLength)) )
            goto exit;

         *retVal = TRUE;
         break;
      }

      case 2:  /*if no password exists but key is DSA*/
      {
         if(OK > (status = KEY_UTILS_convertDsaKeyPEM(MOC_DSA(hwAccelCtx) pPrivKey, privKeyLength, pRetKeyBlob, pRetKeyBlobLength)) )
            goto exit;

         *retVal = TRUE;
         break;
      }

      case 11:  /*Case of RSA and password exists*/
      {
         if( OK > (status = CA_MGMT_convertKeyDER(convertedKey, convertedKeyLen, pRetKeyBlob, pRetKeyBlobLength)) )
            goto exit;

         *retVal = TRUE;
         break;
      }

      case 12:   /*Case of DSA and password exists*/
      {
         if ( OK > (status = KEY_UTILS_convertDsaKeyDER(MOC_DSA(hwAccelCtx) convertedKey, convertedKeyLen, pRetKeyBlob, pRetKeyBlobLength)) )
            goto exit;

         *retVal = TRUE;
         break;
      }

   default:
      status = ERR_BAD_KEY;  /*If none of the cases match, then there has to be a problem with key */
      break;
   }

exit:
   if( NULL != convertedKey )
      DIGICERT_freeReadFile(&convertedKey);

   return status;
}


MOC_EXTERN MSTATUS KEY_UTILS_PEMKeyIsValid(MOC_ASYM(hwAccelDescr hwAccelCtx) ubyte *passphrase, ubyte *pPrivKey, ubyte4 privKeyLength, ubyte4 *retVal)
{
    MSTATUS status = OK;
    ubyte4 isEncrypted;
    ubyte* keyBlob = NULL;
    ubyte4 keyBlobLen;
    ubyte4 success;
    AsymmetricKey key;
    ubyte4 numBits;
    ubyte4 type = 0; /*1 for RSA, 2 for DSA, 0 otherwise */
    ubyte4 i, j, temp = 0;

    *retVal = 0;

    if (OK > (status = CRYPTO_initAsymmetricKey(&key)))
        goto exit;

    /************************************************************************/
    /*****Following block of code checks for formatting *********************/
    /************************************************************************/

    for( i = 0; i < privKeyLength && i < 5; i++)
    {
        if( '-' != pPrivKey[i] ) /*Checks for five dashes in beginning*/
            goto exit;
    }

    if( (i+5) < privKeyLength && 'B' != pPrivKey[i] && 'E' != pPrivKey[i+1] && 'G' != pPrivKey[i+2] && 'I' != pPrivKey[i+3] && 'N' != pPrivKey[i+4] )
        goto exit;

    for( i = privKeyLength - 30; (i+3) < privKeyLength && (0 == temp); i++)
    {
        if( 'E' == pPrivKey[i] && 'N' == pPrivKey[i+1] && 'D' == pPrivKey[i+2] ) /*Tries to find the word END*/
            temp = 1;  /*If found, we can continue with the checking*/
    }

    if( 1 != temp )
        goto exit;

    temp = 0;

    for( ; (i+3) < privKeyLength && (0 == temp); i++)
    {
        if( 'K' == pPrivKey[i] && 'E' == pPrivKey[i+1] && 'Y' == pPrivKey[i+2] ) /*Tries to find the word KEY*/
        {
            temp = 1; /*"KEY" found so we can continue with the checking*/
            i+=2; /*To set i to the first dash */
        }
    }

    if( 1 == temp )
    {
        for( j = i; j < (i+5) && j < privKeyLength; j++ )
        {
            if( '-' != pPrivKey[j] )  /*Makes sure there are five dashes after the word KEY*/
                goto exit;
        }

        for( ; j < privKeyLength; j++ )
        {
            if( ' ' != pPrivKey[j] && '\r' != pPrivKey[j] && '\n' != pPrivKey[j] && '\0' != pPrivKey[j] ) /*Makes sure there is nothing after dashes*/
                goto exit;
        }
    }

    KEY_UTILS_PEMKeyIsEncrypted(pPrivKey, privKeyLength, &isEncrypted); /*Checks to see if key is encrypted */

    if( isEncrypted )
    {
        temp = 0;

        /*If it is encrypted, checking for triple-des*/
        for( i = 30; i < privKeyLength && i < 100 && 1 != temp; i++ ) /*30 for the first line or so, 100 for general size of a header */
        {
            if( 'D' == pPrivKey[i] && 'E' == pPrivKey[i+1] && 'S' == pPrivKey[i+2] && '-' == pPrivKey[i+3]
               && 'E' == pPrivKey[i+4] &&  'D' == pPrivKey[i+5] &&  'E' == pPrivKey[i+6]
               &&  '3' == pPrivKey[i+7] && '-' == pPrivKey[i+8] &&  'C' == pPrivKey[i+9]
               &&  'B' == pPrivKey[i+10] &&  'C' == pPrivKey[i+11])
                temp = 1;
        }
    }

    if( 0 == temp ) /*Not a valid certificate*/
        goto exit;

    /*************************************************************************/
    /****************Following block of code checks for size of key***********/
    /*************************************************************************/

    for( i = 0; (36 < privKeyLength) && (i + 3) < 36 && (0 == type); i++) /*36 is the amount of characters for the first line*/
    {
        if( 'R' == pPrivKey[i] && 'S' == pPrivKey[i+1] && 'A' == pPrivKey[i+2] ) /*Checking to see if RSA can be found in header*/
        {
            type = 1;
        }
        if( 'D' == pPrivKey[i] && 'S' == pPrivKey[i+1] && 'A' == pPrivKey[i+2] ) /*Checking to see if DSA can be found in header*/
        {
            type = 2;
        }
    }

    if ( NULL == passphrase && isEncrypted ) /* Encrypted but no passphrase given */
    {
        status = ERR_BAD_KEY;
        goto exit;
    }
    else  /*Encrypted and passphrase exists or not encrypted and whether password exists does not matter*/
    {
        if( OK > (status = KEY_UTILS_CreateKeyBlobFromPEM(MOC_DSA(hwAccelCtx) passphrase, pPrivKey, privKeyLength, &keyBlob, &keyBlobLen, &success)) )
            goto exit;

        if( OK > (status = CA_MGMT_extractKeyBlobEx(MOC_ASYM(hwAccelCtx) keyBlob, keyBlobLen, &key)) ) /*Extracts information from KeyBlob and stores it in assymetric key*/
            goto exit;

        if( 1 == type )
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_getRSACipherTextLength( MOC_RSA(hwAccelCtx)
              key.key.pRSA, &numBits, key.type);
            if (OK != status)
               goto exit;

            numBits *= 8;
#else
            numBits = VLONG_bitLength( RSA_N(key.key.pRSA) ); /*Checks the bitlength for rsa*/
#endif
        }
        else if ( 2 == type )
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_DSA_getCipherTextLength(MOC_DSA(hwAccelCtx)
               key.key.pDSA, &numBits);
#else
            status = DSA_getCipherTextLength(MOC_DSA(hwAccelCtx) key.key.pDSA, &numBits);
#endif
            if (OK != status)
               goto exit;

            numBits *= 8;
        }
        else
        {
            goto exit;
        }

        if( 1 == type && !(numBits >= 768) ) /*RSA and not at least 768 bits*/
            goto exit;
        else if ( 2 == type && (1024 > numBits) ) /*DSA and less than 1024 bits*/
            goto exit;
        else
            *retVal = 1;  /*everything checks out and is a valid key*/
    }

exit:

    CRYPTO_uninitAsymmetricKey(&key, 0);

    if( NULL != keyBlob )
        DIGICERT_freeReadFile(&keyBlob);

    return status;
}

#endif
