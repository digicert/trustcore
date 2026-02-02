/**
 * rsa_keygen.c
 *
 * Key Generation tool for RSA keys (from primes).
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#if defined(__ENABLE_DIGICERT_RSA_KEYGEN__)

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../common/mrtos.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../common/base64.h"
#include "../../crypto/rsa.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/pkcs_key.h"

#if defined(__RTOS_LINUX__)
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#endif /* __RTOS_LINUX__ */

#define PREDEFINED_E (65537)

#ifndef RSAGEN_PATH_MAX
#define RSAGEN_PATH_MAX 1024
#endif

#ifndef MOC_KEYGEN_PKCS8_ALGO
#define MOC_KEYGEN_PKCS8_ALGO PCKS8_EncryptionType_pkcs5_v2_aes256
#endif

#ifndef MOC_KEYGEN_PKCS8_HASH
#define MOC_KEYGEN_PKCS8_HASH PKCS8_PrfType_pkcs5_v2_hmacSHA256Digest
#endif

static sbyte *gpPrimeFile = NULL;
static sbyte *gpPrimeFile2 = NULL;
static ubyte4 gKeySize = 0; /* we require user to specify */
static sbyte *gpKeyPass = NULL;
static sbyte *gpOutDir = ".";
static sbyte *gpOutPrefix = "rsa";
static intBoolean gIsPem = FALSE;

static randomContext *gpRand = NULL;
static vlong *pDelta = NULL;

/* must be the same as in the prime_gen */
static char gMagic[4] = {0xd4, 0xe3, 0x29, 0x77};

/* local version of VLONG_vlongFromByteString that does not allocate the vlong */
static void RSAGEN_vlongFromByteString (
    const ubyte* byteString,
    sbyte4 len,
    vlong *pRetVlong
    )
{
    sbyte4 i, j, count = 0;
    vlong_unit elem;

    /* now copy the contents of the byte string to the array of vlong_units */
    /* respecting the endianess of the architecture */

    for (i = len - 1; i >= 0; ++count)
    {
        elem = 0;

        for (j = 0; j < (sbyte4)(sizeof(vlong_unit)) && i >= 0; ++j, --i)
        {
            elem |= (((vlong_unit)byteString[i]) << (j * 8));
        }

        pRetVlong->pUnits[count] = elem;
        /* all primes are same bitlength, no need to change numUnitsUsed */
    }
} /* VLONG_vlongFromByteString */

/*---------------------------------------------------------------------------*/

static MSTATUS RSAGEN_generateKey(RSAKey *pPri, ubyte *pPrime1, ubyte *pPrime2, ubyte4 primeBytes, vlong *pDelta)
{
    MSTATUS status = OK;
    ubyte4 i = 0;

    RSAGEN_vlongFromByteString (pPrime1, primeBytes, RSA_P(pPri));
    RSAGEN_vlongFromByteString (pPrime2, primeBytes, RSA_Q(pPri));
    
    /* small optimization later on when using private keys */
    if (VLONG_compareSignedVlongs(RSA_P(pPri), RSA_Q(pPri)) < 0)
    {
        vlong *pSwap = RSA_P(pPri);
        RSA_P(pPri) = RSA_Q(pPri);
        RSA_Q(pPri) = pSwap;
    }

    /* | p - q | */
    
    /* make a copy of P too */
    for( ; i < primeBytes / sizeof(vlong_unit); i++)
    {
        pDelta->pUnits[i] = RSA_P(pPri)->pUnits[i];
        /* reset numUnitsUsed in case it was modified in the previous subtract */
        pDelta->numUnitsUsed = RSA_P(pPri)->numUnitsUsed;
    }
    
    status = VLONG_subtractSignedVlongs(pDelta, RSA_Q(pPri), NULL);
    if (OK != status)
       goto exit;

    /* |p-q| <= 2^((nLen/2)-100) */
    if (!(((gKeySize/2)-100) <= VLONG_bitLength(pDelta)))
    {
        /* set an error status but we'll continue and ignore these primes */
        status = ERR_BAD_LENGTH;
        goto exit;
    }
    
    /* The public key has the same N so this will put the right answer there too */
    status = VLONG_vlongSignedMultiply(RSA_N(pPri), RSA_P(pPri), RSA_Q(pPri));
    if (OK != status)
       goto exit;

    status = RSA_prepareKey(pPri, NULL);

exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS RSAGEN_outputKey(AsymmetricKey *pPri, AsymmetricKey *pPub, ubyte4 index)
{
    MSTATUS status = OK;

    ubyte *pPriv = NULL;
    ubyte4 privLen = 0;

    ubyte *pPrivTemp = NULL;
    ubyte4 privTempLen = 0;

    ubyte *pPubSer = NULL;
    ubyte4 pubLen = 0;

    char fullFilePath[RSAGEN_PATH_MAX] = {0};
    ubyte4 dirLen = DIGI_STRLEN(gpOutDir);
    ubyte4 prefixLen = DIGI_STRLEN(gpOutPrefix);
    char *pSuffix = gIsPem ? ".pem" : ".der";

    ubyte4 pos = 0;
    ubyte4 posCopy = 0;

    /* validate space for output files before continuing */
    /* full path, directory + '/' + file prefix, up to 10 digit number + "_priv.pem" and null char */
    if (dirLen + 1 + prefixLen + 10 + 9 >= RSAGEN_PATH_MAX)
    {
        printf("ERROR: Directory and file prefix lengths are too large.\n");
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    /* serialize the keys to a buffer first */
    if (NULL != gpKeyPass)
    {
        ubyte4 passLen = (ubyte4) DIGI_STRLEN(gpKeyPass);

        status = PKCS_setPKCS8Key(pPri, gpRand, MOC_KEYGEN_PKCS8_ALGO, MOC_KEYGEN_PKCS8_HASH,
                                  gpKeyPass, passLen, &pPriv, &privLen);
        if (OK != status)
            goto exit;
        
        if (gIsPem)
        {
            status = BASE64_makePemMessageAlloc (MOC_PEM_TYPE_ENCR_PRI_KEY, pPriv, privLen, &pPrivTemp, &privTempLen);
            if (OK != status)
                goto exit;
            
            /* free pPriv now so we can re-use the pointer for the PEM form key to be output */
            status = DIGI_MEMSET_FREE(&pPriv, privLen);
            if (OK != status)
                goto exit;
            
            pPriv = pPrivTemp; pPrivTemp = NULL;
            privLen = privTempLen; privTempLen = 0;
        }
    }
    else
    {        
        status = CRYPTO_serializeAsymKey (pPri, gIsPem ? privateKeyPem : privateKeyInfoDer, &pPriv, &privLen);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_serializeAsymKey (pPub, gIsPem ? publicKeyPem : publicKeyInfoDer, &pPubSer, &pubLen);
    if (OK != status)
        goto exit;

    /* create the key output file names */
    (void) DIGI_MEMCPY(fullFilePath, gpOutDir, dirLen);
    pos += dirLen;

    fullFilePath[pos] = '/';
    pos++;

    (void) DIGI_MEMCPY(fullFilePath + pos, gpOutPrefix, prefixLen);    
    pos += prefixLen;

    posCopy = pos;

    /* write pub first since it's name is shorter than priv */
    (void) DIGI_MEMCPY(fullFilePath + pos, (ubyte *) "_pub", 4);
    pos += 4;

    pos += (ubyte4) sprintf(fullFilePath + pos, "%d", index);

    (void) DIGI_MEMCPY(fullFilePath + pos, (ubyte *) pSuffix, 4);

    status = DIGICERT_writeFile((const char *) fullFilePath, pPubSer, pubLen);
    if (OK != status)
        goto exit;

    /* now back up to posCopy and write the priv */
    pos = posCopy;

    (void) DIGI_MEMCPY(fullFilePath + pos, (ubyte *) "_priv", 5);
    pos += 5;

    pos += (ubyte4) sprintf(fullFilePath + pos, "%d", index);
 
    (void) DIGI_MEMCPY(fullFilePath + pos, (ubyte *) pSuffix, 4);

    status = DIGICERT_writeFile((const char *) fullFilePath, pPriv, privLen);

exit:

    if (NULL != pPriv)
    {
        (void) DIGI_MEMSET_FREE(&pPriv, privLen);
    }

    if (NULL != pPrivTemp)
    {
        (void) DIGI_MEMSET_FREE(&pPrivTemp, privTempLen);
    }

    if (NULL != pPubSer)
    {
        (void) DIGI_MEMSET_FREE(&pPubSer, pubLen);   
    }

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS RSAGEN_generator(void)
{
    MSTATUS status = OK;
    AsymmetricKey keyPri = {0};
    AsymmetricKey keyPub = {0};
    FILE *pPrimeFile = NULL;
    FILE *pPrimeFile2 = NULL;
    char primeBuf[512]; /* big enough for 4096 bit primes */
    char primeBuf2[512];
    char header[10]; /* 4 byte magic, 2 byte prime len, 4 byte number */
    size_t ret = 0;
    ubyte4 numPrimes = 0;
    ubyte4 numPrimes2 = 0;
    ubyte4 numKeys = 0;
    ubyte4 primeBytes = gKeySize/16;
    ubyte4 i = 1;  /* start at index 1 for outfile names */
    vlong *pDelta = NULL;

    /* first set up a the key shells with enough space for the calculated params */
    status = CRYPTO_initAsymmetricKey(&keyPri);
    if (OK != status)
        goto exit;

    status = CRYPTO_createRSAKey(&keyPri, NULL);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(&keyPub);
    if (OK != status)
        goto exit;

    status = CRYPTO_createRSAKey(&keyPub, NULL);
    if (OK != status)
        goto exit;

    /* Allocate the params for the private key */
    status = VLONG_makeVlongFromUnsignedValue ((vlong_unit) PREDEFINED_E, &RSA_E(keyPri.key.pRSA), NULL);
    if (OK != status)
        goto exit;
    
    status = VLONG_allocVlong(&RSA_N(keyPri.key.pRSA), NULL);
    if (OK != status)
        goto exit;

    status = VLONG_allocVlong(&RSA_P(keyPri.key.pRSA), NULL);
    if (OK != status)
        goto exit;
    
    status = VLONG_allocVlong(&RSA_Q(keyPri.key.pRSA), NULL);
    if (OK != status)
        goto exit;

    status = expandVlong (RSA_N(keyPri.key.pRSA), (2*primeBytes) / sizeof(vlong_unit));
    if (OK != status)
        goto exit;

    status = expandVlong (RSA_P(keyPri.key.pRSA), primeBytes / sizeof(vlong_unit));
    if (OK != status)
        goto exit;
    
    status = expandVlong (RSA_Q(keyPri.key.pRSA), primeBytes / sizeof(vlong_unit));
    if (OK != status)
        goto exit;

    /* units are used yet, but they will be filled in later! N not needed to be set here */
    RSA_P(keyPri.key.pRSA)->numUnitsUsed = primeBytes / sizeof(vlong_unit);
    RSA_Q(keyPri.key.pRSA)->numUnitsUsed = primeBytes / sizeof(vlong_unit);

    /* set the public key N and E to the same vlong or vlong shell */

    RSA_N(keyPub.key.pRSA) = RSA_N(keyPri.key.pRSA);
    RSA_E(keyPub.key.pRSA) = RSA_E(keyPri.key.pRSA);

    keyPri.key.pRSA->privateKey = TRUE;
    keyPub.key.pRSA->privateKey = FALSE;

    /* create a temp var pDelta for use in each key calculation */
    status = VLONG_allocVlong(&pDelta, NULL);
    if (OK != status)
        goto exit;  

    status = expandVlong (pDelta, primeBytes / sizeof(vlong_unit));
    if (OK != status)
        goto exit;

    /* now we'll start reading the prime files */
    pPrimeFile = fopen(gpPrimeFile, "rb");
    if (NULL == pPrimeFile)
    {
        printf("ERROR: Failed to open file %s.\n", gpPrimeFile);
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    /* validate the magic, size, and number of primes */
    status = ERR_INVALID_INPUT;
    if (10 != fread(header, 1, sizeof(header), pPrimeFile))
    {
        printf("ERROR: Invalid file %s.\n", gpPrimeFile);
        goto exit;
    }
    
    if (header[0] != gMagic[0] || header[1] != gMagic[1] ||
        header[2] != gMagic[2] || header[3] != gMagic[3])
    {
        printf("ERROR: Invalid file type %s.\n", gpPrimeFile);
        goto exit;
    }

    if (gKeySize != (2 * (((ubyte4) header[4] << 8) | (ubyte4) header[5])))
    {
        printf("ERROR: File prime size not compatible with requested key size.\n");
        goto exit;
    }

    numPrimes = ((ubyte4) header[6] << 24) | 
                ((ubyte4) header[7] << 16) | 
                ((ubyte4) header[8] << 8) | 
                 (ubyte4) header[9];
 
    /* see if we have another prime file */
    if (NULL != gpPrimeFile2)
    {
        pPrimeFile2 = fopen(gpPrimeFile2, "rb");
        if (NULL == pPrimeFile2)
        {
            printf("ERROR: Failed to open file %s.\n", gpPrimeFile2);
            status = ERR_FILE_OPEN_FAILED;
            goto exit;
        }

        /* validate the magic, size, and number of primes, ok to re-use header  */
        if (10 != fread(header, 1, sizeof(header), pPrimeFile2))
        {
            printf("ERROR: Invalid file %s.\n", gpPrimeFile2);
            goto exit;
        }
        
        if (header[0] != gMagic[0] || header[1] != gMagic[1] ||
            header[2] != gMagic[2] || header[3] != gMagic[3])
        {
            printf("ERROR: Invalid file type %s.\n", gpPrimeFile2);
            goto exit;
        }

        if (gKeySize != (2 * (((ubyte4) header[4] << 8) | (ubyte4) header[5])))
        {
            printf("ERROR: File-2 prime size not compatible with requested key size.\n");
            goto exit;
        }

        numPrimes2 = ((ubyte4) header[6] << 24) | 
                    ((ubyte4) header[7] << 16) | 
                    ((ubyte4) header[8] << 8) | 
                    (ubyte4) header[9];

        if (numPrimes2 != numPrimes)
        {   
            printf("ERROR: The two prime files contain a different number of primes.\n");
            goto exit;
        }

        numKeys = numPrimes;
    }
    else
    {
        numKeys = numPrimes/2;
    }

    for (; i <= numKeys; i++)
    {
        if (primeBytes != fread(primeBuf, 1, primeBytes, pPrimeFile))
        {
            goto exit;
        }

        if (NULL != pPrimeFile2) /* get next prime from second file */
        {
            if (primeBytes != fread(primeBuf2, 1, primeBytes, pPrimeFile2))
            {
                goto exit;
            }
               
        }
        else  /* get next prime again from first file */
        {
            if (primeBytes != fread(primeBuf2, 1, primeBytes, pPrimeFile))
            {
                goto exit;
            }
        }

        status = RSAGEN_generateKey(keyPri.key.pRSA, (ubyte *) primeBuf, (ubyte *) primeBuf2, primeBytes, pDelta);
        if (OK == status)
        {
            status = RSAGEN_outputKey(&keyPri, &keyPub, i);
            if (OK != status)
                goto exit;
        }
        else if (ERR_BAD_LENGTH == status)
        {
            /* ignore these primes, continue on with the next ones, reset i */
            i--; numKeys--;
            status = OK;
        }
        else
        {
            goto exit;
        }
    }

    status = OK;
    
exit:

    (void) VLONG_freeVlong(&pDelta, NULL);
    (void) CRYPTO_uninitAsymmetricKey(&keyPri, NULL);
    
    /* E and N were shallow copies in both keys, already freed, don't double free */
    RSA_E(keyPub.key.pRSA) = NULL;
    RSA_N(keyPub.key.pRSA) = NULL;

    (void) CRYPTO_uninitAsymmetricKey(&keyPub, NULL);

    if (NULL != pPrimeFile)
    {
        (void) fclose(pPrimeFile);
    }

    if (NULL != pPrimeFile2)
    {
        (void) fclose(pPrimeFile2);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

static void RSAGEN_displayHelp()
{
    printf("Usage: tc_rsakeygen --prime-file FILE [--prime-file-2 FILE] [--key-length NUM] [--key-pw PASSWORD]\n");
    printf("                                      [--output-path PATH] [--output-prefix PREFIX]\n");
    printf("                                      [--output-form FORM]\n");
    printf("\n");
    printf(" --prime-file FILE       [Required] A file of the input prime numbers to be used in key generation.\n");
    printf(" --prime-file-2 FILE     [Optional] An additional prime number input file. If specified,\n");
    printf("                         keys will be made up of one prime from the first file and one from this file.\n");
    printf(" --key-length NUM        [Required] The size in bits of the desired key. Will be validated against the prime sizes.\n");
    printf(" --key-pw PASSWORD       [Optional] If specified private keys will be pkcs5 encrypted.\n");
    printf(" --output-path PATH      [Optional] Directory that will contain the output files. The directory\n");
    printf("                         must exist. If omitted, the current working directory will be used.\n");
    printf(" --output-prefix PREFIX  [Optional] File prefix for the output files. They will be suffixed with\n");
    printf("                         _priv and _pub. If omitted rsa_ will be used.\n");
    printf(" --output-form FORM      [Optional] DER form will be the default but PEM may be specified.\n");
 
    return;
}

/*---------------------------------------------------------------------------*/

static MSTATUS RSAGEN_getArgs(int argc, char *argv[])
{
    MSTATUS status = OK;
    sbyte4 i = 0;

    if (NULL == argv)
    {
        RSAGEN_displayHelp();
        return (MSTATUS) -1;
    }

    for (i = 1; i < argc; i++)
    {
        if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-h") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--help") ||
            0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"?"))
        {
            RSAGEN_displayHelp();
            return (MSTATUS) -1;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--prime-file"))
        {
            if (i++ < argc)
            {
                gpPrimeFile = (sbyte *) argv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--prime-file-2"))
        {
            if (i++ < argc)
            {
                gpPrimeFile2 = (sbyte *) argv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--key-length"))
        {
            if (i++ < argc)
            {
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"2048"))
                {
                    gKeySize = 2048;
                }
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"3072"))
                {
                    gKeySize = 3072;
                }
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"4096"))
                {
                    gKeySize = 4096;
                }
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"6144"))
                {
                    gKeySize = 6144;
                }
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"8192"))
                {
                    gKeySize = 8192;
                }
                else
                {
                    printf("ERROR: Invalid --key-length option (must be 2048, 3072, 4096, 6144 or 8192): %s.\n", argv[i]);
                    RSAGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--key-pw"))
        {
            if (i++ < argc)
            {
                gpKeyPass = (sbyte *) argv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--output-path"))
        {
            if (i++ < argc)
            {
                gpOutDir = (sbyte *) argv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--output-prefix"))
        {
            if (i++ < argc)
            {
                gpOutPrefix = (sbyte *) argv[i];
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--output-form"))
        {
            if (i++ < argc)
            {
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"PEM") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"pem"))
                {
                    gIsPem = TRUE;
                }
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"DER") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"der"))
                {
                    gIsPem = FALSE;
                }
                else
                {
                    printf("ERROR: Invalid --putput-form option: %s.\n", argv[i]);
                    RSAGEN_displayHelp();
                    return (MSTATUS) -1;
                }
            }
            continue;
        }
    }

    if (NULL == gpPrimeFile)
    {
        printf("ERROR: --prime-file must be specified.\n");
        RSAGEN_displayHelp();
        return (MSTATUS) -1;        
    }

    if (0 == gKeySize)
    {
        printf("ERROR: --key-length must be specified.\n");
        RSAGEN_displayHelp();
        return (MSTATUS) -1;  
    }

    return OK;
}

/*---------------------------------------------------------------------------*/

int main(int argc, char *argv[])
{
    MSTATUS status = OK;

    status = RSAGEN_getArgs(argc, argv);
    if (OK != status)
        goto exit;

    status = (MSTATUS) DIGICERT_initDigicert();
    if (OK != status)
        goto exit;

    status = RANDOM_acquireContext(&gpRand);
    if (OK != status)
        goto exit;
    
    status = RSAGEN_generator();
    /* error already printed if it failed */
    
exit:

    (void) RANDOM_releaseContext(&gpRand);
    (void) DIGICERT_freeDigicert();

    return (int) status;
}
#endif /* #if defined(__ENABLE_DIGICERT_RSA_KEYGEN__) */
