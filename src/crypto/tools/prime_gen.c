/**
 * prime_gen.c
 *
 * Prime Generation tool for RSA keys.
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

#if defined(__ENABLE_DIGICERT_PRIME_GEN__)

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../common/mrtos.h"

#if defined(__RTOS_LINUX__)
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#endif /* __RTOS_LINUX__ */

#include <openssl/crypto.h>
#include <openssl/bn.h>

#define PREDEFINED_E (65537)

#ifndef PRIMEGEN_PATH_MAX
#define PRIMEGEN_PATH_MAX 1024
#endif

int ossl_bn_rsa_fips186_4_gen_prob_primes(BIGNUM *p, BIGNUM *Xpout,
                                          BIGNUM *p1, BIGNUM *p2,
                                          const BIGNUM *Xp, const BIGNUM *Xp1,
                                          const BIGNUM *Xp2, int nlen,
                                          const BIGNUM *e, BN_CTX *ctx,
                                          BN_GENCB *cb);


static sbyte *gpOutDir = ".";
static sbyte *gpOutPrefix = "primes";

static ubyte4 gPrimeSize = 2048;
static ubyte4 gNumPrimes = 0;
static ubyte4 gPrimesPerFile = 0;

static char gMagic[4] = {0xd4, 0xe3, 0x29, 0x77};

/*---------------------------------------------------------------------------*/

static MSTATUS PRIMEGEN_writePrimes(FILE *pOutFile)
{   
    MSTATUS status = ERR_MEM_ALLOC_FAIL;
    BIGNUM *p = NULL;
    BIGNUM *Xpout = NULL;
    int nlen = (int) (gPrimeSize * 2);
    BIGNUM *e = NULL;
    BN_CTX *ctx = NULL;
    size_t primeByteLen = (size_t) gPrimeSize/8;
    unsigned char buf[512]; /* big enough for 4096 bit primes */
    ubyte4 ctr = 0;
    
    ctx = BN_CTX_new();
    if (NULL == ctx)
        goto exit;

    e = BN_new();
    if (NULL == e)
        goto exit;

    p = BN_new();
    if (NULL == p)
        goto exit;
    
    Xpout = BN_new();
    if (NULL == Xpout)
        goto exit;

    status = ERR_INTERNAL_ERROR;
    if(!BN_set_word(e, PREDEFINED_E))
    {
        goto exit;
    }

    for (; ctr < gPrimesPerFile; ctr++)
    {
        if (!ossl_bn_rsa_fips186_4_gen_prob_primes(p, Xpout, NULL, NULL, NULL, NULL, NULL, 
                                                   nlen, e, ctx, NULL))
        {
            goto exit;
        }

        if (primeByteLen != (size_t) BN_bn2bin(p, buf))
        {
            goto exit;
        }

        if (primeByteLen != fwrite(buf, 1, primeByteLen, pOutFile))
        {
            goto exit;
        }
    }

    status = OK;

exit:

    (void) BN_free(p);
    (void) BN_free(e);
    (void) BN_free(Xpout);
    (void) BN_CTX_free(ctx);

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS PRIMEGEN_writeFile(char *pPathAndName)
{
    MSTATUS status = ERR_INTERNAL_ERROR;
    FILE* pOutFile = NULL;
    size_t ret = 0;
    char primeLenBuf[2] = {0};
    char numPrimesBuf[4] = {0};

    primeLenBuf[0] = (char) ((gPrimeSize >> 8) & 0xff);
    primeLenBuf[1] = (char) (gPrimeSize & 0xff);

    numPrimesBuf[0] = (char) ((gPrimesPerFile >> 24) & 0xff);
    numPrimesBuf[1] = (char) ((gPrimesPerFile >> 16) & 0xff);
    numPrimesBuf[2] = (char) ((gPrimesPerFile >> 8) & 0xff);
    numPrimesBuf[3] = (char) (gPrimesPerFile & 0xff);

    /* We open for writing first, in order to delete it if it exists */
    pOutFile = fopen(pPathAndName, "wb+");
    if (NULL != pOutFile)
    {
       (void) fclose(pOutFile);
    }

    /* Now open for appending */
    pOutFile = fopen(pPathAndName, "ab");
    if (NULL == pOutFile)
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    ret = fwrite (gMagic, 1, sizeof(gMagic), pOutFile);
    if (4 != ret)
    {
        goto exit;
    }

    ret = fwrite (primeLenBuf, 1, sizeof(primeLenBuf), pOutFile);
    if (2 != ret)
    {
        goto exit;
    }

    ret = fwrite (numPrimesBuf, 1, sizeof(numPrimesBuf), pOutFile);
    if (4 != ret)
    {
        goto exit;
    }

    status = PRIMEGEN_writePrimes(pOutFile);

exit:

    if (NULL != pOutFile)
    {
        fclose(pOutFile);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS PRIMEGEN_generator(void)
{
    MSTATUS status = OK;

    ubyte4 totalFiles = gNumPrimes/gPrimesPerFile;
    char fullFilePath[PRIMEGEN_PATH_MAX] = {0};
    ubyte4 dirLen = DIGI_STRLEN(gpOutDir);
    ubyte4 prefixLen = DIGI_STRLEN(gpOutPrefix);

    ubyte4 pos = 0;

    /* full path, directory + '/' + file prefix, up to 10 digit number + ".dat" and null char */
    if (dirLen + 1 + prefixLen + 10 + 4 >= PRIMEGEN_PATH_MAX)
    {
        printf("ERROR: Directory and file prefix lengths are too large.\n");
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    (void) DIGI_MEMCPY(fullFilePath, gpOutDir, dirLen);
    pos += dirLen;

    fullFilePath[pos] = '/';
    pos++;

    (void) DIGI_MEMCPY(fullFilePath + pos, gpOutPrefix, prefixLen);    
    pos += prefixLen;

    if (1 == totalFiles)  /* We don't suffix with a number */
    {
        (void) DIGI_MEMCPY(fullFilePath + pos, ".dat", 4);
        status = PRIMEGEN_writeFile(fullFilePath);
        /* next step is exit block anyway */
    }
    else
    {
        /* we will overwirte the counter each time */
        ubyte4 ctrPos = pos; 
        ubyte4 fileCtr = 1;

        for (; fileCtr <= totalFiles; fileCtr++)
        {
            pos = ctrPos;
            pos += (ubyte4) sprintf(fullFilePath + ctrPos, "%d", fileCtr);

            (void) DIGI_MEMCPY(fullFilePath + pos, ".dat", 4);
            status = PRIMEGEN_writeFile(fullFilePath);
            if (OK != status)
                goto exit;
        }
    }

exit:

    if (OK != status)
    {
        printf("ERROR: Failed to write to file %s.\n", fullFilePath);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

static void PRIMEGEN_displayHelp()
{
    printf("Usage: tc_primegen --num-primes NUM [--primes-per-file NUM] [--prime-length NUM]\n");
    printf("                                    [--output-path PATH] [--output-prefix PREFIX]\n");
    printf("\n");
    printf(" --num-primes NUM        [Required] The total number of primes to be generated.\n");
    printf(" --primes-per-file NUM   [Optional] The total number of primes per file. Must divide --num-primes.\n");
    printf("                         If omitted all primes will be generated in a single file.\n");
    printf(" --prime-length NUM      [Optional] The length of the primes to be generated, in bits.\n");
    printf("                         If omitted 2048 will be the default bitlength.\n");
    printf(" --output-path PATH      [Optional] Directory that will contain the output files. The directory\n");
    printf("                         must exist. If omitted, the current working directory will be used.\n");
    printf(" --output-prefix PREFIX  [Optional] File prefix for the output files. If multiple files are used\n");
    printf("                         files will be suffixed with a counter. If omitted 'primes' will be used.\n");

    return;
}

/*---------------------------------------------------------------------------*/

static MSTATUS PRIMEGEN_getArgs(int argc, char *argv[])
{
    MSTATUS status = OK;
    sbyte4 i = 0;

    if (NULL == argv)
    {
        PRIMEGEN_displayHelp();
        return (MSTATUS) -1;
    }

    for (i = 1; i < argc; i++)
    {
        if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"-h") || 0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--help") ||
            0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"?"))
        {
            PRIMEGEN_displayHelp();
            return (MSTATUS) -1;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--num-primes"))
        {
            if (i++ < argc)
            {
                sbyte4 mTemp = DIGI_ATOL((sbyte *) argv[i], NULL);
                if (mTemp < 1)
                {
                    printf("ERROR: Invalid --num-primes option: %s.\n", argv[i]);
                    PRIMEGEN_displayHelp();
                    return (MSTATUS) -1;
                }

                gNumPrimes = (ubyte4) mTemp;
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--primes-per-file"))
        {
            if (i++ < argc)
            {
                sbyte4 mTemp = DIGI_ATOL((sbyte *) argv[i], NULL);
                if (mTemp < 1)
                {
                    printf("ERROR: Invalid --primes-per-file option: %s.\n", argv[i]);
                    PRIMEGEN_displayHelp();
                    return (MSTATUS) -1;
                }
                
                gPrimesPerFile = (ubyte4) mTemp;
            }
            continue;
        }
        else if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"--prime-length"))
        {
            if (i++ < argc)
            {
                if (0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"1024"))
                {
                    gPrimeSize = 1024;
                }
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"1536"))
                {
                    gPrimeSize = 1536;
                }
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"2048"))
                {
                    gPrimeSize = 2048;
                }
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"3072"))
                {
                    gPrimeSize = 3072;
                }
                else if(0 == DIGI_STRCMP((const sbyte *)argv[i], (const sbyte *)"4096"))
                {
                    gPrimeSize = 4096;
                }
                else
                {
                    printf("ERROR: Invalid --prime-length option (must be 1024, 1536, 2048, 3072 or 4096): %s.\n", argv[i]);
                    PRIMEGEN_displayHelp();
                    return (MSTATUS) -1;
                }
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
    }

    if (!gNumPrimes)
    {
        printf("ERROR: --num-primes must be specified.\n");
        PRIMEGEN_displayHelp();
        return (MSTATUS) -1;        
    }

    if (0 == gPrimesPerFile)
    {
        gPrimesPerFile = gNumPrimes;
    }
    else if(0 != (gNumPrimes % gPrimesPerFile))
    {
        printf("ERROR: --primes-per-file must evenly divide --num-primes.\n");
        PRIMEGEN_displayHelp();
        return (MSTATUS) -1;
    }

    return OK;
}

/*---------------------------------------------------------------------------*/

int main(int argc, char *argv[])
{
    MSTATUS status = OK;

    status = PRIMEGEN_getArgs(argc, argv);
    if (OK != status)
        goto exit;

    status = PRIMEGEN_generator();
    /* error already printed if it failed */
    
exit:

    return (int) status;
}
#endif /* #if defined(__ENABLE_DIGICERT_PRIME_GEN__) */
