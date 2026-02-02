/*
 * fips_integ.c
 *
 * FIPS 140-3 Self Test Compliance
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

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/debug_console.h"
#include "../common/memory_debug.h"
#include "../crypto/crypto.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ecb.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/aes_ccm.h"
#include "../crypto/aes_cmac.h"
#include "../crypto/aes_xts.h"
#include "../crypto/gcm.h"
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/sha3.h"
#include "../crypto/hmac.h"
#include "../crypto/hmac_kdf.h"
#include "../crypto/dh.h"
#include "../crypto/rsa.h"
#include "../crypto/dsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primefld_priv.h"
#include "../crypto/primeec.h"
#include "../crypto/ecc.h"
#ifdef __ENABLE_DIGICERT_ECC_ED_COMMON__
#include "../crypto/ecc_edwards.h"
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */
#include "../crypto/nist_rng.h"
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#include "../harness/harness.h"


#if defined(__RTOS_LINUX__) || defined(__RTOS_ANDROID__)
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
#include <stdio.h>
#include <string.h>
#define __DIGICERT_LINUX_SHARED_LIBRARY__
#else
#include <linux/string.h>
#include <linux/slab.h>
#endif
#endif

#ifdef __RTOS_VXWORKS__
#include <stdio.h>
#endif

#ifdef __RTOS_WIN32__
#include <stdio.h>
/* Conflicts w/ def in WinNT.h */
#ifdef CR
#undef CR
#endif
#include <Windows.h>
#include <string.h>
#include <tchar.h>
#define DLL_NAME _T("mss_fips")
#define SIGNATURE_FILE (DLL_NAME _T(".sig"))
#endif

#ifdef __RTOS_WINCE__
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <tchar.h>
#define DLL_NAME _T("mss_ce_dll")
#define SIGNATURE_FILE (DLL_NAME _T(".sig"))
#endif

MOC_EXTERN FIPSRuntimeConfig sCurrRuntimeConfig; /* What are we configured to run */
MOC_EXTERN volatile FIPSStartupStatus sCurrStatus; /* What has passed (or not). */

#if (!defined(__DISABLE_DIGICERT_SHA256__))
static const BulkHashAlgo SHA256Suite =
{
    SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest,
    (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest,
    (BulkCtxFinalFunc)SHA256_finalDigest, NULL, NULL, NULL, ht_sha256
};
#endif

/* Extern for Linux/Win32 Crypto Module FILE Read */
#ifdef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
MOC_EXTERN sbyte4 DIGI_CRYPTO_fipsSelfTestInit(ubyte* filename);
MOC_EXTERN sbyte4 DIGI_CRYPTO_fipsSelfTestUpdate(sbyte4 fd, ubyte* buf, ubyte4 bufLen);
MOC_EXTERN sbyte4 DIGI_CRYPTO_fipsSelfTestFinal(sbyte4 fd);
#endif

/*---------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_FIPS_INTEG_TEST__))
#if (defined(__ENABLE_DIGICERT_FIPS_STATIC_INTEG_TEST__))
MOC_EXTERN MSTATUS
FIPS_INTEG_TEST_hash_locate(ubyte* hashReturn)
{
    MSTATUS status = OK;
    int i;

    extern const unsigned char FIPS_MOCANA_SHA[];

    for (i=0; i<SHA256_RESULT_SIZE; ++i) {
        hashReturn[i] = (ubyte)FIPS_MOCANA_SHA[i];
    }

    return status;
}

#ifndef __ENABLE_DIGICERT_FIPS_STATIC_INTEG_MODULE_TEST__
/**********************************************/
/* Calculate hash over text & const           */
/* sections from in-memory. (for static libs) */
/**********************************************/
MOC_EXTERN MSTATUS
FIPS_INTEG_TEST_hash_inplace(ubyte* hashReturn)
{
    MSTATUS status = OK;
    int i;
    int sLen = SHA256_RESULT_SIZE;

    /* The edges of the static code regions in ".text" and ".rodata" */
    extern const void *FIPS_MOCANA_START(), *FIPS_MOCANA_STOP();
    extern const unsigned char FIPS_data0[], FIPS_data1[];

    const BulkHashAlgo SHA256Suite =
    {
        SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest,
        (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, (BulkCtxFinalFunc)SHA256_finalDigest, NULL
    };

    ubyte4 keyLen = 117;
    ubyte key[] = {
        0xd6,0xc3,0x44,0xd5,0x0f,0x0d,0xc1,0x88,
        0xbb,0xf8,0x74,0x59,0xcc,0x7e,0xf8,0xc7,
        0xd2,0xbc,0x8b,0x6a,0x14,0xb0,0xc0,0xda,
        0xe0,0x41,0x74,0xcc,0x1f,0x7f,0x02,0x7e,
        0x2c,0x2d,0xbb,0x56,0xe7,0x7d,0x90,0xc6,
        0x05,0x1a,0x12,0x72,0xaa,0x6b,0x9d,0x95,
        0x39,0x17,0xcf,0xa0,0x6b,0xc4,0x3f,0x25,
        0x9e,0x25,0x6c,0xf4,0x70,0x33,0xf4,0x84,
        0x8d,0xba,0x07,0x94,0xc5,0x18,0x1a,0x11,
        0x62,0x41,0xe0,0x3b,0xb8,0x07,0x76,0x04,
        0xfd,0x99,0xde,0xb8,0x5b,0x49,0xae,0xe3,
        0x44,0x92,0x09,0x70,0x06,0x59,0xcf,0x0e,
        0x9f,0x73,0x11,0xd8,0xd2,0x68,0xc8,0x34,
        0x7a,0x76,0xc6,0xfb,0x1f,0xd9,0xec,0xdb,
        0xc7,0x4a,0x9e,0xfa,0x0e
    };

    /* HMAC context pointer */
    HMAC_CTX* pHMACCtx = NULL;

    if (OK > (status = HmacCreate( MOC_HASH(hwAccelCtx) &pHMACCtx, &SHA256Suite )))
      goto exit;

    if (OK > (status = HmacKey( MOC_HASH(hwAccelCtx) pHMACCtx, key, keyLen )))
      goto exit;

    /* Add FIPS bytes from ".text" */
    /* Create data for ".text" */
    if (OK > (status = HmacUpdate( MOC_HASH(hwAccelCtx) pHMACCtx, (char*)FIPS_MOCANA_START, ((size_t)FIPS_MOCANA_STOP-(size_t)FIPS_MOCANA_START) )))
      goto exit;

    /* Add FIPS bytes from ".rodata" */
    /* Create data for ".rodata" */
    if (OK > (status = HmacUpdate( MOC_HASH(hwAccelCtx) pHMACCtx, FIPS_data0, ((size_t)FIPS_data1-(size_t)FIPS_data0) )))
      goto exit;

    /* Finalize data streaming */
    if (OK > (status = HmacFinal( MOC_HASH(hwAccelCtx) pHMACCtx, hashReturn
)))
      goto exit;

    exit:
    HmacDelete( MOC_HASH(sbyte4 hwAccelCtx) &pHMACCtx );

    return status;
}

#else /* __ENABLE_DIGICERT_FIPS_STATIC_INTEG_MODULE_TEST__ */
/**********************************************/
/* Calculate hash over text & const           */
/* sections from lib file (parse PE sections) */
/**********************************************/

#if defined(__ENABLE_DIGICERT_FIPS_DBG_STATIC_HASH__)
#define DMSGBUFF_SIZE 300
static char dmsgbuff[DMSGBUFF_SIZE];
int d_ndx;
#endif

MOC_EXTERN MSTATUS
FIPS_INTEG_TEST_hash_file_segments(ubyte* hashReturn)
{
        MSTATUS status = OK;
        FILE*   fbin = NULL;
#if defined( __RTOS_WIN32__ ) || defined(__RTOS_WINCE__)
    TCHAR   modulePath[_MAX_PATH + 5]; /* add a little buffer to the buffer. 5 should be enough (.sig) */
    HMODULE hModule;
#endif

    extern const unsigned char FIPS_MOCANA_SHA[];
    /* Section descriptions */
    int *FIPS_MOCANA_MODULE = (int*)(FIPS_MOCANA_SHA + SHA256_RESULT_SIZE);

    ubyte4 keyLen = 117;
    ubyte key[] = {
        0xd6,0xc3,0x44,0xd5,0x0f,0x0d,0xc1,0x88,
        0xbb,0xf8,0x74,0x59,0xcc,0x7e,0xf8,0xc7,
        0xd2,0xbc,0x8b,0x6a,0x14,0xb0,0xc0,0xda,
        0xe0,0x41,0x74,0xcc,0x1f,0x7f,0x02,0x7e,
        0x2c,0x2d,0xbb,0x56,0xe7,0x7d,0x90,0xc6,
        0x05,0x1a,0x12,0x72,0xaa,0x6b,0x9d,0x95,
        0x39,0x17,0xcf,0xa0,0x6b,0xc4,0x3f,0x25,
        0x9e,0x25,0x6c,0xf4,0x70,0x33,0xf4,0x84,
        0x8d,0xba,0x07,0x94,0xc5,0x18,0x1a,0x11,
        0x62,0x41,0xe0,0x3b,0xb8,0x07,0x76,0x04,
        0xfd,0x99,0xde,0xb8,0x5b,0x49,0xae,0xe3,
        0x44,0x92,0x09,0x70,0x06,0x59,0xcf,0x0e,
        0x9f,0x73,0x11,0xd8,0xd2,0x68,0xc8,0x34,
        0x7a,0x76,0xc6,0xfb,0x1f,0xd9,0xec,0xdb,
        0xc7,0x4a,0x9e,0xfa,0x0e
    };

    HMAC_CTX* pHMACCtx = NULL;

    ubyte  bdata[BDATA_READ_SIZE];
    ubyte4 bShift = 0;
    sbyte4 bytesRead;
    ubyte4 inFileOff = 0;

#if defined( __RTOS_WIN32__ ) || defined(__RTOS_WINCE__)
    hModule = GetModuleHandle(DLL_NAME);

    if (!GetModuleFileName(hModule, modulePath, _MAX_PATH))
    {
        DEBUG_PRINTNL(DEBUG_CRYPTO, (sbyte *) "FIPS_INTEG: GetModuleFileName failed");
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_FIPS_DBG_STATIC_HASH__)
    FIPS_TESTLOG_FMT(500, "modulePath:: %s", modulePath);
#endif

    fbin = _tfopen(modulePath, _T("rb"));
    if (0 == fbin)
    {
        FIPS_TESTLOG(501, "FIPS_INTEG: Binary file load error!");
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }
#else /* Not: __RTOS_WIN32__ || __RTOS_WINCE__ */
#error
#endif

    if (OK > (status = HmacCreate(MOC_HASH(hwAccelCtx) &pHMACCtx, &SHA256Suite)))
        goto exit;

    if (OK > (status = HmacKey(MOC_HASH(hwAccelCtx) pHMACCtx, key, keyLen)))
        goto exit;

#if defined(__ENABLE_DIGICERT_FIPS_DBG_STATIC_HASH__)
    FIPS_TESTLOG(502, "DLL segments:");
    FIPS_TESTLOG_FMT(503, "Section 0: %ld + %d", FIPS_MOCANA_MODULE[0], FIPS_MOCANA_MODULE[1]);
    FIPS_TESTLOG_FMT(504, "Section 1: %ld + %d", FIPS_MOCANA_MODULE[2], FIPS_MOCANA_MODULE[3]);
#endif

    DIGI_MEMSET(bdata, 0x00, BDATA_READ_SIZE);

    /* while( EOF != (intVal = fgetc(fbin)) )*/
    while (0 < (bytesRead = (ubyte4)fread(bdata, 1, BDATA_READ_SIZE, fbin)))
    {
        bShift = 0;
        if ((FIPS_MOCANA_MODULE[1] > 0) &&
            (inFileOff >= FIPS_MOCANA_MODULE[0]) &&
            (inFileOff < (FIPS_MOCANA_MODULE[0] + FIPS_MOCANA_MODULE[1])))
        {
            /* In .text */
            if ((inFileOff + bytesRead) >= (FIPS_MOCANA_MODULE[0] + FIPS_MOCANA_MODULE[1]))
            {
                /* Only use these bytes in buffer */
                ubyte4 move = bytesRead;
                bytesRead = (FIPS_MOCANA_MODULE[0] + FIPS_MOCANA_MODULE[1]) - inFileOff;
                inFileOff += move;
            }
            else
            {
                inFileOff += (ubyte4)bytesRead;
            }
        }
        else if ((FIPS_MOCANA_MODULE[1] > 0) &&
            ((inFileOff+bytesRead) > FIPS_MOCANA_MODULE[0]) &&
            (inFileOff < (FIPS_MOCANA_MODULE[0] + FIPS_MOCANA_MODULE[1])))
        {
            bShift = FIPS_MOCANA_MODULE[0] - inFileOff;
            inFileOff += (ubyte4)bytesRead;
            bytesRead = bytesRead - bShift;
            if (bytesRead > FIPS_MOCANA_MODULE[1])
            {
                bytesRead = FIPS_MOCANA_MODULE[1];
            }
        }
        else if ((FIPS_MOCANA_MODULE[3] > 0) &&
            (inFileOff >= FIPS_MOCANA_MODULE[2]) &&
            (inFileOff < (FIPS_MOCANA_MODULE[2] + FIPS_MOCANA_MODULE[3])))
        {
            /* In .data */
            if ((inFileOff + bytesRead) >= (FIPS_MOCANA_MODULE[2] + FIPS_MOCANA_MODULE[3]))
            {
                /* Only use these bytes in buffer */
                ubyte4 move = bytesRead;
                bytesRead = (FIPS_MOCANA_MODULE[2] + FIPS_MOCANA_MODULE[3]) - inFileOff;
                inFileOff += move;
            }
            else
            {
                inFileOff += (ubyte4)bytesRead;
            }
        }
        else if ((FIPS_MOCANA_MODULE[3] > 0) &&
            ((inFileOff + bytesRead) > FIPS_MOCANA_MODULE[2]) &&
            (inFileOff < (FIPS_MOCANA_MODULE[2] + FIPS_MOCANA_MODULE[3])))
        {
            bShift = FIPS_MOCANA_MODULE[2] - inFileOff;
            inFileOff += (ubyte4)bytesRead;
            bytesRead = bytesRead - bShift;
            if (bytesRead > FIPS_MOCANA_MODULE[3])
            {
                bytesRead = FIPS_MOCANA_MODULE[3];
            }
        }
        else
        {
            inFileOff += (ubyte4)bytesRead;
            continue; /* Ignore */
        }

        if (OK > (status = HmacUpdate(MOC_HASH(hwAccelCtx) pHMACCtx, bdata + bShift, bytesRead)))
            goto exit;
    }

    if (OK > (status = HmacFinal(MOC_HASH(hwAccelCtx) pHMACCtx, hashReturn)))
        goto exit;

exit:
    HmacDelete(MOC_HASH(sbyte4 hwAccelCtx) &pHMACCtx);

    if (fbin)
    {
        fclose(fbin);
    }
    return status;
}
#endif /*__ENABLE_DIGICERT_FIPS_STATIC_INTEG_MODULE_TEST__ */

/*---------------------------------------------------------------------------*/

#else   /* Not: __ENABLE_DIGICERT_FIPS_STATIC_INTEG_TEST__ */
MOC_EXTERN MSTATUS
FIPS_INTEG_TEST_hash_load(ubyte* hashReturn, const char* optionalSigFileName)
{
    MSTATUS status = OK;

#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
    FILE*   fhash = NULL;
#else
    sbyte4  fhash = 0;
#endif
    ubyte   buffer = 0;
    ubyte   indexWrite = 0;
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
    ubyte4  bytesRead;
#endif
    ubyte   indexBuf = 0;
    ubyte   hBuffer[SHA256_RESULT_SIZE*2];


#if defined( __RTOS_WIN32__ ) || defined(__RTOS_WINCE__)
    if (optionalSigFileName)
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
        fhash = fopen( optionalSigFileName, "rb");
#else
        fhash = DIGI_CRYPTO_fipsSelfTestInit((ubyte *)optionalSigFileName);
#endif
    }
    else
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
        TCHAR modulePath[_MAX_PATH+5]; /* add a little buffer to the buffer. 5 should be enough (.sig) */
        HMODULE hModule;
        TCHAR* lastBS;

        hModule = GetModuleHandle(DLL_NAME);

        if (!GetModuleFileName( hModule, modulePath, _MAX_PATH))
        {
            FIPS_TESTLOG(505, "FIPS_INTEG: GetModuleFileName failed");
            status = ERR_FILE_OPEN_FAILED;
            goto exit;
        }

        /* signature file is mss_dll.dll.sig */
        /* don't bother with splitpath */
        lastBS = _tcsrchr( modulePath, _T('\\'));
        if (lastBS)
        {
            size_t signatureFileLen = _tcslen(SIGNATURE_FILE);
            if (lastBS + 2 + signatureFileLen - modulePath > _MAX_PATH + 5)
            {
                FIPS_TESTLOG(506, "FIPS_INTEG: Internal Error -- Constant");
                status = ERR_FILE_OPEN_FAILED;
                goto exit;
            }

            memcpy(lastBS+1, SIGNATURE_FILE, (1+signatureFileLen)*sizeof(TCHAR));
            fhash = _tfopen(modulePath, _T("rt"));
        }
#else /* WIN32 Kernel Space */
        fhash = DIGI_CRYPTO_fipsSelfTestInit("\\SystemRoot\\system32\\drivers\\moc_crypto.sys.sig");
#endif /* !__ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__ */
    }
#else
    /* other OSes like linux uses an absolute file name */
    if (optionalSigFileName)
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
        fhash = fopen( optionalSigFileName, "rb");
#else
        fhash = DIGI_CRYPTO_fipsSelfTestInit((ubyte *)optionalSigFileName);
#endif
    }
    else
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
        fhash = fopen( FIPS_INTEG_TEST_HASH_FILENAME, "r");
#else
        fhash = DIGI_CRYPTO_fipsSelfTestInit( FIPS_INTEG_TEST_HASH_FILENAME);
#endif
    }
#endif

    if (0 == fhash)
    {
        FIPS_TESTLOG(507, "FIPS_INTEG: Hash file load error!" );
        if (optionalSigFileName)
        {
            FIPS_TESTLOG_FMT(508, "%s", optionalSigFileName );
        }
        else
        {
            FIPS_TESTLOG_FMT(509, "%s", FIPS_INTEG_TEST_HASH_FILENAME );
        }
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
    bytesRead = (ubyte4)fread(hBuffer, 1, SHA256_RESULT_SIZE*2, fhash);
    if (bytesRead < SHA256_RESULT_SIZE*2)
    {
        status = ERR_FILE_READ_FAILED;
        goto exit;
    }
#else
    DIGI_CRYPTO_fipsSelfTestUpdate( fhash, hBuffer, SHA256_RESULT_SIZE*2 );
#endif
    while( SHA256_RESULT_SIZE > indexWrite )
    {
        buffer = hBuffer[indexBuf];
        if( ('0' <= buffer) && ('9' >= buffer) )
            hashReturn[indexWrite] = (buffer - '0') * 16;
        if( ('A' <= buffer) && ('F' >= buffer) )
            hashReturn[indexWrite] = (buffer - ('A' - 10)) * 16;
        if( ('a' <= buffer) && ('f' >= buffer) )
            hashReturn[indexWrite] = (buffer - ('a' - 10)) * 16;

        indexBuf++;
        buffer = hBuffer[indexBuf];

        if( ('0' <= buffer) && ('9' >= buffer) )
            hashReturn[indexWrite] += buffer - '0';
        if( ('A' <= buffer) && ('F' >= buffer) )
            hashReturn[indexWrite] += buffer - ('A' - 10);
        if( ('a' <= buffer) && ('f' >= buffer) )
            hashReturn[indexWrite] += buffer - ('a' - 10);

        indexBuf++;
        indexWrite++;
    }

exit:
    if ( fhash)
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
        fclose(fhash);
#else
        DIGI_CRYPTO_fipsSelfTestFinal( fhash );
#endif
    }

    return status;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_INTEG_TEST_hash_bin( ubyte* hashReturn, const char* optionalBinFileName)
{
    return FIPS_INTEG_TEST_hash_binSkip(hashReturn, optionalBinFileName, 0);
}

static MSTATUS
DIGI_CRYPTO_fipsGetLibPath(char *pOut, ubyte4 outSize)
{
#ifdef __DIGICERT_LINUX_SHARED_LIBRARY__
   /* Look for path in '/proc/self/maps' */
   MSTATUS status = ERR_NOT_FOUND;
   FILE *fdPr = NULL;
   char lBuf[512];
   char *pNext = NULL;
   char *myAddr = (char*)DIGI_CRYPTO_fipsGetLibPath;
   char *pBegin, *pEnd;

   fdPr = fopen("/proc/self/maps", "r");
   if (NULL == fdPr)
   {
      return ERR_RTOS;
   }

   while(1)
   {
      if (NULL == fgets(lBuf, sizeof(lBuf), fdPr))
         break;

      pBegin = (char*)strtoull(lBuf, &pNext, 16);
      pEnd   = (char*)strtoull(pNext+1, NULL, 16);

      if ((pBegin <= myAddr) && (myAddr <= pEnd))
      {
         char *path = strrchr(lBuf, ' ');
         if (NULL != path)
         {
            if (DIGI_STRLEN(path+1) < outSize)
            {
               DIGI_MEMCPY(pOut, path+1, DIGI_STRLEN(path+1));
	       pOut[DIGI_STRLEN(path+1)-1] = '\0';
	       status = OK;
            }
            else
            {
	       status = ERR_BUFFER_TOO_SMALL;
            }
         }
         break;
      }
   }
   fclose(fdPr);

   return status;
#else
   return ERR_NOT_IMPLEMENTED;
#endif
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_INTEG_TEST_hash_binSkip( ubyte* hashReturn, const char* optionalBinFileName, ubyte4 offset)
{
    MSTATUS status = OK;

    ubyte4 keyLen = 117;
    ubyte key[] = {
        0xd6,0xc3,0x44,0xd5,0x0f,0x0d,0xc1,0x88,
        0xbb,0xf8,0x74,0x59,0xcc,0x7e,0xf8,0xc7,
        0xd2,0xbc,0x8b,0x6a,0x14,0xb0,0xc0,0xda,
        0xe0,0x41,0x74,0xcc,0x1f,0x7f,0x02,0x7e,
        0x2c,0x2d,0xbb,0x56,0xe7,0x7d,0x90,0xc6,
        0x05,0x1a,0x12,0x72,0xaa,0x6b,0x9d,0x95,
        0x39,0x17,0xcf,0xa0,0x6b,0xc4,0x3f,0x25,
        0x9e,0x25,0x6c,0xf4,0x70,0x33,0xf4,0x84,
        0x8d,0xba,0x07,0x94,0xc5,0x18,0x1a,0x11,
        0x62,0x41,0xe0,0x3b,0xb8,0x07,0x76,0x04,
        0xfd,0x99,0xde,0xb8,0x5b,0x49,0xae,0xe3,
        0x44,0x92,0x09,0x70,0x06,0x59,0xcf,0x0e,
        0x9f,0x73,0x11,0xd8,0xd2,0x68,0xc8,0x34,
        0x7a,0x76,0xc6,0xfb,0x1f,0xd9,0xec,0xdb,
        0xc7,0x4a,0x9e,0xfa,0x0e
    };

    HMAC_CTX* pHMACCtx = NULL;
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
    FILE*  fbin = NULL;
#else
    sbyte4 fbin = 0;
#endif
#define BDATA_READ_SIZE 64
    ubyte  bdata[BDATA_READ_SIZE];
    sbyte4 bytesRead;


#if defined (__RTOS_WIN32__) || defined(__RTOS_WINCE__)

    if (optionalBinFileName)
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
        fbin = fopen( optionalBinFileName, "rb");
#else
        fbin = DIGI_CRYPTO_fipsSelfTestInit((ubyte *)optionalBinFileName);
#endif
    }
    else
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
        TCHAR modulePath[_MAX_PATH+5]; /* add a little buffer to the buffer. 5 should be enough (.sig) */
        HMODULE hModule;

        hModule = GetModuleHandle(DLL_NAME);

        if (!GetModuleFileName( hModule, modulePath, _MAX_PATH))
        {
            DEBUG_PRINTNL( DEBUG_CRYPTO, (sbyte *) "FIPS_INTEG: GetModuleFileName failed");
            status = ERR_FILE_OPEN_FAILED;
            goto exit;
        }

        fbin = _tfopen(modulePath, _T("rb"));
#else
        fbin = DIGI_CRYPTO_fipsSelfTestInit("\\SystemRoot\\system32\\drivers\\moc_crypto.sys");
#endif
    }
#elif defined(__RTOS_WINCE__) /* defined (__RTOS_WIN32__) || defined(__RTOS_WINCE__) */

    TCHAR modulePath[_MAX_PATH+5]; /* add a little buffer to the buffer. 5 should be enough (.sig) */
    HMODULE hModule;

    hModule = GetModuleHandle(_T("mss_ce_dll"));

    if (!GetModuleFileName( hModule, modulePath, _MAX_PATH))
    {
        FIPS_TESTLOG(510, "FIPS_INTEG: GetModuleFileName failed");
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    fbin = _tfopen(modulePath, _T("rb"));

#else /* defined(__RTOS_WINCE__) */

    if (optionalBinFileName)
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
        fbin = fopen( optionalBinFileName, "rb");
#else
        fbin = DIGI_CRYPTO_fipsSelfTestInit((ubyte *)optionalBinFileName);
#endif
    }
    else
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
        ubyte pBuf[512];

        if (OK == DIGI_CRYPTO_fipsGetLibPath((char*)pBuf, sizeof(pBuf)))
        {
           FIPS_TESTLOG_FMT(511, "FIPS_INTEG: LibPath:'%s'", pBuf);
           fbin = fopen(pBuf, "rb");
        }
        else
        {
           fbin = fopen(FIPS_INTEG_TEST_BINARY_FILENAME, "rb");
        }
#else
        fbin = DIGI_CRYPTO_fipsSelfTestInit( FIPS_INTEG_TEST_BINARY_FILENAME);
#endif
    }
#endif

    if (0 == fbin)
    {
        FIPS_TESTLOG(512, "FIPS_INTEG: Binary file load error!" );
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    /* skip first 'section' of <offset> bytes, if requested */
    if (0 < offset)
    {
       ubyte4 blk = (offset>BDATA_READ_SIZE)?BDATA_READ_SIZE:offset;
       ubyte4 total = 0;
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
       while (0 < (bytesRead = (ubyte4)fread(bdata, 1, blk, fbin)))
#else
       while (0 < (bytesRead = DIGI_CRYPTO_fipsSelfTestUpdate(fbin, bdata, blk)))
#endif
       {
	 total += bytesRead;
	 if (total >= offset)
	   break; /* done */

	 /* Check if near end */
	 if ((offset - total) < blk)
	   blk = offset - total;
       }
    }
    
    if (OK > (status = HmacCreate( MOC_HASH(hwAccelCtx) &pHMACCtx, &SHA256Suite )))
       goto exit;

    if (OK > (status = HmacKey( MOC_HASH(hwAccelCtx) pHMACCtx, key, keyLen )))
        goto exit;

    DIGI_MEMSET(bdata, 0x00, BDATA_READ_SIZE);

#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
    /* while( EOF != (intVal = fgetc(fbin)) )*/
    while (0 < (bytesRead = (ubyte4)fread(bdata, 1, BDATA_READ_SIZE, fbin)))
#else
    while (0 < (bytesRead = DIGI_CRYPTO_fipsSelfTestUpdate(fbin, bdata, BDATA_READ_SIZE)))
#endif
    {
        if (OK > (status = HmacUpdate( MOC_HASH(hwAccelCtx) pHMACCtx, bdata, bytesRead )))
            goto exit;
    }

    if (OK > (status = HmacFinal( MOC_HASH(hwAccelCtx) pHMACCtx, hashReturn )))
        goto exit;

exit:
    HmacDelete( MOC_HASH(sbyte4 hwAccelCtx) &pHMACCtx );

    if ( fbin)
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_KERNEL_MODULE_FIPS__
        fclose(fbin);
#else
        DIGI_CRYPTO_fipsSelfTestFinal( fbin );
#endif
    }

    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_INTEG_TEST_hash_memory(ubyte* hashReturn, ubyte* data, ubyte4 dataLen)
{
    MSTATUS status = OK;

    ubyte4 keyLen = 117;
    ubyte key[] = {
        0xd6,0xc3,0x44,0xd5,0x0f,0x0d,0xc1,0x88,
        0xbb,0xf8,0x74,0x59,0xcc,0x7e,0xf8,0xc7,
        0xd2,0xbc,0x8b,0x6a,0x14,0xb0,0xc0,0xda,
        0xe0,0x41,0x74,0xcc,0x1f,0x7f,0x02,0x7e,
        0x2c,0x2d,0xbb,0x56,0xe7,0x7d,0x90,0xc6,
        0x05,0x1a,0x12,0x72,0xaa,0x6b,0x9d,0x95,
        0x39,0x17,0xcf,0xa0,0x6b,0xc4,0x3f,0x25,
        0x9e,0x25,0x6c,0xf4,0x70,0x33,0xf4,0x84,
        0x8d,0xba,0x07,0x94,0xc5,0x18,0x1a,0x11,
        0x62,0x41,0xe0,0x3b,0xb8,0x07,0x76,0x04,
        0xfd,0x99,0xde,0xb8,0x5b,0x49,0xae,0xe3,
        0x44,0x92,0x09,0x70,0x06,0x59,0xcf,0x0e,
        0x9f,0x73,0x11,0xd8,0xd2,0x68,0xc8,0x34,
        0x7a,0x76,0xc6,0xfb,0x1f,0xd9,0xec,0xdb,
        0xc7,0x4a,0x9e,0xfa,0x0e
    };

    HMAC_CTX* pHMACCtx = NULL;
    
    if (OK > (status = HmacCreate( MOC_HASH(hwAccelCtx) &pHMACCtx, &SHA256Suite )))
       goto exit;

    if (OK > (status = HmacKey( MOC_HASH(hwAccelCtx) pHMACCtx, key, keyLen )))
        goto exit;

    if (OK > (status = HmacUpdate( MOC_HASH(hwAccelCtx) pHMACCtx, data, dataLen )))
        goto exit;

    if (OK > (status = HmacFinal( MOC_HASH(hwAccelCtx) pHMACCtx, hashReturn )))
        goto exit;

exit:
    HmacDelete( MOC_HASH(sbyte4 hwAccelCtx) &pHMACCtx );

    return status;
}

#endif  /* __ENABLE_DIGICERT_FIPS_STATIC_INTEG_TEST__ */


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_FIPS_INTEG_TEST__) && \
    defined(__ENABLE_DIGICERT_FIPS_STATIC_INTEG_TEST__)
/* this section places ascii tags into section to support the tampering test */
const unsigned int FIPS_OPS_TEST_CONST[] =
        /* "FIPS_OPS_TEST_DATA"; */
{
        0x53504946, 0x53504f5f, 0x5345545f, 0x41445f54, 0x00004154
/*        FIPS        _OPS        _TES         T_DA         TA     */
};

#ifndef __RTOS_INTEGRITY__
void fips_ops_test_code()
{
    asm volatile  (  ".ascii \"FIPS_OPS_TEST_TEXT\" " );
}
#endif
#endif /* defined(__ENABLE_DIGICERT_FIPS_INTEG_TEST__) ... */

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
FIPS_INTEG_TESTO(ubyte* pOut, ubyte4 outLen)
{
    MSTATUS status = OK;

#ifdef __ENABLE_DIGICERT_FIPS_STATIC_INTEG_TEST__
    int i;
#endif
    ubyte fileHash[SHA256_RESULT_SIZE];
    ubyte binHash[SHA256_RESULT_SIZE];
    sbyte4 cmpRes = 0;

#ifdef __ENABLE_DIGICERT_FIPS_STATUS_TIMING_MESSAGES__
    static volatile ubyte4 teststarttime, testendtime;
#endif /* __ENABLE_DIGICERT_FIPS_STATUS_TIMING_MESSAGES__ */

    FIPS_TESTLOG(513, "FIPS_INTEG: Testing..." );
#ifdef __ENABLE_DIGICERT_FIPS_STATUS_TIMING_MESSAGES__
    teststarttime = RTOS_getUpTimeInMS();
    FIPS_TESTLOG_FMT(514, "S-Time= %d", teststarttime);
#endif /* __ENABLE_DIGICERT_FIPS_STATUS_TIMING_MESSAGES__ */

#ifdef __ENABLE_DIGICERT_FIPS_STATIC_INTEG_TEST__
    /****************************************/
    /* Stamped in hash.                     */
    /****************************************/
    /* Load hash answer from stamped in val */
    /****************************************/
    if (OK > (status = FIPS_INTEG_TEST_hash_locate( fileHash )))
        goto exit;
#ifndef __ENABLE_DIGICERT_FIPS_STATIC_INTEG_MODULE_TEST__
    /**********************************************/
    /* Calculate hash over text & const           */
    /* sections from in-memory. (for static libs) */
    /**********************************************/
    if (OK > (status = FIPS_INTEG_TEST_hash_inplace(binHash)))
    goto exit;
#else
    /**********************************************/
    /* Calculate hash over text & const           */
    /* sections from lib file (parse PE sections) */
    /**********************************************/
    if (OK > (status = FIPS_INTEG_TEST_hash_file_segments(binHash)))
        goto exit;
#endif /* __ENABLE_DIGICERT_FIPS_STATIC_INTEG_MODULE_TEST__ */

#if defined(__ENABLE_DIGICERT_FIPS_DBG_STATIC_HASH__)
    if (FIPS_TESTLOG_ENABLED)
    {
        d_ndx = 0;
        for (i=0; i<SHA256_RESULT_SIZE; ++i) {
            sprintf(&(dmsgbuff[d_ndx]), "%02X", binHash[i]);
            d_ndx +=2;
	}
	FIPS_TESTLOG_FMT(515, "HASH: %s", dmsgbuff);
	DIGI_MEMSET((ubyte *)dmsgbuff, 0x00, DMSGBUFF_SIZE);
    }
#endif

#else /*  __ENABLE_DIGICERT_FIPS_STATIC_INTEG_TEST__ */
    if (OK > (status = FIPS_INTEG_TEST_hash_load( fileHash, sCurrRuntimeConfig.sigPath )))
        goto exit;

    if (OK > (status = FIPS_INTEG_TEST_hash_bin( binHash, sCurrRuntimeConfig.libPath )))
        goto exit;
#endif

    if (OK != DIGI_CTIME_MATCH( fileHash, binHash, SHA256_RESULT_SIZE, &cmpRes ))
    {
        FIPS_TESTLOG(516, "FIPS_INTEG: FAILED!" );
        status = ERR_FIPS_INTEGRITY_FAILED;
        goto exit;
    }

    if (0 != cmpRes)
    {
        FIPS_TESTLOG(517, "FIPS_INTEG: FAILED!" );
        status = ERR_FIPS_INTEGRITY_FAILED;
        goto exit;
    }

    FIPS_TESTLOG(518, "FIPS_INTEG:\t\t\tPASS" );

    if ((NULL != pOut) && (0 < outLen))
    {
        if (outLen < sizeof(fileHash))
	{
            DIGI_MEMCPY(pOut, fileHash, outLen);
	}
	else
	{
            DIGI_MEMCPY(pOut, fileHash, sizeof(fileHash));
            DIGI_MEMSET(pOut+sizeof(fileHash), 0x00, outLen-sizeof(fileHash));
	}
    }
    
exit:
    sCurrStatus.integrityTestStatus = status;

    /* Zeroize */
    DIGI_MEMSET(fileHash, 0x00, sizeof(fileHash));
    DIGI_MEMSET(binHash, 0x00, sizeof(binHash));

    FIPS_TESTLOG(519, "FIPS_INTEG:\t\t\tFinished" );
#ifdef __ENABLE_DIGICERT_FIPS_STATUS_TIMING_MESSAGES__
    testendtime = RTOS_getUpTimeInMS();
    FIPS_TESTLOG_FMT(520, "E-Time = %d  Elapsed (mil) = %d",
		     testendtime, testendtime-teststarttime);
#endif /* __ENABLE_DIGICERT_FIPS_STATUS_TIMING_MESSAGES__ */

    return status;
}

MOC_EXTERN MSTATUS
FIPS_INTEG_TEST(void)
{
    return FIPS_INTEG_TESTO(NULL, 0);
}

#endif /* defined(__ENABLE_DIGICERT_FIPS_INTEG_TEST__) */


#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

