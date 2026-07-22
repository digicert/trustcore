/*
 * fips_entropy.c
 *
 * FIPS Entropy Source connection implementation
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

/**
@file       fips_entropy.c
@brief      C source code for the FIPS Entropy access API.

@filedoc    fips_entropy.c
*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips.h"
#include "../crypto/fips_priv.h"
#endif

#include "../crypto/fips_entropy.h"
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips_entropy_priv.h"
#endif

#ifdef __FIPS_ALWAYS_ADD_ENTROPY_NIST_RNG__
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>

#ifdef __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LKM__
#define FIPS_ENTROPY_FROM_FD
#define ENTROPY_SRC_STRING "JENT_KCAPI"
#else
#ifndef __DISABLE_DIGICERT_FIPS_LINUX_RAND__
#define FIPS_ENTROPY_FROM_FD
#define ENTROPY_SRC_STRING "LINUX"
#endif
#endif
#ifdef __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LIB__
#include <jitterentropy.h>
#define ENTROPY_SRC_STRING "JENT_LIB"
#endif

#ifdef __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LKM__
/* Needed to connect to RNG */
#include <sys/socket.h>
#include <linux/if_alg.h>
#endif

#ifndef FIPS_ALWAYS_ADD_ENTROPY_NIST_SIZE
#define FIPS_ALWAYS_ADD_ENTROPY_NIST_SIZE 48
#endif

#define LINUX_RAND_FILE "/dev/urandom"

static const char *fips_ent_src = ENTROPY_SRC_STRING;

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
static int read_fail = 0;
#endif
/*-------------------------------------------------------------------------*/

#ifdef __KERNEL__
#define PRINTDBG printk
#else
#define PRINTDBG printf
#endif

/*------------------------------------------------------------------*/
/* 'Hidden' structure for the context */
struct FIPS_ENTROPY_st
{
	intBoolean inited;
#ifdef	FIPS_ENTROPY_FROM_FD
	int        entropyFd;
	ubyte4     retries_allowed;
#endif
	const char *entropySrc;
	intBoolean zeroized;
};

/*------------------------------------------------------------------*/
/* Internal Socket-supplier related functions */
/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LKM__
static MSTATUS
FD_ENT_initJEntEntropyConnection(int fd)
{
    MSTATUS       status = OK;
    struct stat   mystatbuf = {0};
    struct msghdr msg;
    struct iovec  iov;
    ubyte         buf[16] __attribute__((aligned(8))) = { 0 };
    const ubyte   zero[16] = { 0 };
    sbyte4        result = -1;
    size_t        iovlen = 1;
    ssize_t       ret = 0;

    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);

    /* Read message with random data */
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = iovlen;
    ret = recvmsg(fd, &msg, 0);
    if (ret < 0)
    {
        PRINTDBG("Error recv KCAPI msg: %d\n", errno);
        status = ERR_FALSE;
        goto exit;
    }

    /* All zeros is not valid */
    DIGI_MEMCMP(buf, zero, sizeof(buf), &result);
    if (0 == result)
    {
        PRINTDBG("Empty KCAPI msg!\n");
        status = ERR_FALSE;
        goto exit;
    }
    /* Clear */
    DIGI_MEMSET(buf, 0x00, sizeof(buf));

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LKM__ */

static MSTATUS
FD_ENT_openFileDescriptor(int *outFd, const char **pSrc)
{
    MSTATUS status = ERR_FILE_OPEN_FAILED;

    int     fd = -1;
    int     sock_fd = -1;

#ifdef __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LKM__
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "rng",
        .salg_name = "jitterentropy_rng"
    };

    sock_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);

    if (sock_fd >= 0)
    {
        bind(sock_fd, (struct sockaddr *)&sa, sizeof(sa));
        fd = accept(sock_fd, NULL, 0);
        if (fd >= 0)
        {
            /* Trial run to confirm the API is working */
            if (FD_ENT_initJEntEntropyConnection(fd) != OK)
            {
                close(fd);
                fd = -1;
            }
        }
        close(sock_fd);
        *pSrc = fips_ent_src;
    }
#endif /* __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LKM__ */

#ifndef __DISABLE_DIGICERT_FIPS_LINUX_RAND__
    /* Use Linux RAND pseudo device, if no other option available */
    if (fd < 0)
    {
        fd = open(LINUX_RAND_FILE, O_RDONLY);
        *pSrc = fips_ent_src;
    }
#endif

    /* success */
    if (0 <= fd)
    {
       *outFd = fd;
       fd = -1;
       status = OK;
    }
    else
    {
       *pSrc = "<FAILED>";
    }

exit:
   if (0 <= fd)
   {
      close(fd);
   }
   return status;
}

static MSTATUS
FD_ENT_readFromFileDescriptor(int fd, const char* src, ubyte4 retry_limit, ubyte *pData, ubyte4 outLen)
{
    MSTATUS status = ERR_FALSE;
    ubyte4  remLen = outLen;
    ubyte4  offs = 0;
    sbyte4  rlen;
    ubyte4  tries = 0;
    int     i = 0;

    if ((pData == NULL) || (fd < 0))
    {
    	goto exit;
    }

    while (remLen > 0)
    {
        rlen = read(fd, pData+offs, remLen);
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
        if (read_fail < 0)
            rlen = read_fail;
        else if (read_fail > 0)
        {
            rlen = -EAGAIN;
            read_fail--;
        }
#endif
        if (rlen <= 0)
        {
            if (rlen != -EAGAIN)
            {
                status = ERR_FILE_READ_FAILED;
                goto exit;
            }
            if ((retry_limit > 0) && (++tries > retry_limit))
            {
                status = ERR_FILE_READ_FAILED;
                goto exit;
            }

            /* Retry */
            offs = 0;
            remLen = outLen;
            continue;
        }
        remLen -= rlen;
        offs += rlen;
    }
    /* Success */
    status = OK;

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    DEBUG_CONSOLE_printf("FIPS_ENTROPY: Read %d entropy bits from %s.\n", outLen*8, src);
#endif

exit:
    return status;
}

/*------------------------------------------------------------------*/
/* Internal JENT-Lib related functions */
/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LIB__

/* We only want one Jent entropy collector instance per instance of the crypto-module */
static RTOS_MUTEX ec_mutex;
static struct rand_data *jent_ec_nostir = NULL;

#define JENTLIB_DEFAULT_OSR 0

/* This should be called during the constructor. It will create the mutex, but doesn't actually allocate anything */
static MSTATUS
JL_ENT_initJEntEntropyLib(void)
{
    MSTATUS status = OK;

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    DEBUG_CONSOLE_printf("FIPS_ENTROPY: JL_ENT_initJEntEntropyLib(%s)\n", fips_ent_src);
#endif
    status = RTOS_mutexCreate( &ec_mutex, 0, 0);

    return status;
}

static MSTATUS
JL_ENT_allocJEntEntropyLibCtx(struct rand_data **ppJent_ctx, const char **ppSrc)
{
    MSTATUS status = OK;
	unsigned int  osr = JENTLIB_DEFAULT_OSR;
	unsigned int  flags = 0;
    struct rand_data *pjctx = NULL;

    if ( OK > ( status = RTOS_mutexWait(ec_mutex) ) )
    	goto exit;

    if (NULL == jent_ec_nostir)
    {
    	flags |= JENT_FORCE_FIPS;

    	pjctx = jent_entropy_collector_alloc(osr, flags);
    	if (NULL == pjctx)
    	{
            PRINTDBG("Error : jent_entropy_collector_alloc returned NULL \n");
            *ppSrc = "<FAILED>";
    		status = ERR_INTERNAL_ERROR;
    		goto exit;
    	}
    	*ppSrc = fips_ent_src;
    	*ppJent_ctx = pjctx;
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_CONSOLE_printf("FIPS_ENTROPY: JL_ENT_allocJEntEntropyLibCtx(%s) (new)\n", *ppSrc);
#endif
    }
    else
    {
    	*ppSrc = fips_ent_src;
    	*ppJent_ctx = jent_ec_nostir; /* Just return the ptr that already exists */
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_CONSOLE_printf("FIPS_ENTROPY: JL_ENT_allocJEntEntropyLibCtx(%s) (reuse)\n", *ppSrc);
#endif
    }

exit:
    RTOS_mutexRelease(ec_mutex);
    return status;
}

static MSTATUS
JL_ENT_readFromJEntEntropyLib(struct rand_data **ppJent_ctx, const char* src, ubyte *pData, ubyte4 outLen)
{
    MSTATUS status = OK;
    ssize_t numread = 0;

    if ( OK > ( status = RTOS_mutexWait(ec_mutex) ) )
    	goto exit;

    /* Calling the safe version because it will automatically attempt to recover from Health failures. If this function fails, just return an error */
    numread = jent_read_entropy_safe(ppJent_ctx, (char *)pData, (size_t)outLen);
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
    if (read_fail < 0)
        numread = read_fail;
#endif
    RTOS_mutexRelease(ec_mutex);

    if (numread <= 0)
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        DEBUG_CONSOLE_printf("FIPS_ENTROPY: Failed reading %ld entropy bits from %s ret=%ld\n", outLen, src, numread);
#endif
        PRINTDBG("Error : jent_read_entropy returned ERROR: %ld\n",numread);

        switch (numread)
        {
            case -1: /* *	-1	entropy_collector is NULL */
                status = ERR_NULL_POINTER;
                break;
            case -4: /* *	-4	The timer cannot be initialized */
                status = ERR_INTERNAL_ERROR;
                break;

	    /* Health checks failed */
            case -2: /* *	-2	RCT (Repetition Count Test) test failed */
            case -3: /* *	-3	APT (Adaptive Proportion Test) test failed */
            case -5: /* *	-5	LAG failure */
                status = ERR_FIPS_RNG_FAIL;
                break;
            default:
                status = ERR_INTERNAL_ERROR;
                break;
        }

        goto exit;
    }
    /* Success */

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    DEBUG_CONSOLE_printf("FIPS_ENTROPY: Read %d entropy bits from %s.\n", numread*8, src);
#endif

exit:
	return status;
}

static MSTATUS
JL_ENT_freeJEntEntropyLibCtx(struct rand_data **pJent_ctx)
{
    MSTATUS status = OK;

    if ( OK > ( status = RTOS_mutexWait(ec_mutex) ) )
    	goto exit;

    jent_entropy_collector_free(*pJent_ctx);
    *pJent_ctx = NULL;

    RTOS_mutexRelease(ec_mutex);

 exit:
    return status;
}

#endif /* __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LIB__ */

/*------------------------------------------------------------------*/
/* External functions */
/*------------------------------------------------------------------*/
MOC_EXTERN MSTATUS FIPS_ENTROPY_initExternalEntropyConstructor(void)
{
    MSTATUS status = ERR_MOCANA_NOT_INITIALIZED;

#ifdef __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LIB__
    status = JL_ENT_initJEntEntropyLib();
#endif /* __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LIB__ */

    return status;
}

MOC_EXTERN MSTATUS
FIPS_ENTROPY_allocateExternalEntropy(FIPS_ENTROPY_ctx **ppCtx)
{
   MSTATUS status = ERR_NULL_POINTER;

   if (NULL == ppCtx)
   {
      goto exit;
   }

   status = DIGI_CALLOC((void**)ppCtx, 1, sizeof(struct FIPS_ENTROPY_st));

exit:
   return status;
}

MOC_EXTERN MSTATUS
FIPS_ENTROPY_initExternalEntropy(FIPS_ENTROPY_ctx* pCtx, ubyte4 retries_allowed)
{
    MSTATUS status = ERR_NULL_POINTER;
    const char *src = NULL;

    if (NULL == pCtx)
    {
        goto exit;
    }

    status = ERR_FALSE;
    if (pCtx->inited)
    {
        goto exit;
    }

#ifdef FIPS_ENTROPY_FROM_FD
   int fd;

   pCtx->entropyFd = -1;

   /* Generic open of file */
   status = FD_ENT_openFileDescriptor(&fd, &src);
   if (OK != status)
   {
      goto exit;
   }
   pCtx->entropyFd = fd;
   pCtx->entropySrc = src;
   pCtx->retries_allowed = retries_allowed;
#endif

#ifdef __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LIB__
   status = JL_ENT_allocJEntEntropyLibCtx(&jent_ec_nostir, &src);
   if (OK != status)
   {
      goto exit;
   }
   pCtx->entropySrc = src;
#endif

   /* Success */
   pCtx->inited = TRUE;

exit:
   return status;
}

MOC_EXTERN MSTATUS
FIPS_ENTROPY_readExternalEntropy(FIPS_ENTROPY_ctx *pCtx, ubyte *pData, ubyte4 outLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
    {
        goto exit;
    }
    status = ERR_ENTROPY_UNINITIALIZED;
    if (!pCtx->inited)
    {
       goto exit;
    }
    status = ERR_INTERNAL_ERROR;
    if (pCtx->zeroized)
    {
       goto exit;
    }

#ifdef FIPS_ENTROPY_FROM_FD
    /* Read data from file */
    status = FD_ENT_readFromFileDescriptor(pCtx->entropyFd, pCtx->entropySrc, pCtx->retries_allowed,
                                           pData, outLen);
#endif /* FIPS_ENTROPY_FROM_FD */

#ifdef __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LIB__

    /* Read data from JENT-LIB */
    status = JL_ENT_readFromJEntEntropyLib(&jent_ec_nostir, pCtx->entropySrc, pData, outLen);
    /* If the safe version fails, just return the mapped error to the DRBG caller. */

#endif /* __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LIB__ */

exit:
    return status;
}

MOC_EXTERN MSTATUS
FIPS_ENTROPY_zeroizeExternalEntropy(void)
{
#ifdef __ZEROIZE_TEST__
    FIPS_PRINT("\nFIPS_ENTROPY - Before Zeroization\n");
#endif

#ifdef FIPS_ENTROPY_FROM_FD
    /* Nothing to do */
#endif

#ifdef __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LIB__
    JL_ENT_freeJEntEntropyLibCtx(&jent_ec_nostir);
    jent_ec_nostir = NULL;
    RTOS_mutexFree(&ec_mutex);
#endif /* __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LIB__ */

#ifdef __ZEROIZE_TEST__
    FIPS_PRINT("\nFIPS_ENTROPY - After Zeroization\n");
#endif
    return OK;
}

MOC_EXTERN MSTATUS
FIPS_ENTROPY_freeExternalEntropy(FIPS_ENTROPY_ctx **ppCtx)
{
    if (NULL == ppCtx || NULL == *ppCtx)
    {
        return ERR_NULL_POINTER;
    }
    else 
    {
#ifdef FIPS_ENTROPY_FROM_FD
        if((*ppCtx)->entropyFd > 0)
            close((*ppCtx)->entropyFd);
#endif

#ifdef __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LIB__
    /* Nothing to do here */
#endif /* __ENABLE_DIGICERT_FIPS_JITTERENTROPY_LIB__ */

    }

    return DIGI_FREE((void**)ppCtx);
}

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
#include "../crypto/fips_entropy_priv.h"

static void FIPS_ENTROPY_triggerFail(int code)
{
    read_fail = code;
}

static FIPS_entry_fct entropy_table[] = {
    { ENTROPY_TRIGGER_FAIL_F_ID,    (s_fct*)FIPS_ENTROPY_triggerFail},
    { -1, NULL } /* End of array */
};

MOC_EXTERN const FIPS_entry_fct* FIPS_ENTROPY_getPrivileged()
{
    if (OK == FIPS_isTestMode())
        return entropy_table;

    return NULL;
}
#endif

#endif /* __FIPS_ALWAYS_ADD_ENTROPY_NIST_RNG__ */
