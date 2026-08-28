/*************************************************************************
 * File:        moc_crypto.c
 * Created:     Mon June 15th 2009
 * Description:
 *
 * Copyright (C) Mocana Corp 2006-2009. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Linking this program statically or dynamically with other modules is
 * making a combined work based on this program.  Thus, the terms and
 * conditions of the GNU General Public License cover the whole combination.
 *
 * As a special exception, the copyright holders of this program give you
 * permission to link this program with independent modules that
 * communicate with this program solely through the IPSEC_ interface,
 * regardless of the license terms of these independent modules, and to
 * copy and distribute the resulting combined work under terms of your
 * choice, provided that every copy of the combined work is accompanied by
 * a complete copy of the source code of this program (the version of this
 * program used to produce the combined work), being distributed under the
 * terms of the GNU General Public License plus this exception.
 * An independent module is a module which is not derived from or based on
 * this program.
 *
 * Note that people who make modified versions of this program are not
 * obligated to grant this special exception for their modified versions;
 * it is their choice whether to do so.  The GNU General Public License
 * gives permission to release a modified version without this exception;
 * this exception also makes it possible to release a modified version
 * which carries forward this exception.
 *************************************************************************/

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/percpu.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>


#include "../../../../common/moptions.h"

#include "../../../../common/mtypes.h"
#include "../../../../common/mocana.h"
#include "../../../../crypto/hw_accel.h"

#include "../../../../common/mdefs.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/mjson.h"
#include "../../../../common/mrtos.h"
#include "../../../../common/debug_console.h"
#include "../../../../common/random.h"
#include "../../../../common/rng_seed.h"
#include "../../../../common/vlong.h"
#ifdef __ENABLE_DIGICERT_MEM_PART__
#include "../../../../common/mem_part.h"
#endif
#include "../../../../crypto/crypto.h"
#include "../../../../harness/harness.h"
#include "../../../../crypto/md5.h"
#include "../../../../crypto/md4.h"
#include "../../../../crypto/md2.h"

#include "../../../../crypto/aes.h"
#include "../../../../crypto/aesalgo.h"
#include "../../../../crypto/aes_ctr.h"
#include "../../../../crypto/aes_ccm.h"
#include "../../../../crypto/aes_cmac.h"
#include "../../../../crypto/aes_ecb.h"
#include "../../../../crypto/aes_xcbc_mac_96.h"
#include "../../../../crypto/aes_eax.h"
#include "../../../../crypto/aes_xts.h"

#include "../../../../crypto/gcm.h"

#include "../../../../crypto/des.h"
#include "../../../../crypto/three_des.h"
#include "../../../../crypto/sha1.h"
#include "../../../../crypto/sha256.h"
#include "../../../../crypto/sha512.h"
#include "../../../../crypto/sha3.h"
#include "../../../../crypto/hmac.h"

#include "../../../../crypto/sha1.h"
#include "../../../../crypto/sha256.h"
#include "../../../../crypto/sha512.h"
#include "../../../../crypto/fips.h"
#include "../../../../crypto/fips_priv.h"
#include "../../../../crypto/nist_rng.h"
#include "../../../../crypto/nist_rng_priv.h"

#include "../../../../common/mversion.h"


#if 0
#include "../examples/ipsec/linux/gpl/nf_ipsec.h"
#endif

MODULE_AUTHOR("www.mocana.com");
MODULE_DESCRIPTION("Mocana FIPS crypto module");
MODULE_LICENSE("DIGICERT INC");

#ifndef __DISABLE_DIGICERT_INIT__
extern moctime_t gStartTime;

extern MSTATUS CRYPTO_DIGI_init(void);
extern MSTATUS CRYPTO_DIGI_free(void);
#endif
extern int DIGI_kernelTaskId(void);

#define KERNEL_64BIT_FIX

/* Enable the first #def below to debug kernel module file I/O */
/* Enable the second #def for even more print statement when debugging kernel module file I/O */
/* // #define MOC_DEBUGGING_MOC_KERNEL_FILE_IO */
/* // #define MOC_DEBUGGING_VERBOSE_MOC_KERNEL_FILE_IO */

#if defined (__ENABLE_DIGICERT_FIPS_STATUS_MESSAGES__)
#define PRINTDEBUG printk
#warning "__ENABLE_DIGICERT_FIPS_STATUS_MESSAGES__ is defined."
#elif defined (MOC_DEBUGGING_MOC_KERNEL_FILE_IO)
#define PRINTDEBUG printk
#warning "MOC_DEBUGGING_MOC_KERNEL_FILE_IO is defined."
#else
#define PRINTDEBUG(...)
#endif

/* Access to user space is done differently in different version.  */
/* For kernels 5.18.0 and above, no special calls need to be made! */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)
static mm_segment_t old_fs;

/* The API 'get_fs()' and 'set_fs()' can be used directly in       */
/* kernel versions before 5.9.0                                    */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,9,0)
#define START_ACCESS(V)  V=get_fs()
#define SET_ACCESS(V)    set_fs(KERNEL_DS)
#define END_ACCESS(V)    set_fs(V)
#else
#include "linux/uaccess.h"
#define START_ACCESS(V)  V=force_uaccess_begin()
#define SET_ACCESS(V)
#define END_ACCESS(V)    force_uaccess_end(V)
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5,9,0) */

#else  /* LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0) */

#define START_ACCESS(V)
#define SET_ACCESS(V)
#define END_ACCESS(V)

#endif

#ifdef KERNEL_64BIT_FIX

	/* I'm implementing my own fd to File ptr mapping. */
	/* Because I get a troubling kernel warning when I use the kernel versions. */
	/* This could be changed to use kernel functions by changing the macros below. */
	#if 0
		#define GET_UNUSED_FD()      get_unused_fd()
		#define PUT_UNUSED_FD(fd)      put_unused_fd(fd)
		#define FD_INSTALL(fd,filp)    fd_install(fd,filp)
		#define FD_UNINSTALL(fd,filp)
		#define FGET(fd)               fget(fd)
		#define FPUT(fd)               fput(fd)
	#else
		#define GET_UNUSED_FD()      my_get_unused_fd()
		#define PUT_UNUSED_FD(fd)      my_put_unused_fd(fd)
		#define FD_INSTALL(fd,filp)    my_fd_install(fd,filp)
		#define FD_UNINSTALL(fd,filp)  my_fd_uninstall(fd,filp)
		#define FGET(fd)               my_fget(fd)
		#define FPUT(fd)               my_fput(fd)

		int my_get_unused_fd(void);
		void my_put_unused_fd(int fd);
		void my_fd_install(int fd, struct file *pf);
		void my_fd_uninstall(int fd, struct file *pf);
		struct file *my_fget(int fd);
		void my_fput(struct file *);

		#define MAX_MY_FDS 16 /* This is overkill it's really 1. */

		typedef struct _my_fds_t
		{
			int m_refcnt;
			struct file *m_pFile;
		} my_fds_t;

		static my_fds_t my_fds[MAX_MY_FDS+1] = { { 0 } };

		int my_get_unused_fd(void)
		{
			int ret = -1;
			int i;
			for (i=1;i<=MAX_MY_FDS;i++)
			{
			  if ((my_fds[i].m_refcnt == 0) && (my_fds[i].m_pFile == NULL))
			  {
				  return i;
			  }
			}
			PRINTDEBUG("my_get_unused_fd: BAD: returning: -1\n");
			return ret;
		}

		void my_put_unused_fd(int fd)
		{
			if ((fd < 1)||(fd>MAX_MY_FDS))
			{
				PRINTDEBUG("my_put_unused_fd: BAD PARM.\n");
				return;
			}
			if ((my_fds[fd].m_refcnt != 0)
					&& (my_fds[fd].m_pFile != NULL))
			{
				PRINTDEBUG("my_put_unused_fd: BAD: pFilp still open.\n");
			}

			/* Do it anyway. */
			my_fds[fd].m_refcnt = 0;
			my_fds[fd].m_pFile = NULL;
		}

		void my_fd_install(int fd, struct file *pf)
		{
			if ((fd < 1)||(fd>MAX_MY_FDS)||(pf==NULL))
			{
				PRINTDEBUG("my_fd_install: BAD PARM.\n");
				return;
			}
			my_fds[fd].m_pFile = pf;
		}

		void my_fd_uninstall(int fd, struct file *pf)
		{
			if ((fd < 1)||(fd>MAX_MY_FDS)||(pf==NULL))
			{
				PRINTDEBUG("my_fd_uninstall: BAD PARM.\n");
				return;
			}
			if (my_fds[fd].m_refcnt > 0)
			{
				PRINTDEBUG("my_fd_uninstall: BAD: pFilp still in use.\n");
				return;
			}
			my_fds[fd].m_pFile = NULL;
		}

		struct file *my_fget(int fd)
		{
			if ((fd < 1)||(fd>MAX_MY_FDS))
			{
				PRINTDEBUG("my_fget: BAD PARM.\n");
				return NULL;
			}
			my_fds[fd].m_refcnt++;
			return(my_fds[fd].m_pFile);
		}

		int find_used_fd(struct file *pf)
		{
			int ret = -1;
			int i;
			for (i=1;i<=MAX_MY_FDS;i++)
			{
			  if (my_fds[i].m_pFile == pf)
			  {
				  return i;
			  }
			}
			PRINTDEBUG("my_get_unused_fd: BAD: returning: -1\n");
			return ret;
		}

		void my_fput(struct file *pf)
		{
			int fd = 0;
			if (pf==NULL)
			{
				PRINTDEBUG("my_fput: BAD PARM.\n");
				return;
			}

			fd = find_used_fd(pf);

			if ((fd < 1)||(fd>MAX_MY_FDS))
			{
				PRINTDEBUG("my_fput: BAD: fd not found for file ptr.\n");
				return;
			}

			my_fds[fd].m_refcnt--;
		}

	#endif

#else
	static struct file *phMscd_Filp = NULL;
#endif

#ifdef MOC_USE_VFS_READ
/* Use this to fix portability issue with overlay file-systems */
#define USE_VFS_READ
#endif

/*---------------------------------------------------------------------------*/

extern sbyte4
DIGI_CRYPTO_fipsSelfTestInit(ubyte *filename)
{
#ifdef KERNEL_64BIT_FIX
 	int fd = 0;
 	struct file *pFilp = NULL;

    /* PRINTDEBUG("Entering DIGI_CRYPTO_fipsSelfTestInit...\n"); */

 	fd = GET_UNUSED_FD();	/* get next fd */
 	if (fd >= 0)
 	{
 		  PRINTDEBUG(" opening file [%s].\n", (char *)filename);
 		  pFilp = filp_open(filename, O_RDONLY , 0);
 		  if ((pFilp == NULL) || (IS_ERR(pFilp)))
 		  {
 			  PRINTDEBUG(" file_open error!!.\n");
 			  PUT_UNUSED_FD(fd);  /* release fd */
 			  fd = 0;
 		  }
 		  else
 		  {
 	 		  PRINTDEBUG(" file_open : %d : %p.\n", fd, pFilp);
 	 		  FD_INSTALL(fd, pFilp);
 		  }

 	}

 	/* Put us firmly into KERNEL_SPACE */
    START_ACCESS(old_fs);
    SET_ACCESS(KERNEL_DS);

 	return fd;
#else
 	/* Old version (works on 32 bits) */

  sbyte4 fd = 0;


  PRINTDEBUG(" opening filp [%s].\n", (char *)filename);
  phMscd_Filp = filp_open(filename, O_RDONLY , 0);
  if (phMscd_Filp == NULL)
  {
      PRINTDEBUG(" filp_open error!!.\n");
  }
  PRINTDEBUG(" filp_open %p.\n", phMscd_Filp);
  START_ACCESS(old_fs);
  SET_ACCESS(KERNEL_DS);
#if 0
  fd = sys_open(filename, O_RDONLY, 0);
#endif
  fd = (sbyte4) phMscd_Filp;
  if (fd == -2)
      fd = 0;
  return fd;

#endif /* KERNEL_64BIT_FIX */



}

/*---------------------------------------------------------------------------*/

extern int
DIGI_CRYPTO_getKernelTaskId(void)
{
    return DIGI_kernelTaskId();
}

/*---------------------------------------------------------------------------*/
#ifdef MOC_DEBUGGING_VERBOSE_MOC_KERNEL_FILE_IO
static int read_print_counter = 0;
#endif

extern sbyte4
DIGI_CRYPTO_fipsSelfTestUpdate(sbyte4 fd, ubyte * buf, ubyte4 bufLen)
{
    sbyte4 status = 0;

    /*
     * PRINTDEBUG("Entering DIGI_CRYPTO_fipsSelfTestUpdate...\n");
     */

#ifdef KERNEL_64BIT_FIX

#ifndef USE_VFS_READ
    PRINTDEBUG("DIGI_CRYPTO_fipsSelfTestUpdate::USE_VFS_READ DISABLED...\n");
	ssize_t (*read)(struct file *, char *, size_t, loff_t *); /* func ptr */
#endif
	struct file * pFilp;
	ssize_t ret = -EINVAL;

	pFilp = FGET(fd); /* get file structure, inc use count */
	if (pFilp)
	{
#ifdef USE_VFS_READ

#ifdef MOC_DEBUGGING_VERBOSE_MOC_KERNEL_FILE_IO
	    if (read_print_counter++ < 50)
	    {
	        PRINTDEBUG("Calling DIGI_readVFS() %p. bufLen=%ld f_pos=%ld \n", pFilp, bufLen, pFilp->f_pos);
	    }
#endif /* MOC_DEBUGGING_VERBOSE_MOC_KERNEL_FILE_IO */

            ret = DIGI_readVFS(pFilp, buf, bufLen, &pFilp->f_pos);

#else
	    /* Get pointer to read function from f_op */
	    if (pFilp->f_op && (read = pFilp->f_op->read) != NULL)
	    {
#ifdef MOC_DEBUGGING_VERBOSE_MOC_KERNEL_FILE_IO
                if (read_print_counter++ < 50)
	        {
	            PRINTDEBUG("Calling read() %p. bufLen=%ld f_pos=%ld \n", pFilp, bufLen, pFilp->f_pos);
	        }
#endif /* MOC_DEBUGGING_VERBOSE_MOC_KERNEL_FILE_IO */
	        ret = read(pFilp, buf, bufLen, &pFilp->f_pos);
	    }
#endif
	    FPUT(pFilp); /* dec use count */
	}

#ifdef MOC_DEBUGGING_VERBOSE_MOC_KERNEL_FILE_IO
        if (read_print_counter++ < 42)
        {
            PRINTDEBUG(" Read-?? returned %ld.\n", ret);
        }
#endif /* MOC_DEBUGGING_VERBOSE_MOC_KERNEL_FILE_IO */

    if (ret < 0 || ret > bufLen)
    {
        status  = ERR_FILE_READ_FAILED;
    }
    else
    {
        status = ret;
    }

    return status;

#else /* KERNEL_64BIT_FIX */

    sbyte4 status = 0;
    sbyte4 bytesRead = 0;
    struct file *phMscd_Filp = (struct file *)fd;

#if 0
    if ( 0 > fd  )
    {
        status  = ERR_FILE_READ_FAILED;
        goto exit;
    }
    if (sys_read(fd, buf, bufLen) != bufLen)
    {
        status  = ERR_FILE_READ_FAILED;
        goto exit;
    }
#endif
    if ( 0 == fd  )
    {
        status  = ERR_FILE_READ_FAILED;
        goto exit;
    }

#ifdef USE_VFS_READ
    bytesRead = DIGI_readVFS(phMscd_Filp, buf, bufLen, &phMscd_Filp->f_pos);
#else
    bytesRead = phMscd_Filp->f_op->read(phMscd_Filp, buf, bufLen, &phMscd_Filp->f_pos);
#endif
    if (bytesRead < 0 || bytesRead > bufLen)
    {
        status  = ERR_FILE_READ_FAILED;
        goto exit;
    }

    status = bytesRead;

exit:
    return status;

#endif /* KERNEL_64BIT_FIX */

}

/*---------------------------------------------------------------------------*/

extern sbyte4
DIGI_CRYPTO_fipsSelfTestFinal(sbyte4 fd)
{
#ifdef KERNEL_64BIT_FIX
	struct file * pFilp;

/* // #define TRY_REAL_CLOSE */

#ifdef TRY_REAL_CLOSE
	/* Looking at the kernel code, this *should* do all the needed work. */
    close(fd);
#else
	/* If we have to do it ourselves... */
	pFilp = FGET(fd); /* get file structure, inc use count */
	if (pFilp)
	{
    	FPUT(pFilp); /* dec use count */
        filp_close(pFilp,NULL);
		PRINTDEBUG(" file_closed : %d : %p.\n", fd, pFilp);
	}

	FD_UNINSTALL(fd,pFilp); /* KRB: This is the issue. */

	PUT_UNUSED_FD(fd);  /* release fd */
#endif

    PRINTDEBUG(" file_closed : released fd\n");

    /* Put us back (prob still in KERNEL DATA SPACE) */
    END_ACCESS(old_fs);

    return OK;


#else /* KERNEL_64BIT_FIX */

    struct file *phMscd_Filp = (struct file *)fd;
#if 0
    if (fd >= 0)
        sys_close(fd);
#endif
    if ((fd > 0) && (phMscd_Filp != NULL))
    {
        filp_close(phMscd_Filp,NULL);

    }

    END_ACCESS(old_fs);

    PRINTDEBUG(" filp_closed %p.\n", phMscd_Filp);
    return OK;

#endif /* KERNEL_64BIT_FIX */

}

/*---------------------------------------------------------------------------*/

/* Simple wrappers to support using of app library in kernel space */
void *
malloc(size_t size)
{
    /* Don't know where I'm from, so do it as atomic to be safe */
    return kmalloc(size, GFP_ATOMIC);
}

void
free(void *data)
{
    return kfree(data);
}

/*************************************************************
 *    Function: mss_ipsec_init
 * Description: .
 *        void:
 *************************************************************/
static int __init
mss_crypto_init(void)
{
    int status = 0;
    printk("moc_crypto_init.\n");

    FIPS_InitializeBeforeIntegrityChk();

#ifndef __DISABLE_DIGICERT_FIPS_CONSTRUCTOR_SELFTEST__
    printk("moc_crypto_init::FIPS_powerupSelfTest.\n");
    if (OK > (status = FIPS_powerupSelfTest()))
    {
        PRINTDEBUG("powerup test failed!\n");
        goto cleanup;
    }
    else
    {
        PRINTDEBUG("powerup test passed!\n");
        goto cleanup;
    }
#else
    printk("powerup test disabled!\n");
#endif

    FIPS_InitializeAfterIntegrityChk();

cleanup:
    printk("moc_crypto_init:: finished. status: %d.\n", status);
    return status;

}

static void __exit
mss_crypto_fini(void)
{
    printk("moc_crypto_fini.\n");
    FIPS_Finalize();
    FIPS_Zeroize();
#ifdef __ENABLE_DIGICERT_FIPS_STATUS_MESSAGES__
    PRINTDEBUG("moc_crypto_fini finished.\n");
#endif

}

#ifdef __ENABLE_DIGICERT_FIPS_AES__
EXPORT_SYMBOL(AESCCM_decrypt);
EXPORT_SYMBOL(AESCCM_encrypt);
EXPORT_SYMBOL(AESCCM_createCtx);
EXPORT_SYMBOL(AESCCM_deleteCtx);
EXPORT_SYMBOL(AESCCM_clone);
EXPORT_SYMBOL(AESCCM_cipher);
EXPORT_SYMBOL(AESCMAC_clear);
EXPORT_SYMBOL(AESCMAC_final);
EXPORT_SYMBOL(AESCMAC_init);
EXPORT_SYMBOL(AESCMAC_update);
EXPORT_SYMBOL(AES_EAX_encryptMessage);
EXPORT_SYMBOL(AES_EAX_final);
EXPORT_SYMBOL(AES_EAX_init);
EXPORT_SYMBOL(AES_EAX_updateHeader);
EXPORT_SYMBOL(AES_EAX_clear);
EXPORT_SYMBOL(AES_XCBC_MAC_96_final);
EXPORT_SYMBOL(AES_XCBC_MAC_96_init);
EXPORT_SYMBOL(AES_XCBC_MAC_96_update);
EXPORT_SYMBOL(AES_XCBC_clear);
EXPORT_SYMBOL(CreateAESCFBCtx);
EXPORT_SYMBOL(CreateAESCTRCtx);
EXPORT_SYMBOL(CreateAesCtrCtx);
EXPORT_SYMBOL(CreateAESCtx);
EXPORT_SYMBOL(CreateAESECBCtx);
EXPORT_SYMBOL(CreateAESOFBCtx);
EXPORT_SYMBOL(CreateAESXTSCtx);
EXPORT_SYMBOL(CloneAESCtx);
EXPORT_SYMBOL(CloneAESCTRCtx);
EXPORT_SYMBOL(DeleteAESCTRCtx);
EXPORT_SYMBOL(DeleteAESCtx);
EXPORT_SYMBOL(DeleteAESECBCtx);
EXPORT_SYMBOL(DeleteAESXTSCtx);
#endif

#ifdef __ENABLE_DIGICERT_FIPS_AES__
EXPORT_SYMBOL(aesEncrypt);
EXPORT_SYMBOL(aesDecrypt);
EXPORT_SYMBOL(aesKeySetupEnc);
EXPORT_SYMBOL(aesKeySetupDec);

EXPORT_SYMBOL(DoAesCtr);
EXPORT_SYMBOL(DoAESCTR);
EXPORT_SYMBOL(DoAesCtrEx);
EXPORT_SYMBOL(DoAESECB);
EXPORT_SYMBOL(DoAES);
EXPORT_SYMBOL(DoAESXTS);
#endif

#ifdef __ENABLE_DIGICERT_FIPS_3DES__
EXPORT_SYMBOL(Create2Key3DESCtx);
EXPORT_SYMBOL(Create3DESCtx);
EXPORT_SYMBOL(Clone3DESCtx);
EXPORT_SYMBOL(Delete3DESCtx);
EXPORT_SYMBOL(Do3DES);
EXPORT_SYMBOL(THREE_DES_encipher);
EXPORT_SYMBOL(THREE_DES_initKey);
#endif


EXPORT_SYMBOL(getFIPS_powerupStatus);
EXPORT_SYMBOL(FIPS_setTestMode);
EXPORT_SYMBOL(FIPS_getPrivileged);
EXPORT_SYMBOL(DRBG_getPrivileged);
EXPORT_SYMBOL(FIPS_locateFunction);

#ifdef __ENABLE_FIPS_POWERUP_TEST__
EXPORT_SYMBOL(FIPS_getDefaultConfig);
EXPORT_SYMBOL(FIPS_powerupSelfTestEx);
#endif

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
EXPORT_SYMBOL(FIPS_ModeEnabled);
#endif

#ifdef __ENABLE_DIGICERT_GCM_256B__
EXPORT_SYMBOL(GCM_createCtx_256b);
EXPORT_SYMBOL(GCM_deleteCtx_256b);
EXPORT_SYMBOL(GCM_final_256b);
EXPORT_SYMBOL(GCM_init_256b);
EXPORT_SYMBOL(GCM_clone_256b);
EXPORT_SYMBOL(GCM_cipher_256b);
EXPORT_SYMBOL(GCM_update_decrypt_256b);
EXPORT_SYMBOL(GCM_update_encrypt_256b);
#endif


#ifdef __ENABLE_DIGICERT_GCM_4K__
EXPORT_SYMBOL(GCM_createCtx_4k);
EXPORT_SYMBOL(GCM_deleteCtx_4k);
EXPORT_SYMBOL(GCM_final_4k);
EXPORT_SYMBOL(GCM_init_4k);
EXPORT_SYMBOL(GCM_clone_4k);
EXPORT_SYMBOL(GCM_cipher_4k);
EXPORT_SYMBOL(GCM_update_decrypt_4k);
EXPORT_SYMBOL(GCM_update_encrypt_4k);
#endif


#ifdef __ENABLE_DIGICERT_GCM_64K__
EXPORT_SYMBOL(GCM_createCtx_64k);
EXPORT_SYMBOL(GCM_deleteCtx_64k);
EXPORT_SYMBOL(GCM_final_64k);
EXPORT_SYMBOL(GCM_init_64k);
EXPORT_SYMBOL(GCM_clone_64k);
EXPORT_SYMBOL(GCM_cipher_64k);
EXPORT_SYMBOL(GCM_update_decrypt_64k);
EXPORT_SYMBOL(GCM_update_encrypt_64k);
#endif

#ifdef __ENABLE_DIGICERT_FIPS_HMAC__
EXPORT_SYMBOL(HmacCreate);
EXPORT_SYMBOL(HmacDelete);
EXPORT_SYMBOL(HmacFinal);
EXPORT_SYMBOL(HmacKey);
EXPORT_SYMBOL(HMAC_SHA1);
EXPORT_SYMBOL(HMAC_SHA1_quick);
EXPORT_SYMBOL(HMAC_MD5_quick);
EXPORT_SYMBOL(HmacUpdate);
EXPORT_SYMBOL(HmacQuickerEx);
EXPORT_SYMBOL(HmacQuickerInlineEx);
EXPORT_SYMBOL(HmacQuickerInline);
EXPORT_SYMBOL(HmacQuicker);
EXPORT_SYMBOL(HmacQuickEx);
EXPORT_SYMBOL(HmacQuick);
#endif

#if (defined(__ENABLE_DIGICERT_MD2__))
EXPORT_SYMBOL(MD2Final);
EXPORT_SYMBOL(MD2Init);
EXPORT_SYMBOL(MD2Update);
#endif

#if (defined(__ENABLE_DIGICERT_MD4__))
EXPORT_SYMBOL(MD4Final);
EXPORT_SYMBOL(MD4Init);
EXPORT_SYMBOL(MD4Update);
EXPORT_SYMBOL(MD5Final_m);
EXPORT_SYMBOL(MD5Init_m);
EXPORT_SYMBOL(MD5Update_m);
EXPORT_SYMBOL(MD5_completeDigest);
#endif

#if (defined(__ENABLE_DIGICERT_RNG_DRBG_CTR__))
EXPORT_SYMBOL(RNG_SEED_initDepotState);
EXPORT_SYMBOL(RNG_SEED_freeDepotState);
EXPORT_SYMBOL(RNG_SEED_extractDepotBits);
EXPORT_SYMBOL(DIGICERT_addEntropyBit);
EXPORT_SYMBOL(DIGICERT_addEntropy32Bits);
#endif
#if (defined(__ENABLE_DIGICERT_RNG_DRBG_CTR__))
EXPORT_SYMBOL(NIST_CTRDRBG_deleteContext);
EXPORT_SYMBOL(NIST_CTRDRBG_generate);
EXPORT_SYMBOL(NIST_CTRDRBG_newContext);
EXPORT_SYMBOL(NIST_CTRDRBG_reseed);
#endif

#if (defined(__ENABLE_DIGICERT_FIPS_RANDOM__))
EXPORT_SYMBOL(RANDOM_acquireContextEx);
EXPORT_SYMBOL(RANDOM_acquireContext);
EXPORT_SYMBOL(RANDOM_addEntropyBit);
EXPORT_SYMBOL(RANDOM_newFIPS186Context);
EXPORT_SYMBOL(RANDOM_numberGenerator);
EXPORT_SYMBOL(RANDOM_releaseContext);
EXPORT_SYMBOL(RANDOM_setEntropySource);
EXPORT_SYMBOL(RANDOM_rngFun);
#endif

#if (defined(__ENABLE_DIGICERT_FIPS_SHA1__))
EXPORT_SYMBOL(SHA1_allocDigest);
EXPORT_SYMBOL(SHA1_completeDigest);
EXPORT_SYMBOL(SHA1_finalDigest);
EXPORT_SYMBOL(SHA1_freeDigest);
EXPORT_SYMBOL(SHA1_initDigest);
EXPORT_SYMBOL(SHA1_updateDigest);
#endif

#if (defined(__ENABLE_DIGICERT_FIPS_SHA256__))
EXPORT_SYMBOL(SHA224_completeDigest);
EXPORT_SYMBOL(SHA224_finalDigest);
EXPORT_SYMBOL(SHA224_initDigest);
EXPORT_SYMBOL(SHA256_allocDigest);
EXPORT_SYMBOL(SHA256_completeDigest);
EXPORT_SYMBOL(SHA256_finalDigest);
EXPORT_SYMBOL(SHA256_freeDigest);
EXPORT_SYMBOL(SHA256_initDigest);
EXPORT_SYMBOL(SHA256_updateDigest);
EXPORT_SYMBOL(SHA384_completeDigest);
EXPORT_SYMBOL(SHA384_finalDigest);
EXPORT_SYMBOL(SHA384_initDigest);
#endif

#if (defined(__ENABLE_DIGICERT_FIPS_SHA512__))
EXPORT_SYMBOL(SHA512_allocDigest);
EXPORT_SYMBOL(SHA512_completeDigest);
EXPORT_SYMBOL(SHA512_finalDigest);
EXPORT_SYMBOL(SHA512_freeDigest);
EXPORT_SYMBOL(SHA512_initDigest);
EXPORT_SYMBOL(SHA512_updateDigest);
#endif

#if (defined(__ENABLE_DIGICERT_FIPS_SHA3__))
EXPORT_SYMBOL(SHA3_allocDigest);
EXPORT_SYMBOL(SHA3_completeDigest);
EXPORT_SYMBOL(SHA3_finalDigest);
EXPORT_SYMBOL(SHA3_freeDigest);
EXPORT_SYMBOL(SHA3_initDigest);
EXPORT_SYMBOL(SHA3_updateDigest);
#endif

EXPORT_SYMBOL(DIGICERT_readVersion);
#ifndef __DISABLE_DIGICERT_INIT__
EXPORT_SYMBOL(gStartTime);
EXPORT_SYMBOL(CRYPTO_DIGI_init);
EXPORT_SYMBOL(CRYPTO_DIGI_free);
#endif
EXPORT_SYMBOL(g_pRandomContext);

EXPORT_SYMBOL(DIGI_CRYPTO_getKernelTaskId);
EXPORT_SYMBOL(DIGI_CRYPTO_fipsSelfTestInit);
EXPORT_SYMBOL(DIGI_CRYPTO_fipsSelfTestUpdate);
EXPORT_SYMBOL(DIGI_CRYPTO_fipsSelfTestFinal);
EXPORT_SYMBOL(FIPS_DumpStartupStatusData);
EXPORT_SYMBOL(sInternalCurrPowerupTestConfig);

EXPORT_SYMBOL(VLONG_compareSignedVlongs);
EXPORT_SYMBOL(VLONG_freeVlongQueue);
EXPORT_SYMBOL(VLONG_makeVlongFromVlong);

EXPORT_SYMBOL(JSON_acquireContext);
EXPORT_SYMBOL(JSON_parse);
EXPORT_SYMBOL(JSON_getToken);
EXPORT_SYMBOL(JSON_DBG_dumpContextInfo);
EXPORT_SYMBOL(JSON_DBG_dumpAllTokens);
EXPORT_SYMBOL(JSON_getObjectIndex);
EXPORT_SYMBOL(JSON_releaseContext);

module_init(mss_crypto_init);
module_exit(mss_crypto_fini);
