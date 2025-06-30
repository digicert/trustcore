#include "../common/moptions.h"
#ifdef __MOCANA_FORCE_ENTROPY__
#ifndef __DISABLE_MOCANA_ADD_ENTROPY__
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/utils.h"
#include "../common/mocana.h"
#include "../common/mfmgmt.h"
#if defined(__RTOS_LINUX__) || defined(__RTOS_VXWORKS__)
#ifndef __KERNEL__
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <linux/random.h>
#include "../common/external_rand_thread.h"

/* NEEDS_JOIN is defined for now so that MOCANA_initMocana() can
 * block waiting for the entropy collection thread to finish. This
 * is needed for FIPS certification. Later we can consider undefining
 * it for performance reasons
 */
#define EXTERN_RAND_THREAD_NEEDS_JOIN 1

/* random or urandom ? See http://www.2uo.de/myths-about-urandom */
#define LINUX_DEV_URANDOM_FILE	"/dev/urandom"
#define LINUX_DEV_RANDOM_FILE	"/dev/random"

/* Use urandom unless force random is defined */
#ifdef __ENABLE_MOCANA_FORCE_DEV_RANDOM__
#define MOC_LINUX_RAND_FILE LINUX_DEV_RANDOM_FILE
#else
#define MOC_LINUX_RAND_FILE LINUX_DEV_URANDOM_FILE
#endif

#define RAND_WAKE_THRESH    "/proc/sys/kernel/random/read_wakeup_threshold"
#define MOC_READ_WMARK    4

#define MAX_EXT_RAND_BYTES	64
#define MOCANA_RANDOM_STORE_MAX_SIZE    4096
#define MOCANA_RANDOM_STORE    "/var/run/MocanaRandomStore"

static pthread_mutex_t externalRandomMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t gExternalRandomThreadId;
static intBoolean gExternalRandomThreadIsSpawned = 0;
#ifdef EXTERN_RAND_THREAD_NEEDS_JOIN
static intBoolean gExternalRandomThreadNeedsJoin = FALSE;
#endif
static intBoolean gExternalRandomThreadCancel = 0;

static MSTATUS MOCANA_initDevRandom(ubyte4 read_thresh);
static MSTATUS MOCANA_ReadRandomStoreWriteKernel(sbyte4 randFd, sbyte4 count);
static MSTATUS MOCANA_RandomFileStoreClear(void);
static MSTATUS MOCANA_RandomFileStoreWrite(ubyte4 val);
static int MOCANA_RandomFileStoreIsFull(void);

static void *
externalRandomThreadStart(void *arg)
{
    (void)MOCANA_addExternalEntropy(1);
    gExternalRandomThreadIsSpawned = 0;
    return NULL;
}

static MSTATUS
read32bits(int fd, ubyte4 *val)
{
    unsigned char randReadBuf[8];
    int  remLen = 4, rlen, offs=0, i;

    *val = 0;

    MOC_MEMSET(randReadBuf, 0x00, 8);
    while (remLen > 0)
    {
        rlen = read(fd, randReadBuf, remLen);
        if (rlen <= 0)
        {
            return ERR_FILE_READ_FAILED;
        }
        remLen -= rlen;
        for (i = 0; i < rlen; ++i)
            *val |= randReadBuf[i] << (8*(offs+i));
        offs += rlen;
    }

    return 4;
}

/**
 * @brief Have Mocana obtain more entropy and add it to the random number
 * generator.
 *
 * @details This function will obtain entropy from some source and add it to the
 * global random context. The source of entropy might be /dev/urandom if the
 * platform has one, it might be CAPI on a Windows platform, it might be hardware
 * random if the platform is connected to some sort of hardware device that
 * offers a random number generator.
 *
 * <p>This function will obtain 512 bits of entropy, add them, and return. This
 * is synchronous, meaning it will not return until it completes. It can be made
 * to return early by calling MOCANA_cancelExternalEntropy(). If it's called from a
 * thread, the async argument is 1. In this case, the function will read previously
 * harvested entropy from a disk file and write it into /dev/random to be used to
 * generate fresh random numbers. After writing, the file is truncated to 0 size.
 * In addition if async is 1, after reading 512 bits of random values the function
 * will continue to read random values and write it into the disk file for use on the
 * next reboot. If async is 0, then it only reads 512 bits from /dev/random to seed
 * the RNG
 *
 * <p>You could call this function directly in your program without having to go
 * through MOCANA_addExternalEntropyThread(). If you do so, make sure that no other
 * thread calls this or MOCANA_addExternalEntropyThread() concurrently
 *
 * @param
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */

/* This is copied from addExternEntropy function in src/examples/fips_utils.c */
MSTATUS MOCANA_addExternalEntropy (int async)
{
    MSTATUS status = OK;
    ubyte4 count = 384/32;
    int fd=-1, rval=-1;
    ubyte4  randVal=0;
    int i = 0;

    MOC_UNUSED(async);
    fd = open(MOC_LINUX_RAND_FILE, O_RDONLY);
    if (fd < 0)
        goto exit;

    for (i = 0; i < count; i++)
    {
        randVal=0;
        rval = read32bits(fd, &randVal);

        if (OK > rval)
        {
            goto exit;
        }

        status = MOCANA_addEntropy32Bits(randVal);
        if (OK != status)
        {
            goto exit;
        }
    }

    exit:
    if (0 <= fd)
    {
        close(fd);
    }
    return status;
}

#if 0
MSTATUS MOCANA_addExternalEntropy (int async)
{
    MSTATUS	status = ERR_FILE_OPEN_FAILED;
    int		fd=-1, rval=-1, bytes_read=0, done=0;
    ubyte4	randVal=0;
    int     ronly=0;

    fd = open(MOC_LINUX_RAND_FILE, O_RDONLY);
    if (fd < 0)
	    goto exit;

    status = OK;

    while (!done)
    {
	    if (0 != gExternalRandomThreadCancel)
	        break;

        randVal=0;
        rval = read32bits(fd, &randVal);

        if (OK > rval)
            goto exit;

        if (MAX_EXT_RAND_BYTES >= bytes_read)
        {
            status = MOCANA_addEntropy32Bits(randVal);
            if (OK != status)
                goto exit;
        }
        else
        {
            break;
        }

        bytes_read += rval;
        done = ((MAX_EXT_RAND_BYTES <= bytes_read) && (!async || (0 < MOCANA_RandomFileStoreIsFull())));
    }

    status = OK;

exit:
    if (0 <= fd)
     close(fd);
    return status;
}
#endif

/**
 * @brief This function is called from MOCANA_freeMocana() to wait for the
 * running entropy thread (if any) to complete
 *
 * @detais If an entropy reading thread is running, it will wait for
 * the thread to complete before returning
 *
 * <p>NOTE! Do not call this function until you have called MOCANA_initMocana (or
 * related function).
 *
 * <p>NOTE! This function can block since it waits for the entropy reader thread to
 * finish
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MSTATUS MOCANA_waitForExternalEntropy (void)
{
#ifdef EXTERN_RAND_THREAD_NEEDS_JOIN
    void      * res;
    if (gExternalRandomThreadNeedsJoin)
	pthread_join(gExternalRandomThreadId, &res);
    gExternalRandomThreadNeedsJoin = FALSE;
#endif
    return OK;
}

/**
 * @brief This function is called from MOCANA_freeMocana() to indicate to a
 * running entropy thread that it needs to quit
 *
 * @detais This function will set a variable so the loop in the external entropy reader
 * thread can quit early. It does not make the caller wait for the thread to complete
 * <p>NOTE! Do not call this function until you have called MOCANA_initMocana (or
 * related function).
 *
 * <p>NOTE! This function can block since it waits for the entropy reader thread to
 * finish
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */

MSTATUS MOCANA_cancelExternalEntropy (void)
{
    gExternalRandomThreadCancel = 1;
    return OK;
}

/**
 * @brief This is similar to MOCANA_addExternalEntropy, except it does the
 * operation in a newly-created thread and is therefore asynchronous.
 *
 * @detais This function will create a new thread and return. That new thread
 * will call MOCANA_addExternalEntropy. Once that function is complete, the
 * thread will exit. You can call this function and have the entropy collection
 * happen "in the background". That is, you don't have to wait for the entropy
 * collection to complete before continuing on with your work.
 *
 * <p>NOTE! Do not call this function until you have called MOCANA_initMocana (or
 * related function).
 *
 * <p>NOTE! This function will check to see if another thread is already
 * collecting entropy through this function. If so, it will return
 * ERR_ENTROPY_THREAD_IN_USE. That is, if you or some other operation calls this
 * function, it launches a thread and starts collecting entropy, and you call the
 * function again before the previous call's thread has completed, this call will
 * not do anything, it will simply return the error listed above. Hence, you will
 * likely want to check the return from this function as more than OK or error.
 * You will probably want to check the return, if it is 0, no error, if it is
 * THREAD_IN_USE, continue as if there is no error, if it is some other error,
 * break out. If you want to do something else with the THREAD_IN_USE error, you
 * have the option.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */

MSTATUS MOCANA_addExternalEntropyThread (void)
{
    MSTATUS	status;
    int		rval;
    void      * res;
    pthread_attr_t	attr;

    /* XXX Use platform independent thread call */
    if (pthread_mutex_trylock(&externalRandomMutex) != 0) {
	return ERR_ENTROPY_THREAD_IN_USE; /* XXX */
    }
    /* We have the Mutex; To make sure only 1 copy of the worker thread
     * we check if IsSpawned is TRUE. If so we return. When worker thread
     * exits it will set IsSpawned to 0
     */
    if (gExternalRandomThreadIsSpawned) {
	status = ERR_ENTROPY_THREAD_IN_USE;
	goto done;
    }
#ifdef EXTERN_RAND_THREAD_NEEDS_JOIN
    /* If a previously spawned has exitedwe need to reap its exit status otherwise
     * all its resources won't be freed up
     */
    if (gExternalRandomThreadNeedsJoin) {
	pthread_join(gExternalRandomThreadId, &res);
	gExternalRandomThreadNeedsJoin = FALSE;
    }
#endif
    pthread_attr_init(&attr);
#ifndef EXTERN_RAND_THREAD_NEEDS_JOIN
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
#endif
    rval = pthread_create(&gExternalRandomThreadId, &attr,
			  &externalRandomThreadStart, NULL);
    pthread_attr_destroy(&attr);
    if (rval == 0) {
	gExternalRandomThreadIsSpawned = 1;
#ifdef EXTERN_RAND_THREAD_NEEDS_JOIN
	gExternalRandomThreadNeedsJoin = TRUE;
#endif
	gExternalRandomThreadCancel = 0;
    }
    status = OK;
  done:
    pthread_mutex_unlock(&externalRandomMutex);
    return status;
}

/**
 * @brief This is a convenience function that combines the operations of
 * spawning the entropy thread and waiting for it to complete.
 *
 * @detais This is called in MOCANA_initMocana() to get gather entropy before
 * going further. So it blocks until the 512 bits have been gathered
 *
 * <p>NOTE! This function can block since it waits for the entropy reader thread to
 * finish
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */

MSTATUS MOCANA_addExternalEntropyThreadWait (void)
{
    MSTATUS status;
    status = MOCANA_addExternalEntropyThread();
    if (OK > status)
	goto exit;
    status = MOCANA_waitForExternalEntropy();
  exit:
    return status;
}

/**
 * @brief This is an internal function that sets the read threshold
 * for reading from /dev/random. It's only relevant if you are doing
 * a select on the fd corresponding to dev/random
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
static MSTATUS
MOCANA_initDevRandom(ubyte4 read_thresh)
{
    FileDescriptor fp;

    if (OK != FMGMT_fopen (RAND_WAKE_THRESH, "w", &fp))
        return ERR_FILE;
    else
    {
	    FMGMT_fprintf (fp, "%u\n", read_thresh);
	    FMGMT_fclose (&fp);
    }
    return OK;
}

/**
 * @brief This is an internal function that provides /dev/random with
 * a bunch of random numbers harvested earlier
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
static MSTATUS
MOCANA_DevRandomAddEntropyFromBuffer(sbyte4 fd, void *buf, size_t size)
{
    struct {
	int ent_count;
	int size;
	unsigned char data[size];
    } entropy;

    entropy.ent_count = size * 8;
    entropy.size = size;
    MOC_MEMCPY(entropy.data, buf, size);

    if (ioctl(fd, RNDADDENTROPY, &entropy) != 0)
    {
	    return ERR_FILE;
    }

    return OK;
}

/**
 * @brief This is an internal function that checks if the disk file that stores
 * random numbers for later use has reached its maximum size
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
static int
MOCANA_RandomFileStoreIsFull(void)
{
    FileDescriptorInfo fileInfo;

    if (OK != FMGMT_pathExists (MOCANA_RANDOM_STORE, &fileInfo))
        return 0;

    if (fileInfo.fileSize >= MOCANA_RANDOM_STORE_MAX_SIZE)
    {
	    return 1; /* Tell caller we don't need any more */
    }

    return 0;
}

/**
 * @brief This is an internal function that takes a uint32 read from /dev/random
 * and appends it to the disk file
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
static MSTATUS
MOCANA_RandomFileStoreWrite(ubyte4 val)
{
    FileDescriptor fp;
    ubyte4 bytesWritten;

    if (0 < MOCANA_RandomFileStoreIsFull())
	    return 1;

    if (OK == FMGMT_fopen (MOCANA_RANDOM_STORE, "a", &fp))
    {
        FMGMT_fwrite ((ubyte *) &val, sizeof(val), 1, fp, &bytesWritten);
        FMGMT_fclose (&fp);
    }
    else
    {
	    return ERR_FILE_OPEN_FAILED;
    }

    return OK;
}

/**
 * @brief This is an internal function that truncates the disk file with random
 * values to 0 size
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
static MSTATUS
MOCANA_RandomFileStoreClear(void)
{
     FileDescriptor fp;

     if (OK == FMGMT_fopen (MOCANA_RANDOM_STORE, "w", &fp))
     {
        FMGMT_fclose (&fp);
     }

     return OK;
}

/**
 * @brief This is an internal function that writes previously harvested random values
 * to /dev/random so that on system startup /dev/random need not start from scratch
 *
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
static MSTATUS
MOCANA_ReadRandomStoreWriteKernel(sbyte4 randFd, sbyte4 count)
{
    FileDescriptor     fp;
    FileDescriptorInfo fileInfo;
    int 	         len, act_len;
    char             *pBuf = NULL;
    MSTATUS	status;

    status = FMGMT_pathExists (MOCANA_RANDOM_STORE, &fileInfo);
    if (OK != status)
        return status;

    len = fileInfo.fileSize;

    if (count && (count < len))
	    len = count;

    status = MOC_MALLOC((void **)&pBuf, len);

    if (OK > status)
	    return status;

    status = FMGMT_fopen (MOCANA_RANDOM_STORE, "r", &fp);
    if (OK == status)
    {
        FMGMT_fread (pBuf, 1, len, fp, &act_len);
        FMGMT_fclose (&fp);
	    if (act_len > 0)
	    {
	        status = MOCANA_DevRandomAddEntropyFromBuffer(randFd, pBuf, act_len);
	    }
    }

    MOC_FREE((void **)&pBuf);
    return status;
}

#endif /* __KERNEL__ */
#else  /*  __RTOS_LINUX || __RTOS_VXWORKS__ */
MSTATUS MOCANA_waitForExternalEntropy (void)
{
    return ERR_NOT_IMPLEMENTED;
}

MSTATUS MOCANA_cancelExternalEntropy (void)
{
    return ERR_NOT_IMPLEMENTED;
}

MSTATUS MOCANA_addExternalEntropyThread (void);
{
    return ERR_NOT_IMPLEMENTED;
}

MSTATUS MOCANA_addExternalEntropy (int async);
{
    return ERR_NOT_IMPLEMENTED;
}

MSTATUS MOCANA_addExternalEntropyThreadWait (void)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif /*  __RTOS_LINUX || __RTOS_VXWORKS__ */
#endif /* __DISABLE_MOCANA_ADD_ENTROPY__ */
#endif /* __MOCANA_FORCE_ENTROPY__ */
