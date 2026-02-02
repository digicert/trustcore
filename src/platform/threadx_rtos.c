/*
 * THREADX_rtos.c
 *
 * THREADX RTOS Abstraction Layer
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../common/moptions.h"

#ifdef __RTOS_THREADX__
#include "tx_api.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"

/* These macros can optionally be defined in the e2 Studio */
#ifndef USE_E2_CONF
#define MOCANA_THREAD_STACK_SIZE    0x100
#define MOCANA_THREAD_PRI           11
#define TX_BYTE_POOL_SIZE           0xC800 // 0xB000
#define TX_BYTE_BIGPOOL_SIZE        0xA900 // 0xB000
#endif

typedef VOID (*Thread_ENTRY_FUNC)(ULONG);

/* Allocate static memory for byte pool */
static ubyte4 gBytePoolMemory[TX_BYTE_POOL_SIZE];
static ubyte4 gByteBigPoolMemory[TX_BYTE_BIGPOOL_SIZE];

/* Byte pool control block */
TX_BYTE_POOL gBytePool;
TX_BYTE_POOL gByteBigPool;

/**
 * Holds the control structure and stack for a thread
 */
typedef struct _MTHREAD_CONTEXT
{
    /* ThreadX's thread type */
    TX_THREAD ThreadControl;

    /**
     * Each thread must have its own stack for saving the
     * context of its last execution and compiler use. Most C
     * compilers use the stack for making function calls and
     * for temporarily allocating local variables.
     * Where a thread stack is located in memory is up to
     * the application. The stack area is specified during
     * thread creation and can be located anywhere in the 
     */
    ubyte *ThreadStack;
} MTHREAD_CONTEXT, *PMTHREAD_CONTEXT;

TX_THREAD moc_thread;
static uint8_t moc_thread_stack[MOCANA_THREAD_STACK_SIZE] BSP_PLACE_IN_SECTION(".stack.moc_thread") BSP_ALIGN_VARIABLE(BSP_STACK_ALIGNMENT);


/*------------------------------------------------------------------*/

/**
 * The ThreadX OS itself has no date/time API
 */
int THREADX_timeGMT(TimeDate*t){
    DIGI_MEMSET(t,0,sizeof(TimeDate));
    t->m_year = 49;
    return ERR_RTOS_GMT_TIME_NOT_AVAILABLE;
}


/*------------------------------------------------------------------*/

/**
 * Allocate memory from the byte pool
 */
void *THREADX_malloc(ubyte4 size)
{
    void *memoryBlockPtr = NULL;
    MSTATUS status = ERR_GENERAL;

    if (size <= 0)
    {
    	return(memoryBlockPtr);
    }

    /**
     * tx_byte_allocate
     *
     * Prototype
     * UINT tx_byte_allocate(TX_BYTE_POOL *pool_ptr,
     *   VOID **memory_ptr, ULONG memory_size,
     *   ULONG wait_option)
     *
     * Description
     * This service allocates the specified number of bytes from the specified
     * memory byte pool.
     * The performance of this service is a function of the block size and the
     * amount of fragmentation in the pool. Hence, this service should not be
     * used during time-critical threads of execution.
     *
     * Parameters
     * pool_ptr    Pointer to a previously created memory pool.
     * memory_ptr  Pointer to a destination memory pointer. On  successful 
     *                allocation, the address of the  allocated memory area 
     *                is placed where this  parameter points to.
     * memory_size Number of bytes requested.
     * wait_option Defines how the service behaves if there is not  enough 
     *               memory available. The wait options are  defined as 
     *               follows:
     *                  TX_NO_WAIT (0x00000000)
     *                  TX_WAIT_FOREVER (0xFFFFFFFF)
     *                  timeout value (0x00000001 through 0xFFFFFFFE)
     *
     *                  Selecting TX_NO_WAIT results in an immediate
     *                  return from this service regardless of whether or
     *                  not it was successful. This is the only valid option
     *                  if the service is called from initialization.
     *   
     *                  Selecting TX_WAIT_FOREVER causes the
     *                  calling thread to suspend indefinitely until
     *                  enough memory is available.
     *
     *                  Selecting a numeric value (1-0xFFFFFFFE)
     *                  specifies the maximum number of timer-ticks to
     *                  stay suspended while waiting for the memory.
     * Return Values
     * - TX_SUCCESS      (0x00) Successful memory allocation.
     * - TX_DELETED      (0x01) Memory pool was deleted while thread
     *                            was suspended.
     * - TX_NO_MEMORY    (0x10) Service was unable to allocate the
     *                            memory within the specified time to wait.
     * - TX_WAIT_ABORTED (0x1A) Suspension was aborted by another thread, 
     *                            timer, or ISR.
     * - TX_POOL_ERROR   (0x02) Invalid memory pool pointer.
     * - TX_PTR_ERROR    (0x03) Invalid pointer to destination pointer.
     * - TX_SIZE_ERROR   (0X05) Requested size is zero or larger than the pool.
     * - TX_WAIT_ERROR   (0x04) A wait option other than TX_NO_WAIT  was 
     *                            specified on a call from a nonthread.
     * - TX_CALLER_ERROR (0x13) Invalid caller of this service.
     */


    if(size < 768)
    {
    status = tx_byte_allocate(
            &gBytePool,  
            (VOID *)&memoryBlockPtr,
            (ULONG)size,
            TX_NO_WAIT);
        if (status !=TX_SUCCESS)
        {
            status = tx_byte_allocate(
                &gByteBigPool,
                (VOID *)&memoryBlockPtr,
                (ULONG)size,
                TX_NO_WAIT);
        }
    }
    else
    {
        status = tx_byte_allocate(
                &gByteBigPool,
                (VOID *)&memoryBlockPtr,
                (ULONG)size,
                TX_NO_WAIT);
        if (status !=TX_SUCCESS)
        {
    status = tx_byte_allocate(
            &gBytePool,  
            (VOID *)&memoryBlockPtr,
            (ULONG)size,
            TX_NO_WAIT);
        }
    }

    if (status !=TX_SUCCESS)
    {
        memoryBlockPtr=(void *)0;
    }

    return(memoryBlockPtr);
} /* THREADX_malloc */


/*------------------------------------------------------------------*/

/**
 * Frees memory from the byte pool 
 */
void THREADX_free(void *memoryBlockPtr)
{
	if(!memoryBlockPtr)
		return;
    (void)tx_byte_release(memoryBlockPtr);
    return;
}


/*------------------------------------------------------------------*/

/**
 * Sets up byte pool for memory allocation
 *
 */
extern MSTATUS THREADX_rtosInit(void)
{
    UINT txStatus;

    /**
     * tx_byte_pool_create
     *
     * This service creates a memory byte pool in the area specified. Initially
     * the pool consists of basically one very large free block. However, the 
     * pool is broken into smaller blocks as allocations are made.
     *
     * UINT tx_byte_pool_create(TX_BYTE_POOL *pool_ptr,
     * CHAR *name_ptr, VOID *pool_start,
     * ULONG pool_size)
     *
     * Parameters
     *   pool_ptr Pointer to a memory pool control block.
     *   name_ptr Pointer to the name of the memory pool.
     *   pool_start Starting address of the memory pool.
     *   pool_size Total number of bytes available for the memory
     *
     * Allowed From:
     * - Initialization and threads
     * 
     * Preemption Possible:
     * No
     */
    txStatus = tx_byte_pool_create(&gBytePool,
            "General",
            &gBytePoolMemory,
            (ULONG)TX_BYTE_POOL_SIZE);

    switch(txStatus){
        case TX_SUCCESS:
            break;
        case TX_POOL_ERROR:
            /* Invalid memory pool pointer. Either the pointer is NULL, or
             * the pool is already created */
            return ERR_MEM_POOL_CREATE;
        case TX_PTR_ERROR:
            /* Invalid starting address of the pool */
            return ERR_MEM_POOL_BAD_ADDRESS;
        case TX_SIZE_ERROR:
            /* Size of pool is invalid */
            return ERR_MEM_POOL_BAD_SIZE;
        default:
            return ERR_RTOS;
    }
    txStatus = tx_byte_pool_create(&gByteBigPool,
            "BigPool",
            &gByteBigPoolMemory,
            (ULONG)TX_BYTE_BIGPOOL_SIZE);

    switch(txStatus){
        case TX_SUCCESS:
            return OK;
        case TX_POOL_ERROR:
            /* Invalid memory pool pointer. Either the pointer is NULL, or
             * the pool is already created */
            return ERR_MEM_POOL_CREATE;
        case TX_PTR_ERROR:
            /* Invalid starting address of the pool */
            return ERR_MEM_POOL_BAD_ADDRESS;
        case TX_SIZE_ERROR:
            /* Size of pool is invalid */
            return ERR_MEM_POOL_BAD_SIZE;
        default:
            return ERR_RTOS;
    }
} /* THREADX_rtosInit */


/*------------------------------------------------------------------*/

extern MSTATUS THREADX_rtosShutdown(void)
{
    MSTATUS status = ERR_GENERAL;

    /**
     * tx_byte_pool_delete
     *
     * Prototype:
     * UINT tx_byte_pool_delete(TX_BYTE_POOL *pool_ptr
     *
     * This service deletes the specified memory byte pool. All threads 
     * suspended waiting for memory from this pool are resumed and given a
     * TX_DELETE return status.
     *
     * Parameters
     * - TX_BYTE_POOL *pool_ptr Pointer to a previously created pool
     *
     * Allowed From:
     * - Threads
     * 
     * Preemption Possible
     * Yes
     */
    status = tx_byte_pool_delete(&gBytePool);
    if(TX_SUCCESS == status){
        return OK;
    } else {
        return ERR_MEM_POOL;
    }
    status = tx_byte_pool_delete(&gByteBigPool);
    if(TX_SUCCESS == status){
        return OK;
    } else {
        return ERR_MEM_POOL;
    }
} /* THREADX_rtosShutdown */

extern MSTATUS THREADX_rtosResetAppPool(byteBoolean bCompactPool)
{
    MSTATUS status = OK;
    if(TRUE == bCompactPool)
    {
        void *pBigMem, *pMem;
        pBigMem = THREADX_malloc(gByteBigPool.tx_byte_pool_available - 200);
        pMem = THREADX_malloc(gBytePool.tx_byte_pool_available - 200);
        if(pBigMem)
        {
    	    THREADX_free(pBigMem);
        }
        if(pMem)
        {
    	    THREADX_free(pMem);
        }
        return status;
    }
    else
    {
        tx_byte_pool_delete(&gByteBigPool);
        tx_byte_pool_delete(&gBytePool);
        status = tx_byte_pool_create(&gBytePool,
            "General",
            &gBytePoolMemory,
            (ULONG)TX_BYTE_POOL_SIZE);

        switch(status){
            case TX_SUCCESS:
                break;
            case TX_POOL_ERROR:
            /* Invalid memory pool pointer. Either the pointer is NULL, or
             * the pool is already created */
                return ERR_MEM_POOL_CREATE;
            case TX_PTR_ERROR:
            /* Invalid starting address of the pool */
                return ERR_MEM_POOL_BAD_ADDRESS;
            case TX_SIZE_ERROR:
            /* Size of pool is invalid */
                return ERR_MEM_POOL_BAD_SIZE;
            default:
                return ERR_RTOS;
        }
        status = tx_byte_pool_create(&gByteBigPool,
            "BigPool",
            &gByteBigPoolMemory,
            (ULONG)TX_BYTE_BIGPOOL_SIZE);

        switch(status){
            case TX_SUCCESS:
                return OK;
            case TX_POOL_ERROR:
            /* Invalid memory pool pointer. Either the pointer is NULL, or
             * the pool is already created */
                return ERR_MEM_POOL_CREATE;
            case TX_PTR_ERROR:
            /* Invalid starting address of the pool */
                return ERR_MEM_POOL_BAD_ADDRESS;
            case TX_SIZE_ERROR:
            /* Size of pool is invalid */
                return ERR_MEM_POOL_BAD_SIZE;
            default:
                return ERR_RTOS;
        }
    }


}
/*------------------------------------------------------------------*/

    extern MSTATUS
THREADX_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    TX_MUTEX* pTxMutex;
    MSTATUS   status = ERR_RTOS_MUTEX_CREATE;
    ubyte4    txStatus;
    /* MOC_UNUSED(mutexType); */
    MOC_UNUSED(mutexCount);

    if (NULL == (pTxMutex = MALLOC(sizeof(TX_MUTEX))))
        goto exit;

    /**
     * tx_mutex_create
     *
     * Prototype
     *   UINT tx_mutex_create(TX_MUTEX *mutex_ptr,
     *   CHAR *name_ptr, UINT priority_inherit)
     *
     *   Parameters
     *   mutex_ptr        Pointer to a mutex control block.
     *
     *   name_ptr         Pointer to the name of the mutex.
     *
     *   priority_inherit Specifies whether or not this mutex supports 
     *                      priority inheritance. If this value is
     *                      TX_INHERIT, then priority inheritance is 
     *                      supported. However, if TX_NO_INHERIT is 
     *                      specified, priority inheritance is not supported
     *                      by this mutex.
     */
    txStatus = tx_mutex_create(pTxMutex, "General Mutex"+mutexType,TX_INHERIT);
    if(TX_SUCCESS == txStatus){
        *pMutex = (RTOS_MUTEX)pTxMutex;
        status = OK;
    } else
    {
        FREE(pTxMutex);
    	status = ERR_RTOS_MUTEX_CREATE;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

    extern MSTATUS
THREADX_mutexWait(RTOS_MUTEX mutex)
{
    TX_MUTEX* pTxMutex = (TX_MUTEX *)mutex;
    MSTATUS   status   = ERR_GENERAL;
    ubyte4    txStatus;

    if(NULL == pTxMutex){
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /**
     * tx_mutex_get
     *
     * Prototype:
     * UINT tx_mutex_get(TX_MUTEX *mutex_ptr, ULONG wait_option)
     *
     * This service attempts to obtain exclusive ownership of the specified
     * mutex. If the calling thread already owns the mutex, an internal counter is
     * incremented and a successful status is returned.
     * If the mutex is owned by another thread and this thread is higher priority
     * and priority inheritance was specified at mutex create, the lower priority
     * thread’s priority will be temporarily raised to that of the calling thread.
     * The priority of the lower priority thread owning a mutex with priorityinheritance
     * should never be modified by an external thread during mutex
     * ownership.

     * Parameters
     * mutex_ptr   Pointer to a previously created mutex.
     * wait_option Defines how the service behaves if the mutex is
     *               already owned by another thread. The wait
     *               options are defined as follows:
     *                   TX_NO_WAIT (0x00000000)
     *                   TX_WAIT_FOREVER (0xFFFFFFFF)
     *                   timeout value (0x00000001 through 0xFFFFFFFE)

     *               Selecting TX_NO_WAIT results in an immediate
     *               return from this service regardless of whether or
     *               not it was successful. This is the only valid option
     *               if the service is called from Initialization.
     *
     *               Selecting TX_WAIT_FOREVER causes the
     *               calling thread to suspend indefinitely until the
     *               mutex is available.
     *
     *               Selecting a numeric value (1-0xFFFFFFFE)
     *               specifies the maximum number of timer-ticks to
     *               stay suspended while waiting for the mutex.
     *
     * Return Values
     * TX_SUCCESS       (0x00) Successful mutex get operation.
     * TX_DELETED       (0x01) Mutex was deleted while thread was suspended.
     * TX_NOT_AVAILABLE (0x1D) Service was unable to get ownership  of the 
     *                           mutex within the specified time to wait.
     * TX_WAIT_ABORTED  (0x1A) Suspension was aborted by another thread, 
     *                           timer, or ISR.
     * TX_MUTEX_ERROR   (0x1C) Invalid mutex pointer.
     * TX_WAIT_ERROR    (0x04) A wait option other than TX_NO_WAIT was 
     *                           specified on a call from a nonthread.
     * TX_CALLER_ERROR (0x13) Invalid caller of this service.
     *
     * Allowed From:
     * Initialization and threads and timers
     *
     * Preemption Possible
     * Yes
     */
    txStatus = tx_mutex_get(pTxMutex,TX_WAIT_FOREVER);

    switch(txStatus){
        case TX_SUCCESS:
            status = OK;
            goto exit;
        case TX_WAIT_ERROR:
            status = ERR_RTOS_MUTEX_WAIT;
            goto exit;
        default:
            status = ERR_RTOS;
            goto exit;
    }

exit:
    return status;
} /* THREADX_mutexWait */


/*------------------------------------------------------------------*/

    extern MSTATUS
THREADX_mutexRelease(RTOS_MUTEX mutex)
{
    TX_MUTEX* pTxMutex = (TX_MUTEX *)mutex;
    MSTATUS        status  = ERR_RTOS_MUTEX_RELEASE;
    ubyte4 txStatus;
    if(NULL == pTxMutex){
        status = ERR_NULL_POINTER;
        goto exit;
    }


    /**
     * tx_mutex_put
     *
     * Prototype
     * UINT tx_mutex_put(TX_MUTEX *mutex_ptr)
     *
     * This service decrements the ownership count of the specified mutex. If
     * the ownership count is zero, the mutex is made available.
     * If priority inheritance was selected during mutex creation, the priority of
     * the releasing thread will be restored to the priority it had when it originally
     * obtained ownership of the mutex. Any other priority changes made to the
     * releasing thread during ownership of the mutex may be undone.
     *
     * Parameters
     * mutex_ptr Pointer to the previously created mutex.
     *
     * Return Values
     * TX_SUCCESS      (0x00) Successful mutex release.
     * TX_NOT_OWNED    (0x1E) Mutex is not owned by caller.
     * TX_MUTEX_ERROR  (0x1C) Invalid pointer to mutex.
     * TX_CALLER_ERROR (0x13) Invalid caller of this service.
     *
     * Allowed From
     * Initialization and threads and timers
     *
     * Preemption Possible
     * Yes
     */
    if(TX_SUCCESS == (txStatus = tx_mutex_put(pTxMutex))){
        status = OK;
    }
exit:
    return status;
}


/*------------------------------------------------------------------*/

/**
 * Frees the memory allocated for a mutex
 */
extern MSTATUS THREADX_mutexFree(RTOS_MUTEX* pMutex)
{
    /**
     * tx_mutex_delete
     *
     * Prototype
     * UINT tx_mutex_delete(TX_MUTEX *mutex_ptr)
     *
     * Description
     * This service deletes the specified mutex. All threads suspended waiting
     * for the mutex are resumed and given a TX_DELETED return status.
     * It is the application’s responsibility to prevent use of a deleted mutex.
     *
     * Parameters
     * mutex_ptr Pointer to a previously created mutex.
     *
     * Return Values
     * TX_SUCCESS      (0x00) Successful mutex deletion.
     * TX_MUTEX_ERROR  (0x1C) Invalid mutex pointer.
     * TX_CALLER_ERROR (0x13) Invalid caller of this service.
     *
     * Allowed From:
     * Threads
     *
     * Preemption Possible
     * Yes
     */
	MSTATUS        status  = ERR_RTOS_MUTEX_FREE;
    if(TX_SUCCESS == tx_mutex_delete((TX_MUTEX*)*pMutex)){
        status = OK;
    } else {
        status = ERR_RTOS_MUTEX_FREE;
    }
	FREE(*pMutex);
    return status;
} /* THREADX_mutexFree */


/*------------------------------------------------------------------*/

/**
 * Returns internal system clock count.
 *
 * <b>Note</b>
 * The actual time each tick represents is application specific.
 */
    extern ubyte4
THREADX_getUpTimeInMS(void)
{
    /**
     * tx_time_get
     *
     * Prototype
     * ULONG tx_time_get(VOID)
     *
     * This service returns the contents of the internal system clock. Each 
     * timertick increases the internal system clock by one. The system clock
     * is set tozero during initialization and can be changed to a specific
     * value by the service tx_time_set.
     *
     * Note - The actual time each timer-tick represents is application specific.
     * 
     * Return Values
     * system clock ticks Value of the internal, free running, system clock.
     *
     * Allowed From:
     * Initialization, threads, timers, and ISRs
     *
     * Preemption Possible
     * No
     */
    return tx_time_get();
} /* THREADX_getUptimeInMS */


/*------------------------------------------------------------------*/

/**
 * Returns the difference in _clock ticks_ between the two moctime_t 
 * parameters.
 */
extern ubyte4 THREADX_deltaMS(const moctime_t* origin, moctime_t* current)
{
    ubyte4  retVal = 0;
    ubyte4  tickCount;

    /* see THREADX_getUpTimeInMS for special considrations when using 
     * tx_time_get().
     */
    tickCount = tx_time_get();

    if (origin)
    {
        retVal = (tickCount - origin->u.time[0]);
    }

    if (current)
    {
        current->u.time[0] = tickCount;
    }

    return retVal;
} /* THREADX_deltaMS */


/*------------------------------------------------------------------*/

    extern void
THREADX_sleepMS(ubyte4 sleepTimeInMS)
{
    tx_thread_sleep(sleepTimeInMS);
}

/*------------------------------------------------------------------*/

    /**
     * Creates a new thread
     *
     * Calls tx_thread_create to create a new thread. The threadEntry function
     * is called when the thread is started. The context is a void pointer to
     * application-specific data. The threadType is only used to name the
     * thread, though it is possible for the developer to allocate a thread
     * in different pools depending on the type. Lastly, the pRetTid points to
     * the nearly created PMTHREAD_CONTEXT structure.
     *
     */
    extern MSTATUS
THREADX_createThread(void(*threadEntry)(void*), void* context, ubyte4 threadType, RTOS_THREAD *pRetTid)
{

    MSTATUS          status = OK;
    PMTHREAD_CONTEXT pThreadContext;
    char             *threadName = NULL;

    /* Create the thread name based on the threadType param */
    switch (threadType)
    {
        case ENTROPY_THREAD:
            status = DIGI_CALLOC((void**)&threadName,22, sizeof(char));
            if(OK != status){
                goto exit;
            }

            status = DIGI_MEMCPY(threadName,"MOCANA_ENTROPY_THREAD",22);
            if(OK != status){
                goto exit;
            }

            break;
        case SSL_MAIN:
            status = DIGI_CALLOC((void**)&threadName,16, sizeof(char));
            if(OK != status){
                goto exit;
            }

            status = DIGI_MEMCPY(threadName,"MOCANA_SSL_MAIN",16);
            if(OK != status){
                goto exit;
            }

            break;
        default:
            status = ERR_RTOS_THREAD_CREATE;
#ifdef __ENABLE_ALL_DEBUGGING__
            printf("THREADX_createThread: unknown thread type.\n");
#endif
            goto exit;
    }

    pThreadContext = MALLOC(sizeof(MTHREAD_CONTEXT));
    if(NULL == pThreadContext){
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    pThreadContext->ThreadControl = moc_thread;
    pThreadContext->ThreadStack = &moc_thread_stack;

    /**
     * tx_thread_create
     *
     * Prototype
     * UINT tx_thread_create(TX_THREAD *thread_ptr,
     *       CHAR *name_ptr, VOID (*entry_function)(ULONG),
     *       ULONG entry_input, VOID *stack_start,
     *       ULONG stack_size, UINT priority,
     *       UINT preempt_threshold, ULONG time_slice,
     *       UINT auto_start)
     *
     * This service creates an application thread that starts execution at the
     * specified task entry function. The stack, priority, preemption-threshold, and
     * time-slice are among the attributes specified by the input parameters. In
     * addition, the initial execution state of the thread is also specified.
     *
     * Parameters
     * thread_ptr        Pointer to a thread control block.
     * name_ptr          Pointer to the name of the thread.
     * entry_function    Specifies the initial C function for thread execution.
     *                     When a thread returns from this entry function, it is
     *                     placed in a completed state and suspended
     *                     indefinitely.
     * entry_input       A 32-bit value that is passed to the thread’s entry
     *                     function when it first executes. The use for this
     *                     input is determined exclusively by the application.
     * stack_start       Starting address of the stack’s memory area.
     * stack_size        Number bytes in the stack memory area. The
     *                     thread’s stack area must be large enough to
     *                     handle its worst-case function call nesting and
     *                     local variable usage.
     * priority          Numerical priority of thread. Legal values range
     *                     from 0 through (TX_MAX_PRIORITES-1), where a
     *                     value of 0 represents the highest priority.
     * preempt_threshold Highest priority level (0 through
     *                     (TX_MAX_PRIORITIES-1)) of disabled 
     *                     preemption. Only priorities higher than this level
     *                     are allowed to preempt this thread. This value
     *                     must be less than or equal to the specified
     *                     priority. A value equal to the thread priority
     *                     disables preemption-threshold.
     * time_slice        Number of timer-ticks this thread is allowed to
     *                     run before other ready threads of the same
     *                     priority are given a chance to run. Note that
     *                     using preemption-threshold disables time-slicing.
     *                     Legal time-slice values range from 1 to
     *                     0xFFFFFFFF (inclusive). A value of
     *                     TX_NO_TIME_SLICE (a value of 0) disables
     *                     time-slicing of this thread.
     *                     Using time-slicing results in a slight amount of
     *                     system overhead. Since time-slicing is only
     *                     useful in cases where multiple threads share the
     *                     same priority, threads having a unique priority
     *                     should not be assigned a time-slice.
     * auto_start        Specifies whether the thread starts immediately
     *                     or is placed in a suspended state. Legal options
     *                     are TX_AUTO_START (0x01) and
     *                     TX_DONT_START (0x00). If TX_DONT_START
     *                     is specified, the application must later call
     *                     tx_thread_resume in order for the thread to run.
     *
     * Return Values
     * TX_SUCCESS        (0x00) Successful thread creation.
     * TX_THREAD_ERROR   (0x0E) Invalid thread control
     *                            pointer. Either the pointer is
     *                            NULL or the thread is
     *                            already created.
     * TX_PTR_ERROR      (0x03) Invalid starting address of
     *                            the entry point or the stack
     *                            area is invalid, usually
     *                            NULL.
     * TX_SIZE_ERROR     (0x05) Size of stack area is invalid.
     *                            Threads must have at least TX_MINIMUM_STACK
     *                            bytes to execute.
     * TX_PRIORITY_ERROR (0x0F) Invalid thread priority, which is a value 
     *                            outside the range of 
     *                            (0 through (TX_MAX_PRIORITIES-1)).
     * TX_THRESH_ERROR   (0x18) Invalid preemptionthreshold
     *                            specified. This value must be a valid priority
     *                            less than or equal to the initial priority 
     *                            of the thread.
     * TX_START_ERROR    (0x10) Invalid auto-start selection.
     * TX_CALLER_ERROR   (0x13) Invalid caller of this service.

     * Allowed From:
     * Initialization and threads
     *
     * Preemption Possible
     * Yes
     */
     status = tx_thread_create(
                &moc_thread, /* TX_THREAD*       Thread pointer */
                threadName                    ,   /* CHAR*            Thread Name */
                (Thread_ENTRY_FUNC)threadEntry,   /* VOID(*)(ULONG)   Entry function */
                (ULONG)context,                   /* void* as ULONG   Entry input */
                &moc_thread_stack,   /* void*            Stack start */
                MOCANA_THREAD_STACK_SIZE,         /* ULONG            Stack size */
                MOCANA_THREAD_PRI,                /* UINT             Thread priority */
                MOCANA_THREAD_PRI,                /* (disable)        Preemption threshold */
                TX_NO_TIME_SLICE,                 /* (disable)        Time slice */
                TX_AUTO_START);                   /* UINT             Auto start */

    if(status == TX_SUCCESS)
    {
        *pRetTid = pThreadContext;
    }
    else
    {
        THREADX_free(pThreadContext);
        status = ERR_RTOS_THREAD_CREATE;
    }

exit:
    if(OK != status){
        if(NULL != threadName){
            DIGI_FREE((void**)&threadName);
        }
    }

    return status;
} /* THREADX_createThread */


/*------------------------------------------------------------------*/

    extern void
THREADX_destroyThread(RTOS_THREAD tid)
{
    PMTHREAD_CONTEXT    pThreadContext = (PMTHREAD_CONTEXT)tid;
    if(pThreadContext!= NULL)
    {
        if(TX_SUCCESS == tx_thread_terminate((TX_THREAD*)&(pThreadContext->ThreadControl))){
            if(TX_SUCCESS == tx_thread_delete((TX_THREAD*)&(pThreadContext->ThreadControl))){
                THREADX_free(pThreadContext);
            }
        }
    }
} /* THREADX_destroyThread */

#endif /* __THREADX_RTOS__ */
