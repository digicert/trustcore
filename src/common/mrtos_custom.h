#ifndef __MRTOS_CUSTOM_HEADER__
#define __MRTOS_CUSTOM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif
/*------------------------------------------------------------------*/
/*                Add your own custom #defines here                 */
/*------------------------------------------------------------------*/

#if defined(__MYOS_RTOS__)
#define  __CUSTOM_RTOS__

/* Map RTOS_ macros from mrtos.h for the appropriate methods/structures.
 * For example:
 *   #define RTOS_rtosInit       MYOS_rtosInit
 *
 * where MYOS_rtosInit is an user defined method.
 */
#define RTOS_malloc                 MYOS_malloc
#define RTOS_free                   MYOS_free

#endif

/*------------------------------------------------------------------*/
#ifdef __cplusplus
}
#endif
#endif
