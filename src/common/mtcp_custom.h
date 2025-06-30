#ifndef __MTCP_CUSTOM_HEADER__
#define __MTCP_CUSTOM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/
/*                Add your own custom #defines here                 */
/*------------------------------------------------------------------*/

#if defined(__MYOS_TCP__)
#define __CUSTOM_TCP__

/* Map TCP_ macros from mtcp.h for the appropriate methods/structures.
 * For example:
 *   #define TCP_INIT       MYOS_TCP_init
 *
 * where MYOS_TCP_init is an user defined method.
 */


#endif

/*------------------------------------------------------------------*/
#ifdef __cplusplus
}
#endif
#endif
