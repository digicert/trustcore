#ifndef __MUDP_CUSTOM_HEADER__
#define __MUDP_CUSTOM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/
/*                Add your own custom #defines here                 */
/*------------------------------------------------------------------*/

#if defined(__MYOS_UDP__)
#define __CUSTOM_UDP__

/* Map UDP_ macros from mudp.h for the appropriate methods/structures.
 * For example:
 *   #define UDP_init       MYOS_UDP_init
 *
 * where MYOS_UDP_init is an user defined method.
 */


#endif

/*------------------------------------------------------------------*/
#ifdef __cplusplus
}
#endif
#endif
