/**
 * @file mtypes.h
 *
 * @ingroup common_tree
 * @ingroup common_nanotap_tree
 *
 * @brief Mocana Types
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


/*------------------------------------------------------------------*/

#ifndef __MTYPES_HEADER__
#define __MTYPES_HEADER__


#ifndef __ENABLE_MOCANA_BASIC_TYPES_OVERRIDE__
/*! @brief Default unsigned 1-byte type */
typedef unsigned char           ubyte;
/*! @brief Default unsigned 2-byte type */
typedef unsigned short          ubyte2;
#if ((__SIZEOF_LONG__ == 4) && (__SIZEOF_INT__ != 4))
/*! @brief Default unsigned 4-byte type */
typedef unsigned long           ubyte4;
#else
/*! @brief Default unsigned 4-byte type */
typedef unsigned int            ubyte4;
#endif

/*! @brief Default signed 1-byte type */
typedef signed char             sbyte;
/*! @brief Default signed 2-byte type */
typedef signed short            sbyte2;
#if ((__SIZEOF_LONG__ == 4) && (__SIZEOF_INT__ != 4))
/*! @brief Default signed 4-byte type */
typedef signed long             sbyte4;
#else
/*! @brief Default signed 4-byte type */
typedef signed int              sbyte4;
#endif


#endif

/* gcc 2.95 does not define __LONG_LONG_MAX__ and __LONG_MAX__ as built-in
This code forces the use of long long for all GCC -- using limits.h does
not seem to work (__LONG_LONG_MAX__ is still undefined) */
#if defined (__GNUC__)

/**
 * @cond __DOXYGEN_DONT_SHOW__
 */
#if !defined(__LONG_LONG_MAX__)
#define __LONG_LONG_MAX__ 9223372036854775807LL
#endif

#if !defined(__LONG_MAX__)
#define __LONG_MAX__ 2147483647L
#endif
/**
 * @endcond
 */

#endif /* __GNUC__ */

#if defined(__ARMCC_VERSION) || defined (__RTOS_WIN32__) || defined (__RTOS_VXWORKS__) || defined( __ENABLE_MOCANA_64_BIT__) || defined(__LP64__) || (defined(__LONG_LONG_MAX__) && __LONG_LONG_MAX__ > __LONG_MAX__ && !defined(__MOCANA_MAX_INT_32__) ) || (defined(_INTEGRAL_MAX_BITS) && _INTEGRAL_MAX_BITS >= 64)

/**
 * @cond __DOXYGEN_DONT_SHOW__
 */
#define __MOCANA_MAX_INT__ (64)
/**
 * @endcond
 */

#if defined( _MSC_VER)
/*! @brief Unsigned 8-byte type */
typedef unsigned __int64        ubyte8;
/*! @brief Signed 8-byte type */
typedef signed __int64          sbyte8;
#else
/*! @brief Unsigned 8-byte type */
typedef unsigned long long ubyte8;
/*! @brief Signed 8-byte type */
typedef signed long long sbyte8;
#endif


/*! @brief Unsigned 16-byte type */
/*! @details Unsigned 16-byte type */
typedef struct ubyte16
{
    /* @brief Upper 8-byte (64-bit) field */
    ubyte8 upper64;
    /* @brief Lower 8-byte (64-bit) field */
    ubyte8 lower64;
} ubyte16;


#else

/**
 * @cond __DOXYGEN_DONT_SHOW__
 */
#define __MOCANA_MAX_INT__ (32)
/**
 * @endcond
 */

/*! @brief Unsigned 8-byte type */
/*! @details Unsigned 8-byte type */
typedef struct
{
    /*! @brief Upper 4-byte (32-bit) field */
    ubyte4  upper32;
    /*! @brief Lower 4-byte (32-bit) field */
    ubyte4  lower32;

} ubyte8;

/*! @brief Unsigned 16-byte type */
/*! @details Unsigned 16-byte type */
typedef struct ubyte16
{
    /*! @brief 1st 4-byte word */
    ubyte4 w1;
    /*! @brief 2nd 4-byte word */
    ubyte4 w2;
    /*! @brief 3rd 4-byte word */
    ubyte4 w3;
    /*! @brief 4th 4-byte word */
    ubyte4 w4;
} ubyte16;

#endif /* __ENABLE_MOCANA_64_BIT__ */

/**
 * @cond __DOXYGEN_DONT_SHOW__
 */
#if __LONG_MAX__ == __INT_MAX__
typedef ubyte4 usize;
#else
typedef ubyte8 usize;
#endif
/**
 * @endcond
 */

/*! @brief One-byte boolean type */
typedef sbyte               byteBoolean;
/*! @brief Integer boolean type */
typedef sbyte4              intBoolean;

/**
 * @cond __DOXYGEN_DONT_SHOW__
 */
typedef void*               BulkCtx;
/**
 * @endcond
 */

/* Intentionally not a real pointer--used in pointer math */
/**
 * @cond __DOXYGEN_DONT_SHOW__
 */
#if defined(__RTOS_WIN32__) && defined(_WIN64)
typedef unsigned __int64    uintptr;
#else
typedef usize               uintptr;
#endif
/**
 * @endcond
 */

/**
 * @cond __DOXYGEN_DONT_SHOW__
 */
#ifdef __ENABLE_MOCANA_IPV6__
typedef struct moc_ipaddr
{
    ubyte2 family;          /* AF_INET or AF_INET6 */
    union
    {
        ubyte4 addr6[5];    /* IPv6 (128 bits); in network byte order
                               (with trailing scope id in host byte order) */
        ubyte4 addr;        /* IPv4 (32 bits); in host byte order */
    } uin;

} *MOC_IP_ADDRESS, MOC_IP_ADDRESS_S;
#else
#ifndef __ENABLE_MOCANA_NETWORK_TYPES_OVERRIDE__
/* KJW - Make 64-bit safe, avoid 'long' */
typedef ubyte4              MOC_IP_ADDRESS;
#endif
#define MOC_IP_ADDRESS_S    MOC_IP_ADDRESS
#endif
/**
 * @endcond
 */

/**
 * @details The Universally Unique IDentifier as defined by RFC 4122.
 */
typedef struct
{
    /*! The low field of the timestamp */
    ubyte4  timeLow;
    /*! The middle field of the timestamp */
    ubyte2  timeMid;
    /*! The high field of the timestamp */
    ubyte2  timeHigh;
    /*! The high field of the clock sequence */
    ubyte   clockSeqHigh;
    /*! The low field of the clock sequence */
    ubyte   clockSeqLow;
    /*! The spatially unique node identifier */
    ubyte   node[6];
} MOC_UUID;

typedef enum dataType
{
    DATA_TYPE_UNDEFINED = 0,
    DATA_TYPE_PASSWORD,
    DATA_TYPE_CERT,
    DATA_TYPE_KEY,
    DATA_TYPE_OBJECT
} dataType;

typedef enum dataEncoding
{
    DATA_ENCODE_UNDEFINED = 0,
    DATA_ENCODE_PLAINTEXT,
    DATA_ENCODE_SHA1,
    DATA_ENCODE_SHA256,
    DATA_ENCODE_DER,
    DATA_ENCODE_PEM,
    DATA_ENCODE_BYTE_BUFFER
} dataEncoding;

#ifdef __RTOS_WIN32__
#include <basetsd.h>
#ifndef __MINGW32__
typedef SSIZE_T ssize_t;
#endif /* !__MINGW32__ */
#endif /* __RTOS_WIN32__ */

#endif /* __MTYPES_HEADER__ */
