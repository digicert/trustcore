/*
 * ike2_nist_sample.c
 *
 * Sample code for testing IKEv2 against SP 800-135
 *
 */

#include "../../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#ifndef __RTOS_WINCE__
#include <errno.h>
#endif

#ifdef __PLATFORM_HAS_GETOPT__
#ifdef __OSE_RTOS__
#include <getopt.h>
#include <string.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#endif

#if defined(__WIN32_RTOS__) || defined(__RTOS_WINCE__)
  #define WIN32_LEAN_AND_MEAN
  #ifndef _WIN32_WINNT
  #define _WIN32_WINNT 0x0400
  #endif

  #include <windows.h>
  #include <winbase.h>
  #include <winsock2.h>
  #include <Ws2tcpip.h>
  #include <iphlpapi.h>
  #if defined(_DEBUG) && !defined(__RTOS_WINCE__)
  #include <crtdbg.h>
  #endif
#elif defined(__LINUX_RTOS__) || defined(__OPENBSD_RTOS__) || defined(__QNX_RTOS__) || defined(__CYGWIN_RTOS__) || defined(__ANDROID_RTOS__) || defined(__OSX_RTOS__)
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <arpa/inet.h>
#elif defined(__VXWORKS_RTOS__)
  #include <vxWorks.h>
  #include <sockLib.h>
  #include <inetLib.h>
#elif defined(__OSE_RTOS__)
  #include <inet.h>
#elif defined(__INTEGRITY_RTOS__)
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <arpa/inet.h>
#endif

#include "../../../common/mdefs.h"
#include "../../../common/mtypes.h"
#include "../../../common/merrors.h"
#include "../../../common/mrtos.h"
#include "../../../common/mocana.h"
#include "../../../common/debug_console.h"
#include "../../../common/mstdlib.h"
#include "../../../common/mudp.h"
#include "../../../common/vlong.h"
#include "../../../common/random.h"
#include "../../../crypto/crypto.h"
#include "../../../crypto/pubcrypto.h"
#include "../../../crypto/ca_mgmt.h"
#include "../../../asn1/oiddefs.h"
#include "../../../common/sizedbuffer.h"
#include "../../../crypto/cert_store.h"
#include "../../../crypto/hw_accel.h"
#include "../../../ipsec/ipsec.h"
#include "../../../ipsec/ipsec_defs.h"
#include "../../../ipsec/ipsecconf.h"
#include "../../../ipsec/ipseckey.h"
#include "../../../ike/ike.h"
#include "../../../ike/ike_defs.h"
#include "../../../ike/ike_event.h"
#include "../../../ike/ike_utils.h"
#include "../../../ike/ike_status.h"
#include "../../../ike/ike_state.h"
#include "../../../ike/ikesa.h"
#include "../../../ike/ikekey.h"

#include "../../../ike2/nist/ike2_nist.h"

static sbyte4
IKE_SAMPLE_ikeGetHostAddr(MOC_IP_ADDRESS_S *pHostAddr, sbyte4 serverInstance)
{
    *pHostAddr = 1;
    return OK;

} /* IKE_SAMPLE_ikeGetHostAddr */

/* Utility functions used in sample code */
static ubyte UTILS_ValOfHexChar( sbyte c)
{
    if ('0' <= c && c <= '9')
    {
        return (ubyte) (c - '0');
    }
    else if ( 'A' <= c && c <= 'F')
    {
        return (ubyte) ( c + 10 - 'A');
    }
    else if ( 'a' <= c && c <= 'f')
    {
        return (ubyte) ( c + 10 - 'a');
    }
    return 0;
}

static ubyte4 UTILS_str_to_byteStr( const sbyte* s, ubyte** bs)
{
    ubyte* buffer = 0;
    ubyte4 bsLen;
    ubyte4 sLen = DIGI_STRLEN( s);
    ubyte* pTemp;

    bsLen = (sLen+1)/2;
    buffer = MALLOC( bsLen + 1); /* to prevent a malloc 0 */
    if (!buffer)
    {
        *bs = 0;
        return 0;
    }

    pTemp = buffer;

    if ( sLen & 1)
    {
        *pTemp++ = UTILS_ValOfHexChar(*s++);
    }
    while ( *s)
    {
        *pTemp = (ubyte) ((UTILS_ValOfHexChar(*s++)) << 4);
        *pTemp++ |= (UTILS_ValOfHexChar(*s++));
    }
    *bs = buffer;
    return bsLen;
}

MSTATUS sampleUsageIKE()
{
    MSTATUS status;
    IKESA pSa1 = NULL;
    IKESA pSa2 = NULL;
    ikePeerConfig emptyConfig = { 0 };
    MOC_IP_ADDRESS ip;
    sbyte4 serverInstance = 1;
    intBoolean b = FALSE;
    struct ike_context ctx = { NULL };
    ubyte4 i = 0;
    sbyte4 ret = 0;

    ubyte *pNonceI = NULL;
    ubyte4 iLen = 0;
    ubyte *pNonceR = NULL;
    ubyte4 rLen = 0;
    ubyte *pII = NULL;
    ubyte4 iiLen = 0;
    ubyte *pIR = NULL;
    ubyte4 irLen = 0;
    ubyte *pSecret = NULL;
    ubyte4 secretLen = 0;
    ubyte *pNewSecret = NULL;
    ubyte4 newSecretLen = 0;

    ubyte *pSeed = NULL;
    ubyte4 seedLen = 0;
    ubyte *pDKM = NULL;
    ubyte4 dkmLen = 0;
    ubyte *pChildDkm = NULL;
    ubyte4 childDkmLen = 0;
    ubyte *pChildDhDkm = NULL;
    ubyte4 childDhDkmLen = 0;
    ubyte *pReseed = NULL;
    ubyte4 reseedLen = 0;

    /* DIGICERT_initDigicert must be called one time before operation */
    status = DIGICERT_initDigicert();
    if (OK != status)
        goto exit;

    iLen = UTILS_str_to_byteStr(
        "ed80dc79912c32a9", &pNonceI);
    rLen = UTILS_str_to_byteStr(
        "35fb6d1a3feac078", &pNonceR);
    iiLen = UTILS_str_to_byteStr(
        "47c1858efc932ea4", &pII);
    irLen = UTILS_str_to_byteStr(
        "606fd05609624002", &pIR);
    secretLen = UTILS_str_to_byteStr(
        "42968e5d0ccc3cfc5a3e4bc1bba370cea1fae0d54c49ccba34b2bee804beeb2e9e8c57a4e01bd45102cf2433aacc6cfec06792f363e5170e6aa6650274e906648e449d27a8f00b5b44261982c9835c748a751ec5138eaacc5e025661339538a61bf418e454699e19c32db8d9ce5dd86b220f1e89afc5872e68be36cb1a0c8866", &pSecret);
    newSecretLen = UTILS_str_to_byteStr(
        "a0747f546ca1460016828843c9a5bfaff64f1beb0eaf2a7999a55790851546b93e79600e9c1fd263f10e0a6b0b3efe0cada3e57e2352779156392d2372fe834e874d0aaecff5d1ba0dfb02b1b7848275e5f6951a57fda99d365acf3a8909139ad8714995ffc7aedd5764d36c1a6936afacfbee7ab74a44695019ee544c9b525f", &pNewSecret);

    /* initialize the IKE tables and structures */
    if (0 > (ret = IKE_init()))
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    IKE_ikeSettings()->funcPtrIkeGetHostAddr    = IKE_SAMPLE_ikeGetHostAddr;

    pSa1 = IKE2_newSa(&emptyConfig, ip, 0, NULL, NULL, b);
    if (NULL == pSa1)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    /* Set vector values in SA1 */
    status = setIKEValue(pSa1, IkeInitiatorNonce, pNonceI, iLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    status = setIKEValue(pSa1, IkeResponderNonce, pNonceR, rLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    status = setIKEValue(pSa1, IkeInitiatorIndex, pII, iiLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    status = setIKEValue(pSa1, IkeResponderIndex, pIR, irLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    status = setIKEValue(pSa1, IkeSharedSecret, pSecret, secretLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    /* Set the desired DKM len */
    status = setIKEDkmLen(pSa1, ht_sha256, 132);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    /* Set both SA as SA1 */
    status = setIKESA(&ctx, pSa1);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    status = setIKEOldSA(&ctx, pSa1);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    /* Generate SKEYSEED and DKM */
    status = DoKe(&ctx);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    /* Retrieve generated values */
    status = getIKEValue(&ctx, IkeSKEYSEED, &pSeed, &seedLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    printf("seed len: %d SKEYSEED value:\n", seedLen);
    for (i = 0; i < seedLen; i++)
    {
        printf("%02x", pSeed[i]);
    }
    printf("\n");

    status = getIKEValue(&ctx, IkeDKM, &pDKM, &dkmLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    printf("DKM len: %d DKM value:\n", dkmLen);
    for (i = 0; i < dkmLen; i++)
    {
        printf("%02x", pDKM[i]);
    }
    printf("\n");

    /* Set the child SA DKM len */
    status = setIKEChildDkmLen(&ctx, ht_sha256, 132);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    /* Generate Child SA DKM */
    status = DoKe2(&ctx);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    status = getIKEValue(&ctx, IkeDKMChildSa, &pChildDkm, &childDkmLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    printf("Child DKM len: %d Child DKM value:\n", childDkmLen);
    for (i = 0; i < childDkmLen; i++)
    {
        printf("%02x", pChildDkm[i]);
    }
    printf("\n");

    /* Set the new shared secret g^ir (new), setIKENewSharedSecret is only 
     * used for setting g^ir (new) for generating Child SA DH DKM */
    status = setIKENewSharedSecret(&ctx, pNewSecret, newSecretLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    /* Generate Child SA DH DKM */
    status = DoKe2(&ctx);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    status = getIKEValue(&ctx, IkeDKMChildSa, &pChildDhDkm, &childDhDkmLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    printf("Child DH DKM len: %d Child DH DKM value:\n", childDhDkmLen);
    for (i = 0; i < childDhDkmLen; i++)
    {
        printf("%02x", pChildDhDkm[i]);
    }
    printf("\n");

    /* Create SA1 */
    pSa2 = IKE2_newSa(&emptyConfig, ip, 0, NULL, NULL, b);
    if (NULL == pSa2)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    /* Set the original nonces into SA2 */
    status = setIKEValue(pSa2, IkeInitiatorNonce, pNonceI, iLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    status = setIKEValue(pSa2, IkeResponderNonce, pNonceR, rLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    /* For this step, use setIKEValue to set g^ir (new) into SA2 */
    status = setIKEValue(pSa2, IkeSharedSecret, pNewSecret, newSecretLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    /* Must set lengths in new SA */
    status = setIKEDkmLen(pSa2, ht_sha256, 132);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    /* Set SA2 in prep for generating SKEYSEED (reseed) */
    status = setIKEOldSA(&ctx, pSa2);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    /* Generate SKEYSEED (reseed) */
    status = DoKe(&ctx);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    status = getIKEValue(&ctx, IkeSKEYSEED, &pReseed, &reseedLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    printf("reseed len: %d SKEYSEED(Rekey) value:\n", reseedLen);
    for (i = 0; i < reseedLen; i++)
    {
        printf("%02x", pReseed[i]);
    }
    printf("\n");

exit:
    DIGI_FREE((void **)&pNonceI);
    DIGI_FREE((void **)&pNonceR);
    DIGI_FREE((void **)&pII);
    DIGI_FREE((void **)&pIR);
    DIGI_FREE((void **)&pSecret);
    DIGI_FREE((void **)&pNewSecret);
    DIGI_FREE((void **)&pSeed);
    DIGI_FREE((void **)&pDKM);
    DIGI_FREE((void **)&pChildDkm);
    DIGI_FREE((void **)&pChildDhDkm);
    DIGI_FREE((void **)&pReseed);
    if (NULL != pSa1) FreeSa(pSa1);
    if (NULL != pSa2) FreeSa(pSa2);
    return status;
}

int main(int argc, char *argv[])
{
    MSTATUS status = OK;
    status = sampleUsageIKE();
    printf("sampleUsageIKE status = %d\n", status);
    return 0;
}
#endif
