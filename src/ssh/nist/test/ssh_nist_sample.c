/*
 * ssl_nist_sample.c
 *
 * Sample code for testing TLS 1.2 against SP 800-135
 *
 */

#include "../../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SP800_135_ACVP__

#include <string.h>
#include <stdio.h>

#include "../../../common/mtypes.h"
#include "../../../common/mocana.h"
#include "../../../crypto/hw_accel.h"
#include "../../../common/debug_console.h"
#include "../../../common/mdefs.h"
#include "../../../common/merrors.h"
#include "../../../common/mrtos.h"
#include "../../../common/mstdlib.h"
#include "../../../common/mfmgmt.h"
#include "../../../common/mtcp.h"
#include "../../../common/int64.h"
#include "../../../crypto/pubcrypto.h"
#include "../../../crypto/ca_mgmt.h"
#include "../../../common/sizedbuffer.h"
#include "../../../common/moc_stream.h"
#include "../../../common/mem_pool.h"
#include "../../../crypto/cert_store.h"
#include "../../../crypto/cert_chain.h"
#include "../../../ssh/ssh_filesys.h"
#include "../../../ssh/sftp.h"
#include "../../../ssh/ssh.h"
#include "../../../ssh/ssh_utils.h"
#include "../../../ssh/ssh_str.h"
#include "../../../ssh/ssh_context.h"

#include "../../../ssh/nist/ssh_nist.h"

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

MSTATUS sampleUsageSSH()
{
    MSTATUS status;
    ubyte *pOptions = NULL;
    sshContext *pCtx = NULL;

    ubyte *pK = NULL;
    ubyte4 kLen = 0;
    ubyte *pH = NULL;
    ubyte4 hLen = 0;
    ubyte *pSession = NULL;
    ubyte4 sessionLen = 0;
    ubyte *pIVCTS = NULL;
    ubyte4 ivCTSLen = 0;
    ubyte *pCTSIV = NULL;
    ubyte4 ctsIvLen = 0;
    ubyte *pSTCIV = NULL;
    ubyte4 stcIvLen = 0;
    ubyte *pEncrCTS = NULL;
    ubyte4 encrCTSLen = 0;
    ubyte *pEncrSTC = NULL;
    ubyte4 encrSTCLen = 0;
    ubyte *pIntegCTS = NULL;
    ubyte4 integCTSLen = 0;
    ubyte *pIntegSTC = NULL;
    ubyte4 integSTCLen = 0;
    ubyte4 i = 0;
    ubyte msg = 21;

    /* DIGICERT_initDigicert must be called one time before operation */
    status = DIGICERT_initDigicert();
    if (OK != status)
        goto exit;

    status = SSH_CONTEXT_allocStructures(&pCtx);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    status = setSSHDesiredLengths(pCtx, ht_sha1, 8, 24, &pOptions);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    kLen = UTILS_str_to_byteStr(
        "0000008055bae931c07fd824bf10add1902b6fbc7c665347383498a686929ff5a25f8e40cb6645ea814fb1a5e0a11f852f86255641e5ed986e83a78bc8269480eac0b0dfd770cab92e7a28dd87ff452466d6ae867cead63b366b1c286e6c4811a9f14c27aea14c5171d49b78c06e3735d36e6a3be321dd5fc82308f34ee1cb17fba94a59", &pK);
    hLen = UTILS_str_to_byteStr(
        "a4ebd45934f56792b5112dcd75a1075fdc889245", &pH);
    sessionLen = UTILS_str_to_byteStr(
        "a4ebd45934f56792b5112dcd75a1075fdc889245", &pSession);

    status = setSSHValue(pCtx, sshK, pK, kLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    status = setSSHValue(pCtx, sshH, pH, hLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    status = setSSHValue(pCtx, sshSessionId, pSession, sessionLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    status = receiveNewKeysMessage(pCtx, pOptions, &msg, 1);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    status = getSSHValue(pCtx, pOptions, sshCTSIV, &pCTSIV, &ctsIvLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    printf("CTSIV:\n");
    for (i = 0; i < ctsIvLen; i++)
    {
        printf("%02x", pCTSIV[i]);
    }
    printf("\n");

    status = getSSHValue(pCtx, pOptions, sshSTCIV, &pSTCIV, &stcIvLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    printf("STCIV:\n");
    for (i = 0; i < stcIvLen; i++)
    {
        printf("%02x", pSTCIV[i]);
    }
    printf("\n");

    status = getSSHValue(pCtx, pOptions, sshEncrCTS, &pEncrCTS, &encrCTSLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    printf("sshEncrCTS:\n");
    for (i = 0; i < encrCTSLen; i++)
    {
        printf("%02x", pEncrCTS[i]);
    }
    printf("\n");

    status = getSSHValue(pCtx, pOptions, sshEncrSTC, &pEncrSTC, &encrSTCLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    printf("sshEncrSTC:\n");
    for (i = 0; i < encrSTCLen; i++)
    {
        printf("%02x", pEncrSTC[i]);
    }
    printf("\n");

    status = getSSHValue(pCtx, pOptions, sshIntegrityCTS, &pIntegCTS, &integCTSLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    printf("sshIntegrityCTS:\n");
    for (i = 0; i < integCTSLen; i++)
    {
        printf("%02x", pIntegCTS[i]);
    }
    printf("\n");

    status = getSSHValue(pCtx, pOptions, sshIntegritySTC, &pIntegSTC, &integSTCLen);
    if (OK != status)
    {
        printf("ERROR: line %d status %d\n", __LINE__, status);
        goto exit;
    }

    printf("sshIntegritySTC:\n");
    for (i = 0; i < integSTCLen; i++)
    {
        printf("%02x", pIntegSTC[i]);
    }
    printf("\n");

exit:
    freeSSHK(pCtx);
    SSH_CONTEXT_deallocStructures(&pCtx);
    DIGI_FREE((void **)&pOptions);
    DIGI_FREE((void **)&pK);
    DIGI_FREE((void **)&pH);
    DIGI_FREE((void **)&pSession);
    DIGI_FREE((void **)&pIVCTS);
    DIGI_FREE((void **)&pCTSIV);
    DIGI_FREE((void **)&pSTCIV);
    DIGI_FREE((void **)&pEncrCTS);
    DIGI_FREE((void **)&pEncrSTC);
    DIGI_FREE((void **)&pIntegCTS);
    DIGI_FREE((void **)&pIntegSTC);
    DIGICERT_freeDigicert();
    return status;
}

int main(int argc, char *argv[])
{
    MSTATUS status = OK;
    status = sampleUsageSSH();
    printf("sampleUsageSSH status = %d\n", status);
    return 0;
}
#endif
