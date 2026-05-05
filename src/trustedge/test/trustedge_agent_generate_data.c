/*
 * trustedge_agent_generate_data.c
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

#include "../../common/moptions.h"
#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mocana.h"
#include "../../common/mstdlib.h"

#include <stdio.h>

#include "../../common/protobuf.h"

void displayHelp()
{
    printf("Usage: trustedge_agent_simulate_data [options]\n");
    printf("\n");
    printf("Options:\n");
    printf("    --msg-uuid <UUID>           - Optional, Protobuf UUID for CUSTOM messages\n");
    printf("    --msg-metric <name> <value> - Optional, Protobuf metric for CUSTOM messages, can be specified multiple times\n");
    printf("    --msg-body-file <file>      - Optional, Protobuf body for CUSTOM messages, file contents are stored as body\n");
    printf("    --out-file <file>           - Required, Location on file system where encoded message is stored\n");
    printf("\n");
}

int main(int argc, char **ppArgv)
{
    int i;
    ubyte *pBody = NULL;
    ubyte4 bodyLen = 0;
    ProtobufPayload payload;
    ubyte *body = NULL;
    ubyte4 msgLen;
    MSTATUS status;
    ubyte *pMsg = NULL;
    char *pOutFile = NULL;
    sbyte *uuid = NULL;
    ubyte4 uuidLen;

    if (argc <= 1)
    {
        displayHelp();
        goto exit;
    }

    PROTOBUF_resetSequenceNumber();

    status = PROTOBUF_preparePayload(&payload);
    if (OK != status)
    {
        goto exit;
    }

    for (i = 1; i < argc; i++)
    {
        if (0 == DIGI_STRCMP(ppArgv[i], "--msg-uuid"))
        {
            i++;
            uuidLen = DIGI_STRLEN(ppArgv[i]);
            status = DIGI_MALLOC((void**)&uuid, uuidLen + 1);
            if (OK != status)
            {
                goto exit;
            }
            DIGI_MEMCPY(uuid, ppArgv[i], uuidLen);
            payload.pUuid = uuid;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], "--msg-metric"))
        {
            PROTOBUF_addMetricToPayload(&payload, ppArgv[i+1], ppArgv[i+2], PB_METRIC_DATA_TYPE_STRING, DIGI_STRLEN(ppArgv[i+2]));
            i += 2;
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], "--msg-body-file"))
        {
            i++;
            status = DIGICERT_readFile(ppArgv[i], &pBody, &bodyLen);
            if (OK != status)
            {
                goto exit;
            }
        }
        else if (0 == DIGI_STRCMP(ppArgv[i], "--out-file"))
        {
            i++;
            pOutFile = ppArgv[i];
        }
        else
        {
            displayHelp();
            goto exit;
        }
    }

    if (NULL == pOutFile)
    {
        printf("--out-file must be provided\n");
        goto exit;
    }

    if (NULL != pBody)
    {
        status = DIGI_MALLOC((void**)&body, bodyLen);
        if (OK != status)
        {
            goto exit;
        }
        DIGI_MEMCPY(body, pBody, bodyLen);

        payload.pBody = body;
        payload.bodyLen = bodyLen;
    }

    status = PROTOBUF_encodePayload(&payload, &pMsg, &msgLen);

    status = DIGICERT_writeFile(pOutFile, pMsg, msgLen);
    if (OK != status)
    {
        goto exit;
    }

    printf("Successfully generated message and stored at %s\n", pOutFile);

exit:

    return 0;
}
