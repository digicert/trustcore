/*
 * mqtt_msg.c
 *
 * MQTT message handling internals
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

#ifdef __ENABLE_MQTT_CLIENT__

#if defined(__ENABLE_MQTT_CLIENT_DUMP_MESSAGES__)
#warning "*** WARNING: Debug flag __ENABLE_MQTT_CLIENT_DUMP_MESSAGES__ has been enabled."

#include <stdio.h>
#endif

#include "mqtt_client.h"
#include "mqtt_client_priv.h"
#include "mqtt_core.h"
#include "mqtt_util.h"

#define MQTT_CONNECT_TYPE_VAL       0x10
#define MQTT_SUBSCRIBE_TYPE_VAL     0x82
#define MQTT_UNSUBSCRIBE_TYPE_VAL   0xA2
#define MQTT_PUBLISH_TYPE_VAL       0x30
#define MQTT_PUBACK_TYPE_VAL        0x40
#define MQTT_PUBREC_TYPE_VAL        0x50
#define MQTT_PUBREL_TYPE_VAL        0x60
#define MQTT_PUBCOMP_TYPE_VAL       0x70
#define MQTT_PING_TYPE_VAL          0xC0
#define MQTT_DISCONNECT_TYPE_VAL    0xE0
#define MQTT_AUTH_TYPE_VAL          0xF0

#define MQTT_USER_NAME_FLAG     0x80
#define MQTT_PASSWORD_FLAG      0x40
#define MQTT_WILL_RETAIN_FLAG   0x20
#define MQTT_WILL_FLAG          0x04
#define MQTT_CLEAN_START_FLAG   0x02

#define MQTT_QOS_0_FLAG         0x00
#define MQTT_QOS_1_FLAG         0x08
#define MQTT_QOS_2_FLAG         0x10

#define MQTT_AUTH_CONTINUE      0x18
#define MQTT_AUTH_REAUTH        0x19

#define MAX_SUBSCRIPTION_ID     (268435455)

static MSTATUS MQTT_computeConnectLen(MqttCtx *pCtx, MqttConnectOptions *pOptions, ubyte4 *pTotalLen, ubyte4 *pPropLen, ubyte4 *pWillPropLen);
static MSTATUS MQTT_writeUserProps(ubyte *pBuf, MqttProperty *pProps, ubyte4 propCount, ubyte4 *pOffset);
static MSTATUS MQTT_buildConnectFlags(MqttConnectOptions *pOptions, ubyte *pRes);
static MSTATUS MQTT_constructConnectProps(ubyte *pIter, MqttConnectOptions *pOptions, ubyte4 propLen, ubyte **ppIter);
static MSTATUS MQTT_constructWillProps(ubyte *pIter, MqttConnectOptions *pOptions, ubyte4 willPropLen, ubyte **ppIter);

#if defined(__ENABLE_MQTT_CLIENT_DUMP_MESSAGES__)
static void PrintBytes( ubyte* buffer, sbyte4 len)
{
    sbyte4 i;

    for ( i = 0; i < len; ++i)
    {
        DEBUG_HEXBYTE(DEBUG_MQTT_TRANSPORT, buffer[i]);
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, (sbyte*)" ");

        if ( i % 16 == 15)
        {
            DEBUG_PRINTNL(DEBUG_MQTT_TRANSPORT, (sbyte*)"");
        }
    }

    DEBUG_PRINTNL(DEBUG_MQTT_TRANSPORT, (sbyte*)"");
}

#define GMT_TIME_STAMP_SIZE     (24)

static MSTATUS MQTT_getGMTTimeStamp(sbyte *pBuffer, ubyte4 bufSize)
{
    MSTATUS status;
    sbyte pTimeBuf[16];
    TimeDate td;
    sbyte *pTime;

    if (NULL == pBuffer)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (bufSize < GMT_TIME_STAMP_SIZE)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    status = RTOS_timeGMT(&td);
    if (OK != status)
        goto exit;

    status = DATETIME_convertToValidityString(&td, pTimeBuf);
    if (OK != status)
        goto exit;

    /* If its generalized time then offset by 2 */
    pTime = MOC_STRLEN(pTimeBuf) == 15 ? pTimeBuf + 2 : pTimeBuf;

    snprintf((char *) pBuffer, bufSize, "[%.*s/%.*s/%.*s %.*s:%.*s:%.*s GMT]",
                    2, pTime + 2, 2, pTime + 4, 2, pTime,
                    2, pTime + 6, 2, pTime + 8, 2, pTime + 10);

exit:

    return status;
}

static void MQTT_printTime()
{
    MSTATUS status;
    sbyte pTimeBuf[GMT_TIME_STAMP_SIZE];

    status = MQTT_getGMTTimeStamp(pTimeBuf, sizeof(pTimeBuf));
    if (OK == status)
    {
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, pTimeBuf);
    }

    return;
}

static void MQTT_printMsg(
    ubyte *pPacket, ubyte4 packetSize, byteBoolean inbound)
{
    if (TRUE == inbound)
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "< ");
    else
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "> ");
    MQTT_printTime();
    if (TRUE == inbound)
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, " Inbound ");
    else
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, " Outbound ");

    switch(*pPacket >> 4)
    {
        case MQTT_CONNECT:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "CONNECT");
            break;
        case MQTT_CONNACK:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "CONNACK");
            break;
        case MQTT_PUBLISH:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "PUBLISH");
            break;
        case MQTT_PUBACK:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "PUBACK");
            break;
        case MQTT_PUBREC:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "PUBREC");
            break;
        case MQTT_PUBREL:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "PUBREL");
            break;
        case MQTT_PUBCOMP:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "PUBCOMP");
            break;
        case MQTT_SUBSCRIBE:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "SUBSCRIBE");
            break;
        case MQTT_SUBACK:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "SUBACK");
            break;
        case MQTT_UNSUBSCRIBE:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "UNSUBSCRIBE");
            break;
        case MQTT_UNSUBACK:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "UNSUBACK");
            break;
        case MQTT_PINGREQ:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "PINGREQ");
            break;
        case MQTT_PINGRESP:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "PINGRESP");
            break;
        case MQTT_DISCONNECT:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "DISCONNECT");
            break;
        case MQTT_AUTH:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "AUTH");
            break;
        default:
            DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "unknown");
            break;
    }
    DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, " message of size: ");
    DEBUG_INT(DEBUG_MQTT_TRANSPORT, packetSize);
    DEBUG_PRINTNL(DEBUG_MQTT_TRANSPORT, (sbyte *)"");
    PrintBytes(pPacket, packetSize);
}

#endif

/* TODO: Need to determine a better way to get packet IDs */
static MSTATUS MQTT_getPacketId(MqttCtx *pCtx, ubyte2 *pPktId)
{
    do
    {
        pCtx->pktId++;
        if (0 == pCtx->pktId)
            pCtx->pktId++;

    } while(TRUE == MQTT_packetIdExists(pCtx, pCtx->pktId));
    
    *pPktId = pCtx->pktId;

    return OK;
}

static MSTATUS MQTT_setUserProps(MqttProperty **ppProps, ubyte4 propCount, ubyte *pUserPropStarts[])
{
    MSTATUS status;
    ubyte *pIter = NULL;
    ubyte4 i = 0;
    MqttProperty *pProps = NULL;

    status = MOC_CALLOC((void **)&pProps, propCount, sizeof(MqttProperty));
    if (OK != status)
        goto exit;

    /* If user properties exist, create the structure with proper pointers back into the
     * original data buffer for a callback to receive */
    for (i = 0; i < propCount; i++)
    {
        pIter = pUserPropStarts[i];
        pProps[i].name = MQTT_PROP_USER_PROPERTY;

        /* Name */
        pProps[i].data.pair.name.dataLen = MOC_NTOHS(pIter);
        pIter += 2;
        pProps[i].data.pair.name.pData = pIter;
        pIter += pProps[i].data.pair.name.dataLen;

        /* Value */
        pProps[i].data.pair.value.dataLen = MOC_NTOHS(pIter);
        pIter += 2;
        pProps[i].data.pair.value.pData = pIter;
        pIter += pProps[i].data.pair.value.dataLen;
    }

    *ppProps = pProps;
    pProps = NULL;

exit:

    if (NULL != pProps)
    {
        MOC_FREE((void **)&pProps);
    }

    return status;
}

static MSTATUS MQTT_parseReasonString(ubyte **ppIter, ubyte4 *pPropLen, ubyte **ppReasonStr, ubyte2 *pReasonStrLen)
{
    MSTATUS status = OK;

    if (*pPropLen < 2)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    *pReasonStrLen = MOC_NTOHS(*ppIter);
    *ppIter += 2;
    *pPropLen -= 2;
    if (*pPropLen < *pReasonStrLen)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    *ppReasonStr = *ppIter;

    if (*pReasonStrLen > 0)
    {
        if (!isValidUtf8(*ppReasonStr, *pReasonStrLen))
        {
            status = ERR_MQTT_INVALID_UTF8;
            goto exit;
        }
    }

    *ppIter += *pReasonStrLen;
    *pPropLen -= *pReasonStrLen;

exit:
    return status;
}

static MSTATUS MQTT_parseAuthMethod(ubyte **ppIter, ubyte4 *pPropLen, ubyte **ppAuthMethod, ubyte2 *pAuthMethodLen)
{
    MSTATUS status = OK;

    if (*pPropLen < 2)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    *pAuthMethodLen = MOC_NTOHS(*ppIter);
    *ppIter += 2;
    *pPropLen -= 2;
    if (*pPropLen < *pAuthMethodLen)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    *ppAuthMethod = *ppIter;

    if (!isValidUtf8(*ppAuthMethod, *pAuthMethodLen))
    {
        status = ERR_MQTT_INVALID_UTF8;
        goto exit;
    }

    *ppIter += *pAuthMethodLen;
    *pPropLen -= *pAuthMethodLen;

exit:
    return status;
}

static MSTATUS MQTT_parseAuthData(ubyte **ppIter, ubyte4 *pPropLen, ubyte **ppAuthData, ubyte4 *pAuthDataLen)
{
    MSTATUS status = OK;

    if (*pPropLen < 2)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    *pAuthDataLen = MOC_NTOHS(*ppIter);
    *ppIter += 2;
    *pPropLen -= 2;
    if (*pPropLen < *pAuthDataLen)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    *ppAuthData = *ppIter;
    *ppIter += *pAuthDataLen;
    *pPropLen -= *pAuthDataLen;

exit:
    return status;
}

static MSTATUS MQTT_parseAssignedClientId(MqttCtx *pCtx, ubyte **ppIter, ubyte4 *pPropLen, ubyte **ppAssignedClientId, ubyte2 *pAssignedClientIdLen)
{
    MSTATUS status = OK;

    /* Not expecting an assigned client identifier */
    if (TRUE != pCtx->assignedClientId)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    if (*pPropLen < 2)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    *pAssignedClientIdLen = MOC_NTOHS(*ppIter);
    *ppIter += 2;
    *pPropLen -= 2;
    if (*pPropLen < *pAssignedClientIdLen)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    *ppAssignedClientId = *ppIter;
    *ppIter += *pAssignedClientIdLen;
    *pPropLen -= *pAssignedClientIdLen;

    /* Allocate an extra 2 bytes for the client id buffer to be used for appending the packet id
        * when calculating the hash key later when storing publishes */
    status = MOC_MALLOC_MEMCPY(
        (void **) &pCtx->pClientId, *pAssignedClientIdLen + 2,
        *ppAssignedClientId, *pAssignedClientIdLen);
    if (OK != status)
        goto exit;

    pCtx->clientIdLen = *pAssignedClientIdLen;

exit:
    return status;
}

static MSTATUS MQTT_parseUserProperty(ubyte **ppIter, ubyte4 *pPropLen, ubyte **pUserPropIters, ubyte *pUserPropCnt)
{
    MSTATUS status = OK;
    ubyte4 len = 0;

    if (*pPropLen < 6)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    /* Add the user property location to the list and move
    * the iterator to the next property */
    if (*pUserPropCnt >= MAX_NUM_USER_PROPS)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, (sbyte *)"Exceeded maximum number of user properties\n");
#endif
        goto exit;
    }

    pUserPropIters[*pUserPropCnt] = *ppIter;
    (*pUserPropCnt)++;
    len = MOC_NTOHS(*ppIter);
    if (*pPropLen < len)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    *ppIter += 2; *pPropLen -= 2;
    *ppIter += len; *pPropLen -= len;

    len = MOC_NTOHS(*ppIter);
    if (*pPropLen < len)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    *ppIter += 2; *pPropLen -= 2;
    *ppIter += len; *pPropLen -= len;

exit:
    return status;
}

MSTATUS MQTT_parseConnAck(sbyte connInst, MqttCtx *pCtx, ubyte *pBuffer, ubyte4 bufferLen)
{
    MSTATUS status;
    ubyte4 varHdrLen = 0;
    ubyte bytesUsed = 0;
    ubyte4 propLen = 0;
    ubyte propType = 0;
    MqttConnAckInfo info = {0};
    MqttMessage msg = {0};
    ubyte *pUserPropsIters[MAX_NUM_USER_PROPS];
    ubyte userPropCnt = 0;
    ubyte *pIter = pBuffer;
    ubyte pFoundProps[MQTT_PROP_ARRAY_SIZE] = { 0 };
    ubyte4 authDataLen = 0;

    /* Caller has already parsed control packet type, skip past this byte */
    pIter++;


    if (CONNECT_NEGOTIATE != pCtx->connectionState)
    {
#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, (sbyte *)"Unexpected CONNACK packet received\n");
#endif
        status = OK;
        goto exit;
    }

    /* Decode the variable byte length */
    status = MQTT_decodeVariableByteInt(pIter, bufferLen - 1, &varHdrLen, &bytesUsed);
    if (OK != status)
        goto exit;

    /* Ensure the number of bytes in the buffer contain the entire CONNACK
     * packet */
    if ((varHdrLen + 1 + bytesUsed) != bufferLen)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    pIter += bytesUsed;

    /* Begin connack parsing, connect acknowledge flags */
    if (varHdrLen < 1)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    info.sessionPresent = *pIter;
    pIter++;
    varHdrLen--;

    /* Reason code */
    if (varHdrLen < 1)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    info.reasonCode = *pIter;
    pIter++;
    varHdrLen--;

    if (MQTT_V5 <= pCtx->version)
    {
        status = MQTT_decodeVariableByteInt(pIter, varHdrLen, &propLen, &bytesUsed);
        if (OK != status)
            goto exit;

        pIter += bytesUsed;
        varHdrLen -= bytesUsed;

        /* CONNACK has no payload, the remaining variable header length should be
         * equal to the property length */
        if (propLen != varHdrLen)
        {
            status = ERR_MQTT_MALFORMED_PACKET;
            goto exit;
        }

        /* Process properties */
        while (0 != propLen)
        {
            /* Read property type */
            propType = *pIter;
            pIter++;
            propLen--;

            if (MQTT_PROP_LAST <= propType)
            {
                status = ERR_MQTT_MALFORMED_PACKET;
                goto exit;
            }

            if (MQTT_PROP_USER_PROPERTY != propType)
            {
                if (MQTT_PROP_IS_SET(pFoundProps, propType))
                {
                    status = ERR_MQTT_PROTOCOL_ERROR;
                    goto exit;
                }

                MQTT_PROP_SET(pFoundProps, propType);
            }

            /* Determine property type */
            switch(propType)
            {
                case MQTT_PROP_REASON_STRING:
                {
                    status = MQTT_parseReasonString(&pIter, &propLen, &info.pReasonStr, &info.reasonStrLen);
                    if (OK != status)
                        goto exit;
                    break;
                }

                case MQTT_PROP_AUTHENTICATION_METHOD:
                {
                    status = MQTT_parseAuthMethod(&pIter, &propLen, &info.pAuthMethod, &info.authMethodLen);
                    if (OK != status)
                        goto exit;
                    break;
                }

                case MQTT_PROP_AUTHENTICATION_DATA:
                {
                    status = MQTT_parseAuthData(&pIter, &propLen, &info.pAuthData, &authDataLen);
                    if (OK != status)
                        goto exit;
                    info.authDataLen = (ubyte2)authDataLen;
                    break;
                }

                case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
                {
                    if (propLen < 4)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.sessionExpiryIntervalSet = TRUE;
                    info.sessionExpiryInterval = MOC_NTOHL(pIter);
                    pIter += 4;
                    propLen -= 4;
                    break;
                }

                case MQTT_PROP_RECEIVE_MAXIMUM:
                {
                    if (propLen < 2)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.receiveMaxSet = TRUE;
                    info.receiveMax = MOC_NTOHS(pIter);
                    pCtx->sendQuota = info.receiveMax;
                    /* MQTT 5.0 - Section 3.1.2.11.3
                     *
                     *   It is a Protocol Error to include the Receive Maximum value
                     *   more than once or for it to have the value 0.
                     *
                     */
                    if (0 == info.receiveMax)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    pIter += 2;
                    propLen -= 2;
                    break;
                }

                case MQTT_PROP_MAXIMUM_QOS:
                {
                    if (propLen < 1)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.qosSet = TRUE;
                    info.qos = *pIter;
                    /* MQTT 5.0 - Section 3.2.2.3.4
                     *
                     *   It is a Protocol Error to include Maximum QoS more than
                     *   once, or to have a value other than 0 or 1. If the Maximum
                     *   QoS is absent, the Client uses a Maximum QoS of 2.
                     */
                    switch (info.qos)
                    {
                        case 0:
                        case 1:
                            break;
                        default:
                            status = ERR_MQTT_MALFORMED_PACKET;
                            goto exit;
                    }
                    pIter += 1;
                    propLen -= 1;
                    break;
                }

                case MQTT_PROP_RETAIN_AVAILABLE:
                {
                    if (propLen < 1)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    switch (*pIter)
                    {
                        case 0:
                        case 1:
                            info.retainAvailableSet = TRUE;
                            info.retainAvailable = *pIter;
                            break;
                        default:
                            status = ERR_MQTT_MALFORMED_PACKET;
                            goto exit;
                    }
                    pIter += 1;
                    propLen -= 1;
                    break;
                }

                case MQTT_PROP_MAXIMUM_PACKET_SIZE:
                {
                    if (propLen < 4)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.maxPacketSizeSet = TRUE;
                    info.maxPacketSize = MOC_NTOHL(pIter);
                    if (0 == info.maxPacketSize)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    pIter += 4;
                    propLen -= 4;
                    break;
                }

                case MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER:
                {
                    status = MQTT_parseAssignedClientId(pCtx, &pIter, &propLen, &info.pAssignedClientId, &info.assignedClientIdLen);
                    if (OK != status)
                        goto exit;

                    break;
                }

                case MQTT_PROP_TOPIC_ALIAS_MAXIMUM:
                {
                    if (propLen < 2)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.topicAliasMaxSet = TRUE;
                    info.topicAliasMax = MOC_NTOHS(pIter);
                    pCtx->topicAliasMax = info.topicAliasMax;
                    pIter += 2;
                    propLen -= 2;
                    break;
                }

                case MQTT_PROP_USER_PROPERTY:
                {
                    status = MQTT_parseUserProperty(&pIter, &propLen, pUserPropsIters, &userPropCnt);
                    if (OK != status)
                        goto exit;
                    break;
                }

                case MQTT_PROP_WILDCARD_SUBCRIPTION_AVAILABLE:
                {
                    if (propLen < 1)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    switch (*pIter)
                    {
                        case 0:
                        case 1:
                            info.wildcardSubscriptionAvailableSet = TRUE;
                            info.wildcardSubscriptionAvailable = *pIter;
                            break;
                        default:
                            status = ERR_MQTT_MALFORMED_PACKET;
                            goto exit;
                    }
                    pIter += 1;
                    propLen -= 1;
                    break;
                }

                case MQTT_PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE:
                {
                    if (propLen < 1)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    switch (*pIter)
                    {
                        case 0:
                        case 1:
                            info.subscriptionIdentifiersAvailableSet = TRUE;
                            info.subscriptionIdentifiersAvailable = *pIter;
                            break;
                        default:
                            status = ERR_MQTT_MALFORMED_PACKET;
                            goto exit;
                    }
                    pIter += 1;
                    propLen -= 1;
                    break;
                }

                case MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE:
                {
                    if (propLen < 1)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    switch (*pIter)
                    {
                        case 0:
                        case 1:
                            info.sharedSubscriptionAvailableSet = TRUE;
                            info.sharedSubscriptionAvailable = *pIter;
                            break;
                        default:
                            status = ERR_MQTT_MALFORMED_PACKET;
                            goto exit;
                    }
                    pIter += 1;
                    propLen -= 1;
                    break;
                }

                case MQTT_PROP_SERVER_KEEP_ALIVE:
                {
                    if (propLen < 2)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.keepAliveSet = TRUE;
                    info.keepAlive = MOC_NTOHS(pIter);
                    /* Set server provided keep alive */
                    pCtx->keepAliveMS = 1000 * info.keepAlive;
                    pIter += 2;
                    propLen -= 2;
                    break;
                }

                case MQTT_PROP_RESPONSE_INFORMATION:
                {
                    if (propLen < 2)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.responseInfoLen = MOC_NTOHS(pIter);
                    pIter += 2;
                    propLen -= 2;
                    if (propLen < info.responseInfoLen)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.pResponseInfo = pIter;

                    if (!isValidUtf8(info.pResponseInfo, info.responseInfoLen))
                    {
                        status = ERR_MQTT_INVALID_UTF8;
                        goto exit;
                    }

                    pIter += info.responseInfoLen;
                    propLen -= info.responseInfoLen;
                    break;
                }

                case MQTT_PROP_SERVER_REFERENCE:
                {
                    if (propLen < 2)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.serverRefLen = MOC_NTOHS(pIter);
                    pIter += 2;
                    propLen -= 2;
                    if (propLen < info.serverRefLen)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.pServerRef = pIter;

                    if (!isValidUtf8(info.pServerRef, info.serverRefLen))
                    {
                        status = ERR_MQTT_INVALID_UTF8;
                        goto exit;
                    }

                    pIter += info.serverRefLen;
                    propLen -= info.serverRefLen;
                    break;
                }

                default:
                {
                    /* This should never happen, packet is malformed */
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
            }

        }

        /* MQTT 5.0 - Section 3.2.2.3.7
         *
         *   If the Client connects using a zero length Client Identifier, the
         *   Server MUST respond with a CONNACK containing an Assigned Client
         *   Identifier.
         *
         * Throw fatal error if the server has not provided a client ID
         */
        if ( (TRUE == pCtx->assignedClientId) && (NULL == pCtx->pClientId) )
        {
            status = ERR_MQTT_MALFORMED_PACKET;
            goto exit;
        }


        /* If user properties exist, create the structure with proper pointers back into the
         * original data buffer for a callback to receive */
        if (userPropCnt > 0)
        {
            info.propCount = userPropCnt;

            status = MQTT_setUserProps(&info.pProps, userPropCnt, pUserPropsIters);
            if (OK != status)
                goto exit;
        }
    }
    else
    {
        if (0 != varHdrLen)
        {
            status = ERR_MQTT_MALFORMED_PACKET;
            goto exit;
        }
    }

    msg.type = MQTT_CONNACK;
    msg.pData = pBuffer;
    msg.dataLen = bufferLen;
    msg.finished = TRUE;

    /* Logically at open state */
    if (0 == info.reasonCode)
    {
        pCtx->connectionState = CONNECT_OPEN;
    }
    else
    {
        pCtx->connectionState = CONNECT_CLOSED;
    }


    if (NULL != pCtx->handlers.connAckHandler)
    {
        /* Intentionally ignore return */
        pCtx->handlers.connAckHandler(connInst, &msg, &info);
    }

    if (0 == pCtx->sendQuota)
    {
        pCtx->sendQuota = MQTT_RECV_MAX_DEFLT;
    }

    if ((MQTT_V3_1_1 >= pCtx->version && info.reasonCode >= MQTT_CONNECT_UNACCEPTABLE_PROTOCOL_VERSION_V3) ||
        (MQTT_V5 <= pCtx->version && info.reasonCode >= MQTT_CONNECT_UNSPECIFIED_V5))
    {
        status = ERR_MQTT_CONNECTION_REFUSED;
        goto exit;
    }


    /* See if we have any publishes to timeout */
    MQTT_timeoutStoredPublishes(pCtx);

    if (TRUE == info.sessionPresent)
    {
        status = MQTT_resendUnackedPackets(pCtx);
    }

exit:

    if (NULL != info.pProps)
    {
        MOC_FREE((void **)&info.pProps);
    }

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_parseConnAck() returns status = ", status);
    }
#endif

    return status;
}

MSTATUS MQTT_parsePingResp(
    sbyte connInst,
    MqttCtx *pCtx,
    ubyte *pBuffer,
    ubyte4 bufferLen)
{
    MSTATUS status;
    ubyte4 varHdrLen = 0;
    ubyte bytesUsed = 0;
    ubyte *pIter = pBuffer;
    byteBoolean releaseMutex = FALSE;

    if (TRUE == pCtx->keepAliveThreadActive)
    {
        status = RTOS_mutexWait(pCtx->keepAliveMutex);
        if (OK != status)
            goto exit;

        releaseMutex = TRUE;
    }

    /* Caller has already parsed control packet type, skip past this byte */
    pIter++;

    if (bufferLen != 2)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    pCtx->pingCounter--;

    /* Unexpected PINGRESP will be ignored */
    if (0 > pCtx->pingCounter)
    {
        /* Reset the counter */
        pCtx->pingCounter = 0;
        status = ERR_MQTT_MALFORMED_PACKET;
#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, (sbyte *)"Unexpected PINGRESP packet received\n");
#endif
        goto exit;
    }

    /* Decode the variable byte length */
    status = MQTT_decodeVariableByteInt(pIter, bufferLen - 1, &varHdrLen, &bytesUsed);
    if (OK != status)
        goto exit;

    /* Ensure the number of bytes in the buffer contain the entire PING response
     * packet */
    if ( ((varHdrLen + 1 + bytesUsed) != bufferLen) || (0 != varHdrLen) )
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

exit:

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_parsePingResp() returns status = ", status);
    }
#endif

    if (TRUE == releaseMutex)
    {
        RTOS_mutexRelease(pCtx->keepAliveMutex);
    }

    return status;
}

MSTATUS MQTT_parseSubAck(sbyte connInst, MqttCtx *pCtx, ubyte *pBuffer, ubyte4 bufferLen)
{
    MSTATUS status;
    ubyte4 varHdrLen = 0;
    ubyte bytesUsed = 0;
    ubyte4 propLen = 0;
    ubyte propType = 0;
    MqttSubAckInfo info = {0};
    MqttMessage msg = {0};
    ubyte *pUserPropsIters[MAX_NUM_USER_PROPS];
    ubyte userPropCnt = 0;
    intBoolean found = FALSE;
    ubyte *pIter = pBuffer;
    ubyte pFoundProps[MQTT_PROP_ARRAY_SIZE] = { 0 };

    /* Caller has already parsed control packet type, skip past this byte */
    pIter++;

    /* Decode the variable byte length */
    status = MQTT_decodeVariableByteInt(pIter, bufferLen - 1, &varHdrLen, &bytesUsed);
    if (OK != status)
        goto exit;

    /* Ensure the number of bytes in the buffer contain the entire SUBACK
     * packet */
    if ((varHdrLen + 1 + bytesUsed) != bufferLen)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    pIter += bytesUsed;

    /* Begin suback parsing, packet ID */
    if (varHdrLen < 2)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    info.msgId = MOC_NTOHS(pIter);

    status = MQTT_checkAndMarkAcked(pCtx, info.msgId, &found);
    if (OK != status)
        goto exit;

    if (FALSE == found)
    {
        status = OK;
#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, (sbyte *)"Unexpected SUBACK received\n");
#endif
        goto exit;
    }

    pIter += 2;
    varHdrLen -= 2;

    if (MQTT_V5 <= pCtx->version)
    {
        status = MQTT_decodeVariableByteInt(pIter, varHdrLen, &propLen, &bytesUsed);
        if (OK != status)
            goto exit;

        pIter += bytesUsed;
        varHdrLen -= bytesUsed;

        if (propLen > varHdrLen)
        {
            status = ERR_MQTT_MALFORMED_PACKET;
            goto exit;
        }

        varHdrLen -= propLen;

        /* Process properties */
        while (0 != propLen)
        {
            /* Read property type */
            propType = *pIter;
            pIter++;
            propLen--;

            if (MQTT_PROP_LAST <= propType)
            {
                status = ERR_MQTT_MALFORMED_PACKET;
                goto exit;
            }

            if (MQTT_PROP_USER_PROPERTY != propType)
            {
                if (MQTT_PROP_IS_SET(pFoundProps, propType))
                {
                    status = ERR_MQTT_PROTOCOL_ERROR;
                    goto exit;
                }

                MQTT_PROP_SET(pFoundProps, propType);
            }

            /* Determine property type */
            switch(propType)
            {
                case MQTT_PROP_REASON_STRING:
                {
                    status = MQTT_parseReasonString(&pIter, &propLen, &info.pReasonStr, &info.reasonStrLen);
                    if (OK != status)
                        goto exit;
                    break;
                }

                case MQTT_PROP_USER_PROPERTY:
                {
                    status = MQTT_parseUserProperty(&pIter, &propLen, pUserPropsIters, &userPropCnt);
                    if (OK != status)
                        goto exit;
                    break;
                }

                default:
                {
                    /* This should never happen, packet is malformed */
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
            }
        }

        /* If user properties exist, create the structure with proper pointers back into the
         * original data buffer for a callback to receive */
        if (userPropCnt > 0)
        {
            info.propCount = userPropCnt;

            status = MQTT_setUserProps(&info.pProps, userPropCnt, pUserPropsIters);
            if (OK != status)
                goto exit;
        }
    }

    info.pQoS = pIter;
    info.QoSCount = varHdrLen;

    msg.type = MQTT_SUBACK;
    msg.pData = pBuffer;
    msg.dataLen = bufferLen;
    msg.finished = TRUE;

    if (NULL != pCtx->handlers.subAckHandler)
    {
        /* Intentionally ignore return */
        pCtx->handlers.subAckHandler(connInst, &msg, &info);
    }

exit:

    if (NULL != info.pProps)
    {
        MOC_FREE((void **)&info.pProps);
    }

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_parseSubAck() returns status = ", status);
    }
#endif

    return status;
}

MSTATUS MQTT_parseUnsubAck(sbyte connInst, MqttCtx *pCtx, ubyte *pBuffer, ubyte4 bufferLen)
{
    MSTATUS status;
    ubyte4 varHdrLen = 0;
    ubyte bytesUsed = 0;
    ubyte4 propLen = 0;
    ubyte propType = 0;
    MqttUnsubAckInfo info = {0};
    MqttMessage msg = {0};
    ubyte *pUserPropsIters[MAX_NUM_USER_PROPS];
    ubyte userPropCnt = 0;
    intBoolean found = FALSE;
    ubyte *pIter = pBuffer;
    ubyte pFoundProps[MQTT_PROP_ARRAY_SIZE] = { 0 };

    /* Caller has already parsed control packet type, skip past this byte */
    pIter++;

    /* Decode the variable byte length */
    status = MQTT_decodeVariableByteInt(pIter, bufferLen - 1, &varHdrLen, &bytesUsed);
    if (OK != status)
        goto exit;

    /* Ensure the number of bytes in the buffer contain the entire UNSUBACK
     * packet */
    if ((varHdrLen + 1 + bytesUsed) != bufferLen)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    pIter += bytesUsed;

    /* Begin unsuback parsing, packet ID */
    if (varHdrLen < 2)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    info.msgId = MOC_NTOHS(pIter);
    pIter += 2;
    varHdrLen -= 2;

    status = MQTT_checkAndMarkAcked(pCtx, info.msgId, &found);
    if (OK != status)
        goto exit;

    if (FALSE == found)
    {
        status = OK;
#ifdef __ENABLE_MOCANA_DEBUG_CONSOLE__
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, (sbyte *)"Unexpected UNSUBACK received\n");
#endif
        goto exit;
    }

     if (MQTT_V5 <= pCtx->version)
    {
        status = MQTT_decodeVariableByteInt(pIter, varHdrLen, &propLen, &bytesUsed);
        if (OK != status)
            goto exit;

        pIter += bytesUsed;
        varHdrLen -= bytesUsed;

        if (propLen > varHdrLen)
        {
            status = ERR_MQTT_MALFORMED_PACKET;
            goto exit;
        }

        varHdrLen -= propLen;

        /* Process properties */
        while (0 != propLen)
        {
            /* Read property type */
            propType = *pIter;
            pIter++;
            propLen--;

            if (MQTT_PROP_LAST <= propType)
            {
                status = ERR_MQTT_MALFORMED_PACKET;
                goto exit;
            }

            if (MQTT_PROP_USER_PROPERTY != propType)
            {
                if (MQTT_PROP_IS_SET(pFoundProps, propType))
                {
                    status = ERR_MQTT_PROTOCOL_ERROR;
                    goto exit;
                }

                MQTT_PROP_SET(pFoundProps, propType);
            }

            /* Determine property type */
            switch(propType)
            {
                case MQTT_PROP_REASON_STRING:
                {
                    status = MQTT_parseReasonString(&pIter, &propLen, &info.pReasonStr, &info.reasonStrLen);
                    if (OK != status)
                        goto exit;
                    break;
                }

                case MQTT_PROP_USER_PROPERTY:
                {
                    status = MQTT_parseUserProperty(&pIter, &propLen, pUserPropsIters, &userPropCnt);
                    if (OK != status)
                        goto exit;
                    break;
                }

                default:
                {
                    /* This should never happen, packet is malformed */
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
            }
        }

        /* If user properties exist, create the structure with proper pointers back into the
         * original data buffer for a callback to receive */
        if (userPropCnt > 0)
        {
            info.propCount = userPropCnt;

            status = MQTT_setUserProps(&info.pProps, userPropCnt, pUserPropsIters);
            if (OK != status)
                goto exit;
        }
    }
    else
    {
        if (0 != varHdrLen)
        {
            status = ERR_MQTT_MALFORMED_PACKET;
            goto exit;
        }
    }

    info.pReasonCodes = pIter;
    info.reasonCodeCount = varHdrLen;

    msg.type = MQTT_SUBACK;
    msg.pData = pBuffer;
    msg.dataLen = bufferLen;
    msg.finished = TRUE;

    if (NULL != pCtx->handlers.unsubAckHandler)
    {
        /* Intentionally ignore return */
        pCtx->handlers.unsubAckHandler(connInst, &msg, &info);
    }

exit:

    if (NULL != info.pProps)
    {
        MOC_FREE((void **)&info.pProps);
    }

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_parseUnsubAck() returns status = ", status);
    }
#endif

    return status;
}

MSTATUS MQTT_parseAuth(sbyte connInst, MqttCtx *pCtx, ubyte *pBuffer, ubyte4 bufferLen)
{
    MSTATUS status;
    ubyte4 varHdrLen = 0;
    ubyte bytesUsed = 0;
    ubyte4 propLen = 0;
    ubyte propType = 0;
    MqttAuthInfo info = {0};
    MqttMessage msg = {0};
    ubyte *pUserPropsIters[MAX_NUM_USER_PROPS];
    ubyte userPropCnt = 0;
    ubyte *pIter = pBuffer;
    ubyte pFoundProps[MQTT_PROP_ARRAY_SIZE] = { 0 };

    if (MQTT_V3_1_1 >= pCtx->version)
    {
        status = ERR_MQTT_UNEXPECTED_PACKET;
        goto exit;
    }

    /* Caller has already parsed control packet type, skip past this byte */
    pIter++;

    /* Decode the variable byte length */
    status = MQTT_decodeVariableByteInt(pIter, bufferLen - 1, &varHdrLen, &bytesUsed);
    if (OK != status)
        goto exit;

    /* Ensure the number of bytes in the buffer contain the entire AUTH
     * packet */
    if ((varHdrLen + 1 + bytesUsed) != bufferLen)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    pIter += bytesUsed;

    /* Begin auth parsing, reason code */
    if (varHdrLen < 1)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    info.reasonCode = *pIter;
    pIter += 1;
    varHdrLen -= 1;

    status = MQTT_decodeVariableByteInt(pIter, varHdrLen, &propLen, &bytesUsed);
    if (OK != status)
        goto exit;

    pIter += bytesUsed;
    varHdrLen -= bytesUsed;

    if (propLen > varHdrLen)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    varHdrLen -= propLen;

    /* Process properties */
    while (0 != propLen)
    {
        /* Read property type */
        propType = *pIter;
        pIter++;
        propLen--;

        if (MQTT_PROP_LAST <= propType)
        {
            status = ERR_MQTT_MALFORMED_PACKET;
            goto exit;
        }

        if (MQTT_PROP_USER_PROPERTY != propType)
        {
            if (MQTT_PROP_IS_SET(pFoundProps, propType))
            {
                status = ERR_MQTT_PROTOCOL_ERROR;
                goto exit;
            }

            MQTT_PROP_SET(pFoundProps, propType);
        }

        /* Determine property type */
        switch(propType)
        {
            case MQTT_PROP_REASON_STRING:
            {
                status = MQTT_parseReasonString(&pIter, &propLen, &info.pReasonStr, &info.reasonStrLen);
                if (OK != status)
                    goto exit;
                break;
            }

            case MQTT_PROP_AUTHENTICATION_METHOD:
            {
                status = MQTT_parseAuthMethod(&pIter, &propLen, &info.pAuthMethod, &info.authMethodLen);
                if (OK != status)
                    goto exit;
                break;
            }

            case MQTT_PROP_AUTHENTICATION_DATA:
            {
                status = MQTT_parseAuthData(&pIter, &propLen, &info.pAuthData, &info.authDataLen);
                if (OK != status)
                    goto exit;
                break;
            }

            case MQTT_PROP_USER_PROPERTY:
            {
                status = MQTT_parseUserProperty(&pIter, &propLen, pUserPropsIters, &userPropCnt);
                if (OK != status)
                    goto exit;
                break;
            }

            default:
            {
                /* This should never happen, packet is malformed */
                status = ERR_MQTT_MALFORMED_PACKET;
                goto exit;
            }
        }
    }

    /* MQTT 5.0 - Section 3.15.2.2.2
     *
     *   It is a Protocol Error to omit the Authentication Method
     */
    if (NULL == info.pAuthData)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    /* If user properties exist, create the structure with proper pointers back into the
     * original data buffer for a callback to receive */
    if (userPropCnt > 0)
    {
        info.propCount = userPropCnt;

        status = MQTT_setUserProps(&info.pProps, userPropCnt, pUserPropsIters);
        if (OK != status)
            goto exit;
    }

    msg.type = MQTT_AUTH;
    msg.pData = pBuffer;
    msg.dataLen = bufferLen;
    msg.finished = TRUE;

    if (NULL != pCtx->handlers.authHandler)
    {
        /* Intentionally ignore return */
        pCtx->handlers.authHandler(connInst, &msg, &info);
    }

exit:

    if (NULL != info.pProps)
    {
        MOC_FREE((void **)&info.pProps);
    }

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_parseAuth() returns status = ", status);
    }
#endif

    return status;
}


MSTATUS MQTT_parseDisconnect(sbyte connInst, MqttCtx *pCtx, ubyte *pBuffer, ubyte4 bufferLen)
{
    MSTATUS status;
    ubyte4 varHdrLen = 0;
    ubyte bytesUsed = 0;
    ubyte4 propLen = 0;
    ubyte propType = 0;
    MqttDisconnectInfo info = {0};
    MqttMessage msg = {0};
    ubyte *pUserPropsIters[MAX_NUM_USER_PROPS];
    ubyte userPropCnt = 0;
    ubyte *pIter = pBuffer;
    ubyte pFoundProps[MQTT_PROP_ARRAY_SIZE] = { 0 };

    if (MQTT_V3_1_1 >= pCtx->version)
    {
        status = ERR_MQTT_UNEXPECTED_PACKET;
        goto exit;
    }

    /* Caller has already parsed control packet type, skip past this byte */
    pIter++;

    /* Decode the variable byte length */
    status = MQTT_decodeVariableByteInt(pIter, bufferLen - 1, &varHdrLen, &bytesUsed);
    if (OK != status)
        goto exit;

    /* Ensure the number of bytes in the buffer contain the entire DISCONNECT
     * packet */
    if ((varHdrLen + 1 + bytesUsed) != bufferLen)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    pIter += bytesUsed;

    /* Begin disconnect parsing, reason code */
    if (varHdrLen < 2)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    info.reasonCode = *pIter;
    pIter += 1;
    varHdrLen -= 1;

    if (MQTT_V5 <= pCtx->version)
    {
        status = MQTT_decodeVariableByteInt(pIter, varHdrLen, &propLen, &bytesUsed);
        if (OK != status)
            goto exit;

        pIter += bytesUsed;
        varHdrLen -= bytesUsed;

        if (propLen > varHdrLen)
        {
            status = ERR_MQTT_MALFORMED_PACKET;
            goto exit;
        }

        varHdrLen -= propLen;

        /* Process properties */
        while (0 != propLen)
        {
            /* Read property type */
            propType = *pIter;
            pIter++;
            propLen--;

            if (MQTT_PROP_LAST <= propType)
            {
                status = ERR_MQTT_MALFORMED_PACKET;
                goto exit;
            }

            if (MQTT_PROP_USER_PROPERTY != propType)
            {
                if (MQTT_PROP_IS_SET(pFoundProps, propType))
                {
                    status = ERR_MQTT_PROTOCOL_ERROR;
                    goto exit;
                }

                MQTT_PROP_SET(pFoundProps, propType);
            }

            /* Determine property type */
            switch (propType)
            {
            case MQTT_PROP_REASON_STRING:
            {
                status = MQTT_parseReasonString(&pIter, &propLen, &info.pReasonStr, &info.reasonStrLen);
                if (OK != status)
                    goto exit;
                break;
            }

            case MQTT_PROP_SESSION_EXPIRY_INTERVAL:
            {
                if (propLen < 4)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                info.sessionExpiryIntervalSet = TRUE;
                info.sessionExpiryInterval = MOC_NTOHL(pIter);
                pIter += 4;
                propLen -= 4;
                break;
            }

            case MQTT_PROP_SERVER_REFERENCE:
            {
                if (propLen < 2)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                info.serverRefLen = MOC_NTOHS(pIter);
                pIter += 2;
                propLen -= 2;
                if (propLen < info.serverRefLen)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                info.pServerRef = pIter;

                if (!isValidUtf8(info.pServerRef, info.serverRefLen))
                {
                    status = ERR_MQTT_INVALID_UTF8;
                    goto exit;
                }

                pIter += info.serverRefLen;
                propLen -= info.serverRefLen;
                break;
            }

            case MQTT_PROP_USER_PROPERTY:
            {
                status = MQTT_parseUserProperty(&pIter, &propLen, pUserPropsIters, &userPropCnt);
                if (OK != status)
                    goto exit;
                break;
            }

            default:
            {
                /* This should never happen, packet is malformed */
                status = ERR_MQTT_MALFORMED_PACKET;
                goto exit;
            }
            }
        }

        /* If user properties exist, create the structure with proper pointers back into the
        * original data buffer for a callback to receive */
        if (userPropCnt > 0)
        {
            info.propCount = userPropCnt;

            status = MQTT_setUserProps(&info.pProps, userPropCnt, pUserPropsIters);
            if (OK != status)
                goto exit;
        }
    }

    msg.type = MQTT_DISCONNECT;
    msg.pData = pBuffer;
    msg.dataLen = bufferLen;
    msg.finished = TRUE;

    if (NULL != pCtx->handlers.disconnectHandler)
    {
        /* Intentionally ignore return */
        status = pCtx->handlers.disconnectHandler(connInst, &msg, &info);
    }

exit:

    if (NULL != info.pProps)
    {
        MOC_FREE((void **)&info.pProps);
    }

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_parseDisconnect() returns status = ", status);
    }
#endif

    return status;
}

#if defined(__ENABLE_MQTT_STREAMING__)

static MSTATUS MQTT_parsePublishProps(
    ubyte *pIter,
    ubyte4 propLen,
    MqttPublishInfo *pInfo,
    ubyte **pUserPropsIters)
{
    MSTATUS status = OK;
    ubyte propType = 0;
    ubyte pFoundProps[MQTT_PROP_ARRAY_SIZE] = { 0 };
    ubyte bytesUsed = 0;
    ubyte userPropCnt = 0;
    ubyte4 len = 0;

    /* Process properties */
    while (0 != propLen)
    {
        /* Read property type */
        propType = *pIter;
        pIter++;
        propLen--;

        if (MQTT_PROP_LAST <= propType)
        {
            status = ERR_MQTT_MALFORMED_PACKET;
            goto exit;
        }

        if (MQTT_PROP_USER_PROPERTY != propType)
        {
            if (MQTT_PROP_IS_SET(pFoundProps, propType))
            {
                status = ERR_MQTT_MALFORMED_PACKET;
                goto exit;
            }

            MQTT_PROP_SET(pFoundProps, propType);
        }

        /* Determine property type */
        switch(propType)
        {
            case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
            {
                if (propLen < 1)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                pInfo->payloadFormatSet = TRUE;
                pInfo->payloadFormat = *pIter;
                pIter += 1;
                propLen -= 1;
                break;
            }

            case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
            {
                if (propLen < 4)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                pInfo->messageExpirySet = TRUE;
                pInfo->messageExpiry = MOC_NTOHL(pIter);
                pIter += 4;
                propLen -= 4;
                break;
            }

            case MQTT_PROP_TOPIC_ALIAS:
            {
                if (propLen < 2)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                pInfo->topicAlias = MOC_NTOHS(pIter);
                if (0 == pInfo->topicAlias)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                pIter += 2;
                propLen -= 2;
                break;
            }

            case MQTT_PROP_RESPONSE_TOPIC:
            {
                if (propLen < 2)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                pInfo->responseTopicLen = MOC_NTOHS(pIter);
                pIter += 2;
                propLen -= 2;
                if (propLen < pInfo->responseTopicLen)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                pInfo->pResponseTopic = pIter;

                if (!isValidUtf8(pInfo->pResponseTopic, pInfo->responseTopicLen))
                {
                    status = ERR_MQTT_INVALID_UTF8;
                    goto exit;
                }

                pIter += pInfo->responseTopicLen;
                propLen -= pInfo->responseTopicLen;
                break;
            }

            case MQTT_PROP_CORRELATION_DATA:
            {
                if (propLen < 2)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                pInfo->correlationDataLen = MOC_NTOHS(pIter);
                pIter += 2;
                propLen -= 2;
                if (propLen < pInfo->correlationDataLen)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                pInfo->pCorrelationData = pIter;
                pIter += pInfo->correlationDataLen;
                propLen -= pInfo->correlationDataLen;
                break;
            }

            case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
            {
                status = MQTT_decodeVariableByteInt(
                    pIter, propLen, &pInfo->subId, &bytesUsed);
                if (OK != status)
                    goto exit;

                /* MQTT 5.0 - Section 3.3.2.3.8
                *
                *   The Subscription Identifier can have the value of 1 to
                *   268,435,455. It is a Protocol Error if the Subscription
                *   Identifier has a value of 0.
                *
                * Call to MQTT_decodeVariableByteInt ensures ID is in range
                * 0 to 268,435,455. Ensure ID is not 0.
                */
                if (0 == pInfo->subId)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }

                pIter += bytesUsed;
                propLen -= bytesUsed;
                break;
            }

            case MQTT_PROP_CONTENT_TYPE:
            {
                if (propLen < 2)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                pInfo->contentTypeLen = MOC_NTOHS(pIter);
                pIter += 2;
                propLen -= 2;
                if (propLen < pInfo->contentTypeLen)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                pInfo->pContentType = pIter;
                pIter += pInfo->contentTypeLen;
                propLen -= pInfo->contentTypeLen;
                break;
            }

            case MQTT_PROP_USER_PROPERTY:
            {
                status = MQTT_parseUserProperty(&pIter, &propLen, pUserPropsIters, &userPropCnt);
                if (OK != status)
                    goto exit;
                break;
            }

            default:
            {
                /* This should never happen, packet is malformed */
                status = ERR_MQTT_MALFORMED_PACKET;
                goto exit;
            }
        }
    }

    /* If user properties exist, create the structure with proper pointers back into the
    * original data buffer for a callback to receive */
    if (userPropCnt > 0)
    {
        pInfo->propCount = userPropCnt;

        status = MQTT_setUserProps(&pInfo->pProps, userPropCnt, pUserPropsIters);
        if (OK != status)
            goto exit;
    }

exit:

    return status;
}

static MSTATUS MQTT_parsePublishStream(
    sbyte4 connInst,
    MqttCtx *pCtx,
    ubyte **ppData,
    ubyte4 *pDataLen,
    byteBoolean *pIsDone)
{
    MSTATUS status = OK;
    ubyte4 tmp;
    MqttMessage msg = {0};

    *pIsDone = FALSE;

    while (*pDataLen)
    {
        switch (pCtx->publishState)
        {
            case MQTT_PUBLISH_TYPE_STATE:
                MOC_MEMSET((ubyte *) &pCtx->publishInfo, 0x00, sizeof(MqttPublishInfo));
                MOC_MEMSET((ubyte *) &pCtx->publishData, 0x00, sizeof(MqttPublishData));

                pCtx->publishInfo.dup = (**ppData & 0x08);
                pCtx->publishInfo.qos = (**ppData & 0x06) >> 1;
                pCtx->publishInfo.retain = (**ppData & 0x01);
                (*ppData)++;
                (*pDataLen)--;
                pCtx->publishState = MQTT_PUBLISH_REM_LEN_STATE;
                break;

            case MQTT_PUBLISH_REM_LEN_STATE:
                if (pCtx->publishData.remLenCount >= 4)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                tmp = **ppData;
                pCtx->publishData.pRemLen[pCtx->publishData.remLenCount++] = tmp;
                (*ppData)++;
                (*pDataLen)--;
                if (0 == (tmp & 0x80))
                {
                    status = MQTT_decodeVariableByteInt(
                        pCtx->publishData.pRemLen, pCtx->publishData.remLenCount,
                        &pCtx->publishData.remLen, NULL);
                    if (OK != status)
                        goto exit;

                    pCtx->publishState = MQTT_PUBLISH_TOPIC_LEN_STATE;
                }
                break;

            case MQTT_PUBLISH_TOPIC_LEN_STATE:
                if (pCtx->publishData.remLen-- == 0)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                if (pCtx->publishData.topicLenCount >= 2)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                tmp = **ppData;
                pCtx->publishData.pTopicLen[pCtx->publishData.topicLenCount++] = tmp;
                (*ppData)++;
                (*pDataLen)--;
                if (2 == pCtx->publishData.topicLenCount)
                {
                    pCtx->publishInfo.topicLen = MOC_NTOHS(pCtx->publishData.pTopicLen);

                    status = MOC_MALLOC((void **) &pCtx->publishData.pTopic, pCtx->publishInfo.topicLen);
                    if (OK != status)
                        goto exit;

                    pCtx->publishState = MQTT_PUBLISH_TOPIC_STATE;
                }
                break;

            case MQTT_PUBLISH_TOPIC_STATE:
                if (pCtx->publishData.remLen-- == 0)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                tmp = **ppData;
                pCtx->publishData.pTopic[pCtx->publishData.topicLen++] = tmp;
                (*ppData)++;
                (*pDataLen)--;
                if (pCtx->publishData.topicLen == pCtx->publishInfo.topicLen)
                {
                    pCtx->publishInfo.pTopic = pCtx->publishData.pTopic;
                    if (pCtx->publishInfo.qos > 0)
                    {
                        pCtx->publishState = MQTT_PUBLISH_PACKET_ID_STATE;
                    }
                    else if (MQTT_V5 <= pCtx->version)
                    {
                        pCtx->publishState = MQTT_PUBLISH_PROPS_LEN_STATE;
                    }
                    else
                    {
                        pCtx->publishState = MQTT_PUBLISH_PAYLOAD_STATE;
                    }
                }
                break;

            case MQTT_PUBLISH_PACKET_ID_STATE:
                if (pCtx->publishData.remLen-- == 0)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                if (pCtx->publishData.pktIdCount >= 2)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                tmp = **ppData;
                pCtx->publishData.pPktId[pCtx->publishData.pktIdCount++] = tmp;
                (*ppData)++;
                (*pDataLen)--;
                if (2 == pCtx->publishData.pktIdCount)
                {
                    pCtx->publishInfo.packetId = MOC_NTOHS(pCtx->publishData.pPktId);
                    if (MQTT_V5 <= pCtx->version)
                    {
                        pCtx->publishState = MQTT_PUBLISH_PROPS_LEN_STATE;
                    }
                    else
                    {
                        pCtx->publishState = MQTT_PUBLISH_PAYLOAD_STATE;
                    }
                }
                break;

            case MQTT_PUBLISH_PROPS_LEN_STATE:
                if (pCtx->publishData.remLen-- == 0)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                if (pCtx->publishData.propLenCount >= 4)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                tmp = **ppData;
                pCtx->publishData.pPropLen[pCtx->publishData.propLenCount++] = tmp;
                (*ppData)++;
                (*pDataLen)--;
                if (0 == (tmp & 0x80))
                {
                    status = MQTT_decodeVariableByteInt(pCtx->publishData.pPropLen, pCtx->publishData.propLenCount, &pCtx->publishData.propsLen, NULL);
                    if (OK != status)
                        goto exit;

                    if (0 != pCtx->publishData.propsLen)
                    {
                        status = MOC_MALLOC((void **) &pCtx->publishData.pProps, pCtx->publishData.propsLen);
                        if (OK != status)
                            goto exit;

                        pCtx->publishState = MQTT_PUBLISH_PROPS_STATE;
                    }
                    else
                    {
                        pCtx->publishState = MQTT_PUBLISH_PAYLOAD_STATE;
                    }
                }
                break;

            case MQTT_PUBLISH_PROPS_STATE:
                if (pCtx->publishData.remLen-- == 0)
                {
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
                tmp = **ppData;
                pCtx->publishData.pProps[pCtx->publishData.processedPropsLen++] = tmp;
                (*ppData)++;
                (*pDataLen)--;
                if (pCtx->publishData.propsLen == pCtx->publishData.processedPropsLen)
                {
                    status = MQTT_parsePublishProps(
                        pCtx->publishData.pProps, pCtx->publishData.propsLen,
                        &pCtx->publishInfo, pCtx->publishData.pUserPropsIters);
                    if (OK != status)
                        goto exit;

                    pCtx->publishState = MQTT_PUBLISH_PAYLOAD_STATE;
                }
                break;

            case MQTT_PUBLISH_PAYLOAD_STATE:
                tmp = *pDataLen;
                if (pCtx->publishData.remLen < tmp)
                {
                    tmp = pCtx->publishData.remLen;
                }
                pCtx->publishData.remLen -= tmp;
                pCtx->publishInfo.pPayload = *ppData;
                pCtx->publishInfo.payloadLen = tmp;
                msg.type = MQTT_PUBLISH;
                msg.pData = NULL;
                msg.dataLen = 0;
                if (0 == pCtx->publishData.remLen)
                {
                    msg.finished = TRUE;
                }
                else
                {
                    msg.finished = FALSE;
                }
                if (NULL != pCtx->handlers.publishHandler)
                {
                    pCtx->handlers.publishHandler(connInst, &msg, &pCtx->publishInfo);
                }
                (*ppData) += tmp;
                (*pDataLen) -= tmp;
                if (TRUE == msg.finished)
                {
                    MOC_FREE((void **) &pCtx->publishData.pTopic);
                    MOC_FREE((void **) &pCtx->publishData.pProps);

                    MOC_MEMSET((ubyte *) &pCtx->publishInfo, 0x00, sizeof(MqttPublishInfo));
                    MOC_MEMSET((ubyte *) &pCtx->publishData, 0x00, sizeof(MqttPublishData));

                    pCtx->publishState = MQTT_PUBLISH_TYPE_STATE;

                    *pIsDone = TRUE;
                    goto exit;
                }
                break;

            default:
                status = ERR_MQTT_BAD_PUBLISH_STATE;
                goto exit;
        }
    }

exit:

    return status;
}

#else

MSTATUS MQTT_parsePublish(sbyte connInst, MqttCtx *pCtx, ubyte *pBuffer, ubyte4 bufferLen)
{
    MSTATUS status;
    ubyte4 varHdrLen = 0;
    ubyte bytesUsed = 0;
    ubyte4 propLen = 0;
    ubyte propType = 0;
    MqttPublishInfo info = {0};
    MqttMessage msg = {0};
    ubyte *pUserPropsIters[MAX_NUM_USER_PROPS];
    ubyte userPropCnt = 0;
    byteBoolean allowed = TRUE;
    MqttPubRespOptions options = {0};
    ubyte *pIter = pBuffer;
    ubyte pFoundProps[MQTT_PROP_ARRAY_SIZE] = { 0 };

    /* Parse publish header flags */
    info.dup = *pIter & 0x08;
    info.qos = (*pIter & 0x06) >> 1;
    info.retain = *pIter & 0x01;
    pIter++;

    /* Decode the variable byte length */
    status = MQTT_decodeVariableByteInt(pIter, bufferLen - 1, &varHdrLen, &bytesUsed);
    if (OK != status)
        goto exit;

    /* Ensure the number of bytes in the buffer contain the entire PUBLISH
     * packet */
    if ((varHdrLen + 1 + bytesUsed) != bufferLen)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    pIter += bytesUsed;

    /* Begin publish parsing, topic name */
    if (varHdrLen < 2)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    info.topicLen = MOC_NTOHS(pIter);
    pIter += 2;
    varHdrLen -= 2;
    if (varHdrLen < info.topicLen)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }
    info.pTopic = pIter;
    pIter += info.topicLen;
    varHdrLen -= info.topicLen;

    if (info.qos > 0)
    {
        /* Packet Identifier */
        if (varHdrLen < 2)
        {
            status = ERR_MQTT_MALFORMED_PACKET;
            goto exit;
        }
        info.packetId = MOC_NTOHS(pIter);
        pIter += 2;
        varHdrLen -= 2;
    }

   if (MQTT_QOS_1 == info.qos || MQTT_QOS_2 == info.qos)
   {
        if (0 == pCtx->clientSendQuota)
        {
            status = ERR_MQTT_RECV_MAX_EXCEEDED;
            goto exit;
        }
        else
        {
            pCtx->clientSendQuota--;
        }
   }

    if (MQTT_V5 <= pCtx->version)
    {
        status = MQTT_decodeVariableByteInt(pIter, varHdrLen, &propLen, &bytesUsed);
        if (OK != status)
            goto exit;

        pIter += bytesUsed;
        varHdrLen -= bytesUsed;

        if (propLen > varHdrLen)
        {
            status = ERR_MQTT_MALFORMED_PACKET;
            goto exit;
        }

        varHdrLen -= propLen;

        /* Process properties */
        while (0 != propLen)
        {
            /* Read property type */
            propType = *pIter;
            pIter++;
            propLen--;

            if (MQTT_PROP_LAST <= propType)
            {
                status = ERR_MQTT_MALFORMED_PACKET;
                goto exit;
            }

            if (MQTT_PROP_USER_PROPERTY != propType)
            {
                if (MQTT_PROP_IS_SET(pFoundProps, propType))
                {
                    status = ERR_MQTT_PROTOCOL_ERROR;
                    goto exit;
                }

                MQTT_PROP_SET(pFoundProps, propType);
            }

            /* Determine property type */
            switch(propType)
            {
                case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
                {
                    if (propLen < 1)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.payloadFormatSet = TRUE;
                    info.payloadFormat = *pIter;
                    pIter += 1;
                    propLen -= 1;
                    break;
                }

                case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
                {
                    if (propLen < 4)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.messageExpirySet = TRUE;
                    info.messageExpiry = MOC_NTOHL(pIter);
                    pIter += 4;
                    propLen -= 4;
                    break;
                }

                case MQTT_PROP_TOPIC_ALIAS:
                {
                    if (propLen < 2)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.topicAlias = MOC_NTOHS(pIter);
                    if (0 == info.topicAlias || info.topicAlias > pCtx->topicAliasMax)
                    {
                        status = ERR_MQTT_INVALID_TOPIC_ALIAS;
                        goto exit;
                    }
                    pIter += 2;
                    propLen -= 2;
                    break;
                }

                case MQTT_PROP_RESPONSE_TOPIC:
                {
                    if (propLen < 2)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.responseTopicLen = MOC_NTOHS(pIter);
                    pIter += 2;
                    propLen -= 2;
                    if (propLen < info.responseTopicLen)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.pResponseTopic = pIter;

                    if (!isValidUtf8(info.pResponseTopic, info.responseTopicLen))
                    {
                        status = ERR_MQTT_INVALID_UTF8;
                        goto exit;
                    }

                    pIter += info.responseTopicLen;
                    propLen -= info.responseTopicLen;
                    break;
                }

                case MQTT_PROP_CORRELATION_DATA:
                {
                    if (propLen < 2)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.correlationDataLen = MOC_NTOHS(pIter);
                    pIter += 2;
                    propLen -= 2;
                    if (propLen < info.correlationDataLen)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.pCorrelationData = pIter;
                    pIter += info.correlationDataLen;
                    propLen -= info.correlationDataLen;
                    break;
                }

                case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
                {
                    status = MQTT_decodeVariableByteInt(
                        pIter, propLen, &info.subId, &bytesUsed);
                    if (OK != status)
                        goto exit;

                    /* MQTT 5.0 - Section 3.3.2.3.8
                    *
                    *   The Subscription Identifier can have the value of 1 to
                    *   268,435,455. It is a Protocol Error if the Subscription
                    *   Identifier has a value of 0.
                    *
                    * Call to MQTT_decodeVariableByteInt ensures ID is in range
                    * 0 to 268,435,455. Ensure ID is not 0.
                    */
                    if (0 == info.subId)
                    {
                        status = ERR_MQTT_PROTOCOL_ERROR;
                        goto exit;
                    }

                    pIter += bytesUsed;
                    propLen -= bytesUsed;
                    break;
                }

                case MQTT_PROP_CONTENT_TYPE:
                {
                    if (propLen < 2)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.contentTypeLen = MOC_NTOHS(pIter);
                    pIter += 2;
                    propLen -= 2;
                    if (propLen < info.contentTypeLen)
                    {
                        status = ERR_MQTT_MALFORMED_PACKET;
                        goto exit;
                    }
                    info.pContentType = pIter;
                    pIter += info.contentTypeLen;
                    propLen -= info.contentTypeLen;
                    break;
                }

                case MQTT_PROP_USER_PROPERTY:
                {
                    status = MQTT_parseUserProperty(&pIter, &propLen, pUserPropsIters, &userPropCnt);
                    if (OK != status)
                        goto exit;
                    break;
                }

                default:
                {
                    /* This should never happen, packet is malformed */
                    status = ERR_MQTT_MALFORMED_PACKET;
                    goto exit;
                }
            }
        }

        /* If user properties exist, create the structure with proper pointers back into the
        * original data buffer for a callback to receive */
        if (userPropCnt > 0)
        {
            info.propCount = userPropCnt;

            status = MQTT_setUserProps(&info.pProps, userPropCnt, pUserPropsIters);
            if (OK != status)
                goto exit;
        }
    }

    info.pPayload = pIter;
    info.payloadLen = varHdrLen;

    msg.type = MQTT_PUBLISH;
    msg.pData = pBuffer;
    msg.dataLen = bufferLen;
    msg.finished = TRUE;

    if (info.qos == MQTT_QOS_2)
    {
        /* MQTT v5 spec 4.3.3 receiver responsibilities:
         * Until it has received the corresponding PUBREL packet, the receiver 
         * MUST acknowledge any subsequent PUBLISH packet with the same Packet 
         * Identifier by sending a PUBREC. It MUST NOT cause duplicate messages 
         * to be delivered to any onward recipients in this case */
        status = MQTT_checkPublishDeliveryAllowed(pCtx, info.packetId, &allowed);
        if (OK != status)
            goto exit;
    }

    if ((TRUE == allowed) && (NULL != pCtx->handlers.publishHandler))
    {
        /* Intentionally ignore return */
        pCtx->handlers.publishHandler(connInst, &msg, &info);
    }

    if (info.qos == MQTT_QOS_1)
    {
        options.packetType = MQTT_PUBACK;
    }
    else if (info.qos == MQTT_QOS_2)
    {
        options.packetType = MQTT_PUBREC;
    }

    if ((TRUE == info.payloadFormatSet) && (!isValidUtf8(info.pPayload, info.payloadLen)))
    {
        options.reasonCode = MQTT_PUB_PAYLOAD_FORMAT_INVALID;
    }
    else
    {
        options.reasonCode = MQTT_PUB_SUCCESS;
    }

    if (0 != options.packetType)
    {
        options.packetId = info.packetId;

        status = MQTT_sendPubResp(connInst, &options);
        if (OK != status)
            goto exit;
    }

exit:

    if (NULL != info.pProps)
    {
        MOC_FREE((void **)&info.pProps);
    }

    return status;
}

#endif /* __ENABLE_MQTT_STREAMING__ */

/* Shared parsing for PUBACK, PUBREC, PUBREL, PUBCOMP */
MSTATUS MQTT_parsePubResp(sbyte connInst, MqttCtx *pCtx, ubyte *pBuffer, ubyte4 bufferLen)
{
    MSTATUS status;
    ubyte packetType = 0;
    ubyte4 varHdrLen = 0;
    ubyte bytesUsed = 0;
    ubyte4 propLen = 0;
    ubyte propType = 0;
    MqttMessage msg = {0};
    ubyte *pUserPropsIters[MAX_NUM_USER_PROPS];
    ubyte userPropCnt = 0;
    MqttPubRespInfo info = {0};
    ubyte pFoundProps[MQTT_PROP_ARRAY_SIZE] = { 0 };
    MqttPubRespOptions options = {0};
    ubyte *pIter = pBuffer;

    /* Get the packet type so we know which callback to invoke */
    packetType = *pIter;
    pIter++;

    /* Decode the variable byte length */
    status = MQTT_decodeVariableByteInt(pIter, bufferLen - 1, &varHdrLen, &bytesUsed);
    if (OK != status)
        goto exit;

    /* Ensure the number of bytes in the buffer contain the entire PUBACK
     * packet */
    if ((varHdrLen + 1 + bytesUsed) != bufferLen)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    pIter += bytesUsed;

    info.msgId = MOC_NTOHS(pIter);
    pIter += 2;
    varHdrLen -= 2;

    /* MQTTv5 spec 3.4.2.1, if variable header length for a PUBACK is 2, there is no 
     * reason code and success is used */
    if (0 == varHdrLen)
    {
        goto handle_callback;
    }

    info.reasonCode = MOC_NTOHS(pIter);
    pIter += 1;
    varHdrLen -= 1;

    /* While it does not seem to be within specification, some brokers (mosquitto)
     * send a PUB* packet with no property bytes, instead of zero len encoded. Check
     * for that case now and allow it */
    if (0 == varHdrLen)
    {
        goto handle_callback;
    }

    status = MQTT_decodeVariableByteInt(pIter, varHdrLen, &propLen, &bytesUsed);
    if (OK != status)
        goto exit;

    pIter += bytesUsed;
    varHdrLen -= bytesUsed;

    if (propLen > varHdrLen)
    {
        status = ERR_MQTT_MALFORMED_PACKET;
        goto exit;
    }

    varHdrLen -= propLen;

    /* Process properties */
    while (0 != propLen)
    {
        /* Read property type */
        propType = *pIter;
        pIter++;
        propLen--;

        if (MQTT_PROP_LAST <= propType)
        {
            status = ERR_MQTT_MALFORMED_PACKET;
            goto exit;
        }

        if (MQTT_PROP_USER_PROPERTY != propType)
        {
            if (MQTT_PROP_IS_SET(pFoundProps, propType))
            {
                status = ERR_MQTT_PROTOCOL_ERROR;
                goto exit;
            }

            MQTT_PROP_SET(pFoundProps, propType);
        }

        /* Determine property type */
        switch (propType)
        {
            case MQTT_PROP_REASON_STRING:
            {
                status = MQTT_parseReasonString(&pIter, &propLen, &info.pReasonStr, &info.reasonStrLen);
                if (OK != status)
                    goto exit;
                break;
            }

            case MQTT_PROP_USER_PROPERTY:
            {
                status = MQTT_parseUserProperty(&pIter, &propLen, pUserPropsIters, &userPropCnt);
                if (OK != status)
                    goto exit;
                break;
            }

            default:
            {
                /* This should never happen, packet is malformed */
                status = ERR_MQTT_MALFORMED_PACKET;
                goto exit;
            }
        }
    }

    /* If user properties exist, create the structure with proper pointers back into the
     * original data buffer for a callback to receive */
    if (userPropCnt > 0)
    {
        info.propCount = userPropCnt;

        status = MQTT_setUserProps(&info.pProps, userPropCnt, pUserPropsIters);
        if (OK != status)
            goto exit;
    }

handle_callback:

    msg.type = (packetType >> 4);
    msg.pData = pBuffer;
    msg.dataLen = bufferLen;
    msg.finished = TRUE;

    switch(msg.type)
    {
        case MQTT_PUBACK:
        {
            status = MQTT_markAcked(pCtx, info.msgId);
            if (OK != status)
                goto exit;

            if (NULL != pCtx->handlers.pubAckHandler)
            {
                /* Intentionally ignore return */
                pCtx->handlers.pubAckHandler(connInst, &msg, &info);
            }
        }
        break;

        case MQTT_PUBREC:
        {
            options.packetType = MQTT_PUBREL;
            options.reasonCode = 0;
            options.packetId = info.msgId;

            /* MQTTV5 spec 4.4
             * If PUBACK or PUBREC is received containing a Reason Code of 0x80
             * or greater the corresponding PUBLISH packet is treated as acknowledged */
            if (info.reasonCode >= 0x80)
            {
                status = MQTT_markAcked(pCtx, info.msgId);
                if (OK != status)
                    goto exit;
            }
            else
            {
                status = MQTT_sendPubResp(connInst, &options);
                if (OK != status)
                    goto exit;
            }

            if (NULL != pCtx->handlers.pubRecHandler)
            {
                /* Intentionally ignore return */
                pCtx->handlers.pubRecHandler(connInst, &msg, &info);
            }
        }
        break;

        case MQTT_PUBREL:
        {
            options.packetType = MQTT_PUBCOMP;
            options.reasonCode = 0;
            options.packetId = info.msgId;

            status = MQTT_markInboundPubrel(pCtx, info.msgId);
            if (OK != status)
                goto exit;

            status = MQTT_sendPubResp(connInst, &options);
            if (OK != status)
                goto exit;

            if (NULL != pCtx->handlers.pubRelHandler)
            {
                /* Intentionally ignore return */
                pCtx->handlers.pubRelHandler(connInst, &msg, &info);
            }
        }
        break;

        case MQTT_PUBCOMP:
        {
            status = MQTT_markAcked(pCtx, info.msgId);
            if (OK != status)
                goto exit;

            if (NULL != pCtx->handlers.pubCompHandler)
            {
                /* Intentionally ignore return */
                pCtx->handlers.pubCompHandler(connInst, &msg, &info);
            }
        }
        break;

        default:
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

    }

exit:

    if (NULL != info.pProps)
    {
        MOC_FREE((void **)&info.pProps);
    }

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_parsePubResp() returns status = ", status);
    }
#endif

    return status;
}

MSTATUS MQTT_parsePacket(
    sbyte4 connInst,
    MqttCtx *pCtx,
    ubyte *pBuffer,
    ubyte4 bufferLen)
{
    MSTATUS status = OK;
    ubyte bytesUsed;
    ubyte *pResizeBuffer = NULL;
    ubyte4 copyLen;
    MqttDisconnectOptions options = {0};
    ubyte4 remainingLen;
#if defined(__ENABLE_MQTT_STREAMING__)
    byteBoolean isDone = FALSE;
#endif /* __ENABLE_MQTT_STREAMING__ */

    while (0 != bufferLen)
    {
        if (0 == pCtx->recvMsgSize)
        {
            /* Message byte length not yet calculated, see if we can get the length
             * from the currently stored bytes + caller provided bytes */

            /* The start of all MQTT control packet are structured the same
             *   1 byte - packet type
             *   2-5 byte(s) - variable byte integer for length */
            if (0 == pCtx->recvMsgOffset)
            {
#if defined(__ENABLE_MQTT_STREAMING__)
                if (FALSE == pCtx->streamingCurPkt && MQTT_PUBLISH == (*pBuffer >> 4))
                {
                    pCtx->streamingCurPkt = TRUE;
                    pCtx->pktHandler = MQTT_parsePublishStream;
                }

                if (TRUE == pCtx->streamingCurPkt)
                {
                    goto streamParse;
                }
#endif /* __ENABLE_MQTT_STREAMING__ */

                /* No data stored yet, try to get the packet length from the caller
                 * provided buffer */

                /* Try to get remaining len*/
                status = MQTT_decodeVariableByteInt(
                        pBuffer + 1, bufferLen - 1,
                        &remainingLen, &bytesUsed);

                if ( (5 <= bufferLen) ||
                     (bufferLen > 1 && !(pBuffer[bufferLen - 1] & 0x80)) ||
                     (bufferLen > 1 && (pBuffer[bufferLen - 1] & 0x80) && (OK == status) && (bufferLen >= remainingLen + 1 + bytesUsed))) /* Last byte indicates more bytes, but matches remaining length*/
                {
                    /* Have enough bytes to compute the length */
                    status = MQTT_decodeVariableByteInt(
                        pBuffer + 1, bufferLen - 1,
                        &pCtx->recvMsgSize, &bytesUsed);
                    if (OK != status)
                        goto exit;

                    pCtx->recvMsgSize += bytesUsed + 1;

                    if (pCtx->recvBufferSize < pCtx->recvMsgSize)
                    {
                        /* Check if the maximum packet size is being exceeded */
                        if (0 != pCtx->maxPacketSize)
                        {
                            if (pCtx->recvMsgSize > pCtx->maxPacketSize)
                            {
                                status = ERR_MQTT_PACKET_TOO_LARGE;
                                goto exit;
                            }
                        }
                        /* Resize our buffer so it can fit the full message */
                        MOC_FREE((void **) &pCtx->pRecvBuffer);
                        status = MOC_MALLOC((void **) &pCtx->pRecvBuffer, pCtx->recvMsgSize);
                        if (OK != status)
                            goto exit;

                        pCtx->recvBufferSize = pCtx->recvMsgSize;
                    }
                }
                else
                {
                    /* Not enough bytes to compute the length */
                    if (pCtx->recvBufferSize < 5)
                    {
                        /* Check if the maximum packet size is being exceeded */
                        if (0 != pCtx->maxPacketSize)
                        {
                            if (5 > pCtx->maxPacketSize)
                            {
                                status = ERR_MQTT_PACKET_TOO_LARGE;
                                goto exit;
                            }
                        }
                        /* Resize our buffer so it can fit the partial content */
                        MOC_FREE((void **) &pCtx->pRecvBuffer);
                        status = MOC_MALLOC((void **) &pCtx->pRecvBuffer, 5);
                        if (OK != status)
                            goto exit;

                        pCtx->recvBufferSize = 5;
                    }
                }
                if (bufferLen > pCtx->recvMsgSize)
                    copyLen = pCtx->recvMsgSize;
                else
                    copyLen = bufferLen;

                /* Copy over the contents provided by caller */
                MOC_MEMCPY(pCtx->pRecvBuffer, pBuffer, copyLen);
                pCtx->recvMsgOffset = copyLen;
                pBuffer += copyLen;
                bufferLen -= copyLen;
            }
            else
            {
                /* Message size was not set from a previous call, try to compute
                 * the size now */
                copyLen = 5 - pCtx->recvMsgOffset;
                if (copyLen > bufferLen)
                    copyLen = bufferLen;

                MOC_MEMCPY(pCtx->pRecvBuffer + pCtx->recvMsgOffset, pBuffer, copyLen);
                pCtx->recvMsgOffset += copyLen;
                pBuffer += copyLen;
                bufferLen -= copyLen;

                if ( (5 <= pCtx->recvMsgOffset) ||
                    (!(pCtx->pRecvBuffer[pCtx->recvMsgOffset - 1] & 0x80)) )
                {
                    /* Have enough bytes to compute the length */
                    status = MQTT_decodeVariableByteInt(
                        pCtx->pRecvBuffer + 1, pCtx->recvMsgOffset - 1,
                        &pCtx->recvMsgSize, &bytesUsed);
                    if (OK != status)
                        goto exit;

                    pCtx->recvMsgSize += bytesUsed + 1;

                    if (pCtx->recvBufferSize < pCtx->recvMsgSize)
                    {
                        /* Check if the maximum packet size is being exceeded */
                        if (0 != pCtx->maxPacketSize)
                        {
                            if (pCtx->recvMsgSize > pCtx->maxPacketSize)
                            {
                                status = ERR_MQTT_PACKET_TOO_LARGE;
                                goto exit;
                            }
                        }
                        /* Resize our buffer so it can fit the full message */
                        status = MOC_MALLOC((void **) &pResizeBuffer, pCtx->recvMsgSize);
                        if (OK != status)
                            goto exit;

                        MOC_MEMCPY(pResizeBuffer, pCtx->pRecvBuffer, pCtx->recvMsgOffset);

                        MOC_FREE((void **) &pCtx->pRecvBuffer);
                        pCtx->pRecvBuffer = pResizeBuffer; pResizeBuffer = NULL;
                        pCtx->recvBufferSize = pCtx->recvMsgSize;
                    }
                    if (bufferLen > pCtx->recvMsgSize)
                        copyLen = pCtx->recvMsgSize;
                    else
                        copyLen = bufferLen;

                    MOC_MEMCPY(pCtx->pRecvBuffer + pCtx->recvMsgOffset, pBuffer, copyLen);
                    pCtx->recvMsgOffset += copyLen;
                    pBuffer += copyLen;
                    bufferLen -= copyLen;
                }
            }
        }
        else
        {
            copyLen = pCtx->recvMsgSize - pCtx->recvMsgOffset;
            if (copyLen > bufferLen)
                copyLen = bufferLen;

            MOC_MEMCPY(pCtx->pRecvBuffer + pCtx->recvMsgOffset, pBuffer, copyLen);
            pCtx->recvMsgOffset += copyLen;
            pBuffer += copyLen;
            bufferLen -= copyLen;
        }

        /* Could not determine packet length or a full packet is not available
         * to process, need more bytes, exit with OK */
        if ( (0 == pCtx->recvMsgSize) ||
             (pCtx->recvMsgOffset < pCtx->recvMsgSize) )
        {
            status = OK;
            goto exit;
        }

        /* MQTT v5 spec 3.1.2.11.4:
         * If a Client receives a packet whose size exceeds this limit, this is a 
         * Protocol Error, the Client uses DISCONNECT with Reason Code 0x95 */
        if (pCtx->recvMsgSize > pCtx->maxPacketSize)
        {
            status = ERR_MQTT_PACKET_TOO_LARGE;
            goto exit;
        }


#if defined(__ENABLE_MQTT_CLIENT_DUMP_MESSAGES__)
        MQTT_printMsg(pCtx->pRecvBuffer, pCtx->recvMsgSize, TRUE);
#endif

        switch((*(pCtx->pRecvBuffer) >> 4))
        {
            case MQTT_CONNACK:
                status = MQTT_parseConnAck(connInst, pCtx, pCtx->pRecvBuffer, pCtx->recvMsgSize);
                break;

            case MQTT_SUBACK:
                status = MQTT_parseSubAck(connInst, pCtx, pCtx->pRecvBuffer, pCtx->recvMsgSize);
                break;

            case MQTT_UNSUBACK:
                status = MQTT_parseUnsubAck(connInst, pCtx, pCtx->pRecvBuffer, pCtx->recvMsgSize);
                break;

#if !defined(__ENABLE_MQTT_STREAMING__)
            case MQTT_PUBLISH:
                status = MQTT_parsePublish(connInst, pCtx, pCtx->pRecvBuffer, pCtx->recvMsgSize);
                break;
#endif

            case MQTT_AUTH:
                status = MQTT_parseAuth(connInst, pCtx, pCtx->pRecvBuffer, pCtx->recvMsgSize);
                break;

            case MQTT_PINGRESP:
                status = MQTT_parsePingResp(connInst, pCtx, pCtx->pRecvBuffer, pCtx->recvMsgSize);
                break;

            case MQTT_DISCONNECT:
                status = MQTT_parseDisconnect(connInst, pCtx, pCtx->pRecvBuffer, pCtx->recvMsgSize);
                break;

            case MQTT_PUBACK:
            case MQTT_PUBREC:
            case MQTT_PUBREL:
            case MQTT_PUBCOMP:
                status = MQTT_parsePubResp(connInst, pCtx, pCtx->pRecvBuffer, pCtx->recvMsgSize);
                break;

            default:
                status = ERR_MQTT_INVALID_PACKET_TYPE;
                goto exit;
        }

        if (OK != status)
        {
            goto exit;
        }

        pCtx->recvMsgSize = 0;
        pCtx->recvMsgOffset = 0;

#if defined(__ENABLE_MQTT_STREAMING__)
streamParse:
        if (TRUE == pCtx->streamingCurPkt)
        {
            status = pCtx->pktHandler(connInst, pCtx, &pBuffer, &bufferLen, &isDone);
            if (OK != status)
                goto exit;

            if (TRUE == isDone)
            {
                pCtx->streamingCurPkt = FALSE;
                pCtx->pktHandler = NULL;
            }
        }
#endif /* __ENABLE_MQTT_STREAMING__ */

    }

exit:

    switch (status)
    {
        /* Malformed packet */
        case ERR_MQTT_INVALID_PACKET_TYPE:
        case ERR_MQTT_MALFORMED_PACKET:
            options.reasonCode = MQTT_DISCONNECT_MALFORMED_PACKET;
            break;

        /* Protocol Error */
        case ERR_MQTT_PROTOCOL_ERROR:
        case ERR_MQTT_INVALID_SUB_ID:
            options.reasonCode = MQTT_DISCONNECT_PROTOCOL_ERROR;
            break;

        /* Invalid Topic alias */
        case ERR_MQTT_INVALID_TOPIC_ALIAS:
            options.reasonCode = MQTT_DISCONNECT_TOPIC_ALIAS_INVALID;
            break;

        /* Packet too large */
        case ERR_MQTT_PACKET_TOO_LARGE:
            options.reasonCode = MQTT_DISCONNECT_PACKET_TOO_LARGE;
            break;

        /* Receive max exceeded */
        case ERR_MQTT_RECV_MAX_EXCEEDED:
            options.reasonCode = MQTT_DISCONNECT_RECV_MAX_EXCEEDED;
            break;
    }

    if (0 != options.reasonCode)
    {
        /* Reason code was set, send disconnect and call alert handler */

        /* We have no recourse if we fail to construct or send disconnect, we are already returning
         * a fatal error. */
        MQTT_disconnect(connInst, &options);

        /* Call the alert handler to inform application immediately of disconnect reason */
        if (NULL != pCtx->handlers.alertHandler)
        {
            pCtx->handlers.alertHandler(connInst, status);
        }
    }

    return status;
}

static MSTATUS MQTT_computeConnectLen(MqttCtx *pCtx, MqttConnectOptions *pOptions, ubyte4 *pTotalLen, ubyte4 *pPropLen, ubyte4 *pWillPropLen)
{
    MSTATUS status = OK;
    ubyte4 i = 0;
    ubyte4 len = 0;
    ubyte4 propLen = 0;
    ubyte4 willPropLen = 0;
    ubyte encoded[4];
    ubyte bytesUsed = 0;

    /* CONNECT variable header overhead */
    len = 10;

    /* BEGING connect property length computation */
    if (MQTT_V5 <= pCtx->version)
    {
        if (NULL != pOptions->pAuthMethod)
        {
            /* prop id byte + 2 len bytes + method */
            propLen += 1 + 2 + pOptions->authMethodLen;
        }

        if ( (NULL != pOptions->pAuthData) && (pOptions->authDataLen > 0) )
        {
            /* id byte + 2 len bytes + data */
            propLen += 1 + 2 + pOptions->authDataLen;
        }

        if (0 != pOptions->sessionExpiryIntervalSeconds)
        {
            /* id byte + 4 byte field */
            propLen += 1 + 4;
        }

        if (0 != pOptions->receiveMax)
        {
            /* id byte + 2 byte field */
            propLen += 1 + 2;
        }

        if (0 != pOptions->maxPacketSize)
        {
            /* id byte + 4 byte field */
            propLen += 1 + 4;
        }

        if (0 != pOptions->topicAliasMax)
        {
            /* id byte + 2 byte field */
            propLen += 1 + 2;
        }

        if (0 != pOptions->requestResponseInfo)
        {
            /* id byte + 1 byte field */
            propLen += 1 + 1;
        }

        if (0 != pOptions->requestProblemInfo)
        {
            /* id byte + 1 byte field */
            propLen += 1 + 1;
        }

        if ( (pOptions->propCount > 0) && (NULL == pOptions->pProps) )
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        /* Compute length of user input properties, assuming they are already UTF-8 encoded */
        for (i = 0; i < pOptions->propCount; i++)
        {
            propLen += 1 + 2 + ((pOptions->pProps[i]).data.pair.name.dataLen) +
                           2 + ((pOptions->pProps[i]).data.pair.value.dataLen);
        }

        status = MQTT_encodeVariableByteInt(propLen, encoded, &bytesUsed);
        if (OK != status)
            goto exit;

        len += propLen;

        len += bytesUsed;
    }

    *pPropLen = propLen;

    /* BEGIN payload len computation */

    /* If the Client supplies a zero-byte ClientId, the Client MUST also set
     * CleanSession to 1 */
    if (MQTT_V3_1_1 == pCtx->version && TRUE == pCtx->assignedClientId &&
        TRUE != pOptions->cleanStart)
    {
        status = ERR_MQTT_CLEAN_SESSION_REQUIRED;
        goto exit;
    }

    /* Client ID */
    len += 2 + pCtx->clientIdLen;

    /* Will properties */
    if (MQTT_V5 <= pCtx->version && NULL != pOptions->willInfo.pWill)
    {
        if (0 != pOptions->willInfo.willDelayInterval)
        {
            /* id byte + 4 byte field */
            willPropLen += 1 + 4;
        }

        if (TRUE == pOptions->willInfo.setPayloadFormat)
        {
            /* id byte + 1 byte field */
            willPropLen += 1 + 1;
        }

        if (0 != pOptions->willInfo.msgExpiryInterval)
        {
            /* id byte + 4 byte field */
            willPropLen += 1 + 4;
        }

        if (NULL != pOptions->willInfo.pContentType)
        {
            /* id byte + 2 len bytes + data */
            willPropLen += 1 + 2 + pOptions->willInfo.contentTypeLen;
        }

        if (NULL != pOptions->willInfo.pResponseTopic)
        {
            /* id byte + 2 len bytes + data */
            willPropLen += 1 + 2 + pOptions->willInfo.responseTopicLen;
        }

        if (pOptions->willInfo.correlationDataLen > 0)
        {
            /* id byte + 2 len bytes + data */
            willPropLen += 1 + 2 + pOptions->willInfo.correlationDataLen;
        }

        if ( (pOptions->willInfo.propCount > 0) && (NULL == pOptions->willInfo.pProps) )
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        /* Compute length of user input properties, assuming they are already UTF-8 encoded */
        for (i = 0; i < pOptions->willInfo.propCount; i++)
        {
            willPropLen += 1 + 2 + ((pOptions->willInfo.pProps[i]).data.pair.name.dataLen) +
                               2 + ((pOptions->willInfo.pProps[i]).data.pair.value.dataLen);
        }

        *pWillPropLen = willPropLen;
        len += willPropLen;

        status = MQTT_encodeVariableByteInt(willPropLen, encoded, &bytesUsed);
        if (OK != status)
            goto exit;

        len += bytesUsed;
    }

    /* The follwing data are not properties, but part of an expected ordered connect payload, and as such
     * have no id byte for the length computation */

    /* Will Topic */
    if (NULL != pOptions->willInfo.pWillTopic)
    {
        len += 2 + pOptions->willInfo.willTopicLen;
    }

    /* Will Payload */
    if (NULL != pOptions->willInfo.pWill)
    {
        len += 2 + pOptions->willInfo.willLen;
    }

    /* Username */
    if (NULL != pOptions->pUsername)
    {
        len += 2 + pOptions->usernameLen;
    }

    if (NULL != pOptions->pPassword)
    {
        len += 2 + pOptions->passwordLen;
    }

    *pTotalLen = len;

exit:
    return status;
}

static MSTATUS MQTT_writeUserProps(ubyte *pBuf, MqttProperty *pProps, ubyte4 propCount, ubyte4 *pOffset)
{
    MSTATUS status = OK;
    ubyte4 offset = 0;
    ubyte4 i;

    /* Write the user properties directly, they are UTF-8 String Pair as defined
     * in MQTTv5 spec 2.2.2.2 */
    for (i = 0; i < propCount; i++)
    {
        *pBuf = MQTT_PROP_USER_PROPERTY;
        pBuf++; offset++;

        if (!isValidUtf8((pProps[i]).data.pair.name.pData, (pProps[i]).data.pair.name.dataLen))
        {
            status = ERR_MQTT_INVALID_UTF8;
            goto exit;
        }

        /* Name length */
        MOC_HTONS(pBuf, (pProps[i]).data.pair.name.dataLen);
        pBuf += 2; offset += 2;

        /* Name value */
        status = MOC_MEMCPY((void *)pBuf,
            (void *)(pProps[i]).data.pair.name.pData,
            (pProps[i]).data.pair.name.dataLen);
        if (OK != status)
            goto exit;

        pBuf += (pProps[i]).data.pair.name.dataLen;
        offset += (pProps[i]).data.pair.name.dataLen;

        /* Value length*/
        MOC_HTONS(pBuf, (pProps[i]).data.pair.value.dataLen);
        pBuf += 2; offset += 2;

        status = MOC_MEMCPY((void *)pBuf,
            (void *)(pProps[i]).data.pair.value.pData,
            (pProps[i]).data.pair.value.dataLen);
        if (OK != status)
            goto exit;

        pBuf += (pProps[i]).data.pair.value.dataLen;
        offset += (pProps[i]).data.pair.value.dataLen;
    }

    *pOffset = offset;

exit:
    return status;
}

static MSTATUS MQTT_buildConnectFlags(MqttConnectOptions *pOptions, ubyte *pRes)
{
    MSTATUS status = OK;
    ubyte res = 0;

    /* Build the connect flags byte per MQTTv5 spec 3.1.2.3 */
    if (NULL != pOptions->pUsername)
    {
        res |= MQTT_USER_NAME_FLAG;
    }

    if (NULL != pOptions->pPassword)
    {
        res |= MQTT_PASSWORD_FLAG;
    }

    if (TRUE == pOptions->willInfo.retain)
    {
        res |= MQTT_WILL_RETAIN_FLAG;
    }

    if (NULL != pOptions->willInfo.pWill)
    {
        res |= MQTT_WILL_FLAG;
    }

    if (TRUE == pOptions->cleanStart)
    {
        res |= MQTT_CLEAN_START_FLAG;
    }

    switch(pOptions->willInfo.qos)
    {
        case MQTT_QOS_0:
            break;

        case MQTT_QOS_1:
            res |= MQTT_QOS_1_FLAG;
            break;

        case MQTT_QOS_2:
            res |= MQTT_QOS_2_FLAG;
            break;

        default:
            status = ERR_INVALID_INPUT;
            goto exit;
    }

    *pRes = res;

exit:
    return status;
}


static MSTATUS MQTT_constructConnectProps(ubyte *pIter, MqttConnectOptions *pOptions, ubyte4 propLen, ubyte **ppIter)
{
    MSTATUS status;
    ubyte4 i = 0;
    ubyte encoded[4];
    ubyte bytesUsed = 0;
    ubyte4 offset = 0;

    /* Property Length encoded as variable byte integer */
    status = MQTT_encodeVariableByteInt(propLen, encoded, &bytesUsed);
    if (OK != status)
        goto exit;

    for (i = 0; i < bytesUsed; i++)
    {
        *pIter = encoded[i];
        pIter++;
    }

    /* Construct Connect properties in order as defined in MQTTv5 spec 3.1.2.11 */
    if (0 != pOptions->sessionExpiryIntervalSeconds)
    {
        *pIter = MQTT_PROP_SESSION_EXPIRY_INTERVAL;
        pIter++;
        MOC_HTONL(pIter, pOptions->sessionExpiryIntervalSeconds);
        pIter += 4;
    }

    if (0 != pOptions->receiveMax)
    {
        *pIter = MQTT_PROP_RECEIVE_MAXIMUM;
        pIter++;
        MOC_HTONS(pIter, pOptions->receiveMax);
        pIter += 2;
    }

    if (0 != pOptions->maxPacketSize)
    {
        *pIter = MQTT_PROP_MAXIMUM_PACKET_SIZE;
        pIter++;
        MOC_HTONL(pIter, pOptions->maxPacketSize);
        pIter += 4;
    }

    if (0 != pOptions->topicAliasMax)
    {
        *pIter = MQTT_PROP_TOPIC_ALIAS_MAXIMUM;
        pIter++;
        MOC_HTONS(pIter, pOptions->topicAliasMax);
        pIter += 2;
    }

    if (0 != pOptions->requestResponseInfo)
    {
        *pIter = MQTT_PROP_REQUEST_RESPONSE_INFORMATION;
        pIter++;
        *pIter = pOptions->requestResponseInfo;
        pIter++;
    }

    if (0 != pOptions->requestProblemInfo)
    {
        *pIter = MQTT_PROP_REQUEST_PROBLEM_INFORMATION;
        pIter++;
        *pIter = pOptions->requestProblemInfo;
        pIter++;
    }

    if (NULL != pOptions->pAuthMethod)
    {
        *pIter = MQTT_PROP_AUTHENTICATION_METHOD;
        pIter++;
        MOC_HTONS(pIter, pOptions->authMethodLen);
        
        if (!isValidUtf8(pOptions->pAuthMethod, pOptions->authMethodLen))
        {
            status = ERR_MQTT_INVALID_UTF8;
            goto exit;
        }

        pIter += 2;
        status = MOC_MEMCPY((void *)pIter, (const void *)pOptions->pAuthMethod, pOptions->authMethodLen);
        if (OK != status)
            goto exit;

        pIter += pOptions->authMethodLen;
    }

    if ( (NULL != pOptions->pAuthData) && (pOptions->authDataLen > 0) )
    {
        *pIter = MQTT_PROP_AUTHENTICATION_DATA;
        pIter++;
        MOC_HTONS(pIter, pOptions->authDataLen);
        pIter += 2;
        status = MOC_MEMCPY((void *)pIter, (const void *)pOptions->pAuthData, pOptions->authDataLen);
        if (OK != status)
            goto exit;

        pIter += pOptions->authDataLen;
    }

    /* Process user defined properties */
    if (pOptions->propCount > 0)
    {
        if (NULL == pOptions->pProps)
        {
            status = ERR_INVALID_ARG;
            goto exit;
        }

        status = MQTT_writeUserProps(pIter, pOptions->pProps, pOptions->propCount, &offset);
        if (OK != status)
            goto exit;

        pIter += offset;
    }

    *ppIter = pIter;

exit:
    return status;
}

static MSTATUS MQTT_constructWillProps(ubyte *pIter, MqttConnectOptions *pOptions, ubyte4 willPropLen, ubyte **ppIter)
{
    MSTATUS status;
    ubyte4 i = 0;
    ubyte encoded[4];
    ubyte bytesUsed = 0;
    ubyte4 offset = 0;

    /* Encode length of the will properties as variable byte integer */
    status = MQTT_encodeVariableByteInt(willPropLen, encoded, &bytesUsed);
    if (OK != status)
        goto exit;

    for (i = 0; i < bytesUsed; i++)
    {
        *pIter = encoded[i];
        pIter++;
    }

    /* Construct Will properties in order as defined in MQTTv5 spec 3.1.3.2 */
    if (0 != pOptions->willInfo.willDelayInterval)
    {
        *pIter = MQTT_PROP_WILL_DELAY_INTERVAL;
        pIter++;
        MOC_HTONL(pIter, pOptions->willInfo.willDelayInterval);
        pIter += 4;
    }

    if (TRUE == pOptions->willInfo.setPayloadFormat)
    {
        *pIter = MQTT_PROP_PAYLOAD_FORMAT_INDICATOR;
        pIter++;
        *pIter = pOptions->willInfo.payloadFormat;
        pIter++;
    }

    if (0 != pOptions->willInfo.msgExpiryInterval)
    {
        *pIter = MQTT_PROP_MESSAGE_EXPIRY_INTERVAL;
        pIter++;
        MOC_HTONL(pIter, pOptions->willInfo.msgExpiryInterval);
        pIter += 4;
    }

    if (NULL != pOptions->willInfo.pContentType)
    {
        *pIter = MQTT_PROP_CONTENT_TYPE;
        pIter++;

        if (!isValidUtf8(pOptions->willInfo.pContentType, pOptions->willInfo.contentTypeLen))
        {
            status = ERR_MQTT_INVALID_UTF8;
            goto exit;
        }

        MOC_HTONS(pIter, pOptions->willInfo.contentTypeLen);
        pIter += 2;
        status = MOC_MEMCPY((void *)pIter, (const void *)pOptions->willInfo.pContentType, pOptions->willInfo.contentTypeLen);
        pIter += pOptions->willInfo.contentTypeLen;
    }

    if (NULL != pOptions->willInfo.pResponseTopic)
    {
        *pIter = MQTT_PROP_RESPONSE_TOPIC;
        pIter++;

        if (!isValidUtf8(pOptions->willInfo.pResponseTopic, pOptions->willInfo.responseTopicLen))
        {
            status = ERR_MQTT_INVALID_UTF8;
            goto exit;
        }

        MOC_HTONS(pIter, pOptions->willInfo.responseTopicLen);
        pIter += 2;
        status = MOC_MEMCPY((void *)pIter, (const void *)pOptions->willInfo.pResponseTopic, pOptions->willInfo.responseTopicLen);
        pIter += pOptions->willInfo.responseTopicLen;
    }

    if (pOptions->willInfo.correlationDataLen > 0)
    {
        *pIter = MQTT_PROP_CORRELATION_DATA;
        pIter++;
        MOC_HTONS(pIter, pOptions->willInfo.correlationDataLen);
        pIter += 2;
        status = MOC_MEMCPY((void *)pIter, pOptions->willInfo.pCorrelationData, pOptions->willInfo.correlationDataLen);
        pIter += pOptions->willInfo.correlationDataLen;
    }

    /* Process user defined will properties */
    if (pOptions->willInfo.propCount > 0)
    {
        if (NULL == pOptions->willInfo.pProps)
        {
            status = ERR_INVALID_ARG;
            goto exit;
        }

        status = MQTT_writeUserProps(pIter, pOptions->willInfo.pProps, pOptions->willInfo.propCount, &offset);
        if (OK != status)
            goto exit;

        pIter += offset;
    }

    *ppIter = pIter;

exit:
    return status;
}

MSTATUS MQTT_buildConnectMsg(MqttCtx *pCtx, MqttConnectOptions *pOptions, MqttMessage **ppMsg)
{
    MSTATUS status;
    ubyte4 i = 0;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    ubyte *pIter = NULL;
    ubyte4 connectLen = 0;
    ubyte4 propLen = 0;
    ubyte4 willPropLen = 0;
    ubyte encoded[4];
    ubyte bytesUsed = 0;
    ubyte flags = 0;
    MqttMessage *pNewMsg = NULL;

    status = MQTT_computeConnectLen(pCtx, pOptions, &connectLen, &propLen, &willPropLen);
    if (OK != status)
        goto exit;

    status = MQTT_encodeVariableByteInt(connectLen, encoded, &bytesUsed);
    if (OK != status)
        goto exit;

    /* Fixed Header byte + remaining len encoding + connect msg (variable header + payload) */
    msgLen = 1 + bytesUsed + connectLen;

    status = MOC_CALLOC((void **)&pMsg, msgLen, sizeof(ubyte));
    if (OK != status)
        goto exit;

    pIter = pMsg;
    *pIter = MQTT_CONNECT_TYPE_VAL;

    pIter++;
    for (i = 0; i < bytesUsed; i++)
    {
        *pIter = encoded[i];
        pIter++;
    }

    /* Connect variable header bytes 1-6 MQTTv5 spec 3.1.2.1 */
    *pIter = 0;   pIter++;
    *pIter = 4;   pIter++;
    *pIter = 'M'; pIter++;
    *pIter = 'Q'; pIter++;
    *pIter = 'T'; pIter++;
    *pIter = 'T'; pIter++;

    /* Support v5 and v3.1.1 */
    *pIter = pCtx->version;   pIter++;

    status = MQTT_buildConnectFlags(pOptions, &flags);
    if (OK != status)
        goto exit;

    *pIter = flags;
    pIter++;

    /* Keep alive interval, 2 bytes MQTTv5 spec 3.1.2.10 */
    *pIter = (pOptions->keepAliveInterval & 0xFF00) >> 8;  pIter++;
    *pIter = (pOptions->keepAliveInterval & 0x00FF);       pIter++;

    /* Construct the properties to be sent in CONNECT message */
    if (MQTT_V5 <= pCtx->version)
    {
        status = MQTT_constructConnectProps(pIter, pOptions, propLen, &pIter);
        pCtx->topicAliasMax = pOptions->topicAliasMax;
        if (OK != status)
            goto exit;
    }

    /* Construct payload consisting of:
     * Client ID || Will props || Will topic || Will payload || Username || Password
     * As defined in MQTTv5 spec 3.1.3 */

    /* Client ID */
    MOC_HTONS(pIter, (ubyte4)pCtx->clientIdLen);
    pIter += 2;
    status = MOC_MEMCPY((void *)pIter, (const void *)pCtx->pClientId, pCtx->clientIdLen);
    pIter += pCtx->clientIdLen;

    /* Will properties if applicable */
    if (willPropLen > 0)
    {
        status = MQTT_constructWillProps(pIter, pOptions, willPropLen, &pIter);
        if (OK != status)
            goto exit;
    }
    else
    {
        /* If we have a will but no will properties, write a length of zero for the will properties */
        if (MQTT_V5 <= pCtx->version && NULL != pOptions->willInfo.pWill)
        {
            *pIter = 0;
            pIter++;
        }
    }

    /* Will topic */
    if (NULL != pOptions->willInfo.pWillTopic)
    {
        if (!isValidUtf8(pOptions->willInfo.pWillTopic, pOptions->willInfo.willTopicLen))
        {
            status = ERR_MQTT_INVALID_UTF8;
            goto exit;
        }

        MOC_HTONS(pIter, pOptions->willInfo.willTopicLen);
        pIter += 2;
        status = MOC_MEMCPY((void *)pIter, (const void *)pOptions->willInfo.pWillTopic, pOptions->willInfo.willTopicLen);
        pIter += pOptions->willInfo.willTopicLen;
    }

    /* Will Payload */
    if (NULL != pOptions->willInfo.pWill)
    {
        MOC_HTONS(pIter, pOptions->willInfo.willLen);
        pIter += 2;
        status = MOC_MEMCPY((void *)pIter, pOptions->willInfo.pWill, pOptions->willInfo.willLen);
        pIter += pOptions->willInfo.willLen;
    }

    /* Username */
    if (NULL != pOptions->pUsername)
    {
        if (!isValidUtf8(pOptions->pUsername, pOptions->usernameLen))
        {
            status = ERR_MQTT_INVALID_UTF8;
            goto exit;
        }

        MOC_HTONS(pIter, pOptions->usernameLen);
        pIter += 2;
        status = MOC_MEMCPY((void *)pIter, pOptions->pUsername, pOptions->usernameLen);
        pIter += pOptions->usernameLen;
    }

    /* Password */
    if (NULL != pOptions->pPassword)
    {
        MOC_HTONS(pIter, pOptions->passwordLen);
        pIter += 2;
        status = MOC_MEMCPY((void *)pIter, pOptions->pPassword, pOptions->passwordLen);
        pIter += pOptions->passwordLen;
    }

    status = MOC_CALLOC((void **)&pNewMsg, 1, sizeof(MqttMessage));
    if (OK != status)
        goto exit;

    pNewMsg->type = MQTT_CONNECT;
    pNewMsg->pData = pMsg;
    pNewMsg->dataLen = msgLen;
    pMsg = NULL;
    *ppMsg = pNewMsg;
    pNewMsg = NULL;

    /* Set keep alive */
    pCtx->keepAliveMS = 1000 * pOptions->keepAliveInterval;

exit:

    if (NULL != pMsg)
    {
        MOC_FREE((void **)&pMsg);
    }

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_buildConnectMsg() returns status = ", status);
    }
#endif

    return status;
}

static MSTATUS MQTT_computeSubscribeLen(
    MqttCtx *pCtx,
    MqttSubscribeTopic *pTopics,
    ubyte4 topicCount,
    MqttSubscribeOptions *pOptions,
    ubyte4 *pSubscribeLen,
    ubyte4 *pPropLen)
{
    MSTATUS status = OK;
    ubyte4 i;
    ubyte4 len;
    ubyte4 propLen = 0;
    ubyte bytesUsed = 0;
    MqttSubscribeTopic *pCurTopic;
    MqttProperty *pCurProp;

    /* 2 bytes for packet identifier */
    len = 2;

    /* properties */
    if (MQTT_V5 <= pCtx->version)
    {
        if (NULL != pOptions)
        {
            /* subscription identifier */
            if (0 != pOptions->subId)
            {
                if (MAX_SUBSCRIPTION_ID < pOptions->subId)
                {
                    status = ERR_MQTT_INVALID_SUB_ID;
                    goto exit;
                }

                status = MQTT_encodeVariableByteInt(
                    pOptions->subId, NULL, &bytesUsed);
                if (OK != status)
                    goto exit;

                propLen += 1 + bytesUsed;
            }

            /* user properties */
            for (i = 0; i < pOptions->propCount; i++)
            {
                pCurProp = &pOptions->pProps[i];

                propLen += 1 + 2 + pCurProp->data.pair.name.dataLen +
                            2 + pCurProp->data.pair.value.dataLen;
            }
        }

        len += propLen;

        status = MQTT_encodeVariableByteInt(propLen, NULL, &bytesUsed);
        if (OK != status)
            goto exit;

        len += bytesUsed;
    }

    *pPropLen = propLen;

    /* payload - topics */
    for (i = 0; i < topicCount; i++)
    {
        pCurTopic = pTopics + i;

        if ( (NULL == pCurTopic->pTopic) || (0 == pCurTopic->topicLen) )
        {
            status = ERR_MQTT_NO_TOPIC_PROVIDED;
            goto exit;
        }

        len += 2 + pCurTopic->topicLen + 1;
    }

    *pSubscribeLen = len;

exit:

    return status;
}

MSTATUS MQTT_buildSubscribeMsg(
    MqttCtx *pCtx,
    MqttSubscribeTopic *pTopics,
    ubyte4 topicCount,
    MqttSubscribeOptions *pOptions,
    ubyte2 *pPacketId,
    MqttMessage **ppMsg)
{
    MSTATUS status;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    ubyte *pIter = NULL;
    ubyte4 subscribeLen;
    ubyte4 propLen;
    ubyte4 len;
    ubyte bytesUsed;
    ubyte4 i;
    MqttSubscribeTopic *pCurTopic;
    MqttMessage *pNewMsg = NULL;
    ubyte2 pktId;

    status = MQTT_computeSubscribeLen(
        pCtx, pTopics, topicCount, pOptions, &subscribeLen, &propLen);
    if (OK != status)
        goto exit;

    status = MQTT_encodeVariableByteInt(subscribeLen, NULL, &bytesUsed);
    if (OK != status)
        goto exit;

    /* Fixed Header byte + remaining len encoding + subscribe msg (variable header + payload) */
    msgLen = 1 + bytesUsed + subscribeLen;

    status = MOC_CALLOC((void **)&pMsg, msgLen, sizeof(ubyte));
    if (OK != status)
        goto exit;

    /* Control Packet Type */
    pIter = pMsg;
    *pIter++ = MQTT_SUBSCRIBE_TYPE_VAL;

    /* Variable Byte Integer */
    status = MQTT_encodeVariableByteInt(subscribeLen, pIter, &bytesUsed);
    if (OK != status)
        goto exit;

    pIter += bytesUsed;

    /* Packet Identifier */
    status = MQTT_getPacketId(pCtx, &pktId);
    if (OK != status)
        goto exit;
    
    if (NULL != pPacketId)
        *pPacketId = pktId;

    MOC_HTONS(pIter, pktId);
    pIter += 2;

    if (MQTT_V5 <= pCtx->version)
    {
        /* Properties Length */
        status = MQTT_encodeVariableByteInt(propLen, pIter, &bytesUsed);
        if (OK != status)
            goto exit;

        pIter += bytesUsed;

        /* Properties */
        if (NULL != pOptions)
        {
            /* subscription identifier */
            if (0 != pOptions->subId)
            {
                *pIter++ = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
                status = MQTT_encodeVariableByteInt(
                    pOptions->subId, pIter, &bytesUsed);
                if (OK != status)
                {
                    goto exit;
                }
                pIter += bytesUsed;
            }

            if (0 < pOptions->propCount)
            {
                if (NULL == pOptions->pProps)
                {
                    status = ERR_NULL_POINTER;
                    goto exit;
                }

                status = MQTT_writeUserProps(
                    pIter, pOptions->pProps, pOptions->propCount, &len);
                if (OK != status)
                {
                    goto exit;
                }
                pIter += len;
            }
        }
    }

    /* Payload */
    for (i = 0; i < topicCount; i++)
    {
        pCurTopic = pTopics + i;

        if (!isValidUtf8(pCurTopic->pTopic, pCurTopic->topicLen))
        {
            status = ERR_MQTT_INVALID_UTF8;
            goto exit;
        }

        MOC_HTONS(pIter, pCurTopic->topicLen);
        pIter += 2;

        MOC_MEMCPY(pIter, pCurTopic->pTopic, pCurTopic->topicLen);
        pIter += pCurTopic->topicLen;

        *pIter = 0x00;
        *pIter |= pCurTopic->qos;
        if (TRUE == pCurTopic->noLocalOption)
            *pIter |= 0x04;
        if (TRUE == pCurTopic->retainAsPublished)
            *pIter |= 0x08;
        *pIter |= (pCurTopic->retainHandling << 4);
        pIter++;
    }

    status = MOC_CALLOC((void **)&pNewMsg, 1, sizeof(MqttMessage));
    if (OK != status)
        goto exit;

    pNewMsg->type = MQTT_SUBSCRIBE;
    pNewMsg->pData = pMsg;
    pNewMsg->dataLen = msgLen;
    pMsg = NULL;
    *ppMsg = pNewMsg;
    pNewMsg = NULL;

exit:

    if (NULL != pMsg)
    {
        MOC_FREE((void **)&pMsg);
    }

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_buildSubscribeMsg() returns status = ", status);
    }
#endif

    return status;
}

MSTATUS MQTT_buildUnsubscribeMsg(
    MqttCtx *pCtx,
    MqttUnsubscribeTopic *pTopics,
    ubyte4 topicCount,
    MqttUnsubscribeOptions *pOptions,
    ubyte2 *pPacketId,
    MqttMessage **ppMsg)
{
    MSTATUS status;
    ubyte4 msgLen = 0;
    ubyte4 propLen = 0;
    ubyte4 i, temp;
    ubyte len;
    MqttUnsubscribeTopic *pCurTopic;
    MqttProperty *pCurProp;
    ubyte *pMsg = NULL, *pIter;
    MqttMessage *pNewMsg = NULL;
    ubyte2 pktId;

    /* byte 1 - 10000010 */
    msgLen++;

    /* byte 1-4 - length calculate later */

    /* byte 2 - packet identifier */
    msgLen += 2;

    /* byte 1-4 - prop length */

    if (MQTT_V5 <= pCtx->version)
    {
        /* properties */
        if (NULL != pOptions)
        {
            /* user properties */
            for (i = 0; i < pOptions->propCount; i++)
            {
                pCurProp = &pOptions->pProps[i];

                propLen += 1 + 2 + pCurProp->data.pair.name.dataLen +
                            2 + pCurProp->data.pair.value.dataLen;
            }

            msgLen += propLen;
        }

        status = MQTT_encodeVariableByteInt(propLen, NULL, &len);
        if (OK != status)
            goto exit;

        msgLen += len;
    }

    /* 2 byte - topic length */
    /* topic */
    /* 1 byte - topic options */
    for (i = 0; i < topicCount; i++)
    {
        msgLen += 2 + pTopics[i].topicLen;
    }

    status = MQTT_encodeVariableByteInt(msgLen - 1, NULL, &len);
    if (OK != status)
        goto exit;

    msgLen += len;

    status = MOC_MALLOC((void **) &pMsg, msgLen);
    if (OK != status)
        goto exit;

    pIter = pMsg;

    *pIter++ = MQTT_UNSUBSCRIBE_TYPE_VAL;

    status = MQTT_encodeVariableByteInt(msgLen - 1 - len, pIter, &len);
    if (OK != status)
    {
        goto exit;
    }
    pIter += len;

    /* packet ID */
    status = MQTT_getPacketId(pCtx, &pktId);
    if (OK != status)
        goto exit;

    if (NULL != pPacketId)
        *pPacketId = pktId;

    MOC_HTONS(pIter, pktId);
    pIter += 2;

    if (MQTT_V5 <= pCtx->version)
    {
        status = MQTT_encodeVariableByteInt(propLen, pIter, &len);
        if (OK != status)
        {
            goto exit;
        }
        pIter += len;

        /* properties */
        if (NULL != pOptions)
        {
            if (0 < pOptions->propCount)
            {
                if (NULL == pOptions->pProps)
                {
                    status = ERR_NULL_POINTER;
                    goto exit;
                }

                status = MQTT_writeUserProps(
                    pIter, pOptions->pProps, pOptions->propCount, &temp);
                if (OK != status)
                {
                    goto exit;
                }
                pIter += temp;
            }
        }
    }

    for (i = 0; i < topicCount; i++)
    {
        pCurTopic = pTopics + i;

        if (!isValidUtf8(pCurTopic->pTopic, pCurTopic->topicLen))
        {
            status = ERR_MQTT_INVALID_UTF8;
            goto exit;
        }

        MOC_HTONS(pIter, pCurTopic->topicLen);
        pIter += 2;

        MOC_MEMCPY(pIter, pCurTopic->pTopic, pCurTopic->topicLen);
        pIter += pCurTopic->topicLen;
    }

    status = MOC_CALLOC((void **)&pNewMsg, 1, sizeof(MqttMessage));
    if (OK != status)
        goto exit;

    pNewMsg->type = MQTT_UNSUBSCRIBE;
    pNewMsg->pData = pMsg;
    pNewMsg->dataLen = msgLen;
    pMsg = NULL;
    *ppMsg = pNewMsg;
    pNewMsg = NULL;

exit:

    if (NULL != pMsg)
    {
        MOC_FREE((void **)&pMsg);
    }

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_buildUnsubscribeMsg() returns status = ", status);
    }
#endif

    return status;
}


static MSTATUS MQTT_computePublishLen(
    MqttCtx *pCtx,
    MqttPublishOptions *pOptions,
    ubyte *pTopic,
    ubyte4 topicLen,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte4 *pTotalLen,
    ubyte4 *pPropLen)
{
    MSTATUS status = OK;
    ubyte4 msgLen = 0;
    ubyte4 propLen = 0;
    ubyte len = 0;
    ubyte4 i;
    MqttProperty *pCurProp;

    /* topic */
    msgLen += 2 + topicLen;

    /* packet identifier */
    if (NULL != pOptions && 0 != pOptions->qos)
    {
        msgLen += 2;
    }

    if (MQTT_V5 <= pCtx->version)
    {
        if (NULL != pOptions)
        {
            if (TRUE == pOptions->setPayloadFormat)
            {
                propLen += 1 + 1;
            }

            if (0 != pOptions->msgExpiryInterval)
            {
                propLen += 1 + 4;
            }

            if (0 != pOptions->topicAlias)
            {
                propLen += 1 + 2;
            }

            if (NULL != pOptions->pResponseTopic)
            {
                propLen += 1 + 2 + pOptions->responseTopicLen;
            }

            if (NULL != pOptions->pCorrelationData)
            {
                propLen += 1 + 2 + pOptions->correlationDataLen;
            }

            /* user properties */
            for (i = 0; i < pOptions->propCount; i++)
            {
                pCurProp = &pOptions->pProps[i];

                propLen += 1 + 2 + pCurProp->data.pair.name.dataLen +
                            2 + pCurProp->data.pair.value.dataLen;
            }

            /* subscription identifier */
            if (0 != pOptions->subId)
            {
                if (MAX_SUBSCRIPTION_ID < pOptions->subId)
                {
                    status = ERR_MQTT_INVALID_SUB_ID;
                    goto exit;
                }

                status = MQTT_encodeVariableByteInt(pOptions->subId, NULL, &len);
                if (OK != status)
                    goto exit;

                propLen += 1 + len;
            }

            if (NULL != pOptions->pContentType)
            {
                /* id byte + 2 len bytes + data */
                propLen += 1 + 2 + pOptions->contentTypeLen;
            }

        }

        msgLen += propLen;

        status = MQTT_encodeVariableByteInt(propLen, NULL, &len);
        if (OK != status)
            goto exit;

        msgLen += len;

    }

    msgLen += dataLen;

    *pPropLen = propLen;
    *pTotalLen = msgLen;

exit:

    return status;
}

MSTATUS MQTT_buildPublishMsg(
    MqttCtx *pCtx,
    MqttPublishOptions *pOptions,
    ubyte *pTopic,
    ubyte4 topicLen,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte2 *pPacketId,
    MqttMessage **ppMsg)
{
    MSTATUS status;
    ubyte4 msgLen = 0;
    ubyte4 propLen = 0;
    ubyte4 temp;
    ubyte len;
    ubyte *pMsg = NULL;
    ubyte *pIter;
    MqttMessage *pNewMsg = NULL;
    ubyte bytesUsed;
    ubyte4 publishLen;
    ubyte2 pktId;

    if ( (NULL == pCtx) || (NULL == pTopic) || (NULL == ppMsg) ||
        (NULL == pData && NULL != pOptions && FALSE == pOptions->retain))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = MQTT_computePublishLen(
        pCtx, pOptions, pTopic, topicLen, pData, dataLen,
        &publishLen, &propLen);
    if (OK != status)
        goto exit;

    status = MQTT_encodeVariableByteInt(publishLen, NULL, &bytesUsed);
    if (OK != status)
        goto exit;

    /* Fixed Header byte + remaining len encoding + publish msg (variable header + payload) */
    msgLen = 1 + bytesUsed + publishLen;

    status = MOC_CALLOC((void **)&pMsg, msgLen, sizeof(ubyte));
    if (OK != status)
        goto exit;

    pIter = pMsg;

    /* 1 byte for header */
    *pIter = MQTT_PUBLISH_TYPE_VAL;
    if (NULL != pOptions)
    {
        *pIter |= pOptions->retain;
        *pIter |= (pOptions->qos << 1);
        *pIter |= (pOptions->dup << 3);
    }
    pIter++;

    /* remaining length encoded as variable byte integer */
    status = MQTT_encodeVariableByteInt(publishLen, pIter, &len);
    if (OK != status)
    {
        goto exit;
    }
    pIter += len;

    if (!isValidUtf8(pTopic, topicLen))
    {
        status = ERR_MQTT_INVALID_UTF8;
        goto exit;
    }

    /* topic length */
    MOC_HTONS(pIter, topicLen);
    pIter += 2;

    /* topic */
    MOC_MEMCPY(pIter, pTopic, topicLen);
    pIter += topicLen;

    if ( (NULL != pOptions) && (0 != pOptions->qos) )
    {
        /* packet ID */
        status = MQTT_getPacketId(pCtx, &pktId);
        if (OK != status)
            goto exit;

        MOC_HTONS(pIter, pktId);
        pIter += 2;

        if (NULL != pPacketId)
            *pPacketId = pktId;
    }

    if (MQTT_V5 <= pCtx->version)
    {
        status = MQTT_encodeVariableByteInt(propLen, pIter, &len);
        if (OK != status)
        {
            goto exit;
        }
        pIter += len;

        /* properties */
        if (NULL != pOptions)
        {
            if (TRUE == pOptions->setPayloadFormat)
            {
                *pIter++ = MQTT_PROP_PAYLOAD_FORMAT_INDICATOR;
                *pIter++ = pOptions->payloadFormat;
            }

            if (0 != pOptions->msgExpiryInterval)
            {
                *pIter++ = MQTT_PROP_MESSAGE_EXPIRY_INTERVAL;
                MOC_HTONL(pIter, pOptions->msgExpiryInterval);
                pIter += 4;
            }

            if (0 != pOptions->topicAlias)
            {
                *pIter++ = MQTT_PROP_TOPIC_ALIAS;
                MOC_HTONS(pIter, pOptions->topicAlias);
                pIter += 2;
            }

            if (NULL != pOptions->pResponseTopic)
            {
                if (!isValidUtf8(pOptions->pResponseTopic, pOptions->responseTopicLen))
                {
                    status = ERR_MQTT_INVALID_UTF8;
                    goto exit;
                }

                *pIter++ = MQTT_PROP_RESPONSE_TOPIC;
                MOC_HTONS(pIter, pOptions->responseTopicLen);
                pIter += 2;
                MOC_MEMCPY(pIter, pOptions->pResponseTopic, pOptions->responseTopicLen);
                pIter += pOptions->responseTopicLen;
            }

            if (NULL != pOptions->pCorrelationData)
            {
                *pIter++ = MQTT_PROP_CORRELATION_DATA;
                MOC_HTONS(pIter, pOptions->correlationDataLen);
                pIter += 2;
                MOC_MEMCPY(pIter, pOptions->pCorrelationData, pOptions->correlationDataLen);
                pIter += pOptions->correlationDataLen;
            }

            status = MQTT_writeUserProps(
                pIter, pOptions->pProps, pOptions->propCount, &temp);
            if (OK != status)
            {
                goto exit;
            }
            pIter += temp;

            /* subscription identifier */
            if (0 != pOptions->subId)
            {
                *pIter++ = MQTT_PROP_SUBSCRIPTION_IDENTIFIER;
                status = MQTT_encodeVariableByteInt(pOptions->subId, pIter, &len);
                if (OK != status)
                {
                    goto exit;
                }
                pIter += len;
            }

            if (NULL != pOptions->pContentType)
            {
                if (!isValidUtf8(pOptions->pContentType, pOptions->contentTypeLen))
                {
                    status = ERR_MQTT_INVALID_UTF8;
                    goto exit;
                }

                *pIter++ = MQTT_PROP_CONTENT_TYPE;
                MOC_HTONS(pIter, pOptions->contentTypeLen);
                pIter += 2;
                MOC_MEMCPY(pIter, pOptions->pContentType, pOptions->contentTypeLen);
                pIter += pOptions->contentTypeLen;
            }
        }
    }

    MOC_MEMCPY(pIter, pData, dataLen);
    pIter += dataLen;

    status = MOC_CALLOC((void **)&pNewMsg, 1, sizeof(MqttMessage));
    if (OK != status)
        goto exit;

    pNewMsg->type = MQTT_PUBLISH;
    pNewMsg->pData = pMsg;
    pNewMsg->dataLen = msgLen;
    pMsg = NULL;
    *ppMsg = pNewMsg;
    pNewMsg = NULL;

exit:

    if (NULL != pMsg)
    {
        MOC_FREE((void **)&pMsg);
    }

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_buildPublishMsg() returns status = ", status);
    }
#endif

    return status;
}

MSTATUS MQTT_buildAuthMsg(MqttCtx *pCtx, MqttAuthOptions *pOptions, MqttMessage **ppMsg)
{
    MSTATUS status;
    ubyte4 remLen = 0;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    ubyte4 propLen = 0;
    ubyte *pIter = NULL;
    ubyte4 offset = 0;
    ubyte bytesUsed = 0;
    ubyte propBytesUsed = 0;
    ubyte4 i = 0;
    MqttMessage *pNewMsg = NULL;
    ubyte encodedPropLen[4];
    ubyte encodedLen[4];

    if ( (NULL == pOptions) || (NULL == pOptions->pAuthMethod) || (NULL == pOptions->pAuthData) )
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (!isValidUtf8(pOptions->pAuthMethod, pOptions->authMethodLen))
    {
        status = ERR_MQTT_INVALID_UTF8;
        goto exit;
    }

    /* Compute the length of the auth packet to be constructed */
    propLen = 1 + 2 + pOptions->authMethodLen;
    propLen += 1 + 2 + pOptions->authDataLen;

    if ( (pOptions->propCount > 0) && (NULL == pOptions->pProps) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Compute length of user input properties */
    for (i = 0; i < pOptions->propCount; i++)
    {
        propLen += 1 + 2 + ((pOptions->pProps[i]).data.pair.name.dataLen) +
                       2 + ((pOptions->pProps[i]).data.pair.value.dataLen);
    }

    status = MQTT_encodeVariableByteInt(propLen, encodedPropLen, &propBytesUsed);
    if (OK != status)
        goto exit;

    remLen = 1 + propLen + propBytesUsed;

    status = MQTT_encodeVariableByteInt(remLen, encodedLen, &bytesUsed);
    if (OK != status)
        goto exit;

    msgLen = 1 + bytesUsed + remLen;

    /* Length computed, alloc space for the packet and begin construction */
    status = MOC_CALLOC((void **)&pMsg, msgLen, 1);
    if (OK != status)
        goto exit;

    pIter = pMsg;

    *pIter = MQTT_AUTH_TYPE_VAL;
    pIter++;

    /* Message length encoded as variable byte integer */
    for (i = 0; i < bytesUsed; i++)
    {
        *pIter = encodedLen[i];
        pIter++;
    }

    /* Auth reason code */
    if (TRUE == pOptions->reAuthenticate)
    {
        *pIter = MQTT_AUTH_REAUTH;
    }
    else
    {
        *pIter = MQTT_AUTH_CONTINUE;
    }
    pIter++;

    for (i = 0; i < propBytesUsed; i++)
    {
        *pIter = encodedPropLen[i];
        pIter++;
    }


    *pIter = MQTT_PROP_AUTHENTICATION_METHOD;
    pIter++;
    MOC_HTONS(pIter, pOptions->authMethodLen);
    pIter += 2;
    status = MOC_MEMCPY((void *)pIter, pOptions->pAuthMethod, pOptions->authMethodLen);
    if (OK != status)
        goto exit;

    pIter += pOptions->authMethodLen;

    *pIter = MQTT_PROP_AUTHENTICATION_DATA;
    pIter++;
    MOC_HTONS(pIter, pOptions->authDataLen);
    pIter += 2;

    status = MOC_MEMCPY((void *)pIter, pOptions->pAuthData, pOptions->authDataLen);
    if (OK != status)
        goto exit;

    pIter += pOptions->authDataLen;

    status = MQTT_writeUserProps(pIter, pOptions->pProps, pOptions->propCount, &offset);
    if (OK != status)
        goto exit;

    status = MOC_CALLOC((void **)&pNewMsg, 1, sizeof(MqttMessage));
    if (OK != status)
        goto exit;

    pNewMsg->type = MQTT_AUTH;
    pNewMsg->pData = pMsg;
    pNewMsg->dataLen = msgLen;
    pMsg = NULL;
    *ppMsg = pNewMsg;
    pNewMsg = NULL;

exit:

    if (NULL != pMsg)
    {
        MOC_FREE((void **)&pMsg);
    }

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_buildAuthMsg() returns status = ", status);
    }
#endif

    return status;
}

MSTATUS MQTT_buildPingReqMsg(
    MqttCtx *pCtx,
    MqttMessage **ppMsg)
{
    MSTATUS status;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    MqttMessage *pNewMsg = NULL;

    status = MOC_MALLOC((void **) &pMsg, 2);
    if (OK != status)
        goto exit;

    pMsg[0] = MQTT_PING_TYPE_VAL;
    pMsg[1] = 0x00;
    msgLen = 2;

    status = MOC_CALLOC((void **)&pNewMsg, 1, sizeof(MqttMessage));
    if (OK != status)
        goto exit;

    pNewMsg->type = MQTT_PINGREQ;
    pNewMsg->pData = pMsg;
    pNewMsg->dataLen = msgLen;
    pMsg = NULL;
    *ppMsg = pNewMsg;
    pNewMsg = NULL;

exit:

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_buildPingReqMsg() returns status = ", status);
    }
#endif

    return status;
}


MSTATUS MQTT_buildDisconnectMsg(MqttCtx *pCtx, MqttDisconnectOptions *pOptions, MqttMessage **ppMsg)
{
    MSTATUS status;
    ubyte4 remLen = 0;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    ubyte4 propLen = 0;
    ubyte *pIter = NULL;
    ubyte4 offset = 0;
    ubyte bytesUsed = 0;
    ubyte propBytesUsed = 0;
    ubyte4 i = 0;
    MqttMessage *pNewMsg = NULL;
    ubyte encodedPropLen[4];
    ubyte encodedLen[4];

    if (MQTT_V5 <= pCtx->version)
    {
        if (NULL == pOptions)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        /* MQTTv5 spec 3.14.2.2.2 If the Session Expiry Interval in the CONNECT packet was zero,
         * then it is a Protocol Error to set a non-zero Session Expiry Interval in the DISCONNECT
         * packet sent by the Client */
        if ((pCtx->sessionExpiryInterval == 0) && (0 != pOptions->sessionExpiryInterval))
        {
            status = ERR_MQTT_DISCONN_SESSION_EXPIRY_MISMATCH;
            goto exit;
        }

        /* Compute the length of the disconnect packet to be constructed */
        if (NULL != pOptions->pReasonStr)
        {
            propLen = 1 + 2 + pOptions->reasonStrLen;
        }

        if (TRUE == pOptions->sendSessionExpiry)
        {
            propLen += 1 + 4;
        }

        if ((pOptions->propCount > 0) && (NULL == pOptions->pProps))
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        /* Compute length of user input properties */
        for (i = 0; i < pOptions->propCount; i++)
        {
            propLen += 1 + 2 + ((pOptions->pProps[i]).data.pair.name.dataLen) +
                    2 + ((pOptions->pProps[i]).data.pair.value.dataLen);
        }

        status = MQTT_encodeVariableByteInt(propLen, encodedPropLen, &propBytesUsed);
        if (OK != status)
            goto exit;

        remLen = 1 + propLen + propBytesUsed;
    }

    status = MQTT_encodeVariableByteInt(remLen, encodedLen, &bytesUsed);
    if (OK != status)
        goto exit;

    msgLen = 1 + bytesUsed + remLen;

    /* Length computed, alloc space for the packet and begin construction */
    status = MOC_CALLOC((void **)&pMsg, msgLen, 1);
    if (OK != status)
        goto exit;

    pIter = pMsg;

    *pIter = MQTT_DISCONNECT_TYPE_VAL;
    pIter++;

    if (MQTT_V5 <= pCtx->version)
    {
        /* Message length encoded as variable byte integer */
        for (i = 0; i < bytesUsed; i++)
        {
            *pIter = encodedLen[i];
            pIter++;
        }

        /* Disconnect reason code */
        *pIter = pOptions->reasonCode;
        pIter++;

        /* Property length */
        for (i = 0; i < propBytesUsed; i++)
        {
            *pIter = encodedPropLen[i];
            pIter++;
        }

        if (TRUE == pOptions->sendSessionExpiry)
        {
            *pIter = MQTT_PROP_SESSION_EXPIRY_INTERVAL;
            pIter++;
            MOC_HTONL(pIter, pOptions->sessionExpiryInterval);
            pIter += 4;
        }

        if (NULL != pOptions->pReasonStr)
        {
            if (!isValidUtf8(pOptions->pReasonStr, pOptions->reasonStrLen))
            {
                status = ERR_MQTT_INVALID_UTF8;
                goto exit;
            }

            MOC_HTONS(pIter, pOptions->reasonStrLen);
            pIter += 2;
            status = MOC_MEMCPY((void *)pIter, pOptions->pReasonStr, pOptions->reasonStrLen);
            if (OK != status)
                goto exit;

            pIter += pOptions->reasonStrLen;
        }

        status = MQTT_writeUserProps(pIter, pOptions->pProps, pOptions->propCount, &offset);
        if (OK != status)
            goto exit;
    }
    else
    {
        *pIter = 0x00;
        pIter++;
    }

    status = MOC_CALLOC((void **)&pNewMsg, 1, sizeof(MqttMessage));
    if (OK != status)
        goto exit;

    pNewMsg->type = MQTT_DISCONNECT;
    pNewMsg->pData = pMsg;
    pNewMsg->dataLen = msgLen;
    pMsg = NULL;
    *ppMsg = pNewMsg;
    pNewMsg = NULL;

exit:

    if (NULL != pMsg)
    {
        MOC_FREE((void **)&pMsg);
    }

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_buildDisconnectMsg() returns status = ", status);
    }
#endif

    return status;
}

MSTATUS MQTT_buildPubRespMsg(MqttCtx *pCtx, MqttPubRespOptions *pOptions, MqttMessage **ppMsg)
{
    MSTATUS status;
    ubyte4 remLen = 0;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    ubyte4 propLen = 0;
    ubyte *pIter = NULL;
    ubyte4 offset = 0;
    ubyte bytesUsed = 0;
    ubyte propBytesUsed = 0;
    ubyte4 i = 0;
    byteBoolean shortForm = FALSE;
    byteBoolean pubRel = FALSE;
    MqttMessage *pNewMsg = NULL;
    ubyte encodedPropLen[4];
    ubyte encodedLen[4];

    if (NULL == pOptions)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    switch(pOptions->packetType)
    {
        case MQTT_PUBREL:
            pubRel = TRUE;

        case MQTT_PUBACK:
        case MQTT_PUBREC:
        case MQTT_PUBCOMP:
            break;

        default:
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
    }

    /* Compute the length of the packet to be constructed */
    if (NULL != pOptions->pReasonStr)
    {
        propLen = 1 + 2 + pOptions->reasonStrLen;
    }

    if ((pOptions->propCount > 0) && (NULL == pOptions->pProps))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Compute length of user input properties */
    for (i = 0; i < pOptions->propCount; i++)
    {
        propLen += 1 + 2 + ((pOptions->pProps[i]).data.pair.name.dataLen) +
                   2 + ((pOptions->pProps[i]).data.pair.value.dataLen);
    }

    status = MQTT_encodeVariableByteInt(propLen, encodedPropLen, &propBytesUsed);
    if (OK != status)
        goto exit;
    
    /* Packet ID || Reason code || Properties */
    remLen = 2 + 1 + propLen + propBytesUsed;

    if (0 == pOptions->reasonCode && 0 == propLen)
    {
        shortForm = TRUE;
        remLen = 2;
    }

    status = MQTT_encodeVariableByteInt(remLen, encodedLen, &bytesUsed);
    if (OK != status)
        goto exit;

    msgLen = 1 + bytesUsed + remLen;

    if (TRUE == shortForm)
    {
        msgLen = 4;
    }

    /* Length computed, alloc space for the packet and begin construction */
    status = MOC_CALLOC((void **)&pMsg, msgLen, 1);
    if (OK != status)
        goto exit;

    pIter = pMsg;

    if (TRUE == pubRel)
    {
        *pIter = (pOptions->packetType << 4) | 0x02;
    }
    else
    {
        *pIter = (pOptions->packetType << 4);
    }
    
    pIter++;

    /* Message length encoded as variable byte integer */
    for (i = 0; i < bytesUsed; i++)
    {
        *pIter = encodedLen[i];
        pIter++;
    }

    MOC_HTONS(pIter, pOptions->packetId);
    pIter += 2;

    if (TRUE == shortForm)
    {
        goto finish_construction;
    }

    /* Reason code */
    *pIter = pOptions->reasonCode;

    /* Property length */
    for (i = 0; i < propBytesUsed; i++)
    {
        *pIter = encodedPropLen[i];
        pIter++;
    }

    if (NULL != pOptions->pReasonStr)
    {
        if (!isValidUtf8(pOptions->pReasonStr, pOptions->reasonStrLen))
        {
            status = ERR_MQTT_INVALID_UTF8;
            goto exit;
        }

        MOC_HTONS(pIter, pOptions->reasonStrLen);
        pIter += 2;
        status = MOC_MEMCPY((void *)pIter, pOptions->pReasonStr, pOptions->reasonStrLen);
        if (OK != status)
            goto exit;
    }

    status = MQTT_writeUserProps(pIter, pOptions->pProps, pOptions->propCount, &offset);
    if (OK != status)
        goto exit;

finish_construction:

    status = MOC_CALLOC((void **)&pNewMsg, 1, sizeof(MqttMessage));
    if (OK != status)
        goto exit;

    pNewMsg->type = pOptions->packetType;
    pNewMsg->pData = pMsg;
    pNewMsg->dataLen = msgLen;
    pMsg = NULL;
    *ppMsg = pNewMsg;
    pNewMsg = NULL;

exit:

    if (NULL != pMsg)
    {
        MOC_FREE((void **)&pMsg);
    }

#if defined(__ENABLE_MOCANA_DEBUG_CONSOLE__)
    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_MQTT_TRANSPORT, (sbyte*)"MQTT_buildPubRespMsg() returns status = ", status);
    }
#endif

    return status;
}

extern MSTATUS MQTT_freeMsg(
    MqttMessage **ppMsg)
{
    MSTATUS status = OK, fstatus;

    if ( (NULL != ppMsg) && (NULL != *ppMsg) )
    {
        if (NULL != (*ppMsg)->pData)
        {
            status = MOC_FREE((void **) &((*ppMsg)->pData));
        }

        fstatus = MOC_FREE((void **) ppMsg);
        if (OK == status)
            status = fstatus;
    }

    return status;
}

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)

extern MSTATUS MQTT_freeMsgNode(
    MqttMessageList **ppMsgList)
{
    MSTATUS status = OK, fstatus;

    if ( (NULL != ppMsgList) && (NULL != *ppMsgList) )
    {
        if (NULL != (*ppMsgList)->pMsg)
        {
            status = MQTT_freeMsg(&((*ppMsgList)->pMsg));
        }

        fstatus = MOC_FREE((void **) ppMsgList);
        if (OK == status)
            status = fstatus;
    }

    return status;
}

extern MSTATUS MQTT_freeMsgList(
    MqttMessageList **ppMsgList)
{
    MSTATUS status = OK, fstatus;
    MqttMessageList *pNode = NULL, *pNext;

    if (NULL != ppMsgList)
        pNode = *ppMsgList;

    while (NULL != pNode)
    {
        pNext = pNode->pNext;
        fstatus = MQTT_freeMsgNode(&pNode);
        if (OK == status)
            status = fstatus;

        pNode = pNext;
    }

    return status;
}

static MSTATUS MQTT_queuePacket(
    MqttCtx *pCtx,
    MqttMessage **ppMsg)
{
    MSTATUS status;
    MqttMessageList *pNode = NULL;

    status = MOC_MALLOC((void **) &pNode, sizeof(MqttMessageList));
    if (OK != status)
        goto exit;

    pNode->pMsg = *ppMsg;
    pNode->pNext = NULL;

    if (NULL == pCtx->pMsgListHead)
    {
        pCtx->pMsgListHead = pNode;
    }
    else
    {
        pCtx->pMsgListTail->pNext = pNode;
    }

    pCtx->pMsgListTail = pNode;

    pCtx->numBytesToSend += (*ppMsg)->dataLen;

    *ppMsg = NULL;

exit:

    return status;
}

#endif

extern MSTATUS MQTT_processPacket(
    sbyte4 connInst,
    MqttCtx *pCtx,
    MqttMessage **ppMsg,
    byteBoolean acquireMutex)
{
    MSTATUS status;
    byteBoolean releaseMutex = FALSE;

#if defined(__ENABLE_MQTT_CLIENT_DUMP_MESSAGES__)
    MQTT_printMsg((*ppMsg)->pData, (*ppMsg)->dataLen, FALSE);
#endif

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (MQTT_IS_ASYNC(pCtx))
    {
        status = MQTT_queuePacket(pCtx, ppMsg);
        if (OK != status)
            goto exit;
    }
    else
#endif
    {
        status = pCtx->transportSend(
            connInst, pCtx->pTransportCtx, (*ppMsg)->pData, (*ppMsg)->dataLen);
        if (OK != status)
            goto exit;
    }

    if (TRUE == acquireMutex)
    {
        status = RTOS_mutexWait(pCtx->keepAliveMutex);
        if (OK != status)
            goto exit;

        releaseMutex = TRUE;
    }

    /* Store the time at which the message was sent. Used for keep alive
     * handling. Even if the client sets a keep alive value of 0, server may
     * respond with a different keep alive value so the time must always be
     * stored */
    (void) RTOS_deltaMS(NULL, &pCtx->lastMessageSent);

exit:

    if (TRUE == releaseMutex)
    {
        RTOS_mutexRelease(pCtx->keepAliveMutex);
    }

    return status;
}

#endif
