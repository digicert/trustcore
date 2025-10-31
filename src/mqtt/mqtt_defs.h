/*
 * mqtt_defs.h
 *
 * Definitions for client MQTT implementation
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

#ifndef __MQTT_DEFS_HEADER__
#define __MQTT_DEFS_HEADER__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MQTT_PROP_ARRAY_SIZE                ((MQTT_PROP_LAST + 7)/8)
#define MQTT_PROP_ARRAY_INDEX(_prop)        (_prop >> 3)
#define MQTT_PROP_BIT_FIELD(_prop)          (1 << (_prop & 0x07))
#define MQTT_PROP_IS_SET(_arr, _prop)       (_arr[MQTT_PROP_ARRAY_INDEX(_prop)] & MQTT_PROP_BIT_FIELD(_prop))
#define MQTT_PROP_SET(_arr, _prop)          (_arr[MQTT_PROP_ARRAY_INDEX(_prop)] |= MQTT_PROP_BIT_FIELD(_prop))
#define IS_QOS_1(_pMsg)                     ((_pMsg->pData[0] & 0x06) == 0x02)
#define IS_QOS_2(_pMsg)                     ((_pMsg->pData[0] & 0x06) == 0x04)

typedef enum
{
    MQTT_V3_1_1 = 4,
    MQTT_V5     = 5
} MqttVersion;

typedef enum
{
    MQTT_QOS_0 = 0,
    MQTT_QOS_1,
    MQTT_QOS_2
} MqttQoS;

typedef enum
{
    MQTT_PROP_PAYLOAD_FORMAT_INDICATOR          = 1,    /* 0x01 */
    MQTT_PROP_MESSAGE_EXPIRY_INTERVAL           = 2,    /* 0x02 */
    MQTT_PROP_CONTENT_TYPE                      = 3,    /* 0x03 */
    MQTT_PROP_RESPONSE_TOPIC                    = 8,    /* 0x08 */
    MQTT_PROP_CORRELATION_DATA                  = 9,    /* 0x09 */
    MQTT_PROP_SUBSCRIPTION_IDENTIFIER           = 11,   /* 0x0B */
    MQTT_PROP_SESSION_EXPIRY_INTERVAL           = 17,   /* 0x11 */
    MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER        = 18,   /* 0x12 */
    MQTT_PROP_SERVER_KEEP_ALIVE                 = 19,   /* 0x13 */
    MQTT_PROP_AUTHENTICATION_METHOD             = 21,   /* 0x15 */
    MQTT_PROP_AUTHENTICATION_DATA               = 22,   /* 0x16 */
    MQTT_PROP_REQUEST_PROBLEM_INFORMATION       = 23,   /* 0x17 */
    MQTT_PROP_WILL_DELAY_INTERVAL               = 24,   /* 0x18 */
    MQTT_PROP_REQUEST_RESPONSE_INFORMATION      = 25,   /* 0x19 */
    MQTT_PROP_RESPONSE_INFORMATION              = 26,   /* 0x1A */
    MQTT_PROP_SERVER_REFERENCE                  = 28,   /* 0x1C */
    MQTT_PROP_REASON_STRING                     = 31,   /* 0x1F */
    MQTT_PROP_RECEIVE_MAXIMUM                   = 33,   /* 0x21 */
    MQTT_PROP_TOPIC_ALIAS_MAXIMUM               = 34,   /* 0x22 */
    MQTT_PROP_TOPIC_ALIAS                       = 35,   /* 0x23 */
    MQTT_PROP_MAXIMUM_QOS                       = 36,   /* 0x24 */
    MQTT_PROP_RETAIN_AVAILABLE                  = 37,   /* 0x25 */
    MQTT_PROP_USER_PROPERTY                     = 38,   /* 0x26 */
    MQTT_PROP_MAXIMUM_PACKET_SIZE               = 39,   /* 0x27 */
    MQTT_PROP_WILDCARD_SUBCRIPTION_AVAILABLE    = 40,   /* 0x28 */
    MQTT_PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE = 41,   /* 0x29 */
    MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE     = 42,   /* 0x2A */
    MQTT_PROP_LAST
} MqttPropertyName;

typedef enum
{
    MQTT_CONNECT = 1,
    MQTT_CONNACK,
    MQTT_PUBLISH,
    MQTT_PUBACK,
    MQTT_PUBREC,
    MQTT_PUBREL,
    MQTT_PUBCOMP,
    MQTT_SUBSCRIBE,
    MQTT_SUBACK,
    MQTT_UNSUBSCRIBE,
    MQTT_UNSUBACK,
    MQTT_PINGREQ,
    MQTT_PINGRESP,
    MQTT_DISCONNECT,
    MQTT_AUTH
} MqttControlPacket;

/* This structure defines a MQTT property buffer
 */
typedef struct
{
    ubyte *pData;
    ubyte4 dataLen;
} MqttPropertyBuffer;

/* This structure defines a MQTT property name/value pair
 */
typedef struct
{
    MqttPropertyBuffer name;
    MqttPropertyBuffer value;
} MqttPropertyPair;

/* This structure defines a MQTT property. Used as input/output into MQTT APIs.
 * The name determines which value to access in the union.
 */
typedef struct
{
    MqttPropertyName name;
    union
    {
        ubyte4 value;
        MqttPropertyBuffer buffer;
        MqttPropertyPair pair;
    } data;
} MqttProperty;

/* This structure defines a MQTT message. It contains the type of MQTT message,
 * the data associated with the message, and the length of that data.
 */
typedef struct
{
    MqttControlPacket type;
    ubyte *pData;
    ubyte4 dataLen;
    byteBoolean finished;
} MqttMessage;


#ifdef __cplusplus
}
#endif

#endif /* __MQTT_DEFS_HEADER__ */