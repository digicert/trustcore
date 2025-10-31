/**
 * @file       mqtt_client.h
 * @brief      APIs for client MQTT implementation
 *
 * @filedoc    mqtt_client.h
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

#ifndef __MQTT_CLIENT_HEADER__
#define __MQTT_CLIENT_HEADER__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mtcp.h"
#include "../mqtt/mqtt_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*----------------------------------------------------------------------------*/

#define MQTT_RECV_MAX_DEFLT 65535

/**
 * @struct MqttWillInfo
 * @brief Structure containing will information to be sent on connect.
 *
 * @var MqttWillInfo::qos
 *      The Quality of Service level to use when publishing the will message.
 * @var MqttWillInfo::retain
 *      Specifies if the Will Message is to be retained when it is published.
 * @var MqttWillInfo::pWill
 *      The will payload.
 * @var MqttWillInfo::willLen
 *      Length in bytes of the will payload.
 * @var MqttWillInfo::pWillTopic
 *      The topic the will is to be published to, must be valid UTF8 with no
 *      NULL terminating bytes.
 * @var MqttWillInfo::willTopicLen
 *      Length in bytes of the will topic.
 * @var MqttWillInfo::willDelayInterval
 *      The Server delays publishing the Client’s Will Message until the Will
 *      Delay Interval has passed or the Session ends, whichever happens first.
 * @var MqttWillInfo::setPayloadFormat
 *      If TRUE, the value of payloadFormat will be sent with connect.
 * @var MqttWillInfo::payloadFormat
 *      The payload format be sent with connect if setPayloadFormat is TRUE.
 * @var MqttWillInfo::msgExpiryInterval
 *      The lifetime of the Will Message in seconds and is sent as the
 *      Publication Expiry Interval when the Server publishes the Will Message.
 * @var MqttWillInfo::pContentType
 *      Application defined description of the content of the Will Message,
 *      must be valid UTF8 with no NULL terminating bytes.
 * @var MqttWillInfo::contentTypeLen
 *      Length in bytes of the content type.
 * @var MqttWillInfo::pResponseTopic
 *      Used as the Topic Name for a response message, the presence of a
 *      Response Topic identifies the Will Message as a request,
 *      must be valid UTF8 with no NULL terminating bytes.
 * @var MqttWillInfo::responseTopicLen
 *      Length in bytes of the response topic.
 * @var MqttWillInfo::pCorrelationData
 *      The Correlation Data is used by the sender of the Request Message to
 *      identify which request the Response Message is for when it is received.
 * @var MqttWillInfo::correlationDataLen
 *      Length in bytes of the response topic.
 * @var MqttWillInfo::pProps
 *      Optional pointer to one or more Will User Properties to send on connect.
 * @var MqttWillInfo::propCount
 *      Number of User Properties.
*/
typedef struct
{
    MqttQoS qos;
    byteBoolean retain;
    ubyte *pWill;
    ubyte4 willLen;
    /* Will topic must be vaid UTF8 */
    ubyte *pWillTopic;
    ubyte2 willTopicLen;
    ubyte4 willDelayInterval;
    byteBoolean willDelayIntervalSet;
    byteBoolean setPayloadFormat;
    ubyte payloadFormat;
    ubyte4 msgExpiryInterval;
    byteBoolean msgExpiryIntervalSet;
    /* Content type must be valid UTF8 */
    ubyte *pContentType;
    ubyte2 contentTypeLen;
    /* Response topic must be valid UTF8 */
    ubyte *pResponseTopic;
    ubyte2 responseTopicLen;
    ubyte *pCorrelationData;
    ubyte4 correlationDataLen;
    /* User defined properties for will */
    MqttProperty *pProps;
    ubyte4 propCount;
} MqttWillInfo;

/*----------------------------------------------------------------------------*/

/**
 * @struct MqttConnectOptions
 * @brief Structure containing information to be sent on connect.
 *
 * @var MqttConnectOptions::willInfo
 *      Structure containing will information.
 * @var MqttConnectOptions::pExtCtx
 *      Extended context reserved for future use.
 * @var MqttConnectOptions::cleanStart
 *      If TRUE, indicates to broker to discard any existing session for the client id.
 * @var MqttConnectOptions::keepAliveInterval
 *      The Keep Alive is the maximum time interval that is permitted to elapse between
 *      the point at which the Client finishes transmitting one MQTT Control Packet and
 *      the point it starts sending the next, a Keep Alive value of 0 has the effect of
 *      turning off the Keep Alive mechanism.
 * @var MqttConnectOptions::pUsername
 *      Username to send on connect, must be a valid UTF8 string with no NULL terminators.
 * @var MqttConnectOptions::usernameLen
 *      Length in bytes of the username.
 * @var MqttConnectOptions::pPassword
 *      Password to send on connect.
 * @var MqttConnectOptions::passwordLen
 *      Length in bytes of the password.
 * @var MqttConnectOptions::sessionExpiryIntervalSeconds
 *      A Four Byte Integer representing the Session Expiry Interval in seconds.
 * @var MqttConnectOptions::receiveMax
 *      A Two Byte Integer representing the Receive Maximum value, If the
 *      Receive Maximum value is absent then its value defaults to 65,535.
 * @var MqttConnectOptions::maxPacketSize
 *      A Four Byte Integer representing the Maximum Packet Size the Client is willing to accept.
 * @var MqttConnectOptions::topicAliasMax
 *      This value indicates the highest value that the Client will accept as a Topic Alias sent
 *      by the Server.
 * @var MqttConnectOptions::requestResponseInfo
 *      The Client uses this value to request the Server to return Response Information
 *      in the CONNACK.
 * @var MqttConnectOptions::requestProblemInfo
 *      The Client uses this value to indicate whether the Reason String or User Properties
 *      are sent in the case of failures.
 * @var MqttConnectOptions::pAuthMethod
 *      Authentication Method to send on connect, must be a valid UTF8 string with no NULL terminators.
 * @var MqttConnectOptions::authMethodLen
 *      Length in bytes of the Authentication Method.
 * @var MqttConnectOptions::pAuthData
 *      Authentication Data to send on connect
 * @var MqttConnectOptions::authDataLen
 *      Length in bytes of the Authentication Data.
 * @var MqttConnectOptions::pProps
 *      Optional pointer to one or more User Properties to send on connect.
 * @var MqttConnectOptions::propCount
 *      Number of User Properties.
 */
typedef struct
{
    MqttWillInfo willInfo;
    void *pExtCtx;
    byteBoolean cleanStart;
    ubyte2 keepAliveInterval;
    /* Username must be valid UTF8 */
    ubyte *pUsername;
    ubyte2 usernameLen;
    ubyte *pPassword;
    ubyte4 passwordLen;
    ubyte4 sessionExpiryIntervalSeconds;
    byteBoolean sessionExpiryIntervalSet;
    ubyte2 receiveMax;
    byteBoolean receiveMaxSet;
    ubyte4 maxPacketSize;
    byteBoolean maxPacketSizeSet;
    ubyte2 topicAliasMax;
    byteBoolean topicAliasMaxSet;
    byteBoolean requestResponseInfo;
    byteBoolean requestProblemInfo;
    ubyte4 pollingInterval;

    /* Initial auth method and data to send on connect. Additional auth data
     * for use in multi-step auth mechanisms can be set using an AUTH control
     * packet handler and the MQTT_seAuthInfo() function. Auth method must
     * be valid UTF8 */
    ubyte *pAuthMethod;
    ubyte2 authMethodLen;
    ubyte *pAuthData;
    ubyte4 authDataLen;

    /* User defined properties to send on connect */
    MqttProperty *pProps;
    ubyte4 propCount;
} MqttConnectOptions;

/*----------------------------------------------------------------------------*/

#define MQTT_CONNECT_SUCCESS                            0x00
/* Connect return codes (Mqttv3) */
#define MQTT_CONNECT_UNACCEPTABLE_PROTOCOL_VERSION_V3   0x01
#define MQTT_CONNECT_IDENTIFIER_REJECTED_V3             0x02
#define MQTT_CONNECT_SERVER_UNAVAILABLE_V3              0x03
#define MQTT_CONNECT_BAD_USERNAME_PASSWORD_V3           0x04
#define MQTT_CONNECT_NOT_AUTHORIZED_V3                  0x05

/* Connect reason codes (Mqttv5) */
#define MQTT_CONNECT_UNSPECIFIED_V5                     0x80
#define MQTT_CONNECT_MALFORMED_PACKET_V5                0x81
#define MQTT_CONNECT_PROTOCOL_ERROR_V5                  0x82
#define MQTT_CONNECT_IMPLEMENTATION_SPECIFIC_ERROR_V5   0x83
#define MQTT_CONNECT_UNSUPPORTED_PROTOCOL_VERSION_V5    0x84
#define MQTT_CONNECT_INVALID_CLIENT_IDENTIFIER_V5       0x85
#define MQTT_CONNECT_BAD_USERNAME_PASSWORD_V5           0x86
#define MQTT_CONNECT_NOT_AUTHORIZED_V5                  0x87
#define MQTT_CONNECT_SERVER_UNAVAILABLE_V5              0x88
#define MQTT_CONNECT_BUSY_V5                            0x89
#define MQTT_CONNECT_BANNED_V5                          0x8A
#define MQTT_CONNECT_BAD_AUTHENTICATION_METHOD_V5       0x8C
#define MQTT_CONNECT_INVALID_TOPIC_V5                   0x90
#define MQTT_CONNECT_PACKET_TOO_LARGE_V5                0x95
#define MQTT_CONNECT_QUOTA_EXCEEDED_V5                  0x97
#define MQTT_CONNECT_INVALID_PAYLOAD_FORMAT_V5          0x99
#define MQTT_CONNECT_RETAIN_NOT_SUPPORTED_V5            0x9A
#define MQTT_CONNECT_QOS_NOT_SUPPORTED_V5               0x9B
#define MQTT_CONNECT_USE_ANOTHER_SERVER_V5              0x9C
#define MQTT_CONNECT_SERVER_MOVED_V5                    0x9D
#define MQTT_CONNECT_RATE_EXCEEDED_V5                   0x9F

/**
 * @struct MqttConnAckInfo
 * @brief Structure containing information parsed from a received CONNACK packet.
 *
 * @var MqttConnAckInfo::sessionPresent
 *      The Session Present flag informs the Client whether the Server is using
 *      Session State from a previous connection for this ClientID.
 * @var MqttConnAckInfo::reasonCode
 *      The connect reason code, (0x00) for success.
 * @var MqttConnAckInfo::sessionExpiryIntervalSet
 *      If TRUE, indicates sessionExpiryInterval was included in the packet.
 * @var MqttConnAckInfo::sessionExpiryInterval
 *      The Session Expiry Interval in seconds.
 * @var MqttConnAckInfo::receiveMaxSet
 *      If TRUE, indicates receiveMax was included in the packet.
 * @var MqttConnAckInfo::receiveMax
 *      The Receive Maximum value, the Server uses this value to limit the number
 *      of QoS 1 and QoS 2 publications that it is willing to process concurrently
 *      for the Client.
 * @var MqttConnAckInfo::qosSet
 *      If TRUE, indicates qos was included in the packet.
 * @var MqttConnAckInfo::qos
 *      The Maximum Quality of Service.
 * @var MqttConnAckInfo::retainAvailableSet
 *      If TRUE, indicates retainAvailable was included in the packet.
 * @var MqttConnAckInfo::retainAvailable
 *      This byte declares whether the Server supports retained messages, a value of
 *      0 means that retained messages are not supported, a value of 1 means retained
 *      messages are supported, if not present then retained messages are supported.
 * @var MqttConnAckInfo::maxPacketSizeSet
 *      If TRUE, indicates maxPacketSize was included in the packet.
 * @var MqttConnAckInfo::maxPacketSize
 *      the Maximum Packet Size the Server is willing to accept, if the Maximum
 *      Packet Size is not present there is no limit on the packet size imposed
 *      beyond the limitations in the protocol.
 * @var MqttConnAckInfo::pReasonStr
 *      The Reason String is a human readable UTF8 string representing the reason
 *      associated with this response.
 * @var MqttConnAckInfo::reasonStrLen
 *      Length in bytes of the Reason String.
 * @var MqttConnAckInfo::pAuthMethod
 *      Authentication Method to send, must be a valid UTF8 string with no NULL terminators.
 * @var MqttConnAckInfo::authMethodLen
 *      Length in bytes of the Authentication Method.
 * @var MqttConnAckInfo::pAuthData
 *      Authentication Data to send.
 * @var MqttConnAckInfo::authDataLen
 *      Length in bytes of the Authentication Data.
 * @var MqttConnAckInfo::pAssignedClientId
 *      The Client Identifier which was assigned by the Server because a zero length
 *      Client Identifier was sent on connect.
 * @var MqttConnAckInfo::assignedClientIdLen
 *      Length in bytes of the Reason String.
 * @var MqttConnAckInfo::topicAliasMaxSet
 *      If TRUE, indicates topicAliasMax was included in the packet.
 * @var MqttConnAckInfo::topicAliasMax
 *      This value indicates the highest value that the Server will accept as a Topic Alias
 *      sent by the Client.
 * @var MqttConnAckInfo::wildcardSubscriptionAvailableSet
 *      If TRUE, indicates wildcardSubscriptionAvailable was included in the packet.
 * @var MqttConnAckInfo::wildcardSubscriptionAvailable
 *      If present, this byte declares whether the Server supports Wildcard Subscriptions,
 *      a value is 0 means that Wildcard Subscriptions are not supported, a value of 1 means
 *      Wildcard Subscriptions are supported, if not present then Wildcard Subscriptions are supported.
 * @var MqttConnAckInfo::subscriptionIdentifiersAvailableSet
 *      If TRUE, indicates subscriptionIdentifiersAvailable was included in the packet.
 * @var MqttConnAckInfo::subscriptionIdentifiersAvailable
 *      This byte declares whether the Server supports Subscription Identifiers, a value is 0 means
 *      that Subscription Identifiers are not supported, a value of 1 means Subscription Identifiers
 *      are supported, if not present, then Subscription Identifiers are supported.
 * @var MqttConnAckInfo::sharedSubscriptionAvailableSet
 *      If TRUE, indicates sharedSubscriptionAvailable was included in the packet.
 * @var MqttConnAckInfo::sharedSubscriptionAvailable
 *      This byte declares whether the Server supports Shared Subscriptions, a value is 0 means
 *      that Shared Subscriptions are not supported, a value of 1 means Shared Subscriptions are
 *      supported, if not present, then Shared Subscriptions are supported.
 * @var MqttConnAckInfo::keepAliveSet
 *      If TRUE, indicates keepAlive was included in the packet.
 * @var MqttConnAckInfo::keepAlive
 *      The Keep Alive time assigned by the Server.
 * @var MqttConnAckInfo::pResponseInfo
 *      A UTF-8 Encoded String which is used as the basis for creating a Response Topic.
 * @var MqttConnAckInfo::responseInfoLen
 *      Length in bytes of the Response Info.
 * @var MqttConnAckInfo::pServerRef
 *      A UTF-8 Encoded String which can be used by the Client to identify another Server to use.
 * @var MqttConnAckInfo::serverRefLen
 *      Length in bytes of the Server Reference.
 * @var MqttConnAckInfo::pProps
 *      Optional pointer to one or more User Properties to send on connect.
 * @var MqttConnAckInfo::propCount
 *      Number of User Properties.
 */
typedef struct
{
    byteBoolean sessionPresent;
    ubyte reasonCode;
    byteBoolean sessionExpiryIntervalSet;
    ubyte4 sessionExpiryInterval;
    byteBoolean receiveMaxSet;
    ubyte2 receiveMax;
    byteBoolean qosSet;
    MqttQoS qos;
    byteBoolean retainAvailableSet;
    ubyte retainAvailable;
    byteBoolean maxPacketSizeSet;
    ubyte4 maxPacketSize;
    /* Reason String is valid UTF8 */
    ubyte *pReasonStr;
    ubyte2 reasonStrLen;
    /* Auth method is valid UTF8 */
    ubyte *pAuthMethod;
    ubyte2 authMethodLen;
    ubyte *pAuthData;
    ubyte2 authDataLen;
    /* Client ID is valid UTF8 */
    ubyte *pAssignedClientId;
    ubyte2 assignedClientIdLen;
    byteBoolean topicAliasMaxSet;
    ubyte2 topicAliasMax;
    byteBoolean wildcardSubscriptionAvailableSet;
    ubyte wildcardSubscriptionAvailable;
    byteBoolean subscriptionIdentifiersAvailableSet;
    ubyte subscriptionIdentifiersAvailable;
    byteBoolean sharedSubscriptionAvailableSet;
    ubyte sharedSubscriptionAvailable;
    byteBoolean keepAliveSet;
    ubyte2 keepAlive;
    /* Response Info is valid UTF8 */
    ubyte *pResponseInfo;
    ubyte2 responseInfoLen;
    /* Server Ref is valid UTF8 */
    ubyte *pServerRef;
    ubyte2 serverRefLen;
    /* User properties */
    MqttProperty *pProps;
    ubyte4 propCount;
} MqttConnAckInfo;

/*----------------------------------------------------------------------------*/

/**
 * @details Handler to be called when a CONNACK packet is received.
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pMsg               Pointer to the MQTT message structure.
 * @param pInfo              Information parsed from the received CONNACK.
 */
typedef MSTATUS (*funcPtrConnAckHandler)(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttConnAckInfo *pInfo);

/*----------------------------------------------------------------------------*/

/**
 * @struct MqttSubAckInfo
 * @brief Structure containing information parsed from a received SUBACK packet.
 *
 * @var MqttSubAckInfo::msgId
 *      The Message Identifier.
 * @var MqttSubAckInfo::pReasonStr
 *      The Reason String is a human readable UTF8 string representing the reason
 *      associated with this response.
 * @var MqttSubAckInfo::reasonStrLen
 *      Length in bytes of the Reason String.
 * @var MqttSubAckInfo::pQoS
 *      A list of Reason Codes, each Reason Code corresponds to a Topic Filter in the
 *      SUBSCRIBE packet being acknowledged.
 * @var MqttSubAckInfo::QoSCount
 *      Number of elements in the pQos list.
 * @var MqttSubAckInfo::pProps
 *      Optional pointer to one or more User Properties.
 * @var MqttSubAckInfo::propCount
 *      Number of User Properties.
 */
typedef struct
{
    ubyte2 msgId;
    /* Reason string is valid UTF8 */
    ubyte *pReasonStr;
    ubyte2 reasonStrLen;
    ubyte *pQoS;
    ubyte4 QoSCount;
    /* User properties */
    MqttProperty *pProps;
    ubyte4 propCount;
} MqttSubAckInfo;

/*----------------------------------------------------------------------------*/

/**
 * @details Handler to be called when a SUBACK packet is received
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pMsg               Pointer to the MQTT message structure.
 * @param pInfo              Information parsed from the received SUBACK.
 */
typedef MSTATUS (*funcPtrSubAckHandler)(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttSubAckInfo *pInfo);

/*----------------------------------------------------------------------------*/

/**
 * @struct MqttUnsubAckInfo
 * @brief Structure containing information parsed from a received UNSUBACK packet.
 *
 * @var MqttUnsubAckInfo::msgId
 *      The Message Identifier.
 * @var MqttUnsubAckInfo::pReasonStr
 *      The Reason String is a human readable UTF8 string representing the reason
 *      associated with this response.
 * @var MqttUnsubAckInfo::reasonStrLen
 *      Length in bytes of the Reason String.
 * @var MqttUnsubAckInfo::pReasonCodes
 *      A list of Reason Codes, each Reason Code corresponds to a Topic Filter in the
 *      UNSUBSCRIBE packet being acknowledged.
 * @var MqttUnsubAckInfo::reasonCodeCount
 *      Number of elements in the pQos list.
 * @var MqttUnsubAckInfo::pProps
 *      Optional pointer to one or more User Properties.
 * @var MqttUnsubAckInfo::propCount
 *      Number of User Properties.
 */
typedef struct
{
    ubyte2 msgId;
    ubyte *pReasonStr;
    ubyte2 reasonStrLen;
    ubyte *pReasonCodes;
    ubyte4 reasonCodeCount;
    /* User properties */
    MqttProperty *pProps;
    ubyte4 propCount;
} MqttUnsubAckInfo;

/*----------------------------------------------------------------------------*/

/**
 * @details Handler to be called when a UNSUBACK packet is received
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pMsg               Pointer to the MQTT message structure.
 * @param pInfo              Information parsed from the received UNSUBACK.
 */
typedef MSTATUS (*funcPtrUnsubAckHandler)(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttUnsubAckInfo *pInfo);

/*----------------------------------------------------------------------------*/

/**
 * @struct MqttPublishInfo
 * @brief Structure containing information for a PUBLISH packet.
 *
 * @var MqttPublishInfo::dup
 *      If the DUP flag is set to 0, it indicates that this is the first occasion
 *      that the Client or Server has attempted to send this PUBLISH packet, if the
 *      DUP flag is set to 1, it indicates that this might be re-delivery of an earlier
 *      attempt to send the packet.
 * @var MqttPublishInfo::qos
 *      The Quality of Service for the publish.
 *      associated with this response.
 * @var MqttPublishInfo::retain
 *      The publish retain flag.
 * @var MqttPublishInfo::pTopic
 *      The Topic Name is a UTF8 string which identifies the information channel to
 *      which Payload data is published.
 * @var MqttPublishInfo::topicLen
 *      Length in bytes of the topic.
 * @var MqttPublishInfo::packetId
 *      The Packet Identifier field is only present in PUBLISH packets where the
 *      QoS level is 1 or 2.
 * @var MqttPublishInfo::payloadFormatSet
 *      If TRUE, the value of payloadFormat will be sent.
 * @var MqttPublishInfo::payloadFormat
 *      The payload format be sent with connect if payloadFormatSet is TRUE.
 * @var MqttPublishInfo::messageExpirySet
 *      If TRUE, the value of messageExpiry will be sent.
 * @var MqttPublishInfo::messageExpiry
 *      The lifetime of the Application Message in seconds.
 * @var MqttPublishInfo::topicAlias
 *      A Topic Alias is an integer value that is used to identify the Topic instead
 *      of using the Topic Name, the sender decides whether to use a Topic Alias and
 *      chooses the value, it sets a Topic Alias mapping by including a non-zero length
 *      Topic Name and a Topic Alias in the PUBLISH packet.
 * @var MqttPublishInfo::pResponseTopic
 *      Used as the Topic Name for a response message, the presence of a
 *      Response Topic identifies the Message as a request,
 *      must be valid UTF8 with no NULL terminating bytes.
 * @var MqttPublishInfo::responseTopicLen
 *      Length in bytes of the response topic.
 * @var MqttPublishInfo::pCorrelationData
 *      The Correlation Data is used by the sender of the Request Message to
 *      identify which request the Response Message is for when it is received.
 * @var MqttPublishInfo::correlationDataLen
 *      Length in bytes of the response topic.
 * @var MqttPublishInfo::subId
 *      The Subscription ID.
 * @var MqttPublishInfo::pContentType
 *      Application defined description of the content of the Message,
 *      must be valid UTF8 with no NULL terminating bytes.
 * @var MqttPublishInfo::contentTypeLen
 *      Length in bytes of the content type.
 * @var MqttPublishInfo::pPayload
 *      The publish payload.
 * @var MqttPublishInfo::payloadLen
 *      Length in bytes of the publish payload.
 * @var MqttPublishInfo::pProps
 *      Optional pointer to one or more User Properties.
 * @var MqttPublishInfo::propCount
 *      Number of User Properties.
 */
typedef struct
{
    byteBoolean dup;
    MqttQoS qos;
    byteBoolean retain;
    /* Topic is valid UTF8 */
    ubyte *pTopic;
    ubyte2 topicLen;
    ubyte2 packetId;
    byteBoolean payloadFormatSet;
    ubyte payloadFormat;
    byteBoolean messageExpirySet;
    ubyte4 messageExpiry;
    ubyte2 topicAlias;
    /* Response Topic is valid UTF8 */
    ubyte *pResponseTopic;
    ubyte2 responseTopicLen;
    ubyte *pCorrelationData;
    ubyte2 correlationDataLen;
    ubyte4 subId;
    /* Content Type is valid UTF8 */
    ubyte *pContentType;
    ubyte2 contentTypeLen;
    ubyte *pPayload;
    ubyte4 payloadLen;
    /* User properties */
    MqttProperty *pProps;
    ubyte4 propCount;
} MqttPublishInfo;

/*----------------------------------------------------------------------------*/

/**
 * @details Handler to be called when a PUBLISH packet is received
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pMsg               Pointer to the MQTT message structure.
 * @param pInfo              Information parsed from the received PUBLISH.
 */
typedef MSTATUS (*funcPtrPublishHandler)(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttPublishInfo *pInfo);

/*----------------------------------------------------------------------------*/

/**
 * @struct MqttPubRespInfo
 * @brief Structure containing information parsed from a received PUBACK,
 *        PUBREC, PUBREC, or PUBCOMP packet.
 *
 * @var MqttPubRespInfo::msgId
 *      The Message Identifier.
 * @var MqttPubRespInfo::reasonCode
 *      The Reason Code, will be one of the MQTT_PUBACK_* values.
 * @var MqttPubRespInfo::pReasonStr
 *      The Reason String is a human readable UTF8 string representing the reason
 *      associated with this response.
 * @var MqttPubRespInfo::reasonStrLen
 *      Length in bytes of the Reason String.
 * @var MqttPubRespInfo::pProps
 *      Optional pointer to one or more User Properties.
 * @var MqttPubRespInfo::propCount
 *      Number of User Properties.
 */
typedef struct
{
    ubyte2 msgId;
    ubyte reasonCode;
    /* Reason string is valid UTF8 */
    ubyte *pReasonStr;
    ubyte2 reasonStrLen;
    /* User properties */
    MqttProperty *pProps;
    ubyte4 propCount;
} MqttPubRespInfo;

/**
 * @details Handler to be called when a PUBACK packet is received
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pMsg               Pointer to the MQTT message structure.
 * @param pInfo              Information parsed from the received PUBLISH.
 */
typedef MSTATUS (*funcPtrPubAckHandler)(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttPubRespInfo *pInfo);

/**
 * @details Handler to be called when a PUBREC packet is received
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pMsg               Pointer to the MQTT message structure.
 * @param pInfo              Information parsed from the received PUBLISH.
 */
typedef MSTATUS (*funcPtrPubRecHandler)(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttPubRespInfo *pInfo);

/**
 * @details Handler to be called when a PUBREL packet is received
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pMsg               Pointer to the MQTT message structure.
 * @param pInfo              Information parsed from the received PUBLISH.
 */
typedef MSTATUS (*funcPtrPubRelHandler)(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttPubRespInfo *pInfo);

/**
 * @details Handler to be called when a PUBCOMP packet is received
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pMsg               Pointer to the MQTT message structure.
 * @param pInfo              Information parsed from the received PUBLISH.
 */
typedef MSTATUS (*funcPtrPubCompHandler)(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttPubRespInfo *pInfo);

/*----------------------------------------------------------------------------*/

#define MQTT_CONTINUE_AUTHENTICATION 0x18
#define MQTT_REAUTHENTICATE          0x19

/**
 * @struct MqttAuthInfo
 * @brief Structure containing information parsed from a received AUTH packet.
 *
 * @var MqttAuthInfo::reasonCode
 *      The connect reason code, (0x00) for success (0x18) for continue authentication.
 * @var MqttAuthInfo::pAuthMethod
 *      Authentication Method to send, must be a valid UTF8 string with no NULL terminators.
 * @var MqttAuthInfo::authMethodLen
 *      Length in bytes of the Authentication Method.
 * @var MqttAuthInfo::pAuthData
 *      Authentication Data to send.
 * @var MqttAuthInfo::authDataLen
 *      Length in bytes of the Authentication Data.
 * @var MqttAuthInfo::pReasonStr
 *      The Reason String is a human readable UTF8 string representing the reason
 *      associated with this response.
 * @var MqttAuthInfo::reasonStrLen
 *      Length in bytes of the Reason String.
 * @var MqttAuthInfo::pProps
 *      Optional pointer to one or more User Properties.
 * @var MqttAuthInfo::propCount
 *      Number of User Properties.
 */
typedef struct
{
    ubyte reasonCode;
    /* Auth method is valid UTF8 */
    ubyte *pAuthMethod;
    ubyte2 authMethodLen;
    ubyte *pAuthData;
    ubyte4 authDataLen;
    /* Reason String is valid UTF8 */
    ubyte *pReasonStr;
    ubyte2 reasonStrLen;
    /* User properties */
    MqttProperty *pProps;
    ubyte4 propCount;
} MqttAuthInfo;

/*----------------------------------------------------------------------------*/

/**
 * @details Handler to be called when a AUTH packet is received
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pMsg               Pointer to the MQTT message structure.
 * @param pInfo              Information parsed from the received AUTH.
 */
typedef MSTATUS (*funcPtrAuthHandler)(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttAuthInfo *pInfo);

/*----------------------------------------------------------------------------*/

/**
 * @struct MqttDisconnectInfo
 * @brief Structure containing information parsed from a received DISCONNECT packet.
 *
 * @var MqttDisconnectInfo::reasonCode
 *      The connect reason code, (0x00) for success.
 * @var MqttDisconnectInfo::sessionExpiryIntervalSet
 *      If TRUE, indicates sessionExpiryInterval was included in the packet.
 * @var MqttDisconnectInfo::sessionExpiryInterval
 *      The Session Expiry Interval in seconds.
 * @var MqttDisconnectInfo::pReasonStr
 *      The Reason String is a human readable UTF8 string representing the reason
 *      associated with this response.
 * @var MqttDisconnectInfo::reasonStrLen
 *      Length in bytes of the Reason String.
 * @var MqttDisconnectInfo::pServerRef
 *      A UTF-8 Encoded String which can be used by the Client to identify another Server to use.
 * @var MqttDisconnectInfo::serverRefLen
 *      Length in bytes of the Server Reference.
 * @var MqttDisconnectInfo::pProps
 *      Optional pointer to one or more User Properties.
 * @var MqttDisconnectInfo::propCount
 *      Number of User Properties.
 */
typedef struct
{
    ubyte reasonCode;
    byteBoolean sessionExpiryIntervalSet;
    ubyte4 sessionExpiryInterval;
    /* Reason String is valid UTF8 */
    ubyte *pReasonStr;
    ubyte2 reasonStrLen;
    /* Server ref is valid UTF8 */
    ubyte *pServerRef;
    ubyte2 serverRefLen;
    /* User properties */
    MqttProperty *pProps;
    ubyte4 propCount;
} MqttDisconnectInfo;

/*----------------------------------------------------------------------------*/

/**
 * @details Handler to be called when a DISCONNECT packet is received
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pMsg               Pointer to the MQTT message structure.
 * @param pInfo              Information parsed from the received DISCONNECT.
 */
typedef MSTATUS (*funcPtrDisconnectHandler)(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttDisconnectInfo *pInfo);

/*----------------------------------------------------------------------------*/

/**
 * @details Optional alert handler, this will be called by the stack internals
 *          when a malformed packet or protocol error is encountered.
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param statusCode         The status code associated with the alert.
 *
 */
typedef MSTATUS (*funcPtrAlertHandler)(
    sbyte4 connectionInstance,
    sbyte4 statusCode);

/*----------------------------------------------------------------------------*/

/**
 * @struct MqttPacketHandlers
 * @brief Structure containing function pointers for packet type handler callbacks.
 *
 * @var MqttPacketHandlers::alertHandler
 *      The Alert Handler, called when a fatal alert is encountered.
 * @var MqttPacketHandlers::connAckHandler
 *      Called when a CONNACK packet is received.
 * @var MqttPacketHandlers::subAckHandler
 *      Called when a SUBACK packet is received.
 * @var MqttPacketHandlers::unsubAckHandler
 *      Called when a UNSUBACK packet is received.
 * @var MqttPacketHandlers::publishHandler
 *      Called when a PUBLISH packet is received.
 * @var MqttPacketHandlers::pubackHandler
 *      Called when a PUBACK packet is received.
 * @var MqttPacketHandlers::pubRecHandler
 *      Called when a PUBREC packet is received.
 * @var MqttPacketHandlers::pubRelHandler
 *      Called when a PUBREL packet is received.
 * @var MqttPacketHandlers::pubCompHandler
 *      Called when a PUBCOMP packet is received.
 * @var MqttPacketHandlers::authHandler
 *      Called when a AUTH packet is received.
 * @var MqttPacketHandlers::disconnectHandler
 *      Called when a DISCONNECT packet is received.
 */
typedef struct
{
    funcPtrAlertHandler      alertHandler;
    funcPtrConnAckHandler    connAckHandler;
    funcPtrSubAckHandler     subAckHandler;
    funcPtrUnsubAckHandler   unsubAckHandler;
    funcPtrPublishHandler    publishHandler;
    funcPtrPubAckHandler     pubAckHandler;
    funcPtrPubRecHandler     pubRecHandler;
    funcPtrPubRelHandler     pubRelHandler;
    funcPtrPubCompHandler    pubCompHandler;
    funcPtrAuthHandler       authHandler;
    funcPtrDisconnectHandler disconnectHandler;
} MqttPacketHandlers;

/*----------------------------------------------------------------------------*/

/**
 * @struct MqttSubscribeTopic
 * @brief Structure containing information on a topic to subsribe to.
 *
 * @var MqttSubscribeTopic::pTopic
 *      The Topic Name is a UTF8 string which identifies the information channel to
 *      which Payload data is published.
 * @var MqttSubscribeTopic::topicLen
 *      Length in bytes of the topic.
 * @var MqttSubscribeTopic::qos
 *      The Quality of Service level.
 * @var MqttSubscribeTopic::noLocalOption
 *      If the value is 1, Application Messages MUST NOT be forwarded to a connection
 *      with a ClientID equal to the ClientID of the publishing connection.
 * @var MqttSubscribeTopic::retainAsPublished
 *      If 1, Application Messages forwarded using this subscription keep the RETAIN
 *      flag they were published with, if 0 Application Messages forwarded using this
 *      subscription have the RETAIN flag set to 0, retained messages sent when the
 *      subscription is established have the RETAIN flag set to 1.
 * @var MqttSubscribeTopic::retainHandling
 *      0 = Send retained messages at the time of the subscribe,
 *      1 = Send retained messages at subscribe only if the subscription does not currently exist,
 *      2 = Do not send retained messages at the time of the subscribe
 */
typedef struct
{
    /* Topic is valid UTF8 */
    ubyte *pTopic;
    ubyte4 topicLen;
    MqttQoS qos;
    byteBoolean noLocalOption;
    byteBoolean retainAsPublished;
    ubyte retainHandling;
} MqttSubscribeTopic;

/*----------------------------------------------------------------------------*/

/**
 * @struct MqttSubscribeOptions
 * @brief Structure containing information to be sent with a SUBSCRIBE message.
 *
 * @var MqttSubscribeOptions::subId
 *      The Subscription ID.
 * @var MqttSubscribeOptions::pProps
 *      Optional pointer to one or more User Properties.
 * @var MqttSubscribeOptions::propCount
 *      Number of User Properties.
 */
typedef struct
{
    ubyte4 subId;
    MqttProperty *pProps;
    ubyte4 propCount;
} MqttSubscribeOptions;

/*----------------------------------------------------------------------------*/

/**
 * @struct MqttUnsubscribeTopic
 * @brief Structure containing information on a topic to unsubsribe to.
 *
 * @var MqttUnsubscribeTopic::pTopic
 *      The Topic Name is a UTF8 string which identifies the information channel to
 *      which Payload data is published.
 * @var MqttUnsubscribeTopic::topicLen
 *      Length in bytes of the topic.
 */
typedef struct
{
    /* Topic is valid UTF8 */
    ubyte *pTopic;
    ubyte4 topicLen;
} MqttUnsubscribeTopic;

/*----------------------------------------------------------------------------*/

/**
 * @struct MqttUnsubscribeOptions
 * @brief Structure containing information to be sent with a UNSUBSCRIBE message.
 *
 * @var MqttUnsubscribeOptions::pProps
 *      Optional pointer to one or more User Properties.
 * @var MqttUnsubscribeOptions::propCount
 *      Number of User Properties.
 */
typedef struct
{
    MqttProperty *pProps;
    ubyte4 propCount;
} MqttUnsubscribeOptions;

/*----------------------------------------------------------------------------*/

/**
 * @struct MqttPublishOptions
 * @brief Structure containing information to be sent in a PUBLISH message.
 *
 * @var MqttPublishOptions::setPayloadFormat
 *      If TRUE, the value of payloadFormat will be sent with connect.
 * @var MqttPublishOptions::payloadFormat
 *      The payload format be sent with connect if setPayloadFormat is TRUE.
 * @var MqttPublishOptions::msgExpiryInterval
 *      The lifetime of the Application Message in seconds.
 * @var MqttPublishOptions::topicAlias
 *      A Topic Alias is an integer value that is used to identify the Topic instead
 *      of using the Topic Name, the sender decides whether to use a Topic Alias and
 *      chooses the value, it sets a Topic Alias mapping by including a non-zero length
 *      Topic Name and a Topic Alias in the PUBLISH packet.
 * @var MqttPublishOptions::pResponseTopic
 *      Used as the Topic Name for a response message, the presence of a
 *      Response Topic identifies the Message as a request,
 *      must be valid UTF8 with no NULL terminating bytes.
 * @var MqttPublishOptions::responseTopicLen
 *      Length in bytes of the response topic.
 * @var MqttPublishOptions::pCorrelationData
 *      The Correlation Data is used by the sender of the Request Message to
 *      identify which request the Response Message is for when it is received.
 * @var MqttPublishOptions::correlationDataLen
 *      Length in bytes of the response topic.
 * @var MqttPublishOptions::pProps
 *      Optional pointer to one or more User Properties.
 * @var MqttPublishOptions::propCount
 *      Number of User Properties.
 * @var MqttPublishOptions::subId
 *      The Subscription ID.
 * @var MqttPublishOptions::pContentType
 *      Application defined description of the content of the Message,
 *      must be valid UTF8 with no NULL terminating bytes.
 * @var MqttPublishOptions::contentTypeLen
 *      Length in bytes of the content type.
 * @var MqttPublishOptions::retain
 *      The publish retain flag.
 * @var MqttPublishOptions::qos
 *      The Quality of Service for the publish.
 * @var MqttPublishOptions::dup
 *      If the DUP flag is set to 0, it indicates that this is the first occasion
 *      that the Client or Server has attempted to send this PUBLISH packet, if the
 *      DUP flag is set to 1, it indicates that this might be re-delivery of an earlier
 *      attempt to send the packet.
 */
typedef struct
{
    byteBoolean setPayloadFormat;
    ubyte payloadFormat;
    ubyte4 msgExpiryInterval;
    byteBoolean msgExpiryIntervalSet;
    ubyte2 topicAlias;
    byteBoolean topicAliasSet;
    /* Response topic must be valid UTF8 */
    ubyte *pResponseTopic;
    ubyte4 responseTopicLen;
    ubyte *pCorrelationData;
    ubyte4 correlationDataLen;
    MqttProperty *pProps;
    ubyte4 propCount;
    ubyte4 subId;
    /* Content type must be valid UTF8 */
    ubyte *pContentType;
    ubyte4 contentTypeLen;
    byteBoolean retain;
    MqttQoS qos;
    byteBoolean dup;
} MqttPublishOptions;

/*----------------------------------------------------------------------------*/

/**
 * @struct MqttAuthOptions
 * @brief Structure containing information to be sent in an AUTH packet.
 *
 * @var MqttAuthOptions::pAuthMethod
 *      Authentication Method to send, must be a valid UTF8 string with no NULL terminators.
 * @var MqttAuthOptions::authMethodLen
 *      Length in bytes of the Authentication Method.
 * @var MqttAuthOptions::pAuthData
 *      Authentication Data to send.
 * @var MqttAuthOptions::authDataLen
 *      Length in bytes of the Authentication Data.
 * @var MqttAuthOptions::reAuthenticate
 *      Set to TRUE for reauthentication.
 * @var MqttAuthOptions::pProps
 *      Optional pointer to one or more User Properties.
 * @var MqttAuthOptions::propCount
 *      Number of User Properties.
 */
typedef struct
{
    /* Auth method must be valid UTF8 */
    ubyte *pAuthMethod;
    ubyte2 authMethodLen;
    ubyte *pAuthData;
    ubyte4 authDataLen;
    byteBoolean reAuthenticate;
    /* User defined properties to send with AUTH */
    MqttProperty *pProps;
    ubyte4 propCount;
} MqttAuthOptions;

/*----------------------------------------------------------------------------*/

/* Disconnect reason codes */
#define MQTT_DISCONNECT_NORMAL                  0x00
#define MQTT_DISCONNECT_SEND_WILL               0x04
#define MQTT_DISCONNECT_UNSPECIFIED             0x80
#define MQTT_DISCONNECT_MALFORMED_PACKET        0x81
#define MQTT_DISCONNECT_PROTOCOL_ERROR          0x82
#define MQTT_DISCONNECT_TOPIC_NAME_INVALID      0x90
#define MQTT_DISCONNECT_RECV_MAX_EXCEEDED       0x93
#define MQTT_DISCONNECT_TOPIC_ALIAS_INVALID     0x94
#define MQTT_DISCONNECT_PACKET_TOO_LARGE        0x95
#define MQTT_DISCONNECT_MSG_RATE_TOO_HIGH       0x96
#define MQTT_DISCONNECT_QUOTA_EXCEEDED          0x97
#define MQTT_DISCONNECT_ADMINISTRATIVE_ACTION   0x98

/**
 * @struct MqttDisconnectOptions
 * @brief Structure containing information to be sent in a DISCONNECT packet.
 *
 * @var MqttDisconnectOptions::reasonCode
 *      The disconnect reason code, use (0x00) for success or one of the MQTT_DISCONNECT_* values.
 * @var MqttDisconnectOptions::pReasonStr
 *      The Reason String is a human readable UTF8 string representing the reason
 *      associated with this response.
 * @var MqttDisconnectOptions::reasonStrLen
 *      Length in bytes of the Reason String.
 * @var MqttDisconnectOptions::sendSessionExpiry
 *      Set to TRUE if sessionExpiryInterval value is to be sent.
 * @var MqttDisconnectOptions::sessionExpiryInterval
 *      Only set if session expiry interval was set on connect. If session
 *      expiry on connect was zero and this value is non-zero, it is an error.
 * @var MqttDisconnectOptions::pProps
 *      Optional pointer to one or more User Properties.
 * @var MqttDisconnectOptions::propCount
 *      Number of User Properties.
 */
typedef struct
{
    ubyte reasonCode;
    ubyte *pReasonStr;
    ubyte2 reasonStrLen;
    ubyte sendSessionExpiry;
    ubyte4 sessionExpiryInterval;
    /* User defined properties to send with DISCONNECT */
    MqttProperty *pProps;
    ubyte4 propCount;
} MqttDisconnectOptions;

/*----------------------------------------------------------------------------*/

#define MQTT_PUB_SUCCESS                  0x00
#define MQTT_PUB_NO_MATCHING_SUBSCRIBERS  0x10
#define MQTT_PUB_UNSPECIFIED_ERROR        0x80
#define MQTT_PUB_IMPLEMENTATION_ERROR     0x83
#define MQTT_PUB_NOT_AUTHORIZED           0x87
#define MQTT_PUB_TOPIC_NAME_INVALID       0x90
#define MQTT_PUB_PACKET_ID_IN_USE         0x91
#define MQTT_PUB_QUOTA_EXCEEDED           0x97
#define MQTT_PUB_PAYLOAD_FORMAT_INVALID   0x99

/**
 * @struct MqttPubRespOptions
 * @brief Structure containing information to be sent in a PUB* packet.
 *
 * @var MqttPubRespOptions::reasonCode
 *      The reason code, use (0x00) for success or one of the MQTT_PUB_* values.
 * @var MqttPubRespOptions::packetId
 *      The packet identifier.
 * @var MqttPubRespOptions::pReasonStr
 *      The Reason String is a human readable UTF8 string representing the reason
 *      associated with this response.
 * @var MqttPubRespOptions::reasonStrLen
 *      Length in bytes of the Reason String.
 * @var MqttPubRespOptions::pProps
 *      Optional pointer to one or more User Properties.
 * @var MqttPubRespOptions::propCount
 *      Number of User Properties.
 */
typedef struct
{
    MqttControlPacket packetType;
    ubyte reasonCode;
    ubyte2 packetId;
    ubyte *pReasonStr;
    ubyte2 reasonStrLen;
    /* User defined properties to send with PUBACK */
    MqttProperty *pProps;
    ubyte4 propCount;
} MqttPubRespOptions;

/*----------------------------------------------------------------------------*/

typedef MSTATUS (*funcPtrMqttTransportSend)(
    sbyte4 connectionInstance,
    void *pTransportCtx,
    sbyte *pBuffer,
    ubyte4 bufferLen);

/*----------------------------------------------------------------------------*/

typedef MSTATUS (*funcPtrMqttTransportRecv)(
    sbyte4 connectionInstance,
    void *pTransportCtx,
    sbyte *pBuffer,
    ubyte4 bufferLen,
    ubyte4 *pNumBytesReceived,
    ubyte4 timeoutMS,
    byteBoolean *pTimeout);

/*----------------------------------------------------------------------------*/

typedef MSTATUS (*funcPtrReceiveTimeoutHandler)(sbyte4 connInst, ubyte4 *pTimeout);

/*----------------------------------------------------------------------------*/

/**
 * @details Initialize MQTT stack with maximum number of client sessions allowed
 *
 * @param mqttMaxClientConnections Number of maximum client sessions allowed.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_init(
    sbyte4 mqttMaxClientConnections);

/*----------------------------------------------------------------------------*/

/**
 * @details Clean up MQTT stack. Frees memory and performs shutdown on MQTT stack.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_shutdownStack(void);

/*----------------------------------------------------------------------------*/

/**
 * @details Create a client connection instance. It should be noted this does not establish
 * a network connection or send a CONNECT packet, that is done by
 * MQTT_negotiateConnection().
 *
 * @param version     MQTT version, at this time only version 5 is supported.
 * @param pClientId   UTF8 string of the client identifier,
 * @param clientIdLen Length of client identifier, note this MUST NOT include
 *                    any NULL terminator.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN sbyte4 MQTT_connect(
    MqttVersion version,
    ubyte *pClientId,
    ubyte2 clientIdLen);

/*----------------------------------------------------------------------------*/

/**
 * @details Create a client connection instance for asynchronous communication.
 * It should be noted this does not construct a CONNECT packet, that is done by
 * MQTT_negotiateConnection().
 *
 * @param version     MQTT version, at this time only version 5 is supported.
 * @param pClientId   UTF8 string of the client identifier,
 * @param clientIdLen Length of client identifier, note this MUST NOT include
 *                    any NULL terminator.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN sbyte4 MQTT_asyncConnect(
    MqttVersion version,
    ubyte *pClientId,
    ubyte2 clientIdLen);

/*----------------------------------------------------------------------------*/

/**
 * @details Set a connection instance created with MQTT_connect() to use TCP.
 *
 * @param connectionInstance The connection instance to be set.
 * @param socket             A handle to a socket opened by the caller to be used
 *                           for transport for the connection instance.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_setTransportTCP(
    sbyte4 connectionInstance,
    TCP_SOCKET socket);

/*----------------------------------------------------------------------------*/

/**
 * @details Set a connection instance created with MQTT_connect() to use SSL.
 *
 * @param connectionInstance The connection instance to be set.
 * @param sslConnectionInstance The SSL connection instance.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_setTransportSSL(
    sbyte4 connectionInstance,
    sbyte4 sslConnectionInstance);

/*----------------------------------------------------------------------------*/

/**
 * @details Set custom transport handlers. It should be noted any transport mechanism must
 * be ordered and lossless to comply with MQTT specification.
 *
 * @param connectionInstance The connection instance to be set.
 * @param pTransportCtx      Pointer to application controlled transport context,
 *                           which will be passed to the transport handler implementation.
 * @param send               Function pointer for a transport send to be set.
 * @param recv               Function pointer for a transport recv to be set.
 *
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_setTransport(
    sbyte4 connectionInstance,
    void *pTransportCtx,
    funcPtrMqttTransportSend send,
    funcPtrMqttTransportRecv recv);

/*----------------------------------------------------------------------------*/

/**
 * @details Set a cookie.
 *
 * @param connectionInstance The connection instance to be set.
 * @param pCookie            The cookie to set.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_setCookie(
    sbyte4 connectionInstance,
    void *pCookie);

/*----------------------------------------------------------------------------*/

/**
 * @details Get a cookie.
 *
 * @param connectionInstance The connection instance to get cookie from.
 * @param ppCookie           Pointer to the pointer to the cookie.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_getCookie(
    sbyte4 connectionInstance,
    void **ppCookie);

/*----------------------------------------------------------------------------*/

/**
 * @details Send connect message to the broker
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pOptions           Structure containing info to be sent in CONNECT packet.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_negotiateConnection(
    sbyte4 connectionInstance,
    MqttConnectOptions *pOptions);

/*----------------------------------------------------------------------------*/

/**
 * @details Sends disconnect message, note this does not close a network connection.
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pOptions           Structure containing info to be sent in DISCONNECT packet.
 *                           Reason code will be normal disconnection(0x00) unless one of the
 *                           MQTT_DISCONNECT_* values are set for the reason code in the
 *                           MqttDisconnectOptions structure.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_disconnect(
    sbyte4 connectionInstance,
    MqttDisconnectOptions *pOptions);

/*----------------------------------------------------------------------------*/

/**
 * @details Clean up MQTT connection internal state. Note this function does not close a
 * network connection or send a disconnect packet.
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_closeConnection(
    sbyte4 connectionInstance);

/*----------------------------------------------------------------------------*/

/**
 * @details Get MQTT version.
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pVersion           Pointer to the location that will receive the version.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_getVersion(
    sbyte4 connectionInstance,
    MqttVersion *pVersion);

/*----------------------------------------------------------------------------*/

/**
 * @details Set handlers for control packets. The packet type handler will be invoked when
 * a packet of that type is received. Any non-NULL function pointers will be set
 * for the connection instance.
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pHandlers          Pointer to structure containing at least one non-NULL
 *                           function pointer.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_setControlPacketHandlers(
    sbyte4 connectionInstance,
    MqttPacketHandlers *pHandlers);

/*----------------------------------------------------------------------------*/

/**
 * @details Subscribe to a topic.
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pTopics            Pointer to one or more topics to subscribe to.
 * @param topicCount         Number of topics.
 * @param pOptions           Structure containing info to be sent in SUBSCRIBE packet.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_subscribe(
    sbyte4 connectionInstance,
    MqttSubscribeTopic *pTopics,
    ubyte4 topicCount,
    MqttSubscribeOptions *pOptions);

/*----------------------------------------------------------------------------*/

/**
 * @details Unsubscribe from a topic.
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pTopics            Pointer to one or more topics to unsubscribe from.
 * @param topicCount         Number of topics.
 * @param pOptions           Structure containing info to be sent in UNSUBSCRIBE packet.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_unsubscribe(
    sbyte4 connectionInstance,
    MqttUnsubscribeTopic *pTopics,
    ubyte4 topicCount,
    MqttUnsubscribeOptions *pOptions);

/*----------------------------------------------------------------------------*/

/**
 * @details Publish to a topic.
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pOptions           Structure containing info to be sent in PUBLISH packet.
 * @param pTopic             UTF8 string of topic to publish to.
 * @param topicLen           Length in bytes of topic.
 * @param pData              Data to be published.
 * @param dataLen            Length of data to be published
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h NOTE, the following error codes are not
 *                 fatal and a publish may work after a failure without requiring
 *                 a reconnect:
 *                   ERR_MQTT_SEND_QUOTA
 */
MOC_EXTERN MSTATUS MQTT_publish(
    sbyte4 connectionInstance,
    MqttPublishOptions *pOptions,
    ubyte *pTopic,
    ubyte4 topicLen,
    ubyte *pData,
    ubyte4 dataLen);

/*----------------------------------------------------------------------------*/

/**
 * @details Send a PINGREQ packet.
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_pingRequest(
    sbyte4 connectionInstance);

/*----------------------------------------------------------------------------*/

/**
 * @details Recieve data from the underlying transport and process it. Function reads data
 * on the wire. Once a full control packet is received, the application can process
 * it if it has set a control packet handler for MQTT_PUBLISH.
 * NOTE: If this function returns ERR_MQTT_MALFORMED_PACKET or
 * ERR_MQTT_INVALID_PACKET_TYPE, the caller SHOULD close the network connection
 * and cleanup internal state by calling MQTT_closeConnection().
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_recv(
    sbyte4 connectionInstance);

/*----------------------------------------------------------------------------*/

/**
 * @details Send an AUTH packet. Applications implementing multi-step extended authentication
 * methods can call this from a CONNACK handler to facilitate the multi-step
 * authentication process.
 *
 * @param connectionInstance The connection instance from MQTT_connect().
 * @param pOptions           Structure containing info to be sent in AUTH packet.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_sendAuth(
    sbyte4 connectionInstance,
    MqttAuthOptions *pOptions);

/*----------------------------------------------------------------------------*/

/**
 * @details Retrieve the current state of the connection.
 *
 * @param connectionInstance The connection instance from MQTT_connect() or
 *                           MQTT_asyncConnect().
 *
 * @return         0 indicates the connection is still in the negotiation stage.
 *                 1 indicates the connection has been successfully negotiated.
 *                 Negative number indicates error code from merrors.h
 */
MOC_EXTERN sbyte4 MQTT_isConnectionEstablished(
    sbyte4 connectionInstance);

/*----------------------------------------------------------------------------*/

/**
 * @details Get a copy of the connection's send data buffer. The caller may pass
 * in a NULL data buffer to retrieve the number of bytes in the connection's
 * send data buffer.
 *
 * @param connectionInstance The connection instance from MQTT_asyncConnect().
 * @param pData              Buffer which is populated with data
 * @param pDataLength        Application sets this to the number of bytes
 *                           available in \p pData, method sets this to the
 *                           number of bytes written to \p pData
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_getSendBuffer(
    sbyte4 connectionInstance,
    ubyte *pData,
    ubyte4 *pDataLength);

/*----------------------------------------------------------------------------*/

/**
 * @details Process data received by the application.
 *
 * @param connectionInstance The connection instance from MQTT_asyncConnect().
 * @param pData              Buffer containing data received by the application
 * @param dataLength         Number of bytes in \p pData
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_recvMessage(
    sbyte4 connectionInstance,
    ubyte *pData,
    ubyte4 dataLength);

/*----------------------------------------------------------------------------*/

/**
 * @details Determine is a transaction is pending for the current session. If
 * a transaction is pending it means there is either data pending to by sent
 * out by the session or the session is expecting data from the broker.
 *
 * @param connectionInstance The connection instance from MQTT_connect() or
 *                           MQTT_asyncConnect().
 *
 * @return         0 indicates there is no data pending to be received or sent.
 *                 1 indicates there is data pending to be sent or received.
 *                 Negative number indicates error code from merrors.h
 */
MOC_EXTERN sbyte4 MQTT_transactionPending(
    sbyte4 connectionInstance);

/*----------------------------------------------------------------------------*/

/**
 * @details Get the read buffer timeout. If the timeout is non-zero and once the
 * timeout expires, the application must call MQTT_recvMessage then flush out
 * any pending data.
 *
 * @param connectionInstance The connection instance from MQTT_connect() or
 *                           MQTT_asyncConnect().
 * @param pReadTimeoutMS     Timeout for read operations in MS.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_readTimeout(
sbyte4 connectionInstance,
    ubyte4 *pReadTimeoutMS);

/*----------------------------------------------------------------------------*/

/**
 * @details Reset the connection state. MQTT_connect() guards against disallowed
 *          attempts to connect a client that is already connected. If the internal
 *          network state has been compromised due to network failures, this function
 *          can be used to reset the connection state and force a reconnect.
 *
 * @param connectionInstance The connection instance from MQTT_connect() or
 *                           MQTT_asyncConnect().
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN sbyte4 MQTT_resetConnectionState(
    sbyte4 connectionInstance);

/*----------------------------------------------------------------------------*/

/**
 * @details Retrieves the client id for a given connection instance. NOTE: The
 *          *ppClientId will NOT be a newly allocated pointer, it is a pointer
 *          to internal memory that will be freed by the stack when appropriate.
 *          DO NOT FREE THE POINTER.
 *
 * @param connectionInstance The connection instance from MQTT_connect() or
 *                           MQTT_asyncConnect().
 * @param ppClientId         The location that will receive the pointer to existing
 *                           memory owned by the stack containing the client id.
 * @param pClientIdLen       The location that will receive the length of the client id.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_getClientIdFromConnInst(
    sbyte4 connectionInstance, 
    ubyte **ppClientId, 
    ubyte4 *pClientIdLen);

/*----------------------------------------------------------------------------*/

/**
 * @details Extended version of MQTT_recv() with ability to force timeout behavior.
 *
 * @param connectionInstance The connection instance from MQTT_connect() or
 *                           MQTT_asyncConnect().
 * @param timeoutVal         The timeout in milliseconds.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_recvEx(
    sbyte4 connectionInstance,
    ubyte4 timeoutVal);

/*----------------------------------------------------------------------------*/

typedef struct
{
    ubyte mode;
    char *pDir;
} FilePersistArgs;

#define MQTT_PERSIST_MODE_UNDEFINED 0
#define MQTT_PERSIST_MODE_FILE      1

/**
 * @details Set the persist mode for a client.
 *
 * @param connectionInstance The connection instance from MQTT_connect() or
 *                           MQTT_asyncConnect().
 * @param pArgs              The File Persist argument structure, containing the mode
 *                           and directory where the messages shall be persisted.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_setPersistMode(
    sbyte4 connectionInstance,
    FilePersistArgs *pArgs);

/*----------------------------------------------------------------------------*/

#ifndef MQTT_DEFAULT_PUBLISH_TIMEOUT_SECONDS
#define MQTT_DEFAULT_PUBLISH_TIMEOUT_SECONDS 86400
#endif

/**
 * @details Set the pubish timeout for a client.
 *
 * @param connectionInstance The connection instance from MQTT_connect() or
 *                           MQTT_asyncConnect().
 * @param timeoutVal         The publish timeout in seconds, maximum allowed
 *                           value is 4,294,967.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_setPublishTimeout(
    sbyte4 connectionInstance,
    ubyte4 publishTimeoutSeconds);

/*----------------------------------------------------------------------------*/

/**
 * @details Set the protocol buffer size for a client. This controls the size
 * of bytes read from the underlying transport. Additionally, if MQTT is built
 * with streaming support, this also controls the number of bytes streamed back
 * to the application.
 *
 * @param connectionInstance The connection instance from MQTT_connect() or
 *                          MQTT_asyncConnect().
 * @param size              The size of the network buffer in bytes.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_setProtocolBufferSize(
    sbyte4 connectionInstance,
    ubyte4 size);

/*----------------------------------------------------------------------------*/

/**
 * @details Get the reason string for a given connack reason code.
 *
 * @param connInst    The connection instance from MQTT_connect() or
 *                    MQTT_asyncConnect().
 * @param reasonCode  The reason code for which the string is requested.
 * @param ppReasonStr Pointer to a pointer that will receive the
 *                    reason string.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                code from merrors.h
 */

MOC_EXTERN MSTATUS MQTT_getConnackReasonString(
    sbyte4 connInst,
    ubyte reasonCode,
    sbyte **ppReasonStr);

/*----------------------------------------------------------------------------*/

/**
 * @details Starts keep alive thread for this connection instance. The keep
 * alive thread will send ping request to the broker at the keep alive interval
 * negotiated.
 *
 * @param connectionInstance The connection instance from MQTT_connect() or
 *                          MQTT_asyncConnect().
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_startKeepAliveThread(
    sbyte4 connectionInstance);

/*----------------------------------------------------------------------------*/

/**
 * @details Set timeout handler to invoke when the timeout expires during read.
 *
 * @param connectionInstance The connection instance from MQTT_connect() or
 *                          MQTT_asyncConnect().
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                code from merrors.h
 */
MOC_EXTERN MSTATUS MQTT_setRecieveTimeoutHandler(
    sbyte4 connectionInstance,
    funcPtrReceiveTimeoutHandler pHandler);

#ifdef __cplusplus
}
#endif

#endif /* __MQTT_CLIENT_HEADER__ */
