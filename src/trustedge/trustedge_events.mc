;// trustedge_events.mc
;// Message definitions for DigiCert TrustEdge Windows Service
;//
;// Copyright 2026 DigiCert, Inc. All Rights Reserved.
;//
;// To compile: mc.exe -h <output_dir> -r <output_dir> trustedge_events.mc
;// This generates: trustedge_events.h, trustedge_events.rc, MSG00409.bin

SeverityNames=(
    Success=0x0:STATUS_SEVERITY_SUCCESS
    Informational=0x1:STATUS_SEVERITY_INFO
    Warning=0x2:STATUS_SEVERITY_WARN
    Error=0x3:STATUS_SEVERITY_ERROR
)

LanguageNames=(English=0x409:MSG00409)

MessageIdTypeDef=DWORD

;// ========================================================================
;// Informational Messages (1-99)
;// ========================================================================

MessageId=1
Severity=Informational
SymbolicName=TRUSTEDGE_MSG_SERVICE_STARTED
Language=English
TrustEdge service started successfully.
.

MessageId=2
Severity=Informational
SymbolicName=TRUSTEDGE_MSG_SERVICE_STOPPED
Language=English
TrustEdge service stopped.
.

MessageId=3
Severity=Informational
SymbolicName=TRUSTEDGE_MSG_AGENT_STARTED
Language=English
TrustEdge agent thread started.
.

MessageId=4
Severity=Informational
SymbolicName=TRUSTEDGE_MSG_CERTIFICATE_ENROLLED
Language=English
Certificate enrolled successfully: %1
.

MessageId=5
Severity=Informational
SymbolicName=TRUSTEDGE_MSG_CERTIFICATE_RENEWED
Language=English
Certificate renewed successfully: %1
.

MessageId=6
Severity=Informational
SymbolicName=TRUSTEDGE_MSG_REST_API_STARTED
Language=English
REST API server listening on %1
.

MessageId=7
Severity=Informational
SymbolicName=TRUSTEDGE_MSG_INFO_GENERIC
Language=English
%1
.

;// ========================================================================
;// Warning Messages (100-199)
;// ========================================================================

MessageId=100
Severity=Warning
SymbolicName=TRUSTEDGE_MSG_CERTIFICATE_EXPIRING
Language=English
Certificate expiring soon: %1
.

MessageId=101
Severity=Warning
SymbolicName=TRUSTEDGE_MSG_CONNECTION_RETRY
Language=English
Connection to %1 failed, retrying...
.

MessageId=102
Severity=Warning
SymbolicName=TRUSTEDGE_MSG_WARNING_GENERIC
Language=English
%1
.

;// ========================================================================
;// Error Messages (200-299)
;// ========================================================================

MessageId=200
Severity=Error
SymbolicName=TRUSTEDGE_MSG_SERVICE_START_FAILED
Language=English
TrustEdge service failed to start: %1
.

MessageId=201
Severity=Error
SymbolicName=TRUSTEDGE_MSG_CERTIFICATE_ENROLL_FAILED
Language=English
Certificate enrollment failed: %1 (status: %2)
.

MessageId=202
Severity=Error
SymbolicName=TRUSTEDGE_MSG_CONNECTION_FAILED
Language=English
Connection to %1 failed: %2
.

MessageId=203
Severity=Error
SymbolicName=TRUSTEDGE_MSG_CONFIG_ERROR
Language=English
Configuration error: %1
.

MessageId=204
Severity=Error
SymbolicName=TRUSTEDGE_MSG_INITIALIZATION_FAILED
Language=English
Initialization failed: %1 (status: %2)
.

MessageId=205
Severity=Error
SymbolicName=TRUSTEDGE_MSG_CLEANUP_ERROR
Language=English
Cleanup error at %1: %2
.

MessageId=206
Severity=Error
SymbolicName=TRUSTEDGE_MSG_ERROR_GENERIC
Language=English
%1
.

;// ========================================================================
;// Debug Messages (300-399) - for verbose logging
;// ========================================================================

MessageId=300
Severity=Informational
SymbolicName=TRUSTEDGE_MSG_DEBUG
Language=English
[DEBUG] %1
.

MessageId=301
Severity=Informational
SymbolicName=TRUSTEDGE_MSG_THREAD_STARTED
Language=English
[DEBUG] Thread started: %1
.

MessageId=302
Severity=Informational
SymbolicName=TRUSTEDGE_MSG_THREAD_STOPPED
Language=English
[DEBUG] Thread stopped: %1
.

MessageId=303
Severity=Informational
SymbolicName=TRUSTEDGE_MSG_FUNCTION_ENTRY
Language=English
[DEBUG] Entering: %1
.

MessageId=304
Severity=Informational
SymbolicName=TRUSTEDGE_MSG_FUNCTION_EXIT
Language=English
[DEBUG] Exiting: %1 (status: %2)
.
