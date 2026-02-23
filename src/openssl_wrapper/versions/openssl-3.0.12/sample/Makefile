CFLAGS+=-I../include -I../ -I../../../src

ifeq ($(export),true)
LDFLAGS=-L../../../lib -lopenssl_shim -lnanossl -lcrypto -lcryptomw
else
LDFLAGS=-L../../../lib -lopenssl_shim -lnanossl -lcrypto -lnanocrypto
endif

EXTFLAGS=
CC ?= gcc

ifeq ($(sysroot),)
	SYSROOT_ARG=
else
	SYSROOT_ARG=--sysroot=${sysroot} -L${sysroot}/lib -L${sysroot}/usr/lib
	LDFLAGS += $(SYSROOT_ARG)
endif

ifeq ($(tap),true)
ifeq ($(export),true)
    LDFLAGS+=-L ../../../lib  -lssl -lcrypto -lnanotap2 -lnanotap2_common -lcryptointerface -lcommon -lcryptomw
else
    LDFLAGS+=-L ../../../lib  -lssl -lcrypto -lnanotap2 -lnanotap2_common -lcryptointerface -lcommon -lnanocrypto
endif
    CFLAGS += -D__ENABLE_DIGICERT_TAP__ -D__ENABLE_DIGICERT_CRYPTO_INTERFACE__

ifeq ($(tap_remote),true)
    CFLAGS += -D__ENABLE_DIGICERT_TAP_REMOTE__
    LDFLAGS += -lnanotap2_clientcomm
else
    LDFLAGS += -lsmptpm2 -ltpm2
endif
else
    LDFLAGS+=-L ../../../lib -lssl -lcrypto
endif

ifeq ($(cryptointerface),true)
   LDFLAGS += -L../../../lib -lcryptointerface -lcommon -lnanocert -lplatform -lasn1 -linitialize -lnanocap
endif

ifeq ($(tap_extern),true)
	CFLAGS += -D__ENABLE_DIGICERT_TAP_EXTERN__
endif

ifeq ($(fips),true)
    CFLAGS  += -D__EVP_NAMESPACE_CONFLICT__
    LDFLAGS += -L../../../lib -lmss
endif

ifeq ($(android),true)
CFLAGS += -Wl,-rpath-link=../../../lib
LDFLAGS += -ldl
else
LDFLAGS += -lpthread -lrt -ldl
endif

ifeq ($(gdb),true)
    CFLAGS += -g
endif

ifeq ($(mauth),true)
    CFLAGS += -D__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
endif

ifeq ($(openssl_load_algos),true)
	CFLAGS += -D__ENABLE_DIGICERT_OSSL_LOAD_ALL_ALGORITHMS__
endif

ifeq ($(rehandshake),true)
    CFLAGS += -D__ENABLE_DIGICERT_SSL_REHANDSHAKE__
endif

ifeq ($(sendquit),true)
    CFLAGS += -D__ENABLE_DIGICERT_SSL_SEND_QUIT_CMD__
endif

ifeq ($(alertcb),true)
    CFLAGS += -D__ENABLE_DIGICERT_SSL_ALERT_CALLBACK_SUPPORT__
endif

ifeq ($(pem_read),true)
    CFLAGS += -D__ENABLE_DIGICERT_PEM_READ_BIO_PRIVATE_KEY__
endif

ifeq ($(posthandshake_auth),true)
    CFLAGS += -D__ENABLE_DIGICERT_TLS13_POST_HANDSHAKE_AUTH__
endif

ifeq ($(key_update),true)
    CFLAGS += -D__ENABLE_DIGICERT_TLS13_KEYUPDATE__
endif

ifeq ($(psk),true)
    CFLAGS += -D__ENABLE_DIGICERT_TLS13_PSK__
endif

ifeq ($(0rtt),true)
    CFLAGS += -D__ENABLE_DIGICERT_TLS13_0RTT__
endif
ifeq ($(ocsp),true)
    CFLAGS+= -D__ENABLE_DIGICERT_OCSP_EXAMPLE__
endif

ifeq ($(enable_ticket_tls12),true)
    CFLAGS+= -D__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__
endif

ifeq ($(client_cert_callback),true)
	CFLAGS += -D__ENABLE_DIGICERT_SSL_EXAMPLE_SMART_CARD__
endif

LDFLAGS += $(EXTFLAGS)

openssl_client:
	$(CC) -o openssl_client openssl_client.c $(CFLAGS) $(LDFLAGS)

openssl_server:
	$(CC) -o openssl_server openssl_server.c -DOPENSSL_ENGINE -DOPENSSL_SUPPRESS_DEPRECATED -D__RTOS_LINUX__ $(CFLAGS) $(LDFLAGS)

openssl_client_tpm:
	$(CC) -o openssl_client_tpm openssl_client_tpm.c -DOPENSSL_ENGINE -D__ENABLE_DIGICERT_HW_SECURITY_MODULE__ -D__ENABLE_DIGICERT_TPM__ -D__RTOS_LINUX__ $(CFLAGS) $(LDFLAGS)

openssl_client_local:
	$(CC) -o openssl_client_local openssl_client_local.c -DOPENSSL_SUPPRESS_DEPRECATED $(CFLAGS) $(LDFLAGS)

openssl_dtls_client:
	$(CC) -o openssl_dtls_client openssl_dtls_client.c $(CFLAGS) $(LDFLAGS)

openssl_dtls_server:
	$(CC) -o openssl_dtls_server openssl_dtls_server.c $(CFLAGS) $(LDFLAGS)

openssl_client_tap:
	$(CC) -o openssl_client_tap openssl_client_tap.c -DOPENSSL_SUPPRESS_DEPRECATED -DOPENSSL_ENGINE  -D__RTOS_LINUX__ $(CFLAGS) $(LDFLAGS)

all: openssl_client openssl_client_tpm openssl_dtls_client openssl_dtls_server openssl_client_local openssl_client_tap

all_sw: openssl_client openssl_dtls_client openssl_dtls_server openssl_client_local

.PHONY : clean
clean :
	rm -f openssl_server openssl_client openssl_client_tpm openssl_dtls_client openssl_dtls_server openssl_client_local openssl_client_tap

