INCDIR= .
IDIR= ./include
CC= gcc
CFLAGS= -I$(IDIR) -g -O0
ODIR= obj
LDIR= ../../../bin_static
LIB_DIR= ../../../lib
SRC= ./src
MKDIR_P= @mkdir -p $(@D)
SYSLIBS= -lpthread -ldl -lrt
LIBSOPENSSL= -lssl -lcrypto
LIBSNANOSSL_STATIC= $(LDIR)/libopenssl_shim.a $(LDIR)/libnanossl.a $(LDIR)/libcrypto.a $(LDIR)/libnanocrypto.a
LIBSNANOSSL_SHARED= -L$(LIB_DIR) -lssl -lnanossl -lcrypto

_DEPS= main.h
DEPS= $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ= logger.o common.o client.o server.o main.o
OBJ= $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%.o: $(SRC)/%.c $(DEPS)
	$(MKDIR_P)
	$(CC) -g -c -o $@ $< $(CFLAGS)

all: clean test_openssl test_openssl_shim_static test_openssl_shim

# This target links to system copy of libssl and libcrypto
test_openssl: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBSOPENSSL) $(SYSLIBS)

# This target statically links with libssl/libcrypto - it could be handy for use
# with debugger
test_openssl_shim_static: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBSNANOSSL_STATIC) $(SYSLIBS)

# This target links to system copy of libssl.so (which should be statically
# linked with libcrypto) - this should be easiest way to test and swap libssl.so
# as needed without re-compiling the binary
test_openssl_shim: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBSNANOSSL_SHARED) $(SYSLIBS)

.PHONY: clean

clean:
	rm -rf $(ODIR)/ $(INCDIR)/*~ test_openssl*

