#!/bin/bash
################################################################################
# This script generates a patch for official OpenSSL distribution based on the
# source files in the ./thirdparty/${OPENSSL_VER} directory.
#
# The generated patch file (tar.gz) is used by patch-openssl-1.0.2.sh script
# to modify OpenSSL distribution in a way that enables Mocana EVP engine support
# in libcrypto.so
################################################################################
SEP=/
################################################################################
function error_exit()
{
    echo "ERROR: $1"
    exit 1
}

OPENSSL_VER=$1
[ "${OPENSSL_VER}" == "" ] && error_exit "Usage: $0 [openssl-1.0.2i|openssl-1.0.2k|openssl-1.0.2l|openssl-1.0.2n]"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PATCH_DIR=.${SEP}openssl_patch
OPENSSL_SRC_DIR=${DIR}${SEP}..${SEP}..${SEP}thirdparty${SEP}${OPENSSL_VER}
PATCH_TAR_NAME=${DIR}${SEP}${OPENSSL_VER}_patch.tar.gz

[ -d ${OPENSSL_SRC_DIR} ] || error_exit "Directory '${OPENSSL_VER}' was not found!"

# prepare patch dir
rm -rf ${PATCH_DIR}
mkdir -p ${PATCH_DIR}

# copy files
echo ${OPENSSL_VER} > ${PATCH_DIR}${SEP}version.txt
cp ${OPENSSL_SRC_DIR}${SEP}README.MOCANA.txt ${PATCH_DIR}
cp ${OPENSSL_SRC_DIR}${SEP}Makefile.org ${PATCH_DIR}
cp ${OPENSSL_SRC_DIR}${SEP}Configure ${PATCH_DIR}
cp ${OPENSSL_SRC_DIR}${SEP}openssl.ld ${PATCH_DIR}
cp ${OPENSSL_SRC_DIR}${SEP}copy_to_mss_bin.sh ${PATCH_DIR}
cp ${OPENSSL_SRC_DIR}${SEP}crypto${SEP}engine${SEP}eng_all.c ${PATCH_DIR}
cp ${OPENSSL_SRC_DIR}${SEP}crypto${SEP}engine${SEP}engine.h ${PATCH_DIR}
cp ${OPENSSL_SRC_DIR}${SEP}crypto${SEP}ecdsa${SEP}ecdsa.h ${PATCH_DIR}
cp ${OPENSSL_SRC_DIR}${SEP}crypto${SEP}rsa${SEP}rsa.h ${PATCH_DIR}
cp ${OPENSSL_SRC_DIR}${SEP}crypto${SEP}evp${SEP}evp_enc.c ${PATCH_DIR}
cp ${OPENSSL_SRC_DIR}${SEP}crypto${SEP}evp${SEP}digest.c ${PATCH_DIR}
[ -L ${OPENSSL_SRC_DIR}${SEP}engines${SEP}mocana ] && SYMLINK_DIR=L
cp -R${SYMLINK_DIR} ${OPENSSL_SRC_DIR}${SEP}engines${SEP}mocana ${PATCH_DIR}
cp -R${SYMLINK_DIR} ${OPENSSL_SRC_DIR}${SEP}sample ${PATCH_DIR}

# make patch archive
rm -f ${PATCH_TAR_NAME}
tar -cvzf ${PATCH_TAR_NAME} --exclude='*.o' --exclude='.DS_Store' ${PATCH_DIR}

# cleanup
rm -rf ${PATCH_DIR}
