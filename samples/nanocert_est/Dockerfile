# =============================================================================
# Base Image and Environment Configuration
# =============================================================================
# Ubuntu 22.04 base configured for DigiCert's EST sample application.
# Provides certificate enrollment and management capabilities with
# TPM 2.0 hardware security module support.
# =============================================================================
ARG UBUNTU_VERSION=22.04
FROM ubuntu:${UBUNTU_VERSION}
ENV DEBIAN_FRONTEND=noninteractive
ENV TRUSTCORE_ROOT=/opt/trustcore
ENV PATH="${TRUSTCORE_ROOT}/samples/bin:${PATH}"

# =============================================================================
# System Dependencies
# =============================================================================
# Install build toolchain, cryptographic libraries and TPM-related dependencies
# needed for software TPM emulation and TrustCore.
# =============================================================================
RUN apt-get update && apt-get install -y \
    git cmake build-essential libssl-dev python3 curl \
    dh-autoreconf libtasn1-6-dev pkg-config net-tools iproute2 \
    libjson-glib-dev libgnutls28-dev expect gawk socat libseccomp-dev \
    automake autoconf libtool unzip dos2unix \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# Build libtpms - TPM 2.0 Software Implementation
# =============================================================================
# libtpms provides the core TPM functionality that swtpm uses to emulate
# a Trusted Platform Module in software.
# =============================================================================
RUN git clone https://github.com/stefanberger/libtpms.git /tmp/libtpms && \
    cd /tmp/libtpms && \
    ./autogen.sh --with-openssl --with-tpm2 --prefix=/usr/local && \
    make -j$(nproc) && make install && ldconfig && \
    rm -rf /tmp/libtpms

# =============================================================================
# Build swtpm - Software TPM Emulator
# =============================================================================
# swtpm emulates a TPM device, allowing TPM operations without physical
# hardware. Runs as a daemon listening on TCP ports for TPM commands.
# =============================================================================
RUN git clone https://github.com/stefanberger/swtpm.git /tmp/swtpm && \
    cd /tmp/swtpm && \
    ./autogen.sh --with-openssl --prefix=/usr/local && \
    make -j$(nproc) && make install && ldconfig && \
    rm -rf /tmp/swtpm

# =============================================================================
# Setup User, Group and Directories
# =============================================================================
RUN mkdir -p /etc/digicert
RUN useradd -MU trustedge

# =============================================================================
# Download Architecture-Specific TPM2 Tools
# =============================================================================
# DigiCert provides pre-compiled TPM2 management tools for provisioning and
# configuration. Downloads the appropriate binary package for the target arch.
# =============================================================================
ARG TARGETARCH
RUN ARCH=$(case ${TARGETARCH} in \
        "amd64") echo "x86_64" ;; \
        "arm64") echo "aarch64" ;; \
        "386") echo "x86_32" ;; \
        "arm") echo "arm32" ;; \
        *) echo "aarch64" ;; \
    esac) && \
    curl -L -o /tmp/tpm2_tools.zip "https://github.com/digicert/trustedge/raw/refs/heads/master/tools/SecureElement/tpm2_tools-${ARCH}-24.7.2-3262.zip" && \
    cd /tmp && unzip -o tpm2_tools.zip && unzip -o tpm2_tools-${ARCH}.zip && \
    rm tpm2_tools.zip tpm2_tools-${ARCH}.zip && chmod +x /tmp/bin/*

# =============================================================================
# Build TrustCore with EST and TPM2 Support
# =============================================================================
# Building with:
# - BUILD_SAMPLES: Include example applications (EST client)
# - ENABLE_EST: Enrollment over Secure Transport (RFC 7030)
# - ENABLE_TPM2: TPM 2.0 hardware security module support
# =============================================================================
RUN git clone https://github.com/digicert/trustcore.git ${TRUSTCORE_ROOT}
WORKDIR ${TRUSTCORE_ROOT}

RUN cmake -DBUILD_SAMPLES=ON -DENABLE_EST=ON -DENABLE_TPM2=ON -B build -S . && \
    cmake --build build

# =============================================================================
# Entrypoint Script
# =============================================================================
# Creates a startup script that:
# 1. Launches swtpm daemon on ports 2321/2322 if not running
# 2. Performs one-time TPM provisioning
# 3. Generates TPM configuration file for TrustCore
# 4. Executes the EST sample application with any provided arguments
#
# TPM provisioning includes:
# - Taking ownership with empty passwords (test setup)
# - Creating endorsement key (EK) and storage root key (SRK) with RSA
# - Extracting TPM identifier string for device identification
# =============================================================================
WORKDIR ${TRUSTCORE_ROOT}

# Create symlink to est_sample binary in the working directory
RUN ln -s ${TRUSTCORE_ROOT}/samples/bin/est_sample ${TRUSTCORE_ROOT}/est_sample

RUN printf '#!/bin/bash\n\
set -e\n\
export LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}\n\
CRED_FILE="/etc/digicert/creds.tpm2"\n\
TPM_CONF="/etc/digicert/tpm2.conf"\n\
TPCONF_JSON="/opt/trustcore/keystore/conf/tpconf.json"\n\
\n\
if [ ! -f "${TPCONF_JSON}" ]; then\n\
    mkdir -p /opt/trustcore/keystore/conf\n\
    cat > "${TPCONF_JSON}" <<EOF\n\
{\n\
    "http_proxy": null,\n\
    "root_dir": "${TRUSTCORE_ROOT}",\n\
    "keystore_dir": "${TRUSTCORE_ROOT}/keystore",\n\
    "truststore_dir": "${TRUSTCORE_ROOT}/keystore/ca",\n\
    "conf_dir": "${TRUSTCORE_ROOT}/keystore/conf"\n\
}\n\
EOF\n\
fi\n\
\n\
if ! pgrep -x "swtpm" > /dev/null; then\n\
    mkdir -p /tmp/tpm-state\n\
    swtpm socket --tpm2 --tpmstate dir=/tmp/tpm-state --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init,startup-clear --log file=/tmp/swtpm.log,level=20 --daemon\n\
    sleep 2\n\
fi\n\
if [ ! -f /etc/digicert/.provisioned ]; then\n\
    cd /tmp/bin\n\
    ./digicert_tpm2_takeownership --sm=localhost --ep=2321 --c --credfile="${CRED_FILE}"\n\
    ./digicert_tpm2_takeownership --sm=localhost --ep=2321 --lhpwd= --ehpwd= --shpwd= --credfile="${CRED_FILE}"\n\
    ./digicert_tpm2_provision --sm=localhost --ep=2321 --ekpwd= --srkpwd= --ekalg=rsa --srkalg=rsa --credfile="${CRED_FILE}"\n\
    echo -e "providerType=3" > "${TPM_CONF}"\necho "[module]" >> "${TPM_CONF}"\necho "modulename=localhost" >> "${TPM_CONF}"\necho "moduleport=2321" >> "${TPM_CONF}"\necho "moduleidstr=0000000000000000000000000000000000000000000000000000000000000000" >> "${TPM_CONF}"\necho "modulenum=1" >> "${TPM_CONF}"\necho "credfile=${CRED_FILE}" >> "${TPM_CONF}"\n\
    ./smp_tpm2_getidstr_bin --c ${TPM_CONF} --w\n\
    touch /etc/digicert/.provisioned\n\
fi\n\
cd /opt/trustcore\n\
exec ./est_sample "$@"\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh && dos2unix /entrypoint.sh

# =============================================================================
# Container Runtime Configuration
# =============================================================================
# Expose TPM communication ports (2321=data, 2322=control)
# Default command shows EST sample help if no arguments provided
# =============================================================================
EXPOSE 2321 2322
ENTRYPOINT ["/entrypoint.sh"]
CMD ["--help"]
