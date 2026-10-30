ARG UBUNTU_VERSION=22.04
FROM ubuntu:${UBUNTU_VERSION}

ENV DEBIAN_FRONTEND=noninteractive
ENV TRUSTCORE_ROOT=/opt/trustcore
ENV LD_LIBRARY_PATH=/opt/trustcore/lib

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    git \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/digicert/trustcore.git ${TRUSTCORE_ROOT}

WORKDIR ${TRUSTCORE_ROOT}

RUN cmake -DBUILD_SAMPLES=ON -B build -S . \
    && cmake --build build

EXPOSE 1440
CMD ["./samples/bin/ssl_server", "-ssl_port", "1440", "-ssl_certpath", "/opt/trustcore/keystore", "-ssl_server_cert", "RSACertCA.der", "-ssl_server_keyblob", "RSACertCAKey.pem", "-ssl_servername", "webapptap.securitydemos.net"]