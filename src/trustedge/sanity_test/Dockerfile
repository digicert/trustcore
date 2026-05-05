FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y \
    sudo \
    systemd \
    systemd-sysv \
    less \
    protobuf-compiler \
    jq \
    python3 \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install requests
RUN cd /lib/systemd/system/sysinit.target.wants/ && \
    rm $(ls | grep -v systemd-tmpfiles-setup)
RUN rm -f /lib/systemd/system/multi-user.target.wants/* \
    /etc/systemd/system/*.wants/* \
    /lib/systemd/system/local-fs.target.wants/* \
    /lib/systemd/system/sockets.target.wants/*udev* \
    /lib/systemd/system/sockets.target.wants/*initctl* \
    /lib/systemd/system/basic.target.wants/* \
    /lib/systemd/system/anaconda.target.wants/*
VOLUME ["/sys/fs/cgroup"]
CMD ["/sbin/init"]
