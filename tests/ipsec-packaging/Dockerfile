FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl iproute2 iptables netcat-openbsd iputils-ping \
        procps python3 tcpdump systemd systemd-sysv \
    && printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d \
    && chmod 0755 /usr/sbin/policy-rc.d \
    && rm -rf /var/lib/apt/lists/*

COPY tests/ipsec-e2e/strongswan.conf /etc/strongswan.conf
CMD ["/sbin/init"]
