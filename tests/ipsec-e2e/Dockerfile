FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl iproute2 iptables nftables netcat-openbsd iputils-ping procps \
        python3 libstrongswan-standard-plugins strongswan-charon strongswan-swanctl tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/verify-ipsec-linux.sh /usr/local/bin/verify-ipsec-linux
COPY tests/ipsec-e2e/strongswan.conf /etc/strongswan.conf
RUN chmod 0755 /usr/local/bin/verify-ipsec-linux

CMD ["sleep", "infinity"]
