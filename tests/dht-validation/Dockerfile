FROM ubuntu:22.04
COPY dht-validation.test /usr/local/bin/dht-validation.test
ENTRYPOINT ["/usr/local/bin/dht-validation.test", "-test.v", "-test.timeout=3m"]
