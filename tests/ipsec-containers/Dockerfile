FROM golang:1.24-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . .

CMD ["go", "test", "./internal/ipsec", "-run", "TestFirewallKernelEnforcement", "-count=1", "-v"]
