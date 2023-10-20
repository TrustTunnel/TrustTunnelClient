# syntax=docker/dockerfile:1
FROM adguard/core-libs:1.20

# Install the required utilities
RUN apt update --allow-releaseinfo-change && \
    apt install -y build-essential cmake curl git gnupg lsb-release iperf3 iproute2 \
    net-tools software-properties-common wget nano iputils-ping iptables tcpdump jq

# Install gocurl
RUN go install github.com/ameshkov/gocurl@latest

CMD bash
