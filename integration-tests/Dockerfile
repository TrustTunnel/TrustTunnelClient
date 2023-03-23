# syntax=docker/dockerfile:1
FROM adguard/core-libs:1.16

# Install the required utilities
RUN apt update && \
    apt install -y build-essential cmake curl git gnupg lsb-release iperf3 iproute2 \
    net-tools software-properties-common wget nano iputils-ping iptables

CMD bash
