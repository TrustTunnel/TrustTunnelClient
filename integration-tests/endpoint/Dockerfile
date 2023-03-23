# syntax=docker/dockerfile:1
FROM common-test-image

ARG ENDPOINT_DIR="vpn-libs-endpoint"
ARG ENDPOINT_HOSTNAME="endpoint.test"
ARG CONFIG_FILE="vpn.conf"
ARG TLS_HOSTS_SETTINGS_FILE="tls_hosts.conf"
ARG LOG_LEVEL="info"

RUN apt install -y openssl

COPY $ENDPOINT_DIR /test/$ENDPOINT_DIR

WORKDIR /test/
RUN cd "$ENDPOINT_DIR" && \
    cargo build --release --bin vpn_endpoint && \
    mv ./target/release/vpn_endpoint /test/ && \
    cd examples/my_vpn && \
    openssl req -config openssl.conf -new -x509 -sha256 -newkey rsa:2048 -nodes -days 1000 \
        -keyout /test/key.pem -out /test/cert.pem \
        -subj "/C=de/CN=$ENDPOINT_HOSTNAME" \
        -addext "subjectAltName = DNS:*.$ENDPOINT_HOSTNAME"

RUN echo "{\n\
  \"listen_address\": \"[::]:4433\",\n\
  \"allow_private_network_connections\": true,\n\
  \"ipv6_available\": true, \n\
  \"listen_protocols\": [\n\
    {\n\
      \"http1\": {}\n\
    },\n\
    {\n\
      \"http2\": {}\n\
    },\n\
    {\n\
      \"quic\": {}\n\
    }\n\
  ],\n\
  \"icmp\": {\n\
    \"interface_name\": \"eth0\" \n\
  } \n\
}" >>$CONFIG_FILE

RUN echo "{\n\
  \"tunnel_hosts\": [\n\
    {\n\
      \"hostname\": \"$ENDPOINT_HOSTNAME\",\n\
      \"cert_chain_path\": \"cert.pem\",\n\
      \"private_key_path\": \"key.pem\"\n\
    }\n\
  ]\n\
}" >>$TLS_HOSTS_SETTINGS_FILE

ENV LOG_LEVEL=$LOG_LEVEL \
    CONFIG_FILE=$CONFIG_FILE \
    TLS_HOSTS_SETTINGS_FILE=$TLS_HOSTS_SETTINGS_FILE \
    RUST_BACKTRACE=1
ENTRYPOINT ./vpn_endpoint -l "$LOG_LEVEL" "$CONFIG_FILE" "$TLS_HOSTS_SETTINGS_FILE" >> /tmp/vpn.log 2>&1
