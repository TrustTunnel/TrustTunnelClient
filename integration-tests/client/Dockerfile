# syntax=docker/dockerfile:1
FROM common-test-image

ARG CONAN_REPO_URL=""
ARG VPN_LIBS_DIR=vpn-libs

WORKDIR /test/

COPY $VPN_LIBS_DIR /test/$VPN_LIBS_DIR

RUN conan remote add -i 0 art $CONAN_REPO_URL

WORKDIR /test/$VPN_LIBS_DIR/build
RUN cmake .. -DCMAKE_BUILD_TYPE=Release -G "Ninja" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_CXX_COMPILER="clang++" \
        -DCMAKE_CXX_FLAGS="-stdlib=libc++" && \
    ninja standalone_client && \
    mv ./core/standalone_client /test/

COPY entrypoint.sh tun_tests.sh socks_tests.sh /test/

WORKDIR /test/
ENTRYPOINT ["./entrypoint.sh"]
CMD ["endpoint_hostname", "endpoint_ip", "endpoint_ipv6", "protocol", "mode", "socks_port"]
