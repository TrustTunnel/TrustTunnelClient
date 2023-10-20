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
    mv ./standalone_client/standalone_client /test/

WORKDIR /test/
COPY entrypoint.sh index.js package.json config.conf /test/
RUN npm install

ENTRYPOINT ["./entrypoint.sh"]
