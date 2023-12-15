FROM common-test-image

ARG CONAN_REPO_URL=""
ARG VPN_LIBS_DIR=vpn-libs

WORKDIR /test/

COPY $VPN_LIBS_DIR /test/$VPN_LIBS_DIR

RUN conan remote add --index 0 art ${CONAN_REPO_URL}

WORKDIR /test/$VPN_LIBS_DIR/build
RUN export LDFLAGS=-fuse-ld=lld && cmake ..  \
        -DCMAKE_BUILD_TYPE=Release -G "Ninja" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_CXX_COMPILER="clang++" \
        -DCMAKE_CXX_FLAGS="-stdlib=libc++" \
        -DCONAN_HOST_PROFILE="default;auto-cmake" && \
    ninja standalone_client && \
    mv ./standalone/standalone_client /test/

WORKDIR /test/
COPY entrypoint.sh index.js package.json config.conf /test/
RUN npm install

ENTRYPOINT ["./entrypoint.sh"]
