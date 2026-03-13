FROM ubuntu:24.04

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    clang \
    clang-tools \
    libc++-dev \
    libc++abi-dev \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    lldb \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain 1.85 -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install Conan and Python dependencies
RUN python3 -m pip install conan --break-system-packages
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install -r /tmp/requirements.txt --break-system-packages --ignore-installed

WORKDIR /workspace

# Default command: start lldb-server with constrained port range
CMD ["lldb-server", "platform", "--server", "--listen", "*:12345", "--min-gdbserver-port", "12346", "--max-gdbserver-port", "12350"]
