FROM ubuntu:20.04
RUN apt-get update
RUN apt-get install -y \
    build-essential \
    curl \
    protobuf-compiler
RUN apt update
RUN apt install -y git
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y --default-toolchain none
RUN sh -c "$(curl -sSfL https://release.solana.com/v1.18.4/install)"
ENV PATH="/root/.local/share/solana/install/active_release/bin:/root/.cargo/bin:${PATH}"
