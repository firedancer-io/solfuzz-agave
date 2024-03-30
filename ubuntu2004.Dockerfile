FROM ubuntu:20.04
RUN apt-get update
RUN apt-get install -y \
    build-essential \
    curl \
    protobuf-compiler
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y --default-toolchain none
ENV PATH="/root/.cargo/bin:${PATH}"
COPY . /app
WORKDIR /app
RUN make
