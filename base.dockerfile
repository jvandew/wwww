FROM nginx:1.15.0

RUN apt-get update && \
    apt-get -y install curl file gcc gpg libssl-dev pkg-config supervisor wget && \
    rm -rf /var/lib/apt/lists/* && \
    wget https://static.rust-lang.org/rustup.sh && \
    chmod +x rustup.sh && \
    ./rustup.sh --disable-sudo

COPY Cargo.* /usr/src/wwww/
COPY src /usr/src/wwww/src

WORKDIR /usr/src/wwww
RUN cargo install --root . && \
    rm -rf target
