FROM nginx:1.15.0

RUN apt-get update && \
    apt-get -y install curl file gcc gpg libssl-dev pkg-config supervisor wget && \
    wget https://static.rust-lang.org/rustup.sh && \
    chmod +x rustup.sh && \
    ./rustup.sh --disable-sudo

COPY Cargo.* /usr/src/wwww/
COPY keys /usr/src/wwww/keys
COPY www /usr/src/wwww/www
COPY src /usr/src/wwww/src
COPY templates /usr/src/wwww/templates

WORKDIR /usr/src/wwww
RUN cargo install --root .
