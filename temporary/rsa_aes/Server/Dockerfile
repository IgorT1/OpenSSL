

FROM ubuntu:20.04
LABEL maintainer="Everybody :)"

COPY . /usr/src/openssl_server
WORKDIR /usr/src/openssl_server

RUN apt-get update && \
    apt-get install -y \
        g++ \
        make \
        libssl-dev \
        bash && \
    rm -rf /var/lib/apt/lists/* && \
    make


CMD ["./Server"]
