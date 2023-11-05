# FROM alpine:latest
# LABEL maintainer = "Everybody :)"

# COPY . /usr/src/openssl
# WORKDIR /usr/src/openssl

# RUN apk update && \
#     apk upgrade && \
#     apk --update add \
#         g++ \
#         make \
#         openssl-dev \
#         bash \
#     rm -rf /var/cache/apk/* && \
#     make

# ENTRYPOINT ["./Server", "./Client"]

# FROM ubuntu:20.04
# LABEL maintainer="Everybody :)"

# COPY . /usr/src/openssl
# WORKDIR /usr/src/openssl

# RUN apt-get update && \
#     apt-get install -y \
#         g++ \
#         openssl-dev \
#         bash\
#     make
# RUN g++ Server.cpp -o Server ${LIB}
# RUN g++ Client.cpp -o Client ${LIB}

# ENTRYPOINT ["./Server"]

# CMD ["--option", "value"]

# RUN rm -rf ${OBJECTS} ${TERGET}
# RUN rm -rf ${OBJECTS1} ${TERGET1}
# RUN rm -rf ${EXTRA_GEN_FILE}

# Base image
# FROM ubuntu:20.04

# # Set working directory
# WORKDIR /app

# # Install necessary libraries and tools
# RUN apt-get update && apt-get install -y g++ openssl

# # Copy source code into the container
# COPY . /app

# # Compile the Server and Client applications
# RUN g++ Server.cpp -o Server -lssl -lcrypto
# RUN g++ Client.cpp -o Client -lssl -lcrypto

# # Expose any necessary ports
# # EXPOSE <port_number>

# # Start the Server application when the container launches
# CMD ./Server

FROM ubuntu:20.04
LABEL maintainer="Everybody :)"

COPY . /usr/src/openssl_client
WORKDIR /usr/src/openssl_client

RUN apt-get update && \
    apt-get install -y \
        g++ \
        make \
        libssl-dev \
        bash && \
    rm -rf /var/lib/apt/lists/* && \
    make

CMD ["./Client"]
