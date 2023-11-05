OBJECTS = Server.cpp 

TERGET = Server

CFLAG 	+= -c -fPIC -w

EXTRA_GEN_FILE += \
		private_key.pem \
		server_public_key.pem \


all: ${TERGET} 
${TERGET}:
	g++ ${OBJECTS} -o ${TERGET} -lssl -lcrypto


%.o:%.cpp
	g++ ${CFLAG} $< -o $@ $(LIB)

SHELL := /bin/bash


clean:
	rm -rf ${OBJECTS} ${TERGET} 

deep_clean:
	rm -rf ${OBJECTS} ${TERGET} ${EXTRA_GEN_FILE}


# all: Client Server
# Server:
# 	g++ Server.cpp -o Server -lssl -lcrypto
# Client:
# 	g++ Client.cpp -o Client -lssl -lcrypto
