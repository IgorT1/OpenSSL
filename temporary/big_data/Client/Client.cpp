#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024
#define DEFAULT_PORT 1235

#define SERVER_ADDRESS "127.0.0.1"

int main() {
    int clientSocket;
    struct sockaddr_in serverAddress;
    char buffer[BUFFER_SIZE];

    // Create socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        std::cerr << "Failed to create socket." << std::endl;
        return -1;
    }

    // Set up server address
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);
    serverAddress.sin_port = htons(DEFAULT_PORT);

    // Connect to the server
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Failed to connect to the server." << std::endl;
        return -1;
    }

    // Open file to read
    std::ifstream inputFile("text.txt", std::ios::binary);
    if (!inputFile) {
        std::cerr << "Failed to open input file." << std::endl;
        return -1;
    }

    // Load public key for encryption
    FILE *publicKeyFile = fopen("server_public_key.pem", "rb");
    if (!publicKeyFile) {
        std::cerr << "Failed to open public key file." << std::endl;
        return -1;
    }

    RSA *rsaPublicKey = PEM_read_RSA_PUBKEY(publicKeyFile, nullptr, nullptr, nullptr);
    fclose(publicKeyFile);

    if (!rsaPublicKey) {
        std::cerr << "Failed to read public key." << std::endl;
        return -1;
    }

    unsigned char plaintextBuffer[BUFFER_SIZE];
    unsigned char encryptedBuffer[RSA_size(rsaPublicKey)];

    // Read and encrypt file contents
    while (!inputFile.eof()) {
        inputFile.read(reinterpret_cast<char *>(plaintextBuffer), BUFFER_SIZE);
        int bytesRead = inputFile.gcount();

        int offset = 0;
        while (offset < bytesRead) {
            int chunkSize = RSA_size(rsaPublicKey) - RSA_PKCS1_PADDING_SIZE;

            // Encrypt a chunk of data
            int encryptedLength = RSA_public_encrypt(chunkSize, plaintextBuffer + offset, encryptedBuffer, rsaPublicKey, RSA_PKCS1_PADDING);
            if (encryptedLength < 0) {
                std::cerr << "Failed to encrypt file chunk." << std::endl;
                return -1;
            }

            // Send the encrypted chunk to the server
            int bytesSent = send(clientSocket, encryptedBuffer, encryptedLength, 0);
            if (bytesSent < 0) {
                std::cerr << "Failed to send encrypted file chunk." << std::endl;
                return -1;
            }

            offset += chunkSize;
        }
    }

    // Send an empty chunk to indicate the end of the file
    int bytesSent = send(clientSocket, nullptr, 0, 0);
    if (bytesSent < 0) {
        std::cerr << "Failed to send end of file indicator." << std::endl;
        return -1;
    }

    inputFile.close();
    close(clientSocket);

    RSA_free(rsaPublicKey);
    ERR_free_strings();

    std::cout << "File sent successfully." << std::endl;

    return 0;
}