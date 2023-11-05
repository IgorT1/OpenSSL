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

int main() {
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddress, clientAddress;
    char buffer[BUFFER_SIZE];

    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Failed to create socket." << std::endl;
        return -1;
    }

    // Set up server address
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(DEFAULT_PORT);

    // Bind socket to the server address
    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Failed to bind socket." << std::endl;
        return -1;
    }

    // Listen for incoming connections
    if (listen(serverSocket, 1) < 0) {
        std::cerr << "Failed to listen for connections." << std::endl;
        return -1;
    }

    socklen_t clientAddressLength = sizeof(clientAddress);

    // Accept a client connection
    clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddressLength);
    if (clientSocket < 0) {
        std::cerr << "Failed to accept client connection." << std::endl;
        return -1;
    }

    // Open file to write decrypted data
    std::ofstream outputFile("decrypted.txt", std::ios::binary);
    if (!outputFile) {
        std::cerr << "Failed to open output file." << std::endl;
        return -1;
    }

    // Load private key for decryption
    FILE *privateKeyFile = fopen("private_key.pem", "rb");
    if (!privateKeyFile) {
        std::cerr << "Failed to open private key file." << std::endl;
        return -1;
    }

    RSA *rsaPrivateKey = PEM_read_RSAPrivateKey(privateKeyFile, nullptr, nullptr, nullptr);
    fclose(privateKeyFile);

    if (!rsaPrivateKey) {
        std::cerr << "Failed to read private key." << std::endl;
        return -1;
    }

    unsigned char encryptedBuffer[BUFFER_SIZE];
    unsigned char decryptedBuffer[BUFFER_SIZE];

    // Receive and decrypt file contents
    int decryptedLength = 0;
    while (true) {
        int bytesRead = recv(clientSocket, encryptedBuffer, BUFFER_SIZE, 0);
        if (bytesRead <= 0) {
            break;  // End of file or error occurred
        }

        int decryptedBytes = RSA_private_decrypt(bytesRead, encryptedBuffer, decryptedBuffer, rsaPrivateKey, RSA_PKCS1_PADDING);
        if (decryptedBytes < 0) {
            std::cerr << "Failed to decrypt file chunk." << std::endl;
            return -1;
        }

        decryptedLength += decryptedBytes;
        outputFile.write(reinterpret_cast<const char *>(decryptedBuffer), decryptedBytes);
    }

    outputFile.close();
    close(clientSocket);
    close(serverSocket);

    RSA_free(rsaPrivateKey);
    ERR_free_strings();

    std::cout << "File received and decrypted successfully." << std::endl;

    return 0;
}