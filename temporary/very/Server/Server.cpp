#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <chrono>
#include <thread>

#define BUFFER_SIZE 1024
#define DEFAULT_PORT 1235

using namespace std;

// Функція для зчитування вмісту файлу в строку
string read_file(const char* filename) {
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        cerr << "Не вдалося відкрити файл: " << filename << endl;
        exit(EXIT_FAILURE);
    }

    string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();

    return content;
}

// Функція для перевірки цифрового підпису
bool verify_signature(const char* public_key_file, const string& file_data, const string& signature) {
    FILE* key_file = fopen(public_key_file, "rb");
    if (!key_file) {
        cerr << "Не вдалося відкрити файл з публічним ключем: " << public_key_file << endl;
        exit(EXIT_FAILURE);
    }

    RSA* public_key = PEM_read_RSA_PUBKEY(key_file, nullptr, nullptr, nullptr);
    fclose(key_file);

    if (!public_key) {
        cerr << "Не вдалося зчитати публічний ключ" << endl;
        exit(EXIT_FAILURE);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(file_data.c_str()), file_data.size(), hash);

    if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, reinterpret_cast<const unsigned char*>(signature.c_str()), signature.size(), public_key) != 1) {
        cerr << "Цифровий підпис не валідний" << endl;
        return false;
    }

    RSA_free(public_key);

    cout << "Цифровий підпис валідний" << endl;
    return true;
}

void receiveFile(int socket, const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Unable to create file: " << filename << std::endl;
        exit(1);
    }

    char buffer[BUFFER_SIZE];
    ssize_t bytesRead;
    while ((bytesRead = recv(socket, buffer, BUFFER_SIZE, 0)) > 0) {
        file.write(buffer, bytesRead);
    }

    file.close();
}

void sendAck(int socket) {
    const char* ackMessage = "File received successfully.";
    send(socket, ackMessage, strlen(ackMessage), 0);
}

int main() {

    
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddress, clientAddress;
    char buffer[BUFFER_SIZE];

    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        cerr << "Failed to create socket." << endl;
        return -1;
    }

    // Set up server address
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(DEFAULT_PORT);

    // Bind the socket to the specified IP and port
    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        cerr << "Failed to bind." << endl;
        return -1;
    }

    // Listen for incoming connections
    listen(serverSocket, 1);

    cout << "Server listening on port " << DEFAULT_PORT << "..." << endl;

    // Accept incoming connection
    socklen_t clientAddressLength = sizeof(clientAddress);
    clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddressLength);
    if (clientSocket < 0) {
        cerr << "Failed to accept connection." << endl;
        return -1;
    }



    //###################      Отримання цифрового підпису       #####################################
    std::string filename1 = "received_file1.bin";
    receiveFile(clientSocket, filename1);
    std::cout << "Received file: " << filename1 << std::endl;

    // Відправка підтвердження до клієнта про отримання цифрового підпису
    sendAck(clientSocket);
    std::cout << "Sent acknowledgement for file: " << filename1 << std::endl;

    //##################################### отримання зашифрованого файлу №№№№№№№№№№№№№№№№№№№№№№№


    // Open file to store received and decrypted data
    ofstream file("get_text.txt", ios::binary);
    if (!file) {
        cerr << "Failed to create file." << endl;
        return -1;
    }

    // Receive and decrypt file contents
    int bytesRead;
    while ((bytesRead = recv(clientSocket, buffer, BUFFER_SIZE, 0)) > 0) {
        file.write(buffer, bytesRead);
    }

    if (bytesRead < 0) {
        cerr << "Failed to receive file." << endl;
        return -1;
    }

    // Close the file and sockets
    file.close();
    close(clientSocket);
    close(serverSocket);

    cout << "File received successfully." << endl;



    //###################  перевірка підпису на валідність  ###################################


    const char* public_key_file = "public_key.pem";
    const char* file_to_verify = "get_text.txt";
    const char* signature_file = "signature.txt";

    // Зчитати дані для перевірки з файлу
    string file_data = read_file(file_to_verify);
    string signature = read_file(signature_file);

    // Перевірити цифровий підпис
    bool signature_valid = verify_signature(public_key_file, file_data, signature);

    if (signature_valid) {
        // Дії, якщо підпис валідний
        cout<<"підпис валідний"<<endl;
    } else {
        // Дії, якщо підпис не валідний
        cout<<"підпис не валідний"<<endl;
    }

    //##########################################################




    // Decrypt the received file using RSA
    FILE *privateKeyFile = fopen("private_key.pem", "rb");
    if (!privateKeyFile) {
        cerr << "Failed to open private key file." << endl;
        return -1;
    }

    RSA *rsaPrivateKey = PEM_read_RSAPrivateKey(privateKeyFile, nullptr, nullptr, nullptr);
    fclose(privateKeyFile);

    if (!rsaPrivateKey) {
        cerr << "Failed to read private key." << endl;
        return -1;
    }

    ifstream encryptedFile("get_text.txt", ios::binary);
    if (!encryptedFile) {
        cerr << "Failed to open encrypted file." << endl;
        return -1;
    }

    ofstream decryptedFile("decrypted_text.txt", ios::binary);
    if (!decryptedFile) {
        cerr << "Failed to create decrypted file." << endl;
        return -1;
    }

    while (!encryptedFile.eof()) {
        encryptedFile.read(buffer, BUFFER_SIZE);
        int bytesRead = encryptedFile.gcount();
        unsigned char encryptedBuffer[BUFFER_SIZE];
        memcpy(encryptedBuffer, buffer, bytesRead);

        unsigned char decryptedBuffer[RSA_size(rsaPrivateKey)];
        int decryptedLength = RSA_private_decrypt(bytesRead, encryptedBuffer, decryptedBuffer, rsaPrivateKey, RSA_PKCS1_PADDING);
        if (decryptedLength < 0) {
            cerr << "Failed to decrypt file." << endl;
            return -1;
        }

        decryptedFile.write(reinterpret_cast<char *>(decryptedBuffer), decryptedLength);
    }

    encryptedFile.close();
    decryptedFile.close();

    RSA_free(rsaPrivateKey);
    ERR_free_strings();

    cout << "File decrypted successfully." << endl;


    return 0;
}