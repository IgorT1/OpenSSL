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


#include <string>


#define BUFFER_SIZE 1024
#define DEFAULT_PORT 1235
#define SERVER_ADDRESS "127.0.0.1"

using namespace std;

void sendFile(int socket, const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        cerr << "Unable to open file: " << filename << endl;
        exit(1);
    }

    char buffer[BUFFER_SIZE];
    while (!file.eof()) {
        file.read(buffer, BUFFER_SIZE);
        ssize_t bytesRead = file.gcount();
        send(socket, buffer, bytesRead, 0);
    }

    file.close();
}

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

// Функція для створення цифрового підпису
string sign_file(const char* private_key_file, const string& file_data) {
    FILE* key_file = fopen(private_key_file, "rb");
    if (!key_file) {
        cerr << "Не вдалося відкрити файл з приватним ключем: " << private_key_file << endl;
        exit(EXIT_FAILURE);
    }

    RSA* private_key = PEM_read_RSAPrivateKey(key_file, nullptr, nullptr, nullptr);
    fclose(key_file);

    if (!private_key) {
        cerr << "Не вдалося зчитати приватний ключ" << endl;
        exit(EXIT_FAILURE);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(file_data.c_str()), file_data.size(), hash);

    unsigned char signature[RSA_size(private_key)];
    unsigned int signature_length;

    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &signature_length, private_key) != 1) {
        cerr << "Не вдалося підписати дані" << endl;
        exit(EXIT_FAILURE);
    }

    RSA_free(private_key);

    return string(reinterpret_cast<char*>(signature), signature_length);
}

int main() {

    int clientSocket;
    struct sockaddr_in serverAddress;
    char buffer[BUFFER_SIZE];

    // Create socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        cerr << "Failed to create socket." << endl;
        return -1;
    }

    // Set up server address
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(DEFAULT_PORT);
    if (inet_pton(AF_INET, SERVER_ADDRESS, &(serverAddress.sin_addr)) <= 0) {
        cerr << "Invalid address." << endl;
        return -1;
    }

    // Connect to the server
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        cerr << "Failed to connect to the server." << endl;
        return -1;
    }

    // Open file to send encгrypted data
    ifstream file("text.txt", ios::binary);
    if (!file) {
        cerr << "Failed to open file." << endl;
        return -1;
    }

    // Encrypt and send file contents
    FILE *publicKeyFile = fopen("server_public_key.pem", "rb");
    if (!publicKeyFile) {
        cerr << "Failed to open public key file." << endl;
        return -1;
    }

    RSA *rsaPublicKey = PEM_read_RSA_PUBKEY(publicKeyFile, nullptr, nullptr, nullptr);
    fclose(publicKeyFile);

    if (!rsaPublicKey) {
        cerr << "Failed to read public key." << endl;
        return -1;
    }





    //##################### створення зашифрованого текстового файла  ################
    while (!file.eof()) {
        file.read(buffer, BUFFER_SIZE);
        int bytesRead = file.gcount();
        unsigned char plaintextBuffer[BUFFER_SIZE];
        memcpy(plaintextBuffer, buffer, bytesRead);

        unsigned char encryptedBuffer[RSA_size(rsaPublicKey)];
        int encryptedLength = RSA_public_encrypt(bytesRead, plaintextBuffer, encryptedBuffer, rsaPublicKey, RSA_PKCS1_PADDING);
        if (encryptedLength < 0) {
            cerr << "Failed to encrypt file." << endl;
            return -1;
        }

        const char* encryptedFile = "encryption_file.bin";

        // Відкрийте файл для запису в бінарному режимі
        ofstream encryptedOutput(encryptedFile, std::ios::binary);

        // Перевірте, чи файл успішно відкрито
        if (!encryptedOutput) {
            cerr << "Не вдалося відкрити файл для запису зашифрованих даних." << std::endl;
            return 1; // Повернення коду помилки
        }

        // Запишіть зашифровані дані у файл
        encryptedOutput.write(reinterpret_cast<const char*>(encryptedBuffer), encryptedLength);

        // Закрийте файл після запису
        encryptedOutput.close();

        //send(clientSocket, encryptedBuffer, encryptedLength, 0);
    }


    //################## створення цифрового підпису ###############################

    const char* private_key_file = "private_key.pem";
    const char* file_to_sign = "encryption_file.bin";

    // Зчитати дані для підпису з файлу
    string file_data = read_file(file_to_sign);

    // Створити цифровий підпис
    string signature = sign_file(private_key_file, file_data);

    cout<<signature<<endl;

    ofstream file_signature("signature.bin");

    if(file_signature.is_open())
        file_signature << signature;
    

    //###########################################################

            // Відправка цифрового підпису
    string filename1 = "signature.bin";
    sendFile(clientSocket, filename1);
    cout << "Sent file: " << filename1 << endl;

    // Отримання підтвердження від сервера про отримання першого файлу
    char ackBuffer[BUFFER_SIZE];
    ssize_t bytesRead = recv(clientSocket, ackBuffer, BUFFER_SIZE, 0);
    if (bytesRead > 0) {
        cout << "Received acknowledgement from the server for file: " << filename1 << endl;
    }


   // ##################### ###########################################################

               // Відправка другого файлу
    string filename2 = "encryption_file.bin";
    sendFile(clientSocket, filename2);
    cout << "Sent file: " << filename2 << endl;

    //##################################################

    file.close();
    close(clientSocket);

    RSA_free(rsaPublicKey);
    ERR_free_strings();

    cout << "File sent successfully." << endl;


    return 0;
}