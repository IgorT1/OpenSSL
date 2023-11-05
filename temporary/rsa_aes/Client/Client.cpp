#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 4096 // Размер буфера для чтения файла
#define AES_KEYLEN 256  // Размер ключа AES в битах
#define AES_BLOCK_SIZE 16
#define DEFAULT_PORT 1234
#define SERVER_ADDRESS "127.0.0.1"

using namespace std;

// Генерация случайного ключа и IV для AES
bool generate_aes_key_iv(unsigned char *aes_key, unsigned char *iv) {
    // Генерация ключа
    if (!RAND_bytes(aes_key, AES_KEYLEN / 8)) {
        cerr << "Ошибка при генерации ключа AES." << endl;
        return false;
    }
    // Генерация IV
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        cerr << "Ошибка при генерации IV AES." << endl;
        return false;
    }
    return true;
}

int main() {
    int clientSocket;
    struct sockaddr_in serverAddress;
    char buffer[BUFFER_SIZE];

    // Создание сокета
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        cerr << "Не удалось создать сокет." << endl;
        return -1;
    }

    // Настройка адреса сервера
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(DEFAULT_PORT);
    if (inet_pton(AF_INET, SERVER_ADDRESS, &serverAddress.sin_addr) <= 0) {
        cerr << "Неверный адрес/адрес не поддерживается." << endl;
        return -1;
    }

    // Подключение к серверу
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        cerr << "Не удалось подключиться к серверу." << endl;
        return -1;
    }

    // Генерация AES ключа и IV
    unsigned char aes_key[AES_KEYLEN / 8];
    unsigned char iv[AES_BLOCK_SIZE];
    if (!generate_aes_key_iv(aes_key, iv)) {
        cerr << "Не удалось сгенерировать ключ и IV для AES." << endl;
        return -1;
    }

    // Чтение и шифрование файла
    ifstream file("text.txt", ios::binary);
    if (!file) {
        cerr << "Не удалось открыть файл." << endl;
        return -1;
    }

    // Открытие файла с публичным ключом RSA
    FILE *publicKeyFile = fopen("server_public_key.pem", "rb");
    if (!publicKeyFile) {
        cerr << "Не удалось открыть файл с публичным ключом." << endl;
        return -1;
    }

    RSA *rsaPublicKey = PEM_read_RSA_PUBKEY(publicKeyFile, nullptr, nullptr, nullptr);
    fclose(publicKeyFile);

    if (!rsaPublicKey) {
        cerr << "Ошибка при чтении публичного ключа." << endl;
        return -1;
    }

    // Шифрование ключа AES с помощью RSA
    unsigned char encryptedAesKey[RSA_size(rsaPublicKey)];
    int encryptedKeyLen = RSA_public_encrypt(AES_KEYLEN / 8, aes_key, encryptedAesKey, rsaPublicKey, RSA_PKCS1_OAEP_PADDING);
    if (encryptedKeyLen == -1) {
        cerr << "Ошибка при шифровании ключа AES: " << ERR_error_string(ERR_get_error(), NULL) << endl;
        return -1;
    }

    // Отправка зашифрованного ключа AES
    send(clientSocket, encryptedAesKey, encryptedKeyLen, 0);

    // Шифрование и отправка IV
    send(clientSocket, iv, AES_BLOCK_SIZE, 0);

    // Шифрование файла с помощью AES и отправка
    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, AES_KEYLEN, &enc_key);

    unsigned char encryptedData[BUFFER_SIZE + AES_BLOCK_SIZE];
    int blockSize = 0;

    while (!file.eof()) {
        file.read(buffer, BUFFER_SIZE);
        streamsize bytesRead = file.gcount();

        // Добавляем паддинг, если это конец файла
        if (file.eof()) {
            blockSize = AES_BLOCK_SIZE - (bytesRead % AES_BLOCK_SIZE);
            memset(buffer + bytesRead, blockSize, blockSize);
            bytesRead += blockSize;
        }

        AES_cfb128_encrypt((unsigned char*)buffer, encryptedData, bytesRead, &enc_key, iv, &blockSize, AES_ENCRYPT);

        // Отправляем зашифрованные данные
        send(clientSocket, encryptedData, bytesRead, 0);
    }

    // Освобождение ресурсов
    file.close();
    close(clientSocket);
    RSA_free(rsaPublicKey);

    cout << "Файл успешно отправлен." << endl;

    return 0;
}
