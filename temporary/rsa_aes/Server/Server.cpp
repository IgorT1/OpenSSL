
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

#define BUFFER_SIZE 4096 // Размер буфера для чтения файла
#define AES_KEYLEN 256  // Размер ключа AES в битах
#define AES_BLOCK_SIZE 16
#define DEFAULT_PORT 1234
#define SERVER_ADDRESS "127.0.0.1"

using namespace std;

int main() {
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrSize;
    unsigned char buffer[BUFFER_SIZE];

    // Создание сокета
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        cerr << "Не удалось создать сокет." << endl;
        return -1;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(DEFAULT_PORT);
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);

    // Привязка сокета
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        cerr << "Ошибка привязки." << endl;
        close(serverSocket);
        return -1;
    }

    // Слушаем подключения
    if (listen(serverSocket, 1) < 0) {
        cerr << "Ошибка при попытке прослушивания." << endl;
        close(serverSocket);
        return -1;
    }

    cout << "Ожидание подключений..." << endl;

    addrSize = sizeof(clientAddr);
    clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &addrSize);
    if (clientSocket < 0) {
        cerr << "Ошибка при попытке принять подключение." << endl;
        close(serverSocket);
        return -1;
    }

    cout << "Клиент подключен." << endl;

    // Чтение публичного ключа RSA
    FILE *privateKeyFile = fopen("private_key.pem", "rb");
    if (!privateKeyFile) {
        cerr << "Не удалось открыть файл с приватным ключом." << endl;
        close(clientSocket);
        return -1;
    }

    RSA *rsaPrivateKey = PEM_read_RSAPrivateKey(privateKeyFile, nullptr, nullptr, nullptr);
    fclose(privateKeyFile);

    if (!rsaPrivateKey) {
        cerr << "Ошибка при чтении приватного ключа." << endl;
        close(clientSocket);
        return -1;
    }

    // Получение и расшифровка ключа AES
    unsigned char encryptedAesKey[RSA_size(rsaPrivateKey)];
    unsigned char aes_key[AES_KEYLEN / 8];
    recv(clientSocket, encryptedAesKey, sizeof(encryptedAesKey), 0);
    RSA_private_decrypt(RSA_size(rsaPrivateKey), encryptedAesKey, aes_key, rsaPrivateKey, RSA_PKCS1_OAEP_PADDING);

    // Получение IV
    unsigned char iv[AES_BLOCK_SIZE];
    recv(clientSocket, iv, AES_BLOCK_SIZE, 0);

    // Подготовка к дешифрованию
    ofstream encryptedFile("encryption.txt", ios::binary | ios::out);
    if (!encryptedFile) {
        cerr << "Не удалось открыть файл для записи зашифрованных данных." << endl;
        close(clientSocket);
        RSA_free(rsaPrivateKey);
        return -1;
    }

    // Получение и запись зашифрованных данных
    int bytesReceived = 0;
    while ((bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0)) > 0) {
        encryptedFile.write(reinterpret_cast<char*>(buffer), bytesReceived);
    }
    encryptedFile.close();

    // Закрытие сокета клиента
    close(clientSocket);

    // Открытие зашифрованного файла
    ifstream encryptedFileIn("encryption.txt", ios::binary | ios::in);
    ofstream decryptedFile("decrypted_text.txt", ios::binary | ios::out);

    if (!encryptedFileIn) {
        cerr << "Не удалось открыть файл для чтения зашифрованных данных." << endl;
        RSA_free(rsaPrivateKey);
        return -1;
    }

    if (!decryptedFile) {
        cerr << "Не удалось открыть файл для записи расшифрованных данных." << endl;
        RSA_free(rsaPrivateKey);
        return -1;
    }

    // Расшифровка данных
    AES_KEY dec_key;
    AES_set_decrypt_key(aes_key, AES_KEYLEN, &dec_key);


while (!encryptedFileIn.eof()) {
        encryptedFileIn.read(reinterpret_cast<char*>(buffer), BUFFER_SIZE);
        streamsize bytesRead = encryptedFileIn.gcount();

        if (bytesRead > 0) {
            AES_cfb128_encrypt(buffer, buffer, bytesRead, &dec_key, iv, &bytesReceived, AES_DECRYPT);
            decryptedFile.write(reinterpret_cast<char*>(buffer), bytesRead);
        }
    }

    // Закрытие файлов
    decryptedFile.close();
    encryptedFileIn.close();

    // Очистка и выход
    RSA_free(rsaPrivateKey);
    close(serverSocket);
    cout << "Файл успешно расшифрован и сохранён." << endl;

    return 0;
}