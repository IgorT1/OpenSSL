//конечно можно использовать хедоры, но для облегчения сборки и создание Docker образа код немного громадский 
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
#define DEFAULT_PORT 1234
#define SERVER_ADDRESS "127.0.0.1"//так как работаею на локальной машины используем localhost

using namespace std;

int main() {

    //######################### creat socket #############################################
    int clientSocket;//дескриптор 
    struct sockaddr_in serverAddress; //структура 
    char buffer[BUFFER_SIZE];//буфер 


    clientSocket = socket(AF_INET, SOCK_STREAM, 0);//создание сокета 
    if (clientSocket == -1) {
        cerr << "Ошибка создания сокета " << endl;
        return -1;
    }

    // Настраиваем адрес
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(DEFAULT_PORT);
    if (inet_pton(AF_INET, SERVER_ADDRESS, &(serverAddress.sin_addr)) <= 0) {
        cerr << "Invalid address." << endl;
        return -1;
    }

    //#################################################################################3########

    // подключение к сереверу  
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        cerr << "Ошибка подключение к серверу " << endl;
        return -1;
    }

    // Откритие файла который будем шифровать для отправки 
    ifstream file("text.txt", ios::binary);
    if (!file) {
        cerr << "Ошибка открития файла ." << endl;
        return -1;
    }

    // Зашифрование и отправка файла 
    FILE *publicKeyFile = fopen("server_public_key.pem", "rb");//считиваем публичный ключ 
    if (!publicKeyFile) {
        cerr << "Ошибка открытия файла для считывания ПК." << endl;
        return -1;
    }

    RSA *rsaPublicKey = PEM_read_RSA_PUBKEY(publicKeyFile, nullptr, nullptr, nullptr);//считывание публичного ключа типа RSA
    fclose(publicKeyFile);

    if (!rsaPublicKey) {
        cerr << "Публичный ключ не считан" << endl;
        return -1;
    }

    //#################### зашифрование и отправка информации ########################################

    while (!file.eof()) {//цикл определяюший конец файла 
        file.read(buffer, BUFFER_SIZE);//считание файла в буфер размером BUFFER_SIZE
        int bytesRead = file.gcount();//фактическоке количества считаный байт 
        unsigned char plaintextBuffer[BUFFER_SIZE]; //беззнаковая переменая в которой будут хранится считанй байти с файла  
        memcpy(plaintextBuffer, buffer, bytesRead);//копирование считаного буфера в plaintextBuffer

        unsigned char encryptedBuffer[RSA_size(rsaPublicKey)]; //буфер размера ключа 
        int encryptedLength = RSA_public_encrypt(bytesRead, plaintextBuffer, encryptedBuffer, rsaPublicKey, RSA_PKCS1_PADDING); //шифрование 
        //PKCS #1 является первым из семейства стандартов, называемых Стандартами криптографии с открытым ключом, опубликованных RSA Laboratories.
        // Он содержит основные определения и рекомендации по реализации алгоритма RSA для криптографии с открытым ключом.
        if (encryptedLength < 0) {
            cerr << "Ошибка зашифрования файла." << endl;
            return -1;
        }

        send(clientSocket, encryptedBuffer, encryptedLength, 0);//отправка шашифрованой информации, ее размера, через сокет clientSocket
    }

    //##################################################################################################

    //закрытие файла и освобождение ресурсов и памяти 

    file.close();
    close(clientSocket);

    RSA_free(rsaPublicKey);
    ERR_free_strings();

    cout << "File sent successfully." << endl;


    return 0;
}