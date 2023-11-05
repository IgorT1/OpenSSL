//необходимые библиотеки 
#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024 //размер буфера который будем использовать 
#define DEFAULT_PORT 1234//и наш дефолтный порт(при не выполнения кода лучше поменять вдруг занят )

using namespace std;//так удобнее использование пространста имен 

int main() {


    //######################### creat socket #######################################################

    int serverSocket, clientSocket; //Дескриптор или же абстракция 
    struct sockaddr_in serverAddress, clientAddress;
    char buffer[BUFFER_SIZE];//основной буфер 

   
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);//создание потокового сокету IPv4 симейства с автоматичесой подбором протокола 
    if (serverSocket == -1) {                      //это означает, что сокет не получилось создать 
        cerr << "Failed to create socket." << endl;
        return -1;
    }

    serverAddress.sin_family = AF_INET;      //определение симейства 
    serverAddress.sin_addr.s_addr = INADDR_ANY; //присвоение к доступному адресу на устройстве 
    serverAddress.sin_port = htons(DEFAULT_PORT); //преобразование в сетевой порядок битов порт 


    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {  //установление соединения 
        cerr << "Failed to bind." << endl;
        return -1;
    }

    //##################################################################################################

  
    listen(serverSocket, 3); // ожидание соединения (прослушивание) ,есть возможность подклюсчения нескольких пользователей(to be continued )
    cout << "Сервер(первый пользователь) слушает порт : " << DEFAULT_PORT << "..." << endl;


     //переменная для сохронение размера структуры 
    socklen_t clientAddressLength = sizeof(clientAddress);
    
     //блокирует выполнение кода пока не будет установлено соединение, 
    clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddressLength); //clientSocket будет заполненно информацией о клиенте 
    if (clientSocket < 0) {
        cerr << "Failed to accept connection." << endl;
        return -1;
    }

    ofstream file("get_text.txt", ios::binary); //создание объекта file для зариси пинятого файла по битово, что дает возможность приема файлов разного формата  
    if (!file) {
        cerr << "ошибка создания файла ." << endl;
        return -1;
    }

 
    int bytesRead;//сохранение количество полученый байтов 
    while ((bytesRead = recv(clientSocket, buffer, BUFFER_SIZE, 0)) > 0) { //получение байтов от клиента buffer, размер для получения BUFFER_SIZE
        file.write(buffer, bytesRead);//записывания в файл байтов определенного размера 
    }

    if (bytesRead < 0) {
        cerr << "ошибка получения  ." << endl;
        return -1;
    }

    // Закрытие файла и сокетов 
    file.close();
    close(clientSocket);
    close(serverSocket);

    cout << "файл успешно записан ." << endl;

    // Разшифровка полученого файла с помошью RSA приватныым ключом 
    FILE *privateKeyFile = fopen("private_key.pem", "rb");//считани е в бинарном виде ключа приватного 
    if (!privateKeyFile) {
        cerr << "Ошибка открытия секретного ключа ." << endl;
        return -1;
    }

    RSA *rsaPrivateKey = PEM_read_RSAPrivateKey(privateKeyFile, nullptr, nullptr, nullptr); //сохранение ключа в переменную типа  RSA
    fclose(privateKeyFile);//особождаем память 

    if (!rsaPrivateKey) {
        cerr << "Ошибка считания секретного ключа ." << endl;
        return -1;
    }

    ifstream encryptedFile("get_text.txt", ios::binary);//считование данных с файла для расшифровки 
    if (!encryptedFile) {
        cerr << "Ошибка открытия зашифрованого файла ." << endl;
        return -1;
    }

    ofstream decryptedFile("decrypted_text.txt", ios::binary);//создание файла в который будет записана расшифрованая информация 
    if (!decryptedFile) {
        cerr << "Ошибка создания расшифрованого файла " << endl;
        return -1;
    }



    //################################# разшифровка   ##################################################

    //цикл для поэтапного читания и расшифровки 
    while (!encryptedFile.eof()) {//пока нету конца файла 
        encryptedFile.read(buffer, BUFFER_SIZE);//считание до BческоеUFFER_SIZE и запись в buffer
        int bytesRead = encryptedFile.gcount();//фактитическое количество байт 
        unsigned char encryptedBuffer[BUFFER_SIZE]; //беззнаковая переменная которая хранит считаные байти 
        memcpy(encryptedBuffer, buffer, bytesRead);//копирует сичитаные байты в encryptedBuffer

        unsigned char decryptedBuffer[RSA_size(rsaPrivateKey)];//безнаковвый буфер для 
        int decryptedLength = RSA_private_decrypt(bytesRead, encryptedBuffer, decryptedBuffer, rsaPrivateKey, RSA_PKCS1_PADDING);//разшифровка с указанием режима заполнения 
        if (decryptedLength < 0) {
            cerr << "Ошибка разшифровки файла ." << endl;
            return -1;
        }

        decryptedFile.write(reinterpret_cast<char *>(decryptedBuffer), decryptedLength);//записывание преобразованых байт в char 
    }


    //##################################################################################################

    //закрытие файлов 
    encryptedFile.close();
    decryptedFile.close();

    //освобождение памяти и ресурсов 
    RSA_free(rsaPrivateKey);
    ERR_free_strings();

    cout << "Файл успешно расшифрован ." << endl;


    return 0;
}