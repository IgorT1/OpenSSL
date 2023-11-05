#include <iostream>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

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
    const char* private_key_file = "private_key.pem";
    const char* file_to_sign = "file.txt";

    // Зчитати дані для підпису з файлу
    string file_data = read_file(file_to_sign);

    // Створити цифровий підпис
    string signature = sign_file(private_key_file, file_data);

    cout<<signature<<endl;

    ofstream file("signature.txt");

    if(file.is_open())
        file << signature;

    // Тепер можна передати файл та його цифровий підпис

    return 0;
}
