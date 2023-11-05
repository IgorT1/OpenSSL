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

int main() {
    const char* public_key_file = "public_key.pem";
    const char* file_to_verify = "file.txt";
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

    return 0;
}
