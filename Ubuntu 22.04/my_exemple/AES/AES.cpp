#include <iostream>
#include <fstream>
#include <string>
#include <openssl/aes.h>

using namespace std;

// Function to encrypt a file using AES
void encryptFile(const string& inputFile, const string& outputFile, const string& key) {
    ifstream ifs(inputFile, ios::binary);
    if (!ifs) {
        cerr << "Failed to open input file: " << inputFile << endl;
        return;
    }

    ofstream ofs(outputFile, ios::binary);
    if (!ofs) {
        cerr << "Failed to open output file: " << outputFile << endl;
        return;
    }

    // Convert the key to 256-bit format
    unsigned char aesKey[32];
    fill_n(aesKey, 32, 0); // Fill with null bytes
    copy(key.begin(), key.end(), aesKey);

    // Set up AES encryption context
    AES_KEY aesKeyEnc;
    AES_set_encrypt_key(aesKey, 256, &aesKeyEnc);

    // Encryption buffer
    unsigned char inputBuffer[AES_BLOCK_SIZE];
    unsigned char outputBuffer[AES_BLOCK_SIZE];

    // Encrypt the file
    while (ifs.read(reinterpret_cast<char*>(inputBuffer), AES_BLOCK_SIZE)) {
        AES_encrypt(inputBuffer, outputBuffer, &aesKeyEnc);
        ofs.write(reinterpret_cast<const char*>(outputBuffer), AES_BLOCK_SIZE);
    }

    // Close the files
    ifs.close();
    ofs.close();

    cout << "Encryption completed." << endl;
}

// Function to decrypt a file using AES
void decryptFile(const string& inputFile, const string& outputFile, const string& key) {
    ifstream ifs(inputFile, ios::binary);
    if (!ifs) {
        cerr << "Failed to open input file: " << inputFile << endl;
        return;
    }

    ofstream ofs(outputFile, ios::binary);
    if (!ofs) {
        cerr << "Failed to open output file: " << outputFile << endl;
        return;
    }

    // Convert the key to 256-bit format
    unsigned char aesKey[32];
    fill_n(aesKey, 32, 0); // Fill with null bytes
    copy(key.begin(), key.end(), aesKey);

    // Set up AES decryption context
    AES_KEY aesKeyDec;
    AES_set_decrypt_key(aesKey, 256, &aesKeyDec);

    // Decryption buffer
    unsigned char inputBuffer[AES_BLOCK_SIZE];
    unsigned char outputBuffer[AES_BLOCK_SIZE];

    // Decrypt the file
    while (ifs.read(reinterpret_cast<char*>(inputBuffer), AES_BLOCK_SIZE)) {
        AES_decrypt(inputBuffer, outputBuffer, &aesKeyDec);
        ofs.write(reinterpret_cast<const char*>(outputBuffer), AES_BLOCK_SIZE);
    }

    // Close the files
    ifs.close();
    ofs.close();

    cout << "Decryption completed." << endl;
}

int main() {
    const string inputFile = "input.txt";
    const string encryptedFile = "encrypted.bin";
    const string decryptedFile = "decrypted.txt";
    const string key = "44";

    encryptFile(inputFile, encryptedFile, key);
    decryptFile(encryptedFile, decryptedFile, key);

    return 0;
}