#include <iostream>
#include <fstream>
#include <string>
#include <openssl/aes.h>

using namespace std;


// Function to decrypt a file using AES
void decryptFile(const  string& inputFile, const  string& outputFile, const  string& key) {
     ifstream ifs(inputFile,  ios::binary);
    if (!ifs) {
         cerr << "Failed to open input file: " << inputFile <<  endl;
        return;
    }

     ofstream ofs(outputFile,  ios::binary);
    if (!ofs) {
         cerr << "Failed to open output file: " << outputFile <<  endl;
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

     cout << "Decryption completed." <<  endl;
}

int main() {

    const  string encryptedFile = "encrypted.bin";
    const  string decryptedFile = "decrypted.txt";
    const  string key = "76";

    decryptFile(encryptedFile, decryptedFile, key);

    return 0;
}