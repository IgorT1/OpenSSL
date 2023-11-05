#include <iostream>
#include <fstream>
#include <string>
#include <openssl/aes.h>

using namespace std;


void encryptFile(const  string& inputFile, const  string& outputFile, const  string& key) {
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

     cout << "Encryption completed." <<  endl;
}


int main() {
    const  string inputFile = "input.txt";
    const  string encryptedFile = "encrypted.bin";
    const  string key = "76";

    encryptFile(inputFile, encryptedFile, key);
    system("less encrypted.bin");

    return 0;
}