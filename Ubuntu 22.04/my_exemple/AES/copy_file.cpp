#include <iostream>
#include <fstream>

using namespace std;

int main() {
    ifstream inputFile("cool.mp4", ios::binary);
    ofstream outputFile("output.mp4", ios::binary);

    if (!inputFile) {
        cerr << "Failed to open the input file." << endl;
        return 1;
    }

    if (!outputFile) {
        cerr << "Failed to open the output file." << endl;
        return 1;
    }

    // Отримання розміру вхідного файлу
    inputFile.seekg(0, ios::end);
    streampos fileSize = inputFile.tellg();
    inputFile.seekg(0, ios::beg);

    // Створення буфера для збереження даних
    char* buffer = new char[fileSize];

    // Читання даних з вхідного файлу
    inputFile.read(buffer, fileSize);

    // Запис даних у вихідний файл
    outputFile.write(buffer, fileSize);

    // Звільнення пам'яті та закриття файлів
    delete[] buffer;
    inputFile.close();
    outputFile.close();

    cout << "File copied successfully." << endl;

    return 0;
}