#include <iostream> 
#include <vector> 
#include <random> 

#include <algorithm>
#include <experimental/iterator>
#include <iterator>
 
// Функція для обчислення степені числа a за модулем p 
using namespace std;


int modPow(int b, int b_, int a) {
    int c = 1;
    b = b % a; // Ensure base is within the modulus

    while (b_ > 0) {
        // If exponent is odd, multiply result with base
        if (b_ % 2 == 1)
            c = (c * b) % a;
        // Now exponent must be even
        b_ = b_ >> 1; // Divide exponent by 2
        b = (b * b) % a;
    }
    return c;
}

 
// Функція для генерації випадкового числа від 2 до p-1 
int generateRandomNumber(int p) { 
    random_device rd; 
    mt19937 generator(rd()); 
 
    uniform_int_distribution<int> distribution(2, p - 1); 
    return distribution(generator); 
} 
 
int main() { 
    int p = 103; // Модуль поля 
    vector<vector<int>> generatorsMatrix; 
 
    for (int g = 2; g < p; g++) { 
        bool isGenerator = true; 
        vector<bool> used(p, false); 
 
        for (int i = 1; i < p; i++) { 
            int value = modPow(g, i, p); 
            if (used[value]) { 
                isGenerator = false; 
                break; 
            } 
            used[value] = true; 
        } 
 
        if (isGenerator) { 
            vector<int> generatorRow; 
            generatorRow.push_back(g); 
            generatorsMatrix.push_back(generatorRow); 
        } 
    } 

 
 
    // Виведення матриці генераторів на консоль 
    cout << "Матриця генераторів поля за модулем " << p << ":\n"; 
    for (const vector<int>& row : generatorsMatrix) { 
        for (int generator : row) { 
            cout << generator << " "; 
        } 
        cout << "\n"; 
    } 
     
    if (!generatorsMatrix.empty()) { 
        int firstGenerator = generatorsMatrix[0][0]; // Отримуємо перше число з матриці генераторів 
        cout << "Перше число з матриці генераторів: " << firstGenerator << endl; 
        int randomValue_a = generateRandomNumber(p); 

 
        cout << "Згенероване випадкове число x для A: "  << randomValue_a << endl; 

         
        int KA = modPow(firstGenerator,  randomValue_a , p); 
        cout << "KA = " << KA << endl;

        cout << "введите KB"<<endl;     
        int KB;
        cin >> KB;
    
         
        int K_from_b_to_a = modPow(KB,  randomValue_a , p); 
        cout << "K from B to A = " << K_from_b_to_a << endl; 
     
    } 
     
 
    return 0; 
}