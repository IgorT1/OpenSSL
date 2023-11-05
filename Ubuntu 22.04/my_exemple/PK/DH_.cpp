#include<iostream>
#include <cmath>
#include <algorithm>
#include<vector>


using namespace std;


int powerMod(int b, int b_, int a) {
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

vector<int> g_gen(int a){
    int arr_l = a -1;
    int arr[arr_l ];//массив в котором будем хранить наши значения 
    vector<int> g_param;

    int b = 2;//первоначалльное число которое возводим в степень
    int b_ = 0;

    for (b; b < a; b++)
    {
        for (int i = 0; i < arr_l ; i++)
        {
            if(b_ == arr_l)
                b_ = 0;

            //long long c = pow(b,b_);//возводим число в степень 
            int c = powerMod(b, b_, a);
            arr[i] = c % a;//заносим это число в массив по модул
            b_++;
        }
        cout<<endl;

        int size = sizeof(arr) / sizeof(arr[0]);
        sort(arr, arr + size);
        
        for (int i = 0; i < size; ++i) {
        cout << arr[i] << " ";
        }



        bool hasDuplicates = false;
        for (int i = 1; i < size; ++i) {
            if (arr[i] == arr[i - 1]) {
                hasDuplicates = true;
                break;
            }
        }
        if (!hasDuplicates) 
            g_param.push_back(b);
    }

    return g_param;
}


int main(int argc, char const *argv[])
{
    int a = 103;//наше простое число 

    vector<int> gg = g_gen(a);
    
        for (int i : gg) {
            cout << i <<"\n";
    }

    int g = gg.at(0);
    int r_step = 1 + rand() % 225;


   

    return 0;
}
