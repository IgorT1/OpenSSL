#include <cstring>
#include <iostream>
#include <bitset>
#include <vector>
#include <map>
#include <boost/dynamic_bitset.hpp>
#include <openssl/sha.h>
#include <chrono>

std::vector<boost::dynamic_bitset<>> short_sha(const unsigned char *hash, size_t len, size_t start = 0);
void gen_random(const int len, unsigned char* data);
void print_uc(const unsigned char* data, int len, char del = '\0');
void print_uc(const std::vector<boost::dynamic_bitset<>> data, int len, char del = '\0');
unsigned char* parse_bits(std::vector<boost::dynamic_bitset<>> vec);


static const int DATA_BITS = 256;
//static const int SHORT_BITS = 24;

static const int DATA_BYTES = DATA_BITS / 8;
//static const int SHORT_BYTES = SHORT_BITS / 8;


int main(int argc, char const *argv[])
{
    auto start = std::chrono::high_resolution_clock::now();

	unsigned char hash[SHA256_DIGEST_LENGTH]; //буфер хешу
	std::vector<unsigned char*> datas; //вектор згенерованих даних
	std::vector<unsigned char*> short_hashes; //вектор згенерованих shorthash
	srand(time(nullptr));

    int answer = -1, n;
    printf("n = ");
    scanf("%i", &n);

    for(int i = 0; answer < 0; i++){
    	unsigned char* r_data = new unsigned char[32]; //буфер випадкових даних
    	
    	gen_random(DATA_BYTES, r_data);//генерація випадкових даних
    	datas.push_back(r_data); //додавання даних до вектору
    	printf("\ndata[%d]: ", i); //вивід даних
    	print_uc(r_data, DATA_BYTES);

    	SHA256(r_data, strlen((char *)r_data), hash); //генерація 256біт хешу
    	short_hashes.push_back(parse_bits(short_sha(hash, n))); //додавання shortsha(n) до вектору

    	printf("\nsha256[%d]: ", i);//вивід 256біт хешу
    	print_uc(hash, SHA256_DIGEST_LENGTH);

    	printf("\nshortsha(%d)[%d]: ", n, i);//вивід короткого хешу
    	print_uc(short_hashes[i], n/8, ' ');
    	printf("\n");

        //порівнюємо дані по циклу
    	int size = short_hashes.size();
    	for(int j = 0; j < size - 1; j++){ // з short_hashes[0] до short_hashes[size - 1]
    		if(!memcmp(short_hashes[j],short_hashes[size - 1], n/4)){ 
    			answer = j;
    			break; //перериваємо цикл
    		}
    	}
    }

    //вивід відповіді
    int size = short_hashes.size();
    printf("\ndata[%d]: ", answer);
   	print_uc(datas[answer], DATA_BYTES);

    printf("\ndata[%d]: ", size-1);
    print_uc(datas[size-1], DATA_BYTES);

    printf("\nshort_sha[%d]: ", answer);
    print_uc(short_hashes[answer], n/4, ' ');

    printf("\nshort_sha[%d]: ", size - 1);
    print_uc(short_hashes[size - 1], n/4, ' ');

    SHA256(datas[answer], strlen((char *)datas[answer]), hash);
    printf("\nsha256[%d]: ", answer);
    print_uc(hash, SHA256_DIGEST_LENGTH);

	SHA256(datas[size-1], strlen((char *)datas[size-1]), hash); 
	printf("\nsha256[%d]: ", size-1);   
	print_uc(hash, SHA256_DIGEST_LENGTH);

    printf("\n");

    
    auto end = std::chrono::high_resolution_clock::now();

    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    
    int minutes = std::chrono::duration_cast<std::chrono::minutes>(duration).count();
    int seconds = std::chrono::duration_cast<std::chrono::seconds>(duration % std::chrono::minutes(1)).count();
    int milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration % std::chrono::seconds(1)).count();

    // Виведення результату
    std::cout << "Час виконання: " << minutes << " хв " << seconds << " с " << milliseconds << " мс" << std::endl;


	return 0;
}


std::vector<boost::dynamic_bitset<>> short_sha(const unsigned char *hash, size_t len, size_t start)
{
	//вектор байтів
	std::vector<boost::dynamic_bitset<>> bits;
	
	int bytes = (len) / 8; //count of full bytes
	int lost = (len) % 8; //additional bits

	//getting full bytes from original hash
	for(int i = 0; i < bytes; i++){
		boost::dynamic_bitset<> word(8, (int)(hash[i]));
		bits.push_back(word);
	}

	//getting additional bits
	if(lost > 0){
		boost::dynamic_bitset<> sub(lost);
		std::bitset<8> word = (int)(hash[bytes]);
		for(int i = 0; i < lost; i++){
			sub[i] = word[8-lost+i];
		}

		bits.push_back(sub);
	}

	return bits;
}

//random data generatot
void gen_random(const int len, unsigned char* data) 
{
    for (int i = 0; i < len; ++i) {
    	do{
    		data[i] = rand() % 256; //255 = 11111111
    	}while(data[i] == 0);
    }   
}

//print from uchar array
void print_uc(const unsigned char* data, int len, char del){
	for(int i = 0; i < len; i++)
		printf("%02x%c", (int) data[i], del);
}

//print from vector of bitsets
void print_uc(const std::vector<boost::dynamic_bitset<>> data, int len, char del){
	for(int i = 0; i < len; i++)
		printf("%02x%c", (int) data[i].to_ulong(), del);
}

//parse from vector to uchar
unsigned char* parse_bits(std::vector<boost::dynamic_bitset<>> vec){
	unsigned char* data = new unsigned char[vec.size()];

	for(int i = 0; i < vec.size(); i++)
		data[i] = static_cast<unsigned char>(vec[i].to_ulong());

	return data;
}








// #include <iostream>
// #include <bitset>
// #include <unordered_map>
// #include <openssl/sha.h>
// #include <boost/dynamic_bitset.hpp>

// using namespace std;

// bitset<64> short_sha_64(const bitset<256>& input) {
//     unsigned char hash[SHA512_DIGEST_LENGTH];
//     SHA512(reinterpret_cast<const unsigned char*>(input.to_string().c_str()), input.size() / 8, hash);

//     bitset<64> result;
//     for (int i = 0; i < 8; i++) {
//         result <<= 8;
//         result |= hash[i];
//     }
//     return result;
// }

// vector<boost::dynamic_bitset<>> short_sha(const unsigned char *hash, size_t len, size_t start = 0)
// {
// 	vector<boost::dynamic_bitset<>> bits;
// 	int ch_len = (len) / 8;
// 	int lost = (len) % 8;
// 	bool breaked = false;
	
// 	for(int i = 0; i < ch_len; i++){
// 		boost::dynamic_bitset<> word(8, (int)(hash[i]));
// 		bits.push_back(word);
// 	}

// 	if(lost > 0){
// 		boost::dynamic_bitset<> sub(lost);
// 		bitset<8> word = (int)(hash[ch_len]);
// 		for(int i = 0; i < lost; i++){
// 			sub[i] = word[8-lost+i];
// 		}

// 		bits.push_back(sub);
// 	}

// 	return bits;	
// }

// pair<bitset<256>, bitset<256>> find_collision() {
//     unordered_map<bitset<64>, bitset<256>> hash_table;
//     bitset<256> random_vector;
//     bitset<256> collision_candidate;

//     while (true) {
//         random_vector = bitset<256>(rand());
//         bitset<64> hash_result = short_sha_64(random_vector);

//         if (hash_table.find(hash_result) != hash_table.end()) {
//             return make_pair(hash_table[hash_result], random_vector);
//         }

//         hash_table[hash_result] = random_vector;
//     }
// }

// int main() {
//     srand(time(nullptr));

//     pair<bitset<256>, bitset<256>> collision_pair = find_collision();
//     cout << "Collision Found!" << endl;
//     cout << "Vector 1: " << collision_pair.first << endl;
//     cout << "Vector 2: " << collision_pair.second << endl;

//     return 0;
// }