#include <cstring>
#include <iostream>
#include <bitset>
#include <vector>
#include <boost/dynamic_bitset.hpp>
#include <openssl/sha.h>

using namespace std;

vector<boost::dynamic_bitset<>> short_sha(const unsigned char *hash, size_t lenght, size_t start = 0)
{
	vector<boost::dynamic_bitset<>> bits;
	int char_lenght = (lenght) / 8;
	int lost = (lenght) % 8;
	bool breaked = false;
	
	for(int i = 0; i < char_lenght; i++){
		boost::dynamic_bitset<> word(8, (int)(hash[i]));
		bits.push_back(word);
	}

	if(lost > 0){
		boost::dynamic_bitset<> sub(lost);
		bitset<8> word = (int)(hash[char_lenght]);
		for(int i = 0; i < lost; i++){
			sub[i] = word[8-lost+i];
		}

		bits.push_back(sub);
	}

	return bits;	
}

int main(int argc, char const *argv[])
{
	unsigned char data[512];

	printf("enter data: ");
	scanf("%s", data);

    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(data, strlen((char *)data), hash);

    printf("SHA512(hex): ");
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++){
    	printf("%02x ", (int)(hash[i]));
    }

    int n;
    printf("\nEnter n: ");
    scanf("%i", &n);

    vector<boost::dynamic_bitset<>> answer = short_sha(hash, n);

    printf("%d bits of hash: ", n);
    for(int i = 0; i < answer.size(); i++){
    	printf("%02x ", (int)answer[i].to_ulong());
    	cout << answer[i] << " ";
    }
    printf("\n");

	return 0;
}

