#pragma once

#include <cstring>
#include <iostream>
#include <bitset>
#include <vector>
#include <boost//dynamic_bitset.hpp>
#include <openssl/sha.h>
#include <map>


std::vector<boost::dynamic_bitset<>> short_sha(const unsigned char *hash, size_t len, size_t start = 0);
void gen_random(const int len, unsigned char* data);
void print_uc(const unsigned char* data, int len, char del = '\0');
void print_uc(const std::vector<boost::dynamic_bitset<>> data, int len, char del = '\0');
unsigned char* parse_bits(std::vector<boost::dynamic_bitset<>> vec);
