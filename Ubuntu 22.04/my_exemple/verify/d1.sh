#! /bin/bash
g++ verify.cpp -o verify -lssl -lcrypto
./verify 