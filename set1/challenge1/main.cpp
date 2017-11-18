#include <iostream>
#include <vector>
#include <string>

#include "base64.h"

std::vector<unsigned char> hex_to_bytes(std::string hex) {
	std::vector<unsigned char> bytes;

	for(size_t i = 0; i < hex.length(); i+=2) {
		std::string hex_byte = hex.substr(i, 2);
		char byte = strtol(hex_byte.c_str(), NULL, 16);
		bytes.push_back(byte);
	}

	return bytes;
}

int main() {
	std::string hex;
	std::vector<unsigned char> bytes;
		
	std::cin >> hex;
	bytes = hex_to_bytes(hex);

	std::cout << base64_encode(&bytes[0], bytes.size());
}
