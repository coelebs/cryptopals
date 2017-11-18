#include <iostream>
#include <vector>
#include <string>
#include <cstdio>

#include "base64.h"
#include "docopt.h"

#define FORMAT_BUF_SIZE 3

static const char USAGE[] = 
R"(cryptopals

	Usage:
		cryptopals xor <a> <b>
)";

std::vector<unsigned char> hex_to_bytes(std::string hex) {
	std::vector<unsigned char> bytes;

	for(size_t i = 0; i < hex.length(); i+=2) {
		std::string hex_byte = hex.substr(i, 2);
		char byte = strtol(hex_byte.c_str(), NULL, 16);
		bytes.push_back(byte);
	}

	return bytes;
}

std::string bytes_to_hex(std::vector<unsigned char> bytes) { 
	std::string hex;

	for(size_t i = 0; i < bytes.size(); i++) {
		char buf[FORMAT_BUF_SIZE];
		snprintf(buf, FORMAT_BUF_SIZE, "%x", bytes[i]);
		hex.append(buf);
	}
	return hex;
}


std::vector<unsigned char> operator^(std::vector<unsigned char> a, std::vector<unsigned char> b) {
	std::vector<unsigned char> c;

	if(a.size() != b.size()) {
		return c;
	}
		

	for(size_t i = 0; i < a.size(); i++) {
		unsigned char res; 
		res = a[i] ^ b[i];
		c.push_back(res);
	}

	return c; 

}

int main(int argc, const char** argv) {
	std::map<std::string, docopt::value> args = 
		docopt::docopt(USAGE, {argv+1, argv+argc}, true, "cryptopals set 1 challenge 2");

	std::vector<unsigned char> a = hex_to_bytes(args["<a>"].asString());
	std::vector<unsigned char> b = hex_to_bytes(args["<b>"].asString());

	std::vector<unsigned char> c = a^b;

	std::cout << args["<a>"] << " ^ " << args["<b>"] << std::endl;
	std::cout << bytes_to_hex(c) << std::endl;
}
