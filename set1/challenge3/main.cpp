#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include <algorithm>
#include <map>

#include "base64.h"
#include "docopt.h"

#define FORMAT_BUF_SIZE 3

#define LETTERS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz "

static const char USAGE[] = 
R"(cryptopals
Usage:
		cryptopals xor <a> <b>
		cryptopals find_xor <a>
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

std::vector<unsigned char> operator^(std::vector<unsigned char> a, unsigned char b) {
	std::vector<unsigned char> c;

	for(size_t i = 0; i < a.size(); i++) {
		unsigned char res;
		res = a[i] ^ b;
		c.push_back(res);
	}

	return c;
}

int score_string(std::string input) { 
	int score = 0;
	std::string hint = LETTERS;

	for(size_t i = 0; i < input.length(); i++) { 
		if(hint.find(input[i]) != std::string::npos) {
			score++;
		}
	}
	
	return score;
}

int main(int argc, const char** argv) {
	std::map<std::string, docopt::value> args = 
		docopt::docopt(USAGE, {argv+1, argv+argc}, true, "cryptopals set 1 challenge 2");

	if(args["xor"].asBool()) {
		std::cout << "xor" << std::endl;
		std::vector<unsigned char> a = hex_to_bytes(args["<a>"].asString());
		std::vector<unsigned char> b = hex_to_bytes(args["<b>"].asString());

		std::vector<unsigned char> c = a^b;

		std::cout << args["<a>"] << " ^ " << args["<b>"] << std::endl;
		std::cout << bytes_to_hex(c) << std::endl;
	}

	if(args["find_xor"].asBool()) {
		std::cout << "find_xor" << std::endl;
		std::vector<unsigned char> a = hex_to_bytes(args["<a>"].asString());

		int high_score = 0;
		std::string solution;

		for(size_t key = 0; key < 256; key++) {
			std::vector<unsigned char> c = a ^ key;
		
			std::string c_string((char*)&c[0], c.size());

			int score = score_string(c_string);

			if(score > high_score) {
				high_score = score;
				solution = c_string;
				std::cout << int(key) << " " << score << std::endl;
			}
		}

		std::cout << solution << std::endl;
	}
}
