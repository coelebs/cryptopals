#include <iostream>
#include <vector>
#include <string> 
#include <cstdio>
#include <algorithm>
#include <map>
#include <fstream>

#include "base64.h"
#include "docopt.h"

#define FORMAT_BUF_SIZE 3

#define LETTERS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz "

typedef struct {
	std::string value;
	int score;
} scored_value;

static const char USAGE[] = 
R"(cryptopals
Usage:
		cryptopals challenge2 <a> <b>
		cryptopals challenge3 <a>
		cryptopals challenge4 <file>
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

scored_value find_key(std::vector<unsigned char> input) {
	scored_value result = {"", 0};

	for(size_t key = 0; key < 256; key++) {
		std::vector<unsigned char> c = input ^ key;
	
		std::string c_string((char*)&c[0], c.size());

		int score = score_string(c_string);

		if(score > result.score) {
			result.value = c_string;
			result.score = score;
		}
	}

	return result;
}

std::vector< std::vector<unsigned char> > read_hex_file(std::string path) {
	std::vector< std::vector<unsigned char> > hex_file;
	std::string line;
	std::ifstream f(path);

	if(f.is_open()) {
		while(getline(f, line)) {
			std::vector<unsigned char> hex_line = hex_to_bytes(line);
			hex_file.push_back(hex_line);
		}
	}

	return hex_file;
}

std::vector<scored_value> score_file(std::vector< std::vector<unsigned char> > f) {
	std::vector<scored_value> result;
	std::vector< std::vector<unsigned char> >::iterator iter;

	for(iter = f.begin(); iter < f.end(); iter++) {
		scored_value solution = find_key(*iter);	
		result.push_back(solution);	
	}

	return result;
}

int main(int argc, const char** argv) {
	std::map<std::string, docopt::value> args = 
		docopt::docopt(USAGE, {argv+1, argv+argc}, true, "cryptopals set 1 challenge 2");

	if(args["challenge2"].asBool()) {
		std::vector<unsigned char> a = hex_to_bytes(args["<a>"].asString());
		std::vector<unsigned char> b = hex_to_bytes(args["<b>"].asString());

		std::vector<unsigned char> c = a^b;

		std::cout << args["<a>"] << " ^ " << args["<b>"] << std::endl;
		std::cout << bytes_to_hex(c) << std::endl;
	}

	if(args["challenge3"].asBool()) {
		std::vector<unsigned char> a = hex_to_bytes(args["<a>"].asString());

		scored_value solution;

		solution = find_key(a);

		std::cout << solution.value << " (" << solution.score << ")" << std::endl;
	}

	if(args["challenge4"].asBool()) {
		std::vector< std::vector<unsigned char> > byte_file = read_hex_file(args["<file>"].asString());
		std::vector<scored_value> scored_file = score_file(byte_file);

		scored_value solution = {"", 0};

		for(std::vector<scored_value>::iterator i = scored_file.begin(); i < scored_file.end(); i++) {
			if(i->score > solution.score) {
				solution = *i;
			}

			std::cout << " (" << i->score << ")" << std::endl;
		}

		std::cout << solution.value << " (" << solution.score << ")" << std::endl;
	}
}
