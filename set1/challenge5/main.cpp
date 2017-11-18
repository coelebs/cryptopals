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
		cryptopals challenge5 <value> <key>
)";

std::vector<char> hex_to_bytes(std::string hex) {
	std::vector<char> bytes;

	for(size_t i = 0; i < hex.length(); i+=2) {
		std::string hex_byte = hex.substr(i, 2);
		char byte = strtol(hex_byte.c_str(), NULL, 16);
		bytes.push_back(byte);
	}

	return bytes;
}

std::string bytes_to_hex(std::vector<char> bytes) { 
	std::string hex;

	for(size_t i = 0; i < bytes.size(); i++) {
		char buf[FORMAT_BUF_SIZE];
		snprintf(buf, FORMAT_BUF_SIZE, "%02x", bytes[i]);
		hex.append(buf);
	}
	return hex;
}

std::vector<char> operator^(std::vector<char> a, std::vector<char> b) {
	std::vector<char> c;

	/*
	if(a.size() != b.size()) {  
			char res; 
			res = a[i] ^ b[i];
			c.push_back(res);
		}
	} else {
		for(size_t i = 0; i < a.size(); i++) {
			char res;
			res = a[i] ^ b[i % b.size()];
			c.push_back(res);
		}
	}
	*/

	for(size_t i = 0; i < a.size(); i++) {
		char res;
		res = a[i] ^ b[i % b.size()];
		c.push_back(res);
	}

	return c; 
}

std::vector<char> operator^(std::vector<char> a, char b) {
	std::vector<char> c;

	for(size_t i = 0; i < a.size(); i++) {
		char res;
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

scored_value find_key(std::vector<char> input) {
	scored_value result = {"", 0};

	for(size_t key = 0; key < 256; key++) {
		std::vector<char> c = input ^ key;
	
		std::string c_string((char*)&c[0], c.size());

		int score = score_string(c_string);

		if(score > result.score) {
			result.value = c_string;
			result.score = score;
		}
	}

	return result;
}

std::vector< std::vector<char> > read_hex_file(std::string path) {
	std::vector< std::vector<char> > hex_file;
	std::string line;
	std::ifstream f(path);

	if(f.is_open()) {
		while(getline(f, line)) {
			std::vector<char> hex_line = hex_to_bytes(line);
			hex_file.push_back(hex_line);
		}
	}

	return hex_file;
}

std::vector<scored_value> score_file(std::vector< std::vector<char> > f) {
	std::vector<scored_value> result;
	std::vector< std::vector<char> >::iterator iter;

	for(iter = f.begin(); iter < f.end(); iter++) {
		scored_value solution = find_key(*iter);	
		result.push_back(solution);	
	}

	return result;
}

std::string challenge2(std::string hexa, std::string hexb) {
	std::vector<char> a = hex_to_bytes(hexa);
	std::vector<char> b = hex_to_bytes(hexb);

	std::vector<char> c = a^b;

	return bytes_to_hex(c);
}

scored_value challenge3(std::string hexa) {
	std::vector<char> a = hex_to_bytes(hexa);
	scored_value solution;
	solution = find_key(a);
	return solution;
}

scored_value challenge4(std::string file) {
	std::vector< std::vector<char> > byte_file = read_hex_file(file);
	std::vector<scored_value> scored_file = score_file(byte_file);

	scored_value solution = {"", 0};

	for(std::vector<scored_value>::iterator i = scored_file.begin(); i < scored_file.end(); i++) {
		if(i->score > solution.score) {
			solution = *i;
		}
	}

	return solution;
}

std::string challenge5(std::string hex_value, std::string hex_key) {
	std::vector<char> value(hex_value.begin(), hex_value.end());
	std::vector<char> key(hex_key.begin(), hex_key.end());	
	
	std::vector<char> c = value ^ key;

	return bytes_to_hex(c);
}

int main(int argc, const char** argv) {
	std::map<std::string, docopt::value> args = 
		docopt::docopt(USAGE, {argv+1, argv+argc}, true, "cryptopals set 1 challenge 2");

	if(args["challenge2"].asBool()) {
		std::string result = challenge2(args["<a>"].asString(), args["<b>"].asString());
		std::cout << result << std::endl;
	}

	if(args["challenge3"].asBool()) {
		scored_value solution = challenge3(args["<a>"].asString());
		std::cout << solution.value << " (" << solution.score << ")" << std::endl;
	}

	if(args["challenge4"].asBool()) {
		scored_value solution = challenge4(args["<file>"].asString());
		std::cout << solution.value << " (" << solution.score << ")" << std::endl;
	}

	if(args["challenge5"].asBool()) {
		std::string result = challenge5(args["<value>"].asString(), args["<key>"].asString());
		std::cout << result << std::endl;
	}
}
