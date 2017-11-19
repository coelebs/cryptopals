#include <iostream>
#include <vector>
#include <string> 
#include <algorithm>
#include <map>
#include <fstream>
#include <numeric>

#include <cstdio>
#include <climits>

#include "base64.h"
#include "docopt.h"

#include <openssl/evp.h>

#define FORMAT_BUF_SIZE 3
#define LETTERS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz "
#define MIN_KEYSIZE 2   // min keysize is always 2, otherwise we're not searching for keysize
#define KEYSIZE_BLOCK_CHECK 4

typedef struct {
	std::string value;
	int score;
	unsigned char key;
} scored_string;

typedef struct {
	int value;
	int score;
} scored_int;

typedef struct {
	std::vector<unsigned char> value;
	int score;
} scored_bytes;

static const char USAGE[] = 
R"(cryptopals
Usage:
		cryptopals challenge2 <a> <b>
		cryptopals challenge3 <a> 
		cryptopals challenge4 <file> 
		cryptopals challenge5 <value> <key>
		cryptopals hamming <a> <b>
		cryptopals challenge6 <file> <max keysize>
		cryptopals challenge7 <file> <key>
		cryptopals challenge8 <file> <blocksize>
)";

std::vector<unsigned char> hex_to_bytes(std::string hex) {
	std::vector<unsigned char> bytes;

	for(size_t i = 0; i < hex.length(); i+=2) {
		std::string hex_byte = hex.substr(i, 2);
		unsigned char byte = strtol(hex_byte.c_str(), NULL, 16);
		bytes.push_back(byte);
	}

	return bytes;
}

std::string bytes_to_hex(std::vector<unsigned char> bytes) { 
	std::string hex;

	for(size_t i = 0; i < bytes.size(); i++) {
		char buf[FORMAT_BUF_SIZE];
		snprintf(buf, FORMAT_BUF_SIZE, "%02x", bytes[i]);
		hex.append(buf);
	}
	return hex;
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

std::vector<unsigned char> read_base64_file(std::string path) {
	std::string data;
	std::string line;
	std::ifstream f(path);

	if(f.is_open()) {
		while(getline(f, line)) {
			data += base64_decode(line);
		}
	}

	return std::vector<unsigned char>(data.begin(), data.end());
}

//XOR a with b. If b is smaller than a, use b as repeating key
std::vector<unsigned char> operator^(std::vector<unsigned char> a, std::vector<unsigned char> b) {
	std::vector<unsigned char> c;

	for(size_t i = 0; i < a.size(); i++) {
		unsigned char res;
		res = a[i] ^ b[i % b.size()];
		c.push_back(res);
	}

	return c; 
}

//XOR a with single key b
std::vector<unsigned char> operator^(std::vector<unsigned char> a, char single_b) {
	std::vector<unsigned char> b;
	b.push_back(single_b);
	return a ^ b;
}

//Score string as english by looking at how many letters it contains
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

//Try all keys, one with highest score wins
scored_string find_key(std::vector<unsigned char> input) {
	scored_string result = {"", 0};

	for(size_t key = 0; key < 256; key++) {
		std::vector<unsigned char> c = input ^ key;
	
		std::string c_string(c.begin(), c.end());

		int score = score_string(c_string);

		if(score > result.score) {
			result.value = c_string;
			result.score = score;
			result.key = key;
		}
	}

	return result;
}

//One line is single key encrypted
//Try all keys on all lines, line+key combination with highest score wins
std::vector<scored_string> score_file(std::vector< std::vector<unsigned char> > f) {
	std::vector<scored_string> result;
	std::vector< std::vector<unsigned char> >::iterator iter;

	for(iter = f.begin(); iter < f.end(); iter++) {
		scored_string solution = find_key(*iter);	
		result.push_back(solution);	
	}

	return result;
}

//Return number of differing bits between a and b
int hamming(std::vector<unsigned char> a, std::vector<unsigned char> b) {
	std::vector<unsigned char> c = a ^ b;

	int hamming_distance = 0;

	for(std::vector<unsigned char>::iterator iter = c.begin(); iter < c.end(); iter++) {
		hamming_distance += __builtin_popcount(*iter);	
	}

	return hamming_distance;
}

//Find the most probable keysize 
//Hint: For each KEYSIZE, take the first KEYSIZE worth of bytes, and the
//		second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by
//		KEYSIZE.  The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed
//		perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the
//		distances. 
//		Return multiple possible solutions
std::vector<scored_int> find_keysize(std::vector<unsigned char> data, int max, int block_check) {
	std::vector<scored_int> result(1);
	result[0].score = INT_MAX; //Need to "seed" first on int max or otherwise there will never be a match

	for(int keysize = MIN_KEYSIZE; keysize < max; keysize++) {
		scored_int score = {keysize, 0};
		std::vector<int> scores;

		for(int i = 0; i < block_check; i++) {
			std::vector<unsigned char> a(data.begin() + (i*keysize),		data.begin() + ((i+1)*keysize));
			std::vector<unsigned char> b(data.begin() + ((i+1)*keysize),	data.begin() + ((i+2)*keysize));	
			scores.push_back(hamming(a,b));
		}

		score.score = std::accumulate(scores.begin(), scores.end(), 0) / scores.size(); 
		score.score = score.score / keysize;

		if(score.score == result[0].score) {
			result.push_back(score);
		} else if(score.score < result[0].score) {
			result.clear();
			result.push_back(score);
		}
	}	

	return result; 
}

//Find repeating key in multiple steps:
//  Find the most probable keysize
//  Try probable keysizes and score result
//  Highest scored result is the answer
scored_bytes find_repeating_key(std::vector<unsigned char> data, int keysize) {
	std::vector< std::vector<unsigned char> > sliced_data(keysize);
	scored_bytes key;

	key.score = 0; //need to init @ 0 to compare 

	for(size_t i = 0; i < data.size(); i += keysize) {
		for(int j = 0; j < keysize; j++) {
			if(i+j > data.size()) { 
				break;
			}
			sliced_data[j].push_back(data[i+j]);
		}
	}

	for(std::vector< std::vector<unsigned char> >::iterator iter = sliced_data.begin(); iter < sliced_data.end(); iter++) {
		int score;
		scored_string decrypt_data = find_key(*iter);
		key.value.push_back(decrypt_data.key);

		score = decrypt_data.score * keysize; //Normalize to keysize, wrong way around but works...

		if(score > key.score) {
			key.score = score;
		}
	}

	return key;
}

//Use the SSL library to decrypt a text with an AES128ECB cipher
std::vector<unsigned char> AES128ECB_decrypt(std::vector<unsigned char> ciphertext, std::vector<unsigned char> key) {
	EVP_CIPHER_CTX *ctx;

	std::vector<unsigned char> plaintext(ciphertext.size());
	int len;

	if(!(ctx = EVP_CIPHER_CTX_new())) std::cerr << "Unable to set up EVP cipher context" << std::endl;

	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, &key[0], NULL)) {
		std::cerr << "Unable to initialize EVP cipher context" << std::endl;
	}

	if(1 != EVP_DecryptUpdate(ctx, &plaintext[0], &len, &ciphertext[0], ciphertext.size())) {
		std::cerr << "Unable to decrypt ciphertext" << std::endl;
	}

	if(1 != EVP_DecryptFinal_ex(ctx, &plaintext[len], &len)) {
		std::cerr << "Unable to finalize the decryption" << std::endl;	
	}

	if((size_t)len > plaintext.size()) {
		std::cerr << "Overwritten buffer" << std::endl;
	}

	EVP_CIPHER_CTX_free(ctx);

	return plaintext;
}

int score_line(std::vector<unsigned char> line, int blocksize) {
	int score = 0;
	std::vector<int> scores;

	for(size_t i = 0; i < line.size(); i += blocksize) {
		for(size_t j = i + blocksize; j < line.size(); j += blocksize) {
			std::vector<unsigned char> a(line.begin() + i,	line.begin() + (i + blocksize));
			std::vector<unsigned char> b(line.begin() + j,	line.begin() + (j + blocksize));	

			bool same = true;
			for(size_t k = 0; k < a.size(); k++) {
				if(a[k] != b[k]) {
					same = false;
				}
			}

			if(same) { 
				score++;
			}
		}
	}

	return score;
}

std::string challenge2(std::string hexa, std::string hexb) {
	std::vector<unsigned char> a = hex_to_bytes(hexa);
	std::vector<unsigned char> b = hex_to_bytes(hexb);

	std::vector<unsigned char> c = a^b; 
	return bytes_to_hex(c);
}

scored_string challenge3(std::string hexa) {
	std::vector<unsigned char> a = hex_to_bytes(hexa);
	scored_string solution;
	solution = find_key(a);
	return solution;
}

scored_string challenge4(std::string file) {
	std::vector< std::vector<unsigned char> > byte_file = read_hex_file(file);
	std::vector<scored_string> scored_file = score_file(byte_file);

	scored_string solution = {"", 0};

	for(std::vector<scored_string>::iterator i = scored_file.begin(); i < scored_file.end(); i++) {
		if(i->score > solution.score) {
			solution = *i;
		}
	}

	return solution;
}

std::string challenge5(std::string hex_value, std::string hex_key) {
	std::vector<unsigned char> value(hex_value.begin(), hex_value.end());
	std::vector<unsigned char> key(hex_key.begin(), hex_key.end());	
	
	std::vector<unsigned char> c = value ^ key;

	return bytes_to_hex(c);
}

std::string challenge6(std::string path, int max_keysize) {
	std::vector<unsigned char> data;
	std::vector<scored_int> keysize;
	scored_bytes key;
	std::vector<unsigned char> c;

	data = read_base64_file(path);
	keysize = find_keysize(data, max_keysize, KEYSIZE_BLOCK_CHECK);

	key.score = 0; //init
	for(std::vector<scored_int>::iterator iter = keysize.begin(); iter < keysize.end(); iter++) {
		scored_bytes possible = find_repeating_key(data, iter->value);

		if(possible.score > key.score) {
			key = possible;
		}
	}

	c = data ^ key.value;

	std::string result(c.begin(), c.end());
	
	return result;
}

std::string challenge7(std::string path, std::string key) {
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;

	std::vector<unsigned char> key_data(key.begin(), key.end());

	ciphertext = read_base64_file(path);

	plaintext = AES128ECB_decrypt(ciphertext, key_data);	

	std::string result(plaintext.begin(), plaintext.end());
	
	return result;
}

scored_int challenge8(std::string path, int blocksize) {
	std::vector< std::vector<unsigned char> > cipher_file;
	std::vector<unsigned char> plaintext;
	scored_int top_line;

	cipher_file = read_hex_file(path);
	top_line.score = 0;

	int i = 0;
	for(std::vector< std::vector<unsigned char> >::iterator iter = cipher_file.begin(); 
			iter < cipher_file.end(); iter++) {
		int score = score_line(*iter, blocksize);

		if(score > top_line.score) {
			top_line.score = score;
			top_line.value = i;
		}	

		i++;
	}

	return top_line;
}

int main(int argc, const char** argv) {
	std::map<std::string, docopt::value> args = 
		docopt::docopt(USAGE, {argv+1, argv+argc}, true, "cryptopals set 1 challenge 2");

	if(args["challenge2"].asBool()) {
		std::string result = challenge2(args["<a>"].asString(), args["<b>"].asString());
		std::cout << result << std::endl;
	}

	if(args["challenge3"].asBool()) {
		scored_string solution = challenge3(args["<a>"].asString());
		std::cout << solution.value << " (" << solution.score << ")" << std::endl;
	}

	if(args["challenge4"].asBool()) {
		scored_string solution = challenge4(args["<file>"].asString());
		std::cout << solution.value << " (" << solution.score << ")" << std::endl;
	}

	if(args["challenge5"].asBool()) {
		std::string result = challenge5(args["<value>"].asString(), args["<key>"].asString());
		std::cout << result << std::endl;
	}

	if(args["hamming"].asBool()) {
		std::string raw = args["<a>"].asString();
		std::vector<unsigned char> a(raw.begin(), raw.end());

		raw = args["<b>"].asString();
		std::vector<unsigned char> b(raw.begin(), raw.end());

		std::cout << hamming(a, b) << std::endl;
	}

	if(args["challenge6"].asBool()) {
		std::string result = challenge6(args["<file>"].asString(), args["<max keysize>"].asLong());
		std::cout << result << std::endl;
	}

	if(args["challenge7"].asBool()) {
		std::string result = challenge7(args["<file>"].asString(), args["<key>"].asString());
		std::cout << result << std::endl;
	}

	if(args["challenge8"].asBool()) {
		scored_int result = challenge8(args["<file>"].asString(), args["<blocksize>"].asLong());
		std::cout << "Line " << result.value << "\tScore " << result.score << std::endl;
	}
}
