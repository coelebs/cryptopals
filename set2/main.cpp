#include <iostream>
#include <map>
#include <random>
#include <sstream>
#include <climits>

#include "base64.h"
#include "docopt.h"

#include "set2.h"

static const char USAGE[] = 
R"(cryptopals
Usage:
		cryptopals challenge2  <a> <b>
		cryptopals challenge3  <a> 
		cryptopals challenge4  <file> 
		cryptopals challenge5  <value> <key>
		cryptopals hamming     <a> <b>
		cryptopals challenge6  <file> <max keysize>
		cryptopals challenge7  <file> <key>
		cryptopals challenge8  <file> <blocksize>
		cryptopals challenge9  <data> <blocksize>
		cryptopals challenge10 <file> <key>
		cryptopals challenge11
)";

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

	c = score_keysize(data, max_keysize, KEYSIZE_BLOCK_CHECK);

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

	cipher_file = read_hex_file(path);

	return detect_ecb_line(cipher_file, blocksize);
}

std::string challenge10(std::string path, std::string key) {
	std::vector<unsigned char> ciphertext = read_base64_file(path);
	std::vector<unsigned char> keydata(key.begin(), key.end());
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> IV(BLOCKSIZE);

	std::fill(IV.begin(), IV.end(), 0);

	plaintext = AES128CBC_decrypt(ciphertext, keydata, IV);

	std::string result(plaintext.begin(), plaintext.end());

	return result;
}

std::string challenge11() {
	std::random_device rnd_device;
	std::mt19937 mersenne_engine(rnd_device());
	std::vector<unsigned char> plaintext(BLOCKSIZE * 18);
	std::stringstream result;

	std::fill(plaintext.begin(), plaintext.end(), 0);

	int min = INT_MAX, max = 0;
	for(size_t i = 0; i < 10; i++) {
		std::vector<unsigned char> ciphertext = encryption_oracle(plaintext);
		int score = score_line(ciphertext, BLOCKSIZE, true);

		if(score < min) {
			min = score;
		} else if(score > max) {
			max = score;
		}

		result << i;
		if(score > 0) {
			result << "\t CBC";
		} else {
			result << "\t ECB";
		}
		result << std::endl;
	}

	return result.str();
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

	if(args["challenge9"].asBool()) {
		std::vector<unsigned char> data(args["<data>"].asString().begin(), args["<data>"].asString().end());
		std::vector<unsigned char> result = pkcs7_pad(data, args["<blocksize>"].asLong());

		std::cout << print_hex(data) << std::endl << print_hex(result);
	}

	if(args["challenge10"].asBool()) {
		std::string result = challenge10(args["<file>"].asString(), args["<key>"].asString());
		std::cout << result << std::endl;
	}

	if(args["challenge11"].asBool()) {
		std::cout << challenge11() << std::endl;
	}
}
