#include <iostream>
#include <vector>
#include <string> 
#include <algorithm>
#include <map>
#include <fstream>
#include <numeric>
#include <random>
#include <sstream>

#include <cstdio>
#include <climits>

#include "base64.h"
#include "docopt.h"

#include <openssl/evp.h>
#include <openssl/err.h>

#include "set2.h"

#define FORMAT_BUF_SIZE 3
#define LETTERS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz "
#define MIN_KEYSIZE 2   // min keysize is always 2, otherwise we're not searching for keysize

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

std::vector<unsigned char> slice(std::vector<unsigned char> input, size_t begin, size_t end) {
	std::vector<unsigned char> sliced(input.begin() + begin, input.begin() + end);
	return sliced;
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

//Find the most probjjjkable keysize 
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
		score.score = 10;

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

std::vector<unsigned char> score_keysize(std::vector<unsigned char> data, int max_keysize, int block_check) {
	std::vector<scored_int> keysize = find_keysize(data, max_keysize, block_check);
	scored_bytes key;

	key.score = 0; //init
	for(std::vector<scored_int>::iterator iter = keysize.begin(); iter < keysize.end(); iter++) {
		scored_bytes possible = find_repeating_key(data, iter->value);

		if(possible.score > key.score) {
			key = possible;
		}
	}

	return data;// ^ key.value;
}

//Use the SSL library to decrypt a text with an AES128ECB cipher
std::vector<unsigned char> AES128ECB_decrypt(std::vector<unsigned char> ciphertext, std::vector<unsigned char> key) {
	EVP_CIPHER_CTX *ctx;

	std::vector<unsigned char> plaintext(ciphertext.size());
	int len;

	if(!(ctx = EVP_CIPHER_CTX_new())) std::cerr << "Unable to set up EVP cipher context" << std::endl;

	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, &key[0], NULL)) {
		ERR_print_errors_fp(stderr);
	}

	if(1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) {
		ERR_print_errors_fp(stderr);
	}

	if(1 != EVP_DecryptUpdate(ctx, &plaintext[0], &len, &ciphertext[0], ciphertext.size())) {
		ERR_print_errors_fp(stderr);
	}

	if(1 != EVP_DecryptFinal_ex(ctx, &plaintext[len], &len)) {
		ERR_print_errors_fp(stderr);
	}

	EVP_CIPHER_CTX_free(ctx);

	return plaintext;
}

//Use the SSL library to encrypt a text with an AES128ECB cipher
std::vector<unsigned char> AES128ECB_encrypt(std::vector<unsigned char> plaintext, std::vector<unsigned char> key, bool pad) {
	EVP_CIPHER_CTX *ctx;
	int len, cipherlen = plaintext.size();

	if(pad) {
		cipherlen += BLOCKSIZE;
	}

	std::vector<unsigned char> ciphertext(cipherlen);

	if(!(ctx = EVP_CIPHER_CTX_new())) std::cerr << "Unable to set up EVP cipher context" << std::endl;

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, &key[0], NULL)) {
		ERR_print_errors_fp(stderr);
	}

	if(!pad) {
		if(1 != EVP_CIPHER_CTX_set_padding(ctx, 0)) {
			ERR_print_errors_fp(stderr);
		}
	}


	if(1 != EVP_EncryptUpdate(ctx, &ciphertext[0], &len, &plaintext[0], plaintext.size())) {
		ERR_print_errors_fp(stderr);
	}
	cipherlen = len;
	
	if(1 != EVP_EncryptFinal_ex(ctx, &ciphertext[len], &len)) {
		ERR_print_errors_fp(stderr);
	}
	cipherlen += len;

	ciphertext.resize(cipherlen);

	EVP_CIPHER_CTX_free(ctx);

	return ciphertext;
}

//decrypt using CBC block cipher mode
//   Use the AES128ECB_decrypt to do the AES encryption
std::vector<unsigned char> AES128CBC_decrypt(std::vector<unsigned char> ciphertext, std::vector<unsigned char> key, std::vector<unsigned char> IV) {
	std::vector<unsigned char> plaintext;

	for(size_t i = 0; i < ciphertext.size(); i+= BLOCKSIZE) {
		std::vector<unsigned char> cipherblock(ciphertext.begin() + i, ciphertext.begin() + i + BLOCKSIZE);

		std::vector<unsigned char> plainblock = AES128ECB_decrypt(cipherblock, key);

		plainblock = plainblock ^ IV;

		plaintext.insert(plaintext.end(), plainblock.begin(), plainblock.end());

		IV = cipherblock;
	}

	return plaintext;
}

//Encrypt using CBC block cipher mode
//   Use the AES128ECB_encrypt to do the AES encryption
std::vector<unsigned char> AES128CBC_encrypt(std::vector<unsigned char> plaintext, std::vector<unsigned char> key, std::vector<unsigned char> IV) {
	std::vector<unsigned char> ciphertext;

	//plaintext = pkcs7_pad(plaintext, BLOCKSIZE); //Because we do not know dat size, we need to pad

	for(size_t i = 0; i < plaintext.size(); i += BLOCKSIZE) {
		std::vector<unsigned char> plainblock(plaintext.begin() + i, plaintext.begin() + i + BLOCKSIZE);

		std::vector<unsigned char> xorblock = plainblock ^ IV;
		std::vector<unsigned char> cipherblock = AES128ECB_encrypt(xorblock, key, false);
		cipherblock.resize(BLOCKSIZE);

		ciphertext.insert(ciphertext.end(), cipherblock.begin(), cipherblock.end());

		IV = cipherblock;
	}
	
	return ciphertext;
}

//Score line, amount of recurring blocks as the deciding factor
int score_line(std::vector<unsigned char> line, int blocksize, bool use_hamming) {
	int score = 0;
	std::vector<int> scores;

	for(size_t i = 0; i < line.size(); i += blocksize) {
		for(size_t j = i + blocksize; j < line.size(); j += blocksize) {
			std::vector<unsigned char> a(line.begin() + i,	line.begin() + (i + blocksize));
			std::vector<unsigned char> b(line.begin() + j,	line.begin() + (j + blocksize));	

			bool same = false;
			for(size_t k = 0; k < a.size(); k++) {
				if(a[k] == b[k]) {
					same = true;
				}
				scores.push_back(hamming(a, b));

			}

			if(use_hamming) { 
				score += std::accumulate(scores.begin(), scores.end(), 0) / scores.size();
			} else {
				if(same) { 
					score++;
				}
			}
		}
	}

	return score;
}

scored_int detect_ecb_line(std::vector< std::vector<unsigned char> > ciphertexts, int blocksize) {
	scored_int top_line({0,0});

	int i = 0;
	for(std::vector< std::vector<unsigned char> >::iterator iter = ciphertexts.begin(); 
			iter < ciphertexts.end(); iter++) {
		int score = score_line(*iter, blocksize);

		if(score > top_line.score) {
			top_line.score = score;
			top_line.value = i;
		}	

		i++;
	}

	return top_line;
}

//Pad data with bytes to match blocksize
//  Value of bytes is amount of blocks to pad
std::vector<unsigned char> pkcs7_pad(std::vector<unsigned char> data, int blocksize) {
	char padding;

	padding = blocksize - (data.size() % blocksize);

	for(unsigned char i = 0; i < padding; i++) {
		data.push_back(padding);
	}

	return data;
}

//Print data in a pretty way to std::string
std::string print_hex(std::vector<unsigned char> data) {
	std::string result;
	char *buffer;
	size_t len;
	FILE *fp;
   
	fp = open_memstream(&buffer, &len);
	BIO_dump_fp(fp, (const char *)&data[0], data.size());
	fclose(fp);

	result += buffer;
	free(buffer);

	return result;
}

//Encrypt the plaintext with a random key, with a random IV padded with random data
std::vector<unsigned char> encryption_oracle(std::vector<unsigned char> plaintext, std::string *method) {
	std::vector<unsigned char> key(BLOCKSIZE);
	std::vector<unsigned char> IV(BLOCKSIZE);
	std::vector<unsigned char> ciphertext(BLOCKSIZE);
	std::vector<unsigned char> rand_bytes;
	std::random_device rnd_device;
	std::mt19937 mersenne_engine(rnd_device());

	std::generate(key.begin(), key.end(), mersenne_engine);
	mersenne_engine.discard(BLOCKSIZE); //BLOCKSIZE chosen at random, need to "reset" the engine. Proper seed would be better of course

	std::generate(IV.begin(), IV.end(), mersenne_engine);
	mersenne_engine.discard(BLOCKSIZE); //BLOCKSIZE chosen at random, need to "reset" the engine. Proper seed would be better of course

	rand_bytes.resize((mersenne_engine() % 5) + 5);
	std::generate(rand_bytes.begin(), rand_bytes.end(), mersenne_engine);
	plaintext.insert(plaintext.begin(), rand_bytes.begin(), rand_bytes.end());

	rand_bytes.resize((mersenne_engine() % 5) + 5);
	std::generate(rand_bytes.begin(), rand_bytes.end(), mersenne_engine);
	plaintext.insert(plaintext.end(), rand_bytes.begin(), rand_bytes.end());

	if(mersenne_engine() % 2 == 0) {
		if(method != NULL) *method += "CBC";
		ciphertext = AES128CBC_encrypt(plaintext, key, IV);
	} else {
		if(method != NULL) *method += "ECB";
		ciphertext = AES128ECB_encrypt(plaintext, key);
	}

	return ciphertext;
}

int find_blocksize(EncryptionBox box) {
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	int blocksize, prevsize = 0;


	for(size_t i = 0; i < 32; i++) {
		plaintext.assign(i, 0);
		ciphertext = box.encrypt(plaintext);

		if(prevsize != 0 && ciphertext.size() - prevsize > 1) {
			blocksize = ciphertext.size() - prevsize;
		}
		prevsize = ciphertext.size();
	}

	return blocksize;
}

std::vector<unsigned char> crack_ecb_simple(EncryptionBox box) {
	std::vector<unsigned char> plaintext, ciphertext, result;

	int score, blocksize = find_blocksize(box);
	bool ecb;

	plaintext.assign(4 * blocksize, 0);
	ciphertext = box.encrypt(plaintext);
	score = score_line(ciphertext, blocksize);

	ecb = score > 1;	

	if(ecb) {
		std::vector<std::vector<unsigned char>> dictionary;
		plaintext.resize(blocksize);
		plaintext.assign(blocksize, 'a');
		auto test_cipher = box.encrypt(plaintext);

		for(size_t i = 0; i < 255; i++) {
			size_t index = blocksize - 1;
			plaintext[index] = i;			
			ciphertext = box.encrypt(plaintext);
			dictionary.push_back(slice(ciphertext, 0, blocksize));
		}

		auto first_block = slice(test_cipher, 0, blocksize);
		for(size_t i = 0; i < dictionary.size(); i++) {
			if(dictionary[i] == first_block) {
				result.push_back(i);
			}
		}
	} else {
		std::cout << "Not ECB" << std::endl;
	}

	return result;
}
