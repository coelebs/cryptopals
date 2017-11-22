#ifndef SET2
#define SET2

#include <vector>
#include <string> 

#define BLOCKSIZE			16
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

std::vector<unsigned char> hex_to_bytes(std::string hex);
std::string bytes_to_hex(std::vector<unsigned char> bytes);
std::vector< std::vector<unsigned char> > read_hex_file(std::string path);
std::vector<unsigned char> read_base64_file(std::string path);

//XOR a with b. If b is smaller than a, use b as repeating key
std::vector<unsigned char> operator^(std::vector<unsigned char> a, std::vector<unsigned char> b);
//XOR a with single key b
std::vector<unsigned char> operator^(std::vector<unsigned char> a, char single_b);

//Score string as english by looking at how many letters it contains
int score_string(std::string input); 
//Try all keys, one with highest score wins
scored_string find_key(std::vector<unsigned char> input);
//One line is single key encrypted
//Try all keys on all lines, line+key combination with highest score wins
std::vector<scored_string> score_file(std::vector< std::vector<unsigned char> > f);

//Return number of differing bits between a and b
int hamming(std::vector<unsigned char> a, std::vector<unsigned char> b);
//Find the most probjjjkable keysize 
//Hint: For each KEYSIZE, take the first KEYSIZE worth of bytes, and the
//		second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by
//		KEYSIZE.  The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed
//		perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the
//		distances. 
//		Return multiple possible solutions
//
std::vector<scored_int> find_keysize(std::vector<unsigned char> data, int max, int block_check);
//Find repeating key in multiple steps:
//  Find the most probable keysize
//  Try probable keysizes and score result
//  Highest scored result is the answer
scored_bytes find_repeating_key(std::vector<unsigned char> data, int keysize);
std::vector<unsigned char> score_keysize(std::vector<unsigned char> data, int max_keysize, int block_check);

//Use the SSL library to decrypt a text with an AES128ECB cipher
std::vector<unsigned char> AES128ECB_decrypt(std::vector<unsigned char> ciphertext, std::vector<unsigned char> key);
//Use the SSL library to encrypt a text with an AES128ECB cipher
std::vector<unsigned char> AES128ECB_encrypt(std::vector<unsigned char> plaintext, std::vector<unsigned char> key, bool pad=true);

//decrypt using CBC block cipher mode
//   Use the AES128ECB_decrypt to do the AES encryption
std::vector<unsigned char> AES128CBC_decrypt(std::vector<unsigned char> ciphertext, std::vector<unsigned char> key, std::vector<unsigned char> IV);
//Encrypt using CBC block cipher mode
//   Use the AES128ECB_encrypt to do the AES encryption
std::vector<unsigned char> AES128CBC_encrypt(std::vector<unsigned char> plaintext, std::vector<unsigned char> key, std::vector<unsigned char> IV);

//Score line, amount of recurring blocks as the deciding factor
int score_line(std::vector<unsigned char> line, int blocksize, bool use_hamming = false);
scored_int detect_ecb_line(std::vector< std::vector<unsigned char> > ciphertexts, int blocksize);

//Pad data with bytes to match blocksize
//  Value of bytes is amount of blocks to pad
std::vector<unsigned char> pkcs7_pad(std::vector<unsigned char> data, int blocksize);
//Print data in a pretty way to std::string
std::string print_hex(std::vector<unsigned char> data);
std::vector<unsigned char> encryption_oracle(std::vector<unsigned char> plaintext, std::string *method = NULL);

#endif
