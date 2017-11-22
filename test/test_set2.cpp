#include <gtest/gtest.h>

#include "set2.h"

bool VERBOSE = false;

TEST(Set2, Challenge9) {
	int blocksize = 10;

	std::string input_string = "YELLOW SUBMARINE";
	std::vector<unsigned char> input_data(input_string.begin(), input_string.end());

	std::vector<unsigned char> output_data(input_string.begin(), input_string.end());
	for(size_t i = 0; i < 4; i++) {
		output_data.push_back(4);
	}

	ASSERT_EQ(output_data, pkcs7_pad(input_data, blocksize));
}

TEST(Set2, Challenge10) {
	std::string path = "10.txt";
	std::string key = "YELLOW SUBMARINE";

	std::vector<unsigned char> IV(BLOCKSIZE);
	std::fill(IV.begin(), IV.end(), 0);
	std::vector<unsigned char> key_data(key.begin(), key.end());

	std::string input = "YELLOW SUBMARINEYELLOW SUBMARINE";
	std::vector<unsigned char> plaintext(input.begin(), input.end());
	std::vector<unsigned char> ciphertext;
    ciphertext = AES128CBC_encrypt(plaintext, key_data, IV);
	ASSERT_EQ(AES128CBC_decrypt(ciphertext, key_data, IV), plaintext);

	ciphertext = AES128ECB_encrypt(plaintext, key_data, false);
	ASSERT_EQ(AES128ECB_decrypt(ciphertext, key_data), plaintext);

	ciphertext = read_base64_file(path);
	std::fill(IV.begin(), IV.end(), 0);
	plaintext = AES128CBC_decrypt(ciphertext, key_data, IV);
	std::string result(plaintext.begin(), plaintext.end());

	if(VERBOSE) { 
		std::cerr << result << std::endl;
	}
}

TEST(Set2, Challenge11) {
	int blocks = 24;
	std::vector<unsigned char> plaintext(BLOCKSIZE * blocks);
	std::vector<unsigned char> ciphertext(BLOCKSIZE * blocks);
	int score;

	std::fill(plaintext.begin(), plaintext.end(), 0); //fill plaintext with repeating data

	for(size_t i = 0; i < 10; i++) {
		std::string method;
		ciphertext = encryption_oracle(plaintext, &method);
		score = score_line(ciphertext, BLOCKSIZE, false);
		score /= blocks;

		if(score > 1) { //we have matching blocks therefore ECB
			EXPECT_EQ(method, "ECB");
		} else {
			EXPECT_EQ(method, "CBC");
		}
	}
}

int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
