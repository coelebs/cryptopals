#include <gtest/gtest.h>

#include "set2.h"

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
	std::vector<unsigned char> ciphertext = AES128CBC_encrypt(plaintext, key_data, IV);
	ASSERT_EQ(AES128CBC_decrypt(ciphertext, key_data, IV), plaintext);

	ciphertext = read_base64_file(path);
	plaintext = AES128CBC_decrypt(ciphertext, key_data, IV);
	std::string result(plaintext.begin(), plaintext.end());

	std::cerr << result << std::endl;
}

TEST(Set2, Challenge11) {
	std::vector<unsigned char> plaintext(128);

	//ASSERT_NE(encryption_oracle(plaintext), plaintext);
}

int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
