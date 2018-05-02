#include <gtest/gtest.h>

#include "set2.h"
#include "base64.h"

TEST(Set1, Challenge1) {
	std::vector<unsigned char> bytes = 
		hex_to_bytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
	std::string expected("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

	ASSERT_EQ(base64_encode(&bytes[0], bytes.size()), expected);
}

TEST(Set1, Challenge2) {
	std::vector<unsigned char> a = hex_to_bytes("1c0111001f010100061a024b53535009181c");
	std::vector<unsigned char> b = hex_to_bytes("686974207468652062756c6c277320657965");
	std::string expected_result("746865206b696420646f6e277420706c6179");

	std::vector<unsigned char> c = a ^ b;

	ASSERT_EQ(bytes_to_hex(c), expected_result);
}

TEST(Set1, Challenge3) {
	std::vector<unsigned char> ciphertext = 
		hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
	scored_string solution = find_key(ciphertext);
	std::cout << solution.value << " (" << solution.score << ")" << std::endl;
}

TEST(Set1, Challenge4) {
	std::vector< std::vector<unsigned char> > byte_file = read_hex_file("4.txt");
	std::vector<scored_string> scored_file = score_file(byte_file);

	scored_string solution = {"", 0};

	for(std::vector<scored_string>::iterator i = scored_file.begin(); i < scored_file.end(); i++) {
		if(i->score > solution.score) {
			solution = *i;
		}
	}

	std::cout << solution.value << " (" << solution.score << ")" << std::endl;
}

TEST(Set1, Challenge5) {
	std::string plaintext("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
	std::string key("ICE");
	std::string expected_result("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");

	std::vector<unsigned char> plaintext_data(plaintext.begin(), plaintext.end());
	std::vector<unsigned char> key_data(key.begin(), key.end());	
	
	std::vector<unsigned char> c = plaintext_data ^ key_data;

	std::string result = bytes_to_hex(c);

	ASSERT_EQ(result, expected_result);
}

TEST(Set1, Challenge6) {
	std::vector<unsigned char> data;
	std::vector<unsigned char> plaintext;
	scored_bytes key;

	data = read_base64_file("6.txt");

	plaintext = score_keysize(data, 40, 4);

	std::string result(plaintext.begin(), plaintext.end());

	std::cout << result << std::endl;
}

TEST(Set1, Challenge7) {
	std::string path = "7.txt";
	std::string key = "YELLOW SUBMARINE";

	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;

	std::vector<unsigned char> key_data(key.begin(), key.end());

	ciphertext = read_base64_file(path);

	plaintext = AES128ECB_decrypt(ciphertext, key_data);	

	std::string result(plaintext.begin(), plaintext.end());
	
	std::cout << result << std::endl;
}

TEST(Set1, Challenge8) { 
	std::vector< std::vector<unsigned char> > cipher_file = read_hex_file("8.txt");
	scored_int top_line;

	top_line = detect_ecb_line(cipher_file, 16);

	std::cout << "Line " << top_line.value << "\tScore " << top_line.score << std::endl;
}

int main(int argc, char **argv) {
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
