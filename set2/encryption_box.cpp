#include "encryption_box.h"
#include "set2.h"

#include <iostream>

EncryptionBox::EncryptionBox(std::vector<unsigned char> key) {
	this->key = key;
}

void EncryptionBox::set_key(std::vector<unsigned char> key) {
	this->key = key;
}

void EncryptionBox::set_appendix(std::vector<unsigned char> appendix) {
	this->appendix = appendix;
}

std::vector<unsigned char> EncryptionBox::encrypt(std::vector<unsigned char> plaintext) {
	plaintext.insert(plaintext.end(), this->appendix.begin(), this->appendix.end());
	auto ciphertext = AES128ECB_encrypt(plaintext, this->key);
	return ciphertext;
}
