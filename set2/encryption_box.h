#include <vector>

#ifndef encryption_box
#define encryption_box

class EncryptionBox {
	private:
		std::vector<unsigned char> key;
		std::vector<unsigned char> appendix;

	public:
		EncryptionBox(std::vector<unsigned char> key);

		void set_key(std::vector<unsigned char> key);
		void set_appendix(std::vector<unsigned char> appendix);

		std::vector<unsigned char> encrypt(std::vector<unsigned char> plaintext);
};

#endif 
