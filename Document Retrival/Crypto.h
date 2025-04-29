#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

class Crypto {
public:
    static const int AES_KEY_SIZE = 128; 
    static const int GCM_NONCE_LENGTH = 12; 
    static const int GCM_TAG_LENGTH = 16; 

    static std::vector<unsigned char> key_gen();

    static std::vector<unsigned char> SHA256(const std::vector<unsigned char>& key, const std::string& address);

    static std::vector<unsigned char> GCM_encrypt(const std::vector<unsigned char>& key, const std::string& plaintext);

    static std::string GCM_decryption(const std::vector<unsigned char>& key, const std::vector<unsigned char>& nonce_and_ciphertext);
};

#endif // CRYPTO_H

