#include "Crypto.h"
#include <stdexcept>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>


std::vector<unsigned char> Crypto::key_gen() {
    std::vector<unsigned char> key(AES_KEY_SIZE / 8); 
    if (!RAND_bytes(key.data(), key.size())) {
        throw std::runtime_error("Failed to generate key");
    }
    return key;
}


std::vector<unsigned char> Crypto::SHA256(const std::vector<unsigned char>& key, const std::string& address) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    
    HMAC_CTX* ctx = HMAC_CTX_new();
    if (!ctx) {
        throw std::runtime_error("HMAC_CTX_new() failed");
    }

    HMAC_Init_ex(ctx, key.data(), key.size(), EVP_sha256(), NULL);
    HMAC_Update(ctx, reinterpret_cast<const unsigned char*>(address.c_str()), address.size());
    HMAC_Final(ctx, hash, &hash_len);
    HMAC_CTX_free(ctx);

    return std::vector<unsigned char>(hash, hash + 16); 
}


std::vector<unsigned char> Crypto::GCM_encrypt(const std::vector<unsigned char>& key, const std::string& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new() failed");
    }

    std::vector<unsigned char> nonce(GCM_NONCE_LENGTH);
    std::vector<unsigned char> ciphertext(plaintext.size() + GCM_TAG_LENGTH);
    int len;

    
    if (!RAND_bytes(nonce.data(), nonce.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to generate nonce");
    }

    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex() failed");
    }

    
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate() failed");
    }
    int ciphertext_len = len;

    
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex() failed");
    }
    ciphertext_len += len;

    
    std::vector<unsigned char> tag(GCM_TAG_LENGTH);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LENGTH, tag.data());

    
    std::vector<unsigned char> nonce_and_ciphertext(nonce.begin(), nonce.end());
    nonce_and_ciphertext.insert(nonce_and_ciphertext.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    nonce_and_ciphertext.insert(nonce_and_ciphertext.end(), tag.begin(), tag.end());

    EVP_CIPHER_CTX_free(ctx);
    return nonce_and_ciphertext;
}


std::string Crypto::GCM_decryption(const std::vector<unsigned char>& key, const std::vector<unsigned char>& nonce_and_ciphertext) {
    if (nonce_and_ciphertext.size() < GCM_NONCE_LENGTH + GCM_TAG_LENGTH) {
        throw std::runtime_error("Invalid nonce and ciphertext size");
    }

    
    std::vector<unsigned char> nonce(nonce_and_ciphertext.begin(), nonce_and_ciphertext.begin() + GCM_NONCE_LENGTH);
    std::vector<unsigned char> ciphertext(nonce_and_ciphertext.begin() + GCM_NONCE_LENGTH, nonce_and_ciphertext.end() - GCM_TAG_LENGTH);
    std::vector<unsigned char> tag(nonce_and_ciphertext.end() - GCM_TAG_LENGTH, nonce_and_ciphertext.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new() failed");
    }

    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex() failed");
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;

    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate() failed");
    }
    int plaintext_len = len;

    
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LENGTH, tag.data());

    
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

