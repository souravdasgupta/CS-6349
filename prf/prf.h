#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <errno.h>
#include <string.h>

#define min(a,b) ((a) < (b) ? (a) : (b))
#define NUM_FEISTEL_ROUNDS 4                                                         //Number of rounds in the feistel network
#define BLOCK_SIZE  64                                                                         //Block size in bytes
#define KEY_SIZE 32                                                                              //Key size in bytes
#define HASH_LEN SHA256_DIGEST_LENGTH                                    //Length of Hash in bytes (SHA256)
#define HASH_FILE_READ_SZ 32768                                                   //File chunk size


extern int feistel_decrypt(unsigned char *data, size_t size, unsigned char *key, unsigned char **plaintext );
extern int feistel_encrypt(unsigned char *data, size_t size, unsigned char *key, unsigned char **ciphertext);

void encrypt_ctr(unsigned char in[], size_t in_len, unsigned char **output, unsigned char key[], unsigned char iv[]);
void decrypt_ctr( unsigned char in[], size_t in_len, unsigned char out[],  unsigned char key[],  unsigned char iv[]);

extern int generate_auth_key(unsigned char *master, unsigned char **auth_key);
extern int generate_integrity_key(unsigned char *master, unsigned char **integrity_key);

extern int rsa_encrypt(unsigned char *pt, size_t pt_size, unsigned char **ct, const char pubkeycert_file[]);
extern int rsa_decrypt(unsigned char *pt,  unsigned char *ct, const char privkey_file[]);

extern int calc_hash(const char path[], unsigned char digest[]);
