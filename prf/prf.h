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
#define NUM_FEISTEL_ROUNDS 4                //Number of rounds in the feistel network
#define BLOCK_SIZE  64                                //Block size in bytes
#define KEY_SIZE 32                                      //Key size in bytes


extern int feistel_decrypt(unsigned char *data, size_t size, unsigned char *key, unsigned char **plaintext );
extern int feistel_encrypt(unsigned char *data, size_t size, unsigned char *key, unsigned char **ciphertext);
