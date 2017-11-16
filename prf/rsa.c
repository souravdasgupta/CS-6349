#include "prf.h"

/*
 * rsa_encrypt(): Method to encrypt data using RSA 2048  
 * @pt: Buffer to the plaintext to be encrypted
 * @pt_size: Size of the plaintext, must be less than 2048 bits or 256 bytes
 * @ct: Uninitialize pointer to return the calculated ciphertext (TODO: Must be freed by the caller)
 * @pubkey_file: Path of the public key file
 */
int rsa_encrypt(unsigned char *pt, size_t pt_size, unsigned char **ct, const char pubkey_file[]) {
        
}
