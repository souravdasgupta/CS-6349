#include "prf.h"

void xor_buf(unsigned char in[], unsigned char out[], size_t len) {
        size_t idx;

        for (idx = 0; idx < len; idx++)
                out[idx] ^= in[idx];
}

void increment_iv(unsigned char iv[], int counter_size) {
        int idx;

        // Use counter_size bytes at the end of the IV as the big-endian integer to increment.
        for (idx = BLOCK_SIZE - 1; idx >= BLOCK_SIZE - counter_size; idx--) {
                iv[idx]++;
                if (iv[idx] != 0 || idx == BLOCK_SIZE - counter_size)
                        break;
        }
}

// Performs the encryption in-place, the input and output buffers may be the same.
// Input may be an arbitrary length (in bytes).
void aes_encrypt_ctr(unsigned char in[], size_t in_len, unsigned char out[], unsigned char key[], unsigned char iv[]) {
        size_t idx = 0, last_block_length, sz;
        unsigned char iv_buf[BLOCK_SIZE], *out_buf;

        if (in != out)
                memcpy(out, in, in_len);

        memcpy(iv_buf, iv, BLOCK_SIZE);
        last_block_length = in_len - BLOCK_SIZE;

        if (in_len > BLOCK_SIZE) {
                for (idx = 0; idx < last_block_length; idx += BLOCK_SIZE) {
                        
                        sz = feistel_encrypt(iv_buf, BLOCK_SIZE,  key, &out_buf);
                        xor_buf(out_buf, &out[idx], sz);
                        increment_iv(iv_buf, BLOCK_SIZE);
                }
        }

        sz = feistel_encrypt(iv_buf, BLOCK_SIZE, key, &out_buf);
        xor_buf(out_buf, &out[idx], in_len - idx);   // Use the Most Significant bytes.
}

void aes_decrypt_ctr( unsigned char in[], size_t in_len, unsigned char out[],  unsigned char key[],  unsigned char iv[]) {
	// CTR encryption is its own inverse function.
	aes_encrypt_ctr(in, in_len, out, key, iv);
}
 
