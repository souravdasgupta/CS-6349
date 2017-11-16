#include "prf.h"

static unsigned int rnd_mask[] = {134, 19051, 6604, 20439};

/*
 * calc_secure_hash(): Calculates the SHA256 message digest of the data
 * @data: Data whose hash we need to calculate
 * @size: size of the data
 * @digest: Pointer to the buffer which will store the digest
 * @key: Pointer to the buffer containing the key.
 */
void calc_secure_hash(unsigned char *data, size_t size, unsigned char *digest, unsigned char *key) {
        unsigned char *data_with_secret;
        
        data_with_secret = (unsigned char *)calloc(size + KEY_SIZE, sizeof(unsigned char));
        memcpy(data_with_secret, data, size);
        memcpy(data_with_secret + size, key, KEY_SIZE);  
     
        SHA256(data_with_secret, size + KEY_SIZE, digest);
}

/*
 * get_round_key(): Generates round keys from the encryption key for each round
 * @key: Pointer to a buffer containing the actual encryption key 
 * @rnd: Round number
 * @rndkey: Pointer to store the address of the generated round key
 */
void get_round_key(unsigned char *key,  int rnd, unsigned char *rndkey){
        unsigned int *tkey, i;
    
        if(key == NULL ){
                printf("get_round_key()::key is improper\n");
                return;
        }
    
        if(rnd <0 || rnd >3){
                printf("get_round_key():: round %d is not correct\n", rnd);
                return;
        }
        
        memcpy(rndkey, key, KEY_SIZE);
        tkey = (unsigned int *) rndkey;
    
        for(i = 0; i < KEY_SIZE/(sizeof(unsigned int)); i++) {
                tkey[i] ^= rnd_mask[rnd];
        }
}

/*
 * feistel_encrypt(): Performs encryption of data and returns the ciphertext 
 * @data: Pointer to the data to be encrypted
 * @size: Size of the data to be encrypted
 * @key: Decryption key
 * @pt: Uninitialized pointer to store the decrypted plaintext (TODO: Must be freed by the caller)
 */
int feistel_decrypt(unsigned char *data, size_t size, unsigned char *key, unsigned char **plaintext ) {
        int r, ret = 0;
        unsigned char *curr, *index;
        
        if(data == NULL) {
                printf("feistel_decrypt()::Data passed is Null\n");
                return -1;
        }
    
        if(size % BLOCK_SIZE){
                printf("feistel_decrypt()::Invalid ciphertext\n");
                return -1;
        }

        *plaintext =  (unsigned char *)calloc(size, sizeof(unsigned char));
        curr = *plaintext;
        index = data;
    
        while(size > 0){
                unsigned char *left, *right;
                
                memcpy(curr, index, BLOCK_SIZE);
                right = curr;
                left = curr + (BLOCK_SIZE/2);
        
                size -= BLOCK_SIZE;
                index += BLOCK_SIZE;
        
                for(r = 0 ; r < NUM_FEISTEL_ROUNDS; r++) {
                        int i;
                        unsigned char rndkey[KEY_SIZE], digest[SHA256_DIGEST_LENGTH], *tmp;
                        
                        get_round_key(key, NUM_FEISTEL_ROUNDS - r - 1, rndkey);

                        calc_secure_hash(right, (BLOCK_SIZE/2), digest, rndkey);
                        
                        for(i = 0; i < (BLOCK_SIZE/2); i++){
                                left[i] ^= digest[i]; 
                        }
                        tmp = right;
                        right =left;
                        left = tmp;
                }
                ret += BLOCK_SIZE;
                curr += BLOCK_SIZE;
        }

        return ret;
}

/*
 * feistel_encrypt(): Performs encryption of data and returns the ciphertext 
 * @data: Pointer to the data to be encrypted
 * @size: Size of the data to be encrypted
 * @key: Pointer to the buffer storing the encryption key
 * @ct: Uninitialized pointer to return the buffer holding the ciphertext (TODO: Must be greed by the caller)
 */
int feistel_encrypt(unsigned char *data, size_t size, unsigned char *key, unsigned char **ciphertext) {
        
        int r, num_blocks = 0, ret = 0;
        unsigned char *curr, *index;
    
        if(data == NULL) {
                printf("feistel_encrypt()::Data passed is Null\n");
                return -1;
        }
    
        if( size % BLOCK_SIZE){
                printf("feistel_encrypt()::padding opted out yet data size not multiple of block size\n"
                          "If Padding option is set to 0, the data size must be a multiple of Block Size \n");
                return -1;
        }
        
       
        num_blocks = (size/BLOCK_SIZE);
        *ciphertext =  (unsigned char *)calloc(num_blocks * BLOCK_SIZE, sizeof(unsigned char));
         curr = *ciphertext;
        if(curr == NULL) {
                printf("feistel_encrypt()::Unable to allocate buffer for ciphertext\n");
                return -1;
        }
        index = data;
    
        while(size > 0){
                unsigned char *left, *right;

                memcpy(curr, index, BLOCK_SIZE);
                left = curr;
                right = curr + (BLOCK_SIZE/2);
        
                size -= BLOCK_SIZE;
                index += BLOCK_SIZE;
        
                for(r = 0 ; r < NUM_FEISTEL_ROUNDS; r++) {
                        int i;
                        unsigned char rndkey[KEY_SIZE], digest[SHA256_DIGEST_LENGTH], *tmp;
            
                        get_round_key(key, r, rndkey);
                        
                        calc_secure_hash(right, BLOCK_SIZE/2, digest, rndkey);
                        
                        for(i = 0; i < (BLOCK_SIZE/2); i++){
                                left[i] ^= digest[i]; 
                        }
                        tmp = right;
                        right =left;
                        left = tmp;
                        
                }
                ret += BLOCK_SIZE;
                curr += BLOCK_SIZE;
        }
        return ret;  
}