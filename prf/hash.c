#include "prf.h"
#include <openssl/sha.h>

/*
 * calc_hash: Calculate the hash of a file 
 * @path: Path of the file whose hash we want to calculate
 * @digest: The buffer to store the calculate hash, must be of length SHA256_DIGEST_LENGTH
 */
int calc_hash(const char path[], unsigned char digest[]) {
        
        FILE* file = NULL;
        SHA256_CTX sha256;
        unsigned char buffer[HASH_FILE_READ_SZ];
        size_t bytes_read;
        int ret = 0;
        
        ret = SHA256_Init(&sha256);
        if(!ret){
                printf("calc_hash()::Error in initializing SHA 256\n");
                return -1;
        }
        
        file = fopen(path, "rb");
        if(!file) {
                    perror("calc_hash()::");    
                    return -1;
        }
        
        while((bytes_read = fread(buffer, sizeof(unsigned char), HASH_FILE_READ_SZ, file))) {
                if(!SHA256_Update(&sha256, buffer, bytes_read)) {
                        fclose(file);
                        printf("calc_hash()::Error in SHA256_Update\n");
                        return -1;
                }
        }
        
        if(!SHA256_Final(digest, &sha256)){
                fclose(file);
                printf("calc_hash()::Error in SHA256_Update\n");
                return -1;
        }
        
        fclose(file);
        return 1;
}
