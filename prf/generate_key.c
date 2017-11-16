#include "prf.h"
/*
 * generate_auth_key(): Generates authentication key from the master session key
 * @master: Pointer to the buffer containing the master key
 * @auth_key: Uninitialized pointer to store the new key (must be freed by the caller)
 */
int generate_auth_key(unsigned char *master, unsigned char **auth_key) {
        
        int i , tmax, byte, carry = 0;
        unsigned char *ret;
        
        *auth_key = (unsigned char *)calloc(KEY_SIZE, sizeof(unsigned char));
        ret = *auth_key;
        if(!ret){
                perror("generate_auth_key()::Memory Allocation failed.");
                return -1;
        }
        memcpy(ret, master, KEY_SIZE);
        tmax = (1 << (sizeof(unsigned char) * 8)) - 1;
        
        byte = ret[0];
        ret[0] += 1;
        if((byte+1) < tmax)
                return 0;
        carry = 1;
        for(i = 1; i < KEY_SIZE; i++) {
                byte = ret[i];
                ret[i] += carry;
                if((byte + carry) < tmax){
                        break;
                }
        }
        return 0;
}

/*
 * generate_integrity_key(): Generates integrity key from the master session key
 * @master: Pointer to the buffer containing the master key
 * @integrity_key: Uninitialized pointer to store the new key (must be freed by the caller)
 */
int generate_integrity_key(unsigned char *master, unsigned char **integrity_key) {
        int i , max, byte, carry = 0;
        unsigned char *ret;
        
        *integrity_key = (unsigned char *)calloc(KEY_SIZE, sizeof(unsigned char));
        ret = *integrity_key;
        if(!ret){
                perror("generate_integrity_key()::Memory Allocation failed.");
                return -1;
        }
        memcpy(ret, master, KEY_SIZE);
        max = (1 << (sizeof(unsigned char) * 8)) - 1;
        
        byte = ret[0];
        ret[0] = ret[0] + 2;
        if((byte+2) < max)
                return 0;
        carry = 1;
        for(i = 1; i < KEY_SIZE; i++) {
                byte = ret[i];
                ret[i] += carry;
                if((byte + carry) < max){
                        break;
                }
        }
        return 0;
}
