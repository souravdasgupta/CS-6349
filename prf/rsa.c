#include "prf.h"

/*
 * extract_pubkey_from_cert(): Method to extract the RSA key from PKC
 * @pkc_file: Path of the PKC
 * @rsa: Pointer to the RSA object containing the key
 */
int extract_pubkey_from_cert(const char pkc_file[], RSA **rsa) {
        
        BIO *certbio = NULL;
        X509 *cert = NULL;
        EVP_PKEY *pkey = NULL;
        int ret = -1;
        
        certbio = BIO_new(BIO_s_file());
        ret = BIO_read_filename(certbio, pkc_file);
        if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
                printf("extract_pubkey_from_cert()::Error loading cert into memory\n");
                goto error;     
        }
        
        if ((pkey = X509_get_pubkey(cert)) == NULL) {
                  printf("extract_pubkey_from_cert()::Error getting public key from certificate\n");
                  goto error;
        }
        
        *rsa = EVP_PKEY_get1_RSA(pkey);
        if(!rsa){
                printf("extract_pubkey_from_cert()::Error while getting the RSA structure\n");
                goto error;
        }
        ret = 1;
error:
        if(certbio) {
                BIO_free_all(certbio);
        }
        if(cert) {
                X509_free(cert);
        }
        if(pkey) {
                 EVP_PKEY_free(pkey);
        }
        return ret;
}

/*
 * rsa_encrypt(): Method to encrypt data using RSA 2048  
 * @pt: Buffer to the plaintext to be encrypted
 * @pt_size: Size of the plaintext, must be less than 2048 bits or 256 bytes
 * @ct: Uninitialize pointer to return the calculated ciphertext (TODO: Must be freed by the caller)
 * @pubkey_file: Path of the public key file
 */
int rsa_encrypt(unsigned char *pt, size_t pt_size, unsigned char **ct, const char pubkeycert_file[]) {
        int ret; 
        RSA *rsa = NULL;
        
       if(extract_pubkey_from_cert(pubkeycert_file, &rsa) < 0) {
               return -1;
       }
        *ct = (unsigned char *)calloc(RSA_size(rsa), sizeof(unsigned char));
        
        ret = RSA_public_encrypt(pt_size, pt, *ct, rsa, RSA_PKCS1_PADDING);
        if(ret < 0){
                        printf("rsa_encrypt()::Error during encryption, error code = %lu\n",ERR_get_error() );
                        free((void *)*ct);
                        return -1;
        }
        
        if(rsa)
                free(rsa);
        return ret;
}

/*
 * rsa_decrypt(): Method to decrypt data using RSA  
 * @pt: Buffer to hold the decrypted plaintext
 * @ct: Buffer containing the ciphertext
 * @privkey_file: Path of the public key file
 */
int rsa_decrypt(unsigned char *pt,  unsigned char *ct, const char privkey_file[]) {
        FILE * fp = fopen(privkey_file,"rb");
        int ret; 
        RSA *rsa = NULL;
        
        if(fp == NULL) {
                printf("rsa_decrypt()::Unable to open file %s \n",privkey_file);
                return -1;    
        }
        rsa = RSA_new() ;
        PEM_read_RSAPrivateKey(fp, &rsa,NULL, NULL);
        
        ret = RSA_private_decrypt(RSA_size(rsa), ct, pt, rsa, RSA_PKCS1_PADDING);
        if(ret < 0){
                        printf("rsa_decrypt()::Error during decrption, error code = %lu\n",ERR_get_error() );
                        return -1;
        }
        return ret;
}
