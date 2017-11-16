#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

/*
 * Validates the chain of certificate and returns the validation result
 * @ca_path: The path of the crt file for the CA
 * @cert_path: Path of the cerificate(.crt) file of the principal 
 */
int validate_certificate(const char ca_path[], const char cert_path[]) {
        
        X509_STORE_CTX  *vrfy_ctx = NULL;
        BIO *cert_bio = NULL;
        X509_STORE *store = NULL;
        X509 *cert = NULL;
        int ret = 0;
        
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        
        cert_bio = BIO_new(BIO_s_file());
        
        if (!(store=X509_STORE_new())){
                printf("validate_certificate()::Error creating new certificate store\n");
                ret = -1;
                goto error;
        }
        
        vrfy_ctx = X509_STORE_CTX_new();
        
        ret = X509_STORE_load_locations(store, ca_path, NULL);
        if(ret < 0){
                printf("validate_certificate()::Error loading CA certificate file\n");
                ret = -1;
                goto error;
        }
        
        ret = BIO_read_filename(cert_bio, cert_path);
        if (! (cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL))) {
                printf( "validate_certificate()::Error loading cert into memory\n");
                ret = -1;
                goto error;
        }
        
        X509_STORE_CTX_init(vrfy_ctx, store, cert, NULL);
        ret = X509_verify_cert(vrfy_ctx);
        
        if(ret == 0 || ret == 1){
                        printf("validate_certificate()::Verification result text: %s\n", X509_verify_cert_error_string(vrfy_ctx->error));
        }
error:
        if(!vrfy_ctx)
                X509_STORE_CTX_free(vrfy_ctx);
        if(!store)
                X509_STORE_free(store);
        if(!cert)
                X509_free(cert);
        if(!cert_bio)
                BIO_free_all(cert_bio);
        
        return ret;
}
