#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>


int verify_signature(const char* pubKeyFile,
                     unsigned char *data, size_t dataLen,
                     unsigned char *sig, size_t sigLen) {
	EVP_PKEY* pkey = NULL;
    EVP_MD_CTX *mdCtx = NULL;
    BIO *keyBio = NULL;
    int result = 0;

    // 1. Load Public Key
    FILE* keyFile = fopen(pubKeyFile, "r");
	if (!PEM_read_PUBKEY(keyFile, &pkey, NULL, NULL)){
		printf("error reading public key");
		exit(1);
	}
	fclose(keyFile);

    // 2. Initialize Verification Context
    mdCtx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mdCtx, NULL, EVP_sha256(), NULL, pkey);

    // 3. Update with Data
    EVP_DigestVerifyUpdate(mdCtx, data, dataLen);

    // 4. Final Verification
    if (EVP_DigestVerifyFinal(mdCtx, sig, sigLen) == 1) {
        result = 1; // Success
    }

    // Cleanup
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(pkey);
    BIO_free(keyBio);
    return result;
}

// Assuming 'private.pem' exists
int sign_message(const char* privKeyFile, const unsigned char* msg, size_t msgLen, unsigned char** sig, size_t* sigLen) {
    FILE* keyFile = fopen(privKeyFile, "r");
    EVP_PKEY* pkey = NULL;
	if (!PEM_read_PrivateKey(keyFile, &pkey, NULL, NULL)){
		printf("error reading private key");
		exit(1);
	}
    fclose(keyFile);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    // Initialize context with SHA256
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    // Update with message
    EVP_DigestSignUpdate(ctx, msg, msgLen);
    // Determine signature length
    EVP_DigestSignFinal(ctx, NULL, sigLen);
    // Allocate memory and finalize signature
    printf("test\n");
    *sig = (unsigned char*)malloc(*sigLen);
    EVP_DigestSignFinal(ctx, *sig, sigLen);
    printf("test\n");

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 1;
}

int main() {
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    unsigned long e = RSA_F4; // 65537
    FILE *bp_public = NULL, *bp_private = NULL;
    int bits = 2048;

    // 1. Generate Key Pair
    bne = BN_new();
    BN_set_word(bne, e);
    rsa = RSA_new();
    RSA_generate_key_ex(rsa, bits, bne, NULL);

    // 2. Save Private Key
    bp_private = fopen("private.pem", "w");
    PEM_write_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(bp_private);

    // 3. Save Public Key
    bp_public = fopen("public.pem", "w");
    PEM_write_RSA_PUBKEY(bp_public, rsa);
    fclose(bp_public);

    printf("RSA keys generated: private.pem, public.pem\n");

    unsigned char* sig = NULL;
	size_t sigLen;

    sign_message("private.pem", "test", 4, &sig, &sigLen);

    printf("signiture: %s\n", sig);
    printf("signiture len: %ld\n", sigLen);

    int result = verify_signature("public.pem","test", 4, sig, sigLen);

    printf("result: %d", result);

    // 4. Cleanup
    RSA_free(rsa);
    BN_free(bne);

    return 0;
}
