#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>
#include <errno.h>


// Helper: return time in nanoseconds
static long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((long long)ts.tv_sec * 1000000000LL) + ts.tv_nsec;
}

// Helper: file size in bytes
static long long get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return (long long)st.st_size;
    }
    return -1;
}

// Helper: print buffer as hex
static void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

// Helper: report memory usage
static void print_memory_usage(void) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        printf("RAM usage (max RSS): %ld\n", usage.ru_maxrss);
    } else {
        perror("getrusage");
    }
}

int verify_signature(const char* pubKeyFile,
                     const unsigned char *data, size_t dataLen,
                     const unsigned char *sig, size_t sigLen,
                     double *verify_ms) {
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdCtx = NULL;
    FILE *keyFile = NULL;
    int result = 0;

    keyFile = fopen(pubKeyFile, "r");
    if (!keyFile) {
        perror("fopen public key");
        return 0;
    }

    pkey = PEM_read_PUBKEY(keyFile, NULL, NULL, NULL);
    fclose(keyFile);

    if (!pkey) {
        fprintf(stderr, "Error reading public key\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    mdCtx = EVP_MD_CTX_new();
    if (!mdCtx) {
        EVP_PKEY_free(pkey);
        return 0;
    }

    if (EVP_DigestVerifyInit(mdCtx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (EVP_DigestVerifyUpdate(mdCtx, data, dataLen) != 1) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    long long start_ns = now_ns();
    int verify_ret = EVP_DigestVerifyFinal(mdCtx, sig, sigLen);
    long long end_ns = now_ns();

    if (verify_ms) {
        *verify_ms = (end_ns - start_ns) / 1e6;
    }

    if (verify_ret == 1) {
        result = 1;
    } else if (verify_ret == 0) {
        result = 0;
    } else {
        ERR_print_errors_fp(stderr);
        result = 0;
    }

cleanup:
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(pkey);
    return result;
}

int sign_message(const char* privKeyFile,
                 const unsigned char* msg, size_t msgLen,
                 unsigned char** sig, size_t* sigLen,
                 double *sign_ms) {
    FILE *keyFile = fopen(privKeyFile, "r");
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ok = 0;

    if (!keyFile) {
        perror("fopen private key");
        return 0;
    }

    pkey = PEM_read_PrivateKey(keyFile, NULL, NULL, NULL);
    fclose(keyFile);

    if (!pkey) {
        fprintf(stderr, "Error reading private key\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return 0;
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (EVP_DigestSignUpdate(ctx, msg, msgLen) != 1) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (EVP_DigestSignFinal(ctx, NULL, sigLen) != 1) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    *sig = (unsigned char *)malloc(*sigLen);
    if (!*sig) {
        perror("malloc");
        goto cleanup;
    }

    long long start_ns = now_ns();
    if (EVP_DigestSignFinal(ctx, *sig, sigLen) != 1) {
        ERR_print_errors_fp(stderr);
        free(*sig);
        *sig = NULL;
        goto cleanup;
    }
    long long end_ns = now_ns();

    if (sign_ms) {
        *sign_ms = (end_ns - start_ns) / 1e6;
    }

    ok = 1;

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

int main(int argc, char *argv[]) {
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    unsigned long e = RSA_F4;
    FILE *bp_public = NULL, *bp_private = NULL;
    int bits = 2048;

    const char *message = "test";
    size_t message_len = strlen(message);

    unsigned char *sig = NULL;
    size_t sigLen = 0;

    double sign_ms = 0.0;
    double verify_ms = 0.0;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // 1. Generate Key Pair
    bne = BN_new();
    if (!bne || !BN_set_word(bne, e)) {
        fprintf(stderr, "BN setup failed\n");
        return 1;
    }

    rsa = RSA_new();
    if (!rsa || !RSA_generate_key_ex(rsa, bits, bne, NULL)) {
        fprintf(stderr, "RSA key generation failed\n");
        ERR_print_errors_fp(stderr);
        BN_free(bne);
        return 1;
    }

    // 2. Save Private Key
    bp_private = fopen("private.pem", "w");
    if (!bp_private) {
        perror("fopen private.pem");
        RSA_free(rsa);
        BN_free(bne);
        return 1;
    }
    PEM_write_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(bp_private);

    // 3. Save Public Key
    bp_public = fopen("public.pem", "w");
    if (!bp_public) {
        perror("fopen public.pem");
        RSA_free(rsa);
        BN_free(bne);
        return 1;
    }
    PEM_write_RSA_PUBKEY(bp_public, rsa);
    fclose(bp_public);

    printf("RSA keys generated: private.pem, public.pem\n");

    // Sign
    if (!sign_message("private.pem",
                      (const unsigned char *)message, message_len,
                      &sig, &sigLen, &sign_ms)) {
        fprintf(stderr, "Signing failed\n");
        RSA_free(rsa);
        BN_free(bne);
        return 1;
    }

    // Verify
    int result = verify_signature("public.pem",
                                  (const unsigned char *)message, message_len,
                                  sig, sigLen, &verify_ms);

    // Measurements
    printf("\n=== Measurements ===\n");

    // Signature verification time
    printf("Signature verification time: %.3f ms\n", verify_ms);

    // Optional signing time
    printf("Signature generation time: %.3f ms\n", sign_ms);

    // Signature size
    printf("Signature size: %zu bytes\n", sigLen);

    // Public key size
    long long public_key_size = get_file_size("public.pem");
    if (public_key_size >= 0) {
        printf("Public key size: %lld bytes\n", public_key_size);
    } else {
        printf("Public key size: unavailable\n");
    }

    // Private key size
    long long private_key_size = get_file_size("private.pem");
    if (private_key_size >= 0) {
        printf("Private key size: %lld bytes\n", private_key_size);
    }

    // Current executable size = use this to compare against baseline build
    if (argc > 0) {
        long long exe_size = get_file_size(argv[0]);
        if (exe_size >= 0) {
            printf("Current binary size: %lld bytes\n", exe_size);
            printf("Code size increase: compare this against baseline build manually\n");
        } else {
            printf("Current binary size: unavailable\n");
        }
    }

    // RAM usage
    print_memory_usage();

    // Verification result
    printf("Verification result: %s\n", result ? "SUCCESS" : "FAILURE");

    return 0;
}
