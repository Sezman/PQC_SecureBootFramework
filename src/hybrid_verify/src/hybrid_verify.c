#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <errno.h>

#include "api.h"
#include "randombytes.h"

// PQC bindings
#define PQC_KEYPAIR_FN PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair
#define PQC_SIGN_FN    PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature
#define PQC_VERIFY_FN  PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify

#define PQC_PUBLICKEYBYTES PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES
#define PQC_SECRETKEYBYTES PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES
#define PQC_SIGBYTES       PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES
#define PQC_ALGNAME        PQCLEAN_MLDSA65_CLEAN_CRYPTO_ALGNAME

// Timing helpers
static long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((long long) ts.tv_sec * 1000000000LL) + ts.tv_nsec;
}

static long get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000L + tv.tv_usec;
}

// File helpers
static long long get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return (long long) st.st_size;
    }
    return -1;
}

static void print_hex(const unsigned char *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void print_memory_usage(void) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        printf("RAM usage (max RSS): %ld\n", usage.ru_maxrss);
    } else {
        perror("getrusage");
    }
}

//randombytes implementation
int randombytes(uint8_t *out, size_t outlen) {
    FILE *fp = fopen("/dev/urandom", "rb");
    size_t total = 0;

    if (!fp) {
        return -1;
    }

    while (total < outlen) {
        size_t got = fread(out + total, 1, outlen - total, fp);
        if (got == 0) {
            fclose(fp);
            return -1;
        }
        total += got;
    }

    fclose(fp);
    return 0;
}

// RSA helpers
static int rsa_generate_keys(const char *priv_path,
                             const char *pub_path,
                             int bits) {
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    FILE *bp_private = NULL;
    FILE *bp_public = NULL;
    int ok = 0;

    bne = BN_new();
    if (!bne || !BN_set_word(bne, RSA_F4)) {
        goto cleanup;
    }

    rsa = RSA_new();
    if (!rsa || !RSA_generate_key_ex(rsa, bits, bne, NULL)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    bp_private = fopen(priv_path, "w");
    if (!bp_private) {
        perror("fopen private key");
        goto cleanup;
    }
    if (!PEM_write_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    fclose(bp_private);
    bp_private = NULL;

    bp_public = fopen(pub_path, "w");
    if (!bp_public) {
        perror("fopen public key");
        goto cleanup;
    }
    if (!PEM_write_RSA_PUBKEY(bp_public, rsa)) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    fclose(bp_public);
    bp_public = NULL;

    ok = 1;

cleanup:
    if (bp_private) fclose(bp_private);
    if (bp_public) fclose(bp_public);
    RSA_free(rsa);
    BN_free(bne);
    return ok;
}

static int rsa_sign_message(const char *privKeyFile,
                            const unsigned char *msg, size_t msgLen,
                            unsigned char **sig, size_t *sigLen,
                            double *sign_ms) {
    FILE *keyFile = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;
    int ok = 0;

    keyFile = fopen(privKeyFile, "r");
    if (!keyFile) {
        perror("fopen private key");
        return 0;
    }

    pkey = PEM_read_PrivateKey(keyFile, NULL, NULL, NULL);
    fclose(keyFile);
    keyFile = NULL;

    if (!pkey) {
        fprintf(stderr, "Error reading RSA private key\n");
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

    *sig = (unsigned char *) malloc(*sigLen);
    if (!*sig) {
        perror("malloc");
        goto cleanup;
    }

    {
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
    }

    ok = 1;

cleanup:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

static int rsa_verify_signature(const char *pubKeyFile,
                                const unsigned char *data, size_t dataLen,
                                const unsigned char *sig, size_t sigLen,
                                double *verify_ms) {
    FILE *keyFile = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdCtx = NULL;
    int result = 0;

    keyFile = fopen(pubKeyFile, "r");
    if (!keyFile) {
        perror("fopen public key");
        return 0;
    }

    pkey = PEM_read_PUBKEY(keyFile, NULL, NULL, NULL);
    fclose(keyFile);
    keyFile = NULL;

    if (!pkey) {
        fprintf(stderr, "Error reading RSA public key\n");
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

    {
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
    }

cleanup:
    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(pkey);
    return result;
}

// PQC helpers
static int pqc_keypair(uint8_t *pk, uint8_t *sk) {
    return PQC_KEYPAIR_FN(pk, sk);
}

static int pqc_sign(uint8_t *sig, size_t *siglen,
                    const uint8_t *msg, size_t msglen,
                    const uint8_t *sk,
                    double *sign_ms) {
    long start = get_time_us();
    int rc = PQC_SIGN_FN(sig, siglen, msg, msglen, sk);
    long end = get_time_us();

    if (sign_ms) {
        *sign_ms = (double)(end - start) / 1000.0;
    }

    return rc;
}

static int pqc_verify(const uint8_t *sig, size_t siglen,
                      const uint8_t *msg, size_t msglen,
                      const uint8_t *pk,
                      double *verify_ms) {
    long start = get_time_us();
    int rc = PQC_VERIFY_FN(sig, siglen, msg, msglen, pk);
    long end = get_time_us();

    if (verify_ms) {
        *verify_ms = (double)(end - start) / 1000.0;
    }

    return rc;
}

// Main hybrid protocol
int main(int argc, char *argv[]) {
    const unsigned char *message = (const unsigned char *)"test firmware image";
    size_t message_len = strlen((const char *)message);

    // RSA artifacts
    const char *rsa_priv = "rsa_private.pem";
    const char *rsa_pub  = "rsa_public.pem";
    unsigned char *rsa_sig = NULL;
    size_t rsa_sig_len = 0;

    // PQC artifacts
    uint8_t *pqc_pk = NULL;
    uint8_t *pqc_sk = NULL;
    uint8_t *pqc_sig_buf = NULL;
    size_t pqc_sig_len = 0;

    // Measurements
    double rsa_sign_ms = 0.0;
    double rsa_verify_ms = 0.0;
    double pqc_sign_ms = 0.0;
    double pqc_verify_ms = 0.0;

    int rsa_valid = 0;
    int pqc_valid = 0;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    printf("=== Hybrid Secure Boot Test ===\n");
    printf("Message: %s\n\n", message);

    // RSA key generation
    if (!rsa_generate_keys(rsa_priv, rsa_pub, 2048)) {
        fprintf(stderr, "RSA key generation failed\n");
        return 1;
    }

    // RSA sign
    if (!rsa_sign_message(rsa_priv, message, message_len,
                          &rsa_sig, &rsa_sig_len, &rsa_sign_ms)) {
        fprintf(stderr, "RSA signing failed\n");
        return 1;
    }

    // RSA verify
    rsa_valid = rsa_verify_signature(rsa_pub, message, message_len,
                                     rsa_sig, rsa_sig_len, &rsa_verify_ms);

    // PQC allocations
    pqc_pk = (uint8_t *) malloc(PQC_PUBLICKEYBYTES);
    pqc_sk = (uint8_t *) malloc(PQC_SECRETKEYBYTES);
    pqc_sig_buf = (uint8_t *) malloc(PQC_SIGBYTES);

    if (!pqc_pk || !pqc_sk || !pqc_sig_buf) {
        fprintf(stderr, "PQC memory allocation failed\n");
        free(rsa_sig);
        free(pqc_pk);
        free(pqc_sk);
        free(pqc_sig_buf);
        return 1;
    }

    // PQC key generation
    if (pqc_keypair(pqc_pk, pqc_sk) != 0) {
        fprintf(stderr, "PQC key generation failed\n");
        free(rsa_sig);
        free(pqc_pk);
        free(pqc_sk);
        free(pqc_sig_buf);
        return 1;
    }

    // PQC sign
    if (pqc_sign(pqc_sig_buf, &pqc_sig_len, message, message_len,
                 pqc_sk, &pqc_sign_ms) != 0) {
        fprintf(stderr, "PQC signing failed\n");
        free(rsa_sig);
        free(pqc_pk);
        free(pqc_sk);
        free(pqc_sig_buf);
        return 1;
    }

    // PQC verify
    pqc_valid = (pqc_verify(pqc_sig_buf, pqc_sig_len, message, message_len,
                            pqc_pk, &pqc_verify_ms) == 0);

    // Hybrid decision
    printf("=== Verification Results ===\n");
    printf("RSA verification: %s\n", rsa_valid ? "VALID" : "INVALID");
    printf("PQC verification: %s\n", pqc_valid ? "VALID" : "INVALID");
    printf("Hybrid verification: %s\n\n",
           (rsa_valid && pqc_valid) ? "VALID" : "INVALID");

    // Measurements
    printf("=== Measurements ===\n");

    printf("\n[RSA]\n");
    printf("Signature generation time: %.3f ms\n", rsa_sign_ms);
    printf("Signature verification time: %.3f ms\n", rsa_verify_ms);
    printf("Signature size: %zu bytes\n", rsa_sig_len);
    printf("Public key size: %lld bytes\n", get_file_size(rsa_pub));

    printf("\n[PQC - %s]\n", PQC_ALGNAME);
    printf("Signature generation time: %.3f ms\n", pqc_sign_ms);
    printf("Signature verification time: %.3f ms\n", pqc_verify_ms);
    printf("Signature size: %zu bytes\n", pqc_sig_len);
    printf("Public key size: %d bytes\n", PQC_PUBLICKEYBYTES);

    printf("\n[Hybrid Totals]\n");
    printf("Combined verification time: %.3f ms\n", rsa_verify_ms + pqc_verify_ms);
    printf("Combined signature size: %zu bytes\n", rsa_sig_len + pqc_sig_len);
    printf("Combined public key size: %lld bytes\n",
           get_file_size(rsa_pub) + (long long) PQC_PUBLICKEYBYTES);

    if (argc > 0) {
        long long exe_size = get_file_size(argv[0]);
        if (exe_size >= 0) {
            printf("Current binary size: %lld bytes\n", exe_size);
            printf("Code size increase: compare against baseline build manually\n");
        } else {
            printf("Current binary size: unavailable\n");
        }
    }

    print_memory_usage();

    printf("\n[RSA signature hex]\n");
    print_hex(rsa_sig, rsa_sig_len);

    free(rsa_sig);
    free(pqc_pk);
    free(pqc_sk);
    free(pqc_sig_buf);

    EVP_cleanup();
    ERR_free_strings();

    return (rsa_valid && pqc_valid) ? 0 : 1;
}
