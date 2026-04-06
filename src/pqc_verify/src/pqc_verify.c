#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "api.h"
#include "randombytes.h"

#define PQC_KEYPAIR_FN PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair
#define PQC_SIGN_FN    PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature
#define PQC_VERIFY_FN  PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify

#define CRYPTO_PUBLICKEYBYTES PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES
#define CRYPTO_SECRETKEYBYTES PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES
#define CRYPTO_BYTES          PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES
#define CRYPTO_ALGNAME        PQCLEAN_MLDSA65_CLEAN_CRYPTO_ALGNAME

static long get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000L + tv.tv_usec;
}

static unsigned char *read_binary_file(const char *filename, size_t *size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("fopen");
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }

    long file_size = ftell(file);
    if (file_size < 0) {
        fclose(file);
        return NULL;
    }

    rewind(file);

    unsigned char *buffer = NULL;

    if (file_size == 0) {
        buffer = (unsigned char *)malloc(1);
        if (!buffer) {
            fclose(file);
            return NULL;
        }
        *size = 0;
        fclose(file);
        return buffer;
    }

    buffer = (unsigned char *)malloc((size_t)file_size);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    size_t bytes_read = fread(buffer, 1, (size_t)file_size, file);
    fclose(file);

    if (bytes_read != (size_t)file_size) {
        free(buffer);
        return NULL;
    }

    *size = (size_t)file_size;
    return buffer;
}

static int write_binary_file(const char *filename, const unsigned char *data, size_t size) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("fopen");
        return 0;
    }

    size_t bytes_written = fwrite(data, 1, size, file);
    fclose(file);

    return bytes_written == size;
}

static void print_memory_usage(void) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        printf("RAM usage (max RSS): %ld KB\n", usage.ru_maxrss);
    } else {
        perror("getrusage");
    }
}

int randombytes(uint8_t *out, size_t outlen) {
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        return -1;
    }

    size_t total = 0;
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

static int pqc_keypair(uint8_t *pk, uint8_t *sk) {
    return PQC_KEYPAIR_FN(pk, sk);
}

static int pqc_sign(uint8_t *sig, size_t *siglen,
                    const uint8_t *msg, size_t msglen,
                    const uint8_t *sk) {
    return PQC_SIGN_FN(sig, siglen, msg, msglen, sk);
}

static int pqc_verify(const uint8_t *sig, size_t siglen,
                      const uint8_t *msg, size_t msglen,
                      const uint8_t *pk) {
    return PQC_VERIFY_FN(sig, siglen, msg, msglen, pk);
}

static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s gen <image> <signature> <publickey> <secretkey>\n", prog);
    printf("  %s verify <image> <signature> <publickey>\n", prog);
}

static int do_gen(const char *image_path,
                  const char *sig_path,
                  const char *pubkey_path,
                  const char *seckey_path) {
    size_t image_len = 0;
    size_t sig_len = 0;

    unsigned char *image_data = read_binary_file(image_path, &image_len);
    if (!image_data) {
        fprintf(stderr, "Error: failed to read image file: %s\n", image_path);
        return 1;
    }

    uint8_t *public_key = (uint8_t *)malloc(CRYPTO_PUBLICKEYBYTES);
    uint8_t *secret_key = (uint8_t *)malloc(CRYPTO_SECRETKEYBYTES);
    uint8_t *signature  = (uint8_t *)malloc(CRYPTO_BYTES);

    if (!public_key || !secret_key || !signature) {
        fprintf(stderr, "Error: memory allocation failed.\n");
        free(image_data);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    if (pqc_keypair(public_key, secret_key) != 0) {
        fprintf(stderr, "Error: keypair generation failed.\n");
        free(image_data);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    if (pqc_sign(signature, &sig_len, image_data, image_len, secret_key) != 0) {
        fprintf(stderr, "Error: signing failed.\n");
        free(image_data);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    if (!write_binary_file(pubkey_path, public_key, CRYPTO_PUBLICKEYBYTES) ||
        !write_binary_file(seckey_path, secret_key, CRYPTO_SECRETKEYBYTES) ||
        !write_binary_file(sig_path, signature, sig_len)) {
        fprintf(stderr, "Error: failed to write output files.\n");
        free(image_data);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    printf("Algorithm: %s\n", CRYPTO_ALGNAME);
    printf("Image: %s (%zu bytes)\n", image_path, image_len);
    printf("Public key written: %s (%d bytes)\n", pubkey_path, CRYPTO_PUBLICKEYBYTES);
    printf("Secret key written: %s (%d bytes)\n", seckey_path, CRYPTO_SECRETKEYBYTES);
    printf("Signature written: %s (%zu bytes)\n", sig_path, sig_len);
    print_memory_usage();

    free(image_data);
    free(public_key);
    free(secret_key);
    free(signature);
    return 0;
}



static int do_verify(const char *image_path,
                     const char *sig_path,
                     const char *pubkey_path) {
    size_t image_len = 0;
    size_t sig_len = 0;
    size_t pubkey_len = 0;

    unsigned char *image_data = read_binary_file(image_path, &image_len);
    unsigned char *sig_data = read_binary_file(sig_path, &sig_len);
    unsigned char *pubkey_data = read_binary_file(pubkey_path, &pubkey_len);

    if (!image_data || !sig_data || !pubkey_data) {
        fprintf(stderr, "Error: failed to read one or more input files.\n");
        free(image_data);
        free(sig_data);
        free(pubkey_data);
        return 1;
    }

    if (pubkey_len != CRYPTO_PUBLICKEYBYTES) {
        fprintf(stderr, "Error: public key size mismatch. Expected %d bytes, got %zu.\n",
                CRYPTO_PUBLICKEYBYTES, pubkey_len);
        free(image_data);
        free(sig_data);
        free(pubkey_data);
        return 1;
    }

    long start = get_time_us();
    int valid = (pqc_verify(sig_data, sig_len, image_data, image_len, pubkey_data) == 0);
    long end = get_time_us();

    printf("Algorithm: %s\n", CRYPTO_ALGNAME);
    printf("Image: %s (%zu bytes)\n", image_path, image_len);
    printf("Signature: %s (%zu bytes)\n", sig_path, sig_len);
    printf("Public key: %s (%zu bytes)\n", pubkey_path, pubkey_len);
    printf("Verification: %s\n", valid ? "VALID" : "INVALID");
    printf("Verification time: %ld us\n", end - start);
    print_memory_usage();

    free(image_data);
    free(sig_data);
    free(pubkey_data);
    return valid ? 0 : 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "gen") == 0) {
        if (argc != 6) {
            print_usage(argv[0]);
            return 1;
        }
        return do_gen(argv[2], argv[3], argv[4], argv[5]);
    }

    if (strcmp(argv[1], "verify") == 0) {
        if (argc != 5) {
            print_usage(argv[0]);
            return 1;
        }
        return do_verify(argv[2], argv[3], argv[4]);
    }

    print_usage(argv[0]);
    return 1;
}
