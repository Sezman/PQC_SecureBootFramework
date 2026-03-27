#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

long get_time_us();
unsigned char *read_binary_file(const char *filename, size_t *size);
int write_binary_file(const char *filename, const unsigned char *data, size_t size);

static const char *ALG_NAME = OQS_SIG_alg_ml_dsa_65;

static void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s verify <image> <signature> <publickey>\n", prog);
    printf("  %s gen <image> <signature> <publickey> <secretkey>\n", prog);
}

static int verify_pqc(const char *image_path, const char *sig_path, const char *pubkey_path) {
    int valid = 0;
    size_t image_size = 0, sig_size = 0, pubkey_size = 0;

    unsigned char *image_data = NULL;
    unsigned char *sig_data = NULL;
    unsigned char *pubkey_data = NULL;
    OQS_SIG *sig = NULL;

    image_data = read_binary_file(image_path, &image_size);
    sig_data = read_binary_file(sig_path, &sig_size);
    pubkey_data = read_binary_file(pubkey_path, &pubkey_size);

    if (!image_data || !sig_data || !pubkey_data) {
        fprintf(stderr, "Error: failed to read one or more input files.\n");
        goto cleanup;
    }

    sig = OQS_SIG_new(ALG_NAME);
    if (!sig) {
        fprintf(stderr, "Error: failed to initialize algorithm %s\n", ALG_NAME);
        goto cleanup;
    }

    if (pubkey_size != sig->length_public_key) {
        fprintf(stderr, "Error: public key size mismatch. Expected %zu bytes.\n",
                sig->length_public_key);
        goto cleanup;
    }

    printf("Algorithm: %s\n", ALG_NAME);
    printf("Image: %s (%zu bytes)\n", image_path, image_size);
    printf("Signature: %s (%zu bytes)\n", sig_path, sig_size);
    printf("Public key: %s (%zu bytes)\n", pubkey_path, pubkey_size);

    valid = (OQS_SIG_verify(sig, image_data, image_size,
                            sig_data, sig_size, pubkey_data) == OQS_SUCCESS);

cleanup:
    OQS_SIG_free(sig);
    free(image_data);
    free(sig_data);
    free(pubkey_data);
    return valid;
}

static int generate_test_data(const char *image_path,
                              const char *sig_path,
                              const char *pubkey_path,
                              const char *seckey_path) {
    int status = 1;
    size_t image_len = 0, signature_len = 0;

    unsigned char *image_data = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *signature = NULL;
    OQS_SIG *sig = NULL;

    image_data = read_binary_file(image_path, &image_len);
    if (!image_data) {
        fprintf(stderr, "Error: failed to read %s\n", image_path);
        goto cleanup;
    }

    sig = OQS_SIG_new(ALG_NAME);
    if (!sig) {
        fprintf(stderr, "Error: failed to initialize algorithm %s\n", ALG_NAME);
        goto cleanup;
    }

    public_key = malloc(sig->length_public_key);
    secret_key = malloc(sig->length_secret_key);
    signature  = malloc(sig->length_signature);

    if (!public_key || !secret_key || !signature) {
        fprintf(stderr, "Error: memory allocation failed.\n");
        goto cleanup;
    }

    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Error: keypair generation failed.\n");
        goto cleanup;
    }

    if (OQS_SIG_sign(sig, signature, &signature_len,
                     image_data, image_len, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Error: signing failed.\n");
        goto cleanup;
    }

    if (!write_binary_file(pubkey_path, public_key, sig->length_public_key) ||
        !write_binary_file(seckey_path, secret_key, sig->length_secret_key) ||
        !write_binary_file(sig_path, signature, signature_len)) {
        fprintf(stderr, "Error: failed to write output files.\n");
        goto cleanup;
    }

    printf("Algorithm: %s\n", ALG_NAME);
    printf("Image: %s (%zu bytes)\n", image_path, image_len);
    printf("Public key written: %s (%zu bytes)\n", pubkey_path, sig->length_public_key);
    printf("Secret key written: %s (%zu bytes)\n", seckey_path, sig->length_secret_key);
    printf("Signature written: %s (%zu bytes)\n", sig_path, signature_len);

    status = 0;

cleanup:
    if (secret_key && sig) {
        OQS_MEM_cleanse(secret_key, sig->length_secret_key);
    }
    OQS_SIG_free(sig);
    free(image_data);
    free(public_key);
    free(secret_key);
    free(signature);
    return status;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "verify") == 0) {
        if (argc != 5) {
            print_usage(argv[0]);
            return 1;
        }

        long start = get_time_us();
        int valid = verify_pqc(argv[2], argv[3], argv[4]);
        long end = get_time_us();

        printf("Verification: %s\n", valid ? "VALID" : "INVALID");
        printf("Verification time: %ld us\n", end - start);
        return valid ? 0 : 1;
    }

    if (strcmp(argv[1], "gen") == 0) {
        if (argc != 6) {
            print_usage(argv[0]);
            return 1;
        }

        return generate_test_data(argv[2], argv[3], argv[4], argv[5]);
    }

    print_usage(argv[0]);
    return 1;
}