#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>
#include "../common/util.h"

int main(void) {
    const char *alg_name = OQS_SIG_alg_ml_dsa_65;
    const char *image_path = "../../tests/image.bin";
    const char *sig_path = "../../tests/image.sig";
    const char *pubkey_path = "../../tests/pubkey.bin";
    const char *seckey_path = "../../tests/seckey.bin";

    size_t image_len = 0;
    unsigned char *image_data = read_binary_file(image_path, &image_len);
    if (!image_data) {
        fprintf(stderr, "Failed to read %s\n", image_path);
        return 1;
    }

    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (!sig) {
        fprintf(stderr, "Failed to initialize %s\n", alg_name);
        free(image_data);
        return 1;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);

    if (!public_key || !secret_key || !signature) {
        fprintf(stderr, "Memory allocation failed\n");
        OQS_SIG_free(sig);
        free(image_data);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    OQS_STATUS rc = OQS_SIG_keypair(sig, public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "Keypair generation failed\n");
        OQS_SIG_free(sig);
        free(image_data);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    size_t signature_len = 0;
    rc = OQS_SIG_sign(sig, signature, &signature_len, image_data, image_len, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "Signing failed\n");
        OQS_MEM_cleanse(secret_key, sig->length_secret_key);
        OQS_SIG_free(sig);
        free(image_data);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    if (!write_binary_file(pubkey_path, public_key, sig->length_public_key)) {
        fprintf(stderr, "Failed to write %s\n", pubkey_path);
        OQS_MEM_cleanse(secret_key, sig->length_secret_key);
        OQS_SIG_free(sig);
        free(image_data);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    if (!write_binary_file(seckey_path, secret_key, sig->length_secret_key)) {
        fprintf(stderr, "Failed to write %s\n", seckey_path);
        OQS_MEM_cleanse(secret_key, sig->length_secret_key);
        OQS_SIG_free(sig);
        free(image_data);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    if (!write_binary_file(sig_path, signature, signature_len)) {
        fprintf(stderr, "Failed to write %s\n", sig_path);
        OQS_MEM_cleanse(secret_key, sig->length_secret_key);
        OQS_SIG_free(sig);
        free(image_data);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    printf("Algorithm: %s\n", alg_name);
    printf("Image: %s (%zu bytes)\n", image_path, image_len);
    printf("Public key written: %s (%zu bytes)\n", pubkey_path, sig->length_public_key);
    printf("Secret key written: %s (%zu bytes)\n", seckey_path, sig->length_secret_key);
    printf("Signature written: %s (%zu bytes)\n", sig_path, signature_len);

    OQS_MEM_cleanse(secret_key, sig->length_secret_key);
    OQS_SIG_free(sig);
    free(image_data);
    free(public_key);
    free(secret_key);
    free(signature);

    return 0;
}