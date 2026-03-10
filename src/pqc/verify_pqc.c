#include "verify_pqc.h"
#include "../common/util.h"
#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

int verify_pqc(const char *image, const char *sig_path, const char *pubkey_path) {
    const char *alg_name = OQS_SIG_alg_ml_dsa_65;

    size_t image_size = 0;
    size_t sig_size = 0;
    size_t pubkey_size = 0;

    unsigned char *image_data = read_binary_file(image, &image_size);
    unsigned char *sig_data = read_binary_file(sig_path, &sig_size);
    unsigned char *pubkey_data = read_binary_file(pubkey_path, &pubkey_size);

    if (!image_data || !sig_data || !pubkey_data) {
        printf("Error: failed to read one or more input files.\n");
        free(image_data);
        free(sig_data);
        free(pubkey_data);
        return 0;
    }

    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (!sig) {
        printf("Error: failed to initialize algorithm %s\n", alg_name);
        free(image_data);
        free(sig_data);
        free(pubkey_data);
        return 0;
    }

    printf("Algorithm: %s\n", alg_name);
    printf("Image: %s (%zu bytes)\n", image, image_size);
    printf("Signature: %s (%zu bytes)\n", sig_path, sig_size);
    printf("Public key: %s (%zu bytes)\n", pubkey_path, pubkey_size);

    if (pubkey_size != sig->length_public_key) {
        printf("Error: public key size mismatch.\n");
        OQS_SIG_free(sig);
        free(image_data);
        free(sig_data);
        free(pubkey_data);
        return 0;
    }

    OQS_STATUS rc = OQS_SIG_verify(sig, image_data, image_size, sig_data, sig_size, pubkey_data);

    OQS_SIG_free(sig);
    free(image_data);
    free(sig_data);
    free(pubkey_data);

    return (rc == OQS_SUCCESS) ? 1 : 0;
}