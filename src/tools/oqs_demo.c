#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include "../common/timer.h"

//keep only for debggugging later

int main(void) {
    const char *alg_name = OQS_SIG_alg_ml_dsa_65;
    const uint8_t message[] = "hello firmware";
    const size_t message_len = sizeof(message) - 1;

    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (sig == NULL) {
        fprintf(stderr, "Failed to initialize signature algorithm: %s\n", alg_name);
        return 1;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature  = malloc(sig->length_signature);

    if (!public_key || !secret_key || !signature) {
        fprintf(stderr, "Memory allocation failed\n");
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    OQS_STATUS rc = OQS_SIG_keypair(sig, public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "Keypair generation failed\n");
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    size_t signature_len = 0;
    rc = OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "Signing failed\n");
        OQS_SIG_free(sig);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    long start = get_time_us();
    rc = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
    long end = get_time_us();

    printf("Algorithm: %s\n", alg_name);
    printf("Message size: %zu bytes\n", message_len);
    printf("Public key size: %zu bytes\n", sig->length_public_key);
    printf("Secret key size: %zu bytes\n", sig->length_secret_key);
    printf("Signature size: %zu bytes\n", signature_len);
    printf("Verification: %s\n", (rc == OQS_SUCCESS) ? "VALID" : "INVALID");
    printf("Verification time: %ld us\n", end - start);

    OQS_MEM_cleanse(secret_key, sig->length_secret_key);
    OQS_SIG_free(sig);
    free(public_key);
    free(secret_key);
    free(signature);

    return (rc == OQS_SUCCESS) ? 0 : 1;
}