#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

#include "../common/util.h"
#include "../rsa/rsa_sign.h"

int main(void) {
    const char *image_path = "../../tests/image.bin"

    const char *rsa_pub_path = "../../test/rsa_pub.pem"
    const char *rsa_priv_path   = "../../tests/rsa_priv.pem";
    const char *rsa_sig_path    = "../../tests/image.rsa.sig";

    const char *pqc_pub_path    = "../../tests/pqc_pubkey.bin";
    const char *pqc_sec_path    = "../../tests/pqc_seckey.bin";
    const char *pqc_sig_path    = "../../tests/image.pqc.sig";

    const char *alg_name = OQS_SIG_alg_ml_dsa_65;

    size_t image_len = 0;
    unsigned char *image_data = read_binary_file(image_path, &image_len);
    if (!image_data) {
        fprintf(stderr,"ERROR: Could not open image file %s\n",image_path);
        return 1;
    }

    // RSA
    if (!rsa_generate_keypair(rsa_pub_path, rsa_priv_path)) {
        fprintf(stderr,"ERROR: Could not generate RSA keypair\n");
        free(image_data);
        return 1;
    }

    if (!rsa_sign_file(image_path, rsa_priv_path, rsa_sig_path)) {
        fprintf(stderr, "RSA signing failed\n");
        free(image_data);
        return 1;
    }

    // PQC
    OQS_SIG *sig = OQ_SIG_new(alg_name);
    if (!sig) {
        fprintf(stderr,"ERROR: OQS_SIG_new failed\n");
        free(image_data);
        return 1;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);

    if (!public_key || !secret_key || !signature) {
        fprintf(stderr,"ERROR: PQC memory allocation failed\n");
        OQS_SIG_free(sig);
        free(image_data);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr,"ERROR: OQS_SIG_keypair failed\n");
        OQS_SIG_free(sig);
        free(image_data);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    size_t pqc_sig_len = 0;
    if (OQS_SIG_sign(sig, signature, &pqc_sig_len, image_data, image_len, secret_key) != OQS_SUCCESS) {
        fprintf(stderr,"ERROR: OQS_SIG_sign failed\n");
        OQS_MEM_cleanse(secret_key, sig->length_secret_key);
        OQS_SIG_free(sig);
        free(image_data);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    if (!write_binary_file(pqc_pub_path, public_key, sig->length_public_key) ||
        !write_binary_file(pqc_sec_path, secret_key, sig->length_secret_key) ||
        !write_binary_file(pqc_sig_path, signature, pqc_sig_len)) {
        fprintf(stderr,"ERROR: Could not write pqc public key\n");
        OQS_MEM_cleanse(secret_key, sig->length_secret_key);
        OQS_SIG_free(sig);
        free(image_data);
        free(public_key);
        free(secret_key);
        free(signature);
        return 1;
    }

    printf("Hybrid test data generated successfully\n");
    printf("Image: %s (%zu bytes)\n", image_path, image_len);
    printf("RSA public key: %s\n", rsa_pub_path);
    printf("RSA private key: %s\n", rsa_priv_path);
    printf("RSA signature: %s\n", rsa_sig_path);
    printf("PQC public key: %s\n", pqc_pub_path);
    printf("PQC secret key: %s\n", pqc_sec_path);
    printf("PQC signature: %s (%zu bytes)\n", pqc_sig_path, pqc_sig_len);

    OQS_MEM_cleanse(secret_key, sig->length_secret_key);
    OQS_SIG_free(sig);
    free(image_data);
    free(public_key);
    free(secret_key);
    free(signature);

    return 0;
}