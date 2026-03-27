#include "verify_hybrid.h"
#include "../rsa/rsa_sign.h"
#include "../pqc/verify_pqc.h"
#include <stdio.h>

int verify_hybrid(const char *image,
                const char *rsa_sig,
                const char *rsa_pubkey,
                const char *pqc_sig,
                const char *pqc_pubkey) {
    // int rsa_ok = rsa_verify(image, rsa_sig, rsa_pubkey)
    int pqc_ok = verify_pqc(image, rsa_sig, rsa_pubkey);

    // return (rsa_ok && pqc_ok) ? 0 : 1;
}