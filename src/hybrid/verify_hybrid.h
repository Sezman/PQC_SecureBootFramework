#ifndef VERIFY_HYBRID_H
#define VERIFY_HYBRID_H

int verify_hybrid(const char *image,
                const char *rsa_sig,
                const char *rsa_pubkey,
                const char *pqc_sig,
                const char *pqc_pubkey);

#endif
