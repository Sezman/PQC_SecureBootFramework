#include <stdio.h>
#include "verify_pqc.h"
#include "../common/timer.h"

int main(int argc, char *argv[]) {

    if (argc != 4) {
        printf("Usage: %s <image> <signature> <publickey>\n", argv[0]);
        return 1;
    }

    const char *image = argv[1];
    const char *sig = argv[2];
    const char *pubkey = argv[3];

    long start = get_time_us();

    int result = verify_pqc(image, sig, pubkey);

    long end = get_time_us();

    if (result == 1)
        printf("Verification: VALID\n");
    else
        printf("Verification: INVALID\n");

    printf("Verification time: %ld us\n", end - start);

    return 0;
}
