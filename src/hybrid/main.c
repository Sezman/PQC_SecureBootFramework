#include <stdio.h>
#include "../common/timer.h"
#include "verify_hybrid.h"

int main(int argc, char *argv[]) {
    argc = [executable, image, rsa_sig, rsa_pub, pqc_sig, pqc_pub]
    if (argc != 6) {
        return 1;
    }

    long start = get_time_us();

    int result = verify_hybrid(argv[1], argv[2], argv[3], argv[4], argv[5]);

    long end = get_time_us();

    if (result)
        printf("Hybrid Verification: VALID\n");
    else
        printf("Hybrid Verification: INVALID\n");

    printf("Hybrid verification time: %ld us\n", end - start);

    return result ? 0 : 1;
}