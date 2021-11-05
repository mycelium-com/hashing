#include "ripemd160.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

static void print(const uint8_t *data, int length) {
    for (int i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
}

struct testVector {
    const char *input;
    const int input_len;
};

/**
Input message: the empty string "", the bit string of length 0.

Algorithm	Output
RIPEMD-160	9c1185a5 c5e9fc54 61280897 7ee8f548 b2258d31

Input message: "abc", the bit string (0x)616263 of length 24 bits.

Algorithm	Output
RIPEMD-160	8eb208f7 e05d987a 9b044a8e 98c6b087 f15a0bfc

Input message: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (length 448 bits).

Algorithm	Output
RIPEMD-160	12a05338 4a9c0c88 e405a06c 27dcf49a da62eb2b

Input message: "abcdefghijklmnopqrstuvwxyz" (length 208 bits).

Algorithm	Output
RIPEMD-160	f71c2710 9c692c1b 56bbdceb 5b9d2865 b3708dbc
*/

struct testVector testData[4] = {
    {"", 0},
    {"abc", 3},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56},
    {"abcdefghijklmnopqrstuvwxyz", 26}
};

int main() {
    // Array for generated hashes
    uint8_t digest[MYC_RIPEMD160_DIGEST_LENGTH];

    printf("Testing RIPEMD-160 against test vectors:\n");
    
    for (int i = 0; i < 4; ++i) {
        const char *input = testData[i].input;
        const int input_len = testData[i].input_len;

        myc_ripemd160((const uint8_t *)input, input_len, digest);

        printf("ripemd160(%s): ", input);
        print((const uint8_t *)digest, MYC_RIPEMD160_DIGEST_LENGTH);
        printf("\n");
    }

    return 0;
}
