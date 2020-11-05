#include "sha2.h"

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
SHA-224		d14a028c 2a3a2bc9 476102bb 288234c4 15a2b01f 828ea62a c5b3e42f
SHA-256		e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855
SHA-384		38b060a751ac9638 4cd9327eb1b1e36a 21fdb71114be0743 4c0cc7bf63f6e1da 274edebfe76f65fb d51ad2f14898b95b
SHA-512		cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce 47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e

Input message: "abc", the bit string (0x)616263 of length 24 bits.

Algorithm	Output
SHA-224		23097d22 3405d822 8642a477 bda255b3 2aadbce4 bda0b3f7 e36c9da7
SHA-256		ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
SHA-384		cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163 1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7
SHA-512		ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f

Input message: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (length 448 bits).

Algorithm	Output
SHA-224		75388b16 512776cc 5dba5da1 fd890150 b0c6455c b4f58b19 52522525
SHA-256		248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1
SHA-384		3391fdddfc8dc739 3707a65b1b470939 7cf8b1d162af05ab fe8f450de5f36bc6 b0455a8520bc4e6f 5fe95b1fe3c8452b
SHA-512		204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335 96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445

Input message: "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" (length 896 bits).

Algorithm	Output
SHA-224		c97ca9a5 59850ce9 7a04a96d ef6d99a9 e0e0e2ab 14e6b8df 265fc0b3
SHA-256		cf5b16a7 78af8380 036ce59e 7b049237 0b249b11 e8f07a51 afac4503 7afee9d1
SHA-384		09330c33f71147e8 3d192fc782cd1b47 53111b173b3b05d2 2fa08086e3b0f712 fcc7c71a557e2db9 66c3e9fa91746039
SHA-512		8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909
*/

struct testVector testData[4] = {
    {"", 0},
    {"abc", 3},
    {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56},
    {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112}
};

int main() {
    // Array for generated hashes
    uint8_t digest[64];

    printf("Testing SHA-224 against test vectors:\n");
    
    for (int i = 0; i < 4; ++i) {
        const char *input = testData[i].input;
        const int input_len = testData[i].input_len;

        sha224((const uint8_t *)input, input_len, digest);

        printf("sha224(%s): ", input);
        print((const uint8_t *)digest, SHA224_DIGEST_SIZE);
        printf("\n");
    }

    printf("Testing SHA-256 against test vectors:\n");
    
    for (int i = 0; i < 4; ++i) {
        const char *input = testData[i].input;
        const int input_len = testData[i].input_len;

        sha256((const uint8_t *)input, input_len, digest);

        printf("sha256(%s): ", input);
        print((const uint8_t *)digest, SHA256_DIGEST_SIZE);
        printf("\n");
    }

    printf("Testing SHA-384 against test vectors:\n");
    
    for (int i = 0; i < 4; ++i) {
        const char *input = testData[i].input;
        const int input_len = testData[i].input_len;

        sha384((const uint8_t *)input, input_len, digest);

        printf("sha384(%s): ", input);
        print((const uint8_t *)digest, SHA384_DIGEST_SIZE);
        printf("\n");
    }

    printf("Testing SHA-512 against test vectors:\n");
    
    for (int i = 0; i < 4; ++i) {
        const char *input = testData[i].input;
        const int input_len = testData[i].input_len;

        sha512((const uint8_t *)input, input_len, digest);

        printf("sha512(%s): ", input);
        print((const uint8_t *)digest, SHA512_DIGEST_SIZE);
        printf("\n");
    }

    return 0;
}
