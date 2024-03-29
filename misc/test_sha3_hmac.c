#include "hmac_sha3.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

static void print(const uint8_t *data, int length) {
    for (int i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
}

struct testVector {
    const char *key;
    const int key_len;
    const char *data;
    const int data_len;
};

/**
 * Test vectors by W. Ehrhardt
 */

/*
W.Ehrhardt -- Test vectors for HMAC-SHA3 -- June 2017

Introduction

This page provides test vectors for the HMAC-SHA3 family of message
authentication schemes using the new SHA-3 secure hash algorithm published in
Standard SHA3 / FIPS202. It is an extended update of David Ireland's former
test vector page based on Keccak. Because SHA-3 is not identical to the
submitted Keccak, the HMAC-SHA3 test digests differ. The test vectors given
below were generated using our my SHA-3 implementation. They are used for
regression testing because for a long time there were no known published other
vectors; meanwhile the test cases are cross-verified by independent
implementations, and NIST test vectors are available from
http://csrc.nist.gov/groups/ST/toolkit/examples.html#aMsgAuth.

The HMAC algorithm is described in RFC 2104. The block lengths B to be used in
the HMAC algorithm (i.e. the byte-length of the digest input block) is given in
Tab.3 of FIPS202 (144 bytes for SHA3-224, 136 bytes for SHA3-256, 104 bytes for
SHA3-384, and 72 bytes for SHA3-512).

These tests use the seven test cases from RFC 4231, plus three extra tests (6a,
7a, 8) with key sizes greater than the longest block size for SHA-3 (144 bytes)
or data bit sizes no multiple of 8.

Changes Mar. 2016: Fixed the result values for test case 8 (in earlier versions
the data byte containing the five bits was hashed too), user-requested
intermediate output values in hmac-sha3-intermediate.zip.

Changes June 2017: NIST test vectors are now checked in t_hmac.

Test Vectors

Test Case 1

  Key =          0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
                 0b0b0b0b                          (20 bytes)
  Data =         4869205468657265                  ("Hi There")

 HMAC-SHA3-224 = 3b16546bbc7be2706a031dcafd56373d
                 9884367641d8c59af3c860f7
 HMAC-SHA3-256 = ba85192310dffa96e2a3a40e69774351
                 140bb7185e1202cdcc917589f95e16bb
 HMAC-SHA3-384 = 68d2dcf7fd4ddd0a2240c8a437305f61
                 fb7334cfb5d0226e1bc27dc10a2e723a
                 20d370b47743130e26ac7e3d532886bd
 HMAC-SHA3-512 = eb3fbd4b2eaab8f5c504bd3a41465aac
                 ec15770a7cabac531e482f860b5ec7ba
                 47ccb2c6f2afce8f88d22b6dc61380f2
                 3a668fd3888bb80537c0a0b86407689e

Test Case 2

Test with a key shorter than the length of the HMAC output.

  Key =          4a656665                          ("Jefe")
  Data =         7768617420646f2079612077616e7420  ("what do ya want ")
                 666f72206e6f7468696e673f          ("for nothing?")

 HMAC-SHA3-224 = 7fdb8dd88bd2f60d1b798634ad386811
                 c2cfc85bfaf5d52bbace5e66
 HMAC-SHA3-256 = c7d4072e788877ae3596bbb0da73b887
                 c9171f93095b294ae857fbe2645e1ba5
 HMAC-SHA3-384 = f1101f8cbf9766fd6764d2ed61903f21
                 ca9b18f57cf3e1a23ca13508a93243ce
                 48c045dc007f26a21b3f5e0e9df4c20a
 HMAC-SHA3-512 = 5a4bfeab6166427c7a3647b747292b83
                 84537cdb89afb3bf5665e4c5e709350b
                 287baec921fd7ca0ee7a0c31d022a95e
                 1fc92ba9d77df883960275beb4e62024

Test Case 3

Test with a combined length of key and data that is larger than 64 bytes (=
block-size of SHA-224 and SHA-256).

  Key =          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaa                          (20 bytes)
  Data =         dddddddddddddddddddddddddddddddd
                 dddddddddddddddddddddddddddddddd
                 dddddddddddddddddddddddddddddddd
                 dddd                              (50 bytes)

 HMAC-SHA3-224 = 676cfc7d16153638780390692be142d2
                 df7ce924b909c0c08dbfdc1a
 HMAC-SHA3-256 = 84ec79124a27107865cedd8bd82da996
                 5e5ed8c37b0ac98005a7f39ed58a4207
 HMAC-SHA3-384 = 275cd0e661bb8b151c64d288f1f782fb
                 91a8abd56858d72babb2d476f0458373
                 b41b6ab5bf174bec422e53fc3135ac6e
 HMAC-SHA3-512 = 309e99f9ec075ec6c6d475eda1180687
                 fcf1531195802a99b5677449a8625182
                 851cb332afb6a89c411325fbcbcd42af
                 cb7b6e5aab7ea42c660f97fd8584bf03

Test Case 4

Test with a combined length of key and data that is larger than 64 bytes (=
block-size of SHA-224 and SHA-256).

  Key =          0102030405060708090a0b0c0d0e0f10
                 111213141516171819                (25 bytes)
  Data =         cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
                 cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
                 cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
                 cdcd                              (50 bytes)

 HMAC-SHA3-224 = a9d7685a19c4e0dbd9df2556cc8a7d2a
                 7733b67625ce594c78270eeb
 HMAC-SHA3-256 = 57366a45e2305321a4bc5aa5fe2ef8a9
                 21f6af8273d7fe7be6cfedb3f0aea6d7
 HMAC-SHA3-384 = 3a5d7a879702c086bc96d1dd8aa15d9c
                 46446b95521311c606fdc4e308f4b984
                 da2d0f9449b3ba8425ec7fb8c31bc136
 HMAC-SHA3-512 = b27eab1d6e8d87461c29f7f5739dd58e
                 98aa35f8e823ad38c5492a2088fa0281
                 993bbfff9a0e9c6bf121ae9ec9bb09d8
                 4a5ebac817182ea974673fb133ca0d1d

Test Case 5

Test with a truncation of output to 128 bits.

  Key =          0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
                 0c0c0c0c                          (20 bytes)
  Data =         546573742057697468205472756e6361  ("Test With Trunca")
                 74696f6e                          ("tion")

 HMAC-SHA3-224 = 49fdd3abd005ebb8ae63fea946d1883c
 HMAC-SHA3-256 = 6e02c64537fb118057abb7fb66a23b3c
 HMAC-SHA3-384 = 47c51ace1ffacffd7494724682615783
 HMAC-SHA3-512 = 0fa7475948f43f48ca0516671e18978c

Test Case 6

Test with a key larger than 128 bytes (= block-size of SHA-384 and SHA-512).

  Key =          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaa                            (131 bytes)
  Data =         54657374205573696e67204c61726765  ("Test Using Large")
                 72205468616e20426c6f636b2d53697a  ("r Than Block-Siz")
                 65204b6579202d2048617368204b6579  ("e Key - Hash Key")
                 204669727374                      (" First")

 HMAC-SHA3-224 = b4a1f04c00287a9b7f6075b313d279b8
                 33bc8f75124352d05fb9995f
 HMAC-SHA3-256 = ed73a374b96c005235f948032f09674a
                 58c0ce555cfc1f223b02356560312c3b
 HMAC-SHA3-384 = 0fc19513bf6bd878037016706a0e57bc
                 528139836b9a42c3d419e498e0e1fb96
                 16fd669138d33a1105e07c72b6953bcc
 HMAC-SHA3-512 = 00f751a9e50695b090ed6911a4b65524
                 951cdc15a73a5d58bb55215ea2cd839a
                 c79d2b44a39bafab27e83fde9e11f634
                 0b11d991b1b91bf2eee7fc872426c3a4

Test Case 6a

Test with a key larger than 144 bytes (= block-size of SHA3-224).

  Key =          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaa                            (147 bytes)
  Data =         54657374205573696e67204c61726765  ("Test Using Large")
                 72205468616e20426c6f636b2d53697a  ("r Than Block-Siz")
                 65204b6579202d2048617368204b6579  ("e Key - Hash Key")
                 204669727374                      (" First")

 HMAC-SHA3-224 = b96d730c148c2daad8649d83defaa371
                 9738d34775397b7571c38515
 HMAC-SHA3-256 = a6072f86de52b38bb349fe84cd6d97fb
                 6a37c4c0f62aae93981193a7229d3467
 HMAC-SHA3-384 = 713dff0302c85086ec5ad0768dd65a13
                 ddd79068d8d4c6212b712e4164944911
                 1480230044185a99103ed82004ddbfcc
 HMAC-SHA3-512 = b14835c819a290efb010ace6d8568dc6
                 b84de60bc49b004c3b13eda763589451
                 e5dd74292884d1bdce64e6b919dd61dc
                 9c56a282a81c0bd14f1f365b49b83a5b

Test Case 7

Test with a key and data that is larger than 128 bytes (= block-size of SHA-384
and SHA-512).

  Key =          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaa                            (131 bytes)
  Data =         54686973206973206120746573742075  ("This is a test u")
                 73696e672061206c6172676572207468  ("sing a larger th")
                 616e20626c6f636b2d73697a65206b65  ("an block-size ke")
                 7920616e642061206c61726765722074  ("y and a larger t")
                 68616e20626c6f636b2d73697a652064  ("han block-size d")
                 6174612e20546865206b6579206e6565  ("ata. The key nee")
                 647320746f2062652068617368656420  ("ds to be hashed ")
                 6265666f7265206265696e6720757365  ("before being use")
                 642062792074686520484d414320616c  ("d by the HMAC al")
                 676f726974686d2e                  ("gorithm.")

 HMAC-SHA3-224 = 05d8cd6d00faea8d1eb68ade28730bbd
                 3cbab6929f0a086b29cd62a0
 HMAC-SHA3-256 = 65c5b06d4c3de32a7aef8763261e49ad
                 b6e2293ec8e7c61e8de61701fc63e123

 HMAC-SHA3-384 = 026fdf6b50741e373899c9f7d5406d4e
                 b09fc6665636fc1a530029ddf5cf3ca5
                 a900edce01f5f61e2f408cdf2fd3e7e8
 HMAC-SHA3-512 = 38a456a004bd10d32c9ab83366841128
                 62c3db61adcca31829355eaf46fd5c73
                 d06a1f0d13fec9a652fb3811b577b1b1
                 d1b9789f97ae5b83c6f44dfcf1d67eba

Test Case 7a

Test with a key larger than 144 bytes (= block-size of SHA3-224).

  Key =          aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                 aaaaaa                            (147 bytes)
  Data =         54686973206973206120746573742075  ("This is a test u")
                 73696e672061206c6172676572207468  ("sing a larger th")
                 616e20626c6f636b2d73697a65206b65  ("an block-size ke")
                 7920616e642061206c61726765722074  ("y and a larger t")
                 68616e20626c6f636b2d73697a652064  ("han block-size d")
                 6174612e20546865206b6579206e6565  ("ata. The key nee")
                 647320746f2062652068617368656420  ("ds to be hashed ")
                 6265666f7265206265696e6720757365  ("before being use")
                 642062792074686520484d414320616c  ("d by the HMAC al")
                 676f726974686d2e                  ("gorithm.")

 HMAC-SHA3-224 = c79c9b093424e588a9878bbcb089e018
                 270096e9b4b1a9e8220c866a
 HMAC-SHA3-256 = e6a36d9b915f86a093cac7d110e9e04c
                 f1d6100d30475509c2475f571b758b5a
 HMAC-SHA3-384 = cad18a8ff6c4cc3ad487b95f9769e9b6
                 1c062aefd6952569e6e6421897054cfc
                 70b5fdc6605c18457112fc6aaad45585
 HMAC-SHA3-512 = dc030ee7887034f32cf402df34622f31
                 1f3e6cf04860c6bbd7fa488674782b46
                 59fdbdf3fd877852885cfe6e22185fe7
                 b2ee952043629bc9d5f3298a41d02c66

*/

struct testVector testData[9] = {
    {"\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v\v", 20, "Hi There", 8},
    {"Jefe", 4, "what do ya want for nothing?", 28},
    {"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20, "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd", 50},
    {"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25, "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd", 50},
    {"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", 20, "Test With Truncation", 20},
    {"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131, "Test Using Larger Than Block-Size Key - Hash Key First", 54},
    {"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 147, "Test Using Larger Than Block-Size Key - Hash Key First", 54},
    {"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 131, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", 152},
    {"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 147, "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", 152},
};

int main() {
    // Array for generated hashes
    uint8_t digest[64];

    printf("Testing SHA3-HMAC-224 against test vectors:\n");
    
    for (int i = 0; i < 9; ++i) {
        const char *key = testData[i].key;
        const int key_len = testData[i].key_len;
        const char *data = testData[i].data;
        const int data_len = testData[i].data_len;

        myc_hmac_sha3_224((const uint8_t *)key, key_len, (const uint8_t*)data, data_len, digest, MYC_SHA3_224_DIGEST_LENGTH);

        printf("sha3_hmac_224 (case %d): ", i + 1);
        print((const uint8_t *)digest, MYC_SHA3_224_DIGEST_LENGTH);
        printf("\n");
    }

    printf("Testing SHA3-HMAC-256 against test vectors:\n");
    
    for (int i = 0; i < 9; ++i) {
        const char *key = testData[i].key;
        const int key_len = testData[i].key_len;
        const char *data = testData[i].data;
        const int data_len = testData[i].data_len;

        myc_hmac_sha3_256((const uint8_t *)key, key_len, (const uint8_t*)data, data_len, digest, MYC_SHA3_256_DIGEST_LENGTH);

        printf("sha3_hmac_256 (case %d): ", i + 1);
        print((const uint8_t *)digest, MYC_SHA3_256_DIGEST_LENGTH);
        printf("\n");
    }

    printf("Testing SHA3-HMAC-384 against test vectors:\n");
    
    for (int i = 0; i < 9; ++i) {
        const char *key = testData[i].key;
        const int key_len = testData[i].key_len;
        const char *data = testData[i].data;
        const int data_len = testData[i].data_len;

        myc_hmac_sha3_384((const uint8_t *)key, key_len, (const uint8_t*)data, data_len, digest, MYC_SHA3_384_DIGEST_LENGTH);

        printf("sha2_hmac_384 (case %d): ", i + 1);
        print((const uint8_t *)digest, MYC_SHA3_384_DIGEST_LENGTH);
        printf("\n");
    }

    printf("Testing SHA3-HMAC-512 against test vectors:\n");
    
    for (int i = 0; i < 9; ++i) {
        const char *key = testData[i].key;
        const int key_len = testData[i].key_len;
        const char *data = testData[i].data;
        const int data_len = testData[i].data_len;

        myc_hmac_sha3_512((const uint8_t *)key, key_len, (const uint8_t*)data, data_len, digest, MYC_SHA3_512_DIGEST_LENGTH);

        printf("sha2_hmac_512 (case %d): ", i + 1);
        print((const uint8_t *)digest, MYC_SHA3_512_DIGEST_LENGTH);
        printf("\n");
    }

    return 0;
}
