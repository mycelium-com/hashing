/*
 * FIPS 180-2 SHA-224/256/384/512 implementation
 * Last update: 02/02/2007
 * Issue date:  04/30/2005
 *
 * Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef MYC_SHA2_H
#define MYC_SHA2_H

#define MYC_SHA224_DIGEST_SIZE ( 224 / 8)
#define MYC_SHA256_DIGEST_SIZE ( 256 / 8)
#define MYC_SHA384_DIGEST_SIZE ( 384 / 8)
#define MYC_SHA512_DIGEST_SIZE ( 512 / 8)

#define MYC_SHA256_BLOCK_SIZE  ( 512 / 8)
#define MYC_SHA512_BLOCK_SIZE  (1024 / 8)
#define MYC_SHA384_BLOCK_SIZE  MYC_SHA512_BLOCK_SIZE
#define MYC_SHA224_BLOCK_SIZE  MYC_SHA256_BLOCK_SIZE

#ifndef MYC_SHA2_TYPES
#define MYC_SHA2_TYPES
typedef unsigned char uint8;
typedef unsigned int  uint32;
typedef unsigned long long uint64;
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned int tot_len;
    unsigned int len;
    unsigned char block[2 * MYC_SHA256_BLOCK_SIZE];
    uint32 h[8];
} myc_sha256_ctx;

typedef struct {
    unsigned int tot_len;
    unsigned int len;
    unsigned char block[2 * MYC_SHA512_BLOCK_SIZE];
    uint64 h[8];
} myc_sha512_ctx;

typedef myc_sha512_ctx myc_sha384_ctx;
typedef myc_sha256_ctx myc_sha224_ctx;

void myc_sha224_init(myc_sha224_ctx *ctx);
void myc_sha224_update(myc_sha224_ctx *ctx, const unsigned char *message,
                   unsigned int len);
void myc_sha224_final(myc_sha224_ctx *ctx, unsigned char *digest);
void myc_sha224(const unsigned char *message, unsigned int len,
            unsigned char *digest);

void myc_sha256_init(myc_sha256_ctx * ctx);
void myc_sha256_update(myc_sha256_ctx *ctx, const unsigned char *message,
                   unsigned int len);
void myc_sha256_final(myc_sha256_ctx *ctx, unsigned char *digest);
void myc_sha256(const unsigned char *message, unsigned int len,
            unsigned char *digest);

void myc_sha384_init(myc_sha384_ctx *ctx);
void myc_sha384_update(myc_sha384_ctx *ctx, const unsigned char *message,
                   unsigned int len);
void myc_sha384_final(myc_sha384_ctx *ctx, unsigned char *digest);
void myc_sha384(const unsigned char *message, unsigned int len,
            unsigned char *digest);

void myc_sha512_init(myc_sha512_ctx *ctx);
void myc_sha512_update(myc_sha512_ctx *ctx, const unsigned char *message,
                   unsigned int len);
void myc_sha512_final(myc_sha512_ctx *ctx, unsigned char *digest);
void myc_sha512(const unsigned char *message, unsigned int len,
            unsigned char *digest);

#ifdef __cplusplus
}
#endif

#endif /* !SHA2_P */

