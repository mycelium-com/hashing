/*
 * Original copyright notice:
 * 
 * HMAC-SHA-224/256/384/512 implementation
 * Last update: 06/15/2005
 * Issue date:  06/15/2005
 *
 * Copyright (C) 2005 Olivier Gay <olivier.gay@a3.epfl.ch>
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

#ifndef MYC_HMAC_SHA3_H
#define MYC_HMAC_SHA3_H

#include "sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    MYC_SHA3_CTX ctx_inside;
    MYC_SHA3_CTX ctx_outside;

    /* for hmac_reinit */
    MYC_SHA3_CTX ctx_inside_reinit;
    MYC_SHA3_CTX ctx_outside_reinit;

    unsigned char block_ipad[MYC_SHA3_224_BLOCK_LENGTH];
    unsigned char block_opad[MYC_SHA3_224_BLOCK_LENGTH];
} myc_hmac_sha3_224_ctx;

typedef struct {
    MYC_SHA3_CTX ctx_inside;
    MYC_SHA3_CTX ctx_outside;

    /* for hmac_reinit */
    MYC_SHA3_CTX ctx_inside_reinit;
    MYC_SHA3_CTX ctx_outside_reinit;

    unsigned char block_ipad[MYC_SHA3_256_BLOCK_LENGTH];
    unsigned char block_opad[MYC_SHA3_256_BLOCK_LENGTH];
} myc_hmac_sha3_256_ctx;

typedef struct {
    MYC_SHA3_CTX ctx_inside;
    MYC_SHA3_CTX ctx_outside;

    /* for hmac_reinit */
    MYC_SHA3_CTX ctx_inside_reinit;
    MYC_SHA3_CTX ctx_outside_reinit;

    unsigned char block_ipad[MYC_SHA3_384_BLOCK_LENGTH];
    unsigned char block_opad[MYC_SHA3_384_BLOCK_LENGTH];
} myc_hmac_sha3_384_ctx;

typedef struct {
    MYC_SHA3_CTX ctx_inside;
    MYC_SHA3_CTX ctx_outside;

    /* for hmac_reinit */
    MYC_SHA3_CTX ctx_inside_reinit;
    MYC_SHA3_CTX ctx_outside_reinit;

    unsigned char block_ipad[MYC_SHA3_512_BLOCK_LENGTH];
    unsigned char block_opad[MYC_SHA3_512_BLOCK_LENGTH];
} myc_hmac_sha3_512_ctx;

void myc_hmac_sha3_224_init(myc_hmac_sha3_224_ctx *ctx, const unsigned char *key,
                      unsigned int key_size);
void myc_hmac_sha3_224_reinit(myc_hmac_sha3_224_ctx *ctx);
void myc_hmac_sha3_224_update(myc_hmac_sha3_224_ctx *ctx, const unsigned char *message,
                        unsigned int message_len);
void myc_hmac_sha3_224_final(myc_hmac_sha3_224_ctx *ctx, unsigned char *mac,
                       unsigned int mac_size);
void myc_hmac_sha3_224(const unsigned char *key, unsigned int key_size,
                 const unsigned char *message, unsigned int message_len,
                 unsigned char *mac, unsigned mac_size);

void myc_hmac_sha3_256_init(myc_hmac_sha3_256_ctx *ctx, const unsigned char *key,
                      unsigned int key_size);
void myc_hmac_sha3_256_reinit(myc_hmac_sha3_256_ctx *ctx);
void myc_hmac_sha3_256_update(myc_hmac_sha3_256_ctx *ctx, const unsigned char *message,
                        unsigned int message_len);
void myc_hmac_sha3_256_final(myc_hmac_sha3_256_ctx *ctx, unsigned char *mac,
                       unsigned int mac_size);
void myc_hmac_sha3_256(const unsigned char *key, unsigned int key_size,
                 const unsigned char *message, unsigned int message_len,
                 unsigned char *mac, unsigned mac_size);

void myc_hmac_sha3_384_init(myc_hmac_sha3_384_ctx *ctx, const unsigned char *key,
                      unsigned int key_size);
void myc_hmac_sha3_384_reinit(myc_hmac_sha3_384_ctx *ctx);
void myc_hmac_sha3_384_update(myc_hmac_sha3_384_ctx *ctx, const unsigned char *message,
                        unsigned int message_len);
void myc_hmac_sha3_384_final(myc_hmac_sha3_384_ctx *ctx, unsigned char *mac,
                       unsigned int mac_size);
void myc_hmac_sha3_384(const unsigned char *key, unsigned int key_size,
                 const unsigned char *message, unsigned int message_len,
                 unsigned char *mac, unsigned mac_size);

void myc_hmac_sha3_512_init(myc_hmac_sha3_512_ctx *ctx, const unsigned char *key,
                      unsigned int key_size);
void myc_hmac_sha3_512_reinit(myc_hmac_sha3_512_ctx *ctx);
void myc_hmac_sha3_512_update(myc_hmac_sha3_512_ctx *ctx, const unsigned char *message,
                        unsigned int message_len);
void myc_hmac_sha3_512_final(myc_hmac_sha3_512_ctx *ctx, unsigned char *mac,
                       unsigned int mac_size);
void myc_hmac_sha3_512(const unsigned char *key, unsigned int key_size,
                 const unsigned char *message, unsigned int message_len,
                 unsigned char *mac, unsigned mac_size);

#ifdef __cplusplus
}
#endif

#endif /* !HMAC_SHA3_H */
