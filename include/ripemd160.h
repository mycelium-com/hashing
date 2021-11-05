#ifndef __MYCRIPEMD160_H__
#define __MYCRIPEMD160_H__

#include <stdint.h>

#define MYC_RIPEMD160_BLOCK_LENGTH 64
#define MYC_RIPEMD160_DIGEST_LENGTH 20

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _MYC_RIPEMD160_CTX {
  uint32_t total[2];                      /*!< number of bytes processed  */
  uint32_t state[5];                      /*!< intermediate digest state  */
  uint8_t buffer[MYC_RIPEMD160_BLOCK_LENGTH]; /*!< data block being processed */
} MYC_RIPEMD160_CTX;

void myc_ripemd160_Init(MYC_RIPEMD160_CTX *ctx);
void myc_ripemd160_Update(MYC_RIPEMD160_CTX *ctx, const uint8_t *input, uint32_t ilen);
void myc_ripemd160_Final(MYC_RIPEMD160_CTX *ctx,
                     uint8_t output[MYC_RIPEMD160_DIGEST_LENGTH]);
void myc_ripemd160(const uint8_t *msg, uint32_t msg_len,
               uint8_t hash[MYC_RIPEMD160_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif
