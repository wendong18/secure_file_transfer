// include/sm4.h

#ifndef SM4_CBC_WRAPPER_H
#define SM4_CBC_WRAPPER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <gmssl/sm4.h>   // GmSSL 提供：SM4_KEY, sm4_set_encrypt_key, sm4_set_decrypt_key, sm4_encrypt

/**
 * @brief 使用 SM4-CBC 对 in[0..len) 加密，输出到 out。
 *        len 必须是 16 字节的倍数。
 */
static inline void sm4_cbc_encrypt_wrapper(
    const uint8_t key_bytes[16],
    const uint8_t iv[16],
    const uint8_t *in,
    uint8_t       *out,
    size_t         len)
{
    SM4_KEY sk;
    sm4_set_encrypt_key(&sk, key_bytes);

    uint8_t prev[16];
    memcpy(prev, iv, 16);

    for (size_t off = 0; off < len; off += 16) {
        uint8_t block[16];
        // CBC XOR
        for (int i = 0; i < 16; i++) {
            block[i] = in[off + i] ^ prev[i];
        }
        // 单块 ECB 加密
        sm4_encrypt(&sk, block, out + off);
        // 更新 IV
        memcpy(prev, out + off, 16);
    }
}

/**
 * @brief 使用 SM4-CBC 对 in[0..len) 解密，输出到 out。
 *        len 必须是 16 字节的倍数。
 */
static inline void sm4_cbc_decrypt_wrapper(
    const uint8_t key_bytes[16],
    const uint8_t iv[16],
    const uint8_t *in,
    uint8_t       *out,
    size_t         len)
{
    SM4_KEY sk;
    // 准备解密子密钥
    sm4_set_decrypt_key(&sk, key_bytes);

    uint8_t prev[16];
    memcpy(prev, iv, 16);

    for (size_t off = 0; off < len; off += 16) {
        uint8_t block[16];
        // 单块 ECB“解密”同样调用 sm4_encrypt，只是使用了解密子密钥
        sm4_encrypt(&sk, in + off, block);
        // CBC XOR 还原明文
        for (int i = 0; i < 16; i++) {
            out[off + i] = block[i] ^ prev[i];
        }
        // 更新 IV
        memcpy(prev, in + off, 16);
    }
}

#endif // SM4_CBC_WRAPPER_H

