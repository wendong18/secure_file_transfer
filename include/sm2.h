// include/sm2.h

#ifndef SM2_WRAPPER_H
#define SM2_WRAPPER_H

#include <stddef.h>
#include <stdint.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>

// SM2密钥对管理
/**
 * @brief 生成SM2密钥对
 * @param privkey_hex 输出，私钥的十六进制字符串，长度至少为65字节
 * @param pubkey_hex 输出，公钥的十六进制字符串，长度至少为129字节
 * @return 成功返回0，失败返回-1
 */
int sm2_generate_keypair(char *privkey_hex, char *pubkey_hex);

/**
 * @brief 使用SM2算法对数据进行签名
 * @param data 待签名数据
 * @param data_len 数据长度
 * @param privkey_hex 私钥的十六进制字符串
 * @param sig_hex 输出，签名的十六进制字符串，长度至少为129字节
 * @return 成功返回0，失败返回-1
 */
int sm2_sign_data(const uint8_t *data, size_t data_len, const char *privkey_hex, char *sig_hex);

/**
 * @brief 使用SM2算法验证签名
 * @param data 原始数据
 * @param data_len 数据长度
 * @param pubkey_hex 公钥的十六进制字符串
 * @param sig_hex 签名的十六进制字符串
 * @return 签名有效返回1，无效返回0，错误返回-1
 */
int sm2_verify_signature(const uint8_t *data, size_t data_len, const char *pubkey_hex, const char *sig_hex);

/**
 * @brief 使用SM2和SM4实现混合加密：对称密钥的非对称加密
 * @param data 明文数据
 * @param data_len 数据长度
 * @param pubkey_hex 接收方公钥的十六进制字符串
 * @param out 输出缓冲区，需要预先分配足够空间
 * @param out_len 输出参数，加密后的数据长度
 * @return 成功返回0，失败返回-1
 * 
 * 注：输出格式为 [SM2加密的SM4密钥(固定长度)][SM4加密的数据]
 */
int sm2_hybrid_encrypt(const uint8_t *data, size_t data_len, const char *pubkey_hex, 
                        uint8_t *out, size_t *out_len);

/**
 * @brief 使用SM2和SM4实现混合解密
 * @param in 加密数据
 * @param in_len 加密数据长度
 * @param privkey_hex 接收方私钥的十六进制字符串
 * @param out 输出缓冲区，需要预先分配足够空间
 * @param out_len 输出参数，解密后的数据长度
 * @return 成功返回0，失败返回-1
 */
int sm2_hybrid_decrypt(const uint8_t *in, size_t in_len, const char *privkey_hex, 
                        uint8_t *out, size_t *out_len);

/**
 * @brief 使用SM2实现密钥交换，生成共享密钥
 * @param self_privkey_hex 本方私钥
 * @param self_pubkey_hex 本方公钥
 * @param peer_pubkey_hex 对方公钥
 * @param shared_key 输出参数，共享密钥（用于后续通信的对称加密）
 * @param key_len 共享密钥长度（通常为16字节）
 * @return 成功返回0，失败返回-1
 */
int sm2_key_exchange(const char *self_privkey_hex, const char *self_pubkey_hex,
                      const char *peer_pubkey_hex, uint8_t *shared_key, size_t key_len);

#endif // SM2_WRAPPER_H 