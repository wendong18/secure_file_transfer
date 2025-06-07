#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/hex.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>
#include "../../include/sm2.h"
#include "../../include/sm4.h"

// SM2密钥生成
int sm2_generate_keypair(char *privkey_hex, char *pubkey_hex) {
    if (!privkey_hex || !pubkey_hex) {
        fprintf(stderr, "SM2: Invalid output buffers\n");
        return -1;
    }

    SM2_KEY key;
    sm2_z256_t privkey; // 使用正确的类型
    
    // 生成随机密钥对
    if (sm2_key_generate(&key) != 1) {
        fprintf(stderr, "SM2: Failed to generate key pair\n");
        return -1;
    }
    
    // 提取私钥和公钥
    memcpy(privkey, key.private_key, sizeof(sm2_z256_t));
    
    // 转换私钥为十六进制字符串
    uint8_t privkey_bin[32];
    uint8_t pubkey_bin[65];
    
    sm2_z256_to_bytes(privkey, privkey_bin);
    sm2_z256_point_to_bytes(&key.public_key, pubkey_bin);
    
    // 转换为十六进制字符串
    for (int i = 0; i < 32; i++) {
        sprintf(privkey_hex + i*2, "%02x", privkey_bin[i]);
    }
    privkey_hex[64] = '\0';
    
    for (int i = 0; i < 65; i++) {
        sprintf(pubkey_hex + i*2, "%02x", pubkey_bin[i]);
    }
    pubkey_hex[130] = '\0';
    
    return 0;
}

// 从十六进制字符串加载SM2私钥
static int sm2_load_private_key(SM2_KEY *key, const char *privkey_hex) {
    uint8_t privkey_bin[32];
    size_t outlen = 32;
    
    // 十六进制字符串转二进制
    if (hex_to_bytes(privkey_hex, strlen(privkey_hex), privkey_bin, &outlen) < 0 || outlen != 32) {
        fprintf(stderr, "SM2: Invalid private key hex format\n");
        return -1;
    }
    
    // 加载私钥
    sm2_z256_t z256;
    sm2_z256_from_bytes(z256, privkey_bin);
    
    if (sm2_key_set_private_key(key, z256) != 1) {
        fprintf(stderr, "SM2: Failed to set private key\n");
        return -1;
    }
    
    return 0;
}

// 从十六进制字符串加载SM2公钥
static int sm2_load_public_key(SM2_KEY *key, const char *pubkey_hex) {
    uint8_t pubkey_bin[65];
    size_t outlen = 65;
    
    // 十六进制字符串转二进制
    if (hex_to_bytes(pubkey_hex, strlen(pubkey_hex), pubkey_bin, &outlen) < 0 || outlen != 65) {
        fprintf(stderr, "SM2: Invalid public key hex format\n");
        return -1;
    }
    
    // 加载公钥
    SM2_Z256_POINT point;
    if (sm2_z256_point_from_bytes(&point, pubkey_bin) != 1) {
        fprintf(stderr, "SM2: Failed to convert public key bytes to point\n");
        return -1;
    }
    
    if (sm2_key_set_public_key(key, &point) != 1) {
        fprintf(stderr, "SM2: Failed to set public key\n");
        return -1;
    }
    
    return 0;
}

// SM2数字签名
int sm2_sign_data(const uint8_t *data, size_t data_len, const char *privkey_hex, char *sig_hex) {
    if (!data || !data_len || !privkey_hex || !sig_hex) {
        fprintf(stderr, "SM2: Invalid sign parameters\n");
        return -1;
    }
    
    SM2_KEY key;
    uint8_t dgst[32];
    
    // 加载私钥
    if (sm2_load_private_key(&key, privkey_hex) != 0) {
        return -1;
    }
    
    // 计算数据的SM3哈希值
    SM3_CTX sm3_ctx;
    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, data, data_len);
    sm3_finish(&sm3_ctx, dgst);
    
    // 使用SM2签名
    uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
    size_t sig_len;
    
    if (sm2_sign(&key, dgst, sig, &sig_len) != 1) {
        fprintf(stderr, "SM2: Signature generation failed\n");
        return -1;
    }
    
    // 将签名转换为十六进制字符串
    for (size_t i = 0; i < sig_len; i++) {
        sprintf(sig_hex + i*2, "%02x", sig[i]);
    }
    sig_hex[sig_len * 2] = '\0';
    
    return 0;
}

// SM2签名验证
int sm2_verify_signature(const uint8_t *data, size_t data_len, const char *pubkey_hex, const char *sig_hex) {
    if (!data || !data_len || !pubkey_hex || !sig_hex) {
        fprintf(stderr, "SM2: Invalid verify parameters\n");
        return -1;
    }
    
    SM2_KEY key;
    uint8_t dgst[32];
    
    // 加载公钥
    if (sm2_load_public_key(&key, pubkey_hex) != 0) {
        return -1;
    }
    
    // 将签名从十六进制字符串转换为二进制
    size_t sig_hex_len = strlen(sig_hex);
    size_t sig_len = sig_hex_len / 2;
    uint8_t *sig = (uint8_t *)malloc(sig_len);
    if (!sig) {
        fprintf(stderr, "SM2: Memory allocation failed\n");
        return -1;
    }
    
    size_t actual_sig_len = sig_len;
    if (hex_to_bytes(sig_hex, sig_hex_len, sig, &actual_sig_len) < 0) {
        fprintf(stderr, "SM2: Invalid signature hex format\n");
        free(sig);
        return -1;
    }
    
    // 计算数据的SM3哈希值
    SM3_CTX sm3_ctx;
    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, data, data_len);
    sm3_finish(&sm3_ctx, dgst);
    
    // 验证签名
    int result = sm2_verify(&key, dgst, sig, actual_sig_len);
    free(sig);
    
    if (result == 1) {
        return 1; // 验证成功
    } else {
        return 0; // 验证失败
    }
}

// 混合加密 - 使用SM2加密SM4密钥，然后使用SM4加密数据
int sm2_hybrid_encrypt(const uint8_t *data, size_t data_len, const char *pubkey_hex, 
                       uint8_t *out, size_t *out_len) {
    if (!data || !data_len || !pubkey_hex || !out || !out_len) {
        fprintf(stderr, "SM2: Invalid hybrid encrypt parameters\n");
        return -1;
    }
    
    SM2_KEY key;
    
    // 加载公钥
    if (sm2_load_public_key(&key, pubkey_hex) != 0) {
        return -1;
    }
    
    // 生成随机SM4密钥和IV
    uint8_t sm4_key[16];
    uint8_t sm4_iv[16];
    if (rand_bytes(sm4_key, 16) != 1 || rand_bytes(sm4_iv, 16) != 1) {
        fprintf(stderr, "SM2: Random generation failed\n");
        return -1;
    }
    
    // 使用SM2加密SM4密钥和IV
    uint8_t key_iv[32]; // 将密钥和IV合并
    memcpy(key_iv, sm4_key, 16);
    memcpy(key_iv + 16, sm4_iv, 16);
    
    uint8_t encrypted_key_iv[SM2_MAX_CIPHERTEXT_SIZE];
    size_t encrypted_key_iv_len;
    
    if (sm2_encrypt(&key, key_iv, 32, encrypted_key_iv, &encrypted_key_iv_len) != 1) {
        fprintf(stderr, "SM2: Key encryption failed\n");
        return -1;
    }
    
    // 使用SM4加密数据
    // 计算需要的填充
    size_t padded_len = ((data_len + 15) / 16) * 16; // 向上取16的倍数
    uint8_t *padded_data = (uint8_t *)malloc(padded_len);
    if (!padded_data) {
        fprintf(stderr, "SM2: Memory allocation failed\n");
        return -1;
    }
    
    // 拷贝数据并进行PKCS#7填充
    memcpy(padded_data, data, data_len);
    uint8_t padding = padded_len - data_len;
    if (padding == 0) padding = 16;
    memset(padded_data + data_len, padding, padding);
    
    // 分配空间给加密后的数据
    uint8_t *encrypted_data = (uint8_t *)malloc(padded_len);
    if (!encrypted_data) {
        fprintf(stderr, "SM2: Memory allocation failed\n");
        free(padded_data);
        return -1;
    }
    
    // 使用SM4-CBC加密
    sm4_cbc_encrypt_wrapper(sm4_key, sm4_iv, padded_data, encrypted_data, padded_len);
    
    // 组合最终输出：[SM2加密的密钥和IV][SM4加密的数据]
    if (*out_len < encrypted_key_iv_len + padded_len) {
        fprintf(stderr, "SM2: Output buffer too small\n");
        free(padded_data);
        free(encrypted_data);
        return -1;
    }
    
    memcpy(out, encrypted_key_iv, encrypted_key_iv_len);
    memcpy(out + encrypted_key_iv_len, encrypted_data, padded_len);
    *out_len = encrypted_key_iv_len + padded_len;
    
    free(padded_data);
    free(encrypted_data);
    return 0;
}

// 混合解密 - 使用SM2解密SM4密钥，然后使用SM4解密数据
int sm2_hybrid_decrypt(const uint8_t *in, size_t in_len, const char *privkey_hex, 
                       uint8_t *out, size_t *out_len) {
    if (!in || in_len < SM2_MIN_CIPHERTEXT_SIZE || !privkey_hex || !out || !out_len) {
        fprintf(stderr, "SM2: Invalid hybrid decrypt parameters\n");
        return -1;
    }
    
    SM2_KEY key;
    
    // 加载私钥
    if (sm2_load_private_key(&key, privkey_hex) != 0) {
        return -1;
    }
    
    // 分离SM2加密的密钥和SM4加密的数据
    size_t sm2_cipher_len;
    // 从加密数据中提取SM2密文长度
    // 注：实际项目中应该有更好的方式确定SM2密文的确切长度
    // 这里为简化实现，假设前136字节是SM2密文
    sm2_cipher_len = SM2_MAX_CIPHERTEXT_SIZE;
    if (in_len <= sm2_cipher_len) {
        fprintf(stderr, "SM2: Input data too short\n");
        return -1;
    }
    
    // 解密SM4密钥和IV
    uint8_t key_iv[32];
    size_t key_iv_len = 32;
    if (sm2_decrypt(&key, in, sm2_cipher_len, key_iv, &key_iv_len) != 1 || key_iv_len != 32) {
        fprintf(stderr, "SM2: Key decryption failed\n");
        return -1;
    }
    
    uint8_t sm4_key[16];
    uint8_t sm4_iv[16];
    memcpy(sm4_key, key_iv, 16);
    memcpy(sm4_iv, key_iv + 16, 16);
    
    // 解密SM4数据
    size_t sm4_cipher_len = in_len - sm2_cipher_len;
    if (sm4_cipher_len % 16 != 0) {
        fprintf(stderr, "SM2: Invalid SM4 ciphertext length\n");
        return -1;
    }
    
    uint8_t *decrypted_data = (uint8_t *)malloc(sm4_cipher_len);
    if (!decrypted_data) {
        fprintf(stderr, "SM2: Memory allocation failed\n");
        return -1;
    }
    
    // 使用SM4-CBC解密
    sm4_cbc_decrypt_wrapper(sm4_key, sm4_iv, in + sm2_cipher_len, decrypted_data, sm4_cipher_len);
    
    // 处理PKCS#7填充
    uint8_t padding = decrypted_data[sm4_cipher_len - 1];
    if (padding > 16 || padding == 0) {
        fprintf(stderr, "SM2: Invalid padding\n");
        free(decrypted_data);
        return -1;
    }
    
    // 验证填充
    for (size_t i = sm4_cipher_len - padding; i < sm4_cipher_len; i++) {
        if (decrypted_data[i] != padding) {
            fprintf(stderr, "SM2: Padding verification failed\n");
            free(decrypted_data);
            return -1;
        }
    }
    
    // 输出解密后的数据
    size_t data_len = sm4_cipher_len - padding;
    if (*out_len < data_len) {
        fprintf(stderr, "SM2: Output buffer too small\n");
        free(decrypted_data);
        return -1;
    }
    
    memcpy(out, decrypted_data, data_len);
    *out_len = data_len;
    
    free(decrypted_data);
    return 0;
}

// SM2密钥交换
int sm2_key_exchange(const char *self_privkey_hex, const char *self_pubkey_hex,
                    const char *peer_pubkey_hex, uint8_t *shared_key, size_t key_len) {
    if (!self_privkey_hex || !self_pubkey_hex || !peer_pubkey_hex || !shared_key || key_len == 0) {
        fprintf(stderr, "SM2: Invalid key exchange parameters\n");
        return -1;
    }
    
    SM2_KEY self_key, peer_key;
    
    // 加载本方私钥
    if (sm2_load_private_key(&self_key, self_privkey_hex) != 0) {
        return -1;
    }
    
    // 加载对方公钥
    if (sm2_load_public_key(&peer_key, peer_pubkey_hex) != 0) {
        return -1;
    }
    
    // 生成临时密钥对
    SM2_KEY tmp_key;
    if (sm2_key_generate(&tmp_key) != 1) {
        fprintf(stderr, "SM2: Failed to generate temporary key\n");
        return -1;
    }
    
    // 生成种子数据
    uint8_t seed[128];
    uint8_t self_bytes[65], peer_bytes[65];
    
    sm2_z256_point_to_bytes(&self_key.public_key, self_bytes);
    sm2_z256_point_to_bytes(&peer_key.public_key, peer_bytes);
    
    // 合并公钥作为种子数据
    memcpy(seed, self_bytes, 65);
    memcpy(seed + 65, peer_bytes, 63); // 只复制有效数据部分
    
    // 使用SM3作为KDF生成共享密钥
    SM3_CTX sm3_ctx;
    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, seed, 128);
    uint8_t hash[32];
    sm3_finish(&sm3_ctx, hash);
    
    // 截取需要的长度作为共享密钥
    size_t copy_len = key_len < 32 ? key_len : 32;
    memcpy(shared_key, hash, copy_len);
    
    return 0;
} 