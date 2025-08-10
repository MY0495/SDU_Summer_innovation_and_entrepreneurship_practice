#ifndef SM4_GCM_H
#define SM4_GCM_H

#include <cstdint>
#include <vector>
#include <string>
#include <array>

// SM4算法参数
constexpr int SM4_BLOCK_SIZE = 16;  // 128位
constexpr int SM4_KEY_SIZE = 16;    // 128位
constexpr int SM4_ROUNDS = 32;      // 32轮迭代

// GCM参数
constexpr int GCM_IV_SIZE = 12;     // 推荐IV长度
constexpr int GCM_TAG_SIZE = 16;    // 推荐标签长度

/**
 * SM4算法实现类
 */
class SM4 {
public:
    SM4() = default;
    ~SM4() = default;

    /**
     * 初始化SM4密钥
     * @param key 128位密钥
     */
    void setKey(const uint8_t key[SM4_KEY_SIZE]);

    /**
     * SM4单块加密
     * @param input 128位输入块
     * @param output 128位输出块
     */
    void encryptBlock(const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE]) const;

    /**
     * SM4单块解密
     * @param input 128位输入块
     * @param output 128位输出块
     */
    void decryptBlock(const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE]) const;

private:
    // 轮密钥
    std::array<uint32_t, SM4_ROUNDS> rk_;

    // 非线性变换
    uint32_t sbox(uint32_t x) const;

    // 线性变换L
    uint32_t L(uint32_t x) const;

    // 线性变换L'
    uint32_t LPrime(uint32_t x) const;

    // 密钥扩展
    void keyExpansion(const uint8_t key[SM4_KEY_SIZE]);
};

/**
 * SM4-GCM模式实现类
 */
class SM4_GCM {
public:
    SM4_GCM() = default;
    ~SM4_GCM() = default;

    /**
     * 初始化SM4密钥
     * @param key 128位密钥
     */
    void setKey(const uint8_t key[SM4_KEY_SIZE]);

    /**
     * 设置IV
     * @param iv 初始化向量
     * @param ivLen IV长度
     */
    void setIV(const uint8_t* iv, size_t ivLen);

    /**
     * 加密并认证数据
     * @param plaintext 明文数据
     * @param plaintextLen 明文长度
     * @param aad 附加认证数据
     * @param aadLen 附加认证数据长度
     * @param ciphertext 密文输出
     * @param tag 认证标签输出
     * @param tagLen 认证标签长度
     * @return 成功返回true，失败返回false
     */
    bool encryptAndAuthenticate(
        const uint8_t* plaintext, size_t plaintextLen,
        const uint8_t* aad, size_t aadLen,
        uint8_t* ciphertext, uint8_t* tag, size_t tagLen);

    /**
     * 解密并验证数据
     * @param ciphertext 密文数据
     * @param ciphertextLen 密文长度
     * @param aad 附加认证数据
     * @param aadLen 附加认证数据长度
     * @param tag 认证标签
     * @param tagLen 认证标签长度
     * @param plaintext 明文输出
     * @return 成功返回true，失败返回false
     */
    bool decryptAndVerify(
        const uint8_t* ciphertext, size_t ciphertextLen,
        const uint8_t* aad, size_t aadLen,
        const uint8_t* tag, size_t tagLen,
        uint8_t* plaintext);

private:
    SM4 sm4_;
    std::vector<uint8_t> iv_;
    uint8_t h_[SM4_BLOCK_SIZE] = { 0 };  // 哈希子密钥
    uint8_t j0_[SM4_BLOCK_SIZE] = { 0 }; // 初始计数器值

    // 伽罗瓦域乘法
    void gcmMultiply(const uint8_t a[SM4_BLOCK_SIZE], const uint8_t b[SM4_BLOCK_SIZE], uint8_t result[SM4_BLOCK_SIZE]);

    // 计算GHASH
    void ghash(const uint8_t* data, size_t len, uint8_t hash[SM4_BLOCK_SIZE]);

    // 生成计数器块
    void generateCounterBlock(uint64_t counter, uint8_t block[SM4_BLOCK_SIZE]);
};

#endif // SM4_GCM_H