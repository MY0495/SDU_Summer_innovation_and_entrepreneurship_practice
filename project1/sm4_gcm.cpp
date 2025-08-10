#include "sm4_gcm.h"
#include <cstring>
#include <iostream>

// SM4 S盒
constexpr uint8_t SM4_SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// SM4 系统参数FK
constexpr uint32_t SM4_FK[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };

// SM4 固定参数CK
constexpr uint32_t SM4_CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

// 非线性变换
uint32_t SM4::sbox(uint32_t x) const {
    uint8_t* bytes = reinterpret_cast<uint8_t*>(&x);
    for (int i = 0; i < 4; ++i) {
        bytes[i] = SM4_SBOX[bytes[i]];
    }
    return x;
}

// 线性变换L
uint32_t SM4::L(uint32_t x) const {
    return x ^ (x << 2) ^ (x << 10) ^ (x << 18) ^ (x << 24);
}

// 线性变换L'
uint32_t SM4::LPrime(uint32_t x) const {
    return x ^ (x << 13) ^ (x << 23);
}

// 密钥扩展
void SM4::keyExpansion(const uint8_t key[SM4_KEY_SIZE]) {
    // 将密钥转换为4个32位字
    uint32_t mk[4];
    memcpy(mk, key, SM4_KEY_SIZE);

    // 初始化轮密钥
    uint32_t k[SM4_ROUNDS + 4];
    for (int i = 0; i < 4; ++i) {
        k[i] = mk[i] ^ SM4_FK[i];
    }

    // 生成轮密钥
    for (int i = 0; i < SM4_ROUNDS; ++i) {
        uint32_t t = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i];
        t = sbox(t);
        t = LPrime(t);
        k[i + 4] = k[i] ^ t;
        rk_[i] = k[i + 4];
    }
}

// 设置密钥
void SM4::setKey(const uint8_t key[SM4_KEY_SIZE]) {
    keyExpansion(key);
}

// 加密单块
void SM4::encryptBlock(const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE]) const {
    uint32_t x[4];
    memcpy(x, input, SM4_BLOCK_SIZE);

    // 32轮迭代
    for (int i = 0; i < SM4_ROUNDS; ++i) {
        uint32_t t = x[1] ^ x[2] ^ x[3] ^ rk_[i];
        t = sbox(t);
        t = L(t);
        x[0] ^= t;

        // 轮换
        uint32_t temp = x[0];
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = temp;
    }

    // 反序
    uint32_t temp = x[0];
    x[0] = x[3];
    x[3] = temp;
    temp = x[1];
    x[1] = x[2];
    x[2] = temp;

    memcpy(output, x, SM4_BLOCK_SIZE);
}

// 解密单块
void SM4::decryptBlock(const uint8_t input[SM4_BLOCK_SIZE], uint8_t output[SM4_BLOCK_SIZE]) const {
    uint32_t x[4];
    memcpy(x, input, SM4_BLOCK_SIZE);

    // 32轮迭代（使用反向轮密钥）
    for (int i = 0; i < SM4_ROUNDS; ++i) {
        uint32_t t = x[1] ^ x[2] ^ x[3] ^ rk_[SM4_ROUNDS - 1 - i];
        t = sbox(t);
        t = L(t);
        x[0] ^= t;

        // 轮换
        uint32_t temp = x[0];
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = temp;
    }

    // 反序
    uint32_t temp = x[0];
    x[0] = x[3];
    x[3] = temp;
    temp = x[1];
    x[1] = x[2];
    x[2] = temp;

    memcpy(output, x, SM4_BLOCK_SIZE);
}

// 设置SM4密钥
void SM4_GCM::setKey(const uint8_t key[SM4_KEY_SIZE]) {
    sm4_.setKey(key);

    // 计算哈希子密钥H
    uint8_t zero_block[SM4_BLOCK_SIZE] = { 0 };
    sm4_.encryptBlock(zero_block, h_);
}

// 设置IV
void SM4_GCM::setIV(const uint8_t* iv, size_t ivLen) {
    iv_.assign(iv, iv + ivLen);

    // 生成初始计数器值J0
    if (ivLen == GCM_IV_SIZE) {
        // 当IV长度为12字节时，J0 = IV || 0x00000001
        memcpy(j0_, iv, ivLen);
        j0_[12] = 0x00;
        j0_[13] = 0x00;
        j0_[14] = 0x00;
        j0_[15] = 0x01;
    }
    else {
        // 当IV长度不是12字节时，J0 = GHASH(IV || 0x00000000 || len(IV))
        // 这里简化实现，仅支持12字节IV
        std::cerr << "错误: 仅支持12字节长度的IV" << std::endl;
        memset(j0_, 0, SM4_BLOCK_SIZE);
    }
}

// 伽罗瓦域乘法
void SM4_GCM::gcmMultiply(const uint8_t a[SM4_BLOCK_SIZE], const uint8_t b[SM4_BLOCK_SIZE], uint8_t result[SM4_BLOCK_SIZE]) {
    // 简化实现，实际应用中可使用更高效的方法
    uint64_t a_low = 0, a_high = 0;
    uint64_t b_low = 0, b_high = 0;

    // 将128位数分解为两个64位数
    memcpy(&a_low, a + 8, 8);
    memcpy(&a_high, a, 8);
    memcpy(&b_low, b + 8, 8);
    memcpy(&b_high, b, 8);


    uint64_t res_high = a_high * b_high;
    uint64_t res_low = a_low * b_low;

    memcpy(result, &res_high, 8);
    memcpy(result + 8, &res_low, 8);
}

// 计算GHASH
void SM4_GCM::ghash(const uint8_t* data, size_t len, uint8_t hash[SM4_BLOCK_SIZE]) {
    // 初始化哈希值为0
    uint8_t temp_hash[SM4_BLOCK_SIZE] = { 0 };

    // 处理完整的块
    size_t num_blocks = len / SM4_BLOCK_SIZE;
    for (size_t i = 0; i < num_blocks; ++i) {
        // 异或当前块
        for (int j = 0; j < SM4_BLOCK_SIZE; ++j) {
            temp_hash[j] ^= data[i * SM4_BLOCK_SIZE + j];
        }

        // 伽罗瓦域乘法
        uint8_t temp_result[SM4_BLOCK_SIZE];
        gcmMultiply(temp_hash, h_, temp_result);
        memcpy(temp_hash, temp_result, SM4_BLOCK_SIZE);
    }

    // 处理剩余数据
    size_t remaining = len % SM4_BLOCK_SIZE;
    if (remaining > 0) {
        uint8_t last_block[SM4_BLOCK_SIZE] = { 0 };
        memcpy(last_block, data + num_blocks * SM4_BLOCK_SIZE, remaining);

        // 异或最后一个块
        for (int j = 0; j < SM4_BLOCK_SIZE; ++j) {
            temp_hash[j] ^= last_block[j];
        }

        // 伽罗瓦域乘法
        uint8_t temp_result[SM4_BLOCK_SIZE];
        gcmMultiply(temp_hash, h_, temp_result);
        memcpy(temp_hash, temp_result, SM4_BLOCK_SIZE);
    }

    memcpy(hash, temp_hash, SM4_BLOCK_SIZE);
}

// 生成计数器块
void SM4_GCM::generateCounterBlock(uint64_t counter, uint8_t block[SM4_BLOCK_SIZE]) {
    // 复制IV的前12字节
    memcpy(block, iv_.data(), std::min(iv_.size(), (size_t)12));

    // 设置计数器值（大端序）
    block[12] = static_cast<uint8_t>((counter >> 24) & 0xFF);
    block[13] = static_cast<uint8_t>((counter >> 16) & 0xFF);
    block[14] = static_cast<uint8_t>((counter >> 8) & 0xFF);
    block[15] = static_cast<uint8_t>(counter & 0xFF);
}

// 加密并认证数据
bool SM4_GCM::encryptAndAuthenticate(
    const uint8_t* plaintext, size_t plaintextLen,
    const uint8_t* aad, size_t aadLen,
    uint8_t* ciphertext, uint8_t* tag, size_t tagLen) {

    if (tagLen > SM4_BLOCK_SIZE) {
        return false;
    }

    // 步骤1: 加密明文
    size_t num_blocks = plaintextLen / SM4_BLOCK_SIZE;
    size_t remaining = plaintextLen % SM4_BLOCK_SIZE;

    for (size_t i = 0; i < num_blocks; ++i) {
        // 生成计数器块
        uint8_t counter_block[SM4_BLOCK_SIZE];
        generateCounterBlock(i + 1, counter_block);

        // 加密计数器块
        uint8_t encrypted_counter[SM4_BLOCK_SIZE];
        sm4_.encryptBlock(counter_block, encrypted_counter);

        // 异或得到密文
        for (int j = 0; j < SM4_BLOCK_SIZE; ++j) {
            ciphertext[i * SM4_BLOCK_SIZE + j] = plaintext[i * SM4_BLOCK_SIZE + j] ^ encrypted_counter[j];
        }
    }

    // 处理剩余数据
    if (remaining > 0) {
        uint8_t counter_block[SM4_BLOCK_SIZE];
        generateCounterBlock(num_blocks + 1, counter_block);

        uint8_t encrypted_counter[SM4_BLOCK_SIZE];
        sm4_.encryptBlock(counter_block, encrypted_counter);

        for (int j = 0; j < remaining; ++j) {
            ciphertext[num_blocks * SM4_BLOCK_SIZE + j] = plaintext[num_blocks * SM4_BLOCK_SIZE + j] ^ encrypted_counter[j];
        }
    }

    // 步骤2: 计算认证标签
    // 2.1 计算GHASH(AAD || 密文 || len(AAD) || len(密文))
    uint8_t aad_len_bytes[8] = { 0 };
    uint8_t cipher_len_bytes[8] = { 0 };

    // 将长度转换为大端序8字节
    *reinterpret_cast<uint64_t*>(aad_len_bytes) = aadLen * 8;
    *reinterpret_cast<uint64_t*>(cipher_len_bytes) = plaintextLen * 8;

    // 拼接AAD、密文和长度信息
    std::vector<uint8_t> ghash_input;
    ghash_input.insert(ghash_input.end(), aad, aad + aadLen);
    ghash_input.insert(ghash_input.end(), ciphertext, ciphertext + plaintextLen);
    ghash_input.insert(ghash_input.end(), aad_len_bytes, aad_len_bytes + 8);
    ghash_input.insert(ghash_input.end(), cipher_len_bytes, cipher_len_bytes + 8);

    // 计算GHASH
    uint8_t ghash_result[SM4_BLOCK_SIZE];
    ghash(ghash_input.data(), ghash_input.size(), ghash_result);

    // 2.2 加密初始计数器值J0
    uint8_t encrypted_j0[SM4_BLOCK_SIZE];
    sm4_.encryptBlock(j0_, encrypted_j0);

    // 2.3 异或得到标签
    for (int j = 0; j < SM4_BLOCK_SIZE; ++j) {
        tag[j] = encrypted_j0[j] ^ ghash_result[j];
    }

    return true;
}

// 解密并验证数据
bool SM4_GCM::decryptAndVerify(
    const uint8_t* ciphertext, size_t ciphertextLen,
    const uint8_t* aad, size_t aadLen,
    const uint8_t* tag, size_t tagLen,
    uint8_t* plaintext) {

    if (tagLen > SM4_BLOCK_SIZE) {
        return false;
    }

    // 步骤1: 解密密文
    size_t num_blocks = ciphertextLen / SM4_BLOCK_SIZE;
    size_t remaining = ciphertextLen % SM4_BLOCK_SIZE;

    for (size_t i = 0; i < num_blocks; ++i) {
        // 生成计数器块
        uint8_t counter_block[SM4_BLOCK_SIZE];
        generateCounterBlock(i + 1, counter_block);

        // 加密计数器块
        uint8_t encrypted_counter[SM4_BLOCK_SIZE];
        sm4_.encryptBlock(counter_block, encrypted_counter);

        // 异或得到明文
        for (int j = 0; j < SM4_BLOCK_SIZE; ++j) {
            plaintext[i * SM4_BLOCK_SIZE + j] = ciphertext[i * SM4_BLOCK_SIZE + j] ^ encrypted_counter[j];
        }
    }

    // 处理剩余数据
    if (remaining > 0) {
        uint8_t counter_block[SM4_BLOCK_SIZE];
        generateCounterBlock(num_blocks + 1, counter_block);

        uint8_t encrypted_counter[SM4_BLOCK_SIZE];
        sm4_.encryptBlock(counter_block, encrypted_counter);

        for (int j = 0; j < remaining; ++j) {
            plaintext[num_blocks * SM4_BLOCK_SIZE + j] = ciphertext[num_blocks * SM4_BLOCK_SIZE + j] ^ encrypted_counter[j];
        }
    }

    // 步骤2: 验证标签
    // 2.1 计算GHASH(AAD || 密文 || len(AAD) || len(密文))
    uint8_t aad_len_bytes[8] = { 0 };
    uint8_t cipher_len_bytes[8] = { 0 };

    // 将长度转换为大端序8字节
    *reinterpret_cast<uint64_t*>(aad_len_bytes) = aadLen * 8;
    *reinterpret_cast<uint64_t*>(cipher_len_bytes) = ciphertextLen * 8;

    // 拼接AAD、密文和长度信息
    std::vector<uint8_t> ghash_input;
    ghash_input.insert(ghash_input.end(), aad, aad + aadLen);
    ghash_input.insert(ghash_input.end(), ciphertext, ciphertext + ciphertextLen);
    ghash_input.insert(ghash_input.end(), aad_len_bytes, aad_len_bytes + 8);
    ghash_input.insert(ghash_input.end(), cipher_len_bytes, cipher_len_bytes + 8);

    // 计算GHASH
    uint8_t ghash_result[SM4_BLOCK_SIZE];
    ghash(ghash_input.data(), ghash_input.size(), ghash_result);

    // 2.2 加密初始计数器值J0
    uint8_t encrypted_j0[SM4_BLOCK_SIZE];
    sm4_.encryptBlock(j0_, encrypted_j0);

    // 2.3 异或得到预期标签
    uint8_t expected_tag[SM4_BLOCK_SIZE];
    for (int j = 0; j < SM4_BLOCK_SIZE; ++j) {
        expected_tag[j] = encrypted_j0[j] ^ ghash_result[j];
    }

    // 2.4 比较标签
    return memcmp(tag, expected_tag, tagLen) == 0;
}

int main() {
    // 密钥和IV
    uint8_t key[SM4_KEY_SIZE] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
    uint8_t iv[GCM_IV_SIZE] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98 };

    // 明文和附加认证数据
    std::string plaintext = "WZJ";
    std::string aad = "20040402";

    // 创建SM4-GCM对象
    SM4_GCM sm4_gcm;
    sm4_gcm.setKey(key);
    sm4_gcm.setIV(iv, GCM_IV_SIZE);

    // 加密并认证
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> tag(GCM_TAG_SIZE);
    bool encrypt_success = sm4_gcm.encryptAndAuthenticate(
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
        reinterpret_cast<const uint8_t*>(aad.data()), aad.size(),
        ciphertext.data(), tag.data(), GCM_TAG_SIZE);

    if (encrypt_success) {
        std::cout << "加密成功" << std::endl;

        // 解密并验证
        std::vector<uint8_t> decrypted(plaintext.size());
        bool decrypt_success = sm4_gcm.decryptAndVerify(
            ciphertext.data(), ciphertext.size(),
            reinterpret_cast<const uint8_t*>(aad.data()), aad.size(),
            tag.data(), GCM_TAG_SIZE,
            decrypted.data());

        if (decrypt_success) {
            std::cout << "解密成功，验证通过" << std::endl;
            std::string decrypted_str(decrypted.begin(), decrypted.end());
            std::cout << "解密后消息: " << decrypted_str << std::endl;
        }
        else {
            std::cout << "解密失败，验证不通过" << std::endl;
        }
    }
    else {
        std::cout << "加密失败" << std::endl;
    }

    return 0;
}