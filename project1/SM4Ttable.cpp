#include <cstdint>
#include <array>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <chrono>

using std::array;
using std::uint32_t;

// SM4算法S盒：8位非线性替换表，用于增强混淆特性
static const uint8_t SM4_SBOX[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

// 轮常量：32个32位值，用于轮密钥生成，增强密钥扩散
static const uint32_t SM4_CK[32] = {
    0x00070E15,0x1C232A31,0x383F464D,0x545B6269,
    0x70777E85,0x8C939AA1,0xA8AFB6BD,0xC4CBD2D9,
    0xE0E7EEF5,0xFC030A11,0x181F262D,0x343B4249,
    0x50575E65,0x6C737A81,0x888F969D,0xA4ABB2B9,
    0xC0C7CED5,0xDCE3EAF1,0xF8FF060D,0x141B2229,
    0x30373E45,0x4C535A61,0x686F767D,0x848B9299,
    0xA0A7AEB5,0xBCC3CAD1,0xD8DFE6ED,0xF4FB0209,
    0x10171E25,0x2C333A41,0x484F565D,0x646B7279
};

// 固定密钥：4个32位初始密钥，用于密钥扩展初始化
static const uint32_t SM4_FK[4] = {
    0xA3B1BAC6,0x56AA3350,0x677D9197,0xB27022DC
};

/**
 * 32位整数循环左移
 * @param value 输入的32位整数
 * @param shift 左移位数（0-31）
 * @return 左移后的结果
 */
inline uint32_t rotate_left(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

/**
 * 字节替换：基于S盒的非线性变换
 * @param input 32位输入（4个字节）
 * @return 替换后的32位结果
 */
inline uint32_t substitute_bytes(uint32_t input) {
    return (static_cast<uint32_t>(SM4_SBOX[(input >> 24) & 0xFF]) << 24) |
        (static_cast<uint32_t>(SM4_SBOX[(input >> 16) & 0xFF]) << 16) |
        (static_cast<uint32_t>(SM4_SBOX[(input >> 8) & 0xFF]) << 8) |
        static_cast<uint32_t>(SM4_SBOX[input & 0xFF]);
}

/**
 * 线性变换：通过多轮移位异或增强扩散
 * @param input 32位输入
 * @return 变换后的32位结果
 */
inline uint32_t linear_transform(uint32_t input) {
    return input ^ rotate_left(input, 2) ^ rotate_left(input, 10) ^ rotate_left(input, 18) ^ rotate_left(input, 24);
}

/**
 * 非线性变换：S盒替换+线性变换的组合（轮函数核心）
 * @param input 32位输入
 * @return 变换后的32位结果
 */
inline uint32_t nonlinear_transform(uint32_t input) {
    return linear_transform(substitute_bytes(input));
}

/**
 * 生成32个轮密钥
 * @param main_key 16字节主密钥
 * @return 32个32位轮密钥的数组
 */
std::array<uint32_t, 32> generate_round_keys(const uint8_t main_key[16]) {
    array<uint32_t, 32> round_keys;  // 存储32轮加密所需的子密钥
    uint32_t key_reg[36];            // 密钥扩展寄存器（中间变量）

    // 初始化密钥寄存器：主密钥转换为32位字并与固定密钥异或
    for (int idx = 0; idx < 4; ++idx) {
        key_reg[idx] = (main_key[4 * idx] << 24) | (main_key[4 * idx + 1] << 16) |
            (main_key[4 * idx + 2] << 8) | main_key[4 * idx + 3];
        key_reg[idx] ^= SM4_FK[idx];  // 与固定密钥异或，增强初始扩散
    }

    // 迭代生成32个轮密钥
    for (int idx = 0; idx < 32; ++idx) {
        // 结合前3个寄存器和轮常量，计算中间值
        uint32_t temp = key_reg[idx + 1] ^ key_reg[idx + 2] ^ key_reg[idx + 3] ^ SM4_CK[idx];
        // 应用S盒替换和L'变换（13位和23位左移异或）
        temp = substitute_bytes(temp);
        temp ^= rotate_left(temp, 13) ^ rotate_left(temp, 23);
        // 更新寄存器并保存轮密钥
        key_reg[idx + 4] = key_reg[idx] ^ temp;
        round_keys[idx] = key_reg[idx + 4];
    }

    return round_keys;
}

/**
 * 单块SM4加密（16字节）
 * @param in 16字节明文输入
 * @param out 16字节密文输出
 * @param round_keys 32个轮密钥
 */
void sm4_block_encrypt(const uint8_t in[16], uint8_t out[16], const std::array<uint32_t, 32>& round_keys) {
    uint32_t state[36];  // 状态寄存器，存储加密过程中的中间状态

    // 初始化状态寄存器：明文转换为32位字
    for (int idx = 0; idx < 4; ++idx) {
        state[idx] = (in[4 * idx] << 24) | (in[4 * idx + 1] << 16) |
            (in[4 * idx + 2] << 8) | in[4 * idx + 3];
    }

    // 32轮加密运算：每轮更新状态寄存器
    for (int idx = 0; idx < 32; ++idx) {
        // 轮函数输入 = 前3个状态 ^ 轮密钥
        uint32_t temp = state[idx + 1] ^ state[idx + 2] ^ state[idx + 3] ^ round_keys[idx];
        // 状态更新：当前状态 ^ 非线性变换结果
        state[idx + 4] = state[idx] ^ nonlinear_transform(temp);
    }

    // 反序输出最后4个状态，得到密文
    for (int idx = 0; idx < 4; ++idx) {
        uint32_t cipher_word = state[35 - idx];  // 反序取状态
        out[4 * idx] = static_cast<uint8_t>(cipher_word >> 24);
        out[4 * idx + 1] = static_cast<uint8_t>(cipher_word >> 16);
        out[4 * idx + 2] = static_cast<uint8_t>(cipher_word >> 8);
        out[4 * idx + 3] = static_cast<uint8_t>(cipher_word);
    }
}

/**
 * 单块SM4解密（16字节）
 * @param in 16字节密文输入
 * @param out 16字节明文输出
 * @param round_keys 32个轮密钥（加密时生成）
 */
void sm4_block_decrypt(const uint8_t in[16], uint8_t out[16], const std::array<uint32_t, 32>& round_keys) {
    std::array<uint32_t, 32> reversed_round_keys;  // 解密用轮密钥（逆序）
    for (int idx = 0; idx < 32; ++idx) {
        reversed_round_keys[idx] = round_keys[31 - idx];  // 轮密钥逆序
    }
    // 复用加密函数，使用反向轮密钥
    sm4_block_encrypt(in, out, reversed_round_keys);
}


int main() {
    // 16字节示例密钥（对应字符串"0123456789abcdef"）
    uint8_t secret_key[16] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66
    };
    // 16字节示例明文（对应字符串"hello, sm4 demo!"）
    const char plaintext_init[16] = { 'h','e','l','l','o',',',' ','s','m','4',' ','d','e','m','o','!' };

    uint8_t plaintext[16], ciphertext[16], decrypted[16];
    memcpy(plaintext, plaintext_init, 16);  // 复制明文到缓冲区

    // 生成轮密钥
    auto round_keys = generate_round_keys(secret_key);

    // 执行加密和解密
    sm4_block_encrypt(plaintext, ciphertext, round_keys);
    sm4_block_decrypt(ciphertext, decrypted, round_keys);

    // 输出结果（十六进制格式）
    std::cout << "明文数据: ";
    for (uint8_t byte : plaintext) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << ' ';
    }
    std::cout << "\n密文数据: ";
    for (uint8_t byte : ciphertext) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << ' ';
    }
    std::cout << "\n解密结果: ";
    for (uint8_t byte : decrypted) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << ' ';
    }
    std::cout << '\n';

    // 加密性能测试（重复10000次计算平均耗时）
    constexpr int TEST_COUNT = 10000;
    auto encrypt_start = std::chrono::high_resolution_clock::now();
    for (int idx = 0; idx < TEST_COUNT; ++idx) {
        sm4_block_encrypt(plaintext, ciphertext, round_keys);
    }
    auto encrypt_end = std::chrono::high_resolution_clock::now();
    double encrypt_avg_ms = std::chrono::duration<double, std::milli>(encrypt_end - encrypt_start).count() / TEST_COUNT;
    std::cout << "加密平均耗时: " << encrypt_avg_ms << " 毫秒/块\n";

    // 解密性能测试（重复10000次计算平均耗时）
    auto decrypt_start = std::chrono::high_resolution_clock::now();
    for (int idx = 0; idx < TEST_COUNT; ++idx) {
        sm4_block_decrypt(ciphertext, plaintext, round_keys);
    }
    auto decrypt_end = std::chrono::high_resolution_clock::now();
    double decrypt_avg_ms = std::chrono::duration<double, std::milli>(decrypt_end - decrypt_start).count() / TEST_COUNT;
    std::cout << "解密平均耗时: " << decrypt_avg_ms << " 毫秒/块\n";

    return 0;
}