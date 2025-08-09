#include <iostream>
#include <cstring>
#include <iomanip>
#include <windows.h>
#include <cinttypes>

// 算法常量定义（符合GM/T 0004-2012标准）
namespace SM3_CONST {
    constexpr uint32_t IV[8] = {  // 初始向量（Initialization Vector）
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };
    constexpr uint32_t T1 = 0x79CC4519;   // 0-15轮常量（增强前16轮扩散性）
    constexpr uint32_t T2 = 0x7A879D8A;   // 16-63轮常量（提高后48轮非线性）
    constexpr size_t BLOCK_SIZE = 64;     // 消息分组大小（字节）
    constexpr size_t HASH_SIZE = 32;       // 输出哈希长度（字节）
}

// 32位循环左移（避免未定义行为）
inline uint32_t ROTL(uint32_t x, uint8_t n) noexcept {
    return (x << n) | (x >> (32 - n));
}

/**
 * @brief SM3单块压缩函数
 * @param data 512位输入消息块
 * @param h 8个32位状态寄存器（输入/输出）
 * @note 遵循GM/T 0004-2012第6.2节标准[1,3](@ref)
 */
void sm3_compress(const uint8_t* data, uint32_t h[8]) {
    uint32_t W[68] = { 0 };   // 扩展消息字（W0-W67）
    uint32_t W1[64] = { 0 };  // 压缩用消息字（W0'-W63'）

    // === 消息扩展阶段 ===
    // 步骤1：加载初始16个字（大端序转换）
    for (size_t i = 0; i < 16; ++i) {
        W[i] = static_cast<uint32_t>(data[i * 4]) << 24 |
            static_cast<uint32_t>(data[i * 4 + 1]) << 16 |
            static_cast<uint32_t>(data[i * 4 + 2]) << 8 |
            data[i * 4 + 3];
    }
    // 步骤2：生成W16-W67（P1置换增强非线性）
    for (size_t i = 16; i < 68; ++i) {
        uint32_t tmp = W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15);
        W[i] = tmp ^ ROTL(tmp, 15) ^ ROTL(tmp, 23) ^
            ROTL(W[i - 13], 7) ^ W[i - 6];
    }
    // 步骤3：生成W'（压缩优化字）
    for (size_t i = 0; i < 64; ++i) {
        W1[i] = W[i] ^ W[i + 4];
    }

    // === 压缩函数迭代 ===
    uint32_t A = h[0], B = h[1], C = h[2], D = h[3];
    uint32_t E = h[4], F = h[5], G = h[6], H = h[7];

    for (size_t j = 0; j < 64; ++j) {
        // 轮常量选择（前16轮用T1，后48轮用T2）
        const uint32_t Tj = (j < 16) ? SM3_CONST::T1 : SM3_CONST::T2;

        // 中间变量计算（SS/TT为SM3核心混淆结构）
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(Tj, j)), 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = (j < 16 ? (A ^ B ^ C) : ((A & B) | (A & C) | (B & C)))
            + D + SS2 + W1[j];
        uint32_t TT2 = (j < 16 ? (E ^ F ^ G) : ((E & F) | ((~E) & G)))
            + H + SS1 + W[j];

        // 寄存器移位更新（Feistel结构）
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = TT2 ^ ROTL(TT2, 9) ^ ROTL(TT2, 17);  // P0置换增强扩散
    }

    // 更新中间哈希值（Davies-Meyer结构）
    h[0] ^= A; h[1] ^= B; h[2] ^= C; h[3] ^= D;
    h[4] ^= E; h[5] ^= F; h[6] ^= G; h[7] ^= H;
}

/**
 * @brief SM3哈希主函数
 * @param data 输入数据指针
 * @param len 输入数据长度（字节）
 * @param hash 输出缓冲区（至少32字节）
 * @note 实现Merkle-Damgård迭代结构[1,6](@ref)
 */
void sm3(const void* data, size_t len, uint8_t hash[SM3_CONST::HASH_SIZE]) {
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    uint32_t h[8];
    memcpy(h, SM3_CONST::IV, sizeof(h));  // 初始化状态寄存器

    // 处理完整消息块
    size_t blocks = len / SM3_CONST::BLOCK_SIZE;
    for (size_t i = 0; i < blocks; ++i) {
        sm3_compress(ptr + i * SM3_CONST::BLOCK_SIZE, h);
    }

    // 消息填充（PKCS#7变体）
    uint8_t last_block[SM3_CONST::BLOCK_SIZE] = { 0 };
    size_t remaining = len % SM3_CONST::BLOCK_SIZE;
    memcpy(last_block, ptr + blocks * SM3_CONST::BLOCK_SIZE, remaining);
    last_block[remaining] = 0x80;  // 比特填充起始标志

    // 长度域处理（64位大端序）
    const uint64_t bit_len = static_cast<uint64_t>(len) * 8;
    if (remaining < SM3_CONST::BLOCK_SIZE - 8) {
        // 尾部空间足够写入长度
        for (int i = 0; i < 8; ++i) {
            last_block[SM3_CONST::BLOCK_SIZE - 8 + i] =
                static_cast<uint8_t>(bit_len >> (56 - i * 8));
        }
        sm3_compress(last_block, h);
    }
    else {
        // 需额外填充块
        sm3_compress(last_block, h);
        memset(last_block, 0, SM3_CONST::BLOCK_SIZE);
        for (int i = 0; i < 8; ++i) {
            last_block[SM3_CONST::BLOCK_SIZE - 8 + i] =
                static_cast<uint8_t>(bit_len >> (56 - i * 8));
        }
        sm3_compress(last_block, h);
    }

    // 输出大端序哈希值
    for (int i = 0; i < 8; ++i) {
        hash[i * 4] = static_cast<uint8_t>(h[i] >> 24);
        hash[i * 4 + 1] = static_cast<uint8_t>(h[i] >> 16);
        hash[i * 4 + 2] = static_cast<uint8_t>(h[i] >> 8);
        hash[i * 4 + 3] = static_cast<uint8_t>(h[i]);
    }
}

int main() {
    uint8_t result[SM3_CONST::HASH_SIZE];
    const std::string message = "WZJ20040402'';

    // 高精度计时（Windows API）
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    sm3(message.data(), message.size(), result);

    QueryPerformanceCounter(&end);
    double time_ms = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;

    // 输出结果
    std::cout << "SM3(\"" << message << "\") = ";
    for (uint8_t byte : result) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(byte);
    }
    std::cout << "\n执行时间: " << std::fixed << time_ms << " ms\n";
    return 0;
}