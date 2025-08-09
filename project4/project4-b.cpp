#include <iostream>
#include <cstring>
#include <iomanip>
#include <vector>
#include <string>

// SM3 基础实现类
class SM3 {
public:
    // 常量定义
    static constexpr uint32_t IV[8] = {
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };
    static constexpr size_t BLOCK_SIZE = 64; // 512 bits
    static constexpr size_t DIGEST_SIZE = 32; // 256 bits

    // 循环左移
    static uint32_t RotL(uint32_t x, uint8_t n) {
        return (x << n) | (x >> (32 - n));
    }

    // 布尔函数 FF
    static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        if (j < 16) return x ^ y ^ z;
        return (x & y) | (x & z) | (y & z);
    }

    // 布尔函数 GG
    static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        if (j < 16) return x ^ y ^ z;
        return (x & y) | (~x & z);
    }

    // 置换函数 P0
    static uint32_t P0(uint32_t x) {
        return x ^ RotL(x, 9) ^ RotL(x, 17);
    }

    // 置换函数 P1
    static uint32_t P1(uint32_t x) {
        return x ^ RotL(x, 15) ^ RotL(x, 23);
    }

    // 消息填充
    static std::vector<uint8_t> PadMessage(const uint8_t* input, size_t len) {
        size_t bit_len = len * 8;
        size_t pad_len = (BLOCK_SIZE - (len % BLOCK_SIZE)) % BLOCK_SIZE;
        if (pad_len < 9) pad_len += BLOCK_SIZE; // 至少需要 9 字节空间

        std::vector<uint8_t> padded(len + pad_len);
        memcpy(padded.data(), input, len);
        padded[len] = 0x80; // 添加比特 "1"

        // 添加比特 "0"
        memset(padded.data() + len + 1, 0, pad_len - 9);

        // 添加长度（大端序）
        for (int i = 0; i < 8; ++i) {
            padded[len + pad_len - 1 - i] = (bit_len >> (i * 8)) & 0xFF;
        }
        return padded;
    }

    // 压缩函数
    static void Compress(const uint8_t block[BLOCK_SIZE], uint32_t state[8]) {
        uint32_t W[68] = { 0 };
        uint32_t W1[64] = { 0 };

        // 消息扩展
        for (int i = 0; i < 16; ++i) {
            W[i] = (block[i * 4] << 24) |
                (block[i * 4 + 1] << 16) |
                (block[i * 4 + 2] << 8) |
                block[i * 4 + 3];
        }

        for (int i = 16; i < 68; ++i) {
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ RotL(W[i - 3], 15)) ^
                RotL(W[i - 13], 7) ^ W[i - 6];
        }

        for (int i = 0; i < 64; ++i) {
            W1[i] = W[i] ^ W[i + 4];
        }

        // 寄存器初始化
        uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
        uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

        // 64 轮迭代
        for (int j = 0; j < 64; ++j) {
            uint32_t Tj = (j < 16) ? 0x79CC4519 : 0x7A879D8A;
            uint32_t SS1 = RotL(RotL(A, 12) + E + RotL(Tj, j), 7);
            uint32_t SS2 = SS1 ^ RotL(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C;
            C = RotL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = RotL(F, 19);
            F = E;
            E = P0(TT2);
        }

        // 更新状态
        state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
        state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
    }

    // 计算哈希
    static std::vector<uint8_t> Hash(const uint8_t* input, size_t len) {
        std::vector<uint8_t> padded = PadMessage(input, len);
        uint32_t state[8];
        memcpy(state, IV, sizeof(state));

        // 处理每个块
        for (size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
            Compress(&padded[i], state);
        }

        // 输出哈希值
        std::vector<uint8_t> digest(DIGEST_SIZE);
        for (int i = 0; i < 8; ++i) {
            digest[i * 4] = (state[i] >> 24) & 0xFF;
            digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
            digest[i * 4 + 2] = (state[i] >> 8) & 0xFF;
            digest[i * 4 + 3] = state[i] & 0xFF;
        }
        return digest;
    }
};

// 长度扩展攻击类
class SM3LengthExtensionAttack {
public:
    static std::vector<uint8_t> ForgeHash(
        const uint32_t original_state[8],     // 原始消息的哈希状态
        size_t original_len,                   // 原始消息长度（字节）
        const std::vector<uint8_t>& append_data // 要追加的数据
    ) {
        // 1. 计算原始消息的填充后长度（含填充块）
        const size_t padding_bytes = CalculatePaddingBytes(original_len);
        const size_t total_length_bytes = original_len + padding_bytes + append_data.size();
        const uint64_t total_length_bits = total_length_bytes * 8;

        // 2. 构造恶意消息：包括追加数据和新的填充
        std::vector<uint8_t> malicious_data = append_data;

        // 3. 添加追加消息的填充（使用总长度）
        malicious_data.push_back(0x80); // 填充起始标记

        // 计算需要填充的0的个数
        const size_t append_len = append_data.size();
        size_t zeros_needed = CalculateZerosNeeded(append_len + 1); // +1 for 0x80

        malicious_data.insert(malicious_data.end(), zeros_needed, 0);

        // 添加总长度（大端序）
        for (int i = 0; i < 8; i++) {
            malicious_data.push_back((total_length_bits >> (56 - i * 8)) & 0xFF);
        }

        // 4. 用原始哈希状态作为IV压缩恶意消息
        uint32_t forged_state[8];
        memcpy(forged_state, original_state, sizeof(forged_state));

        // 处理恶意消息块
        for (size_t i = 0; i < malicious_data.size(); i += SM3::BLOCK_SIZE) {
            SM3::Compress(&malicious_data[i], forged_state);
        }

        // 5. 生成最终哈希
        std::vector<uint8_t> digest(SM3::DIGEST_SIZE);
        for (int i = 0; i < 8; ++i) {
            digest[i * 4] = (forged_state[i] >> 24) & 0xFF;
            digest[i * 4 + 1] = (forged_state[i] >> 16) & 0xFF;
            digest[i * 4 + 2] = (forged_state[i] >> 8) & 0xFF;
            digest[i * 4 + 3] = forged_state[i] & 0xFF;
        }
        return digest;
    }

private:
    // 计算原始消息的填充字节数
    static size_t CalculatePaddingBytes(size_t len) {
        const size_t remainder = len % SM3::BLOCK_SIZE;
        // 如果剩余空间足够（至少9字节），则填充大小为1（0x80）+ zeros + 8
        if (remainder <= SM3::BLOCK_SIZE - 9) {
            return 1 + (SM3::BLOCK_SIZE - 9 - remainder) + 8;
        }
        // 否则需要额外的块
        return 1 + (SM3::BLOCK_SIZE * 2 - 9 - remainder) + 8;
    }

    // 计算追加数据需要填充的0的数量
    static size_t CalculateZerosNeeded(size_t append_len) {
        const size_t position = (append_len) % SM3::BLOCK_SIZE;
        // 确保填充后的总长度 % BLOCK_SIZE == 56（最后8字节用于长度）
        if (position <= 56) {
            return 56 - position;
        }
        return 56 + (SM3::BLOCK_SIZE - position);
    }
};

// 辅助函数：打印十六进制数据
void PrintHex(const std::vector<uint8_t>& data) {
    for (uint8_t b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    // ==================== 测试1：基础SM3功能验证 ====================
    std::string message = "WZJ20040402";
    auto hash = SM3::Hash(
        reinterpret_cast<const uint8_t*>(message.data()), message.size()
    );
    std::cout << "SM3(\"" << message << "\") = ";
    PrintHex(hash); 

    // ==================== 测试2：长度扩展攻击验证 ====================
    std::string secret = "secret_key";
    std::string original_msg = "original_data";
    std::string append_msg = "malicious";

    // 原始消息：secret + original_msg
    std::vector<uint8_t> full_msg(secret.begin(), secret.end());
    full_msg.insert(full_msg.end(), original_msg.begin(), original_msg.end());

    // 计算原始哈希
    auto original_hash = SM3::Hash(full_msg.data(), full_msg.size());
    std::cout << "\n原始消息哈希: ";
    PrintHex(original_hash);

    // 提取原始哈希状态（攻击者已知）
    uint32_t original_state[8];
    for (int i = 0; i < 8; ++i) {
        original_state[i] =
            (original_hash[i * 4] << 24) |
            (original_hash[i * 4 + 1] << 16) |
            (original_hash[i * 4 + 2] << 8) |
            original_hash[i * 4 + 3];
    }

    // 伪造哈希：计算 H(secret || original_msg || padding || malicious)
    auto forged_hash = SM3LengthExtensionAttack::ForgeHash(
        original_state,
        full_msg.size(),
        std::vector<uint8_t>(append_msg.begin(), append_msg.end())
    );
    std::cout << "伪造的哈希:   ";
    PrintHex(forged_hash);

    // 验证攻击结果：实际计算完整消息的哈希
    std::vector<uint8_t> legit_msg(full_msg);

    // 计算原始消息的填充
    auto padded_original = SM3::PadMessage(full_msg.data(), full_msg.size());
    // 移除原始数据（保留填充部分）
    std::vector<uint8_t> padding_only(padded_original.begin() + full_msg.size(), padded_original.end());

    // 添加填充和追加数据
    legit_msg.insert(legit_msg.end(), padding_only.begin(), padding_only.end());
    legit_msg.insert(legit_msg.end(), append_msg.begin(), append_msg.end());

    // 计算合法哈希
    auto legit_hash = SM3::Hash(legit_msg.data(), legit_msg.size());
    std::cout << "实际的哈希:   ";
    PrintHex(legit_hash);

    // 比较结果
    if (forged_hash == legit_hash) {
        std::cout << "\n攻击成功！伪造哈希与实际哈希匹配\n";
    }
    else {
        std::cout << "\n攻击失败！结果不匹配\n";

        // 调试信息
        std::cout << "伪造哈希大小: " << forged_hash.size() << "字节\n";
        std::cout << "实际哈希大小: " << legit_hash.size() << "字节\n";

        std::cout << "伪造哈希最后8字节: ";
        for (int i = 24; i < 32; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(forged_hash[i]);
        }
        std::cout << "\n实际哈希最后8字节: ";
        for (int i = 24; i < 32; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(legit_hash[i]);
        }
        std::cout << std::dec << std::endl;
    }

    return 0;
}