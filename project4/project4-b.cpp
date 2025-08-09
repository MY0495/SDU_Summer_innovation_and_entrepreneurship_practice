#include <iostream>
#include <cstring>
#include <iomanip>
#include <vector>
#include <string>

// SM3 ����ʵ����
class SM3 {
public:
    // ��������
    static constexpr uint32_t IV[8] = {
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };
    static constexpr size_t BLOCK_SIZE = 64; // 512 bits
    static constexpr size_t DIGEST_SIZE = 32; // 256 bits

    // ѭ������
    static uint32_t RotL(uint32_t x, uint8_t n) {
        return (x << n) | (x >> (32 - n));
    }

    // �������� FF
    static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        if (j < 16) return x ^ y ^ z;
        return (x & y) | (x & z) | (y & z);
    }

    // �������� GG
    static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        if (j < 16) return x ^ y ^ z;
        return (x & y) | (~x & z);
    }

    // �û����� P0
    static uint32_t P0(uint32_t x) {
        return x ^ RotL(x, 9) ^ RotL(x, 17);
    }

    // �û����� P1
    static uint32_t P1(uint32_t x) {
        return x ^ RotL(x, 15) ^ RotL(x, 23);
    }

    // ��Ϣ���
    static std::vector<uint8_t> PadMessage(const uint8_t* input, size_t len) {
        size_t bit_len = len * 8;
        size_t pad_len = (BLOCK_SIZE - (len % BLOCK_SIZE)) % BLOCK_SIZE;
        if (pad_len < 9) pad_len += BLOCK_SIZE; // ������Ҫ 9 �ֽڿռ�

        std::vector<uint8_t> padded(len + pad_len);
        memcpy(padded.data(), input, len);
        padded[len] = 0x80; // ��ӱ��� "1"

        // ��ӱ��� "0"
        memset(padded.data() + len + 1, 0, pad_len - 9);

        // ��ӳ��ȣ������
        for (int i = 0; i < 8; ++i) {
            padded[len + pad_len - 1 - i] = (bit_len >> (i * 8)) & 0xFF;
        }
        return padded;
    }

    // ѹ������
    static void Compress(const uint8_t block[BLOCK_SIZE], uint32_t state[8]) {
        uint32_t W[68] = { 0 };
        uint32_t W1[64] = { 0 };

        // ��Ϣ��չ
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

        // �Ĵ�����ʼ��
        uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
        uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

        // 64 �ֵ���
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

        // ����״̬
        state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
        state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
    }

    // �����ϣ
    static std::vector<uint8_t> Hash(const uint8_t* input, size_t len) {
        std::vector<uint8_t> padded = PadMessage(input, len);
        uint32_t state[8];
        memcpy(state, IV, sizeof(state));

        // ����ÿ����
        for (size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
            Compress(&padded[i], state);
        }

        // �����ϣֵ
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

// ������չ������
class SM3LengthExtensionAttack {
public:
    static std::vector<uint8_t> ForgeHash(
        const uint32_t original_state[8],     // ԭʼ��Ϣ�Ĺ�ϣ״̬
        size_t original_len,                   // ԭʼ��Ϣ���ȣ��ֽڣ�
        const std::vector<uint8_t>& append_data // Ҫ׷�ӵ�����
    ) {
        // 1. ����ԭʼ��Ϣ�����󳤶ȣ������飩
        const size_t padding_bytes = CalculatePaddingBytes(original_len);
        const size_t total_length_bytes = original_len + padding_bytes + append_data.size();
        const uint64_t total_length_bits = total_length_bytes * 8;

        // 2. ���������Ϣ������׷�����ݺ��µ����
        std::vector<uint8_t> malicious_data = append_data;

        // 3. ���׷����Ϣ����䣨ʹ���ܳ��ȣ�
        malicious_data.push_back(0x80); // �����ʼ���

        // ������Ҫ����0�ĸ���
        const size_t append_len = append_data.size();
        size_t zeros_needed = CalculateZerosNeeded(append_len + 1); // +1 for 0x80

        malicious_data.insert(malicious_data.end(), zeros_needed, 0);

        // ����ܳ��ȣ������
        for (int i = 0; i < 8; i++) {
            malicious_data.push_back((total_length_bits >> (56 - i * 8)) & 0xFF);
        }

        // 4. ��ԭʼ��ϣ״̬��ΪIVѹ��������Ϣ
        uint32_t forged_state[8];
        memcpy(forged_state, original_state, sizeof(forged_state));

        // ���������Ϣ��
        for (size_t i = 0; i < malicious_data.size(); i += SM3::BLOCK_SIZE) {
            SM3::Compress(&malicious_data[i], forged_state);
        }

        // 5. �������չ�ϣ
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
    // ����ԭʼ��Ϣ������ֽ���
    static size_t CalculatePaddingBytes(size_t len) {
        const size_t remainder = len % SM3::BLOCK_SIZE;
        // ���ʣ��ռ��㹻������9�ֽڣ���������СΪ1��0x80��+ zeros + 8
        if (remainder <= SM3::BLOCK_SIZE - 9) {
            return 1 + (SM3::BLOCK_SIZE - 9 - remainder) + 8;
        }
        // ������Ҫ����Ŀ�
        return 1 + (SM3::BLOCK_SIZE * 2 - 9 - remainder) + 8;
    }

    // ����׷��������Ҫ����0������
    static size_t CalculateZerosNeeded(size_t append_len) {
        const size_t position = (append_len) % SM3::BLOCK_SIZE;
        // ȷ��������ܳ��� % BLOCK_SIZE == 56�����8�ֽ����ڳ��ȣ�
        if (position <= 56) {
            return 56 - position;
        }
        return 56 + (SM3::BLOCK_SIZE - position);
    }
};

// ������������ӡʮ����������
void PrintHex(const std::vector<uint8_t>& data) {
    for (uint8_t b : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
    }
    std::cout << std::dec << std::endl;
}

int main() {
    // ==================== ����1������SM3������֤ ====================
    std::string message = "WZJ20040402";
    auto hash = SM3::Hash(
        reinterpret_cast<const uint8_t*>(message.data()), message.size()
    );
    std::cout << "SM3(\"" << message << "\") = ";
    PrintHex(hash); 

    // ==================== ����2��������չ������֤ ====================
    std::string secret = "secret_key";
    std::string original_msg = "original_data";
    std::string append_msg = "malicious";

    // ԭʼ��Ϣ��secret + original_msg
    std::vector<uint8_t> full_msg(secret.begin(), secret.end());
    full_msg.insert(full_msg.end(), original_msg.begin(), original_msg.end());

    // ����ԭʼ��ϣ
    auto original_hash = SM3::Hash(full_msg.data(), full_msg.size());
    std::cout << "\nԭʼ��Ϣ��ϣ: ";
    PrintHex(original_hash);

    // ��ȡԭʼ��ϣ״̬����������֪��
    uint32_t original_state[8];
    for (int i = 0; i < 8; ++i) {
        original_state[i] =
            (original_hash[i * 4] << 24) |
            (original_hash[i * 4 + 1] << 16) |
            (original_hash[i * 4 + 2] << 8) |
            original_hash[i * 4 + 3];
    }

    // α���ϣ������ H(secret || original_msg || padding || malicious)
    auto forged_hash = SM3LengthExtensionAttack::ForgeHash(
        original_state,
        full_msg.size(),
        std::vector<uint8_t>(append_msg.begin(), append_msg.end())
    );
    std::cout << "α��Ĺ�ϣ:   ";
    PrintHex(forged_hash);

    // ��֤���������ʵ�ʼ���������Ϣ�Ĺ�ϣ
    std::vector<uint8_t> legit_msg(full_msg);

    // ����ԭʼ��Ϣ�����
    auto padded_original = SM3::PadMessage(full_msg.data(), full_msg.size());
    // �Ƴ�ԭʼ���ݣ�������䲿�֣�
    std::vector<uint8_t> padding_only(padded_original.begin() + full_msg.size(), padded_original.end());

    // �������׷������
    legit_msg.insert(legit_msg.end(), padding_only.begin(), padding_only.end());
    legit_msg.insert(legit_msg.end(), append_msg.begin(), append_msg.end());

    // ����Ϸ���ϣ
    auto legit_hash = SM3::Hash(legit_msg.data(), legit_msg.size());
    std::cout << "ʵ�ʵĹ�ϣ:   ";
    PrintHex(legit_hash);

    // �ȽϽ��
    if (forged_hash == legit_hash) {
        std::cout << "\n�����ɹ���α���ϣ��ʵ�ʹ�ϣƥ��\n";
    }
    else {
        std::cout << "\n����ʧ�ܣ������ƥ��\n";

        // ������Ϣ
        std::cout << "α���ϣ��С: " << forged_hash.size() << "�ֽ�\n";
        std::cout << "ʵ�ʹ�ϣ��С: " << legit_hash.size() << "�ֽ�\n";

        std::cout << "α���ϣ���8�ֽ�: ";
        for (int i = 24; i < 32; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(forged_hash[i]);
        }
        std::cout << "\nʵ�ʹ�ϣ���8�ֽ�: ";
        for (int i = 24; i < 32; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(legit_hash[i]);
        }
        std::cout << std::dec << std::endl;
    }

    return 0;
}