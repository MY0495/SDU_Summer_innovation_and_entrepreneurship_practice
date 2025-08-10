#include <cstdint>
#include <array>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <chrono>

using std::array;
using std::uint32_t;

// SM4�㷨S�У�8λ�������滻��������ǿ��������
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

// �ֳ�����32��32λֵ����������Կ���ɣ���ǿ��Կ��ɢ
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

// �̶���Կ��4��32λ��ʼ��Կ��������Կ��չ��ʼ��
static const uint32_t SM4_FK[4] = {
    0xA3B1BAC6,0x56AA3350,0x677D9197,0xB27022DC
};

/**
 * 32λ����ѭ������
 * @param value �����32λ����
 * @param shift ����λ����0-31��
 * @return ���ƺ�Ľ��
 */
inline uint32_t rotate_left(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

/**
 * �ֽ��滻������S�еķ����Ա任
 * @param input 32λ���루4���ֽڣ�
 * @return �滻���32λ���
 */
inline uint32_t substitute_bytes(uint32_t input) {
    return (static_cast<uint32_t>(SM4_SBOX[(input >> 24) & 0xFF]) << 24) |
        (static_cast<uint32_t>(SM4_SBOX[(input >> 16) & 0xFF]) << 16) |
        (static_cast<uint32_t>(SM4_SBOX[(input >> 8) & 0xFF]) << 8) |
        static_cast<uint32_t>(SM4_SBOX[input & 0xFF]);
}

/**
 * ���Ա任��ͨ��������λ�����ǿ��ɢ
 * @param input 32λ����
 * @return �任���32λ���
 */
inline uint32_t linear_transform(uint32_t input) {
    return input ^ rotate_left(input, 2) ^ rotate_left(input, 10) ^ rotate_left(input, 18) ^ rotate_left(input, 24);
}

/**
 * �����Ա任��S���滻+���Ա任����ϣ��ֺ������ģ�
 * @param input 32λ����
 * @return �任���32λ���
 */
inline uint32_t nonlinear_transform(uint32_t input) {
    return linear_transform(substitute_bytes(input));
}

/**
 * ����32������Կ
 * @param main_key 16�ֽ�����Կ
 * @return 32��32λ����Կ������
 */
std::array<uint32_t, 32> generate_round_keys(const uint8_t main_key[16]) {
    array<uint32_t, 32> round_keys;  // �洢32�ּ������������Կ
    uint32_t key_reg[36];            // ��Կ��չ�Ĵ������м������

    // ��ʼ����Կ�Ĵ���������Կת��Ϊ32λ�ֲ���̶���Կ���
    for (int idx = 0; idx < 4; ++idx) {
        key_reg[idx] = (main_key[4 * idx] << 24) | (main_key[4 * idx + 1] << 16) |
            (main_key[4 * idx + 2] << 8) | main_key[4 * idx + 3];
        key_reg[idx] ^= SM4_FK[idx];  // ��̶���Կ�����ǿ��ʼ��ɢ
    }

    // ��������32������Կ
    for (int idx = 0; idx < 32; ++idx) {
        // ���ǰ3���Ĵ������ֳ����������м�ֵ
        uint32_t temp = key_reg[idx + 1] ^ key_reg[idx + 2] ^ key_reg[idx + 3] ^ SM4_CK[idx];
        // Ӧ��S���滻��L'�任��13λ��23λ�������
        temp = substitute_bytes(temp);
        temp ^= rotate_left(temp, 13) ^ rotate_left(temp, 23);
        // ���¼Ĵ�������������Կ
        key_reg[idx + 4] = key_reg[idx] ^ temp;
        round_keys[idx] = key_reg[idx + 4];
    }

    return round_keys;
}

/**
 * ����SM4���ܣ�16�ֽڣ�
 * @param in 16�ֽ���������
 * @param out 16�ֽ��������
 * @param round_keys 32������Կ
 */
void sm4_block_encrypt(const uint8_t in[16], uint8_t out[16], const std::array<uint32_t, 32>& round_keys) {
    uint32_t state[36];  // ״̬�Ĵ������洢���ܹ����е��м�״̬

    // ��ʼ��״̬�Ĵ���������ת��Ϊ32λ��
    for (int idx = 0; idx < 4; ++idx) {
        state[idx] = (in[4 * idx] << 24) | (in[4 * idx + 1] << 16) |
            (in[4 * idx + 2] << 8) | in[4 * idx + 3];
    }

    // 32�ּ������㣺ÿ�ָ���״̬�Ĵ���
    for (int idx = 0; idx < 32; ++idx) {
        // �ֺ������� = ǰ3��״̬ ^ ����Կ
        uint32_t temp = state[idx + 1] ^ state[idx + 2] ^ state[idx + 3] ^ round_keys[idx];
        // ״̬���£���ǰ״̬ ^ �����Ա任���
        state[idx + 4] = state[idx] ^ nonlinear_transform(temp);
    }

    // ����������4��״̬���õ�����
    for (int idx = 0; idx < 4; ++idx) {
        uint32_t cipher_word = state[35 - idx];  // ����ȡ״̬
        out[4 * idx] = static_cast<uint8_t>(cipher_word >> 24);
        out[4 * idx + 1] = static_cast<uint8_t>(cipher_word >> 16);
        out[4 * idx + 2] = static_cast<uint8_t>(cipher_word >> 8);
        out[4 * idx + 3] = static_cast<uint8_t>(cipher_word);
    }
}

/**
 * ����SM4���ܣ�16�ֽڣ�
 * @param in 16�ֽ���������
 * @param out 16�ֽ��������
 * @param round_keys 32������Կ������ʱ���ɣ�
 */
void sm4_block_decrypt(const uint8_t in[16], uint8_t out[16], const std::array<uint32_t, 32>& round_keys) {
    std::array<uint32_t, 32> reversed_round_keys;  // ����������Կ������
    for (int idx = 0; idx < 32; ++idx) {
        reversed_round_keys[idx] = round_keys[31 - idx];  // ����Կ����
    }
    // ���ü��ܺ�����ʹ�÷�������Կ
    sm4_block_encrypt(in, out, reversed_round_keys);
}


int main() {
    // 16�ֽ�ʾ����Կ����Ӧ�ַ���"0123456789abcdef"��
    uint8_t secret_key[16] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66
    };
    // 16�ֽ�ʾ�����ģ���Ӧ�ַ���"hello, sm4 demo!"��
    const char plaintext_init[16] = { 'h','e','l','l','o',',',' ','s','m','4',' ','d','e','m','o','!' };

    uint8_t plaintext[16], ciphertext[16], decrypted[16];
    memcpy(plaintext, plaintext_init, 16);  // �������ĵ�������

    // ��������Կ
    auto round_keys = generate_round_keys(secret_key);

    // ִ�м��ܺͽ���
    sm4_block_encrypt(plaintext, ciphertext, round_keys);
    sm4_block_decrypt(ciphertext, decrypted, round_keys);

    // ��������ʮ�����Ƹ�ʽ��
    std::cout << "��������: ";
    for (uint8_t byte : plaintext) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << ' ';
    }
    std::cout << "\n��������: ";
    for (uint8_t byte : ciphertext) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << ' ';
    }
    std::cout << "\n���ܽ��: ";
    for (uint8_t byte : decrypted) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << ' ';
    }
    std::cout << '\n';

    // �������ܲ��ԣ��ظ�10000�μ���ƽ����ʱ��
    constexpr int TEST_COUNT = 10000;
    auto encrypt_start = std::chrono::high_resolution_clock::now();
    for (int idx = 0; idx < TEST_COUNT; ++idx) {
        sm4_block_encrypt(plaintext, ciphertext, round_keys);
    }
    auto encrypt_end = std::chrono::high_resolution_clock::now();
    double encrypt_avg_ms = std::chrono::duration<double, std::milli>(encrypt_end - encrypt_start).count() / TEST_COUNT;
    std::cout << "����ƽ����ʱ: " << encrypt_avg_ms << " ����/��\n";

    // �������ܲ��ԣ��ظ�10000�μ���ƽ����ʱ��
    auto decrypt_start = std::chrono::high_resolution_clock::now();
    for (int idx = 0; idx < TEST_COUNT; ++idx) {
        sm4_block_decrypt(ciphertext, plaintext, round_keys);
    }
    auto decrypt_end = std::chrono::high_resolution_clock::now();
    double decrypt_avg_ms = std::chrono::duration<double, std::milli>(decrypt_end - decrypt_start).count() / TEST_COUNT;
    std::cout << "����ƽ����ʱ: " << decrypt_avg_ms << " ����/��\n";

    return 0;
}