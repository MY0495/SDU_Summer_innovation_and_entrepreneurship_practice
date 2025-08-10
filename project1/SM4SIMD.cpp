#include <immintrin.h>  // AVX2ָ�ͷ�ļ�
#include <cstdint>      // ��׼��������
#include <array>        // ��������
#include <cstring>      // �ڴ����
#include <iostream>     // �������
#include <iomanip>      // ��ʽ�����
#include <chrono>       // ʱ�����
#include <thread>       // ���߳�֧��
#include <vector>       // ��̬����

// ʹ�ñ�׼�����ռ�򻯴���
using std::array;
using std::uint32_t;

// SM4�㷨�����������
namespace SM4Core {

    // S���û������ұ�׼���壩
    constexpr uint8_t SBOX[256] = {
      0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
      // ...������S�����ݣ�
    };

    // Ԥ������ұ�
    array<uint32_t, 256> T0, T1, T2, T3;  // ������T��

    /**
     * @brief 32λѭ������
     * @param x ����ֵ
     * @param n ��λλ��
     * @return ѭ�����ƽ��
     */
    inline uint32_t RotateLeft(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    /**
     * @brief S���û��������Ա任�ӣ�
     * @param a ������
     * @return �û�����
     */
    uint32_t SboxSubstitution(uint32_t a) {
        return (static_cast<uint32_t>(SBOX[(a >> 24) & 0xFF]) << 24) |
            (static_cast<uint32_t>(SBOX[(a >> 16) & 0xFF]) << 16) |
            (static_cast<uint32_t>(SBOX[(a >> 8) & 0xFF]) << 8) |
            static_cast<uint32_t>(SBOX[a & 0xFF]);
    }

    /**
     * @brief ���Ա任L
     * @param b ������
     * @return �任���
     */
    uint32_t LinearTransform(uint32_t b) {
        return b ^ RotateLeft(b, 2) ^ RotateLeft(b, 10) ^ RotateLeft(b, 18) ^ RotateLeft(b, 24);
    }

    /**
     * @brief �ϳɱ任T
     * @param x ������
     * @return �任���
     */
    uint32_t CompositeTransform(uint32_t x) {
        return LinearTransform(SboxSubstitution(x));
    }

    /**
     * @brief ����Ԥ����T��
     */
    void GenerateLookupTables() {
        for (int i = 0; i < 256; ++i) {
            uint32_t t = SboxSubstitution(i << 24);
            T0[i] = LinearTransform(t);
            T1[i] = RotateLeft(T0[i], 8);   // Ԥ������ת8λ
            T2[i] = RotateLeft(T0[i], 16);  // Ԥ������ת16λ
            T3[i] = RotateLeft(T0[i], 24);  // Ԥ������ת24λ
        }
    }

    /**
     * @brief ��Կ��չ�㷨
     * @param MK ����Կ
     * @return ����Կ����
     */
    array<uint32_t, 32> KeyExpansion(const uint8_t MK[16]) {
        array<uint32_t, 32> roundKeys;
        const uint32_t FK[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };
        const uint32_t CK[32] = {
            0x00070E15,0x1C232A31,0x383F464D,0x545B6269,
            // ...������CK���飩
        };

        uint32_t K[36];
        // ��ʼ������Կ
        for (int i = 0; i < 4; ++i) {
            K[i] = (MK[4 * i] << 24) | (MK[4 * i + 1] << 16) | (MK[4 * i + 2] << 8) | MK[4 * i + 3];
            K[i] ^= FK[i];
        }

        // ��������Կ
        for (int i = 0; i < 32; ++i) {
            uint32_t tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i];
            tmp = CompositeTransform(tmp);
            K[i + 4] = K[i] ^ tmp;
            roundKeys[i] = K[i + 4];
        }
        return roundKeys;
    }

} // namespace SM4Core

// SIMD�Ż�ʵ��
namespace SM4SIMD {

    using namespace SM4Core;

    /**
     * @brief AVX2ָ�ʵ�ֵĺϳɱ任T
     * @param x ��������
     * @return �任�������
     */
    __m256i TransformAVX(__m256i x) {
        const __m256i MASK = _mm256_set1_epi32(0xFF);

        // �����ֽ�
        __m256i i0 = _mm256_srli_epi32(x, 24);
        __m256i i1 = _mm256_srli_epi32(x, 16);
        __m256i i2 = _mm256_srli_epi32(x, 8);
        __m256i i3 = x;
        i0 = _mm256_and_si256(i0, MASK);
        i1 = _mm256_and_si256(i1, MASK);
        i2 = _mm256_and_si256(i2, MASK);
        i3 = _mm256_and_si256(i3, MASK);

        // ������
        __m256i v0 = _mm256_i32gather_epi32((const int*)T0.data(), i0, 4);
        __m256i v1 = _mm256_i32gather_epi32((const int*)T1.data(), i1, 4);
        __m256i v2 = _mm256_i32gather_epi32((const int*)T2.data(), i2, 4);
        __m256i v3 = _mm256_i32gather_epi32((const int*)T3.data(), i3, 4);

        // �ϲ����
        return _mm256_xor_si256(_mm256_xor_si256(v0, v1),
            _mm256_xor_si256(v2, v3));
    }

    /**
     * @brief ���м���8�����ݿ�
     * @param input �������ݿ�����
     * @param output ������ݿ�����
     * @param roundKeys ����Կ
     */
    void ParallelEncrypt(const uint8_t input[8][16],
        uint8_t output[8][16],
        const array<uint32_t, 32>& roundKeys) {
        // �����������ݵ�AVX�Ĵ���
        __m256i X[4];
        uint32_t tmp[8];

        for (int i = 0; i < 4; ++i) {
            for (int b = 0; b < 8; ++b) {
                tmp[b] = (input[b][4 * i] << 24) | (input[b][4 * i + 1] << 16) |
                    (input[b][4 * i + 2] << 8) | input[b][4 * i + 3];
            }
            X[i] = _mm256_loadu_si256((__m256i*)tmp);
        }

        // 32�ֵ�������
        for (int r = 0; r < 32; ++r) {
            __m256i rk = _mm256_set1_epi32(roundKeys[r]);
            __m256i tmp = _mm256_xor_si256(_mm256_xor_si256(X[1], X[2]),
                _mm256_xor_si256(X[3], rk));
            __m256i Xn = _mm256_xor_si256(X[0], TransformAVX(tmp));

            // ���¼Ĵ���
            X[0] = X[1];
            X[1] = X[2];
            X[2] = X[3];
            X[3] = Xn;
        }

        // �洢���
        for (int i = 0; i < 4; ++i) {
            _mm256_storeu_si256((__m256i*)tmp, X[3 - i]);
            for (int b = 0; b < 8; ++b) {
                uint32_t val = tmp[b];
                output[b][4 * i] = val >> 24;
                output[b][4 * i + 1] = val >> 16;
                output[b][4 * i + 2] = val >> 8;
                output[b][4 * i + 3] = val;
            }
        }
    }

} // namespace SM4SIMD

// ���߳�����ַ�
namespace ParallelExecutor {

    using namespace SM4SIMD;

    /**
     * @brief ����������
     * @param input ��������ָ��
     * @param output �������ָ��
     * @param roundKeys ����Կ
     * @param batchCount ��������
     */
    void EncryptionTask(const uint8_t* input,
        uint8_t* output,
        const array<uint32_t, 32>& roundKeys,
        int batchCount) {
        for (int i = 0; i < batchCount; ++i) {
            ParallelEncrypt(
                reinterpret_cast<const uint8_t(*)[16]>(input + i * 8 * 16),
                reinterpret_cast<uint8_t(*)[16]>(output + i * 8 * 16),
                roundKeys);
        }
    }

    /**
     * @brief ���߳�ִ�м���/����
     * @tparam Func ����������
     * @param func ������
     * @param input ��������
     * @param output �������
     * @param roundKeys ����Կ
     * @param totalBlocks �ܿ���
     * @param batchSize ÿ������
     */
    template<typename Func>
    void ExecuteParallel(Func func,
        const std::vector<uint8_t>& input,
        std::vector<uint8_t>& output,
        const array<uint32_t, 32>& roundKeys,
        int totalBlocks,
        int batchSize = 8) {
        // �������κ��̷߳���
        int totalBatches = totalBlocks / batchSize;
        int threadCount = std::max(1, (int)std::thread::hardware_concurrency());
        int batchesPerThread = totalBatches / threadCount;
        int remaining = totalBatches % threadCount;

        std::vector<std::thread> workers;
        int offset = 0;

        // ���������������߳�
        for (int i = 0; i < threadCount; ++i) {
            int count = batchesPerThread + (i < remaining ? 1 : 0);
            if (count == 0) continue;

            workers.emplace_back(func,
                input.data() + offset * batchSize * 16,
                output.data() + offset * batchSize * 16,
                std::ref(roundKeys),
                count);

            offset += count;
        }

        // �ȴ������߳����
        for (auto& t : workers) {
            if (t.joinable()) t.join();
        }
    }

} // namespace ParallelExecutor

// ���ܲ��Ժ�ʾ��
int main() {
    // ��ʼ��SM4�㷨
    SM4Core::GenerateLookupTables();

    // ������Կ������
    const uint8_t key[16] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66
    };
    const uint8_t plaintext[16] = {
        'h','e','l','l','o',',',' ','s',
        'm','4',' ','d','e','m','o','!'
    };

    // ��Կ��չ
    auto roundKeys = SM4Core::KeyExpansion(key);

    // ׼����������
    constexpr int totalBlocks = 80000;  // �����ݿ���
    constexpr int batchSize = 8;        // SIMDÿ���������
    std::vector<uint8_t> plainData(totalBlocks * 16);
    std::vector<uint8_t> cipherData(totalBlocks * 16);
    std::vector<uint8_t> decryptedData(totalBlocks * 16);

    // ����������
    for (int i = 0; i < totalBlocks; ++i) {
        std::memcpy(&plainData[i * 16], plaintext, 16);
    }

    // ���̼߳������ܲ���
    auto start = std::chrono::high_resolution_clock::now();
    ParallelExecutor::ExecuteParallel(
        ParallelExecutor::EncryptionTask,
        plainData,
        cipherData,
        roundKeys,
        totalBlocks,
        batchSize);
    auto end = std::chrono::high_resolution_clock::now();

    // ��������ָ��
    double encryptTime = std::chrono::duration<double, std::milli>(end - start).count();
    double throughput = (totalBlocks * 16) / (encryptTime / 1000) / (1024 * 1024);  // MB/s

    std::cout << "�������ܲ���:\n";
    std::cout << "  ������: " << totalBlocks << " �� ("
        << (totalBlocks * 16 / 1024) << " KB)\n";
    std::cout << "  ��ʱ: " << encryptTime << " ����\n";
    std::cout << "  ������: " << throughput << " MB/s\n";

    // ��֤��һ����
    std::cout << "\n��һ����ܽ��:\n";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << (int)cipherData[i] << ' ';
    }
    std::cout << std::endl;

    return 0;
}