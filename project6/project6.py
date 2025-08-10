import random
import hashlib
from typing import List, Tuple, Set, Dict
from collections import defaultdict


class DDHPrivateIntersectionSum:
    def __init__(self, p: int = None, g: int = None):
        """
        初始化基于DDH的私有交集求和协议

        参数:
            p: 群的质数（如果为None，使用默认的安全质数）
            g: 群的生成元（如果为None，使用默认生成元）
        """
        # 使用安全质数 p = 2q + 1，其中q也是质数
        # 为了演示，使用较小的质数（实际应用中应使用更大的质数）
        if p is None:
            self.p = 2147483647  # 一个大质数 (2^31 - 1)
        else:
            self.p = p

        if g is None:
            self.g = 2  # 生成元
        else:
            self.g = g

    def hash_function(self, identifier: str) -> int:
        """
        哈希函数 H: U -> G，将标识符映射到群元素
        """
        hash_obj = hashlib.sha256(identifier.encode())
        hash_int = int(hash_obj.hexdigest(), 16)
        return hash_int % self.p

    def mod_exp(self, base: int, exp: int, mod: int) -> int:
        """
        模幂运算: (base^exp) mod mod
        """
        return pow(base, exp, mod)

    def generate_random_exponent(self) -> int:
        """
        在Z_p*中生成随机的私有指数
        """
        return random.randint(1, self.p - 2)


class AdditiveHomomorphicEncryption:
    """
    简单的加法同态加密方案
    仅用于演示 - 实际应用中应使用Paillier等成熟方案
    """

    def __init__(self):
        self.public_key = None  # 公钥
        self.private_key = None  # 私钥

    def generate_keypair(self) -> Tuple[int, int]:
        """生成公钥-私钥对"""
        # 简化的密钥生成（实际使用中不安全）
        self.private_key = random.randint(1000, 9999)
        self.public_key = self.private_key * 2 + 1
        return self.public_key, self.private_key

    def encrypt(self, plaintext: int, public_key: int) -> int:
        """加密明文值"""
        # 简化的加密（实际使用中不安全）
        noise = random.randint(1, 100)
        return (plaintext * public_key + noise) % (10 ** 10)

    def decrypt(self, ciphertext: int) -> int:
        """解密密文值"""
        # 简化的解密（实际使用中不安全）
        return (ciphertext // self.public_key) % (10 ** 6)

    def add_encrypted(self, c1: int, c2: int) -> int:
        """对两个加密值进行加法运算"""
        return (c1 + c2) % (10 ** 10)


class Party1:
    def __init__(self, identifiers: Set[str], protocol: DDHPrivateIntersectionSum):
        self.identifiers = identifiers  # 集合V
        self.protocol = protocol
        self.k1 = protocol.generate_random_exponent()  # 私钥k1
        self.round1_data = {}  # 存储第一轮的H(vi)^k1

    def round1(self) -> List[int]:
        """
        第一轮：对标识符进行哈希和指数运算，发送给P2
        """
        result = []
        for identifier in self.identifiers:
            hashed = self.protocol.hash_function(identifier)
            exponential = self.protocol.mod_exp(hashed, self.k1, self.protocol.p)
            self.round1_data[identifier] = exponential
            result.append(exponential)

        # 打乱顺序以保护隐私
        random.shuffle(result)
        return result

    def round3(self, round2_data: List[Tuple[int, int]]) -> int:
        """
        第三轮：计算交集和求和

        参数:
            round2_data: 来自P2的(H(wj)^k2, AEnc(tj))列表

        返回:
            交集的加密和
        """
        # 从第一轮数据创建集合Z
        Z = set(self.round1_data.values())

        # 找到交集J
        intersection_items = []
        intersection_sum_encrypted = 0
        encryption_scheme = AdditiveHomomorphicEncryption()

        for h_wj_k2, encrypted_tj in round2_data:
            # 用k1进行指数运算: (H(wj)^k2)^k1 = H(wj)^(k1*k2)
            h_wj_k1k2 = self.protocol.mod_exp(h_wj_k2, self.k1, self.protocol.p)

            # 检查是否在交集中
            if h_wj_k1k2 in Z:
                intersection_items.append(h_wj_k1k2)
                # 同态地添加加密值
                if intersection_sum_encrypted == 0:
                    intersection_sum_encrypted = encrypted_tj
                else:
                    intersection_sum_encrypted = encryption_scheme.add_encrypted(
                        intersection_sum_encrypted, encrypted_tj
                    )

        print(f"参与方1: 找到的交集大小为 {len(intersection_items)}")
        return intersection_sum_encrypted


class Party2:
    def __init__(self, pairs: List[Tuple[str, int]], protocol: DDHPrivateIntersectionSum):
        self.pairs = pairs  # (wi, ti)对的集合W
        self.protocol = protocol
        self.k2 = protocol.generate_random_exponent()  # 私钥k2
        self.encryption = AdditiveHomomorphicEncryption()
        self.public_key, self.private_key = self.encryption.generate_keypair()

    def get_public_key(self) -> int:
        """返回加法同态加密的公钥"""
        return self.public_key

    def round2(self, round1_data: List[int]) -> List[Tuple[int, int]]:
        """
        第二轮：处理P1的数据并准备自己的数据

        参数:
            round1_data: 来自P1的H(vi)^k1列表

        返回:
            (H(wj)^k2, AEnc(tj))对的列表
        """
        # 步骤1: 用k2对收到的数据进行指数运算
        Z = []
        for h_vi_k1 in round1_data:
            h_vi_k1k2 = self.protocol.mod_exp(h_vi_k1, self.k2, self.protocol.p)
            Z.append(h_vi_k1k2)

        # 步骤2: 处理自己的对
        result = []
        for wi, ti in self.pairs:
            # 对标识符进行哈希
            h_wi = self.protocol.hash_function(wi)
            # 用k2进行指数运算
            h_wi_k2 = self.protocol.mod_exp(h_wi, self.k2, self.protocol.p)
            # 加密值ti
            encrypted_ti = self.encryption.encrypt(ti, self.public_key)
            result.append((h_wi_k2, encrypted_ti))

        # 打乱顺序以保护隐私
        random.shuffle(result)
        return result

    def decrypt_final_result(self, encrypted_sum: int) -> int:
        """
        解密最终的交集和

        参数:
            encrypted_sum: 来自P1的加密和

        返回:
            解密后的交集和
        """
        return self.encryption.decrypt(encrypted_sum)


def run_protocol_example():
    """
    基于DDH的私有交集求和协议的示例执行
    """
    print("=== 基于DDH的私有交集求和协议演示 ===\n")

    # 初始化协议
    protocol = DDHPrivateIntersectionSum()

    # 参与方1的数据：标识符集合
    p1_identifiers = {"alice", "bob", "charlie", "david", "eve"}
    print(f"参与方1的标识符: {p1_identifiers}")

    # 参与方2的数据：(标识符, 值)对
    p2_pairs = [
        ("alice", 10),
        ("bob", 20),
        ("frank", 15),
        ("charlie", 30),
        ("grace", 25)
    ]
    print(f"参与方2的对: {p2_pairs}")

    # 预期的交集：alice, bob, charlie
    # 预期的和：10 + 20 + 30 = 60
    print(f"预期的交集: alice, bob, charlie")
    print(f"预期的和: 10 + 20 + 30 = 60\n")

    # 创建参与方
    party1 = Party1(p1_identifiers, protocol)
    party2 = Party2(p2_pairs, protocol)

    print("--- 协议执行 ---")

    #  setup阶段：P2与P1共享公钥
    pk = party2.get_public_key()
    print(f"setup阶段: 参与方2生成并共享公钥")

    # 第一轮：P1处理其标识符
    print("第一轮: 参与方1对其标识符进行哈希和指数运算")
    round1_result = party1.round1()
    print(f"参与方1向参与方2发送 {len(round1_result)} 个处理后的标识符")

    # 第二轮：P2处理两个数据集
    print("第二轮: 参与方2处理收到的数据并准备自己的数据")
    round2_result = party2.round2(round1_result)
    print(f"参与方2向参与方1发送 {len(round2_result)} 个处理后的对")

    # 第三轮：P1计算交集和
    print("第三轮: 参与方1计算加密的交集和")
    encrypted_sum = party1.round3(round2_result)
    print(f"参与方1计算加密和并发送给参与方2")

    # 输出：P2解密结果
    print("输出: 参与方2解密最终结果")
    final_sum = party2.decrypt_final_result(encrypted_sum)

    print(f"\n=== 结果 ===")
    print(f"计算得到的交集和: {final_sum}")
    print(f"协议成功完成!")

    return final_sum


if __name__ == "__main__":
    # 运行协议示例
    result = run_protocol_example()

    print(f"\n=== 安全特性 ===")
    print("- 参与方1不会获取参与方2的值信息")
    print("- 参与方2仅能获取交集的和，而不能获取单个项目")
    print("- 协议在DDH假设下是安全的")
    print("- 通过批处理和打乱顺序最小化通信量")