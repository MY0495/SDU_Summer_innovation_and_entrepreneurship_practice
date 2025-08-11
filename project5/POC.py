import random
import hashlib
from hashlib import sha256

# SM2推荐曲线参数（GB/T 32918.1-2016标准）
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


class SM2SignatureMisusePOC:
    def __init__(self):
        self.p = P  # 有限域素数
        self.a = A  # 曲线参数A
        self.b = B  # 曲线参数B
        self.n = N  # 基点阶
        self.G = (Gx, Gy)  # 生成元
        self.window_size = 4  # 窗口法优化参数
        self.precompute_table = self._precompute_fixed_point(self.G, self.window_size)

    # ------------------------------
    # 椭圆曲线核心运算（优化实现）
    # ------------------------------
    def _mod_inverse(self, a, p):
        """模逆运算"""
        return pow(a, -1, p)

    def _jacobian_add(self, P, Q):
        """雅可比坐标下的点加法"""
        if P[2] == 0:
            return Q
        if Q[2] == 0:
            return P

        X1, Y1, Z1 = P
        X2, Y2, Z2 = Q

        Z1Z1 = (Z1 * Z1) % self.p
        Z2Z2 = (Z2 * Z2) % self.p

        U1 = (X1 * Z2Z2) % self.p
        U2 = (X2 * Z1Z1) % self.p

        S1 = (Y1 * Z2 * Z2Z2) % self.p
        S2 = (Y2 * Z1 * Z1Z1) % self.p

        H = (U2 - U1) % self.p
        R = (S2 - S1) % self.p

        if H == 0:
            if R == 0:
                return self._jacobian_double(P)
            else:
                return (0, 1, 0)

        HH = (H * H) % self.p
        HHH = (H * HH) % self.p
        V = (U1 * HH) % self.p

        X3 = (R * R - HHH - 2 * V) % self.p
        Y3 = (R * (V - X3) - S1 * HHH) % self.p
        Z3 = (H * Z1 * Z2) % self.p

        return (X3, Y3, Z3)

    def _jacobian_double(self, P):
        """雅可比坐标下的点加倍"""
        X1, Y1, Z1 = P
        if Z1 == 0 or Y1 == 0:
            return (0, 1, 0)

        YY = (Y1 * Y1) % self.p
        S = (4 * X1 * YY) % self.p
        M = (3 * X1 * X1 + self.a * ((Z1 * Z1) % self.p) ** 2) % self.p
        X3 = (M * M - 2 * S) % self.p
        Y3 = (M * (S - X3) - 8 * (YY * YY % self.p)) % self.p
        Z3 = (2 * Y1 * Z1) % self.p

        return (X3, Y3, Z3)

    def _jacobian_to_affine(self, P):
        """雅可比坐标转仿射坐标"""
        X, Y, Z = P
        if Z == 0:
            return (0, 0)
        Z_inv = self._mod_inverse(Z, self.p)
        Z_inv_sq = (Z_inv * Z_inv) % self.p
        x = (X * Z_inv_sq) % self.p
        y = (Y * Z_inv_sq * Z_inv) % self.p
        return (x, y)

    def _precompute_fixed_point(self, base, window_size):
        """预计算固定点倍数表（窗口法优化）"""
        base_jac = (base[0], base[1], 1)
        table = []
        max_idx = 2 ** window_size
        for i in range(1, max_idx, 2):
            pt = self._jacobian_mul_scalar(i, base_jac)
            table.append(pt)
        return table

    def _jacobian_mul_scalar(self, k, P):
        """基础点乘实现（用于预计算）"""
        R = (0, 1, 0)
        Q = P
        for i in reversed(range(k.bit_length())):
            R = self._jacobian_double(R)
            if (k >> i) & 1:
                R = self._jacobian_add(R, Q)
        return R

    def _point_mul_fixed(self, k, table, window_size):
        """窗口法点乘（针对预计算的固定点）"""
        R = (0, 1, 0)
        k_bin = bin(k)[2:]
        i = 0
        while i < len(k_bin):
            if k_bin[i] == '0':
                R = self._jacobian_double(R)
                i += 1
            else:
                j = min(window_size, len(k_bin) - i)
                while j > 1 and int(k_bin[i:i + j], 2) % 2 == 0:
                    j -= 1
                val = int(k_bin[i:i + j], 2)
                idx = (val - 1) // 2
                for _ in range(j):
                    R = self._jacobian_double(R)
                R = self._jacobian_add(R, table[idx])
                i += j
        return R

    def _montgomery_ladder(self, k, P):
        """蒙哥马利阶梯法点乘（抗侧信道攻击）"""
        R0 = (0, 1, 0)
        R1 = (P[0], P[1], 1)
        for i in reversed(range(k.bit_length())):
            bit = (k >> i) & 1
            if bit == 0:
                R1 = self._jacobian_add(R0, R1)
                R0 = self._jacobian_double(R0)
            else:
                R0 = self._jacobian_add(R0, R1)
                R1 = self._jacobian_double(R1)
        return R0

    def _point_mul(self, k, P):
        """点乘主方法（自动选择最优算法）"""
        if P == self.G:
            R_jac = self._point_mul_fixed(k, self.precompute_table, self.window_size)
            return self._jacobian_to_affine(R_jac)
        else:
            R_jac = self._montgomery_ladder(k, P)
            return self._jacobian_to_affine(R_jac)

    # ------------------------------
    # 哈希与密钥派生
    # ------------------------------
    def _hash(self, data):
        """哈希函数（优先SM3， fallback到SHA256）"""
        try:
            h = hashlib.new('sm3')
        except:
            h = hashlib.sha256()
        h.update(data)
        return h.digest()

    # ------------------------------
    # 密钥生成与签名基础方法
    # ------------------------------
    def generate_keypair(self):
        """生成SM2密钥对"""
        d = random.randint(1, self.n - 1)
        P = self._point_mul(d, self.G)
        return d, P

    def sign_specific_k(self, private_key, msg, k):
        """使用指定的k进行签名（用于POC测试）"""
        if isinstance(msg, str):
            msg = msg.encode()
        e = int.from_bytes(self._hash(msg), 'big')
        x1, y1 = self._point_mul(k, self.G)
        r = (e + x1) % self.n
        if r == 0 or r + k == self.n:
            return None
        s = (self._mod_inverse(1 + private_key, self.n) * (k - r * private_key)) % self.n
        if s == 0:
            return None
        return (r, s)

    # ------------------------------
    # 场景1：泄露临时密钥k导致私钥泄露
    # ------------------------------
    def scenario1_leak_k(self):
        print("=== 场景1：泄露临时密钥k导致私钥泄露 ===")
        private_key, public_key = self.generate_keypair()
        msg = b"Scenario 1: Leaking temporary key k"
        k = random.randint(1, self.n - 1)  # 被泄露的k

        # 生成签名
        signature = self.sign_specific_k(private_key, msg, k)
        if not signature:
            return False
        r, s = signature

        # 从k和签名推导私钥
        denominator = (s + r) % self.n
        if denominator == 0:
            return False
        d_derived = (k - s) * pow(denominator, -1, self.n) % self.n

        # 验证结果
        print(f"原始私钥: {hex(private_key)}")
        print(f"推导私钥: {hex(d_derived)}")
        result = d_derived == private_key
        print(f"攻击成功: {result}\n")
        return result

    # ------------------------------
    # 场景2：重用临时密钥k导致私钥泄露
    # ------------------------------
    def scenario2_reuse_k(self):
        print("=== 场景2：重用临时密钥k导致私钥泄露 ===")
        private_key, public_key = self.generate_keypair()
        msg1 = b"Scenario 2: Reuse k - message 1"
        msg2 = b"Scenario 2: Reuse k - message 2"
        k = random.randint(1, self.n - 1)  # 被重用的k

        # 用相同k生成两个签名
        sig1 = self.sign_specific_k(private_key, msg1, k)
        sig2 = self.sign_specific_k(private_key, msg2, k)
        if not sig1 or not sig2:
            return False
        r1, s1 = sig1
        r2, s2 = sig2

        # 从两个签名推导私钥
        numerator = (s1 - s2) % self.n
        denominator = (r2 - r1 - (s1 - s2)) % self.n
        if denominator == 0:
            return False
        d_derived = numerator * pow(denominator, -1, self.n) % self.n

        # 验证结果
        print(f"原始私钥: {hex(private_key)}")
        print(f"推导私钥: {hex(d_derived)}")
        result = d_derived == private_key
        print(f"攻击成功: {result}\n")
        return result

    # ------------------------------
    # 场景3：不同用户重用相同k导致私钥泄露
    # ------------------------------
    def scenario3_same_k_different_users(self):
        print("=== 场景3：不同用户重用相同k导致私钥泄露 ===")
        # 生成两个用户的密钥对
        privA, pubA = self.generate_keypair()
        privB, pubB = self.generate_keypair()
        k = random.randint(1, self.n - 1)  # 被两个用户共用的k

        # 两个用户用相同k签名
        sigA = self.sign_specific_k(privA, b"User A message", k)
        sigB = self.sign_specific_k(privB, b"User B message", k)
        if not sigA or not sigB:
            return False
        rA, sA = sigA
        rB, sB = sigB

        # 用户A推导用户B的私钥
        denominator = (sB + rB) % self.n
        if denominator == 0:
            return False
        d_derived = (k - sB) * pow(denominator, -1, self.n) % self.n

        # 验证结果
        print(f"用户B原始私钥: {hex(privB)}")
        print(f"用户A推导私钥: {hex(d_derived)}")
        result = d_derived == privB
        print(f"攻击成功: {result}\n")
        return result

    # ------------------------------
    # 场景4：ECDSA与Schnorr共用(d,k)导致私钥泄露
    # ------------------------------
    def scenario4_shared_dk_between_algorithms(self):
        print("=== 场景4：ECDSA与Schnorr共用(d,k)导致私钥泄露 ===")
        n = self.n
        d = random.randint(1, n - 1)  # 共用的私钥
        k = random.randint(1, n - 1)  # 共用的临时密钥

        # 共用的消息
        msg = b"Shared message for ECDSA and Schnorr"

        # ECDSA签名参数
        e_ecdsa = int.from_bytes(sha256(msg).digest(), 'big') % n
        x1, y1 = self._point_mul(k, self.G)
        r = x1 % n
        s_ecdsa = (pow(k, -1, n) * (e_ecdsa + d * r)) % n  # ECDSA签名值

        # Schnorr签名参数
        e_schnorr = int.from_bytes(sha256(b"schnorr:" + msg).digest(), 'big') % n
        s_schnorr = (k + e_schnorr * d) % n  # Schnorr签名值

        # 从两个签名推导私钥
        numerator = (s_schnorr * s_ecdsa - e_ecdsa) % n
        denominator = (r + e_schnorr * s_ecdsa) % n
        if denominator == 0:
            return False
        d_derived = (numerator * pow(denominator, -1, n)) % n

        # 验证结果
        print(f"原始私钥: {hex(d)}")
        print(f"推导私钥: {hex(d_derived)}")
        result = d_derived == d
        print(f"攻击成功: {result}\n")
        return result


if __name__ == "__main__":
    # 初始化POC验证实例
    sm2_poc = SM2SignatureMisusePOC()

    # 运行所有场景测试
    success_count = 0
    total_scenarios = 4

    success_count += 1 if sm2_poc.scenario1_leak_k() else 0
    success_count += 1 if sm2_poc.scenario2_reuse_k() else 0
    success_count += 1 if sm2_poc.scenario3_same_k_different_users() else 0
    success_count += 1 if sm2_poc.scenario4_shared_dk_between_algorithms() else 0

    # 输出总结果
    print(f"=== 测试总结 ===")
    print(f"总场景数: {total_scenarios}")
    print(f"攻击成功场景数: {success_count}")
    print(f"所有场景验证完成")