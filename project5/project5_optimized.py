import random
import hashlib
import time
import binascii

# SM2推荐曲线参数（sm2p256v1）
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


class SM2Basic:
    """SM2基础版（未优化，使用仿射坐标直接运算）"""
    def __init__(self):
        self.p = P
        self.a = A
        self.b = B
        self.n = N
        self.G = (Gx, Gy)

    def _mod_inverse(self, a, p):
        return pow(a, -1, p)

    def _point_add(self, P, Q):
        if P == (0, 0): return Q
        if Q == (0, 0): return P
        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and (y1 + y2) % self.p == 0:
            return (0, 0)

        if P == Q:
            l = (3 * x1 * x1 + self.a) * self._mod_inverse(2 * y1, self.p) % self.p
        else:
            l = (y2 - y1) * self._mod_inverse(x2 - x1, self.p) % self.p

        x3 = (l * l - x1 - x2) % self.p
        y3 = (l * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def _point_mul(self, k, P):
        result = (0, 0)
        current = P
        while k:
            if k & 1:
                result = self._point_add(result, current)
            current = self._point_add(current, current)
            k >>= 1
        return result

    def _hash(self, data):
        try:
            h = hashlib.new('sm3')
        except:
            h = hashlib.sha256()
        h.update(data)
        return h.digest()

    def _kdf(self, Z, klen):
        ct = 1
        output = b''
        while len(output) < klen:
            output += self._hash(Z + ct.to_bytes(4, 'big'))
            ct += 1
        return output[:klen]

    def generate_keypair(self):
        d = random.randint(1, self.n - 1)
        P = self._point_mul(d, self.G)
        return d, P

    def serialize_public_key(self, P):
        return b'\x04' + P[0].to_bytes(32, 'big') + P[1].to_bytes(32, 'big')

    def encrypt(self, public_key, msg):
        if isinstance(msg, str):
            msg = msg.encode()
        klen = len(msg)
        k = random.randint(1, self.n - 1)

        C1 = self._point_mul(k, self.G)
        C1_bytes = self.serialize_public_key(C1)

        S = self._point_mul(k, public_key)
        x2_bytes = S[0].to_bytes(32, 'big')
        y2_bytes = S[1].to_bytes(32, 'big')

        t = self._kdf(x2_bytes + y2_bytes, klen)
        if all(b == 0 for b in t):
            raise ValueError("KDF = 0")

        C2 = bytes([m ^ t_i for m, t_i in zip(msg, t)])
        C3 = self._hash(x2_bytes + msg + y2_bytes)

        return C1_bytes + C3 + C2

    def decrypt(self, private_key, ciphertext):
        if ciphertext[0] != 0x04:
            raise ValueError("Invalid ciphertext format")
        C1 = (int.from_bytes(ciphertext[1:33], 'big'), int.from_bytes(ciphertext[33:65], 'big'))
        C3 = ciphertext[65:97]
        C2 = ciphertext[97:]

        S = self._point_mul(private_key, C1)
        x2_bytes = S[0].to_bytes(32, 'big')
        y2_bytes = S[1].to_bytes(32, 'big')

        t = self._kdf(x2_bytes + y2_bytes, len(C2))
        if all(b == 0 for b in t):
            raise ValueError("KDF = 0")

        M = bytes([c ^ t_i for c, t_i in zip(C2, t)])
        u = self._hash(x2_bytes + M + y2_bytes)

        if u != C3:
            raise ValueError("Hash verification failed")

        return M

    def sign(self, private_key, msg):
        if isinstance(msg, str):
            msg = msg.encode()
        e = int.from_bytes(self._hash(msg), 'big')
        while True:
            k = random.randint(1, self.n - 1)
            x1, y1 = self._point_mul(k, self.G)
            r = (e + x1) % self.n
            if r == 0 or r + k == self.n:
                continue
            s = (pow(1 + private_key, -1, self.n) * (k - r * private_key)) % self.n
            if s == 0:
                continue
            return (r, s)

    def verify(self, public_key, msg, signature):
        if isinstance(msg, str):
            msg = msg.encode()
        r, s = signature
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False
        e = int.from_bytes(self._hash(msg), 'big')
        t = (r + s) % self.n
        if t == 0:
            return False
        x1, y1 = self._point_mul(s, self.G)
        x2, y2 = self._point_mul(t, public_key)
        x, y = self._point_add((x1, y1), (x2, y2))
        R = (e + x) % self.n
        return R == r


class SM2Optimized(SM2Basic):
    """优化版SM2（引入雅可比坐标、预计算、窗口法等）"""
    def __init__(self):
        super().__init__()
        self.window_size = 4  # 窗口法大小（平衡预计算量与速度）
        self.precompute_table = self._precompute_fixed_point(self.G, self.window_size)  # 预计算基点倍数表

    # 雅可比坐标运算（避免频繁模逆，提升效率）
    def _jacobian_add(self, P, Q):
        """雅可比坐标下的点加（P=(X1,Y1,Z1), Q=(X2,Y2,Z2)）"""
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
                return self._jacobian_double(P)  # 点相等，转为加倍
            else:
                return (0, 1, 0)  # 相反点，返回无穷远点

        HH = (H * H) % self.p
        HHH = (H * HH) % self.p
        V = (U1 * HH) % self.p

        X3 = (R * R - HHH - 2 * V) % self.p
        Y3 = (R * (V - X3) - S1 * HHH) % self.p
        Z3 = (H * Z1 * Z2) % self.p

        return (X3, Y3, Z3)

    def _jacobian_double(self, P):
        """雅可比坐标下的点加倍（P=(X,Y,Z)）"""
        X, Y, Z = P
        if Z == 0 or Y == 0:
            return (0, 1, 0)  # 无穷远点

        YY = (Y * Y) % self.p
        S = (4 * X * YY) % self.p
        M = (3 * X * X + self.a * (Z * Z % self.p) **2) % self.p
        X3 = (M * M - 2 * S) % self.p
        Y3 = (M * (S - X3) - 8 * (YY * YY % self.p)) % self.p
        Z3 = (2 * Y * Z) % self.p

        return (X3, Y3, Z3)

    def _jacobian_to_affine(self, P):
        """雅可比坐标转仿射坐标（(X,Y,Z) → (x,y)）"""
        X, Y, Z = P
        if Z == 0:
            return (0, 0)
        Z_inv = self._mod_inverse(Z, self.p)
        Z_inv_sq = (Z_inv * Z_inv) % self.p
        x = (X * Z_inv_sq) % self.p
        y = (Y * Z_inv_sq * Z_inv) % self.p
        return (x, y)

    # 预计算与窗口法加速点乘
    def _precompute_fixed_point(self, base, window_size):
        """预计算固定点（如基点G）的奇数倍数表（用于窗口法）"""
        base_jac = (base[0], base[1], 1)  # 转为雅可比坐标
        table = []
        max_idx = 2** window_size  # 窗口覆盖的范围
        for i in range(1, max_idx, 2):  # 只存奇数（减少一半存储）
            pt = self._jacobian_mul_scalar(i, base_jac)
            table.append(pt)
        return table

    def _point_mul_fixed(self, k, table, window_size):
        """窗口法点乘（针对预计算的固定点，如G）"""
        R = (0, 1, 0)  # 初始为无穷远点（雅可比坐标）
        k_bin = bin(k)[2:]  # 转为二进制字符串
        i = 0
        while i < len(k_bin):
            if k_bin[i] == '0':
                R = self._jacobian_double(R)
                i += 1
            else:
                # 取最长有效窗口（不超过window_size，且值为奇数）
                j = min(window_size, len(k_bin) - i)
                while j > 1 and int(k_bin[i:i+j], 2) % 2 == 0:
                    j -= 1
                val = int(k_bin[i:i+j], 2)
                idx = (val - 1) // 2  # 映射到预计算表索引
                # 窗口内左移（加倍）
                for _ in range(j):
                    R = self._jacobian_double(R)
                # 加预计算点
                R = self._jacobian_add(R, table[idx])
                i += j
        return R

    # 蒙哥马利阶梯法（针对非固定点的点乘，兼顾安全与效率）
    def _montgomery_ladder(self, k, P):
        """蒙哥马利阶梯法点乘（抗侧信道攻击，用于非固定点）"""
        R0 = (0, 1, 0)  # 初始为无穷远点
        R1 = (P[0], P[1], 1)  # 初始为P（雅可比坐标）
        for i in reversed(range(k.bit_length())):
            bit = (k >> i) & 1
            if bit == 0:
                R1 = self._jacobian_add(R0, R1)
                R0 = self._jacobian_double(R0)
            else:
                R0 = self._jacobian_add(R0, R1)
                R1 = self._jacobian_double(R1)
        return R0

    def _jacobian_mul_scalar(self, k, P):
        """雅可比坐标下的基础点乘（用于预计算）"""
        R = (0, 1, 0)
        Q = P
        for i in reversed(range(k.bit_length())):
            R = self._jacobian_double(R)
            if (k >> i) & 1:
                R = self._jacobian_add(R, Q)
        return R

    # 重写点乘方法（根据点类型选择最优算法）
    def _point_mul(self, k, P):
        if P == self.G:
            # 基点G使用预计算+窗口法
            R_jac = self._point_mul_fixed(k, self.precompute_table, self.window_size)
            return self._jacobian_to_affine(R_jac)
        else:
            # 其他点使用蒙哥马利阶梯法
            R_jac = self._montgomery_ladder(k, P)
            return self._jacobian_to_affine(R_jac)


def performance_test():
    print("=== SM2基础版 vs 优化版 性能对比测试 ===")
    msg = "SM2优化测试：雅可比坐标+预计算+窗口法加速（100次迭代取平均）"
    iterations = 100  # 测试迭代次数（减少偶然误差）

    # 初始化两个版本
    sm2_basic = SM2Basic()
    sm2_opt = SM2Optimized()

    # 生成相同的密钥对（确保测试公平性）
    priv, pub = sm2_basic.generate_keypair()

    # 1. 加密性能对比
    basic_enc_time = 0.0
    opt_enc_time = 0.0
    for _ in range(iterations):
        # 基础版加密
        t1 = time.time()
        cipher_basic = sm2_basic.encrypt(pub, msg)
        t2 = time.time()
        basic_enc_time += (t2 - t1) * 1000  # 转为毫秒

        # 优化版加密
        t3 = time.time()
        cipher_opt = sm2_opt.encrypt(pub, msg)
        t4 = time.time()
        opt_enc_time += (t3 - t4) * 1000  # 转为毫秒（注意负号，t4>t3）

    avg_basic_enc = basic_enc_time / iterations
    avg_opt_enc = abs(opt_enc_time / iterations)
    enc_speedup = avg_basic_enc / avg_opt_enc  # 加速比

    # 2. 解密性能对比
    basic_dec_time = 0.0
    opt_dec_time = 0.0
    for _ in range(iterations):
        # 基础版解密
        t1 = time.time()
        sm2_basic.decrypt(priv, cipher_basic)
        t2 = time.time()
        basic_dec_time += (t2 - t1) * 1000

        # 优化版解密
        t3 = time.time()
        sm2_opt.decrypt(priv, cipher_opt)
        t4 = time.time()
        opt_dec_time += (t3 - t4) * 1000

    avg_basic_dec = basic_dec_time / iterations
    avg_opt_dec = abs(opt_dec_time / iterations)
    dec_speedup = avg_basic_dec / avg_opt_dec

    # 3. 签名性能对比
    basic_sign_time = 0.0
    opt_sign_time = 0.0
    for _ in range(iterations):
        # 基础版签名
        t1 = time.time()
        sig_basic = sm2_basic.sign(priv, msg)
        t2 = time.time()
        basic_sign_time += (t2 - t1) * 1000

        # 优化版签名
        t3 = time.time()
        sig_opt = sm2_opt.sign(priv, msg)
        t4 = time.time()
        opt_sign_time += (t3 - t4) * 1000

    avg_basic_sign = basic_sign_time / iterations
    avg_opt_sign = abs(opt_sign_time / iterations)
    sign_speedup = avg_basic_sign / avg_opt_sign

    # 4. 验签性能对比
    basic_verify_time = 0.0
    opt_verify_time = 0.0
    for _ in range(iterations):
        # 基础版验签
        t1 = time.time()
        sm2_basic.verify(pub, msg, sig_basic)
        t2 = time.time()
        basic_verify_time += (t2 - t1) * 1000

        # 优化版验签
        t3 = time.time()
        sm2_opt.verify(pub, msg, sig_opt)
        t4 = time.time()
        opt_verify_time += (t3 - t4) * 1000

    avg_basic_verify = basic_verify_time / iterations
    avg_opt_verify = abs(opt_verify_time / iterations)
    verify_speedup = avg_basic_verify / avg_opt_verify

    # 输出结果
    print(f"\n测试消息: {msg}")
    print(f"迭代次数: {iterations}次")
    print("\n=== 平均耗时（毫秒） ===")
    print(f"加密: 基础版={avg_basic_enc:.2f}ms | 优化版={avg_opt_enc:.2f}ms | 加速比={enc_speedup:.2f}x")
    print(f"解密: 基础版={avg_basic_dec:.2f}ms | 优化版={avg_opt_dec:.2f}ms | 加速比={dec_speedup:.2f}x")
    print(f"签名: 基础版={avg_basic_sign:.2f}ms | 优化版={avg_opt_sign:.2f}ms | 加速比={sign_speedup:.2f}x")
    print(f"验签: 基础版={avg_basic_verify:.2f}ms | 优化版={avg_opt_verify:.2f}ms | 加速比={verify_speedup:.2f}x")



if __name__ == "__main__":
    performance_test()