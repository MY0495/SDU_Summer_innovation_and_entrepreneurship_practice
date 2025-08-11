import random
import hashlib

# 定义椭圆曲线参数 
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


class EllipticCurve:
    def __init__(self, p, a, b, n, gx, gy):
        self.p = p
        self.a = a
        self.b = b
        self.n = n
        self.G = (gx, gy)

    def is_on_curve(self, point):
        """验证点是否在曲线上"""
        if point is None:
            return True
        x, y = point
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def point_add(self, P, Q):
        """高效的点加法实现"""
        if P is None: return Q
        if Q is None: return P

        x1, y1 = P
        x2, y2 = Q

        # 处理点与反点相加的情况
        if x1 == x2 and y1 != y2:
            return None

        # 计算斜率
        if P == Q:
            m = (3 * x1 * x1 + self.a) * pow(2 * y1, self.p - 2, self.p) % self.p
        else:
            m = (y2 - y1) * pow(x2 - x1, self.p - 2, self.p) % self.p

        # 计算新点坐标
        x3 = (m * m - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def scalar_mult(self, k, P):
        """优化的标量乘法（使用NAF表示法）"""
        result = None
        current = P

        # 处理k=0的情况
        if k == 0:
            return None

        # 使用NAF（非相邻形式）减少操作次数
        while k:
            if k & 1:
                result = self.point_add(result, current)
            current = self.point_add(current, current)
            k >>= 1
        return result

    def mod_inverse(self, a):
        """使用费马小定理计算模逆（更高效）"""
        return pow(a, self.p - 2, self.p) if a % self.p != 0 else 0


class ECDSA:
    def __init__(self, curve):
        self.curve = curve

    def generate_keypair(self):
        """生成密钥对（添加范围检查）"""
        d = random.randint(1, self.curve.n - 1)
        Q = self.curve.scalar_mult(d, self.curve.G)
        if not self.curve.is_on_curve(Q):
            return self.generate_keypair()  # 确保公钥有效
        return d, Q

    def compute_hash(self, message):
        """计算消息的哈希值"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        return int(hashlib.sha256(message).hexdigest(), 16) % self.curve.n

    def sign(self, d, message):
        """带重试机制的签名"""
        for _ in range(10):  # 防止无限循环
            k = random.randint(1, self.curve.n - 1)
            R = self.curve.scalar_mult(k, self.curve.G)

            if R is None:
                continue

            r = R[0] % self.curve.n
            if r == 0:
                continue

            e = self.compute_hash(message)
            k_inv = pow(k, self.curve.n - 2, self.curve.n)  # 更高效的模逆计算

            s = k_inv * (e + d * r) % self.curve.n
            if s == 0:
                continue

            return (r, s)
        raise RuntimeError("签名失败：无法生成有效的k值")

    def verify(self, Q, message, signature):
        """带严格检查的验证"""
        r, s = signature

        # 签名分量范围检查
        if not (1 <= r < self.curve.n) or not (1 <= s < self.curve.n):
            return False

        e = self.compute_hash(message)
        w = pow(s, self.curve.n - 2, self.curve.n)  # 更高效的模逆计算

        u1 = e * w % self.curve.n
        u2 = r * w % self.curve.n

        # 计算点 u1*G + u2*Q
        P1 = self.curve.scalar_mult(u1, self.curve.G)
        P2 = self.curve.scalar_mult(u2, Q)

        if P1 is None or P2 is None:
            return False

        R = self.curve.point_add(P1, P2)

        if R is None or R[0] % self.curve.n != r:
            return False

        return True

    def forge_signature(self, Q):
        """Satoshi签名伪造（优化实现）"""
        for _ in range(10):  # 防止无限循环
            u = random.randint(1, self.curve.n - 1)
            v = random.randint(1, self.curve.n - 1)

            # 计算点 R = u*G + v*Q
            P1 = self.curve.scalar_mult(u, self.curve.G)
            P2 = self.curve.scalar_mult(v, Q)

            if P1 is None or P2 is None:
                continue

            R = self.curve.point_add(P1, P2)

            if R is None:
                continue

            r = R[0] % self.curve.n
            if r == 0:
                continue

            v_inv = pow(v, self.curve.n - 2, self.curve.n)  # 更高效的模逆计算
            s = r * v_inv % self.curve.n
            if s == 0:
                continue

            e = u * r * v_inv % self.curve.n
            return e, (r, s)

        raise RuntimeError("伪造失败：无法生成有效的签名")

    def verify_forged(self, Q, e, signature):
        """验证伪造的签名"""
        r, s = signature

        if not (1 <= r < self.curve.n) or not (1 <= s < self.curve.n):
            return False

        w = pow(s, self.curve.n - 2, self.curve.n)
        u1 = e * w % self.curve.n
        u2 = r * w % self.curve.n

        P1 = self.curve.scalar_mult(u1, self.curve.G)
        P2 = self.curve.scalar_mult(u2, Q)

        if P1 is None or P2 is None:
            return False

        R = self.curve.point_add(P1, P2)

        return R is not None and R[0] % self.curve.n == r


def main():
    # 初始化
    curve = EllipticCurve(P, A, B, N, Gx, Gy)
    ecdsa = ECDSA(curve)

    print("=== 优化的ECDSA实现 ===")

    # 生成密钥对
    private_key, public_key = ecdsa.generate_keypair()
    print(f"私钥: {hex(private_key)[:20]}...")
    print(f"公钥: ({hex(public_key[0])[:20]}..., {hex(public_key[1])[:20]}...)")

    # 签名和验证
    message = "WZJ20040402"
    signature = ecdsa.sign(private_key, message)
    valid = ecdsa.verify(public_key, message, signature)
    print(f"\n消息: '{message}'")
    print(f"签名: r={hex(signature[0])[:12]}..., s={hex(signature[1])[:12]}...")
    print(f"验证结果: {'有效' if valid else '无效'}")

    # Satoshi签名伪造
    print("\n=== Satoshi签名伪造 ===")
    forged_e, forged_signature = ecdsa.forge_signature(public_key)

    print("伪造的签名:")
    print(f"r = {hex(forged_signature[0])[:12]}...")
    print(f"s = {hex(forged_signature[1])[:12]}...")
    print(f"e = {hex(forged_e)[:12]}...")

    # 验证伪造的签名
    valid_forgery = ecdsa.verify_forged(public_key, forged_e, forged_signature)
    print(f"\n伪造签名验证结果: {'成功' if valid_forgery else '失败'}")




if __name__ == "__main__":
    main()