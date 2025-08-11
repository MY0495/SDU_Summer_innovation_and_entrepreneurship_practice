import random
import hashlib
import time
import binascii

# 基于GB/T 32918.1-2016标准定义
CURVE_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
CURVE_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
CURVE_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
CURVE_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
CURVE_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
CURVE_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0


class SM2Crypto:
    """
    国密SM2椭圆曲线公钥密码算法实现
    支持密钥对生成、加密、解密操作，遵循GB/T 32918.1-2016标准
    """

    def __init__(self):
        # 初始化椭圆曲线参数
        self.prime = CURVE_P  # 有限域素数
        self.coeff_a = CURVE_A  # 曲线参数A
        self.coeff_b = CURVE_B  # 曲线参数B
        self.order = CURVE_N  # 基点阶数
        self.base_point = (CURVE_GX, CURVE_GY)  # 生成元G
        self.infinity = (0, 0)  # 椭圆曲线上的无穷远点

    def _mod_inverse(self, a: int, mod: int) -> int:
        """
        模逆运算实现（基于扩展欧几里得算法）
        :param a: 待求逆的整数
        :param mod: 模数
        :return: a在mod下的逆元
        """
        if a == 0:
            raise ZeroDivisionError("无法计算0的模逆")
        return pow(a, -1, mod)

    def _ec_point_add(self, point_p: tuple, point_q: tuple) -> tuple:
        """
        椭圆曲线点加法运算
        :param point_p: 点P
        :param point_q: 点Q
        :return: P+Q的结果点
        """
        # 处理无穷远点情况
        if point_p == self.infinity:
            return point_q
        if point_q == self.infinity:
            return point_p

        x_p, y_p = point_p
        x_q, y_q = point_q

        # 若两点关于x轴对称，和为无穷远点
        if x_p == x_q and (y_p + y_q) % self.prime == 0:
            return self.infinity

        # 计算斜率λ
        if point_p == point_q:
            # 点加倍：λ = (3x_p² + a) / (2y_p)
            numerator = (3 * pow(x_p, 2, self.prime) + self.coeff_a) % self.prime
            denominator = (2 * y_p) % self.prime
        else:
            # 点相加：λ = (y_q - y_p) / (x_q - x_p)
            numerator = (y_q - y_p) % self.prime
            denominator = (x_q - x_p) % self.prime

        lambda_val = (numerator * self._mod_inverse(denominator, self.prime)) % self.prime

        # 计算结果点坐标
        x_r = (pow(lambda_val, 2, self.prime) - x_p - x_q) % self.prime
        y_r = (lambda_val * (x_p - x_r) - y_p) % self.prime

        return (x_r, y_r)

    def _ec_scalar_mul(self, scalar: int, point: tuple) -> tuple:
        """
        椭圆曲线点乘运算（标量乘法）
        :param scalar: 标量k
        :param point: 点P
        :return: k*P的结果点
        """
        result = self.infinity  # 初始化为无穷远点
        current = point
        k = scalar

        # 二进制展开法实现点乘
        while k > 0:
            if k & 1:  # 若当前位为1，累加结果
                result = self._ec_point_add(result, current)
            current = self._ec_point_add(current, current)  # 倍点运算
            k >>= 1  # 右移一位

        return result

    def _hash_func(self, data: bytes) -> bytes:
        """
        哈希函数封装（优先使用SM3，不支持时回退到SHA256）
        :param data: 输入数据
        :return: 哈希结果
        """
        try:
            hash_obj = hashlib.new('sm3')
        except ValueError:
            hash_obj = hashlib.sha256()  # 兼容性回退
        hash_obj.update(data)
        return hash_obj.digest()

    def _key_derive(self, z: bytes, key_len: int) -> bytes:
        """
        密钥派生函数KDF
        :param z: 输入字节串
        :param key_len: 目标密钥长度（字节）
        :return: 派生密钥
        """
        counter = 1
        derived = b''
        # 循环生成足够长度的密钥材料
        while len(derived) < key_len:
            # 每次迭代添加哈希结果（Z || 计数器）
            derived += self._hash_func(z + counter.to_bytes(4, 'big'))
            counter += 1
        return derived[:key_len]  # 截断到目标长度

    def generate_key_pair(self) -> tuple:
        """
        生成SM2密钥对
        :return: (私钥, 公钥)，私钥为整数，公钥为坐标元组
        """
        # 生成1到n-1之间的随机私钥
        private_key = random.randint(1, self.order - 1)
        # 计算公钥：P = d*G
        public_key = self._ec_scalar_mul(private_key, self.base_point)
        return (private_key, public_key)

    def encode_public_key(self, pub_key: tuple) -> bytes:
        """
        公钥编码（非压缩格式：0x04 + x坐标 + y坐标）
        :param pub_key: 公钥坐标
        :return: 编码后的公钥字节串
        """
        x_bytes = pub_key[0].to_bytes(32, 'big')
        y_bytes = pub_key[1].to_bytes(32, 'big')
        return b'\x04' + x_bytes + y_bytes  # 0x04标识非压缩格式

    def encrypt(self, pub_key: tuple, plaintext: str or bytes) -> bytes:
        """
        SM2加密算法
        :param pub_key: 接收方公钥
        :param plaintext: 明文（字符串或字节串）
        :return: 密文（C1 || C3 || C2）
        """
        # 处理明文类型
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        msg_len = len(plaintext)

        # 1. 生成随机数k ∈ [1, n-1]
        k = random.randint(1, self.order - 1)

        # 2. 计算C1 = k*G（椭圆曲线点）
        c1_point = self._ec_scalar_mul(k, self.base_point)
        c1_bytes = self.encode_public_key(c1_point)

        # 3. 计算S = k*P（对方公钥），若S为无穷远点则加密失败
        s_point = self._ec_scalar_mul(k, pub_key)
        if s_point == self.infinity:
            raise ValueError("加密失败：计算S时得到无穷远点")

        # 4. 计算Z = encode(S)，并派生密钥t = KDF(Z, msg_len)
        z_bytes = self.encode_public_key(s_point)
        t_bytes = self._key_derive(z_bytes, msg_len)

        # 检查派生密钥是否全为0（概率极低，按标准要求处理）
        if all(b == 0 for b in t_bytes):
            raise ValueError("KDF派生密钥全为0，加密失败")

        # 5. 计算C2 = M ⊕ t（异或运算）
        c2_bytes = bytes([m_byte ^ t_byte for m_byte, t_byte in zip(plaintext, t_bytes)])

        # 6. 计算C3 = Hash(M || Z)
        c3_bytes = self._hash_func(plaintext + z_bytes)

        # 密文格式：C1 || C3 || C2
        return c1_bytes + c3_bytes + c2_bytes

    def decrypt(self, priv_key: int, ciphertext: bytes) -> bytes:
        """
        SM2解密算法
        :param priv_key: 解密方私钥
        :param ciphertext: 密文（C1 || C3 || C2）
        :return: 解密后的明文
        """
        # 验证密文格式（首字节应为0x04，标识非压缩点）
        if len(ciphertext) < 97 or ciphertext[0] != 0x04:
            raise ValueError("密文格式错误，无法解密")

        # 解析密文各部分
        c1_x = int.from_bytes(ciphertext[1:33], 'big')  # C1的x坐标（32字节）
        c1_y = int.from_bytes(ciphertext[33:65], 'big')  # C1的y坐标（32字节）
        c1_point = (c1_x, c1_y)
        c3_bytes = ciphertext[65:97]  # C3（32字节哈希值）
        c2_bytes = ciphertext[97:]  # C2（明文加密部分）
        msg_len = len(c2_bytes)

        # 1. 计算S = d*C1（用私钥解密C1）
        s_point = self._ec_scalar_mul(priv_key, c1_point)
        if s_point == self.infinity:
            raise ValueError("解密失败：计算S时得到无穷远点")

        # 2. 计算Z = encode(S)，派生密钥t = KDF(Z, msg_len)
        z_bytes = self.encode_public_key(s_point)
        t_bytes = self._key_derive(z_bytes, msg_len)

        # 检查派生密钥是否全为0
        if all(b == 0 for b in t_bytes):
            raise ValueError("KDF派生密钥全为0，解密失败")

        # 3. 计算明文M = C2 ⊕ t
        plaintext = bytes([c_byte ^ t_byte for c_byte, t_byte in zip(c2_bytes, t_bytes)])

        # 4. 验证哈希值C3 = Hash(M || Z)
        u_hash = self._hash_func(plaintext + z_bytes)
        if u_hash != c3_bytes:
            raise ValueError("解密验证失败：哈希值不匹配，密文可能被篡改")

        return plaintext


if __name__ == "__main__":
    # 初始化SM2加密器
    sm2_crypto = SM2Crypto()

    # 待加密消息
    test_message = "WZJ20040402"
    print(f"原始消息: {test_message}")

    # 生成密钥对
    start_gen = time.time()
    private_key, public_key = sm2_crypto.generate_key_pair()
    gen_time = (time.time() - start_gen) * 1000
    print(f"密钥对生成耗时: {gen_time:.2f} ms")
    print(f"私钥: 0x{private_key:064x}")
    print(f"公钥: 0x{binascii.hexlify(sm2_crypto.encode_public_key(public_key)).decode()}")

    # 执行加密
    start_enc = time.time()
    cipher_data = sm2_crypto.encrypt(public_key, test_message)
    enc_time = (time.time() - start_enc) * 1000
    print(f"加密耗时: {enc_time:.2f} ms")
    print(f"密文长度: {len(cipher_data)} 字节")
    print(f"密文(HEX): {binascii.hexlify(cipher_data).decode()[:64]}...")  # 只显示前64字符

    # 执行解密
    start_dec = time.time()
    decrypted_data = sm2_crypto.decrypt(private_key, cipher_data)
    dec_time = (time.time() - start_dec) * 1000
    print(f"解密耗时: {dec_time:.2f} ms")
    print(f"解密结果: {decrypted_data.decode('utf-8')}")