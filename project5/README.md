# SM2椭圆曲线密码算法Python实现与优化
## 项目介绍
本项目提供了国密SM2椭圆曲线公钥密码算法的Python实现，并针对算法性能进行了优化。同时，项目还包含了对SM2签名算法误用的安全风险验证(POC)以及中本聪数字签名伪造的演示。

## 目录结构
```
├── project5_base.py       # SM2基础实现
├── project5_optimized.py  # SM2优化实现
├── POC.py                 # 签名算法误用POC验
证
├── Satoshi_signature.py   # 中本聪签名伪造演
示
└── README.md              # 项目说明文档
```
## SM2基础与优化实现
### 基础实现 (project5_base.py)
实现了SM2算法的基本功能，包括密钥对生成、加密/解密、椭圆曲线点运算等，遵循GB/T 32918.1-2016标准。

### 优化实现 (project5_optimized.py)
引入多种优化技术提升性能：

- 雅可比坐标：避免频繁模逆运算
- 预计算技术：针对固定点预计算倍数表
- 窗口法：加速点乘运算
- 蒙哥马利阶梯法：增强安全性，抵抗侧信道攻击

### 运行结果：
<img width="400" height="133" alt="result" src="https://github.com/MY0495/SDU_Summer_innovation_and_entrepreneurship_practice/blob/main/project5/base.png" />
<img width="400" height="133" alt="result" src="https://github.com/MY0495/SDU_Summer_innovation_and_entrepreneurship_practice/blob/main/project5/optimized.png" />

## SM2签名算法误用POC验证
### 场景1：泄露临时密钥k导致私钥泄露 数学推导
SM2签名公式为：
$$s = (k - r \cdot d) \cdot (1 + d)^{-1} \mod n$$

其中：

- $d$ 为私钥
- $k$ 为临时密钥
- $r = (e + x_1) \mod n$，$x_1$ 是 $kG$ 的x坐标
- $e$ 为消息哈希值
如果$k$泄露，可重写公式求解$d$：
$$s \cdot (1 + d) = k - r \cdot d \mod n$$
$$s + s \cdot d + r \cdot d = k \mod n$$
$$d \cdot (s + r) = k - s \mod n$$
$$d = (k - s) \cdot (s + r)^{-1} \mod n$$

#### 验证代码
```
# 从k和签名推导私钥
denominator = (s + r) % self.n
if denominator == 0:
    return False
d_derived = (k - s) * pow(denominator, -1, 
self.n) % self.n
```
### 场景2：重用临时密钥k导致私钥泄露 数学推导
对两个不同消息$m_1$和$m_2$使用相同$k$签名，得到$(r_1, s_1)$和$(r_2, s_2)$。

对于消息$m_1$：
$$s_1 = (k - r_1 \cdot d) \cdot (1 + d)^{-1} \mod n$$

对于消息$m_2$：
$$s_2 = (k - r_2 \cdot d) \cdot (1 + d)^{-1} \mod n$$

两式相减：
$$s_1 - s_2 = (r_2 \cdot d - r_1 \cdot d) \cdot (1 + d)^{-1} \mod n$$
$$(s_1 - s_2) \cdot (1 + d) = d \cdot (r_2 - r_1) \mod n$$
$$s_1 - s_2 + d(s_1 - s_2) = d(r_2 - r_1) \mod n$$
$$s_1 - s_2 = d(r_2 - r_1 - s_1 + s_2) \mod n$$
$$d = (s_1 - s_2) \cdot (r_2 - r_1 - s_1 + s_2)^{-1} \mod n$$

####  验证代码
```
# 从两个签名推导私钥
numerator = (s1 - s2) % self.n
denominator = (r2 - r1 - (s1 - s2)) % self.n
if denominator == 0:
    return False
d_derived = numerator * pow(denominator, 
-1, self.n) % self.n
```
### 场景3：不同用户重用相同k导致私钥泄露 数学推导
用户A和用户B使用相同的临时密钥$k$，分别用私钥$d_A$和$d_B$签名，得到$(r_A, s_A)$和$(r_B, s_B)$。

对于用户B：
$$s_B = (k - r_B \cdot d_B) \cdot (1 + d_B)^{-1} \mod n$$

已知$k$和$(r_B, s_B)$，可按场景1的方法推导$d_B$：
$$d_B = (k - s_B) \cdot (s_B + r_B)^{-1} \mod n$$

####  验证代码
```
# 用户A推导用户B的私钥
denominator = (sB + rB) % self.n
if denominator == 0:
    return False
d_derived = (k - sB) * pow(denominator, -1, 
self.n) % self.n
```
### 场景4：ECDSA与Schnorr共用(d,k)导致私钥泄露 数学推导
ECDSA签名公式：
$$s_{ecdsa} = k^{-1} \cdot (e_{ecdsa} + d \cdot r) \mod n$$

Schnorr签名公式：
$$s_{schnorr} = k + e_{schnorr} \cdot d \mod n$$

从ECDSA解出$k$：
$$k = (e_{ecdsa} + d \cdot r) \cdot s_{ecdsa}^{-1} \mod n$$

代入Schnorr公式：
$$s_{schnorr} = (e_{ecdsa} + d \cdot r) \cdot s_{ecdsa}^{-1} + e_{schnorr} \cdot d \mod n$$

整理求解$d$：
$$s_{schnorr} \cdot s_{ecdsa} = e_{ecdsa} + d \cdot r + e_{schnorr} \cdot d \cdot s_{ecdsa} \mod n$$
$$d \cdot (r + e_{schnorr} \cdot s_{ecdsa}) = s_{schnorr} \cdot s_{ecdsa} - e_{ecdsa} \mod n$$
$$d = (s_{schnorr} \cdot s_{ecdsa} - e_{ecdsa}) \cdot (r + e_{schnorr} \cdot s_{ecdsa})^{-1} \mod n$$
####  验证代码
```
# 从两个签名推导私钥
numerator = (s_schnorr * s_ecdsa - e_ecdsa) 
% n
denominator = (r + e_schnorr * s_ecdsa) % n
if denominator == 0:
    return False
d_derived = (numerator * pow(denominator, 
-1, n)) % n
```
### 运行结果：
<img width="400" height="133" alt="result" src="https://github.com/MY0495/SDU_Summer_innovation_and_entrepreneurship_practice/blob/main/project5/POC.png" />

## 中本聪数字签名伪造
### 数学原理
ECDSA签名验证公式为：
$$r = (u_1 G + u_2 Q)_x \mod n$$
其中：

- $u_1 = e \cdot s^{-1} \mod n$
- $u_2 = r \cdot s^{-1} \mod n$
- $Q$ 为公钥
伪造签名时，随机选择$u$和$v$，计算：
$$R = uG + vQ$$
$$r = R_x \mod n$$
$$s = r \cdot v^{-1} \mod n$$
$$e = u \cdot r \cdot v^{-1} \mod n$$

则$(r, s)$是对哈希值$e$的有效签名。

#### 验证代码
```
# 伪造签名
def forge_signature(self, Q):
    u = random.randint(1, self.curve.n - 1)
    v = random.randint(1, self.curve.n - 1)

    P1 = self.curve.scalar_mult(u, self.
    curve.G)
    P2 = self.curve.scalar_mult(v, Q)
    R = self.curve.point_add(P1, P2)

    r = R[0] % self.curve.n
    v_inv = pow(v, self.curve.n - 2, self.
    curve.n)
    s = r * v_inv % self.curve.n
    e = u * r * v_inv % self.curve.n

    return e, (r, s)
```
### 运行结果：
<img width="400" height="133" alt="result" src="https://github.com/MY0495/SDU_Summer_innovation_and_entrepreneurship_practice/blob/main/project5/Satoshi.png" />

## 安全警示
1.
   必须确保每个签名使用不同的随机临时密钥k
2.
   绝不能泄露临时密钥k
3.
   不同算法和不同用户之间不应共享临时密钥k
4.
   应使用经过充分验证的密码库，而非自行实现的密码算法
## 技术文档
- GB/T 32918.1-2016 信息安全技术 SM2椭圆曲线公钥密码算法 第1部分：总则
- 20250713-wen-sm2-public.pdf 
