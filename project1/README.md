# SM4密码算法原理介绍及代码结果展示

## 一、SM4密码算法数学原理

SM4是一种中国国家密码算法，主要用于分组密码加密，采用128位分组长度和128位密钥，支持32轮迭代的迭代分组密码结构。其设计目标是高效安全，适合硬件和软件实现。

### 1. 基本结构

SM4采用**32轮迭代结构**，每轮通过非线性变换和线性变换实现混淆与扩散。

- 输入：128位明文分为4个32位字（X0, X1, X2, X3）
- 密钥：128位分为4个32位字（MK0, MK1, MK2, MK3）
- 输出：128位密文（X35, X34, X33, X32）

每轮迭代核心操作定义为：

X_{i+4} = X_i ⊕ F(X_{i+1}, X_{i+2}, X_{i+3}, RK_i)

其中，轮函数 \(F\) 由非线性和线性变换组成，\(RK_i\) 是轮密钥。

### 2. 非线性变换 — S盒变换

SM4使用一个8x8的S盒，将32位输入拆成4个字节，逐字节通过S盒替换。S盒是一个固定的非线性替换表，用于实现混淆。

设输入字节为 \(b\)，S盒变换为：

S(b) = Sbox[b]

该过程为字节级别的非线性映射，防止线性和差分攻击。

### 3. 线性变换

非线性变换后，进行线性变换 \(L\)：

L(B) = B ⊕ (B <<< 2) ⊕ (B <<< 10) ⊕ (B <<< 18) ⊕ (B <<< 24)

其中`<<<` 表示循环左移。该变换增加比特扩散效果，使输入比特快速影响输出。

### 4. 轮函数组合

综合非线性和线性变换，轮函数：

F(X1, X2, X3, RK) = L( τ(X1 ⊕ X2 ⊕ X3 ⊕ RK) )

其中 \(\tau\) 表示S盒变换。

---

## 二、T-Table的数学原理及优化

### 1. T-Table概念

T-Table是一种**查表优化技术**，主要用于加快加密算法中非线性和线性变换的组合计算。其原理是将S盒变换与线性变换合并成一个表，减少运行时计算。

### 2. SM4中T-Table的构造

SM4轮函数中：

\[
F(X_1, X_2, X_3, RK) = L(\tau(X_1 \oplus X_2 \oplus X_3 \oplus RK))
\]

其中：

- \(\tau\) 对32位分为4个字节，分别进行S盒替换
- \(L\) 线性变换依赖于字节间的组合移位

将两步合成一个表，就是T-Table。

具体做法：

- 对所有可能的字节值 \(b \in [0, 255]\)，计算：

\[
T[b] = L(S(b) \ll 24)
\]

这里左移24位是将字节放到32位中的最高位，后续通过旋转得到其他字节位置的对应T值。

- 因为输入是4个字节，整体轮函数可以拆解为4个字节对应4个不同的T-Table：

T0[b] = L( S(b) << 24 )
T1[b] = ROTL(T0[b], 8)
T2[b] = ROTL(T0[b], 16)
T3[b] = ROTL(T0[b], 24)

### 3. 优化后的轮函数计算

有了4个T-Table，轮函数可以用查表和按位异或替代复杂的S盒与线性变换：

F = T0[b0] ⊕ T1[b1] ⊕ T2[b2] ⊕ T3[b3]

其中 b0, b1, b2, b3 是输入的4个字节。

这样避免了运行时循环移位和多次S盒查表，提高了计算效率。


### 4. 结果对比
#### BASE：
<img width="400" height="133" alt="result" src="https://github.com/MY0495/SDU_Summer_innovation_and_entrepreneurship_practice/blob/main/project1/SM4base.png" />
#### T-table：
<img width="400" height="133" alt="result" src="https://github.com/MY0495/SDU_Summer_innovation_and_entrepreneurship_practice/blob/main/project1/SM4table.png" />
#### SIMD：
<img width="400" height="133" alt="result" src="https://github.com/MY0495/SDU_Summer_innovation_and_entrepreneurship_practice/blob/main/project1/SM4SIMD.png" />


