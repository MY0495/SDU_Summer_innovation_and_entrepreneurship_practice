# LSB隐写术数字水印系统

## 一、原理概述
LSB（Least Significant Bit）隐写术利用人类视觉系统对图像最低有效位不敏感的特性，在像素值的最低位嵌入水印信息。每个像素的RGB通道由8位表示，修改最后几位对视觉效果影响甚微。

### 核心算法实现步骤：
1. **水印嵌入过程**
   - 将文本水印编码为二进制比特流
   - 遍历图像像素，依次替换每个颜色通道的LSB位（位数由bit_depth控制）
   - 像素值修改公式：`modified_pixel = (original_pixel & mask) | watermark_bits`
     - 其中mask用于清除原始LSB位（如bit_depth=2时，mask=0b11111100）

2. **水印提取过程**
   - 从含水印图像中按相同顺序读取LSB位
   - 组合提取的二进制数据流
   - 根据文本编码规则解码为字符串

3. **鲁棒性增强机制**
   - 水印数据分散存储在全图像素中
   - 添加校验信息辅助受损水印恢复
   - 使用编辑距离算法处理部分损坏的水印

## 二、模块实现详解

### 1. 水印嵌入模块
```python
def embed_watermark(self, image_path, watermark, output_path):
    img = cv2.imread(image_path)  # 读取原始图像
    watermark_bin = self._text_to_binary(watermark)  # 文本转二进制
    
    # 计算最大容量并校验
    max_bits = img.shape[0] * img.shape[1] * 3 * self.bit_depth
    if len(watermark_bin) > max_bits:
        raise ValueError("水印超过最大容量")
    
    # 创建掩码 (如bit_depth=2: 0b11111100)
    mask = 0xFF << self.bit_depth
    
    # 嵌入水印核心逻辑
    bit_index = 0
    for row in img:
        for pixel in row:
            for channel in range(3):  # 处理BGR三个通道
                if bit_index < len(watermark_bin):
                    # 清除原始LSB位后嵌入新数据
                    bits = watermark_bin[bit_index:bit_index+self.bit_depth]
                    pixel[channel] = (pixel[channel] & mask) | int(bits, 2)
                    bit_index += self.bit_depth
    
    cv2.imwrite(output_path, img)  # 保存含水印图像
```

### 2. 水印提取模块
```
python
def extract_watermark(self, image_path):
    img = cv2.imread(image_path)
    extracted_bits = []
    bit_mask = (1 << self.bit_depth) - 1  # 创建位掩码
    
    for row in img:
        for pixel in row:
            for channel in range(3):
                # 提取LSB位
                lsb_bits = pixel[channel] & bit_mask
                extracted_bits.append(f"{lsb_bits:0{self.bit_depth}b}")
    
    # 二进制转文本
    return self._binary_to_text(''.join(extracted_bits))
```
### 3. 攻击模拟模块
```
python
def apply_attack(self, image_path, attack_type, **params):
    img = cv2.imread(image_path)
    
    if attack_type == "rotation":
        angle = params.get("angle", 15)
        M = cv2.getRotationMatrix2D((img.shape[1]/2, img.shape[0]/2), angle, 1)
        return cv2.warpAffine(img, M, (img.shape[1], img.shape[0]))
    
    elif attack_type == "scaling":
        scale = params.get("scale", 0.8)
        return cv2.resize(img, None, fx=scale, fy=scale)
 ```   
    # 其他攻击实现类似...
### 4. 鲁棒性评估算法
```
python
def test_robustness(self, orig_img, attacked_img, orig_watermark):
    extracted = self.extract_watermark(attacked_img)
    
    # 计算编辑距离相似度
    distance = Levenshtein.distance(orig_watermark, extracted)
    max_len = max(len(orig_watermark), len(extracted))
    similarity = 1 - distance / max_len
    
    return {
        "similarity": similarity,
        "extracted": extracted,
        "is_recovered": similarity > 0.7  # 设定可恢复阈值
    }
```
## 三、关键技术挑战与解决方案
问题：JPEG压缩会破坏LSB数据

方案：强制使用PNG格式保存含水印图像

实现：在保存时检测文件扩展名，自动转换格式

几何攻击导致水印错位

问题：旋转/缩放后像素位置变化

方案：在图像中心区域嵌入水印

代码实现：
```
python
# 计算中心区域边界
h, w = img.shape[:2]
start_y, end_y = int(h*0.25), int(h*0.75)
start_x, end_x = int(w*0.25), int(w*0.75)
```
水印容量与质量平衡

开发容量计算器：
```
python
def calculate_capacity(self, img):
    pixels = img.shape[0] * img.shape[1]
    return pixels * 3 * self.bit_depth // 8  # 返回字节数
```
自适应bit_depth选择算法：
```
python
def auto_select_depth(self, watermark_len):
    min_depth = 1
    while min_depth <= 4:
        capacity = self.calculate_capacity() 
        if capacity >= watermark_len:
            return min_depth
        min_depth += 1
    raise CapacityError("水印过长")
```
## 四、性能优化策略
向量化处理
```
python
# 传统循环方式（慢）
for row in img:
    for pixel in row:
        ...

# 向量化优化（快10倍）
flat_img = img.reshape(-1, 3)
mask = 0xFF << self.bit_depth
for i in range(len(watermark_bin) // self.bit_depth):
    channel_idx = i % 3
    pixel_idx = i // 3
    # 使用NumPy直接操作数组
```
并行处理
```
python
from concurrent.futures import ThreadPoolExecutor

def parallel_embed(args):
    # 将图像分块并行处理
    with ThreadPoolExecutor() as executor:
        chunks = split_image(img, 4)  # 分为4块
        results = executor.map(embed_chunk, chunks)
```
## 五、安全增强措施
加密水印
```
python
from cryptography.fernet import Fernet

def encrypt_watermark(text, key):
    cipher = Fernet(key)
    return cipher.encrypt(text.encode())
随机嵌入路径

python
# 使用伪随机序列确定嵌入位置
random.seed(key)  # 密钥作为随机种子
positions = [(i, j) for i in range(h) for j in range(w)]
random.shuffle(positions)  # 打乱嵌入顺序
```
## 六、运行结果见附件中output文件夹
