#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于LSB隐写术的数字水印系统
基于数字水印的图片泄露检测作业 - 第二份作业
"""

import cv2
import numpy as np
import os
import json
from datetime import datetime


class LSBWatermarkSystem:
    """基于LSB隐写术的数字水印系统"""
    
    def __init__(self, bit_depth=2):
        """
        初始化LSB水印系统
        
        Args:
            bit_depth (int): 使用的最低有效位数，默认为2位
        """
        self.bit_depth = bit_depth
        self.test_results = {}
        self.original_watermark = None
        self.embedded_image_path = None
        
    def _text_to_binary(self, text):
        """将文本转换为二进制字符串"""
        binary = ''.join(format(ord(char), '08b') for char in text)
        return binary
    
    def _binary_to_text(self, binary):
        """将二进制字符串转换为文本"""
        if len(binary) % 8 != 0:
            binary = binary[:-(len(binary) % 8)]
        
        text = ''
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            if len(byte) == 8:
                char_code = int(byte, 2)
                if 32 <= char_code <= 126:
                    text += chr(char_code)
        return text
    
    def embed_watermark(self, image_path, watermark_content, output_path, watermark_type="text"):
        """嵌入水印"""
        try:
            img = cv2.imread(image_path)
            if img is None:
                return {'status': 'error', 'message': f'无法读取图像: {image_path}'}
            
            if watermark_type == "text":
                watermark_binary = self._text_to_binary(watermark_content)
                watermark_length = len(watermark_binary)
                
                # 添加长度信息（32位）
                length_binary = format(watermark_length, '032b')
                full_binary = length_binary + watermark_binary
                
                # 嵌入水印
                embedded_img = self._embed_binary_lsb(img, full_binary)
                
            elif watermark_type == "image":
                # 图像水印处理
                return {'status': 'error', 'message': '图像水印功能待实现'}
            
            # 保存嵌入水印的图像
            cv2.imwrite(output_path, embedded_img)
            self.embedded_image_path = output_path
            self.original_watermark = watermark_content
            
            return {
                'status': 'success',
                'message': '文本水印嵌入成功',
                'watermark_size': watermark_length,
                'watermark_length': watermark_length
            }
                
        except Exception as e:
            return {'status': 'error', 'message': f'水印嵌入失败: {str(e)}'}
    
    def _embed_binary_lsb(self, img, binary):
        """使用LSB方法嵌入二进制数据"""
        embedded_img = img.copy()
        binary_index = 0
        
        for i in range(img.shape[0]):
            for j in range(img.shape[1]):
                for k in range(img.shape[2]):
                    if binary_index < len(binary):
                        embedded_img[i, j, k] = (img[i, j, k] >> self.bit_depth) << self.bit_depth
                        embedded_img[i, j, k] |= int(binary[binary_index:binary_index+self.bit_depth], 2)
                        binary_index += self.bit_depth
                    else:
                        break
                if binary_index >= len(binary):
                    break
            if binary_index >= len(binary):
                break
        
        return embedded_img
    
    def extract_watermark(self, image_path, watermark_shape, watermark_type="text", output_path=None):
        """提取水印"""
        try:
            img = cv2.imread(image_path)
            if img is None:
                return {'status': 'error', 'message': f'无法读取图像: {image_path}'}
            
            if watermark_type == "text":
                extracted_binary = self._extract_binary_lsb(img)
                
                # 提取长度信息（前32位）
                length_binary = extracted_binary[:32]
                watermark_length = int(length_binary, 2)
                
                # 提取水印内容
                watermark_binary = extracted_binary[32:32+watermark_length]
                extracted_text = self._binary_to_text(watermark_binary)
                
                return {
                    'status': 'success',
                    'message': '文本水印提取成功',
                    'extracted_watermark': extracted_text,
                    'watermark_length': watermark_length
                }
                
        except Exception as e:
            return {'status': 'error', 'message': f'水印提取失败: {str(e)}'}
    
    def _extract_binary_lsb(self, img):
        """从图像中提取二进制数据"""
        binary = ""
        
        for i in range(img.shape[0]):
            for j in range(img.shape[1]):
                for k in range(img.shape[2]):
                    pixel_value = img[i, j, k]
                    bits = format(pixel_value & ((1 << self.bit_depth) - 1), f'0{self.bit_depth}b')
                    binary += bits
        
        return binary
    
    def apply_attack(self, image_path, attack_type, output_path, **params):
        """应用攻击"""
        try:
            img = cv2.imread(image_path)
            if img is None:
                return {'status': 'error', 'message': f'无法读取图像: {image_path}'}
            
            attacked_img = None
            
            if attack_type == "rotation":
                angle = params.get('angle', 30)
                height, width = img.shape[:2]
                center = (width // 2, height // 2)
                matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
                attacked_img = cv2.warpAffine(img, matrix, (width, height))
                
            elif attack_type == "scaling":
                scale = params.get('scale', 0.8)
                height, width = img.shape[:2]
                new_height, new_width = int(height * scale), int(width * scale)
                attacked_img = cv2.resize(img, (new_width, new_height))
                attacked_img = cv2.resize(attacked_img, (width, height))
                
            elif attack_type == "brightness":
                factor = params.get('factor', 1.5)
                attacked_img = cv2.convertScaleAbs(img, alpha=factor, beta=0)
                
            elif attack_type == "noise":
                noise = np.random.normal(0, 25, img.shape).astype(np.uint8)
                attacked_img = cv2.add(img, noise)
                
            elif attack_type == "blur":
                kernel_size = params.get('kernel_size', 5)
                attacked_img = cv2.GaussianBlur(img, (kernel_size, kernel_size), 0)
                
            if attacked_img is not None:
                cv2.imwrite(output_path, attacked_img)
                return {
                    'status': 'success',
                    'message': f'{attack_type}攻击应用成功',
                    'attack_type': attack_type,
                    'output_path': output_path
                }
            else:
                return {'status': 'error', 'message': f'{attack_type}攻击失败'}
                
        except Exception as e:
            return {'status': 'error', 'message': f'攻击应用失败: {str(e)}'}
    
    def test_robustness(self, image_path, watermark_shape, watermark_type="text"):
        """测试鲁棒性"""
        print("开始鲁棒性测试...")
        
        os.makedirs("output/attacks", exist_ok=True)
        
        attacks = [
            ("rotation", {"angle": 15}),
            ("rotation", {"angle": 30}),
            ("scaling", {"scale": 0.8}),
            ("scaling", {"scale": 1.2}),
            ("brightness", {"factor": 1.3}),
            ("brightness", {"factor": 0.8}),
            ("noise", {}),
            ("blur", {"kernel_size": 3}),
            ("blur", {"kernel_size": 5})
        ]
        
        test_results = {}
        
        for i, (attack_type, params) in enumerate(attacks):
            print(f"测试攻击 {i+1}/{len(attacks)}: {attack_type}")
            
            attack_output = f"output/attacks/attacked_{attack_type}_{i}.png"
            attack_result = self.apply_attack(image_path, attack_type, attack_output, **params)
            
            if attack_result['status'] == 'success':
                extract_result = self.extract_watermark(
                    attack_output, watermark_shape, watermark_type
                )
                
                if extract_result['status'] == 'success':
                    similarity = self._calculate_text_similarity(
                        self.original_watermark, 
                        extract_result['extracted_watermark']
                    )
                    
                    test_results[f"{attack_type}_{i}"] = {
                        'attack_type': attack_type,
                        'params': params,
                        'status': 'success',
                        'similarity': similarity,
                        'extracted_watermark': extract_result['extracted_watermark'],
                        'attack_output': attack_output
                    }
                else:
                    test_results[f"{attack_type}_{i}"] = {
                        'attack_type': attack_type,
                        'params': params,
                        'status': 'extraction_failed',
                        'error': extract_result['message']
                    }
            else:
                test_results[f"{attack_type}_{i}"] = {
                    'attack_type': attack_type,
                    'params': params,
                    'status': 'attack_failed',
                    'error': attack_result['message']
                }
        
        self.test_results = test_results
        return test_results
    
    def _calculate_text_similarity(self, original, extracted):
        """计算文本相似度"""
        if not original or not extracted:
            return 0.0
        
        def levenshtein_distance(s1, s2):
            if len(s1) < len(s2):
                return levenshtein_distance(s2, s1)
            
            if len(s2) == 0:
                return len(s1)
            
            previous_row = list(range(len(s2) + 1))
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            
            return previous_row[-1]
        
        distance = levenshtein_distance(original, extracted)
        max_len = max(len(original), len(extracted))
        similarity = 1.0 - (distance / max_len) if max_len > 0 else 0.0
        
        return max(0.0, similarity)
    
    def detect_leakage(self, original_image_path, suspected_image_path, watermark_shape, watermark_type="text"):
        """检测图像泄露"""
        try:
            original_extract = self.extract_watermark(
                original_image_path, watermark_shape, watermark_type
            )
            
            if original_extract['status'] != 'success':
                return {
                    'status': 'error',
                    'message': '无法从原始图像提取水印',
                    'confidence': 0.0
                }
            
            suspected_extract = self.extract_watermark(
                suspected_image_path, watermark_shape, watermark_type
            )
            
            if suspected_extract['status'] != 'success':
                return {
                    'status': 'success',
                    'message': '未检测到水印，图像可能被篡改或不是同一来源',
                    'confidence': 0.0,
                    'similarity': 0.0
                }
            
            similarity = self._calculate_text_similarity(
                original_extract['extracted_watermark'],
                suspected_extract['extracted_watermark']
            )
            
            threshold = 0.7
            is_same_source = similarity >= threshold
            
            if is_same_source:
                message = f"检测到水印匹配，相似度: {similarity:.3f}，图像可能来自同一来源"
                confidence = similarity
            else:
                message = f"水印不匹配，相似度: {similarity:.3f}，图像可能被篡改或不是同一来源"
                confidence = 1.0 - similarity
            
            return {
                'status': 'success',
                'message': message,
                'is_same_source': is_same_source,
                'similarity': similarity,
                'confidence': confidence,
                'threshold': threshold
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'泄露检测失败: {str(e)}',
                'confidence': 0.0
            }
    
    def save_results(self, output_path):
        """保存测试结果到JSON文件"""
        try:
            serializable_results = self._convert_to_serializable(self.test_results)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(serializable_results, f, ensure_ascii=False, indent=2)
            
            return {'status': 'success', 'message': f'结果已保存到: {output_path}'}
        except Exception as e:
            return {'status': 'error', 'message': f'保存失败: {str(e)}'}
    
    def generate_report(self, output_path):
        """生成测试报告"""
        try:
            report = []
            report.append("基于LSB隐写术的数字水印系统 - 鲁棒性测试报告")
            report.append("=" * 60)
            report.append(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            report.append(f"LSB位数: {self.bit_depth}")
            report.append("")
            
            if not self.test_results:
                report.append("暂无测试结果")
            else:
                successful_attacks = 0
                total_similarity = 0.0
                
                for attack_name, result in self.test_results.items():
                    if result['status'] == 'success':
                        successful_attacks += 1
                        total_similarity += result['similarity']
                
                report.append("测试统计:")
                report.append(f"  总攻击数: {len(self.test_results)}")
                report.append(f"  成功攻击: {successful_attacks}")
                report.append(f"  平均相似度: {total_similarity/successful_attacks:.3f}" if successful_attacks > 0 else "  平均相似度: N/A")
                report.append("")
                
                for attack_name, result in self.test_results.items():
                    report.append(f"攻击: {attack_name}")
                    if result['status'] == 'success':
                        report.append(f"  相似度: {result['similarity']:.3f}")
                    else:
                        report.append(f"  状态: {result['status']}")
                        report.append(f"  错误: {result.get('error', 'N/A')}")
                    report.append("")
            
            report_text = "\n".join(report)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report_text)
            
            return {'status': 'success', 'message': f'报告已生成: {output_path}'}
            
        except Exception as e:
            return {'status': 'error', 'message': f'报告生成失败: {str(e)}'}
    
    def _convert_to_serializable(self, obj):
        """转换对象为可JSON序列化的格式"""
        if isinstance(obj, dict):
            return {key: self._convert_to_serializable(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_to_serializable(item) for item in obj]
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        else:
            return obj
