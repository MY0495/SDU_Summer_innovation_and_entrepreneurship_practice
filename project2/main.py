#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于LSB隐写术的数字水印系统 - 主演示程序
基于数字水印的图片泄露检测作业 - 第二份作业
"""

import os
import cv2
from lsb_watermark_system import LSBWatermarkSystem


def main():
    """主函数 - 运行完整的作业演示"""
    print("=" * 60)
    print("基于LSB隐写术的数字水印系统 - 作业演示")
    print("=" * 60)
    
    # 创建输出目录
    os.makedirs("output", exist_ok=True)
    
    # 初始化系统（使用2位LSB）
    system = LSBWatermarkSystem(bit_depth=2)
    
    # 水印内容
    watermark_text = "学号: 2024002 姓名: 李四 课程: 信息隐藏技术 实验日期: 2024年"
    
    try:
        # 步骤1: 水印嵌入
        print("\n📝 步骤1: 嵌入文本水印")
        print("-" * 40)
        
        # ===== 在这里修改您的图片路径 =====
        # 方式1: 使用相对路径（推荐）
        original_image = "wzj.jpg"  # 将 your_image.jpg 改为您的图片文件名
        
        # 方式2: 使用绝对路径
        # original_image = "C:/Users/YourName/Pictures/your_image.png"
        
        # 方式3: 使用项目内的图片
        # original_image = "./images/your_image.bmp"
        
        # 方式4: 使用原始示例图片（如果存在）
        # original_image = "../blind_watermark-master/examples/pic/ori_img.jpeg"
        # ==========================================
        
        # 检查是否有原始图像
        if not os.path.exists(original_image):
            print(f"❌ 未找到原始图像: {original_image}")
            print("请按以下步骤操作：")
            print("1. 将您的图片文件复制到当前目录")
            print("2. 修改上面代码中的 'your_image.jpg' 为您的实际文件名")
            print("3. 或者使用绝对路径指向您的图片位置")
            print("\n支持的图片格式：JPG, PNG, BMP, TIFF 等")
            return
        
        embed_result = system.embed_watermark(
            image_path=original_image,
            watermark_content=watermark_text,
            output_path="output/embedded_lsb.png",
            watermark_type="text"
        )
        
        if embed_result['status'] == 'success':
            print("✅ 文本水印嵌入成功！")
            print(f"水印大小: {embed_result['watermark_size']} bits")
            watermark_length = embed_result['watermark_length']
        else:
            print(f"❌ 文本水印嵌入失败: {embed_result['message']}")
            return
        
        # 步骤2: 水印提取
        print("\n🔍 步骤2: 提取文本水印")
        print("-" * 40)
        
        extract_result = system.extract_watermark(
            image_path="output/embedded_lsb.png",
            watermark_shape=watermark_length,
            watermark_type="text"
        )
        
        if extract_result['status'] == 'success':
            print("✅ 文本水印提取成功！")
            print(f"提取的水印内容: {extract_result['extracted_watermark']}")
            
            # 验证水印是否正确
            if extract_result['extracted_watermark'] == watermark_text:
                print("✅ 水印内容完全匹配！")
            else:
                print("⚠️  水印内容不完全匹配，但提取成功")
        else:
            print(f"❌ 文本水印提取失败: {extract_result['message']}")
            return
        
        # 步骤3: 鲁棒性测试
        print("\n🧪 步骤3: 鲁棒性测试")
        print("-" * 40)
        print("测试的攻击类型包括：")
        print("  - 几何攻击：旋转、缩放")
        print("  - 信号处理攻击：亮度调整、噪声添加")
        print("  - 滤波攻击：高斯模糊")
        print("  - LSB隐写术的特点：对微小变化敏感")
        
        test_results = system.test_robustness(
            image_path="output/embedded_lsb.png",
            watermark_shape=watermark_length,
            watermark_type="text"
        )
        
        print(f"\n✅ 鲁棒性测试完成！共测试了 {len(test_results)} 种攻击")
        
        # 步骤4: 泄露检测演示
        print("\n🕵️  步骤4: 泄露检测演示")
        print("-" * 40)
        
        # 创建一个可疑图像（通过旋转攻击）
        print("创建可疑图像（通过旋转攻击）...")
        original_img = cv2.imread("output/embedded_lsb.png")
        h, w = original_img.shape[:2]
        
        # 应用旋转攻击
        angle = 30
        center = (w // 2, h // 2)
        matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
        suspicious_img = cv2.warpAffine(original_img, matrix, (w, h))
        
        # 保存可疑图像
        suspicious_image_path = "output/suspicious_lsb.png"
        cv2.imwrite(suspicious_image_path, suspicious_img)
        print(f"可疑图像已保存到: {suspicious_image_path}")
        
        # 进行泄露检测
        print("开始泄露检测...")
        leakage_result = system.detect_leakage(
            original_image_path="output/embedded_lsb.png",
            suspected_image_path=suspicious_image_path,
            watermark_shape=watermark_length,
            watermark_type="text"
        )
        
        print(f"泄露检测结果: {leakage_result['message']}")
        if 'similarity' in leakage_result:
            print(f"水印相似度: {leakage_result['similarity']:.3f}")
        print(f"置信度: {leakage_result['confidence']}")
        
        # 步骤5: 保存结果和报告
        print("\n💾 步骤5: 保存结果和报告")
        print("-" * 40)
        
        # 保存测试结果
        system.save_results("output/lsb_test_results.json")
        
        # 生成测试报告
        system.generate_report("output/lsb_test_report.txt")
        
        # 生成作业报告
        generate_homework_report(watermark_text)
        
        print("\n" + "=" * 60)
        print("🎉 所有演示完成！")
        print("=" * 60)
        print("输出文件位置：")
        print("- 嵌入水印的图像: output/embedded_lsb.png")
        print("- 攻击后的图像: output/attacks/attacked_*.png")
        print("- 可疑图像: output/suspicious_lsb.png")
        print("- 测试结果: output/lsb_test_results.json")
        print("- 测试报告: output/lsb_test_report.txt")
        print("- 作业报告: output/lsb_homework_report.txt")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ 演示过程中出现错误: {str(e)}")
        import traceback
        traceback.print_exc()


def generate_homework_report(watermark_text):
    """生成作业报告"""
    from datetime import datetime
    
    report = []
    report.append("基于LSB隐写术的数字水印系统 - 作业报告")
    report.append("=" * 60)
    report.append(f"作者: [您的姓名]")
    report.append(f"学号: [您的学号]")
    report.append(f"课程: [课程名称]")
    report.append(f"日期: {datetime.now().strftime('%Y年%m月%d日')}")
    report.append("")
    
    report.append("一、实验目的")
    report.append("1. 理解LSB隐写术的基本原理和应用")
    report.append("2. 掌握基于LSB的数字水印嵌入和提取技术")
    report.append("3. 学习LSB隐写术的鲁棒性测试方法")
    report.append("4. 实现基于LSB隐写术的图片泄露检测系统")
    report.append("")
    
    report.append("二、实验原理")
    report.append("本实验基于LSB（最低有效位）隐写术实现数字水印：")
    report.append("1. LSB隐写术：利用图像像素值的最低有效位存储隐藏信息")
    report.append("2. 水印嵌入：将水印信息转换为二进制，嵌入到像素的LSB中")
    report.append("3. 水印提取：从像素的LSB中提取二进制信息，重建水印")
    report.append("4. 容量计算：每个像素可嵌入 bit_depth 位信息")
    report.append("5. 鲁棒性：LSB隐写术对图像处理攻击较为敏感")
    report.append("")
    
    report.append("三、实验内容")
    report.append("1. 水印嵌入：将文本水印嵌入到原始图像中")
    report.append("2. 水印提取：从嵌入水印的图像中提取水印信息")
    report.append("3. 鲁棒性测试：测试水印对抗各种攻击的能力")
    report.append("4. 泄露检测：通过水印验证图像是否被篡改或泄露")
    report.append("")
    
    report.append("四、鲁棒性测试")
    report.append("测试的攻击类型包括：")
    report.append("1. 几何攻击：旋转、缩放")
    report.append("2. 信号处理攻击：亮度调整、噪声添加")
    report.append("3. 滤波攻击：高斯模糊")
    report.append("4. LSB特点：对微小变化敏感，适合检测图像篡改")
    report.append("")
    
    report.append("五、实验结果")
    report.append("1. 成功实现了基于LSB的文本水印嵌入与提取")
    report.append("2. 完成了LSB隐写术的鲁棒性测试")
    report.append("3. 实现了基于LSB的泄露检测功能")
    report.append("4. 生成了详细的测试报告和可视化结果")
    report.append("")
    
    report.append("六、实验总结")
    report.append("1. 通过本实验深入理解了LSB隐写术的原理和应用")
    report.append("2. 掌握了LSB数字水印的实现方法")
    report.append("3. 学会了如何进行LSB隐写术的鲁棒性测试")
    report.append("4. 理解了LSB隐写术的优缺点和适用场景")
    report.append("")
    
    report.append("七、技术特点")
    report.append("1. LSB隐写术优点：实现简单、容量大、不可见性好")
    report.append("2. LSB隐写术缺点：鲁棒性较差、对图像处理敏感")
    report.append("3. 适用场景：图像完整性验证、信息隐藏、版权保护")
    report.append("4. 与DWT-DCT-SVD的区别：时域vs频域、简单vs复杂")
    report.append("")
    
    report.append("八、参考文献")
    report.append("1. LSB隐写术相关文献")
    report.append("2. 数字水印技术相关论文")
    report.append("3. 信息隐藏技术教材")
    report.append("")
    
    report.append("=" * 60)
    
    report_text = "\n".join(report)
    
    # 保存报告
    report_file = "output/lsb_homework_report.txt"
    os.makedirs("output", exist_ok=True)
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report_text)
    
    print(f"作业报告已保存到: {report_file}")
    return report_text


if __name__ == "__main__":
    main()
