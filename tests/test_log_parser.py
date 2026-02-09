#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试Snort日志解析器"""

import sys
import os
import json
import unittest

# 添加scripts目录到Python路径
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from parse_snort_logs import SnortLogParser

class TestSnortParser(unittest.TestCase):
    """Snort解析器测试类"""
    
    def test_parse_sql_injection(self):
        """测试SQL注入日志解析"""
        test_log = '''[**] [1:1000001:1] SQL Injection Attempt [**]
[Classification: Web Application Attack] [Priority: 1]
02/04-10:30:25.123456 192.168.1.100:54321 -> 10.0.0.1:80
TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:150'''
        
        result = SnortLogParser.parse_line(test_log)
        
        self.assertIsNotNone(result, "应成功解析SQL注入日志")
        self.assertEqual(result['alert_type'], 'SQL Injection Attempt')
        self.assertEqual(result['severity'], 'CRITICAL')
        self.assertEqual(result['source_ip'], '192.168.1.100')
        self.assertEqual(result['rule_id'], '1:1000001:1')
        print(" SQL注入测试通过")
    
    def test_parse_port_scan(self):
        """测试端口扫描日志解析"""
        test_log = '''[**] [1:2000001:1] Port Scan Detected [**]
[Classification: Attempted Information Leak] [Priority: 3]
02/04-11:45:30.654321 10.0.1.50:55555 -> 192.168.1.1:443
TCP TTL:128 TOS:0x0 ID:22222 IpLen:20 DgmLen:150'''
        
        result = SnortLogParser.parse_line(test_log)
        
        self.assertIsNotNone(result, "应成功解析端口扫描日志")
        self.assertEqual(result['alert_type'], 'Port Scan Detected')
        self.assertEqual(result['severity'], 'MEDIUM')
        self.assertEqual(result['destination_port'], 443)
        print(" 端口扫描测试通过")
    
    def test_parse_invalid_log(self):
        """测试无效日志处理"""
        invalid_log = "This is not a valid Snort log format"
        result = SnortLogParser.parse_line(invalid_log)
        
        # 无效日志应该返回None或空字典
        self.assertIsNotNone(result)  # 我们的解析器会返回默认值
        self.assertEqual(result['alert_type'], 'Unknown Alert')
        print(" 无效日志测试通过")
    
    def test_parse_file_exists(self):
        """测试解析器能处理现有文件"""
        data_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
        input_file = os.path.join(data_dir, 'raw_snort_alerts.log')
        output_file = os.path.join(data_dir, 'test_output.json')
        
        # 确保输入文件存在
        if os.path.exists(input_file):
            logs = SnortLogParser.parse_file(input_file, output_file)
            self.assertGreater(len(logs), 0, "应解析出至少一条日志")
            
            # 清理测试文件
            if os.path.exists(output_file):
                os.remove(output_file)
            
            print(" 文件解析测试通过")
        else:
            print("  跳过文件测试（数据文件不存在）")
    
    def test_severity_mapping(self):
        """测试严重程度映射"""
        test_cases = [
            (1, "CRITICAL"),
            (2, "HIGH"),
            (3, "MEDIUM"),
            (4, "LOW"),
            (5, "MEDIUM")  # 默认值
        ]
        
        for priority, expected_severity in test_cases:
            test_log = f'''[**] [1:1000001:1] Test Alert [**]
[Classification: Test] [Priority: {priority}]
02/04-12:00:00.000000 10.0.0.1:1111 -> 192.168.1.1:80
TCP'''
            
            result = SnortLogParser.parse_line(test_log)
            self.assertEqual(result['severity'], expected_severity)
        
        print(" 严重程度映射测试通过")

def run_tests():
    """运行所有测试"""
    print("=" * 50)
    print("开始运行Snort解析器测试")
    print("=" * 50)
    
    # 创建测试套件
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestSnortParser)
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("=" * 50)
    print("测试完成")
    print(f"总测试数: {result.testsRun}")
    print(f"失败数: {len(result.failures)}")
    print(f"错误数: {len(result.errors)}")
    print("=" * 50)
    
    return len(result.failures) == 0 and len(result.errors) == 0

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
