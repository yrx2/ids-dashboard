#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试数据生成器"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import unittest
import json

class TestDataGenerator(unittest.TestCase):

    def test_generator_import(self):
        """测试能否导入生成器"""
        try:
            # 尝试导入模块而不是特定函数
            import generate_snort_logs
            self.assertTrue(hasattr(generate_snort_logs, '__file__'), "应能导入模块")
            print(" 成功导入数据生成器模块")
        except ImportError as e:
            self.fail(f"无法导入generate_snort_logs模块: {e}")

    def test_data_files_exist(self):
        """测试数据文件是否存在"""
        required_files = [
            '../data/parsed_logs.json',
            '../data/raw_snort_alerts.log',
            '../data/sample_logs.json',
            '../data/data_statistics.json'
        ]

        for file_path in required_files:
            self.assertTrue(
                os.path.exists(file_path),
                f"数据文件不存在: {file_path}"
            )
        print(" 所有数据文件都存在")

    def test_json_format(self):
        """测试JSON数据格式"""
        with open('../data/parsed_logs.json', 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.assertIsInstance(data, list, "数据应该是列表")
        self.assertGreater(len(data), 0, "数据应该至少有一条")
        print(f" JSON格式正确，包含 {len(data)} 条数据")

        # 检查第一条数据的结构
        sample = data[0]
        required_fields = ['id', 'timestamp', 'source_ip', 'alert_type', 'severity']

        for field in required_fields:
            self.assertIn(field, sample, f"数据应包含字段: {field}")
        print(" 数据字段结构完整")

    def test_attack_scenarios(self):
        """测试攻击场景数据"""
        scenarios_dir = '../data/attack_scenarios'
        if os.path.exists(scenarios_dir):
            scenario_files = os.listdir(scenarios_dir)
            self.assertGreater(len(scenario_files), 0, "应该有攻击场景文件")
            print(f" 找到 {len(scenario_files)} 个攻击场景文件")

            for file in scenario_files:
                if file.endswith('.json'):
                    with open(os.path.join(scenarios_dir, file), 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    self.assertIsInstance(data, list, f"{file} 应该是列表")
        else:
            self.fail("攻击场景目录不存在")
        print(" 攻击场景数据格式正确")

    def test_statistics(self):
        """测试统计文件"""
        stats_file = '../data/data_statistics.json'
        self.assertTrue(os.path.exists(stats_file), "统计文件应该存在")
        
        with open(stats_file, 'r', encoding='utf-8') as f:
            stats = json.load(f)

        self.assertIn('total_records', stats, "统计应包含总记录数")
        self.assertIn('severity_distribution', stats, "统计应包含严重程度分布")
        
        total = stats['total_records']
        severity = stats['severity_distribution']
        
        print(f" 统计数据完整: 总记录数={total}, 严重程度分布={severity}")


if __name__ == '__main__':
    print("=" * 50)
    print("运行数据生成器测试...")
    print("=" * 50)
    unittest.main(verbosity=2)
