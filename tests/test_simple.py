# -*- coding: utf-8 -*-
"""测试数据生成器"""
import json
import os

print("开始测试数据生成器...")

# 测试1：检查数据文件是否存在
print("1. 检查数据文件...")
data_files = ["data/parsed_logs.json", "data/raw_snort_alerts.log"]

all_exist = True
for file in data_files:
    if os.path.exists(file):
        size = os.path.getsize(file)
        print(f"    {file}: 存在 ({size} 字节)")
    else:
        print(f"    {file}: 不存在")
        all_exist = False

# 测试2：验证JSON格式
print("\n2. 验证JSON数据格式...")
if os.path.exists("data/parsed_logs.json"):
    try:
        with open("data/parsed_logs.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        
        if isinstance(data, list):
            print(f"    JSON是列表，包含 {len(data)} 条记录")
            if len(data) > 0:
                first = data[0]
                print(f"    第一条数据字段: {list(first.keys())[:5]}...")
        else:
            print("    JSON不是列表格式")
            
    except Exception as e:
        print(f"    JSON解析错误: {e}")
else:
    print("     parsed_logs.json不存在")

# 测试3：检查攻击类型分布
print("\n3. 检查攻击类型...")
if os.path.exists("data/parsed_logs.json"):
    try:
        with open("data/parsed_logs.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        
        attack_types = {}
        for item in data:
            atype = item.get("alert_type", "Unknown")
            attack_types[atype] = attack_types.get(atype, 0) + 1
        
        print(f"   攻击类型分布:")
        for atype, count in attack_types.items():
            print(f"     - {atype}: {count} 条")
            
    except:
        print("     无法分析攻击类型")

print("\n" + "="*50)
if all_exist:
    print(" 基本测试通过！")
else:
    print("  部分测试失败，请检查数据生成")
