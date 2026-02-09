# -*- coding: utf-8 -*-
import json
import os

print("测试数据文件...")

# 使用正确的相对路径
base_path = os.path.join(os.path.dirname(__file__), "..")
data_path = os.path.join(base_path, "data")

print(f"数据目录: {data_path}")

# 列出所有数据文件
print("\n数据文件列表:")
for file in os.listdir(data_path):
    full_path = os.path.join(data_path, file)
    if os.path.isfile(full_path):
        size = os.path.getsize(full_path)
        print(f"  {file}: {size} 字节")
    elif os.path.isdir(full_path):
        print(f"  [{file}/] (目录)")

# 如果有JSON文件，显示内容
json_files = [f for f in os.listdir(data_path) if f.endswith('.json')]
if json_files:
    print(f"\n找到 {len(json_files)} 个JSON文件:")
    for json_file in json_files:
        try:
            with open(os.path.join(data_path, json_file), 'r', encoding='utf-8') as f:
                data = json.load(f)
            print(f"  {json_file}: {len(data)} 条记录")
        except Exception as e:
            print(f"  {json_file}: 读取错误 - {e}")
else:
    print("\n未找到JSON文件")
