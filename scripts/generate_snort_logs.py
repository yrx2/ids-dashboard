#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Snort日志数据生成器 - 完整版
生成多种格式的Snort模拟数据
"""

import json
import random
from datetime import datetime, timedelta
import os

# 确保data目录存在
if not os.path.exists('../data'):
    os.makedirs('../data')
if not os.path.exists('../data/attack_scenarios'):
    os.makedirs('../data/attack_scenarios')

print("=" * 50)
print("Snort数据生成器 - 完整版")
print("=" * 50)

# ==================== 1. 生成基础测试数据 ====================
print("\n1. 生成基础测试数据...")
base_data = []
for i in range(20):
    base_data.append({
        "id": i,
        "timestamp": (datetime.now() - timedelta(hours=random.randint(0, 72))).isoformat(),
        "source_ip": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "destination_ip": "192.168.1.100",
        "alert_type": random.choice(["Port Scan", "SQL Injection", "DDoS", "XSS"]),
        "severity": random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
        "protocol": random.choice(["TCP", "UDP", "ICMP"])
    })

with open('../data/sample_logs.json', 'w', encoding='utf-8') as f:
    json.dump(base_data, f, indent=2, ensure_ascii=False)
print("✅ 已生成 20 条基础数据到 data/sample_logs.json")

# ==================== 2. 生成原始Snort格式日志 ====================
print("\n2. 生成原始Snort格式日志...")
raw_logs = []
for i in range(15):
    timestamp = (datetime.now() - timedelta(minutes=random.randint(0, 10080))).strftime("%m/%d-%H:%M:%S.%f")[:23]
    src_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"
    dst_port = random.choice([80, 443, 22, 3389])
    
    alert = f"""[**] [1:{1000000+i}:1] TEST ALERT {i} [**]
[Classification: Test Classification] [Priority: {random.randint(1, 3)}]
{timestamp} {src_ip}:{random.randint(1024, 65535)} -> 192.168.1.100:{dst_port}
TCP TTL:64 TOS:0x0 ID:{random.randint(1000, 9999)} IpLen:20 DgmLen:150
"""
    raw_logs.append(alert)

with open('../data/raw_snort_alerts.log', 'w', encoding='utf-8') as f:
    f.write("\n".join(raw_logs))
print("✅ 已生成 15 条原始Snort日志到 data/raw_snort_alerts.log")

# ==================== 3. 生成结构化详细数据 ====================
print("\n3. 生成结构化详细数据...")
detailed_logs = []
attack_types = [
    {"name": "SQL Injection", "priority": 1, "port": 80},
    {"name": "XSS Attack", "priority": 1, "port": 443},
    {"name": "Port Scan", "priority": 3, "port": 22},
    {"name": "DDoS Attack", "priority": 1, "port": 80},
    {"name": "Brute Force", "priority": 2, "port": 3389},
    {"name": "Malware Download", "priority": 1, "port": 443}
]

for i in range(50):
    attack = random.choice(attack_types)
    severity_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}
    
    detailed_logs.append({
        "id": i,
        "timestamp": (datetime.now() - timedelta(minutes=random.randint(0, 10080))).strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": f"{random.randint(1, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "destination_ip": "192.168.1.100",
        "destination_port": attack["port"],
        "protocol": random.choice(["TCP", "UDP"]),
        "alert_type": attack["name"],
        "severity": severity_map.get(attack["priority"], "LOW"),
        "priority": attack["priority"],
        "classification": "Web Application Attack" if attack["priority"] == 1 else "Network Attack",
        "description": f"{attack['name']} attempt detected",
        "action": random.choice(["ALERT", "BLOCK", "PASS"]),
        "bytes": random.randint(100, 5000),
        "packets": random.randint(1, 10)
    })

with open('../data/parsed_logs.json', 'w', encoding='utf-8') as f:
    json.dump(detailed_logs, f, indent=2, ensure_ascii=False)
print("✅ 已生成 50 条详细数据到 data/parsed_logs.json")

# ==================== 4. 生成攻击场景数据 ====================
print("\n4. 生成攻击场景数据...")

# 4.1 端口扫描场景
print("  - 生成端口扫描场景...")
port_scan = []
attacker_ip = "10.0.99.99"
base_time = datetime.now() - timedelta(hours=1)

for port in [22, 80, 443, 3389, 8080, 21, 25, 53]:
    port_scan.append({
        "timestamp": (base_time + timedelta(seconds=random.randint(1, 10))).strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": attacker_ip,
        "destination_ip": "192.168.1.100",
        "destination_port": port,
        "alert_type": "Port Scan",
        "severity": "MEDIUM",
        "description": f"Port scan attempt on port {port}"
    })

with open('../data/attack_scenarios/port_scan.json', 'w', encoding='utf-8') as f:
    json.dump(port_scan, f, indent=2, ensure_ascii=False)

# 4.2 DDoS攻击场景
print("  - 生成DDoS攻击场景...")
ddos_attack = []
start_time = datetime.now() - timedelta(minutes=30)

for i in range(20):
    ddos_attack.append({
        "timestamp": (start_time + timedelta(seconds=i*2)).strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "destination_ip": "192.168.1.100",
        "destination_port": 80,
        "alert_type": "DDoS Attack",
        "severity": "CRITICAL",
        "description": f"DDoS flood packet {i+1}"
    })

with open('../data/attack_scenarios/ddos_attack.json', 'w', encoding='utf-8') as f:
    json.dump(ddos_attack, f, indent=2, ensure_ascii=False)

# 4.3 SQL注入场景
print("  - 生成SQL注入场景...")
sql_injection = []
for i in range(5):
    sql_injection.append({
        "timestamp": (datetime.now() - timedelta(minutes=random.randint(1, 60))).strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "destination_ip": "192.168.1.100",
        "destination_port": 80,
        "alert_type": "SQL Injection",
        "severity": "HIGH",
        "description": f"SQL injection attempt with payload: SELECT * FROM users WHERE 1=1",
        "payload": "SELECT * FROM users WHERE 1=1 OR '1'='1'"
    })

with open('../data/attack_scenarios/sql_injection.json', 'w', encoding='utf-8') as f:
    json.dump(sql_injection, f, indent=2, ensure_ascii=False)

# ==================== 5. 生成统计信息 ====================
print("\n5. 生成统计信息文件...")
stats = {
    "generated_at": datetime.now().isoformat(),
    "total_records": len(base_data) + len(detailed_logs),
    "file_summary": {
        "sample_logs.json": len(base_data),
        "raw_snort_alerts.log": len(raw_logs),
        "parsed_logs.json": len(detailed_logs),
        "attack_scenarios": {
            "port_scan.json": len(port_scan),
            "ddos_attack.json": len(ddos_attack),
            "sql_injection.json": len(sql_injection)
        }
    },
    "severity_distribution": {
        "CRITICAL": sum(1 for log in detailed_logs if log["severity"] == "CRITICAL"),
        "HIGH": sum(1 for log in detailed_logs if log["severity"] == "HIGH"),
        "MEDIUM": sum(1 for log in detailed_logs if log["severity"] == "MEDIUM"),
        "LOW": sum(1 for log in detailed_logs if log["severity"] == "LOW")
    }
}

with open('../data/data_statistics.json', 'w', encoding='utf-8') as f:
    json.dump(stats, f, indent=2, ensure_ascii=False)

print("\n" + "=" * 50)
print("🎉 数据生成完成！")
print("=" * 50)
print("\n📁 生成的文件:")
print("  ✅ data/sample_logs.json          - 20条基础数据")
print("  ✅ data/raw_snort_alerts.log      - 15条原始Snort日志")
print("  ✅ data/parsed_logs.json          - 50条详细数据")
print("  ✅ data/attack_scenarios/port_scan.json")
print("  ✅ data/attack_scenarios/ddos_attack.json")
print("  ✅ data/attack_scenarios/sql_injection.json")
print("  ✅ data/data_statistics.json      - 数据统计信息")
print("\n📊 数据统计:")
print(f"  总记录数: {stats['total_records']}")
print(f"  严重程度分布: {stats['severity_distribution']}")