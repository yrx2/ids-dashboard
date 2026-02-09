#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API数据生成器 - 为前后端开发准备测试数据
"""

import json
import os
from datetime import datetime, timedelta
import random

class APIDataGenerator:
    """生成符合API格式的测试数据"""
    
    @staticmethod
    def generate_alerts_data(count=50):
        """生成攻击日志列表数据（对应GET /api/alerts）"""
        alerts = []
        
        attack_types = ["SQL Injection", "Port Scan", "DDoS", "XSS", "Brute Force", "Malware"]
        protocols = ["TCP", "UDP", "HTTP", "HTTPS"]
        
        for i in range(count):
            # 生成随机时间（最近24小时内）
            hours_ago = random.randint(0, 24)
            minutes_ago = random.randint(0, 60)
            timestamp = datetime.now() - timedelta(hours=hours_ago, minutes=minutes_ago)
            
            alert = {
                "id": i + 1,
                "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "source_port": random.randint(1024, 65535),
                "destination_ip": "192.168.1.1",  # 假设被保护服务器
                "destination_port": random.choice([80, 443, 22, 3389]),
                "protocol": random.choice(protocols),
                "alert_type": random.choice(attack_types),
                "severity": random.choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
                "classification": "Web Attack" if random.random() > 0.5 else "Network Scan",
                "rule_id": f"1:{1000000 + i}:1",
                "packet_info": "Sample packet information for testing",
                "action_taken": random.choice(["ALERT", "BLOCK", "PASS"])
            }
            alerts.append(alert)
        
        return alerts
    
    @staticmethod
    def generate_stats_data():
        """生成统计数据（对应GET /api/stats）"""
        return {
            "total_alerts": 156,
            "last_24h_alerts": 42,
            "severity_distribution": {
                "CRITICAL": 45,
                "HIGH": 35,
                "MEDIUM": 50,
                "LOW": 26
            },
            "attack_type_distribution": {
                "SQL Injection": 30,
                "Port Scan": 45,
                "DDoS": 25,
                "XSS": 20,
                "Brute Force": 15,
                "Malware": 10,
                "Other": 11
            },
            "top_source_ips": [
                {"ip": "10.0.23.45", "count": 28, "country": "CN", "threat_level": "HIGH"},
                {"ip": "192.168.100.1", "count": 22, "country": "US", "threat_level": "CRITICAL"},
                {"ip": "172.16.0.123", "count": 18, "country": "RU", "threat_level": "MEDIUM"}
            ],
            "recent_activity": {
                "last_hour": 8,
                "last_6h": 24,
                "last_24h": 42
            },
            "system_status": {
                "ids_status": "active",
                "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "uptime_days": 15
            }
        }
    
    @staticmethod
    def generate_realtime_alert():
        """生成实时攻击数据（对应WebSocket推送）"""
        attack_types = ["SQL Injection", "Port Scan", "DDoS", "Brute Force"]
        severities = ["CRITICAL", "HIGH", "MEDIUM"]
        
        return {
            "id": random.randint(1000, 9999),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "alert_type": random.choice(attack_types),
            "severity": random.choice(severities),
            "destination_port": random.choice([80, 443, 22]),
            "message": f"检测到{random.choice(attack_types)}攻击",
            "is_realtime": True
        }

def main():
    """主函数 - 生成所有API测试数据"""
    print(" 生成API测试数据...")
    
    # 创建数据目录
    os.makedirs('../data/api_test', exist_ok=True)
    
    # 1. 生成攻击日志数据
    print("1. 生成攻击日志列表数据...")
    alerts_data = APIDataGenerator.generate_alerts_data(100)
    alerts_file = '../data/api_test/alerts.json'
    
    with open(alerts_file, 'w', encoding='utf-8') as f:
        json.dump({
            "status": "success",
            "data": {
                "alerts": alerts_data[:20],  # 第一页20条
                "pagination": {
                    "page": 1,
                    "limit": 20,
                    "total": len(alerts_data),
                    "pages": 5
                }
            }
        }, f, indent=2, ensure_ascii=False)
    
    print(f"    已生成到: {alerts_file}")
    print(f"   包含 {len(alerts_data)} 条攻击记录，分页展示")
    
    # 2. 生成统计数据
    print("\n2. 生成统计数据...")
    stats_data = APIDataGenerator.generate_stats_data()
    stats_file = '../data/api_test/stats.json'
    
    with open(stats_file, 'w', encoding='utf-8') as f:
        json.dump({
            "status": "success",
            "data": stats_data
        }, f, indent=2, ensure_ascii=False)
    
    print(f"    已生成到: {stats_file}")
    print(f"   包含总览、分布、TOP IP等统计信息")
    
    # 3. 生成实时数据示例
    print("\n3. 生成实时数据示例...")
    realtime_data = [APIDataGenerator.generate_realtime_alert() for _ in range(5)]
    realtime_file = '../data/api_test/realtime_examples.json'
    
    with open(realtime_file, 'w', encoding='utf-8') as f:
        json.dump({
            "status": "success",
            "data": realtime_data
        }, f, indent=2, ensure_ascii=False)
    
    print(f"    已生成到: {realtime_file}")
    print(f"   包含5条实时攻击示例")
    
    # 4. 生成完整API响应示例（给成员A参考）
    print("\n4. 生成完整API文档示例...")
    api_examples = {
        "alerts_endpoint": {
            "method": "GET",
            "url": "/api/alerts",
            "query_params": {
                "page": "页码 (默认: 1)",
                "limit": "每页数量 (默认: 20)",
                "severity": "过滤严重程度",
                "start_time": "开始时间"
            },
            "response_example": {
                "status": "success",
                "data": {
                    "alerts": "攻击列表数组",
                    "pagination": "分页信息"
                }
            }
        },
        "stats_endpoint": {
            "method": "GET",
            "url": "/api/stats",
            "response_example": {
                "status": "success",
                "data": "统计数据对象"
            }
        }
    }
    
    api_doc_file = '../data/api_test/api_examples.json'
    with open(api_doc_file, 'w', encoding='utf-8') as f:
        json.dump(api_examples, f, indent=2, ensure_ascii=False)
    
    print(f"    已生成到: {api_doc_file}")
    print(f"   API接口说明文档")
    
    print("\n" + "=" * 50)
    print(" API测试数据生成完成！")
    print("=" * 50)
    print("\n 生成的文件:")
    print(f"   {alerts_file}")
    print(f"   {stats_file}")
    print(f"   {realtime_file}")
    print(f"   {api_doc_file}")
    print("\n 给队友的说明:")
    print("  1. 成员A（后端）: 可参考api_examples.json实现API")
    print("  2. 成员B（前端）: 可使用这些JSON文件进行前端开发")
    print("  3. 所有数据格式已标准化，前后端可并行开发")

if __name__ == "__main__":
    main()
