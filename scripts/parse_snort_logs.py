#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Snort日志解析器 
功能：解析原始Snort日志并转换为结构化JSON数据
"""

import re
import json
import os
from datetime import datetime

class SnortLogParser:
    """Snort日志解析器类"""
    
    @staticmethod
    def parse_line(log_text):
        """解析单条Snort日志条目"""
        if not log_text.strip():
            return None
        
        result = {
            "id": 0,
            "timestamp": "",
            "source_ip": "0.0.0.0",
            "source_port": 0,
            "destination_ip": "0.0.0.0",
            "destination_port": 0,
            "protocol": "TCP",
            "alert_type": "Unknown Alert",
            "classification": "Unknown",
            "severity": "MEDIUM",
            "rule_id": "0:0:0",
            "raw_summary": ""
        }
        
        lines = log_text.strip().split('\n')
        
        # 解析规则头 [**] [GID:SID:REV] Description [**]
        if len(lines) > 0:
            header_match = re.search(r'\[\*\*\] \[(\d+):(\d+):(\d+)\] (.+) \[\*\*\]', lines[0])
            if header_match:
                result["rule_id"] = f"{header_match.group(1)}:{header_match.group(2)}:{header_match.group(3)}"
                result["alert_type"] = header_match.group(4)
                result["raw_summary"] = header_match.group(4)[:100]  # 截取前100字符
        
        # 解析分类和优先级 [Classification: ...] [Priority: ...]
        if len(lines) > 1:
            class_match = re.search(r'\[Classification: (.+?)\]', lines[1])
            priority_match = re.search(r'\[Priority: (\d+)\]', lines[1])
            
            if class_match:
                result["classification"] = class_match.group(1)
            
            if priority_match:
                priority = int(priority_match.group(1))
                # 优先级映射到严重程度
                severity_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
                result["severity"] = severity_map.get(priority, "MEDIUM")
        
        # 解析网络流信息: timestamp src_ip:src_port -> dst_ip:dst_port
        if len(lines) > 2:
            flow_match = re.search(
                r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+' +
                r'(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+' +
                r'(\d+\.\d+\.\d+\.\d+):(\d+)',
                lines[2]
            )
            
            if flow_match:
                # 转换时间格式
                timestamp_str = flow_match.group(1)
                current_year = datetime.now().year
                try:
                    dt = datetime.strptime(f"{current_year}-{timestamp_str}", "%Y-%m/%d-%H:%M:%S.%f")
                    result["timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    result["timestamp"] = timestamp_str
                
                result["source_ip"] = flow_match.group(2)
                result["source_port"] = int(flow_match.group(3))
                result["destination_ip"] = flow_match.group(4)
                result["destination_port"] = int(flow_match.group(5))
        
        # 解析协议（可能在第三或第四行）
        for i in range(2, min(4, len(lines))):
            protocol_match = re.search(r'^(TCP|UDP|ICMP|HTTP|HTTPS|FTP|SSH|DNS)', lines[i])
            if protocol_match:
                result["protocol"] = protocol_match.group(1)
                break
        
        return result
    
    @staticmethod
    def parse_file(input_path, output_path):
        """批量解析日志文件"""
        print(f" 开始解析文件: {input_path}")
        
        if not os.path.exists(input_path):
            print(f" 错误: 文件不存在 - {input_path}")
            return []
        
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f" 读取文件失败: {e}")
            return []
        
        # 按空行分割日志条目
        log_entries = [entry.strip() for entry in content.strip().split('\n\n') if entry.strip()]
        parsed_logs = []
        
        print(f" 找到 {len(log_entries)} 条日志条目")
        
        for i, entry in enumerate(log_entries):
            parsed = SnortLogParser.parse_line(entry)
            if parsed:
                parsed["id"] = i + 1
                parsed_logs.append(parsed)
            
            # 显示进度
            if (i + 1) % 10 == 0:
                print(f"  已解析 {i + 1}/{len(log_entries)} 条...")
        
        print(f" 成功解析 {len(parsed_logs)} 条日志")
        
        # 保存结果
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(parsed_logs, f, indent=2, ensure_ascii=False)
            
            print(f" 结果已保存到: {output_path}")
            
            # 显示统计信息
            if parsed_logs:
                severity_count = {}
                alert_type_count = {}
                
                for log in parsed_logs:
                    sev = log.get("severity", "UNKNOWN")
                    alert = log.get("alert_type", "UNKNOWN")
                    
                    severity_count[sev] = severity_count.get(sev, 0) + 1
                    alert_type_count[alert] = alert_type_count.get(alert, 0) + 1
                
                print("\n 统计信息:")
                print("  严重程度分布:")
                for sev, count in severity_count.items():
                    print(f"    {sev}: {count} 条")
                
                print("\n  攻击类型分布 (前5):")
                sorted_alerts = sorted(alert_type_count.items(), key=lambda x: x[1], reverse=True)
                for alert, count in sorted_alerts[:5]:
                    print(f"    {alert}: {count} 条")
            
        except Exception as e:
            print(f" 保存文件失败: {e}")
        
        return parsed_logs

def main():
    """主函数 - 测试和演示"""
    print("=" * 50)
    print("Snort日志解析器 v1.0 ")
    print("=" * 50)
    
    # 获取路径
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    data_dir = os.path.join(project_root, 'data')
    
    # 测试单条日志解析
    print("\n 测试单条日志解析:")
    test_log = '''[**] [1:1000001:1] SQL Injection Attempt [**]
[Classification: Web Application Attack] [Priority: 1]
02/04-10:30:25.123456 192.168.1.100:54321 -> 10.0.0.1:80
TCP TTL:64 TOS:0x0 ID:12345 IpLen:20 DgmLen:150'''
    
    test_result = SnortLogParser.parse_line(test_log)
    if test_result:
        print(" 单条日志解析成功:")
        print(json.dumps(test_result, indent=2, ensure_ascii=False))
    else:
        print(" 单条日志解析失败")
    
    # 测试文件解析
    print("\n 测试文件批量解析:")
    
    input_file = os.path.join(data_dir, 'raw_snort_alerts.log')
    output_file = os.path.join(data_dir, 'parsed_by_parser.json')
    
    if os.path.exists(input_file):
        print(f"  输入文件: {input_file}")
        print(f"  输出文件: {output_file}")
        
        # 解析文件
        logs = SnortLogParser.parse_file(input_file, output_file)
        
        if logs:
            print(f"\n 解析完成! 共 {len(logs)} 条日志")
            print(f"   第一条日志示例:")
            print(f"   时间: {logs[0].get('timestamp', 'N/A')}")
            print(f"   攻击: {logs[0].get('alert_type', 'N/A')}")
            print(f"   严重: {logs[0].get('severity', 'N/A')}")
    else:
        print(f"  输入文件不存在: {input_file}")
        print("   请先运行 generate_snort_logs.py 生成数据")
    
    print("\n" + "=" * 50)
    print(" 解析器测试完成")
    print("=" * 50)

if __name__ == "__main__":
    main()
