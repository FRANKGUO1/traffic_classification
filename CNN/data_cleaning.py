import dpkt
import socket
import time
from datetime import datetime
import csv
import os

def analyze_raw_ip_pcap(pcap_file, target_ip, source_port=None, protocol='tcp', app_name='myapp', data_type='filtered', debug=False):
    """
    分析Raw IP类型的pcap文件，提取指定目的IP、源端口和协议的五元组信息，并写入CSV
    参数:
        pcap_file: pcap文件路径
        target_ip: 目标IP地址
        source_port: 指定源端口号（可选）
        protocol: 传输层协议(tcp/udp), 默认tcp
        app_name: 应用名称，用于生成CSV文件名
        data_type: 数据类型，用于生成CSV文件名
    """
    # 开始计时
    start_time = time.time()
    
    # 生成CSV文件名
    csv_filename = f"{app_name}_{data_type}.csv"
    
    # 初始化结果存储
    packet_info = []
    packet_count = 0
    
    # 转换为IP地址的字节形式
    target_ip_bytes = socket.inet_aton(target_ip)
    protocol_num = 6 if protocol.lower() == 'tcp' else 17  # TCP=6, UDP=17
    
    print(f"正在打开Raw IP pcap文件: {pcap_file}")
    print(f"目标IP: {target_ip}, 源端口: {source_port if source_port is not None else '未指定'}, 协议: {protocol}")
    
    # 打开并解析pcap文件
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        # 验证链路层类型（可选，用于调试）
        linktype = pcap.datalink()
        print(f"链路层类型: {linktype} (1=Ethernet, 12/101=Raw IP)")
        # ip_packets = 0
        
        # 逐包处理
        for timestamp, buf in pcap:
            try:
                if linktype == dpkt.pcap.DLT_EN10MB:  # Ethernet类型 (值为1)
                    eth = dpkt.ethernet.Ethernet(buf)
                    eth_type_raw = int.from_bytes(buf[12:14], byteorder='big')
                    if debug:
                        print(f"eth.type: {eth.type}, raw eth type: {eth_type_raw}")
                    
                    if eth_type_raw != dpkt.ethernet.ETH_TYPE_IP:
                        if debug:
                            print(f"跳过非IPv4包，raw eth.type: {eth_type_raw}")
                        continue
                    ip = eth.data
                    # ip_packets += 1
                elif linktype in (dpkt.pcap.DLT_RAW, 101):  # Raw IP类型
                    ip = dpkt.ip.IP(buf)
                else:
                    print(f"不支持的链路层类型: {linktype}")
                    return
                
                # 直接解析IP层（Raw IP）
                # ip = dpkt.ip.IP(buf)
                
                # 检查协议和目的IP
                if ip.p == protocol_num and ip.dst == target_ip_bytes:
                    # 获取传输层数据
                    trans = ip.data
                    
                    # 如果指定了源端口，则过滤
                    if source_port is not None and trans.sport != source_port:
                        continue
                    
                    # 提取五元组
                    five_tuple = (
                        socket.inet_ntoa(ip.src),  # 源IP
                        socket.inet_ntoa(ip.dst),  # 目的IP
                        trans.sport,              # 源端口
                        trans.dport,              # 目的端口
                        protocol.upper()          # 协议
                    )
                    
                    # 获取包大小和时间戳
                    packet_size = len(buf)
                    # readable_timestamp = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')
                    
                    # 存储结果
                    packet_info.append({
                        'five_tuple': five_tuple,
                        'size': packet_size,
                        'timestamp': timestamp  # 整数部分为s，小数部分为微秒
                    }) 
                    packet_count += 1
                    
            except Exception as e:
                # 跳过解析错误的包
                continue
    
    # 计算处理时间
    end_time = time.time()
    process_time = end_time - start_time
    
    # 写入CSV文件（追加模式）
    file_exists = os.path.isfile(csv_filename)
    with open(csv_filename, 'a', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['Source_IP', 'Destination_IP', 'Source_Port', 'Destination_Port', 
                      'Protocol', 'Packet_Size', 'Timestamp']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        # 如果文件不存在，写入表头
        if not file_exists:
            writer.writeheader()
        
        # 写入数据
        for info in packet_info:
            writer.writerow({
                'Source_IP': info['five_tuple'][0],
                'Destination_IP': info['five_tuple'][1],
                'Source_Port': info['five_tuple'][2],
                'Destination_Port': info['five_tuple'][3],
                'Protocol': info['five_tuple'][4],
                'Packet_Size': info['size'],
                'Timestamp': info['timestamp']
            })
    
    print(f"\n分析完成！匹配的数据包数量: {packet_count}")
    print(f"处理耗时: {process_time:.2f} 秒")
    print(f"数据已写入文件: {csv_filename}")
    
    # 打印前5个匹配数据包
    print("\n前5个匹配数据包的信息:")
    for info in packet_info[:3]:
        print(f"五元组: {info['five_tuple']}")
        print(f"包大小: {info['size']} bytes")
        print(f"时间戳: {info['timestamp']}")
        print("---")
    
    return packet_info

# 使用示例
if __name__ == "__main__":
    # 参数设置
    pcap_file_path = '/home/sinet/gzc/traffic_classification/dataset/NonVPN-PCAPs-01/facebook_audio2a.pcap'   # pcap文件路径
    target_ip_addr = "131.202.240.150"     # 替换为目标IP
    source_port_num = None          # 指定源端口号（可选，设为None则不过滤）
    protocol_type = "udp"              # 可改为"udp"
    application_name = "novpnfacebook"       # 自定义应用名
    data_type_name = "audio"         # 自定义类型名
    
    # 执行分析
    results = analyze_raw_ip_pcap(
        pcap_file_path,
        target_ip_addr,
        source_port=source_port_num,
        protocol=protocol_type,
        app_name=application_name,
        data_type=data_type_name,
        # debug=False
    )
