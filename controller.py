import nnpy
import struct
import ipaddress
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import subprocess 
import os
from datetime import datetime
import p4runtime_sh.shell as sh 
from threading import Thread
from google.protobuf.json_format import MessageToDict
import base64
import time
import json

from scapy.all import *

import argparse
import sys
import time
import logging
import google.protobuf.text_format
from google.rpc import status_pb2, code_pb2

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "utils/"))
from utils import bmv2, helper
from utils.switch import ShutdownAllSwitchConnections

from p4.tmp import p4config_pb2
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc

import grpc
import socket


# 获取特征的列表
packet_features = []
# 不处理的特定端口号的数据包
filter_ports = [53, 161, 162, 21, 20, 25, 587, 465, 143, 993, 110, 995]

five_tuple_list = []
flow_dict = {}
pktlist = []


def printGrpcError(e):
    print("gRPC Error:", e.details(), end="")
    status_code = e.code()
    print("(%s)" % status_code.name, end="")
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))


def monitor_pktlist():
    last_processed_index = 0
    while True:
        current_len = len(pktlist)
        if current_len > last_processed_index:
            for i in range(last_processed_index, current_len):
                pkt = pktlist[i]
                # 使用Scapy解析数据包
                response_dict = MessageToDict(pkt)
                decoded_metadata_values = base64.b64decode(response_dict['packet']['payload'])
                packet = Ether(decoded_metadata_values) # type: ignore

                if IP in packet: # type: ignore
                    ip_layer = packet[IP] # type: ignore
                    if UDP in ip_layer: # type: ignore
                        udp_layer = ip_layer[UDP] # type: ignore
                        # 提取五元组
                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        protocol = ip_layer.proto
                        src_port = udp_layer.sport
                        dst_port = udp_layer.dport
                    elif TCP in ip_layer: # type: ignore
                        tcp_layer = ip_layer[TCP] # type: ignore
                        # 提取五元组
                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        protocol = ip_layer.proto
                        src_port = tcp_layer.sport
                        dst_port = tcp_layer.dport
                                
                    if (src_ip, dst_ip, src_port, dst_port, protocol) in five_tuple_list:
                        continue
                    else:
                        # 添加正向流和反向流五元组
                        five_tuple_list.append((src_ip, dst_ip, src_port, dst_port, protocol))
                        five_tuple_list.append((dst_ip, src_ip, dst_port, src_port, protocol))
                else:
                    print("不是IP数据包")

            last_processed_index = current_len
            print(five_tuple_list)
        
            time.sleep(1)  # 每隔1秒检查一次 pktlist


# 监控 five_tuples 列表并处理新增元素的函数
def monitor_five_tuples(sh):
    last_checked_length = 0
    te_check_flow = sh.TableEntry('check_flow')(action='NoAction')
    te_detect_flow = sh.TableEntry('detect_flow')(action='record_flow')
    while True:
        current_length = len(five_tuple_list)
        if current_length > last_checked_length:
            for i in range(last_checked_length, current_length):
                # 下发check_flow流表
                # te_check_flow = sh.TableEntry('check_flow')(action='NoAction')
                te_check_flow.match['hdr.ipv4.src_addr'] = five_tuple_list[i][0]
                te_check_flow.match['hdr.ipv4.dst_addr'] = five_tuple_list[i][1]
                te_check_flow.match['meta.srcport'] = str(five_tuple_list[i][2])
                te_check_flow.match['meta.dstport'] = str(five_tuple_list[i][3])
                te_check_flow.match['hdr.ipv4.protocol'] = str(five_tuple_list[i][4])
                te_check_flow.insert()

                # 开启线程监控five_tuple_list,获取五元组并下发流表
                # te_detect_flow = sh.TableEntry('detect_flow')(action='record_flow')
                te_detect_flow.match['hdr.ipv4.src_addr'] = five_tuple_list[i][0]
                te_detect_flow.match['hdr.ipv4.dst_addr'] = five_tuple_list[i][1]
                te_detect_flow.match['meta.srcport'] = str(five_tuple_list[i][2])
                te_detect_flow.match['meta.dstport'] = str(five_tuple_list[i][3])
                te_detect_flow.match['hdr.ipv4.protocol'] = str(five_tuple_list[i][4])

                te_detect_flow.action['index'] = str(i)
                te_detect_flow.insert()

                # check_flow_sessions = te_check_flow.read()
                # for session in check_flow_sessions:
                #    print(session)
    
            last_checked_length = current_length


def monitor_flow(sh):
    # te_flow = sh.DirectCounterEntry('packets_bytes_counter')
    te_flow = sh.CounterEntry('packets_bytes_counter')
    while True:    
        sessions = te_flow.read()
        for session in sessions:
            print(session.index)
            print("包数：", session.packet_count)
            print("字节数：", session.byte_count)
            if session.index < len(five_tuple_list):
                if five_tuple_list[session.index] in flow_dict:
                    flow_dict[five_tuple_list[session.index]].append((session.packet_count, session.byte_count))
                else:
                    flow_dict[five_tuple_list[session.index]] = [(session.packet_count, session.byte_count)]
            # flow_list.append((session.index, session.byte_count, session.packet_count))
            print()
        time.sleep(0.5)


# 处理大流还是小流
def print_flow_dict():
    while True:
        if len(flow_dict.values()) % 3 == 0:
            print(flow_dict)


        time.sleep(2)


def main(p4info_path, bmv2_json_path):
    try:
        sh.setup(
            device_id=1,
            grpc_addr='0.0.0.0:9559',
            election_id=(0,1), # (high, low)
            config=sh.FwdPipeConfig(p4info_path, bmv2_json_path)
        )
        
        """
        te = sh.TableEntry('<table_name>')(action='<action_name>')
        te.match['<name>'] = '<value>'
        te.action['<name>'] = '<value>'
        te.insert()
        """

        # 下发ipv4_lpm表项
        te_ipv4_lpm = sh.TableEntry('ipv4_lpm')(action='ipv4_forward')
        te_ipv4_lpm.match['hdr.ipv4.dst_addr'] = '10.1.1.2'
        te_ipv4_lpm.action['dstAddr'] = '00:00:0a:01:01:02'
        te_ipv4_lpm.action['port'] = '1'
        te_ipv4_lpm.match['hdr.ipv4.dst_addr'] = '10.1.2.2'
        te_ipv4_lpm.action['port'] = '2'
        te_ipv4_lpm.action['dstAddr'] = '00:00:0a:01:02:02'
        te_ipv4_lpm.insert()

        ipv4_lpm_sessions = te_ipv4_lpm.read()
        for session in ipv4_lpm_sessions:
            print(session)


        # 添加mirroring_add 指令
        te_clone = sh.CloneSessionEntry(100)
        te_clone.add(255)
        te_clone.insert()

        clone_sessions = te_clone.read()

        # 输出 Clone Session entries
        for session in clone_sessions:
            print(session)
              
            
        packet_in = sh.PacketIn()
        def packet_sniff():
            while True:
                pkt = packet_in.sniff(timeout=1)
                for msg in pkt:
                    # sys.stdout.flush()
                    if msg not in pktlist:
                        pktlist.append(msg)
                # print(pktlist)
        sniffer_thread = Thread(target=packet_sniff)
        sniffer_thread.start()

        pktlist_thread = Thread(target=monitor_pktlist)
        pktlist_thread.start()

        # 下发流表表项
        # 下发流是否需要被检测表项 
        five_tuples_thread = Thread(target=monitor_five_tuples, args=(sh,))
        five_tuples_thread.start()

        # 读取正向流和反向流的数据   
        flow_thread = Thread(target=monitor_flow, args=(sh,))
        flow_thread.start()

        # 处理flow_list，得出流相关特征
        # 这里需要有打流工具，目前找找看DITG

        # 输出flow_list
        print_thread = Thread(target=print_flow_dict)
        print_thread.start()
       
    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    # ShutdownAllSwitchConnections()

    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
    "--p4-file", help="Path to P4 file", type=str, action="store", required=False
    )
    args = parser.parse_args()
    p4_file = args.p4_file.split("/")[-1] # 路径的最后一个为文件名
    name = p4_file.split(".")[0]
    # os.system()是返回状态码，如果参数正确，则result为0
    result = os.system(
        f"p4c --target bmv2 --arch v1model --p4runtime-files {name}.p4info.txt "
        + args.p4_file  # args.p4_file是文件路径
    )
    
   
    p4info_path = "./edge_switch.p4info.txt"
    bmv2_json_path = "./edge_switch.json"
    main(p4info_path, bmv2_json_path)