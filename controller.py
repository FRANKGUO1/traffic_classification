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


def read_register():
    register_names = ["register_packet_count", "register_len_count"]
    current_time = datetime.now()
    formatted_time = current_time.strftime("%Y%m%d%H%M")
    for register_name in register_names:
        p = subprocess.Popen('simple_switch_CLI --thrift-port 9090',shell=True,stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                    universal_newlines=True) 
        p.stdin.write('register_read %s' % register_name)
            # p.stdin.write('register_read reg_enq_qdepth')
        out, err = p.communicate()  # out 就是 str 类型
        print(out)


def writeIpv4LpmRules(p4info_helper, sw_id, dst_ip_addr, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="c_ingress.ipv4_lpm",
        match_fields={"hdr.ipv4.dst_addr": (dst_ip_addr, 32)},
        action_name="c_ingress.ipv4_forward",
        action_params={"port": port},
    )
    sw_id.WriteTableEntry(table_entry)
    print("Installed ingress forwarding rule on %s" % sw_id.name)


def writeDetectFlowRules(p4info_helper, sw_id, five_tuples, index):
    # hdr.ipv4.src_addr: lpm; hdr.ipv4.dst_addr: lpm; meta.srcport: exact; meta.dstport: exact; hdr.ipv4.protocol: exact;
    table_entry = p4info_helper.buildTableEntry(
        table_name="c_ingress.detect_flow",
        match_fields={"hdr.ipv4.src_addr": five_tuples[0], "hdr.ipv4.dst_addr": five_tuples[1], "hdr.meta.srcport": five_tuples[2], "hdr.meta.dstport": five_tuples[3], "hdr.ipv4.protocol": five_tuples[4]},
        action_name="c_ingress.record_flow",
        action_params={"index": index},
    )
    sw_id.WriteTableEntry(table_entry)
    print("Installed ingress forwarding rule on %s" % sw_id.name)


def writeSrcportMatchRules(p4info_helper, sw_id, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="c_ingress.srcport_match",
        match_fields={"meta.srcport": port},
        action_name="NoAction",
        # action_params={"port": port},
    )
    sw_id.WriteTableEntry(table_entry)
    print("Installed ingress forwarding rule on %s" % sw_id.name)


def writeDstportMatchRules(p4info_helper, sw_id, port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="c_ingress.dstport_match",
        match_fields={"meta.dstport": port},
        action_name="NoAction",
        # action_params={"port": port},e
    )
    # writeRules(p4info_helper, switch_name=s1, table_name="MyIngress.Is_local_ip", action="NoAction", match_fields="hdr.ipv4.dstAddr", match_value="192.168.7.128")
    sw_id.WriteTableEntry(table_entry)
    print("Installed ingress forwarding rule on %s" % sw_id.name)


def readTableRules(p4info_helper, sw):
    print("\n----- Reading tables rules for %s -----" % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print("%s: " % table_name, end="")
            for m in entry.match:
                print(
                    p4info_helper.get_match_field_name(table_name, m.field_id), end=""
                )
                print("%r" % (p4info_helper.get_match_field_value(m),), end="")
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print("-> action:%s with parameters:" % action_name, end="")
            for p in action.params:
                print(
                    " %s"
                    % p4info_helper.get_action_param_name(action_name, p.param_id),
                    end="",
                )
                print(" %r" % p.value, end="")
            print("")


def printGrpcError(e):
    print("gRPC Error:", e.details(), end="")
    status_code = e.code()
    print("(%s)" % status_code.name, end="")
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))


# 监控 five_tuples 列表并处理新增元素的函数
def monitor_five_tuples(p4info_helper, sw_id):
    last_checked_length = 0
    while True:
        current_length = len(packet_features)
        if current_length > last_checked_length:
            for i in range(last_checked_length, current_length):
                writeDetectFlowRules(p4info_helper=p4info_helper, sw_id=sw_id, five_tuples=packet_features[i], index=i)
            last_checked_length = current_length


def main(p4info_path, bmv2_json_path):
    # digest_thread = threading.Thread(target=run_digest)
    # 启动线程
    # digest_thread.start()  
    # DigestController("s1").run_digest_loop()
    
    # p4info_helper = helper.P4InfoHelper(p4info_path)

    """
    
        s1 = bmv2.Bmv2SwitchConnection(
            name="s1",
            address="0.0.0.0:50051",
            device_id=1,
            proto_dump_file="p4runtime.log",
        )

        if s1.MasterArbitrationUpdate() == None:
            print("Failed to establish the connection")

        s1.SetForwardingPipelineConfig(
            p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_json_path
        )
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")

        # 建立白名单，一些特定端口的包不处理
        #for port in filter_ports:
        #    writeSrcportMatchRules(p4info_helper=p4info_helper, sw_id=s1, port=port)

        writeIpv4LpmRules(p4info_helper=p4info_helper, sw_id=s1, dst_ip_addr="10.1.1.2", port=1)
        writeIpv4LpmRules(p4info_helper=p4info_helper, sw_id=s1, dst_ip_addr="10.1.2.2", port=2)
    """
    try:
        sh.setup(
            device_id=1,
            grpc_addr='0.0.0.0:9559',
            election_id=(0,1), # (high, low)
            config=sh.FwdPipeConfig(p4info_path, bmv2_json_path)
        )

        
        # 下发ipv4_lpm表项
        """
        te = sh.TableEntry('<table_name>')(action='<action_name>')
        te.match['<name>'] = '<value>'
        te.action['<name>'] = '<value>'
        te.insert()
        """
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
        five_tuple_list = set()
        pktlist = []
        sys.stdout.flush()
        
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


        last_processed_index = 0
        def monitor_pktlist():
            global last_processed_index

            while True:
                current_len = len(pktlist)
                if current_len > last_processed_index:
                    for i in range(last_processed_index, current_len):
                        pkt = pktlist[i]
                        # 使用Scapy解析数据包
                        response_dict = MessageToDict(pkt)
                        decoded_metadata_values = base64.b64decode(response_dict['packet']['payload'])
                        packet = Ether(decoded_metadata_values)

                        # 检查是否是IP数据包
                        if IP in packet:
                            ip_layer = packet[IP]
                            
                            # 检查是否是UDP协议
                            if UDP in ip_layer:
                                udp_layer = ip_layer[UDP]
                                
                                # 提取五元组
                                src_ip = ip_layer.src
                                dst_ip = ip_layer.dst
                                protocol = ip_layer.proto
                                src_port = udp_layer.sport
                                dst_port = udp_layer.dport
                                
                                five_tuple_list.add((src_ip, dst_ip, src_port, dst_port, protocol))
                        else:
                            print("不是IP数据包")

                    last_processed_index = current_len
                    print(five_tuple_list)
        
                    time.sleep(1)  # 每隔1秒检查一次 pktlist
        pktlist_thread = Thread(target=monitor_pktlist)
        pktlist_thread.start()

            
            
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