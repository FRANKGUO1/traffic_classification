import nnpy
import struct
import ipaddress
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
import subprocess 
import os
from datetime import datetime
import p4runtime_sh.shell as sh 
import threading

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



parser = argparse.ArgumentParser()
# parser.add_argument('--thrift-port', help='Thrift server port for table updates', type=int, action="store", default=9090)
parser.add_argument(
    "--p4-file", help="Path to P4 file", type=str, action="store", required=False
)

args = parser.parse_args()

# 获取特征的列表
packet_features = []
# 不处理的特定端口号的数据包
filter_ports = [53, 161, 162, 21, 20, 25, 587, 465, 143, 993, 110, 995]

class DigestController():
    def __init__(self, sw_name):
        self.topo = load_topo('topology.json')
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)

    def recv_msg_digest(self, msg):
        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi", msg[:32])

        # print(num)
        
        offset = 13 # 每个消息在消息体的长度，这里为13字节
        msg = msg[32:]  # 前32字节为头部
        # num为五元组数量
        for _ in range(num):
            src_ip, dst_ip, src_port, dst_port, protocol = struct.unpack("!IIHHB", msg[0:offset]) # 这里已成功获取五元组
            if (str(ipaddress.IPv4Address(src_ip)), str(ipaddress.IPv4Address(dst_ip)), src_port, dst_port, protocol) not in packet_features:
                packet_features.append((str(ipaddress.IPv4Address(src_ip)), str(ipaddress.IPv4Address(dst_ip)), src_port, dst_port, protocol))
            print(packet_features)
            print("src_ip:", str(ipaddress.IPv4Address(src_ip)), "dst_ip:", str(ipaddress.IPv4Address(dst_ip)), "src_port:", src_port, "dst_port:", dst_port, "protocol:", protocol)
            msg = msg[offset:]

        self.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)

    def run_digest_loop(self):
        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        print(sub)
        notifications_socket = self.controller.client.bm_mgmt_get_info().notifications_socket
        print("connecting to notification sub %s" % notifications_socket)
        if notifications_socket:
            sub.connect(notifications_socket)
        else:
            sub.connect("ipc:///tmp/bmv2-1-notifications.ipc")
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')

        while True:
            msg = sub.recv()
            self.recv_msg_digest(msg)


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


def wait_until_not_empty(lst, check_interval=1):
    while not lst:
        print("等待列表填充...")
        time.sleep(check_interval)


# 运行digest，获取五元组信息
def run_digest():
    DigestController("s1").run_digest_loop()


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
    
    p4info_helper = helper.P4InfoHelper(p4info_path)

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

        te_clone = sh.CloneSessionEntry(100)
        te_clone.add(255, 0)
        te_clone.insert()

        clone_sessions = te_clone.read()

        # 输出 Clone Session entries
        for session in clone_sessions:
            print(session)
              

        # 其它表项
        te = sh.TableEntry('<table_name>')(action='<action_name>')
        te.match['<name>'] = '<value>'
        te.action['<name>'] = '<value>'
        te.insert()
        """
        while True:
            packetin = s1.PacketIn()  # Packet in!
            if packetin:
                print("PACKET IN received")
                print(packetin)
        """
        
        
        # 新方案，用packet io来实现，直接在流表项中添加mirror ID，然后用clone复制数据包并转发到cpu端口
        # 额外：试试可不可以简化数据包，比如去除负载等等
                       
    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    # ShutdownAllSwitchConnections()

    
if __name__ == "__main__":
    
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