import nnpy
import struct
import ipaddress
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI


class DigestController():

    def __init__(self, sw_name):
        self.topo = load_topo('/home/sinet/gzc/traffic_classification/topology.json')
        self.sw_name = sw_name
        self.thrift_port = self.topo.get_thrift_port(sw_name)
        self.controller = SimpleSwitchThriftAPI(self.thrift_port)

    def recv_msg_digest(self, msg):
        topic, device_id, ctx_id, list_id, buffer_id, num = struct.unpack("<iQiiQi",
                                                                     msg[:32])
        print(num, len(msg))
        # 4+4+2+2+1+6=19
        offset = 19
        msg = msg[32:]
        for sub_message in range(num):
            src_ip, dst_ip, src_port, dst_port, protocol, timestamp = struct.unpack("!IIHHB6s", msg[0:offset]) # 这里的"!BII"是解包格式，三个部分，分别1，4，4
            # src_ip, dst_ip = struct.unpack("!BII", msg[0:offset])
            print("源ip:", str(ipaddress.IPv4Address(src_ip)), "目的ip:", str(ipaddress.IPv4Address(dst_ip)), "源port:", src_port, "目的port:", dst_port, "协议:", protocol, "时间戳:", timestamp)
            # print("源ip:", str(ipaddress.IPv4Address(src_ip)), "目的ip:", str(ipaddress.IPv4Address(dst_ip)))
            msg = msg[offset:]

        self.controller.client.bm_learning_ack_buffer(ctx_id, list_id, buffer_id)

    def run_digest_loop(self):
        sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
        notifications_socket = self.controller.client.bm_mgmt_get_info().notifications_socket
        print("connecting to notification sub %s" % notifications_socket)
        sub.connect(notifications_socket)
        sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')

        while True:
            msg = sub.recv()
            self.recv_msg_digest(msg)


def main():
    DigestController("s1").run_digest_loop()


if __name__ == "__main__":
    main()