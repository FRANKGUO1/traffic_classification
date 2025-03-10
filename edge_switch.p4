/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
//------------------------------------------------------------
// 定义协议号
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_IPV6 = 0x86dd;
const bit<16> TYPE_SINET = 0x8999;
const bit<16> TYPE_ARP = 0x0806;
const bit<16> TYPE_PROBE = 0x0812;
const bit<8>  IP_PROTO_TCP = 8w6;
const bit<8>  IP_PROTO_UDP = 8w17;
const bit<8>  IP_PROTO_ICMP = 8w1;

#define MAX_HOPS 10
#define MAX_PORTS 8
//定义cpu端口号
#define CPU_PORT 255


//register<bit<32>>(MAX_PORTS) byte_cnt_reg; // 存储接口累积流量，INT协议使用
//register<time_t>(MAX_PORTS) last_time_reg; // 存储上一个INT包到达时间，INT协议使用
//----------------------------- HEADER -------------------------------
// 定义首部
// 物理层首部
header ethernet_h {
    bit<48>  dst_mac;
    bit<48>  src_mac;
    bit<16>  ether_type;
}
//--------------------------
// ARP首部
header arp_h {
    bit<16>  hardware_type;
    bit<16>  protocol_type;
    bit<8>   HLEN;
    bit<8>   PLEN;
    bit<16>  OPER;
    bit<48>  sender_ha;
    bit<32>  sender_ip;
    bit<48>  target_ha;
    bit<32>  target_ip;
}
//--------------------------
// IPv4首部
header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}
//--------------------------

//--------------------------
// ICMP首部
header icmp_h {
    bit<8>   type;
    bit<8>   code;
    bit<16>  hdr_checksum;
}
//--------------------------

//TCP首部
header tcp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<4>   res;
    bit<8>   flags;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}
//--------------------------
//UDP首部
header udp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<16>  hdr_length;
    bit<16>  checksum;
}
//---------------------------
// 用三元组标记一个流，目的Ip，目的端口，协议号即可
struct five_tuple_digest {
    // bit<32> srcIp;
    bit<32> dstIp;
    // bit<16> srcPort;
    bit<16> dstPort;
    bit<8>  proto;
    // bit<48> ingress_cur_time;  
    // bit<48> egress_cur_time;  
    // bit<32>   ingress_byte_cnt;
    bit<32>   egress_byte_cnt;
}
//--------------------------
struct metadata {
    bit<16>  srcport;
    bit<16>  dstport;

    five_tuple_digest five_tuple;
}
//--------------------------
//完整首部
struct headers {
    ethernet_h               ethernet;
    arp_h                    arp;
    ipv4_h                   ipv4;
    icmp_h                   icmp;
    tcp_h                    tcp;
    udp_h                    udp;
}
//----------------------------- PARSER -------------------------------
parser c_parser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_tcp {
       packet.extract(hdr.tcp);
       meta.dstport = hdr.tcp.dst_port;
       meta.srcport = hdr.tcp.src_port;
       transition accept;
    }
    state parse_udp {
       packet.extract(hdr.udp);
       meta.dstport = hdr.udp.dst_port;
       meta.srcport = hdr.udp.src_port;
       transition accept;
    }
}

//------------------------ CONTROL ------------------------------------
control c_verify_checksum(inout headers hdr, 
                          inout metadata meta) {
    apply {

    }
}
//------------------------------------------------------------
control c_ingress(inout headers hdr, 
                  inout metadata meta, 
                  inout standard_metadata_t standard_metadata) {
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action ipv4_forward(bit<9> port) {
        //hdr.ethernet.src_mac = hdr.ethernet.dst_mac;
        //hdr.ethernet.dst_mac = dstAddr;
        //hdr.ipv4.src_addr = src_addr;
        //hdr.ipv4.dst_addr = dst_addr;
        standard_metadata.egress_spec = port;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_forward;
            _drop;
        }
        size = 1024;
        default_action = _drop();
    }

    table srcport_match {
        key = {
            meta.srcport: exact;
        }
        actions = {
            NoAction;
        }
    }

    table dstport_match {
        key = {
            meta.dstport: exact;
        }
        actions = {
            NoAction;
        }
    }

    action send_digest() {
        digest<five_tuple_digest>(1, {hdr.ipv4.dst_addr, meta.dstport, hdr.ipv4.protocol, standard_metadata.packet_length});
        // digest(1, {hdr.ipv4.dst_addr, meta.dstport, hdr.ipv4.protocol, standard_metadata.egress_global_timestamp, standard_metadata.packet_length});
    }
    // Table
    table digest_table {
        key = {
            // hdr.ipv4.dst_addr: lpm;
            meta.dstport: exact;
            // hdr.ipv4.protocol: exact;
            }
        actions = {
            send_digest;
            }
        // no need to set table entry from control plane to send digest
        // const default_action = send_digest;
        }
    
    // 根据五元组来确定流，从而记录流特征,还得用标号标记每个流对应的寄存器索引
    register<bit<32>>(MAX_PORTS) register_packet_count;
    register<bit<32>>(MAX_PORTS) register_len_count;
    action record_flow(bit<32> index) {
        // 记录流包数
        bit<32> packet_count = 0;
        register_packet_count.read(packet_count, index);
        packet_count = packet_count + 1;
        register_packet_count.write(index, packet_count);

        // 记录流字节数
        bit<32> len_count = 0;
        register_len_count.read(len_count, index);
        len_count = len_count + standard_metadata.packet_length;
        register_len_count.write(index, len_count);
    }

    table detect_flow {
        key = {
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
            meta.srcport: exact;
            meta.dstport: exact;
            hdr.ipv4.protocol: exact;
        }
        actions = {
            record_flow;
        }
    }

    apply { 
        if (hdr.ipv4.isValid()) {
            digest_table.apply();
            ipv4_lpm.apply();
            // 这里要有一个处理逻辑，根据端口号来排除一些常见的协议
            if (srcport_match.apply().miss && dstport_match.apply().miss) {                    
                clone(CloneType.I2E, 100);
                // digest<five_tuple_digest>(1, {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, meta.five_tuple.srcPort, meta.five_tuple.dstPort, hdr.ipv4.protocol});      
                detect_flow.apply();
            }  
        }      
        }
    }

//------------------------------------------------------------
control c_egress(inout headers hdr, 
                 inout metadata meta, 
                 inout standard_metadata_t standard_metadata) {

    apply {
        // 发送digest给控制平面
        // digest_table.apply();
        //  digest<five_tuple_digest>(1, {hdr.ipv4.dst_addr, meta.dstport, hdr.ipv4.protocol, standard_metadata.egress_global_timestamp, standard_metadata.packet_length});
        }
    }

//------------------------------------------------------------
control c_compute_checksum(inout headers hdr,
                           inout metadata meta) {
    apply {

    }
}
//------------------------------------------------------------
control c_deparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}
//------------------------------------------------------------
V1Switch(
    c_parser(),
    c_verify_checksum(),
    c_ingress(),
    c_egress(),
    c_compute_checksum(),
    c_deparser()
) main;