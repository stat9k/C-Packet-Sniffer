/*
 * Created by Jack O'Brien on 31/07/17.
 */


#ifndef C_PACKET_SNIFFER_PACKET_HEADERS_H
#define C_PACKET_SNIFFER_PACKET_HEADERS_H

#endif //C_PACKET_SNIFFER_PACKET_HEADERS_H

#define ETH_ADDRESS_LENGTH      6
#define ETH_HEADER_LENGTH       14


struct ethernet_frame {
    unsigned char source_mac_addr[ETH_ADDRESS_LENGTH];
    unsigned char dest_mac_addr[ETH_ADDRESS_LENGTH];
    unsigned short protocol;
};


struct ipv4_header {
    unsigned char ihl : 4;
    unsigned char version : 4;
    unsigned char type_of_service;
    unsigned short total_length;
    unsigned short identification;
    unsigned short flags_and_fragment_offset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short header_checksum;
    unsigned int src_ip_addr;
    unsigned int dst_ip_addr;
};


struct ipv6_header {
#if defined(WORDS_BIGENDIAN)
    u_int8_t version:4, traffic_class_high:4;
	u_int8_t traffic_class_low:4, flow_label_high:4;
#else
    unsigned int traffic_class_high :4, version :4;
    unsigned int flow_label_high :4, traffic_class_low :4;
#endif
    unsigned int flow_label_low : 16;
    unsigned int payload_length : 16;
    unsigned char  next_header : 8;
    unsigned char hop_limit : 8;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
};

struct tcp_header {
    unsigned short src_port;
    unsigned short dest_port;
    u_int32_t sequence;
    u_int32_t acknowledgment;
    unsigned char reserved :4;
    unsigned char data_offset :4;
    unsigned char flags;

#define fin 0x01
#define syn 0x02
#define rst 0x04
#define psh 0x08
#define ack 0x10
#define urg 0x20

    unsigned short window_size;
    unsigned short checksum;
    unsigned short urgent_pointer;
};

struct udp_header {
    unsigned int src_port : 16;
    unsigned int dst_port : 16;
    unsigned int length : 16;
    unsigned int checksum : 16;
};

struct icmp_packet {
    unsigned int type : 8;
    unsigned int code : 8;
    unsigned int checksum : 16;
    unsigned char rest_of_header;
};