/*
 * Created by Jack O'Brien on 1/08/17.
 *
 * The header file for our functions in main.c
 */

#ifndef C_PACKET_SNIFFER_MAIN_H
#define C_PACKET_SNIFFER_MAIN_H

#endif //C_PACKET_SNIFFER_MAIN_H

#define ETH_ADDRESS_LENGTH 6
#define ETH_HEADER_LENGTH 14

int packet_number = 1;


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


/**
 * Prints out the data in raw and ascii format.
 * The raw and ascii correspond with each other, being
 * raw on the lhs, and ascii on the right
 *
 * This method was taken from Github - can't remember who I got it from
 */
void dump (const unsigned char *, unsigned int);

/**
 * Converts a string to a MAC or IPv6 Address
 * in the format of xx:xx... or xxxx::xxxx
 */
void mac_toupper (char *);

/**
 * Unpacks the ethernet frame, prints out the source and destination
 * MAC addresses and returns the protocol
 *
 * @param packet - the parsed data from tcpdump/pcap_file
 * @return - the ethernet protocol - IPv4, IPv6, etc...
 */
int unpack_ethernet_header_frame (const u_char *);


/**
 * Unpacks the IPv4 Packet, prints out the ipv4 header info
 *
 * @param packet - the parsed data from tcpdump + ETHERNET_HEADER_LENGTH
 * @param return - the IPv4 protocol - TCP/UDP/ICMP etc...
 */
int unpack_ipv4_packet (const u_char *);


/**
 * Unpack the IPv6 Packet, prints out the ipv6 header info
 *
 */
int unpack_ipv6_packet (const u_char *);

/**
 * Prints the IPv4 address in the form of 127.0.0.1
 *
 * @param address - the bytes to be converted
 */
void get_ipv4_address (char *, __uint32_t);


/**
 * Print the IPv6 address in the form of xxxx::xxxx
 */
void get_ipv6_address (char *, struct in6_addr);

/**
 * Unpack the tcp segment and print valid information to std.err
 */
void tcp_segment (const u_char *);

/**
 * Unpacks the udp segment and print valid information to std.err
 */
void udp_segment (const u_char *);

/**
 * Unpacks the icmp packet and print valid informaiton to std.err
 */
void icmp_packet (const u_char *);

/**
 * Figures out whether it will be displaying IPv4 or IPv6 protocol.
 * This is done as tcp/udp will use the same functions regardless of
 * ip protocol. The only difference will be ICMPv6
 */
void do_protocol (int, const u_char *, int, unsigned int);


/**
 * The main function for parsing a packet
 */
void got_packet (u_char *, const struct pcap_pkthdr *, const u_char *);

/**
 * Start of program
 */
int
main(int, char **);
