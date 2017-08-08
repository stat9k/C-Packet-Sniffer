/*
 * Created by Jack O'Brien on 1/08/17.
 *
 * The header file for our functions in main.c
 */

#ifndef C_PACKET_SNIFFER_MAIN_H
#define C_PACKET_SNIFFER_MAIN_H

#endif //C_PACKET_SNIFFER_MAIN_H

int packet_number = 1;


/**
 * Prints out the data in a certain way.
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
 * @param packet
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
void do_protocol(int, const u_char *, int, unsigned int);


/**
 * The main function for parsing a packet
 *
 * @param args
 * @param header
 * @param packet
 */
void got_packet (u_char *, const struct pcap_pkthdr *, const u_char *);

