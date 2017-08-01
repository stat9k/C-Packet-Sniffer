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
 * Unpacks the ethernet frame, prints out the source and destination
 * MAC addresses and returns the protocol
 *
 * @param packet - the parsed data from tcpdump/pcap_file
 * @return - the ethernet protocol - IPv4, IPv6, etc...
 */
int unpack_ethernet_header_frame (const u_char *packet);


/**
 * Unpacks the IPv4 Packet, prints out the ipv4 header info
 *
 * @param packet - the parsed data from tcpdump + ETHERNET_HEADER_LENGTH
 * @param return - the IPv4 protocol - TCP/UDP/ICMP etc...
 */
int unpack_ipv4_packet (const u_char *packet);

/**
 * Prints the IPv4 address in the form of 127.0.0.1
 *
 * @param address - the bytes to be converted
 */
void get_ipv4_address (char *msg, __uint32_t address);

/**
 * Unpack the tcp segment and print valid information to std.err
 * @param packet
 */
void tcp_segment (const u_char *packet);


/**
 * The main function for parsing a packet
 *
 * @param args
 * @param header
 * @param packet
 */
void got_packet (u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

