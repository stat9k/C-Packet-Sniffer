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

struct ipv4_packet {
    unsigned char ihl : 4;
    unsigned char version : 4;
    unsigned char type_of_service;
    unsigned short total_length;
    unsigned short identification;
    unsigned short flags_and_fragment_offset;
    unsigned char time_to_live;
    unsigned char protocol;
    unsigned short header_checksum;
    unsigned int src_addr;
    unsigned int dest_addr;

    // payload should be exposed by now...
};