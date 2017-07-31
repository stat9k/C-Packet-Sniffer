/*
 * Created by Jack O'Brien on 31/07/17.
 */

#ifndef C_PACKET_SNIFFER_PACKET_HEADERS_H
#define C_PACKET_SNIFFER_PACKET_HEADERS_H

#endif //C_PACKET_SNIFFER_PACKET_HEADERS_H

#define ETH_ADDRESS_LENGTH      6
#define ETH_HEADER_LENGTH       14


struct ethernet_header {
    unsigned char source_mac_addr[ETH_ADDRESS_LENGTH];
    unsigned char dest_mac_addr[ETH_ADDRESS_LENGTH];
    unsigned short protocol;
};