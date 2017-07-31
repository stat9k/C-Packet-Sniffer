/*
 * sniffer.c
 *
 * By David C Harrison (david.harrison@ecs.vuw.ac.nz) July 2015
 *
 * Modified By Jack O'Brien 300350413
 *
 * Use as-is, modification, and/or inclusion in derivative works is permitted only if
 * the original author is credited.
 *
 * To compile: gcc -o sniffer sniffer.c -l pcap
 *
 * To run: tcpdump -s0 -w - | ./sniffer -
 *     Or: ./sniffer <some file captured from tcpdump or wireshark>
 */

#include <stdio.h>
#include <pcap.h>
#include "packet_headers.h"


/**
 * Unpacks the ethernet frame, prints out the source and destination
 * MAC addresses and returns the protocol
 *
 * @param packet - the parsed data from tcpdump/pcap_file
 * @return - the ethernet protocol - IPv4, IPv6, etc...
 */
short unpack_ethernet_header_packet (const u_char *packet)
{

    struct ethernet_header *eth_packet = (struct ethernet_header*) packet;

    printf("Source Mac");
    for (int i=0; i<ETH_ADDRESS_LENGTH; i++)
    {
        if (i == 0)
            printf(": %02x", eth_packet->source_mac_addr[i]);
        else
            printf(":%02x", eth_packet->source_mac_addr[i]);
    }
    printf("\n");

    printf("Destination Mac");
    for (int i=0; i<ETH_ADDRESS_LENGTH; i++)
    {
        if (i == 0)
            printf(": %02x", eth_packet->dest_mac_addr[i]);
        else
            printf(":%02x", eth_packet->dest_mac_addr[i]);
    }
    printf("\n");
}

void got_packet (u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Header Length: %d\n", header->len);

    // now we have the packet, we need to break it open
    // we start with the ethernet_header
    unpack_ethernet_header_packet(packet);


}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Must have an argument, either a file name or '-'\n");
        return -1;
    }

    pcap_t *handle = pcap_open_offline(argv[1], NULL);
    pcap_loop(handle, 1024*1024, got_packet, NULL);
    pcap_close(handle);

    return 0;
}