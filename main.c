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
#include <arpa/inet.h>
#include "main.h"


int
unpack_ethernet_header_frame(const u_char *packet) {

    struct ethernet_frame *eth_frame = (struct ethernet_frame *) packet;

    printf("Source Mac");
    for (int i=0; i<ETH_ADDRESS_LENGTH; i++)
    {
        if (i == 0)
            printf(": %02x", eth_frame->source_mac_addr[i]);
        else
            printf(":%02x", eth_frame->source_mac_addr[i]);
    }
    printf("\n");

    printf("Destination Mac");
    for (int i=0; i<ETH_ADDRESS_LENGTH; i++)
    {
        if (i == 0)
            printf(": %02x", eth_frame->dest_mac_addr[i]);
        else
            printf(":%02x", eth_frame->dest_mac_addr[i]);
    }
    printf("\n");

    return eth_frame->protocol;
}

int
unpack_ipv4_packet(const u_char *packet) {

    struct ipv4_packet *ip_packet = (struct ipv4_packet *) packet;

    printf("\tVersion: %d\n", ip_packet->version);
    printf("\tTotal Length: %d\n", ip_packet->total_length);
    printf("\tTime To Live: %d\n", ip_packet->ttl);
    get_ipv4_address("\tSource Address", ip_packet->src_addr);
    get_ipv4_address("\tDestination Address", ip_packet->dest_addr);

    return ip_packet->protocol;
}

void
icmp_packet ()
{

}

void
udp_segment ()
{

}

void
dump(const unsigned char *data_buffer, const unsigned int length) {
    unsigned char byte;
    unsigned int i, j;

    for (i = 0; i < length; i++) {
        byte = data_buffer[i];
        printf("%02x", data_buffer[i]);
        if (((i % 16) == 15) || (i == length - 1)) {
            for (j = 0; j < 15 - (i % 16); j++)
                printf("  ");
            printf("| ");
            for (j = (i - (i % 16)); j <= i; j++) {
                byte = data_buffer[j];
                if ((byte > 31) && (byte < 127))
                    printf("%c", byte);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}

void
get_ipv4_address(char *msg, __uint32_t address) {
    struct in_addr ip;
    ip.s_addr = address;

    printf("%s: %s\n", msg, inet_ntoa(ip));
}

void
tcp_segment(const u_char *packet) {
    struct tcp_header *tcp_segment = (struct tcp_header *) packet;

    printf("\t\tSource Port: %d\n", ntohs(tcp_segment->src_port));
    printf("\t\tDestination Port: %d\n", ntohs(tcp_segment->dest_port));
    printf("\t\tSequence: %d\n", ntohl(tcp_segment->sequence));
    printf("\t\tAcknowledgement: %d\n", ntohl(tcp_segment->acknowledgment));
    printf("\t\tData Offset: %d\n", tcp_segment->data_offset);
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    // now we have the packet, we need to break it open
    // we start with the ethernet_frame
    printf("\nEthernet Frame: #%d\n", packet_number++);
    int ip_proto, eth_proto = unpack_ethernet_header_frame(packet);

    switch (eth_proto) {

        case 8:                                     // IPv4
            printf("Protocol: IPv4\n");

            // unpack the IPv4 packet
            ip_proto = unpack_ipv4_packet(packet + ETH_HEADER_LENGTH);

            // unpack the IPv4 protocol
            if (ip_proto == 6)                      // TCP
            {
                printf("\tTCP Segment\n");
                tcp_segment(packet + ETH_HEADER_LENGTH + sizeof(struct ipv4_packet));

                dump((packet + ETH_HEADER_LENGTH + sizeof(struct ipv4_packet) + sizeof(struct tcp_header)), header->len);

            }

            else if (ip_proto == 1)                 // ICMP
            {

            }

            else if (ip_proto == 17)                // UDP
            {

            }

            else
            {
                perror("Unknown IPv4 Protocol\n");
                return;
            }

            break;

        case 56710:                                 // IPv6
            printf("Protocol: IPv6\n");
            break;

        default:
            break;
    }

    printf("\n");
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