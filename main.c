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
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/if_ether.h>
#include "main.h"
#include "packet_headers.h"


void
mac_toupper (char *mac)
{
    int i=0;
    while (mac[i])
    {
        putchar (toupper(mac[i]));
        i++;
    }
    printf("\n");
}


int
unpack_ethernet_header_frame(const u_char *packet) {

    struct ethernet_frame *eth_frame = (struct ethernet_frame *) packet;

    printf("Source Mac: ");
    mac_toupper(ether_ntoa((struct ether_addr *) eth_frame->source_mac_addr));


    printf("Destination Mac: ");
    mac_toupper(ether_ntoa((struct ether_addr *) eth_frame->dest_mac_addr));

    return eth_frame->protocol;
}

int
unpack_ipv4_packet(const u_char *packet) {

    struct ipv4_header *ip_packet = (struct ipv4_header *) packet;

    printf("\tVersion: %d\n", ip_packet->version);
    printf("\tTotal Length: %d\n", ip_packet->total_length);
    printf("\tTime To Live: %d\n", ip_packet->ttl);
    get_ipv4_address("\tSource Address", ip_packet->src_ip_addr);
    get_ipv4_address("\tDestination Address", ip_packet->dst_ip_addr);

    return ip_packet->protocol;
}


int
unpack_ipv6_packet (const u_char *packet)
{
    struct ipv6_header *ip_packet = (struct ipv6_header *) packet;
    printf("\tVersion: %d\n", ip_packet->version);
    get_ipv6_address("\tSource Address", ip_packet->src_addr);
    get_ipv6_address("\tDestination Address", ip_packet->dst_addr);

    return ip_packet->next_header;
}

void
dump(const unsigned char *data_buffer, const unsigned int length) {

    printf("\t\tPayload: (%d bytes)\n\n", length - 32);
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
get_ipv6_address(char *string, struct in6_addr ip_address)
{
    char addr[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &ip_address, addr, INET6_ADDRSTRLEN);

    printf("%s: ", string);
    mac_toupper(addr);
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
udp_segment (const u_char *packet)
{
    struct udp_header *udp_segment = (struct udp_header *) packet;
    printf("\t\tSource Port: %d\n", ntohs(udp_segment->src_port));
    printf("\t\tDestination Port: %d\n", ntohs(udp_segment->dst_port));
    printf("\t\tLength: %d\n", ntohs(udp_segment->length));
}

void
icmp_packet (const u_char *packet)
{
    struct icmp_packet *icmp_header = (struct icmp_packet *) packet;

    printf("\t\tType: %d\n", icmp_header->type);
    printf("\t\tCode: %d\n", icmp_header->code);

}


void
do_protocol(int ip_proto, const u_char *packet, int ipv, unsigned int header_len)
{

    int ip_header_size = sizeof(struct ipv4_header);        //version 4 by default

    if (ipv == 6)                                           // IPv6 6
        ip_header_size = sizeof(struct ipv6_header);

    packet = packet + ip_header_size;


        // TCP
    if (ip_proto == 6)
    {
        printf("\tTCP Segment:\n");
        tcp_segment(packet);

        // print data
        dump((packet + sizeof(struct tcp_header)), header_len);

    }

        // UDP
    else if (ip_proto == 17)
    {
        printf("\tUDP Segment:\n");
        udp_segment(packet);

        // print data
        dump((packet + sizeof(struct udp_header)), header_len);

    }

        // ICMP
    else if (ip_proto == 1 || ip_proto == 58)
    {
        printf("\tICMP Packet:\n");
        icmp_packet(packet);

        // print data
        dump((packet + sizeof(struct icmp_packet)), header_len);
    }

    else
    {
        printf("\tUnknown IPv%d Protocol: %d\n", ipv, ip_proto);
        return;
    }
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

            do_protocol(ip_proto, packet + ETH_HEADER_LENGTH, 4, header->len);

            break;

        case 56710:                                 // IPv6
            printf("Protocol: IPv6\n");

            // unpack the ipv6 packet
            ip_proto = unpack_ipv6_packet(packet + ETH_HEADER_LENGTH);

            do_protocol(ip_proto, packet + ETH_HEADER_LENGTH, 6, header->len);

            break;

        default:
            printf("Protocol: Unknown\n");
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