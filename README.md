# C-Packet-Sniffer
NWEN302 Packet Sniffer created in C

This has been tested on both Mac OSX and Linux. To compile for linux and to avoid warnings, goto line 20 and 
uncomment and comment the correct libraries.

Now run the following

# To compile:
    gcc -o sniffer main.c -l pcap

# To run:
    ./sniffer <filename.pcap>

This program can run IPv4 and IPv6 protocols.
Will display the information from TCP/UDP/ICMP and print the data out as a dump
