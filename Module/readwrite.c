#include "readwrite.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"

int read_pcap(const char *filename, int protocol, int start, int size, char **data, int *data_size) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    struct pcap_pkthdr header;
    const unsigned char *packet;
    int data_space = 1000;

    *data_size = 0;
    *data = (char *)malloc(data_space * size);

    /* Open input PCAP file for reading */
    pcap = pcap_open_offline(filename, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(pcap, &header)) != NULL) {
        struct sniff_ethernet *ethernet; /* The ethernet header */
        struct sniff_ip *ip;             /* The IP header */
        struct sniff_tcp *tcp;           /* The TCP header */
        struct sniff_udp *udp;           /* The UDP header */

        unsigned int size_ip;
        unsigned int size_trans;

        if (*data_size + size > data_space) {
            data_space += 500;
            char *temp_array = malloc(data_space * sizeof(char));
            memcpy(temp_array, *data, *data_size * sizeof(char));
            free(*data);
            *data = temp_array;
            free(temp_array);
        }
        ethernet = (struct sniff_ethernet *)(packet);
        ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;
        if (size_ip < 20) {
            printf("   * Invalid IP header length: %u bytes\n", size_ip);
            return 1;
        }
        if (protocol == ENUM_IP) {
            memcpy(*data + (*data_size), (unsigned char *)ip + start, size * sizeof(unsigned char));
            *data_size += size * sizeof(unsigned char);
            continue;
        }
        if (ip->ip_p == 6) {  // protocal is UDP
            tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
            size_trans = TH_OFF(tcp) * 4;
            if (size_trans < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_trans);
                return 1;
            }
            if (protocol == ENUM_TCP) {
                memcpy(*data + (*data_size), (unsigned char *)tcp + start, size * sizeof(unsigned char));
                *data_size += size * sizeof(unsigned char);
                continue;
            }
        } else if (ip->ip_p == 17) {  // protocal is UDP
            udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
            size_trans = SIZE_UDP;
            if (protocol == ENUM_UDP) {
                memcpy(*data + (*data_size), (unsigned char *)udp + start, size * sizeof(unsigned char));
                *data_size += size * sizeof(unsigned char);
                continue;
            }
        }
        unsigned char *rtp = (unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_trans);
        if (protocol == ENUM_RTP) {
            memcpy(*data + (*data_size), (unsigned char *)rtp + start, size * sizeof(unsigned char));
            *data_size += size * sizeof(unsigned char);
            continue;
        }

        printf("Source IP: ");
        printf("%s\n", inet_ntoa(ip->ip_src));
        printf("Destination IP: ");
        printf("%s\n", inet_ntoa(ip->ip_dst));
    }

    /* Close the file */
    pcap_close(pcap);

    return 0;
}

int write_pcap(const char *infile, const char *outfile, int protocol, int start, int size, char *data, int data_size) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const unsigned char *packet;

    pcap_t *pcap_in = pcap_open_offline(infile, errbuf);
    if (pcap_in == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }
    pcap_t *pacp_out = pcap_open_dead(DLT_EN10MB, MAX_PACKET_SIZE);
    // 開啟空的pcap_t 結構
    pcap_dumper_t *dumper = pcap_dump_open(pacp_out, outfile);

    for (int j = 0; j < (data_size / size); j++) {
        if ((packet = pcap_next(pcap_in, &header)) != NULL) {
            struct sniff_ethernet *ethernet; /* The ethernet header */
            struct sniff_ip *ip;             /* The IP header */
            struct sniff_tcp *tcp;           /* The TCP header */
            struct sniff_udp *udp;           /* The UDP header */
            char *payload;                   /* Packet payload */
            unsigned char *packet = packet;

            unsigned int size_ip;
            unsigned int size_tcp;
            int data_idx = -1;

            ethernet = (struct sniff_ethernet *)(packet);
            ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
            size_ip = IP_HL(ip) * 4;
            tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcp) * 4;
            udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
            payload = (unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
            switch (protocol) {
                case ENUM_IP:  // IP
                    for (int i = SIZE_ETHERNET + start; i < SIZE_ETHERNET + start + size; i++) {
                        packet[i] = data[++data_idx];
                    }
                case ENUM_TCP:  // TCP
                    for (int i = SIZE_ETHERNET + size_ip + start; i < SIZE_ETHERNET + size_ip + start + size; i++) {
                        packet[i] = data[++data_idx];
                    }
                    break;
                case ENUM_UDP:  // UDP
                    for (int i = SIZE_ETHERNET + size_ip + start; i < SIZE_ETHERNET + size_ip + start + size; i++) {
                        printf("%d", 1);
                        packet[i] = data[++data_idx];
                        putchar(packet[i]);
                    }
                    break;
                case ENUM_RTP:  // RTP
                    if (size_tcp < 20) {
                        // 表示不是tcp header
                        for (int i = SIZE_ETHERNET + size_ip + SIZE_UDP + start; i < SIZE_ETHERNET + size_ip + SIZE_UDP + start + size; i++) {
                            packet[i] = data[++data_idx];
                        }
                    } else {
                        for (int i = SIZE_ETHERNET + size_ip + size_tcp + start; i < SIZE_ETHERNET + size_ip + size_tcp + start + size; i++) {
                            packet[i] = data[++data_idx];
                        }
                    }
                    break;
                default:
                    break;
            }
            pcap_dump((unsigned char *)dumper, &header, packet);
        }
    }


    pcap_close(pcap_in);
    pcap_dump_close(dumper);
    pcap_close(pacp_out);

    return 0;
}
