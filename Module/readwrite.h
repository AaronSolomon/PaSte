#include <pcap.h>

#include "utils.h"

#define MAX_PACKET_SIZE 65535

/// @brief Read packet from given pcap file
/// @param filename pcap file name
/// @param protocal protocol type (IP, TCP, UDP, RTP)
/// @param start start index
/// @param size read size per packet
/// @param data return data
/// @param data_size return data size
/// @return 0 if success, 1 if failed
int read_pcap(const char *filename, int protocol, int start, int size, char **data, int *data_size);

/// @brief Write packet to given pcap file
/// @param infile input pcap file
/// @param outfile output pcap file
/// @param protocal protocol type (IP, TCP, UDP, RTP)
/// @param start start index
/// @param size write size per packet
/// @param data data to write
/// @param data_size data size
/// @return
int write_pacp(const char *infile, const char *outfile, int protocol, int start, int size, char *data, int data_size);