//gobode-labs
//Eduardo M
// sniffer.h
#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>          // For packet capturing with libpcap
#include <string>          // For using std::string

// Function to compute SHA-256 hash of a data buffer
std::string compute_sha256(const u_char* data, int len);

// Callback function to process packets captured by pcap
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif // SNIFFER_H

