//gobode-labs
//eduardo m
//sniffer.cpp

#include "sniffer.h"                 // Include the header with function declarations and includes
#include <iostream>                   // For printing output to console
#include <iomanip>                    // For formatting output (hex values, widths)
#include <sstream>                    // For building string streams (to convert bytes to hex strings)
#include <fstream>                   // For file I/O to write JSON logs
#include <cstring>                   // For memory functions like memcpy if needed
#include <netinet/ip.h>              // For IP header structures (struct ip)
#include <netinet/tcp.h>             // For TCP header structures (struct tcphdr)
#include <netinet/udp.h>             // For UDP header structures (struct udphdr)
#include <arpa/inet.h>               // For inet_ntoa to convert IP addresses to string form
#include <openssl/evp.h>             // OpenSSL's high-level cryptographic functions (EVP API)
#include "json.hpp"                  // JSON library for outputting structured logs

using json = nlohmann::json;         // Alias for convenience

// Helper function to provide human-readable descriptions of well-known ports
std::string describe_port(int port) {
    // Use switch-case to match port numbers to common services
    switch (port) {
        case 20:  return "FTP Data";         // FTP data transfer port
        case 21:  return "FTP Control";      // FTP command/control port
        case 22:  return "SSH";               // Secure Shell for remote login
        case 23:  return "Telnet";            // Telnet remote login
        case 25:  return "SMTP";              // Simple Mail Transfer Protocol (email sending)
        case 53:  return "DNS";               // Domain Name System queries
        case 67:  return "DHCP Server";       // DHCP server port
        case 68:  return "DHCP Client";       // DHCP client port
        case 80:  return "HTTP";              // Web traffic (HTTP)
        case 110: return "POP3";              // Email retrieval protocol
        case 123: return "NTP";               // Network Time Protocol for time sync
        case 143: return "IMAP";              // Email retrieval protocol
        case 161: return "SNMP";              // Network management protocol
        case 194: return "IRC";               // Internet Relay Chat
        case 443: return "HTTPS";             // Secure web traffic (HTTP over TLS)
        case 465: return "SMTPS";             // SMTP over SSL
        case 514: return "Syslog";            // System logging service
        case 993: return "IMAPS";             // IMAP over SSL
        case 995: return "POP3S";             // POP3 over SSL
        default:  return "Unknown / Uncommon port";  // Catch-all for other ports
    }
}

// Generalized function to compute cryptographic hashes using OpenSSL EVP API
std::string compute_hash(const u_char* data, int len, const EVP_MD* md_type) {
    unsigned char hash[EVP_MAX_MD_SIZE];   // Buffer to hold the computed hash (max size)
    unsigned int hash_len = 0;             // Actual length of the hash after computation

    // Create a new message digest context (used to perform hashing)
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");  // Fail if context not allocated
    }

    // Initialize the context to use the specified hash algorithm (e.g., MD5, SHA256)
    if (EVP_DigestInit_ex(ctx, md_type, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);            // Free context to avoid memory leak
        throw std::runtime_error("Failed to initialize digest");
    }

    // Feed the input data (packet payload) into the hash function
    if (EVP_DigestUpdate(ctx, data, len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to update digest");
    }

    // Finalize the hash computation, writing the output hash to the buffer
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize digest");
    }

    // Free the context after finishing to prevent leaks
    EVP_MD_CTX_free(ctx);

    // Convert the raw binary hash data into a readable hexadecimal string
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        // Output each byte as two hex digits with leading zeros if needed
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();  // Return the hex string representation of the hash
}

// Specific wrappers for common hash algorithms
std::string compute_md5(const u_char* data, int len) {
    return compute_hash(data, len, EVP_md5());
}

std::string compute_sha1(const u_char* data, int len) {
    return compute_hash(data, len, EVP_sha1());
}

std::string compute_sha256(const u_char* data, int len) {
    return compute_hash(data, len, EVP_sha256());
}

std::string compute_sha512(const u_char* data, int len) {
    return compute_hash(data, len, EVP_sha512());
}

// Callback function invoked by pcap for each captured packet
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    (void)user_data;  // Mark user_data as unused to avoid compiler warnings

    // The first 14 bytes of the packet are the Ethernet header,
    // so the IP header starts immediately after it.
    const struct ip* ip_hdr = (struct ip*)(packet + 14);

    // Convert the source and destination IP addresses from numeric form
    // to standard dot-decimal string format (e.g., "192.168.1.1").
    std::string src_ip = inet_ntoa(ip_hdr->ip_src);
    std::string dst_ip = inet_ntoa(ip_hdr->ip_dst);

    // Identify the IP protocol field to determine the transport layer protocol.
    // IPPROTO_TCP = 6, IPPROTO_UDP = 17
    std::string protocol = (ip_hdr->ip_p == IPPROTO_TCP) ? "TCP" :
                           (ip_hdr->ip_p == IPPROTO_UDP) ? "UDP" : "OTHER";

    // Initialize source and destination ports to zero.
    // These will be set only if the protocol is TCP or UDP.
    int src_port = 0, dst_port = 0;

    // Extract port numbers if the protocol is TCP or UDP.
    // The IP header length (ip_hl) is in 4-byte words, so multiply by 4 to get bytes.
    if (protocol == "TCP") {
        // TCP header follows IP header; cast pointer accordingly.
        const struct tcphdr* tcp_hdr = (struct tcphdr*)(packet + 14 + ip_hdr->ip_hl * 4);
        src_port = ntohs(tcp_hdr->th_sport);  // Convert from network byte order to host byte order
        dst_port = ntohs(tcp_hdr->th_dport);
    } else if (protocol == "UDP") {
        // UDP header follows IP header similarly.
        const struct udphdr* udp_hdr = (struct udphdr*)(packet + 14 + ip_hdr->ip_hl * 4);
        src_port = ntohs(udp_hdr->uh_sport);
        dst_port = ntohs(udp_hdr->uh_dport);
    }

    // Calculate the offset in the packet where the payload starts:
    // Ethernet header (14 bytes) + IP header (variable length) +
    // TCP header (20 bytes fixed) or UDP header (8 bytes fixed)
    int payload_offset = 14 + ip_hdr->ip_hl * 4 + ((protocol == "TCP") ? 20 : (protocol == "UDP") ? 8 : 0);

    // Calculate the length of the payload data by subtracting
    // the headers length from the total packet length.
    int payload_len = pkthdr->len - payload_offset;

    // Pointer to the start of the payload data in the packet buffer.
    const u_char* payload = packet + payload_offset;

    // Compute cryptographic hashes on the payload data using the OpenSSL EVP functions.
    std::string md5_hash = compute_md5(payload, payload_len);
    std::string sha1_hash = compute_sha1(payload, payload_len);
    std::string sha256_hash = compute_sha256(payload, payload_len);
    std::string sha512_hash = compute_sha512(payload, payload_len);

    // Prepare the JSON log entry:
    // Include timestamp, IP addresses, protocol, ports with descriptions,
    // and all computed hashes for the payload.
    json log_entry = {
        {"timestamp", pkthdr->ts.tv_sec},                  // Packet capture timestamp (seconds since epoch)
        {"source_ip", src_ip},                             // Source IP address as string
        {"destination_ip", dst_ip},                        // Destination IP address as string
        {"protocol", protocol},                            // Transport protocol (TCP/UDP/OTHER)
        {"source_port", src_port},                         // Source port number (0 if none)
        {"source_port_description", describe_port(src_port)},  // Description of source port's typical use
        {"destination_port", dst_port},                    // Destination port number (0 if none)
        {"destination_port_description", describe_port(dst_port)}, // Description of destination port
        {"payload_hashes", {                               // Nested JSON object containing all hashes
            {"MD5", md5_hash},
            {"SHA1", sha1_hash},
            {"SHA256", sha256_hash},
            {"SHA512", sha512_hash}
        }}
    };

    // Open the JSON log file in append mode, so new entries are added
    // without overwriting previous data.
    std::ofstream log_file("sniffer_log.json", std::ios::app);
    if (!log_file) {
        std::cerr << "Error: Unable to open sniffer_log.json for writing." << std::endl;
        return;
    }

    // Write the JSON object in a nicely formatted way (indent 4 spaces)
    log_file << log_entry.dump(4) << std::endl;

    // Close the log file to ensure data is flushed to disk.
    log_file.close();

    // Inform the user on the console that a packet was processed and logged.
    std::cout << "[*] Packet logged with hashes and port info." << std::endl;
}

