//gobode-labs
//eduardo m
// main.c

#include <iostream>             // For standard input/output
#include <pcap.h>               // For pcap packet capture functions
#include <cstring>              // For memset and strerror
#include <cstdlib>              // For exit()
#include "sniffer.h"            // Your sniffer function declarations

int main(int argc, char* argv[]) {
    // Step 1: Check if the user provided an interface name as a command line argument.
    // If not, print usage info and exit.
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <network_interface>" << std::endl;
        std::cerr << "Example: " << argv[0] << " eth0" << std::endl;
        return 1;
    }

    const char* dev = argv[1];  // Network interface to listen on (e.g., eth0, wlan0)

    // Step 2: Error buffer to hold error messages from pcap functions.
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);  // Clear buffer to avoid garbage data

    // Step 3: Open the network device for live capture.
    // Parameters:
    //   dev: interface name
    //   snaplen: max number of bytes to capture per packet (65535 to capture full packet)
    //   promiscuous: 1 to capture all packets including those not destined for this host
    //   timeout_ms: read timeout in milliseconds (1000ms here)
    //   errbuf: error message buffer
    pcap_t* handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device " << dev << ": " << errbuf << std::endl;
        return 1;
    }

    // Step 4: Compile a packet filter to capture only TCP and UDP packets.
    // This reduces the amount of irrelevant traffic your program needs to process.
    struct bpf_program fp;
    const char filter_exp[] = "tcp or udp";  // BPF filter expression

    // Compile the filter expression into BPF bytecode
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Failed to compile filter '" << filter_exp << "': "
                  << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    // Apply the compiled filter to the capture handle
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Failed to set filter '" << filter_exp << "': "
                  << pcap_geterr(handle) << std::endl;
        pcap_freecode(&fp);
        pcap_close(handle);
        return 1;
    }

    // Free the compiled filter structure as it is no longer needed
    pcap_freecode(&fp);

    // Step 5: Print informational message
    std::cout << "Starting packet capture on interface: " << dev << std::endl;
    std::cout << "Filtering only TCP and UDP packets." << std::endl;

    // Step 6: Start the capture loop.
    // -1 means capture indefinitely until manually stopped (Ctrl+C)
    // packet_handler is the callback function to process each captured packet
    if (pcap_loop(handle, -1, packet_handler, nullptr) == -1) {
        std::cerr << "Error occurred while capturing packets: "
                  << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    // Step 7: Close the capture handle when done to free resources
    pcap_close(handle);

    // Step 8: Inform the user that capture has ended (if it ever exits the loop)
    std::cout << "Packet capture ended." << std::endl;

    return 0;  // Exit program successfully
}

