# Define the C++ compiler to use
CXX = g++

# Define compiler flags
# -std=c++17 : Use C++17 standard
# -Wall      : Enable most common warning messages
# -Wextra    : Enable extra warnings to help identify potential issues
CXXFLAGS = -std=c++17 -Wall -Wextra

# Define libraries to link
# -lpcap     : Link the libpcap library for packet capturing
# -lssl      : Link OpenSSL library (used for SHA-256 hashing)
# -lcrypto   : Link OpenSSL cryptographic library
LDFLAGS = -lpcap -lssl -lcrypto

# Define the name of the final binary executable
TARGET = hash_sniffer

# List of source files (you can add more .cpp files if needed)
SRCS = main.cpp sniffer.cpp

# Automatically create object files from source files by replacing .cpp with .o
OBJS = $(SRCS:.cpp=.o)

# Default target: when 'make' is run with no arguments, this target is used
all: $(TARGET)

# Rule to link all object files into the final binary
# $@ represents the target file (e.g., hash_sniffer)
# $^ represents all dependencies (e.g., main.o sniffer.o)
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Rule to compile each .cpp file into an object (.o) file
# $< represents the source file (e.g., main.cpp)
# $@ represents the output object file (e.g., main.o)
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Custom command to clean up compiled files
# Use 'make clean' to remove the binary, object files, and the log
clean:
	rm -f $(TARGET) $(OBJS) sniffer_log.json

