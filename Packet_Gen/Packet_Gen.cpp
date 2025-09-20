// Packet generator code
#ifdef _WIN32
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")  // Link with Winsock library
#else
#include <arpa/inet.h>
#endif

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <random>
#include <iomanip>
#include <sstream>

#pragma pack(push, 1)

// Ethernet header
struct EthernetHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
};

// IPv4 header
struct IPv4Header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

// TCP header
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

// DCE/RPC header
struct DCERPCHeader {
    uint8_t version;
    uint8_t version_minor;
    uint8_t packet_type;
    uint8_t fragment_flags;
    uint8_t data_representation[4];
    uint16_t fragment_length;
    uint16_t auth_length;
    uint32_t call_id;
    uint16_t operation_number;
};

#pragma pack(pop)

class RPCPacketGenerator {
private:
    std::mt19937 rng;

    uint16_t calculate_checksum(const uint8_t* data, size_t len) {
        uint32_t sum = 0;

        // Process pairs of bytes
        for (size_t i = 0; i < len - 1; i += 2) {
            sum += (data[i] << 8) + data[i + 1];
        }

        // Add odd byte if present
        if (len % 2 == 1) {
            sum += data[len - 1] << 8;
        }

        // Fold 32-bit sum to 16 bits
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return ~sum;
    }

    uint32_t string_to_ip(const std::string& ip) {
        uint32_t addr = 0;
        int shift = 24;
        size_t start = 0, end = 0;

        for (int i = 0; i < 4; ++i) {
            end = ip.find('.', start);
            if (end == std::string::npos) end = ip.length();

            // Replace std::stoi with a custom string-to-int conversion for compatibility
            int octet = 0;
            std::istringstream iss(ip.substr(start, end - start));
            iss >> octet;

            addr |= (octet << shift);
            shift -= 8;
            start = end + 1;
        }

        return htonl(addr);
    }

public:
    RPCPacketGenerator() : rng(std::random_device{}()) {}

    std::vector<uint8_t> generate_rpc_packet(
        const std::string& src_ip = "10.0.0.100",
        const std::string& dst_ip = "10.0.0.200",
        uint16_t src_port = 49152,
        uint16_t dst_port = 135,
        const std::string& interface_uuid = "367abb81-9844-35f1-ad32-98f038001003", // Service Control Manager
        uint16_t operation_num = 23, // CreateServiceW
        uint8_t packet_type = 0, // request
        const std::string& payload_data = ""
    ) {

        std::vector<uint8_t> packet;

        // Ethernet Header
        EthernetHeader eth_hdr = {};
        // Destination MAC (fake)
        eth_hdr.dst_mac[0] = 0x00; eth_hdr.dst_mac[1] = 0x11; eth_hdr.dst_mac[2] = 0x22;
        eth_hdr.dst_mac[3] = 0x33; eth_hdr.dst_mac[4] = 0x44; eth_hdr.dst_mac[5] = 0x55;
        // Source MAC (fake)
        eth_hdr.src_mac[0] = 0xAA; eth_hdr.src_mac[1] = 0xBB; eth_hdr.src_mac[2] = 0xCC;
        eth_hdr.src_mac[3] = 0xDD; eth_hdr.src_mac[4] = 0xEE; eth_hdr.src_mac[5] = 0xFF;
        eth_hdr.ethertype = htons(0x0800); // IPv4

        // IPv4 Header
        IPv4Header ip_hdr = {};
        ip_hdr.version_ihl = 0x45; // Version 4, IHL 5
        ip_hdr.tos = 0;
        ip_hdr.identification = htons(0x1234);
        ip_hdr.flags_fragment = htons(0x4000); // Don't fragment
        ip_hdr.ttl = 64;
        ip_hdr.protocol = 6; // TCP
        ip_hdr.src_addr = string_to_ip(src_ip);
        ip_hdr.dst_addr = string_to_ip(dst_ip);

        // TCP Header
        TCPHeader tcp_hdr = {};
        tcp_hdr.src_port = htons(src_port);
        tcp_hdr.dst_port = htons(dst_port);
        tcp_hdr.seq_num = htonl(0x12345678);
        tcp_hdr.ack_num = htonl(0x87654321);
        tcp_hdr.data_offset_reserved = 0x50; // Data offset 5 (20 bytes)
        tcp_hdr.flags = 0x18; // PSH + ACK
        tcp_hdr.window = htons(8192);
        tcp_hdr.urgent_ptr = 0;

        // DCE/RPC Header
        DCERPCHeader rpc_hdr = {};
        rpc_hdr.version = 5;
        rpc_hdr.version_minor = 0;
        rpc_hdr.packet_type = packet_type;
        rpc_hdr.fragment_flags = 0x03; // First and last fragment
        rpc_hdr.data_representation[0] = 0x10; // Little endian
        rpc_hdr.data_representation[1] = 0x00;
        rpc_hdr.data_representation[2] = 0x00;
        rpc_hdr.data_representation[3] = 0x00;
        rpc_hdr.auth_length = 0;
        rpc_hdr.call_id = htonl(0xABCDEF00);
        rpc_hdr.operation_number = htons(operation_num);

        // Convert UUID string to bytes
        std::vector<uint8_t> uuid_bytes;
        std::string uuid_clean = interface_uuid;
        uuid_clean.erase(std::remove(uuid_clean.begin(), uuid_clean.end(), '-'), uuid_clean.end());

        for (size_t i = 0; i < uuid_clean.length(); i += 2) {
            std::string byte_str = uuid_clean.substr(i, 2);
            uuid_bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
        }

        // Create test payload with suspicious patterns
        std::string test_payload = payload_data;
        if (test_payload.empty()) {
            test_payload = "psexec.exe -s -i cmd.exe"; // This will trigger threat detection
        }

        // Calculate total RPC payload size
        size_t rpc_payload_size = sizeof(DCERPCHeader) + uuid_bytes.size() + test_payload.length();
        rpc_hdr.fragment_length = htons(static_cast<uint16_t>(rpc_payload_size));

        // Calculate IP total length
        size_t ip_total_len = sizeof(IPv4Header) + sizeof(TCPHeader) + rpc_payload_size;
        ip_hdr.total_length = htons(static_cast<uint16_t>(ip_total_len));

        // Build packet
        packet.reserve(sizeof(EthernetHeader) + ip_total_len);

        // Add Ethernet header
        const uint8_t* eth_ptr = reinterpret_cast<const uint8_t*>(&eth_hdr);
        packet.insert(packet.end(), eth_ptr, eth_ptr + sizeof(EthernetHeader));

        // Add IP header (will calculate checksum later)
        const uint8_t* ip_ptr = reinterpret_cast<const uint8_t*>(&ip_hdr);
        packet.insert(packet.end(), ip_ptr, ip_ptr + sizeof(IPv4Header));

        // Add TCP header (will calculate checksum later)
        const uint8_t* tcp_ptr = reinterpret_cast<const uint8_t*>(&tcp_hdr);
        packet.insert(packet.end(), tcp_ptr, tcp_ptr + sizeof(TCPHeader));

        // Add RPC header
        const uint8_t* rpc_ptr = reinterpret_cast<const uint8_t*>(&rpc_hdr);
        packet.insert(packet.end(), rpc_ptr, rpc_ptr + sizeof(DCERPCHeader));

        // Add UUID
        packet.insert(packet.end(), uuid_bytes.begin(), uuid_bytes.end());

        // Add payload
        packet.insert(packet.end(), test_payload.begin(), test_payload.end());

        // Calculate and set IP checksum
        size_t ip_hdr_offset = sizeof(EthernetHeader);
        uint16_t ip_checksum = calculate_checksum(&packet[ip_hdr_offset], sizeof(IPv4Header));
        *reinterpret_cast<uint16_t*>(&packet[ip_hdr_offset + 10]) = ip_checksum;

        // Calculate and set TCP checksum (simplified - normally includes pseudo-header)
        size_t tcp_hdr_offset = sizeof(EthernetHeader) + sizeof(IPv4Header);
        uint16_t tcp_checksum = calculate_checksum(&packet[tcp_hdr_offset], sizeof(TCPHeader) + rpc_payload_size);
        *reinterpret_cast<uint16_t*>(&packet[tcp_hdr_offset + 16]) = tcp_checksum;

        return packet;
    }

    void generate_test_suite() {
        std::cout << "Generating RPC packet test suite..." << std::endl;

        // Test 1: Service Control Manager - CreateServiceW (High threat)
        auto packet1 = generate_rpc_packet(
            "192.168.1.100", "192.168.1.200", 49152, 135,
            "367abb81-9844-35f1-ad32-98f038001003", 23, 0,
            "psexec -s -i -d cmd.exe /c powershell.exe -enc SQBuAHYAbwBrAGUA"
        );
        write_packet_to_file("test_scm_create_service.bin", packet1);

        // Test 2: DRSUAPI - DRSGetNCChanges (DCSync attack)
        auto packet2 = generate_rpc_packet(
            "10.0.0.50", "10.0.0.10", 50123, 135,
            "e3514235-4b06-11d1-ab04-00c04fc2dcd2", 3, 0,
            "mimikatz dcsync /domain:example.com /user:Administrator"
        );
        write_packet_to_file("test_dcsync_attack.bin", packet2);

        // Test 3: Task Scheduler - Register Task
        auto packet3 = generate_rpc_packet(
            "172.16.1.100", "172.16.1.200", 51234, 135,
            "86d35949-83c9-4044-b424-db363231fd0c", 1, 0,
            "schtasks /create /tn backdoor /tr C:\\windows\\system32\\backdoor.exe /sc onlogon"
        );
        write_packet_to_file("test_schtasks_backdoor.bin", packet3);

        // Test 4: Print Spooler (PrintNightmare)
        auto packet4 = generate_rpc_packet(
            "10.10.10.100", "10.10.10.200", 52345, 135,
            "12345678-1234-abcd-ef00-0123456789ab", 0, 0,
            "\\\\attacker-server\\share\\evil.dll"
        );
        write_packet_to_file("test_printnightmare.bin", packet4);

        // Test 5: Cross-border threat (simulated Chinese IP)
        auto packet5 = generate_rpc_packet(
            "202.108.22.5", "192.168.1.100", 45678, 135,
            "367abb81-9844-35f1-ad32-98f038001003", 19, 0,
            "cobalt strike beacon payload encrypted data here..."
        );
        write_packet_to_file("test_cross_border_threat.bin", packet5);

        // Test 6: Bind request
        auto packet6 = generate_rpc_packet(
            "192.168.1.50", "192.168.1.100", 49999, 135,
            "367abb81-9844-35f1-ad32-98f038001003", 0, 11, // bind packet
            "standard rpc bind request"
        );
        write_packet_to_file("test_rpc_bind.bin", packet6);

        std::cout << "Generated 6 test packets:" << std::endl;
        std::cout << "1. test_scm_create_service.bin - Service creation with PSExec" << std::endl;
        std::cout << "2. test_dcsync_attack.bin - DCSync attack simulation" << std::endl;
        std::cout << "3. test_schtasks_backdoor.bin - Scheduled task backdoor" << std::endl;
        std::cout << "4. test_printnightmare.bin - Print spooler exploitation" << std::endl;
        std::cout << "5. test_cross_border_threat.bin - Cross-border attack" << std::endl;
        std::cout << "6. test_rpc_bind.bin - Standard RPC bind request" << std::endl;
    }

private:
    void write_packet_to_file(const std::string& filename, const std::vector<uint8_t>& packet) {
        std::ofstream file(filename, std::ios::binary);
        if (file.is_open()) {
            file.write(reinterpret_cast<const char*>(packet.data()), packet.size());
            file.close();
            std::cout << "Written " << packet.size() << " bytes to " << filename << std::endl;
        }
        else {
            std::cerr << "Failed to open " << filename << " for writing" << std::endl;
        }
    }
};

int main() {
    RPCPacketGenerator generator;
    generator.generate_test_suite();

    std::cout << "\nTest packets generated successfully!" << std::endl;
    std::cout << "Use these files with your parser like:" << std::endl;
    std::cout << "./your_parser test_scm_create_service.bin" << std::endl;

    return 0;
}