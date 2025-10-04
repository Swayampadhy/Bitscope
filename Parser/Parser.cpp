// The Parser code of the project
//
// * -> You are here
// Packet Capture -> *Parser/Threat Intelligence -> Alert

#define _CRT_SECURE_NO_WARNINGS 1

// Necessary headers
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <map>
#include <vector>
#include <set>
#include <algorithm>
#include <regex>
#include <memory>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <cstring>
// Concurrency headers
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <future>
#include <functional>
// Platform-specific headers
#ifdef _WIN32
#include <winsock2.h>
#endif
// OpenSSL for hashing
#include <openssl/sha.h>
// PcapPlusPlus for packet parsing
#include "PcapPlusPlus/Packet.h"
#include "PcapPlusPlus/IPv4Layer.h"
#include "PcapPlusPlus/IPv6Layer.h"
#include "PcapPlusPlus/TcpLayer.h"
#include "PcapPlusPlus/UdpLayer.h"
#include "PcapPlusPlus/PayloadLayer.h"
// MaxMindDB for geolocation
#include <maxminddb.h>
// JSON for structured output
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ThreadPool implementation for concurrent processing
class ThreadPool {
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;

public:
    ThreadPool(size_t threads) : stop(false) {
        for (size_t i = 0; i < threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this] {
                            return this->stop || !this->tasks.empty();
                        });

                        if (this->stop && this->tasks.empty()) {
                            return;
                        }

                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }
                    task();
                }
            });
        }
    }
	// Enqueue a new task
    template<class F, class... Args>
    auto enqueue(F&& f, Args&&... args)
        -> std::future<typename std::result_of<F(Args...)>::type> {
        using return_type = typename std::result_of<F(Args...)>::type;

        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
        );

        std::future<return_type> res = task->get_future();
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if (stop) {
                throw std::runtime_error("enqueue on stopped ThreadPool");
            }
            tasks.emplace([task]() { (*task)(); });
        }
        condition.notify_one();
        return res;
    }
	// Destructor
    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread& worker : workers) {
            worker.join();
        }
    }
};
// DCERPC Header structure
#pragma pack(push, 1)
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

// Session information structure
struct SessionInfo {
    std::string session_id;
    std::string conversation_id;
    std::time_t start_time;
    int packet_count;
    bool is_new;
};

// Authentication information structure
struct AuthInfo {
    bool auth_present = false;
    std::string auth_type = "None";
    std::string auth_level = "none";
    std::string impersonation_level = "anonymous";
    bool bypass_detected = false;
    bool suspicious_auth = false;
};

// Payload analysis structure
struct PayloadAnalysis {
    bool contains_sensitive_data = false;
    bool encryption_detected = false;
    std::vector<std::string> suspicious_patterns;
    struct StringAnalysis {
        bool contains_unicode = false;
        bool contains_base64 = false;
        bool contains_urls = false;
        bool contains_file_paths = false;
        bool contains_registry_keys = false;
        bool contains_credentials = false;
        bool contains_powershell = false;
        bool contains_executable_extensions = false;
    } string_analysis;
};

// SMB session information structure
struct SMBInfo {
    std::string named_pipe;
    uint16_t tree_id = 0;
    uint32_t session_id = 0;
    bool is_smb_transport = false;
};

// UUID to interface mapping
std::unordered_map<std::string, std::string> uuid_to_interface = {

    // Core Windows Services - High Attack Value
    {"367abb81-9844-35f1-ad32-98f038001003", "Service Control Manager"},
    {"86d35949-83c9-4044-b424-db363231fd0c", "Task Scheduler"},
    {"4b324fc8-1670-01d3-1278-5a47bf6ee188", "Server Service"},
    {"6bffd098-a112-3610-9833-46c3f87e345a", "Workstation Service"},
    {"12345678-1234-abcd-ef00-0123456789ab", "Print Spooler"},
    {"338cd001-2244-31f1-aaaa-900038001003", "Registry"},

    // Active Directory & Authentication Services
    {"e3514235-4b06-11d1-ab04-00c04fc2dcd2", "DRSUAPI"}, // DCSync attacks
    {"12345778-1234-abcd-ef00-0123456789ac", "SAMR"}, // User enumeration
    {"12345778-1234-abcd-ef00-01234567cffb", "LSARPC"}, // LSA policy access
    {"c681d488-d850-11d0-8c52-00c04fd90f7e", "LSASS"}, // LSASS access
    {"12345678-1234-abcd-ef00-01234567cffb", "Netlogon"}, // Domain authentication
	{"894de0c0-0d55-11d3-a322-00c04fa321a1", "Windows Management Instrumentation"}, // WMI lateral movement

    // File System & Share Access
    {"4fc742e0-4a10-11cf-8273-00aa004ae673", "Distributed File System"},
    {"df1941c5-fe89-4e79-bf10-463657acf44d", "File Replication Service"},
    {"d049b186-814f-11d1-9a3c-00c04fc9b232", "Network DDE"},
    {"906b0ce0-c70b-1067-b317-00dd010662da", "Message Queuing"},

    // Security & Certificate Services
    {"d95afe70-a6d5-4259-822e-2c84da1ddb0d", "Certificate Authority"},
    {"91ae6020-9e3c-11cf-8d7c-00aa00c091be", "Certificate Services DCOM"},
    {"12345678-1234-abcd-ef00-0123456789ef", "Windows Firewall"},
    {"f120a684-b926-447f-9df4-c966cb785648", "Windows Security Center"},

    // Network & Remote Access
    {"8fb6d884-2388-11d0-8c35-00c04fda2795", "Windows Installer"},
    {"d61a27c6-8f53-11d0-bfa0-00a024151983", "Remote Access Server"},
    {"12345678-1234-abcd-ef00-0123456789cd", "RADIUS Authentication"},
    {"6139d8a4-e508-4ebb-bac7-d7f275145897", "VPN Service"},

    // System Management
    {"45f52c28-7f9f-101a-b52b-08002b2efabe", "Windows Management"},
    {"975201b0-59ca-11d0-a8d5-00a0c90d8051", "Distributed Transaction Coordinator"},
    {"4d9f4ab8-7d1c-11cf-861e-0020af6e7c57", "Cluster Service"},
    {"2f5f3220-c126-1076-b549-074d078619da", "Indexing Service"},

    // Event & Logging Services
    {"82273fdc-e32a-18c3-3f78-827929dc23ea", "Event Log Service"},
    {"12345678-1234-abcd-ef00-0123456789gh", "Windows Event Collector"},
    {"1c118904-389d-4e21-a6ce-7b4d8e8e5d94", "Performance Logs and Alerts"},

    // Terminal Services & Remote Desktop
    {"484809d6-4239-471b-b5bc-61df8c23ac48", "Terminal Services"},
    {"5ca4a760-ebb1-11cf-8611-00a0245420ed", "Remote Desktop Services"},
    {"12345678-1234-abcd-ef00-0123456789ij", "Terminal Services Session Directory"},

    // Print & Spooler Services (PrintNightmare)
    {"76f03f96-cdfd-44fc-a22c-64950a001209", "Print System Service"},
    {"ae33069b-a2a8-46ee-a235-ddfd339be281", "Print System Remote Protocol"},
    {"12345678-1234-abcd-ef00-0123456789kl", "Fax Service"},

    // Backup & Recovery Services  
    {"833e4010-aff7-4ac3-aac2-9f24c1457bce", "Volume Shadow Copy"},
    {"d61a27c6-8f53-11d0-bfa0-00a024151984", "Backup Service"},
    {"12345678-1234-abcd-ef00-0123456789mn", "System Restore Service"},

    // DNS & Name Resolution
    {"50abc2a4-574d-40b3-9d66-ee4fd5fba076", "DNS Server Service"},
    {"7c44d7d4-31d5-424c-bd5e-2b3e1f323d22", "DNS Client Service"},

    // Storage & Virtualization
    {"b58aa02e-2884-4e97-8176-4ee06d794184", "Storage Service"},
    {"12345678-1234-abcd-ef00-0123456789op", "Hyper-V Management"},

    // Web Services & IIS
    {"2d7a20ad-abb9-4671-8cd4-66515f069231", "IIS Admin Service"},
    {"12345678-1234-abcd-ef00-0123456789qr", "World Wide Web Publishing"},

    // Database Services
    {"17fdd703-1827-4e34-79d4-24a55c53bb37", "SQL Server"},
    {"12345678-1234-abcd-ef00-0123456789st", "SQL Server Browser"},

    // Legacy & Vulnerable Services
    {"4d36e972-e325-11ce-bfc1-08002be10318", "Plug and Play"}, 
    {"12345678-1234-abcd-ef00-0123456789uv", "Telephony Service"},
    {"8d0ffe72-d252-11d0-bf8f-00c04fd9126b", "Windows Time Service"}
};

// Operation mappings
std::unordered_map<std::string, std::unordered_map<int, std::string>> operation_mappings = {
    {"367abb81-9844-35f1-ad32-98f038001003", { // Service Control Manager
        {0, "OpenSCManagerW"}, {2, "EnumServicesStatusW"}, {15, "OpenServiceW"},
        {16, "QueryServiceConfigW"}, {17, "QueryServiceLockStatusW"}, {18, "QueryServiceObjectSecurity"},
        {19, "StartServiceW"}, {20, "ControlService"}, {21, "SetServiceStatus"},
        {22, "DeleteService"}, {23, "CreateServiceW"}, {24, "ChangeServiceConfigW"}
    }},
    {"e3514235-4b06-11d1-ab04-00c04fc2dcd2", { // DRSUAPI - DCSync
        {0, "DRSBind"}, {1, "DRSUnbind"}, {2, "DRSReplicaSync"}, {3, "DRSGetNCChanges"},
        {4, "DRSUpdateRefs"}, {5, "DRSReplicaAdd"}, {6, "DRSReplicaDel"}, {7, "DRSReplicaModify"}
    }},
    {"12345778-1234-abcd-ef00-0123456789ac", { // SAMR
        {0, "SamConnect"}, {1, "SamCloseHandle"}, {2, "SamSetSecurityObject"}, {3, "SamQuerySecurityObject"},
        {5, "SamLookupDomainInSamServer"}, {6, "SamEnumerateDomainsInSamServer"}, {7, "SamOpenDomain"},
        {8, "SamQueryInformationDomain"}, {9, "SamSetInformationDomain"}, {11, "SamLookupNamesInDomain"},
        {12, "SamLookupIdsInDomain"}, {15, "SamCreateUser2InDomain"}, {16, "SamEnumerateUsersInDomain"}
    }},
    {"86d35949-83c9-4044-b424-db363231fd0c", { // Task Scheduler
        {0, "SchRpcHighestVersion"}, {1, "SchRpcRegisterTask"}, {2, "SchRpcRetrieveTask"},
        {3, "SchRpcCreateFolder"}, {4, "SchRpcSetSecurity"}, {5, "SchRpcGetSecurity"},
        {6, "SchRpcEnumFolders"}, {7, "SchRpcEnumTasks"}, {8, "SchRpcEnumInstances"},
        {9, "SchRpcGetInstanceInfo"}, {10, "SchRpcStopInstance"}, {11, "SchRpcStop"},
        {12, "SchRpcRun"}, {13, "SchRpcDelete"}, {14, "SchRpcRename"}, {15, "SchRpcScheduledRuntimes"}
    }},
    {"12345678-1234-abcd-ef00-0123456789ab", { // Print Spooler
        {0, "RpcOpenPrinter"}, {1, "RpcClosePrinter"}, {2, "RpcStartDocPrinter"},
        {3, "RpcEndDocPrinter"}, {4, "RpcAddJob"}, {5, "RpcScheduleJob"},
        {6, "RpcGetPrinter"}, {7, "RpcSetPrinter"}, {8, "RpcGetPrinterDriver"},
        {9, "RpcGetPrinterDriverDirectory"}, {10, "RpcDeletePrinterDriver"},
        {11, "RpcAddPrintProcessor"}, {12, "RpcEnumPrintProcessors"},
        {13, "RpcGetPrintProcessorDirectory"}, {14, "RpcEnumPrintProcessorDatatypes"},
        {15, "RpcStartPagePrinter"}, {16, "RpcEndPagePrinter"}, {17, "RpcAbortPrinter"},
        {18, "RpcReadPrinter"}, {19, "RpcWritePrinter"}, {20, "RpcSplOpenPrinter"}
    }}
};

// Packet type mapping
std::unordered_map<uint8_t, std::string> packet_types = {
    {0, "request"},
    {2, "response"},
    {11, "bind"},
    {12, "bind_ack"},
    {13, "bind_nak"},
    {3, "fault"},
    {14, "alter_context"}
};

// Geographic Risk Assessment Engine
class GeographicRiskAssessment {
private:
    // High-risk countries based on threat intelligence feeds
    std::unordered_map<std::string, int> country_risk_scores = {
        // Tier 1 - Critical Risk (90-100)
        {"CN", 95}, {"RU", 95}, {"KP", 100}, {"IR", 90}, {"SY", 85},

        // Tier 2 - High Risk (70-89) 
        {"VN", 85}, {"BD", 80}, {"PK", 80}, {"NG", 75}, {"GH", 75},
        {"ID", 75}, {"IN", 70}, {"BR", 70}, {"MX", 70}, {"TR", 75},

        // Tier 3 - Medium-High Risk (50-69)
        {"RO", 65}, {"BG", 60}, {"UA", 65}, {"PL", 55}, {"CZ", 50},
        {"HU", 55}, {"RS", 60}, {"BA", 55}, {"HR", 50}, {"SK", 50},

        // Tier 4 - Medium Risk (30-49)
        {"IT", 45}, {"ES", 40}, {"GR", 45}, {"PT", 35}, {"LT", 40},
        {"LV", 40}, {"EE", 35}, {"SI", 30}, {"MT", 30}, {"CY", 35},

        // Tier 5 - Low-Medium Risk (10-29)
        {"FR", 25}, {"DE", 20}, {"NL", 15}, {"BE", 20}, {"LU", 10},
        {"AT", 15}, {"IE", 15}, {"FI", 15}, {"SE", 10}, {"DK", 10},

        // Tier 6 - Low Risk (0-9)
        {"NO", 5}, {"IS", 5}, {"CH", 5}, {"LI", 5}, {"MC", 5},
        {"AD", 5}, {"SM", 5}, {"VA", 0}, {"AU", 10}, {"NZ", 5},
        {"CA", 15}, {"US", 20}, {"GB", 15}, {"JP", 15}, {"KR", 20},
        {"SG", 15}, {"HK", 25}, {"TW", 30}
    };

    // High-risk ASNs based on hosting providers and known malicious infrastructure
    std::unordered_map<int, int> asn_risk_scores = {
        // Bulletproof hosting / VPS providers (High Risk 80-100)
        {16276, 95}, // OVH (known for abuse)
        {24940, 90}, // Hetzner Online (hosting)
        {62217, 95}, // Monarch Digital (bulletproof)
        {39572, 85}, // Secured Servers (hosting)
        {29073, 80}, // DataShack (hosting)

        // Cloud providers (Medium Risk 30-60)
        {16509, 40}, // Amazon AWS
        {15169, 35}, // Google Cloud
        {8075, 45},  // Microsoft Azure
        {13335, 50}, // Cloudflare
        {20940, 45}, // Akamai

        // Residential ISPs (Low Risk 5-25)
        {7922, 15},  // Comcast
        {20115, 20}, // Charter Communications
        {7018, 10},  // AT&T
        {701, 10},   // Verizon
        {3320, 15},  // Deutsche Telekom

        // Tor Exit Nodes and VPN Providers (Very High Risk 90-100)
        {8560, 100}, // IONOS (Tor hosting)
        {42473, 95}, // AS-ANEXIA (VPN)
        {51167, 90}, // CONTABO (VPN hosting)
        {60068, 85}  // CDN77 (proxy services)
    };

    // Geopolitical risk factors
    std::unordered_map<std::string, std::vector<std::string>> geopolitical_tensions = {
        {"US", {"CN", "RU", "IR", "KP"}},
        {"GB", {"RU", "CN", "IR"}},
        {"AU", {"CN", "RU", "KP"}},
        {"JP", {"CN", "RU", "KP"}},
        {"KR", {"CN", "RU", "KP"}},
        {"IL", {"IR", "SY", "LB"}},
        {"UA", {"RU", "BY"}},
        {"TW", {"CN"}},
        {"IN", {"CN", "PK"}}
    };

public:
	// Calculate risk score based on country code
    int calculate_country_risk(const std::string& country_code) {
        auto it = country_risk_scores.find(country_code);
        return (it != country_risk_scores.end()) ? it->second : 30; // Default medium risk
    }

	// Calculate risk score based on ASN
    int calculate_asn_risk(int asn) {
        auto it = asn_risk_scores.find(asn);
        return (it != asn_risk_scores.end()) ? it->second : 25; // Default low-medium risk
    }

	// Check for cross-border geopolitical tensions
    bool is_cross_border_high_risk(const std::string& src_country, const std::string& dst_country) {
        auto it = geopolitical_tensions.find(dst_country);
        if (it != geopolitical_tensions.end()) {
            return std::find(it->second.begin(), it->second.end(), src_country) != it->second.end();
        }
        return false;
    }

	// Assess overall geographic risk
    std::string assess_geographic_risk(int country_risk, int asn_risk, bool cross_border_risk, bool is_internal) {
        if (is_internal) return "low";

        int total_risk = (country_risk * 0.6) + (asn_risk * 0.3) + (cross_border_risk ? 20 : 0);

        if (total_risk >= 75) return "critical";
        if (total_risk >= 50) return "high";
        if (total_risk >= 25) return "medium";
        return "low";
    }
};

// Network Topology and CIDR Configuration
class NetworkTopology {
private:
    struct CIDRRange {
        uint32_t network;
        uint32_t mask;
        std::string description;
    };

    std::vector<CIDRRange> internal_networks;
    std::vector<CIDRRange> dmz_networks;
    std::vector<CIDRRange> management_networks;

	// Parse CIDR notation into network and mask
    CIDRRange parse_cidr(const std::string& cidr) {
        size_t slash_pos = cidr.find('/');
        if (slash_pos == std::string::npos) {
            // Invalid CIDR format, return a default
            return { 0, 0, "invalid" };
        }
        
        std::string ip_str = cidr.substr(0, slash_pos);
        int prefix_len;
        
		// Convert prefix length to integer
        try {
            prefix_len = std::stoi(cidr.substr(slash_pos + 1));
        } catch (const std::exception& e) {
            // Invalid prefix length
            return { 0, 0, "invalid" };
        }

        uint32_t ip = ip_to_uint32(ip_str);
        uint32_t mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF;
        uint32_t network = ip & mask;

        return { network, mask, "" };
    }

	// Convert dotted-decimal IP to uint32
    uint32_t ip_to_uint32(const std::string& ip) {
        uint32_t result = 0;
        int shift = 24;
        size_t start = 0, end = 0;

        for (int i = 0; i < 4; ++i) {
            end = ip.find('.', start);
            if (end == std::string::npos) end = ip.length();

            int octet = std::stoi(ip.substr(start, end - start));
            result |= (octet << shift);
            shift -= 8;
            start = end + 1;
        }

        return result;
    }

// Initialize with common network ranges
public:
    NetworkTopology() {

        // Common internal network ranges
        add_internal_network("10.0.0.0/8", "RFC1918 Class A");
        add_internal_network("172.16.0.0/12", "RFC1918 Class B");
        add_internal_network("192.168.0.0/16", "RFC1918 Class C");
        add_internal_network("169.254.0.0/16", "Link-Local");
        add_internal_network("127.0.0.0/8", "Loopback");

        // Common DMZ ranges
        add_dmz_network("203.0.113.0/24", "Documentation/Test");
        add_dmz_network("198.51.100.0/24", "Documentation/Test");

        // Management networks
        add_management_network("10.255.0.0/16", "Management VLAN");
        add_management_network("172.31.0.0/16", "Admin Network");
    }

	// Add CIDR range to internal networks
    void add_internal_network(const std::string& cidr, const std::string& desc = "") {
        CIDRRange range = parse_cidr(cidr);
        range.description = desc;
        internal_networks.push_back(range);
    }

	// Add CIDR range to DMZ networks
    void add_dmz_network(const std::string& cidr, const std::string& desc = "") {
        CIDRRange range = parse_cidr(cidr);
        range.description = desc;
        dmz_networks.push_back(range);
    }
    
	// Add CIDR range to management networks
    void add_management_network(const std::string& cidr, const std::string& desc = "") {
        CIDRRange range = parse_cidr(cidr);
        range.description = desc;
        management_networks.push_back(range);
    }
	// Check if IP is in internal networks
    bool is_internal_ip(const std::string& ip) {
        uint32_t addr = ip_to_uint32(ip);
        for (const auto& range : internal_networks) {
            if ((addr & range.mask) == range.network) return true;
        }
        return false;
    }
	// Check if IP is in DMZ networks
    bool is_dmz_ip(const std::string& ip) {
        uint32_t addr = ip_to_uint32(ip);
        for (const auto& range : dmz_networks) {
            if ((addr & range.mask) == range.network) return true;
        }
        return false;
    }
	// Check if IP is in management networks
    bool is_management_ip(const std::string& ip) {
        uint32_t addr = ip_to_uint32(ip);
        for (const auto& range : management_networks) {
            if ((addr & range.mask) == range.network) return true;
        }
        return false;
    }
	// Classify IP into network zone
    std::string classify_network_zone(const std::string& ip) {
        if (is_management_ip(ip)) return "management";
        if (is_internal_ip(ip)) return "internal";
        if (is_dmz_ip(ip)) return "dmz";
        return "external";
    }
};

// Threat intelligence patterns
class ThreatIntelligence {
private:
    // Static compiled regex pattern members
    static std::vector<std::pair<std::regex, std::string>> compiled_malware_signatures;
    static std::vector<std::pair<std::regex, std::string>> compiled_auth_bypass_patterns;
    static std::vector<std::pair<std::regex, std::string>> compiled_advanced_string_patterns;
    static std::once_flag init_flag;

    // Initialize all patterns
    static void initialize_patterns() {
        // Malware family signatures
        compiled_malware_signatures = {
            // APT & Nation State
            {std::regex(R"(cobalt.*strike)", std::regex_constants::icase | std::regex_constants::optimize), "cobalt_strike"},
            {std::regex(R"(mimikatz)", std::regex_constants::icase | std::regex_constants::optimize), "mimikatz_credential_dumper"},
            {std::regex(R"(bloodhound)", std::regex_constants::icase | std::regex_constants::optimize), "bloodhound_recon"},
            {std::regex(R"(sharphound)", std::regex_constants::icase | std::regex_constants::optimize), "sharphound_collector"},
            {std::regex(R"(rubeus)", std::regex_constants::icase | std::regex_constants::optimize), "rubeus_kerberos_abuse"},
            {std::regex(R"(powerview)", std::regex_constants::icase | std::regex_constants::optimize), "powerview_enumeration"},
            {std::regex(R"(empire|powerempire)", std::regex_constants::icase | std::regex_constants::optimize), "powershell_empire"},
            {std::regex(R"(metasploit|meterpreter)", std::regex_constants::icase | std::regex_constants::optimize), "metasploit_framework"},
            {std::regex(R"(impacket)", std::regex_constants::icase | std::regex_constants::optimize), "impacket_tools"},
            {std::regex(R"(secretsdump)", std::regex_constants::icase | std::regex_constants::optimize), "secrets_dumping"},

            // Ransomware Families
            {std::regex(R"(ryuk|conti|lockbit)", std::regex_constants::icase | std::regex_constants::optimize), "ransomware_family"},
            {std::regex(R"(revil|sodinokibi)", std::regex_constants::icase | std::regex_constants::optimize), "revil_ransomware"},
            {std::regex(R"(maze|egregor)", std::regex_constants::icase | std::regex_constants::optimize), "maze_ransomware_family"},
            {std::regex(R"(darkside|blackmatter)", std::regex_constants::icase | std::regex_constants::optimize), "darkside_ransomware"},
            {std::regex(R"(babuk|grief)", std::regex_constants::icase | std::regex_constants::optimize), "babuk_ransomware_family"},

            // Living off the Land Binaries
            {std::regex(R"(psexec|paexec)", std::regex_constants::icase | std::regex_constants::optimize), "psexec_lateral_movement"},
            {std::regex(R"(wmic\.exe)", std::regex_constants::icase | std::regex_constants::optimize), "wmi_abuse"},
            {std::regex(R"(rundll32\.exe)", std::regex_constants::icase | std::regex_constants::optimize), "rundll32_abuse"},
            {std::regex(R"(regsvr32\.exe)", std::regex_constants::icase | std::regex_constants::optimize), "regsvr32_abuse"},
            {std::regex(R"(mshta\.exe)", std::regex_constants::icase | std::regex_constants::optimize), "mshta_abuse"},
            {std::regex(R"(powershell\.exe|pwsh\.exe)", std::regex_constants::icase | std::regex_constants::optimize), "powershell_execution"},
            {std::regex(R"(cmd\.exe)", std::regex_constants::icase | std::regex_constants::optimize), "command_execution"},
            {std::regex(R"(bitsadmin\.exe)", std::regex_constants::icase | std::regex_constants::optimize), "bitsadmin_abuse"},
            {std::regex(R"(certutil\.exe)", std::regex_constants::icase | std::regex_constants::optimize), "certutil_abuse"},
            {std::regex(R"(schtasks\.exe)", std::regex_constants::icase | std::regex_constants::optimize), "scheduled_task_abuse"},

            // Credential Access
            {std::regex(R"(lsass\.dmp|lsass\.exe)", std::regex_constants::icase | std::regex_constants::optimize), "lsass_access"},
            {std::regex(R"(sam\.hive|system\.hive|security\.hive)", std::regex_constants::icase | std::regex_constants::optimize), "registry_hive_access"},
            {std::regex(R"(ntds\.dit)", std::regex_constants::icase | std::regex_constants::optimize), "ntds_database_access"},
            {std::regex(R"(ticket\.kirbi|\.ccache)", std::regex_constants::icase | std::regex_constants::optimize), "kerberos_ticket"},

            // Persistence Mechanisms
            {std::regex(R"(golden.*ticket)", std::regex_constants::icase | std::regex_constants::optimize), "golden_ticket"},
            {std::regex(R"(silver.*ticket)", std::regex_constants::icase | std::regex_constants::optimize), "silver_ticket"},
            {std::regex(R"(dcsync|dcshadow)", std::regex_constants::icase | std::regex_constants::optimize), "dc_persistence"},
            {std::regex(R"(skeleton.*key)", std::regex_constants::icase | std::regex_constants::optimize), "skeleton_key"}
        };

        // Authentication context patterns
        compiled_auth_bypass_patterns = {
            // NTLM Authentication Patterns
            {std::regex(R"(NTLMSSP\x00[\x01-\x03])", std::regex_constants::icase | std::regex_constants::optimize), "ntlm_negotiation"},
            {std::regex(R"(Type [123] Message)", std::regex_constants::icase | std::regex_constants::optimize), "ntlm_message_type"},
            {std::regex(R"(NTLM.*hash|LM.*hash)", std::regex_constants::icase | std::regex_constants::optimize), "ntlm_hash"},
            {std::regex(R"(Challenge.*Response)", std::regex_constants::icase | std::regex_constants::optimize), "ntlm_challenge"},

            // Kerberos Authentication
            {std::regex(R"(\x60\x48|\x60\x82)", std::regex_constants::icase | std::regex_constants::optimize), "kerberos_asn1"},
            {std::regex(R"(AS-REQ|AS-REP|TGS-REQ|TGS-REP)", std::regex_constants::icase | std::regex_constants::optimize), "kerberos_message"},
            {std::regex(R"(krbtgt|service.*ticket)", std::regex_constants::icase | std::regex_constants::optimize), "kerberos_ticket"},
            {std::regex(R"(EncTicketPart|EncASRepPart)", std::regex_constants::icase | std::regex_constants::optimize), "kerberos_encrypted"},

            // Authentication Bypass Techniques
            {std::regex(R"(sql.*injection|sqli)", std::regex_constants::icase | std::regex_constants::optimize), "sql_injection_auth"},
            {std::regex(R"(brute.*force|dictionary.*attack)", std::regex_constants::icase | std::regex_constants::optimize), "brute_force"},
            {std::regex(R"(pass.*spray|password.*spray)", std::regex_constants::icase | std::regex_constants::optimize), "password_spraying"},
            {std::regex(R"(pass.*hash|pth)", std::regex_constants::icase | std::regex_constants::optimize), "pass_the_hash"},
            {std::regex(R"(pass.*ticket|ptt)", std::regex_constants::icase | std::regex_constants::optimize), "pass_the_ticket"}
        };

        // String analysis patterns
        compiled_advanced_string_patterns = {
            // URLs and Network Resources
            {std::regex(R"(https?://[^\s<>"{}|\\^`\[\]]+)", std::regex_constants::icase | std::regex_constants::optimize), "http_url"},
            {std::regex(R"(ftp://[^\s<>"{}|\\^`\[\]]+)", std::regex_constants::icase | std::regex_constants::optimize), "ftp_url"},
            {std::regex(R"(\\\\[^\\]+\\[^\\]+)", std::regex_constants::icase | std::regex_constants::optimize), "unc_path"},
            {std::regex(R"(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)", std::regex_constants::icase | std::regex_constants::optimize), "ipv4_address"},

            // File Paths and Extensions
            {std::regex(R"([C-Z]:\\(?:[^<>:"/|?*\r\n]+\\)*[^<>:"/|?*\r\n]*)", std::regex_constants::icase | std::regex_constants::optimize), "windows_file_path"},
            {std::regex(R"(\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|jar|zip|rar))", std::regex_constants::icase | std::regex_constants::optimize), "executable_extension"},

            // Registry Keys and Values
            {std::regex(R"(HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG))", std::regex_constants::icase | std::regex_constants::optimize), "registry_hive"},
            {std::regex(R"(\\(?:SOFTWARE|SYSTEM|SAM|SECURITY)\\)", std::regex_constants::icase | std::regex_constants::optimize), "registry_path"},

            // Credentials and Authentication
            {std::regex(R"((?:password|pass|pwd|passwd)\s*[:=]\s*[^\s]+)", std::regex_constants::icase | std::regex_constants::optimize), "credential_pattern"},
            {std::regex(R"([A-Za-z0-9]{32})", std::regex_constants::icase | std::regex_constants::optimize), "md5_hash"},
            {std::regex(R"([A-Za-z0-9]{64})", std::regex_constants::icase | std::regex_constants::optimize), "sha256_hash"},

            // Encoding and Encryption
            {std::regex(R"([A-Za-z0-9+/]{40,}={0,2})", std::regex_constants::icase | std::regex_constants::optimize), "base64_long"},
            {std::regex(R"([0-9A-Fa-f]{32,})", std::regex_constants::icase | std::regex_constants::optimize), "hex_encoded"},

            // PowerShell and Scripting
            {std::regex(R"(-(?:enc|en|e|encodedcommand))", std::regex_constants::icase | std::regex_constants::optimize), "powershell_encoded"},
            {std::regex(R"(Invoke-(?:Expression|Command|WebRequest|RestMethod))", std::regex_constants::icase | std::regex_constants::optimize), "powershell_invoke"}
        };
    }

public:
	// Initialize patterns only once
    ThreatIntelligence() {
        std::call_once(init_flag, initialize_patterns);
    }

    // Public const accessors
    const std::vector<std::pair<std::regex, std::string>>& get_malware_signatures() const {
        return compiled_malware_signatures;
    }
    const std::vector<std::pair<std::regex, std::string>>& get_auth_bypass_patterns() const {
        return compiled_auth_bypass_patterns;
    }
    const std::vector<std::pair<std::regex, std::string>>& get_advanced_string_patterns() const {
        return compiled_advanced_string_patterns;
    }
};

// Initialize static members
std::vector<std::pair<std::regex, std::string>> ThreatIntelligence::compiled_malware_signatures;
std::vector<std::pair<std::regex, std::string>> ThreatIntelligence::compiled_auth_bypass_patterns;
std::vector<std::pair<std::regex, std::string>> ThreatIntelligence::compiled_advanced_string_patterns;
std::once_flag ThreatIntelligence::init_flag;

// Threat Intelligence Engine
class ThreatIntelligenceEngine {
private:
    // MITRE ATT&CK Technique Database
    struct AttackTechnique {
        std::string technique_id;
        std::string technique_name;
        std::string tactic;
        std::vector<std::string> rpc_indicators;
        std::vector<std::string> interface_uuids;
        std::vector<int> operation_numbers;
        int base_risk_score;
    };

	// This database isn't comprehensive. More techniques can be added as needed.
	// Refer to https://attack.mitre.org/ for a complete list.
	// Also keep in mind that some techniques may overlap in indicators.

    std::vector<AttackTechnique> attack_techniques = {
        // Lateral Movement Techniques
        {"T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement",
        {"psexec", "admin$", "c$", "ipc$"},
        {"367abb81-9844-35f1-ad32-98f038001003"}, {19, 20, 23}, 85},

        {"T1053.005", "Scheduled Task/Job: Scheduled Task", "Execution",
        {"schtasks", "taskschd"},
        {"86d35949-83c9-4044-b424-db363231fd0c"}, {1, 12, 13}, 75},

        // Credential Access Techniques
        {"T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access",
        {"lsass", "mimikatz", "procdump"},
        {"c681d488-d850-11d0-8c52-00c04fd90f7e"}, {}, 95},

        {"T1003.002", "OS Credential Dumping: Security Account Manager", "Credential Access",
        {"sam", "system", "security"},
        {"12345778-1234-abcd-ef00-0123456789ac"}, {0, 7, 16}, 90},

        // Discovery Techniques  
        {"T1087.002", "Account Discovery: Domain Account", "Discovery",
        {"net user", "dsquery", "ldap"},
        {"12345778-1234-abcd-ef00-0123456789ac"}, {5, 6, 16}, 60},

        // Persistence Techniques
        {"T1543.003", "Create or Modify System Process: Windows Service", "Persistence",
        {"sc create", "service install"},
        {"367abb81-9844-35f1-ad32-98f038001003"}, {23, 24}, 80}
    };

    // Known Attack Patterns Database
    std::unordered_map<std::string, std::vector<std::string>> attack_patterns = {
        {"PSExec", {
            "367abb81-9844-35f1-ad32-98f038001003:19", // StartServiceW
            "367abb81-9844-35f1-ad32-98f038001003:23"  // CreateServiceW
        }},
        {"DCSync", {
            "e3514235-4b06-11d1-ab04-00c04fc2dcd2:3"   // DRSGetNCChanges
        }},
        {"Task scheduler abuse", {
            "86d35949-83c9-4044-b424-db363231fd0c:1",  // SchRpcRegisterTask
            "86d35949-83c9-4044-b424-db363231fd0c:12"  // SchRpcRun
        }}
    };

    // IOC Database Structure
    struct IOC {
        std::string ioc_type;
        std::string ioc_value;
        std::string description;
        std::string threat_family;
        int confidence_score;
    };

	// Not exhaustive, more IOCs can be added
    std::vector<IOC> ioc_database = {
        // Interface-based IOCs
        {"interface_uuid", "367abb81-9844-35f1-ad32-98f038001003", "Service Control Manager interface", "Generic", 70},
        {"interface_uuid", "e3514235-4b06-11d1-ab04-00c04fc2dcd2", "DRSUAPI interface - DCSync attacks", "APT", 95},
        {"interface_uuid", "12345778-1234-abcd-ef00-0123456789ac", "SAMR interface - credential access", "APT", 85},

        // Operation-based IOCs
        {"operation_signature", "367abb81-9844-35f1-ad32-98f038001003:23", "Service creation via SCM", "Lateral Movement", 80},
        {"operation_signature", "e3514235-4b06-11d1-ab04-00c04fc2dcd2:3", "DRSGetNCChanges - DCSync", "APT", 100},

        // Pattern-based IOCs
        {"payload_pattern", "mimikatz", "Mimikatz credential dumper", "Credential Theft", 95},
        {"payload_pattern", "cobalt.*strike", "Cobalt Strike C2", "APT", 90},
        {"payload_pattern", "psexec", "PSExec lateral movement", "Lateral Movement", 75}
    };

// Helper function to match IOCs
public:
    struct ThreatIntelligenceResult {
        int risk_score;
        std::vector<json> attack_techniques;
        std::vector<std::string> threat_indicators;
        std::string attack_pattern;
        std::vector<json> ioc_matches;
    };

	// Analyze threat based on multiple inputs
    ThreatIntelligenceResult analyze_threat(
        const std::string& interface_uuid,
        int operation_number,
        const std::vector<std::string>& suspicious_patterns,
        const AuthInfo& auth_info,
        const std::string& source_country,
        int source_asn,
        const std::string& direction,
        bool is_cross_border,
        const PayloadAnalysis& payload_analysis) {
		
        // Aggregate results
        ThreatIntelligenceResult result;
        result.risk_score = calculate_risk_score(interface_uuid, operation_number,
            suspicious_patterns, auth_info, source_country, source_asn, direction, is_cross_border, payload_analysis);
        result.attack_techniques = identify_attack_techniques(interface_uuid, operation_number, suspicious_patterns, payload_analysis);
        result.threat_indicators = detect_threat_indicators(interface_uuid, operation_number, suspicious_patterns, auth_info, source_country, direction, payload_analysis);
        result.attack_pattern = identify_attack_pattern(interface_uuid, operation_number);
        result.ioc_matches = match_iocs(interface_uuid, operation_number, suspicious_patterns, source_country, source_asn);
        return result;
    }

private:
	// Calculate risk score based on various factors
    int calculate_risk_score(const std::string& interface_uuid, int operation_number,
        const std::vector<std::string>& suspicious_patterns,
        const AuthInfo& auth_info, const std::string& source_country,
        int source_asn, const std::string& direction,
        bool is_cross_border, const PayloadAnalysis& payload_analysis) {

        int score = 0;

        // Interface-based scoring (0-25 points)
        if (interface_uuid == "e3514235-4b06-11d1-ab04-00c04fc2dcd2") { // DRSUAPI
            score += 25;
        }
        else if (interface_uuid == "367abb81-9844-35f1-ad32-98f038001003") { // SCM
            score += 20;
        }
        else if (interface_uuid == "12345778-1234-abcd-ef00-0123456789ac") { // SAMR
            score += 18;
        }
        else if (interface_uuid == "c681d488-d850-11d0-8c52-00c04fd90f7e") { // LSASS
            score += 23;
        }

        // Operation-based scoring (0-15 points)
        std::string operation_sig = interface_uuid + ":" + std::to_string(operation_number);
        if (operation_sig == "e3514235-4b06-11d1-ab04-00c04fc2dcd2:3") { // DRSGetNCChanges
            score += 15;
        }
        else if (operation_sig == "367abb81-9844-35f1-ad32-98f038001003:23") { // CreateServiceW
            score += 12;
        }

        // Suspicious pattern scoring (0-20 points)
        for (const auto& pattern : suspicious_patterns) {
            if (pattern.find("cobalt_strike") != std::string::npos ||
                pattern.find("mimikatz") != std::string::npos) {
                score += 20;
                break;
            }
            else if (pattern.find("ransomware") != std::string::npos || pattern.find("apt_group") != std::string::npos) {
                score += 15;
                break;
            }
            else if (pattern.find("psexec") != std::string::npos || pattern.find("powershell") != std::string::npos) {
                score += 10;
                break;
            }
        }

        // Authentication risk scoring (0-15 points)
        if (auth_info.bypass_detected) {
            score += 15;
        }
        else if (auth_info.suspicious_auth) {
            score += 10;
        }
        else if (auth_info.auth_type == "None" && direction == "inbound") {
            score += 8;
        }

        // Geographic risk scoring (0-15 points)
        if (source_country == "CN" || source_country == "RU" || source_country == "KP") {
            score += 15;
        }
        else if (source_country == "IR" || source_country == "VN" || source_country == "BD") {
            score += 12;
        }

        // ASN risk scoring (0-10 points)
        if (source_asn == 16276 || source_asn == 62217) { // Bulletproof hosting
            score += 10;
        }
        else if (source_asn == 16509 || source_asn == 15169) { // Cloud providers
            score += 5;
        }

        return std::min<int>(100, score);
    }

	// Identify attack techniques based on multiple indicators 
    std::vector<json> identify_attack_techniques(const std::string& interface_uuid,
        int operation_number,
        const std::vector<std::string>& suspicious_patterns,
        const PayloadAnalysis& payload_analysis) {
        std::vector<json> techniques;
		
        // Match techniques based on indicators
        for (const auto& technique : attack_techniques) {
            double confidence = 0.0;
            bool matches = false;

            // Check interface UUID match
            if (std::find(technique.interface_uuids.begin(), technique.interface_uuids.end(),
                interface_uuid) != technique.interface_uuids.end()) {
                matches = true;
                confidence += 0.4;
            }

            // Check operation number match
            if (std::find(technique.operation_numbers.begin(), technique.operation_numbers.end(),
                operation_number) != technique.operation_numbers.end()) {
                matches = true;
                confidence += 0.3;
            }

            // Check suspicious patterns
            for (const auto& indicator : technique.rpc_indicators) {
                for (const auto& pattern : suspicious_patterns) {
                    if (pattern.find(indicator) != std::string::npos) {
                        matches = true;
                        confidence += 0.3;
                        break;
                    }
                }
            }

			// Finalize confidence score
            if (matches && confidence > 0.3) {
                json tech = {
                    {"technique_id", technique.technique_id},
                    {"technique_name", technique.technique_name},
                    {"tactic", technique.tactic},
                    {"confidence", confidence}
                };
                techniques.push_back(tech);
            }
        }

        return techniques;
    }

	// Detect threat indicators based on various factors. Not exhaustive.
    std::vector<std::string> detect_threat_indicators(const std::string& interface_uuid,
        int operation_number,
        const std::vector<std::string>& suspicious_patterns,
        const AuthInfo& auth_info,
        const std::string& source_country,
        const std::string& direction,
        const PayloadAnalysis& payload_analysis) {
        std::vector<std::string> indicators;

        // Service-based indicators
        if (interface_uuid == "367abb81-9844-35f1-ad32-98f038001003") {
            if (operation_number == 23) indicators.push_back("remote_service_creation");
            indicators.push_back("privileged_interface_access");
        }

        // DRSUAPI indicators
        if (interface_uuid == "e3514235-4b06-11d1-ab04-00c04fc2dcd2") {
            indicators.push_back("domain_admin_activity");
            indicators.push_back("credential_access_attempt");
        }

        // Authentication indicators
        if (auth_info.bypass_detected) indicators.push_back("suspicious_authentication");
        if (auth_info.auth_type == "None") indicators.push_back("anonymous_connection");

        // Geographic indicators
        if (source_country == "CN" || source_country == "RU") indicators.push_back("cross_border_communication");

        // Pattern-based indicators
        for (const auto& pattern : suspicious_patterns) {
            if (pattern.find("psexec") != std::string::npos) indicators.push_back("lateral_movement_detected");
            if (pattern.find("mimikatz") != std::string::npos) indicators.push_back("credential_access_attempt");
            if (pattern.find("powershell") != std::string::npos) indicators.push_back("powershell_execution");
        }

        return indicators;
    }
	// Identify known attack patterns based on interface and operation
    std::string identify_attack_pattern(const std::string& interface_uuid, int operation_number) {
        std::string operation_sig = interface_uuid + ":" + std::to_string(operation_number);

        for (const auto& attack_pattern : attack_patterns) {
            for (const auto& signature : attack_pattern.second) {
                if (signature == interface_uuid || signature == operation_sig) {
                    return attack_pattern.first;
                }
            }
        }
        return "Unknown";
    }
	// Match IOCs based on multiple inputs
    std::vector<json> match_iocs(const std::string& interface_uuid, int operation_number,
        const std::vector<std::string>& suspicious_patterns,
        const std::string& source_country, int source_asn) {
        std::vector<json> matches;

        for (const auto& ioc : ioc_database) {
            bool match = false;

            if (ioc.ioc_type == "interface_uuid" && ioc.ioc_value == interface_uuid) {
                match = true;
            }
            else if (ioc.ioc_type == "operation_signature") {
                std::string op_sig = interface_uuid + ":" + std::to_string(operation_number);
                if (ioc.ioc_value == op_sig) match = true;
            }
            else if (ioc.ioc_type == "payload_pattern") {
                for (const auto& pattern : suspicious_patterns) {
                    if (pattern.find(ioc.ioc_value) != std::string::npos) {
                        match = true;
                        break;
                    }
                }
            }

			// If IOC matched, add to results
            if (match) {
                json ioc_match = {
                    {"ioc_type", ioc.ioc_type},
                    {"ioc_value", ioc.ioc_value},
                    {"description", ioc.description}
                };
                matches.push_back(ioc_match);
            }
        }

        return matches;
    }
};

// Geolocation Engine using MaxMind DB
class GeolocationEngine {
private:
    std::unique_ptr<MMDB_s> geoip_db;
    std::unique_ptr<MMDB_s> asn_db;
    GeographicRiskAssessment risk_assessor;
    NetworkTopology network_topology;
    bool geoip_db_loaded;
    bool asn_db_loaded;
    std::mutex geo_mutex;

	// Load MaxMind databases
    json extract_geoip_data(MMDB_lookup_result_s& result) {
        json geo_data;
        if (!result.found_entry) return geo_data;

        MMDB_entry_data_s entry_data;

        const char* country_path[] = { "country", "iso_code", NULL };
        if (MMDB_aget_value(&result.entry, &entry_data, country_path) == MMDB_SUCCESS && 
            entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
            geo_data["country"]["iso_code"] = std::string(entry_data.utf8_string, entry_data.data_size);
        }
        const char* country_name_path[] = { "country", "names", "en", NULL };
        if (MMDB_aget_value(&result.entry, &entry_data, country_name_path) == MMDB_SUCCESS && 
            entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
            geo_data["country"]["names"]["en"] = std::string(entry_data.utf8_string, entry_data.data_size);
        }
        const char* city_path[] = { "city", "names", "en", NULL };
        if (MMDB_aget_value(&result.entry, &entry_data, city_path) == MMDB_SUCCESS && 
            entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
            geo_data["city"]["names"]["en"] = std::string(entry_data.utf8_string, entry_data.data_size);
        }
        const char* lat_path[] = { "location", "latitude", NULL };
        if (MMDB_aget_value(&result.entry, &entry_data, lat_path) == MMDB_SUCCESS && 
            entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
            geo_data["location"]["latitude"] = entry_data.double_value;
        }
        const char* lon_path[] = { "location", "longitude", NULL };
        if (MMDB_aget_value(&result.entry, &entry_data, lon_path) == MMDB_SUCCESS && 
            entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
            geo_data["location"]["longitude"] = entry_data.double_value;
        }
        const char* tz_path[] = { "location", "time_zone", NULL };
        if (MMDB_aget_value(&result.entry, &entry_data, tz_path) == MMDB_SUCCESS && 
            entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
            geo_data["location"]["time_zone"] = std::string(entry_data.utf8_string, entry_data.data_size);
        }
        const char* anon_proxy_path[] = { "traits", "is_anonymous_proxy", NULL };
        if (MMDB_aget_value(&result.entry, &entry_data, anon_proxy_path) == MMDB_SUCCESS && 
            entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_BOOLEAN) {
            geo_data["traits"]["is_anonymous_proxy"] = static_cast<bool>(entry_data.boolean);
        }
        const char* satellite_path[] = { "traits", "is_satellite_provider", NULL };
        if (MMDB_aget_value(&result.entry, &entry_data, satellite_path) == MMDB_SUCCESS && 
            entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_BOOLEAN) {
            geo_data["traits"]["is_satellite_provider"] = static_cast<bool>(entry_data.boolean);
        }
        return geo_data;
    }

	// Extract ASN data
    json extract_asn_data(MMDB_lookup_result_s& result) {
        json asn_data;
        if (!result.found_entry) return asn_data;

        MMDB_entry_data_s entry_data;

        const char* asn_path[] = { "autonomous_system_number", NULL };
        if (MMDB_aget_value(&result.entry, &entry_data, asn_path) == MMDB_SUCCESS && 
            entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UINT32) {
            asn_data["autonomous_system_number"] = static_cast<int>(entry_data.uint32);
        }
        const char* org_path[] = { "autonomous_system_organization", NULL };
        if (MMDB_aget_value(&result.entry, &entry_data, org_path) == MMDB_SUCCESS && 
            entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
            asn_data["autonomous_system_organization"] = std::string(entry_data.utf8_string, entry_data.data_size);
        }
        return asn_data;
    }

	// Lookup IP in GeoIP database
    json lookup_ip_geolocation(const std::string& ip) {
        json result;
        if (!geoip_db_loaded || !geoip_db) return result;

        std::lock_guard<std::mutex> lock(geo_mutex);

        int gai_error, mmdb_error;
        MMDB_lookup_result_s lookup_result = MMDB_lookup_string(geoip_db.get(), ip.c_str(), &gai_error, &mmdb_error);

        if (gai_error == 0 && mmdb_error == MMDB_SUCCESS && lookup_result.found_entry) {
            result = extract_geoip_data(lookup_result);
        }
        return result;
    }

	// Lookup IP in ASN database
    json lookup_ip_asn(const std::string& ip) {
        json result;
        if (!asn_db_loaded || !asn_db) return result;

        std::lock_guard<std::mutex> lock(geo_mutex);

        int gai_error, mmdb_error;
        MMDB_lookup_result_s lookup_result = MMDB_lookup_string(asn_db.get(), ip.c_str(), &gai_error, &mmdb_error);

        if (gai_error == 0 && mmdb_error == MMDB_SUCCESS && lookup_result.found_entry) {
            result = extract_asn_data(lookup_result);
        }
        return result;
    }

	// Check if ISP is a known satellite provider
    bool is_satellite_provider(const std::string& isp_name) {
        static const std::vector<std::string> satellite_providers = {
            "Hughes", "Viasat", "HughesNet", "WildBlue", "Exede", "Intelsat",
            "SES", "Eutelsat", "Telesat", "O3b", "Thuraya", "Iridium"
        };

        for (const auto& provider : satellite_providers) {
            if (isp_name.find(provider) != std::string::npos) return true;
        }
        return false;
    }

	// Check if IP is an anonymous proxy
    bool is_anonymous_proxy(const json& geo_data) {
        if (geo_data.contains("traits")) {
            const auto& traits = geo_data["traits"];
            return traits.value("is_anonymous_proxy", false) || traits.value("is_satellite_provider", false);
        }
        return false;
    }

	// Check if ISP is a known hosting provider
    bool is_hosting_provider(const std::string& isp_name, int asn) {
        static const std::vector<std::string> hosting_keywords = {
            "Amazon", "Google", "Microsoft", "Digital Ocean", "Linode",
            "Vultr", "OVH", "Hetzner", "Contabo", "HostGator", "GoDaddy",
            "Cloudflare", "Akamai", "Fastly", "MaxCDN", "KeyCDN"
        };
        for (const auto& keyword : hosting_keywords) {
            if (isp_name.find(keyword) != std::string::npos) return true;
        }
        static const std::set<int> hosting_asns = {
            16509, 15169, 8075, 14061, 63949, 20940, 13335, 16276, 24940
        };

        return hosting_asns.count(asn) > 0;
    }

// Geolocation information structure
public:
    struct GeolocationInfo {
        std::string source_country = "US";
        std::string destination_country = "US";
        int source_asn = 7922;
        int destination_asn = 7922;
        std::string source_city = "New York";
        std::string destination_city = "Los Angeles";
        bool is_internal_communication = false;
        bool is_cross_border = false;
        std::string geographic_risk = "low";
        std::string source_network_zone = "external";
        std::string destination_network_zone = "external";
        double latitude = 40.7128;
        double longitude = -74.0060;
        std::string timezone = "America/New_York";
        std::string isp_name = "Unknown";
        std::string organization = "Unknown";
        bool is_satellite_provider = false;
        bool is_anonymous_proxy = false;
        bool is_hosting_provider = false;
    };

	// GeolocationEngine constructor
    GeolocationEngine(const std::string& geoip_db_path, const std::string& asn_db_path)
        : geoip_db_loaded(false), asn_db_loaded(false) {

        // Initialize MaxMind GeoIP2 databases
        geoip_db = std::make_unique<MMDB_s>();
        asn_db = std::make_unique<MMDB_s>();

        // Open GeoIP database
        int status = MMDB_open(geoip_db_path.c_str(), MMDB_MODE_MMAP, geoip_db.get());
        if (status != MMDB_SUCCESS) {
            std::cerr << "Warning: Failed to open GeoIP database (" << geoip_db_path
                << "): " << MMDB_strerror(status) << std::endl;
            std::cerr << "Geolocation features will use default values." << std::endl;
            geoip_db.reset();
        }
        else {
            geoip_db_loaded = true;
            std::cout << "Successfully loaded GeoIP database: " << geoip_db_path << std::endl;
        }

		// Open ASN database
        status = MMDB_open(asn_db_path.c_str(), MMDB_MODE_MMAP, asn_db.get());
        if (status != MMDB_SUCCESS) {
            std::cerr << "Warning: Failed to open ASN database (" << asn_db_path
                << "): " << MMDB_strerror(status) << std::endl;
            std::cerr << "ASN lookup features will use default values." << std::endl;
            asn_db.reset();
        }
        else {
            asn_db_loaded = true;
            std::cout << "Successfully loaded ASN database: " << asn_db_path << std::endl;
        }

        if (!geoip_db_loaded && !asn_db_loaded) {
            std::cerr << "Warning: No geolocation databases loaded. All geographic analysis will use default/mock values." << std::endl;
        }
    }
	// GeolocationEngine destructor
    ~GeolocationEngine() {
        if (geoip_db && geoip_db_loaded) {
            MMDB_close(geoip_db.get());
        }
        if (asn_db && asn_db_loaded) {
            MMDB_close(asn_db.get());
        }
    }

	// Analyze communication between source and destination IPs
    GeolocationInfo analyze_communication(const std::string& src_ip, const std::string& dst_ip) {
        GeolocationInfo info;

		// Analyze source IP
        json src_geo, src_asn_info;
        if (geoip_db_loaded) {
            src_geo = lookup_ip_geolocation(src_ip);
        }
        if (asn_db_loaded) {
            src_asn_info = lookup_ip_asn(src_ip);
        }

        // Analyze destination IP  
        json dst_geo, dst_asn_info;
        if (geoip_db_loaded) {
            dst_geo = lookup_ip_geolocation(dst_ip);
        }
        if (asn_db_loaded) {
            dst_asn_info = lookup_ip_asn(dst_ip);
        }

        // Populate geolocation data from database results
        if (!src_geo.empty()) {
            if (src_geo.contains("country") && src_geo["country"].contains("iso_code")) {
                info.source_country = src_geo["country"]["iso_code"].get<std::string>();
            }
            if (src_geo.contains("city") && src_geo["city"].contains("names") &&
                src_geo["city"]["names"].contains("en")) {
                info.source_city = src_geo["city"]["names"]["en"].get<std::string>();
            }
            if (src_geo.contains("location")) {
                if (src_geo["location"].contains("latitude")) {
                    info.latitude = src_geo["location"]["latitude"].get<double>();
                }
                if (src_geo["location"].contains("longitude")) {
                    info.longitude = src_geo["location"]["longitude"].get<double>();
                }
                if (src_geo["location"].contains("time_zone")) {
                    info.timezone = src_geo["location"]["time_zone"].get<std::string>();
                }
            }

            // Check for proxy/anonymity flags
            info.is_anonymous_proxy = is_anonymous_proxy(src_geo);
        }

        if (!dst_geo.empty()) {
            if (dst_geo.contains("country") && dst_geo["country"].contains("iso_code")) {
                info.destination_country = dst_geo["country"]["iso_code"].get<std::string>();
            }
            if (dst_geo.contains("city") && dst_geo["city"].contains("names") &&
                dst_geo["city"]["names"].contains("en")) {
                info.destination_city = dst_geo["city"]["names"]["en"].get<std::string>();
            }
        }

        // Populate ASN data
        if (!src_asn_info.empty()) {
            if (src_asn_info.contains("autonomous_system_number")) {
                info.source_asn = src_asn_info["autonomous_system_number"].get<int>();
            }
            if (src_asn_info.contains("autonomous_system_organization")) {
                info.isp_name = src_asn_info["autonomous_system_organization"].get<std::string>();
                info.organization = info.isp_name;

                // Check for hosting provider and satellite provider
                info.is_hosting_provider = is_hosting_provider(info.isp_name, info.source_asn);
                info.is_satellite_provider = is_satellite_provider(info.isp_name);
            }
        }

        if (!dst_asn_info.empty()) {
            if (dst_asn_info.contains("autonomous_system_number")) {
                info.destination_asn = dst_asn_info["autonomous_system_number"].get<int>();
            }
        }

        // Network topology analysis
        info.source_network_zone = network_topology.classify_network_zone(src_ip);
        info.destination_network_zone = network_topology.classify_network_zone(dst_ip);
        info.is_internal_communication = (info.source_network_zone != "external" &&
            info.destination_network_zone != "external");

        // Cross-border analysis
        info.is_cross_border = (info.source_country != info.destination_country);

        // Calculate comprehensive geographic risk
        int country_risk = risk_assessor.calculate_country_risk(info.source_country);
        int asn_risk = risk_assessor.calculate_asn_risk(info.source_asn);
        bool cross_border_risk = risk_assessor.is_cross_border_high_risk(info.source_country, info.destination_country);

        info.geographic_risk = risk_assessor.assess_geographic_risk(country_risk, asn_risk, cross_border_risk, info.is_internal_communication);

        return info;
    }
};

// Complete RPC Parser integrating all components
class CompleteRPCParser {
private:
    std::unique_ptr<GeolocationEngine> geo_engine;
    NetworkTopology network_topology;
    ThreatIntelligence threat_intel;
    ThreatIntelligenceEngine threat_intel_engine;
    std::map<std::string, SessionInfo> session_tracker;
    std::mutex session_mutex;

    std::string get_iso8601_timestamp() {
        auto now = std::time(nullptr);
        auto utc = std::gmtime(&now);
        std::stringstream ss;
        ss << std::put_time(utc, "%Y-%m-%dT%H:%M:%S") << "Z";
        return ss.str();
    }

    inline std::string bytes_to_hex(const uint8_t* data, size_t len) {
        static const char hex_chars[] = "0123456789abcdef";
        std::string result;
        result.reserve(len * 2);
        
        for (size_t i = 0; i < len; ++i) {
            result.push_back(hex_chars[(data[i] >> 4) & 0xF]);
            result.push_back(hex_chars[data[i] & 0xF]);
        }
        return result;
    }

    std::string sha256_hash(const uint8_t* data, size_t len) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(data, len, hash);
        return bytes_to_hex(hash, SHA256_DIGEST_LENGTH);
    }

	// DCERPC header parsing
    bool parse_dcerpc_header(const uint8_t* payload, size_t len, DCERPCHeader& header) {
        if (len < sizeof(DCERPCHeader)) return false;

        memcpy(&header, payload, sizeof(DCERPCHeader));

        // Convert from network byte order if needed
        header.fragment_length = ntohs(header.fragment_length);
        header.auth_length = ntohs(header.auth_length);
        header.call_id = ntohl(header.call_id);
        header.operation_number = ntohs(header.operation_number);
        return true;
    }

	// Extract interface UUID from payload at given offset
    std::string extract_interface_uuid(const uint8_t* payload, size_t len, size_t offset) {
        if (len < offset + 16) return "";

        std::stringstream ss;
        ss << std::hex << std::setfill('0');

        for (int i = 0; i < 16; ++i) {
            ss << std::setw(2) << static_cast<unsigned>(payload[offset + i]);
            if (i == 3 || i == 5 || i == 7 || i == 9) ss << "-";
        }
        return ss.str();
    }

	// Analyze payload for sensitive data and encryption
    PayloadAnalysis analyze_payload(const uint8_t* payload, size_t len) {
        PayloadAnalysis analysis;
        if (len == 0) return analysis;

        std::string payload_str(reinterpret_cast<const char*>(payload), len);

        // Entropy calculation for encryption detection
        double entropy = calculate_entropy(payload, len);
        analysis.encryption_detected = (entropy > 7.5);

        // Skip expensive regex if likely encrypted
        if (analysis.encryption_detected && entropy > 7.9) {
            return analysis;
        }

		// Use pre-compiled regex patterns from threat intelligence
        for (const auto& signature : threat_intel.get_malware_signatures()) {
            if (std::regex_search(payload_str, signature.first)) {
                analysis.contains_sensitive_data = true;
                analysis.suspicious_patterns.push_back(signature.second);
            }
        }

        for (const auto& pattern_type : threat_intel.get_advanced_string_patterns()) {
            if (std::regex_search(payload_str, pattern_type.first)) {
                const auto& type = pattern_type.second;
                if (type == "http_url" || type == "ftp_url") {
                    analysis.string_analysis.contains_urls = true;
                }
                if (type == "windows_file_path") {
                    analysis.string_analysis.contains_file_paths = true;
                }
                if (type == "base64_long" || type == "hex_encoded") {
                    analysis.string_analysis.contains_base64 = true;
                }
            }
        }

        // Unicode detection
        analysis.string_analysis.contains_unicode = has_unicode_strings(payload, len);

        // Additional analysis patterns
        static const std::regex registry_regex(R"(HKEY_|\\SOFTWARE\\|\\SYSTEM\\)",
            std::regex_constants::icase | std::regex_constants::optimize);
        static const std::regex credentials_regex(R"(password|username|token|secret)",
            std::regex_constants::icase | std::regex_constants::optimize);
        static const std::regex powershell_regex(R"(-enc|-en|-e|Invoke-|powershell)",
            std::regex_constants::icase | std::regex_constants::optimize);
        static const std::regex executable_regex(R"(\.(?:exe|dll|bat|cmd|ps1|vbs|js))",
            std::regex_constants::icase | std::regex_constants::optimize);

        analysis.string_analysis.contains_registry_keys = std::regex_search(payload_str, registry_regex);
        analysis.string_analysis.contains_credentials = std::regex_search(payload_str, credentials_regex);
        analysis.string_analysis.contains_powershell = std::regex_search(payload_str, powershell_regex);
        analysis.string_analysis.contains_executable_extensions = std::regex_search(payload_str, executable_regex);

        return analysis;
    }

	// Entropy calculation using static array
    inline double calculate_entropy(const uint8_t* data, size_t len) {
        if (len == 0) return 0.0;
        
        int counts[256] = {0};
        for (size_t i = 0; i < len; ++i) {
            counts[data[i]]++;
        }
        
        double entropy = 0.0;
        const double log2_value = std::log(2.0); 
        const double len_inv = 1.0 / len;        
        
        for (int i = 0; i < 256; ++i) {
            if (counts[i] > 0) {
                double p = counts[i] * len_inv;
                entropy -= p * (std::log(p) / log2_value);
            }
        }
        return entropy;
    }

	// Simple heuristic for Unicode detection
    bool has_unicode_strings(const uint8_t* data, size_t len) {
        int null_count = 0;
        for (size_t i = 1; i < len; i += 2) {
            if (data[i] == 0) null_count++;
        }
        return (null_count > len / 4);
    }

	// Parse authentication context from payload
    AuthInfo parse_auth_context(const uint8_t* payload, size_t len) {
        AuthInfo auth_info;
        if (len == 0) return auth_info;

        std::string payload_str(reinterpret_cast<const char*>(payload), len);

        // Use pre-compiled authentication patterns
        for (const auto& pair : threat_intel.get_auth_bypass_patterns()) {
            const auto& pattern = pair.first;
            const auto& auth_type = pair.second;

            if (std::regex_search(payload_str, pattern)) {
                auth_info.auth_present = true;

                if (auth_type.find("ntlm") != std::string::npos) {
                    auth_info.auth_type = "NTLM";
                    auth_info.auth_level = "packet_integrity";
                    auth_info.impersonation_level = "impersonation";
                }
                else if (pair.second.find("kerberos") != std::string::npos) {
                    auth_info.auth_type = "Kerberos";
                    auth_info.auth_level = "packet_privacy";
                    auth_info.impersonation_level = "delegation";
                }

                auth_info.bypass_detected = (pair.second.find("bypass") != std::string::npos ||
                    pair.second.find("injection") != std::string::npos ||
                    pair.second.find("brute") != std::string::npos);
                auth_info.suspicious_auth = auth_info.bypass_detected;
                break;
            }
        }
        return auth_info;
    }

	// Parse SMB layer for session and named pipe info
    SMBInfo parse_smb_layer(const uint8_t* payload, size_t len) {
        SMBInfo smb_info;

        if (len >= 4 && payload[0] == 0xFE && payload[1] == 'S' &&
            payload[2] == 'M' && payload[3] == 'B') {

            smb_info.is_smb_transport = true;

            if (len >= 64) {
                memcpy(&smb_info.session_id, payload + 44, 4);
                smb_info.session_id = ntohl(smb_info.session_id);

                memcpy(&smb_info.tree_id, payload + 40, 2);
                smb_info.tree_id = ntohs(smb_info.tree_id);

                static const std::regex pipe_regex(R"(\\pipe\\([a-zA-Z0-9_]+))",
                    std::regex_constants::icase | std::regex_constants::optimize);

                std::string payload_str(reinterpret_cast<const char*>(payload), len);
                std::smatch matches;
                if (std::regex_search(payload_str, matches, pipe_regex)) {
                    smb_info.named_pipe = "\\\\" + matches[0].str();
                }
            }
        }
        return smb_info;
    }

	// Track sessions for correlation
    SessionInfo& track_session(const std::string& src_ip, int src_port,
        const std::string& dst_ip, int dst_port, uint32_t call_id) {

        std::string session_key = src_ip + ":" + std::to_string(src_port) +
            "->" + dst_ip + ":" + std::to_string(dst_port);

        std::lock_guard<std::mutex> lock(session_mutex);

        auto it = session_tracker.find(session_key);
        if (it == session_tracker.end()) {
            SessionInfo new_session;
            new_session.session_id = session_key;
            new_session.conversation_id = "rpc_conv_" + std::to_string(
                std::hash<std::string>{}(session_key + std::to_string(call_id)));
            new_session.start_time = std::time(nullptr);
            new_session.packet_count = 1;
            new_session.is_new = true;

            session_tracker[session_key] = new_session;
            return session_tracker[session_key];
        }
        else {
            it->second.packet_count++;
            it->second.is_new = false;
            return it->second;
        }
    }

	// Determine communication direction based on geolocation info
    std::string determine_direction_with_geo(const std::string& src_ip, const std::string& dst_ip,
        const GeolocationEngine::GeolocationInfo& geo_info) {
        if (geo_info.is_internal_communication) {
            if (geo_info.source_network_zone == "management" || geo_info.destination_network_zone == "management") {
                return "management";
            }
            return "lateral";
        }

        if (geo_info.source_network_zone == "external") return "inbound";
        if (geo_info.destination_network_zone == "external") return "outbound";
        return "unknown";
    }

	// Map packet type to event type
    std::string get_event_type_from_packet(uint8_t packet_type) {
        switch (packet_type) {
        case 0:  return "rpc_request";
        case 2:  return "rpc_response";
        case 11: case 12: case 13: case 14: return "rpc_bind";
        case 3:  return "rpc_fault";
        default: return "rpc_request";
        }
    }

	// Calculate overall severity score
    std::string calculate_severity(const std::string& geographic_risk,
        const std::vector<std::string>& suspicious_patterns,
        const AuthInfo& auth_info,
        const std::string& interface_name,
        bool is_cross_border,
        const std::string& direction,
        int threat_intel_risk_score) {

        int severity_score = (threat_intel_risk_score * 0.5);

        if (geographic_risk == "critical") severity_score += 20;
        else if (geographic_risk == "high") severity_score += 15;
        else if (geographic_risk == "medium") severity_score += 8;
        else if (geographic_risk == "low") severity_score += 2;

        if (auth_info.bypass_detected) severity_score += 15;
        else if (auth_info.suspicious_auth) severity_score += 10;
        else if (auth_info.auth_type == "None" && direction == "inbound") severity_score += 8;

        if (interface_name == "Service Control Manager" || interface_name == "DRSUAPI" ||
            interface_name == "LSASS" || interface_name == "Print Spooler") {
            severity_score += 15;
        }
        else if (interface_name == "Task Scheduler" || interface_name == "Registry" || interface_name == "SAMR") {
            severity_score += 10;
        }

        if (severity_score >= 80) return "critical";
        else if (severity_score >= 60) return "high";
        else if (severity_score >= 30) return "medium";
        else return "low";
    }

public:
    CompleteRPCParser(const std::string& geoip_db_path, const std::string& asn_db_path) {
        try {
            geo_engine = std::make_unique<GeolocationEngine>(geoip_db_path, asn_db_path);
        }
        catch (const std::exception& e) {
            std::cerr << "Warning: Could not initialize geolocation engine: " << e.what() << std::endl;
            geo_engine = nullptr;
        }
    }

	// Main packet parsing function
    json parse_packet(const uint8_t* packet_data, size_t packet_len) {
        timeval packetTime;
        std::time_t now = std::time(nullptr);
        packetTime.tv_sec = static_cast<long>(now);
        packetTime.tv_usec = 0;
        pcpp::RawPacket rawPacket(packet_data, packet_len, packetTime, false);
        pcpp::Packet parsedPacket(&rawPacket);

        json event = { {"rpc_packet_analysis", {}} };
        auto& rpc_analysis = event["rpc_packet_analysis"];

        std::string src_ip = "0.0.0.0", dst_ip = "0.0.0.0", protocol = "unknown";
        int src_port = 0, dst_port = 0;
        bool has_valid_network_layer = false;
		
        // Extract network layer information
        if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
            auto ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
            if (ipv4Layer != nullptr) {
                src_ip = ipv4Layer->getSrcIPAddress().toString();
                dst_ip = ipv4Layer->getDstIPAddress().toString();
                has_valid_network_layer = true;
            }
        }
        else if (parsedPacket.isPacketOfType(pcpp::IPv6)) {
            auto ipv6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
            if (ipv6Layer != nullptr) {
                src_ip = ipv6Layer->getSrcIPAddress().toString();
                dst_ip = ipv6Layer->getDstIPAddress().toString();
                has_valid_network_layer = true;
            }
        }
        
        if (parsedPacket.isPacketOfType(pcpp::TCP)) {
            auto tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
            if (tcpLayer != nullptr) {
                src_port = tcpLayer->getSrcPort();
                dst_port = tcpLayer->getDstPort();
                protocol = "TCP";
            }
        }
        else if (parsedPacket.isPacketOfType(pcpp::UDP)) {
            auto udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
            if (udpLayer != nullptr) {
                src_port = udpLayer->getSrcPort();
                dst_port = udpLayer->getDstPort();
                protocol = "UDP";
            }
        }

		// Geolocation analysis
        GeolocationEngine::GeolocationInfo geo_info;
        if (geo_engine && has_valid_network_layer && 
            src_ip != "0.0.0.0" && dst_ip != "0.0.0.0") {
            try {
                geo_info = geo_engine->analyze_communication(src_ip, dst_ip);
            } catch (const std::exception& e) {
                std::cerr << "Geolocation analysis failed: " << e.what() << std::endl;
            }
        }
        
        std::string direction = determine_direction_with_geo(src_ip, dst_ip, geo_info);

        rpc_analysis["network_information"] = {
            {"source_ip", src_ip},
            {"source_port", src_port},
            {"destination_ip", dst_ip},
            {"destination_port", dst_port},
            {"protocol", protocol},
            {"direction", direction}
        };

        std::string event_type = "rpc_request";
        std::string severity = "low";
        std::string interface_name = "Unknown";
        std::string operation_name = "";
        uint32_t call_id = 0;

        auto payloadLayer = parsedPacket.getLayerOfType<pcpp::PayloadLayer>();
        if (payloadLayer) {
            const uint8_t* payload = payloadLayer->getPayload();
            size_t payload_len = payloadLayer->getPayloadLen();

            DCERPCHeader rpc_header = {};
            std::string interface_uuid;

            if (parse_dcerpc_header(payload, payload_len, rpc_header)) {
                event_type = get_event_type_from_packet(rpc_header.packet_type);

                interface_uuid = extract_interface_uuid(payload, payload_len, sizeof(DCERPCHeader));
                interface_name = uuid_to_interface.count(interface_uuid) ?
                    uuid_to_interface[interface_uuid] : "Unknown";

                if (operation_mappings.count(interface_uuid) &&
                    operation_mappings[interface_uuid].count(rpc_header.operation_number)) {
                    operation_name = operation_mappings[interface_uuid][rpc_header.operation_number];
                }

                call_id = rpc_header.call_id;
            }

            std::vector<std::string> fragment_flags;
            if (rpc_header.fragment_flags & 0x01) fragment_flags.push_back("first_fragment");
            if (rpc_header.fragment_flags & 0x02) fragment_flags.push_back("last_fragment");

            rpc_analysis["rpc_details"] = {
                {"interface_uuid", interface_uuid},
                {"interface_name", interface_name},
                {"operation_number", rpc_header.operation_number},
                {"operation_name", operation_name},
                {"rpc_version", rpc_header.version},
                {"packet_type", packet_types.count(rpc_header.packet_type) ? packet_types[rpc_header.packet_type] : "unknown"},
                {"call_id", call_id},
                {"fragment_flags", fragment_flags}
            };

            SMBInfo smb_info = parse_smb_layer(payload, payload_len);

            rpc_analysis["transport_context"] = {
                {"transport_type", smb_info.is_smb_transport ? "named_pipe" : protocol},
                {"named_pipe", smb_info.named_pipe},
                {"smb_tree_id", smb_info.tree_id},
                {"smb_session_id", smb_info.session_id}
            };

            AuthInfo auth_info = parse_auth_context(payload, payload_len);

            rpc_analysis["authentication_context"] = {
                {"auth_present", auth_info.auth_present},
                {"auth_type", auth_info.auth_type},
                {"auth_level", auth_info.auth_level},
                {"impersonation_level", auth_info.impersonation_level}
            };

            PayloadAnalysis payload_analysis = analyze_payload(payload, payload_len);

            rpc_analysis["payload_analysis"] = {
                {"payload_size", static_cast<int>(payload_len)},
                {"contains_sensitive_data", payload_analysis.contains_sensitive_data},
                {"encryption_detected", payload_analysis.encryption_detected},
                {"suspicious_patterns", payload_analysis.suspicious_patterns},
                {"string_analysis", {
                    {"contains_unicode", payload_analysis.string_analysis.contains_unicode},
                    {"contains_base64", payload_analysis.string_analysis.contains_base64},
                    {"contains_urls", payload_analysis.string_analysis.contains_urls},
                    {"contains_file_paths", payload_analysis.string_analysis.contains_file_paths},
                    {"contains_registry_keys", payload_analysis.string_analysis.contains_registry_keys},
                    {"contains_credentials", payload_analysis.string_analysis.contains_credentials},
                    {"contains_powershell", payload_analysis.string_analysis.contains_powershell},
                    {"contains_executable_extensions", payload_analysis.string_analysis.contains_executable_extensions}
                }}
            };

   			// Threat Intelligence integration
            auto threat_result = threat_intel_engine.analyze_threat(
                interface_uuid,
                rpc_header.operation_number,
                payload_analysis.suspicious_patterns,
                auth_info,
                geo_info.source_country,
                geo_info.source_asn,
                direction,
                geo_info.is_cross_border,
                payload_analysis
            );

            //Threat intelligence section
            rpc_analysis["threat_intelligence"] = {
                {"risk_score", threat_result.risk_score},
                {"attack_techniques", threat_result.attack_techniques},
                {"threat_indicators", threat_result.threat_indicators},
                {"attack_pattern", threat_result.attack_pattern},
                {"ioc_matches", threat_result.ioc_matches}
            };

            // Calculate severity using threat intelligence
            severity = calculate_severity(
                geo_info.geographic_risk,
                payload_analysis.suspicious_patterns,
                auth_info,
                interface_name,
                geo_info.is_cross_border,
                direction,
                threat_result.risk_score
            );

            // Session context with tracking
            SessionInfo& session = track_session(src_ip, src_port, dst_ip, dst_port, call_id);
            double session_duration = std::difftime(std::time(nullptr), session.start_time);

            rpc_analysis["session_context"] = {
                {"session_id", session.session_id},
                {"is_new_session", session.is_new},
                {"session_duration", session_duration},
                {"packet_count_in_session", session.packet_count}
            };

            // Raw evidence
            rpc_analysis["raw_evidence"] = {
                {"rpc_header_hex", bytes_to_hex(payload, payload_len)},
                {"interface_signature", interface_uuid + ":" + std::to_string(rpc_header.operation_number)},
                {"packet_hash", sha256_hash(packet_data, packet_len)}
            };
        }

        // Event metadata
        rpc_analysis["event_metadata"] = {
            {"timestamp", get_iso8601_timestamp()},
            {"event_type", event_type},
            {"severity", severity}
        };

        // Geolocation section
        if (geo_engine) {
            rpc_analysis["geolocation"] = {
                {"source_country", geo_info.source_country},
                {"source_asn", geo_info.source_asn},
                {"is_internal_communication", geo_info.is_internal_communication},
                {"is_cross_border", geo_info.is_cross_border},
                {"geographic_risk", geo_info.geographic_risk}
            };
        }
        else {
            rpc_analysis["geolocation"] = {
                {"source_country", ""},
                {"source_asn", nullptr},
                {"is_internal_communication", network_topology.is_internal_ip(src_ip) && network_topology.is_internal_ip(dst_ip)},
                {"is_cross_border", false},
                {"geographic_risk", "unknown"}
            };
        }

        return event;
    }
};

// Mainnnnnn Function
int main(int argc, char* argv[]) {
    try {
        // Initialize parser with MaxMind database paths
        std::string geoip_path = "..\\..\\GeoLite2-City.mmdb";
        std::string asn_path = "..\\..\\GeoLite2-ASN.mmdb";

        // Create the RPC parser
        CompleteRPCParser parser(geoip_path, asn_path);

        // Create a thread pool with hardware concurrency
        unsigned int num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 4;
        ThreadPool pool(num_threads);

        // Check command line arguments
        if (argc < 2) {
            std::cerr << "Usage: " << argv[0] << " <packet1.bin> [packet2.bin] [packet3.bin] ..." << std::endl;
            return 1;
        }

        // Vector to hold futures
        std::vector<std::future<json>> futures;
        std::vector<std::string> input_files;

        // Process each packet file in parallel
        for (int i = 1; i < argc; ++i) {
            std::string packet_file = argv[i];
            input_files.push_back(packet_file);

            futures.push_back(pool.enqueue([packet_file, &parser]() {
                try {
                    // Read packet data
                    std::ifstream file(packet_file, std::ios::binary);
                    if (!file) {
                        std::cerr << "Thread error: Cannot open packet file: " << packet_file << std::endl;
                        return json();
                    }

                    std::vector<uint8_t> packet_data((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

                    if (packet_data.empty()) {
                        std::cerr << "Thread warning: Empty packet file: " << packet_file << std::endl;
                        return json();
                    }

                    json result = parser.parse_packet(packet_data.data(), packet_data.size());
                    return result;
                }
                catch (const std::exception& e) {
                    return json();
                }
            }));
        }

		// Save each result to its own file
        for (size_t i = 0; i < futures.size(); ++i) {
            json result = futures[i].get();
            if (!result.empty()) {
                // Generate output filename based on input filename
                std::string input_file = input_files[i];
                std::string base_filename = input_file;
                
                // Extract just the filename without path
                size_t last_separator = base_filename.find_last_of("/\\");
                if (last_separator != std::string::npos) {
                    base_filename = base_filename.substr(last_separator + 1);
                }
                
                // Remove extension if present
                size_t dot_pos = base_filename.find_last_of('.');
                if (dot_pos != std::string::npos) {
                    base_filename = base_filename.substr(0, dot_pos);
                }
                
                std::string output_file = "analysis_" + base_filename + ".json";
                
                // Write this result to its own file
                std::ofstream out_file(output_file);
                if (out_file) {
                    out_file << std::setw(4) << result << std::endl;
                }
                else {
                    std::cerr << "Error: Unable to write to output file " << output_file << std::endl;
                    // Print to console as fallback
                    std::cout << "Analysis result for " << input_file << ":" << std::endl;
                    std::cout << std::setw(4) << result << std::endl;
                }
            }
        }
    }

	// Global exception handling
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}   