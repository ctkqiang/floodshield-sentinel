#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <unistd.h>

#include <ctime>
#include <deque>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

/** ANSI 颜色代码 */
const string RED = "\033[31m";
const string YELLOW = "\033[33m";
const string RESET = "\033[0m";

/** IP 包计数和时间戳追踪 */
unordered_map<string, int> ip_packet_count;
/** 记录每个IP的最近出现时间 */
unordered_map<string, deque<time_t>> ip_timestamps;
/** 检测重复IP的时间窗口（秒）*/
const int REPEAT_WINDOW = 5;
/** 判定为频繁出现的最小次数 */
const int FREQ_THRESHOLD = 5;

/** 检查IP是否频繁出现 */

void clearScreen();

bool isFrequentIP(const string& ip) {
    auto now = time(nullptr);
    auto& timestamps = ip_timestamps[ip];

    /** 清理过期的时间戳 */
    while (!timestamps.empty() && now - timestamps.front() > REPEAT_WINDOW) {
        timestamps.pop_front();
    }

    /** 添加当前时间戳 */
    timestamps.push_back(now);

    /** 如果在时间窗口内出现次数超过阈值，判定为频繁IP */
    return timestamps.size() >= FREQ_THRESHOLD;
}

/** 流量统计结构 */
struct TrafficStats {
    uint64_t bytes;             /** 字节计数 */
    int packets;                /** 包计数 */
    map<int, int> ports;        /** 端口访问统计 */
    map<string, int> protocols; /** 协议类型统计 */
};

/** 全局统计数据 */
unordered_map<string, TrafficStats> ip_stats;

/** 常见端口服务映射表 */
const map<int, string> common_ports = {
    {80, "HTTP"},  {443, "HTTPS"},  {22, "SSH"},        {21, "FTP"},
    {53, "DNS"},   {3306, "MySQL"}, {27017, "MongoDB"}, {25, "SMTP"},
    {110, "POP3"}, {143, "IMAP"}};

const string BOLD = "\033[1m";

/** 新增 ANSI 颜色和样式定义 */
const string GREEN = "\033[32m";
const string BLUE = "\033[34m";
const string CYAN = "\033[36m";
const string DIM = "\033[2m";
const string ITALIC = "\033[3m";

/** 数据包详细信息结构体 */
struct PacketDetails {
    time_t timestamp;          /** 时间戳 */
    string protocol;           /** 协议类型 */
    uint16_t length;           /** 数据包长度 */
    string src_ip;             /** 源IP地址 */
    string dst_ip;             /** 目标IP地址 */
    uint16_t src_port;         /** 源端口 */
    uint16_t dst_port;         /** 目标端口 */
    map<string, string> flags; /** TCP标志位 */
    vector<uint8_t> payload;   /** 数据负载 */
};

/** 数据包历史记录环形缓冲区 */
const int PACKET_HISTORY_SIZE = 1000;
deque<PacketDetails> packet_history;

void packet_handler(u_char* args, const struct pcap_pkthdr* header,
                    const u_char* packet) {
    /** 解析IP头部 */
    const struct ip* ip_header = (struct ip*)(packet + 14);
    string src_ip = inet_ntoa(ip_header->ip_src);
    string dst_ip = inet_ntoa(ip_header->ip_dst);

    /** 首先进行协议检测 */
    int src_port = 0, dst_port = 0;
    string protocol;

    switch (ip_header->ip_p) {
        case IPPROTO_TCP: {
            /** TCP协议处理 */
            const struct tcphdr* tcp =
                (struct tcphdr*)(packet + 14 + ip_header->ip_hl * 4);
            src_port = ntohs(tcp->th_sport);
            dst_port = ntohs(tcp->th_dport);
            protocol = "TCP";

            /** HTTP/HTTPS检测 */
            const char* payload =
                (const char*)(packet + 14 + ip_header->ip_hl * 4 +
                              tcp->th_off * 4);
            if (dst_port == 80 && strstr(payload, "HTTP") != nullptr) {
                protocol = "HTTP";
            } else if (dst_port == 443) {
                protocol = "HTTPS";
            }
            break;
        }
        case IPPROTO_UDP: {
            /** UDP协议处理 */
            const struct udphdr* udp =
                (struct udphdr*)(packet + 14 + ip_header->ip_hl * 4);
            src_port = ntohs(udp->uh_sport);
            dst_port = ntohs(udp->uh_dport);
            protocol = "UDP";
            break;
        }
        case IPPROTO_ICMP: {
            /** ICMP协议处理 */
            protocol = "ICMP";
            break;
        }
        default:
            protocol = "其他";
    }

    /** 格式化输出界面 */
    static bool header_printed = false;
    if (!header_printed) {
        cout << "\n🌊 流量防护卫士已激活\n"
             << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
        header_printed = true;
    }

    /** 格式化IP地址显示 */
    string formatted_src_ip = isFrequentIP(src_ip)
                                  ? BOLD + RED + "⚠️  " + src_ip + RESET
                                  : "   " + src_ip;

    string formatted_dst_ip = isFrequentIP(dst_ip)
                                  ? BOLD + RED + "⚠️  " + dst_ip + RESET
                                  : "   " + dst_ip;

    /** 获取服务信息 */
    string service_info = common_ports.count(dst_port)
                              ? " (" + common_ports.at(dst_port) + ")"
                              : "";

    /** 构建输出信息 */
    stringstream ss;
    ss << YELLOW << "→ " << RESET << formatted_src_ip << YELLOW << " ⟹  "
       << RESET << formatted_dst_ip << "\n"
       << "   " << protocol << " [" << src_port << "➜" << dst_port
       << service_info << "]"
       << " • " << header->len << " 字节\n"
       << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";

    cout << ss.str();

    /** 更新统计信息 */
    ip_stats[src_ip].bytes += header->len;
    ip_stats[src_ip].packets++;
    ip_packet_count[src_ip]++;
    ip_stats[src_ip].protocols[protocol]++;
    if (dst_port > 0) {
        ip_stats[src_ip].ports[dst_port]++;
    }
}

/** 更新主循环的统计信息显示 */
void displayStatistics() {
    clearScreen();
    cout << "\n🛡️  流量防护卫士监控面板\n"
         << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
         << "📊 流量分析:\n";

    /** 显示IP统计信息 */
    for (const auto& [ip, count] : ip_packet_count) {
        string status_icon = (count > 100) ? "🚨" : (count > 10) ? "⚠️" : "✓";
        string color = (count > 100) ? RED : (count > 10) ? YELLOW : "";

        cout << status_icon << " " << color << ip << RESET << " • " << count
             << " 数据包/秒\n";
    }
    cout << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
}

/** 清屏函数，模拟刷新 */
void clearScreen() {
    /** 使用 ANSI 转义代码清屏 */
    cout << "\033[2J\033[1;1H";
}

string getInterfaceDescription(const string& name) {
    if (name == "en0") return "以太网/Wi-Fi 接口";
    if (name == "lo0") return "本地环回接口";
    if (name == "awdl0") return "苹果无线直连接口";
    if (name == "llw0") return "低延迟无线局域网";
    if (name == "utun0") return "VPN/隧道接口 0";
    if (name == "ap1") return "无线接入点";
    if (name == "bridge0") return "网桥接口";
    if (name == "gif0") return "通用隧道接口";
    if (name == "stf0") return "IPv6隧道接口";
    if (name.substr(0, 2) == "en") return "以太网接口";
    if (name.substr(0, 4) == "utun") return "VPN/隧道接口";
    if (name.substr(0, 4) == "anpi") return "锚点网络接口";
    return "其他网络接口";
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    /** 获取所有可用网络设备 */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "无法找到网络设备: " << errbuf << endl;
        return 1;
    }

    /** 选择监听的网络设备 */
    cout << "选择监听的网络接口 (Select Network Interface):\n" << endl;
    int i = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        string desc = getInterfaceDescription(d->name);
        cout << ++i << ": " << left << setw(15) << d->name << "[" << desc << "]"
             << (d->description ? (" (" + string(d->description) + ")") : "")
             << endl;
    }

    int dev_index;
    cout << "输入设备编号: ";
    cin >> dev_index;

    pcap_if_t* selected_dev = alldevs;
    for (int j = 1; j < dev_index; ++j) {
        selected_dev = selected_dev->next;
    }

    /** 打开设备进行实时包捕获 */
    pcap_t* handle =
        pcap_open_live(selected_dev->name, BUFSIZ, 1, 1000, errbuf);

    /** 每秒更新显示 */
    time_t last = time(nullptr);

    while (true) {
        pcap_loop(handle, 0, packet_handler,
                  nullptr); /** Capture packets indefinitely */

        time_t now = time(nullptr);
        if (now - last >= 1) {
            /** 清屏，模拟 TUI 刷新 */
            clearScreen();

            /** 构建统计信息 */
            stringstream stats;
            stats << "\n📊 每秒包数 Top IPs:\n";
            for (const auto& [ip, count] : ip_packet_count) {
                if (count > 100) {
                    stats << RED << "🚨 " << ip << ": " << count
                          << " packets/sec" << RESET << "\n";
                } else if (count > 10) {
                    stats << "⚠️ " << ip << ": " << count << " packets/sec\n";
                }
            }

            /** 输出统计信息 */
            cout << "🛡️ 抗洪卫士: 正在监听流量...\n" << stats.str();

            last = now;
        }

        /** 睡眠 3 秒，模拟周期更新 */
        usleep(3000000); /** 睡眠 3 秒 */
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
