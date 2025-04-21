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

// ANSI 颜色代码
const string RED = "\033[38;5;203m";     // 柔和的红色
const string YELLOW = "\033[38;5;221m";  // 柔和的黄色
const string GREEN = "\033[38;5;114m";   // 柔和的绿色
const string BLUE = "\033[38;5;110m";    // 柔和的蓝色
const string CYAN = "\033[38;5;116m";    // 柔和的青色
const string PINK = "\033[38;5;218m";    // 温柔的粉色
const string PURPLE = "\033[38;5;183m";  // 柔和的紫色
const string DIM = "\033[2m";
const string ITALIC = "\033[3m";
const string BOLD = "\033[1m";
const string RESET = "\033[0m";

// 边框字符 - 使用ASCII字符替代Unicode
const string TOP_LEFT = "+";
const string TOP_RIGHT = "+";
const string BOTTOM_LEFT = "+";
const string BOTTOM_RIGHT = "+";
const string VERTICAL = "|";
const string HORIZONTAL = "-";
const string MIDDLE_LEFT = "+";
const string MIDDLE_RIGHT = "+";
const string MIDDLE_DOWN = "+";
const string MIDDLE_UP = "+";
const string CROSS = "+";

// IP 包计数和时间戳追踪
unordered_map<string, int> ipPacketCount;
// 记录每个IP的最近出现时间
unordered_map<string, deque<time_t>> ipTimestamps;
// 检测重复IP的时间窗口（秒）
const int REPEAT_WINDOW = 5;
// 判定为频繁出现的最小次数
const int FREQ_THRESHOLD = 5;

// 流量统计结构
struct TrafficStats {
    uint64_t bytes;              // 字节计数
    int packets;                 // 包计数
    map<int, int> ports;         // 端口访问统计
    map<string, int> protocols;  // 协议类型统计
};

// 全局统计数据
unordered_map<string, TrafficStats> ipStats;

// 常见端口服务映射表
const map<int, string> commonPorts = {
    {80, "HTTP"},  {443, "HTTPS"},  {22, "SSH"},        {21, "FTP"},
    {53, "DNS"},   {3306, "MySQL"}, {27017, "MongoDB"}, {25, "SMTP"},
    {110, "POP3"}, {143, "IMAP"}};

// 数据包详细信息结构体
struct PacketDetails {
    time_t timestamp;           // 时间戳
    string protocol;            // 协议类型
    uint16_t length;            // 数据包长度
    string srcIp;               // 源IP地址
    string dstIp;               // 目标IP地址
    uint16_t srcPort;           // 源端口
    uint16_t dstPort;           // 目标端口
    map<string, string> flags;  // TCP标志位
    vector<uint8_t> payload;    // 数据负载
};

// 数据包历史记录环形缓冲区
const int PACKET_HISTORY_SIZE = 1000;
deque<PacketDetails> packetHistory;

// 清屏函数，模拟刷新
void clearScreen() {
    // 使用 ANSI 转义代码清屏
    cout << "\033[2J\033[1;1H";
}

// 检查IP是否频繁出现
bool isFrequentIP(const string& ip) {
    auto now = time(nullptr);
    auto& timestamps = ipTimestamps[ip];

    // 清理过期的时间戳
    while (!timestamps.empty() && now - timestamps.front() > REPEAT_WINDOW) {
        timestamps.pop_front();
    }

    // 添加当前时间戳
    timestamps.push_back(now);

    // 如果在时间窗口内出现次数超过阈值，判定为频繁IP
    return timestamps.size() >= FREQ_THRESHOLD;
}

// 获取接口描述
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

// 数据包处理函数
void packetHandler(u_char* args, const struct pcap_pkthdr* header,
                   const u_char* packet) {
    // 解析IP头部
    const struct ip* ipHeader = (struct ip*)(packet + 14);
    string srcIp = inet_ntoa(ipHeader->ip_src);
    string dstIp = inet_ntoa(ipHeader->ip_dst);

    // 首先进行协议检测
    int srcPort = 0, dstPort = 0;
    string protocol;

    switch (ipHeader->ip_p) {
        case IPPROTO_TCP: {
            // TCP协议处理
            const struct tcphdr* tcp =
                (struct tcphdr*)(packet + 14 + ipHeader->ip_hl * 4);
            srcPort = ntohs(tcp->th_sport);
            dstPort = ntohs(tcp->th_dport);
            protocol = "TCP";

            // HTTP/HTTPS检测
            const char* payload =
                (const char*)(packet + 14 + ipHeader->ip_hl * 4 +
                              tcp->th_off * 4);
            if (dstPort == 80 && strstr(payload, "HTTP") != nullptr) {
                protocol = "HTTP";
            } else if (dstPort == 443) {
                protocol = "HTTPS";
            }
            break;
        }
        case IPPROTO_UDP: {
            // UDP协议处理
            const struct udphdr* udp =
                (struct udphdr*)(packet + 14 + ipHeader->ip_hl * 4);
            srcPort = ntohs(udp->uh_sport);
            dstPort = ntohs(udp->uh_dport);
            protocol = "UDP";
            break;
        }
        case IPPROTO_ICMP: {
            // ICMP协议处理
            protocol = "ICMP";
            break;
        }
        default:
            protocol = "其他";
    }

    // 格式化输出界面
    static bool headerPrinted = false;
    if (!headerPrinted) {
        cout << "\n🌊 流量防护卫士已激活\n"
             << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
        headerPrinted = true;
    }

    // 格式化IP地址显示
    string formattedSrcIp = isFrequentIP(srcIp)
                                ? BOLD + RED + "⚠️  " + srcIp + RESET
                                : "   " + srcIp;

    string formattedDstIp = isFrequentIP(dstIp)
                                ? BOLD + RED + "⚠️  " + dstIp + RESET
                                : "   " + dstIp;

    // 获取服务信息
    string serviceInfo =
        commonPorts.count(dstPort) ? " (" + commonPorts.at(dstPort) + ")" : "";

    // 构建漂亮的表格输出
    cout << PINK << TOP_LEFT << string(70, HORIZONTAL[0]) << TOP_RIGHT << RESET
         << "\n"
         << PINK << VERTICAL << RESET << " 🌸 数据包信息 " << string(57, ' ')
         << PINK << VERTICAL << RESET << "\n"
         << PINK << MIDDLE_LEFT << string(70, HORIZONTAL[0]) << MIDDLE_RIGHT
         << RESET << "\n"
         << PINK << VERTICAL << RESET << " 源地址: " << formattedSrcIp
         << string(10, ' ') << " 目标地址: " << formattedDstIp
         << string(10, ' ') << PINK << VERTICAL << RESET << "\n"
         << PINK << VERTICAL << RESET << " 协议: " << CYAN << setw(10)
         << protocol << RESET << " 端口: " << YELLOW << srcPort << "➜"
         << dstPort << serviceInfo << RESET << " 大小: " << BLUE << header->len
         << " 字节" << RESET << string(5, ' ') << PINK << VERTICAL << RESET
         << "\n"
         << PINK << BOTTOM_LEFT << string(70, HORIZONTAL[0]) << BOTTOM_RIGHT
         << RESET << "\n";

    // 更新统计信息
    ipStats[srcIp].bytes += header->len;
    ipStats[srcIp].packets++;
    ipPacketCount[srcIp]++;
    ipStats[srcIp].protocols[protocol]++;
    if (dstPort > 0) {
        ipStats[srcIp].ports[dstPort]++;
    }
}

// 显示统计信息
void displayStatistics() {
    clearScreen();
    // 显示超可爱的标题框
    cout << "\n"
         << PINK << TOP_LEFT << HORIZONTAL << HORIZONTAL << HORIZONTAL
         << HORIZONTAL << BOLD << "🎀 流量防护卫士 " << RESET << PINK << "🌸"
         << string(30, HORIZONTAL[0]) << TOP_RIGHT << "\n"
         << VERTICAL << string(60, ' ') << VERTICAL << "\n"
         << VERTICAL << "  " << PURPLE
         << "💝 欢迎回来! 让我们一起守护网络安全吧~ 💕" << RESET << PINK
         << string(10, ' ') << VERTICAL << "\n"
         << BOTTOM_LEFT << string(60, HORIZONTAL[0]) << BOTTOM_RIGHT << RESET
         << "\n\n";

    // 数据包统计表格
    cout << CYAN << "🦋 实时流量分析: 每秒数据包统计" << RESET << "\n";
    cout << PINK << TOP_LEFT << string(60, HORIZONTAL[0]) << TOP_RIGHT << "\n"
         << VERTICAL << " " << BOLD << setw(20) << "IP 地址" << " " << VERTICAL
         << " " << setw(15) << "数据包/秒" << " " << VERTICAL << " " << setw(15)
         << "状态" << RESET << PINK << " " << VERTICAL << "\n"
         << MIDDLE_LEFT << string(22, HORIZONTAL[0]) << CROSS
         << string(17, HORIZONTAL[0]) << CROSS << string(18, HORIZONTAL[0])
         << MIDDLE_RIGHT << "\n";

    // 显示IP统计信息
    for (const auto& [ip, count] : ipPacketCount) {
        string statusIcon = (count > 100) ? "🚨" : (count > 10) ? "⚠️" : "✓";
        string color = (count > 100) ? RED : (count > 10) ? YELLOW : "";
        cout << "│ " << left << setw(18) << ip << " │ " << setw(13) << count
             << " │ " << color << setw(13) << statusIcon << RESET << " │\n";
    }
    cout << "└────────────────────┴───────────────┴───────────────┘" << endl;

    // 流量字节数统计
    cout << "\n" << PURPLE << "🎭 流量分析: 总流量统计 " << RESET << "\n";
    cout << PINK << TOP_LEFT << string(45, HORIZONTAL[0]) << TOP_RIGHT << RESET
         << "\n";
    cout << PINK << VERTICAL << RESET << CYAN << " 🌐 " << left << setw(17)
         << "IP 地址" << PINK << VERTICAL << RESET << CYAN << " 💫 "
         << "总字节数" << string(8, ' ') << PINK << VERTICAL << RESET << "\n";
    cout << PINK << MIDDLE_LEFT << string(45, HORIZONTAL[0]) << MIDDLE_RIGHT
         << RESET << "\n";
    for (const auto& [ip, stats] : ipStats) {
        cout << PINK << VERTICAL << RESET << " " << left << setw(19) << ip
             << PINK << VERTICAL << RESET << " " << BLUE << setw(15)
             << stats.bytes << RESET << PINK << VERTICAL << RESET << "\n";
    }
    cout << PINK << BOTTOM_LEFT << string(45, HORIZONTAL[0]) << BOTTOM_RIGHT
         << RESET << "\n";

    // 协议类型统计
    cout << "\n" << PURPLE << "🎪 流量分析: 协议类型分布 " << RESET << "\n";
    cout << PINK << TOP_LEFT << string(52, HORIZONTAL[0]) << TOP_RIGHT << RESET
         << "\n";
    cout << PINK << VERTICAL << RESET << CYAN << " 🌐 " << left << setw(17)
         << "IP 地址" << PINK << VERTICAL << RESET << CYAN << " 🔮 " << setw(12)
         << "协议类型" << PINK << VERTICAL << RESET << CYAN << " 🎯 " << "数量"
         << string(8, ' ') << PINK << VERTICAL << RESET << "\n";
    cout << PINK << MIDDLE_LEFT << string(52, HORIZONTAL[0]) << MIDDLE_RIGHT
         << RESET << "\n";
    for (const auto& [ip, stats] : ipStats) {
        for (const auto& [protocol, count] : stats.protocols) {
            cout << PINK << VERTICAL << RESET << " " << left << setw(19) << ip
                 << PINK << VERTICAL << RESET << " " << setw(14) << protocol
                 << PINK << VERTICAL << RESET << " " << BLUE << setw(13)
                 << count << RESET << PINK << VERTICAL << RESET << "\n";
        }
    }
    cout << PINK << BOTTOM_LEFT << string(52, HORIZONTAL[0]) << BOTTOM_RIGHT
         << RESET << "\n";
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* allDevs;

    // 获取所有可用网络设备
    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        cerr << "无法找到网络设备: " << errbuf << endl;
        return 1;
    }

    // 选择监听的网络设备
    cout << "选择监听的网络接口 (Select Network Interface):\n" << endl;
    int i = 0;
    for (pcap_if_t* d = allDevs; d; d = d->next) {
        string desc = getInterfaceDescription(d->name);
        cout << ++i << ": " << left << setw(15) << d->name << "[" << desc << "]"
             << (d->description ? (" (" + string(d->description) + ")") : "")
             << endl;
    }

    int devIndex;
    cout << "输入设备编号: ";
    cin >> devIndex;

    pcap_if_t* selectedDev = allDevs;
    for (int j = 1; j < devIndex; ++j) {
        selectedDev = selectedDev->next;
    }

    // 打开设备进行实时包捕获
    pcap_t* handle = pcap_open_live(selectedDev->name, BUFSIZ, 1, 1000, errbuf);

    // 每秒更新显示
    time_t last = time(nullptr);

    while (true) {
        pcap_loop(handle, 0, packetHandler,
                  nullptr);  // Capture packets indefinitely

        time_t now = time(nullptr);
        if (now - last >= 1) {
            // 清屏，模拟 TUI 刷新
            clearScreen();

            // 构建统计信息
            displayStatistics();

            last = now;
        }

        // 睡眠 3 秒，模拟周期更新
        usleep(3000000);  // 睡眠 3 秒
    }

    pcap_close(handle);
    pcap_freealldevs(allDevs);
    return 0;
}
