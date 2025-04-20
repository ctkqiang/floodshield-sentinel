#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <unistd.h>

#include <ctime>
#include <deque>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

// ANSI 颜色代码
const string RED = "\033[31m";
const string YELLOW = "\033[33m";
const string RESET = "\033[0m";

// IP 包计数和时间戳追踪
unordered_map<string, int> ip_packet_count;
// 记录每个IP的最近出现时间
unordered_map<string, deque<time_t>> ip_timestamps;
// 检测重复IP的时间窗口（秒）
const int REPEAT_WINDOW = 5;
// 判定为频繁出现的最小次数
const int FREQ_THRESHOLD = 5;

// 检查IP是否频繁出现
bool isFrequentIP(const string& ip) {
    auto now = time(nullptr);
    auto& timestamps = ip_timestamps[ip];

    // 清理过期的时间戳
    while (!timestamps.empty() && now - timestamps.front() > REPEAT_WINDOW) {
        timestamps.pop_front();
    }

    // 添加当前时间戳
    timestamps.push_back(now);

    // 如果在时间窗口内出现次数超过阈值，判定为频繁IP
    return timestamps.size() >= FREQ_THRESHOLD;
}

void packet_handler(u_char* args, const struct pcap_pkthdr* header,
                    const u_char* packet) {
    // IP 头部偏移：Ethernet 是 14 字节
    const struct ip* ip_header = (struct ip*)(packet + 14);
    string src_ip = inet_ntoa(ip_header->ip_src);
    string dst_ip = inet_ntoa(ip_header->ip_dst);

    ip_packet_count[src_ip]++;

    stringstream ss;
    // 根据IP出现频率使用不同颜色标记
    if (isFrequentIP(src_ip)) {
        ss << YELLOW << "📦 " << src_ip << " ➜ " << dst_ip << RESET;
    } else {
        ss << "📦 " << src_ip << " ➜ " << dst_ip;
    }

    if (ip_header->ip_p == IPPROTO_TCP) {
        const struct tcphdr* tcp =
            (struct tcphdr*)(packet + 14 + ip_header->ip_hl * 4);
        ss << " | TCP " << ntohs(tcp->th_sport) << "➜" << ntohs(tcp->th_dport);
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        const struct udphdr* udp =
            (struct udphdr*)(packet + 14 + ip_header->ip_hl * 4);
        ss << " | UDP " << ntohs(udp->uh_sport) << "➜" << ntohs(udp->uh_dport);
    }

    // 打印包的详细信息
    cout << ss.str() << endl;
}

// 清屏函数，模拟刷新
void clearScreen() {
    // 使用 ANSI 转义代码清屏
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

    // 获取所有可用网络设备
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "无法找到网络设备: " << errbuf << endl;
        return 1;
    }

    // 选择监听的网络设备
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

    // 打开设备进行实时包捕获
    pcap_t* handle =
        pcap_open_live(selected_dev->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << "无法打开设备: " << errbuf << endl;
        return 1;
    }

    cout << "🛡️ 正在监听 " << selected_dev->name << " 上的流量...\n";

    // 每秒更新显示
    time_t last = time(nullptr);

    while (true) {
        pcap_loop(handle, 0, packet_handler,
                  nullptr);  // Capture packets indefinitely

        time_t now = time(nullptr);
        if (now - last >= 1) {
            // 清屏，模拟 TUI 刷新
            clearScreen();

            // 构建统计信息
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

            // 输出统计信息
            cout << "🛡️ 抗洪卫士: 正在监听流量...\n" << stats.str();

            last = now;
        }

        // 睡眠 1 秒，模拟周期更新
        usleep(1000000);  // 睡眠 1 秒
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
