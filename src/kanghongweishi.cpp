#include <arpa/inet.h>
#include <iconv.h>
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

// 边框字符 - 使用简单ASCII字符
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
    time_t timestamp;                 // 时间戳
    string protocol;                  // 协议类型
    uint16_t length;                  // 数据包长度
    string srcIp;                     // 源IP地址
    string dstIp;                     // 目标IP地址
    uint16_t srcPort;                 // 源端口
    uint16_t dstPort;                 // 目标端口
    map<string, string> flags;        // TCP标志位
    vector<uint8_t> payload;          // 数据负载
    string httpMethod;                // HTTP方法
    string httpUri;                   // HTTP URI
    map<string, string> httpHeaders;  // HTTP头部
    string httpVersion;               // HTTP版本
    int httpResponseCode;             // HTTP响应码
};

// 流量异常检测配置
// IP地理位置信息结构体
struct GeoLocation {
    string country;    // 国家
    string city;       // 城市
    string region;     // 地区
    double latitude;   // 纬度
    double longitude;  // 经度
    string isp;        // 网络服务提供商
};

// 智能防护建议结构体
struct SecurityAdvice {
    string level;         // 建议等级：温馨提醒/注意/警告
    string description;   // 建议描述
    string emoji;         // 表情图标
    vector<string> tips;  // 具体建议列表
};

struct AnomalyConfig {
    uint64_t maxBytesPerSecond = 1000000;  // 每秒最大字节数
    int maxPacketsPerSecond = 1000;        // 每秒最大包数
    int maxConnectionsPerIP = 100;         // 每个IP最大连接数
    int burstThreshold = 50;               // 突发流量阈值

    // 智能告警配置
    int alertInterval = 60;           // 告警间隔（秒）
    bool enableGeoTracking = true;    // 启用地理位置追踪
    bool enableTrendAnalysis = true;  // 启用趋势分析
    int trendWindowSize = 5;          // 趋势分析窗口（秒）
};

// 流量异常事件
struct AnomalyEvent {
    time_t timestamp;
    string type;         // 异常类型
    string description;  // 异常描述
    string sourceIP;     // 源IP
    double value;        // 异常值
    double threshold;    // 阈值
};

// 全局异常检测配置
AnomalyConfig anomalyConfig;

// 异常事件历史
deque<AnomalyEvent> anomalyHistory;

// TCP连接状态追踪
struct TCPConnection {
    string srcIP;
    string dstIP;
    uint16_t srcPort;
    uint16_t dstPort;
    string state;  // ESTABLISHED, SYN_SENT, etc.
    time_t lastSeen;
    uint64_t bytesReceived;
    uint64_t bytesSent;
};

// TCP连接跟踪映射
map<string, TCPConnection> tcpConnections;

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

// IP地理位置缓存
map<string, GeoLocation> geoCache;

// GBK转UTF8函数
string gbkToUtf8(const string& gbkStr) {
    iconv_t cd = iconv_open("UTF-8", "GBK");
    if (cd == (iconv_t)-1) {
        return gbkStr;
    }

    const char* inbuf = gbkStr.c_str();
    size_t inlen = gbkStr.length();
    size_t outlen = inlen * 3;  // UTF-8最多是GBK的3倍
    char* outbuf = new char[outlen];
    char* outbufStart = outbuf;

    if (iconv(cd, const_cast<char**>(&inbuf), &inlen, &outbuf, &outlen) ==
        (size_t)-1) {
        delete[] outbufStart;
        iconv_close(cd);
        return gbkStr;
    }

    string result(outbufStart, outbuf - outbufStart);
    delete[] outbufStart;
    iconv_close(cd);
    return result;
}

// 获取IP地理位置信息
GeoLocation getIPLocation(const string& ip) {
    // 检查缓存
    if (geoCache.count(ip) > 0) {
        return geoCache[ip];
    }

    // 使用太平洋IP地址库API（国内可用）
    string cmd = "curl -s 'http://whois.pconline.com.cn/ipJson.jsp?ip=" + ip +
                 "&json=true'";
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return GeoLocation{};

    char buffer[4096];
    string result;
    while (!feof(pipe)) {
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }
    }
    pclose(pipe);

    // 解析太平洋IP地址库的JSON响应
    GeoLocation location;
    if (result.find("\"addr\":") != string::npos) {
        size_t start = result.find("\"addr\":") + 8;
        size_t end = result.find('"', start);
        string addr = gbkToUtf8(result.substr(start, end - start));

        // 解析地址字符串（格式：国家 省份 城市）
        size_t pos1 = addr.find(' ');
        size_t pos2 = addr.find(' ', pos1 + 1);

        location.country = addr.substr(0, pos1);
        if (pos2 != string::npos) {
            location.region = addr.substr(pos1 + 1, pos2 - pos1 - 1);
            location.city = addr.substr(pos2 + 1);
        } else if (pos1 != string::npos) {
            location.region = addr.substr(pos1 + 1);
        }
    }

    // 获取运营商信息
    if (result.find("\"pro\":") != string::npos) {
        size_t start = result.find("\"pro\":") + 7;
        size_t end = result.find('"', start);
        location.isp = gbkToUtf8(result.substr(start, end - start));
    }

    // 由于太平洋IP库不提供经纬度信息，这里设置为0
    location.latitude = 0.0;
    location.longitude = 0.0;

    // 保存到缓存
    geoCache[ip] = location;
    return location;
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

// 流量趋势数据结构
struct TrendPoint {
    time_t timestamp;
    uint64_t bytes;
    int packets;
};

// 每个IP的流量趋势记录
map<string, deque<TrendPoint>> ipTrends;

// 绘制ASCII趋势图
string drawTrendGraph(const deque<TrendPoint>& trend, int width = 50,
                      int height = 10) {
    if (trend.empty()) {
        stringstream ss;
        ss << "\n"
           << PINK << "✧･ﾟ: * 流量趋势 * ･ﾟ✧" << RESET << " (最近"
           << anomalyConfig.trendWindowSize << "秒)\n\n"
           << CYAN << "   (｡･ω･｡) 暂无流量数据呢~" << RESET << "\n"
           << PURPLE << "   请稍等片刻，马上就来啦~" << RESET << "\n";
        return ss.str();
    }

    // 找出最大值用于归一化
    uint64_t maxBytes = 0;
    for (const auto& point : trend) {
        maxBytes = max(maxBytes, point.bytes);
    }

    vector<vector<string>> graph(height, vector<string>(width, " "));
    int pointCount = min(static_cast<int>(trend.size()), width);

    // 绘制图表
    for (int i = 0; i < pointCount; ++i) {
        int idx = trend.size() - pointCount + i;
        double normalizedValue =
            static_cast<double>(trend[idx].bytes) / maxBytes;
        int h = static_cast<int>(normalizedValue * (height - 1));

        // 使用方块字符和渐变色填充
        for (int j = 0; j <= h; ++j) {
            double intensity = static_cast<double>(j) / height;
            string color;
            string block;
            if (intensity < 0.125) {
                color = CYAN;
                block = "▁";
            } else if (intensity < 0.25) {
                color = CYAN;
                block = "▂";
            } else if (intensity < 0.375) {
                color = PURPLE;
                block = "▃";
            } else if (intensity < 0.5) {
                color = PURPLE;
                block = "▄";
            } else if (intensity < 0.625) {
                color = PINK;
                block = "▅";
            } else if (intensity < 0.75) {
                color = PINK;
                block = "▆";
            } else if (intensity < 0.875) {
                color = RED;
                block = "▇";
            } else {
                color = RED;
                block = "█";
            }
            graph[height - 1 - j][i] = color + block + RESET;
        }
    }

    // 转换为字符串，添加标题和刻度
    stringstream ss;
    ss << "\n"
       << PINK << "✧･ﾟ: * 流量趋势 * ･ﾟ✧" << RESET << " (最近"
       << anomalyConfig.trendWindowSize << "秒)\n";

    // 添加Y轴刻度和图表内容
    for (int i = height - 1; i >= 0; --i) {
        uint64_t scaleValue = (maxBytes * (i + 1)) / height;
        ss << CYAN << setw(6) << (scaleValue / 1024) << "K" << RESET << PINK
           << "│" << RESET;
        for (const auto& point : graph[i]) {
            ss << point;
        }
        ss << PINK << "│" << RESET << "\n";
    }

    // 添加X轴
    ss << PINK << "+" << string(width, '-') << "+" << RESET << "\n";

    // 添加时间刻度
    ss << "  " << CYAN << "0" << RESET << string(width / 2 - 3, ' ') << CYAN
       << anomalyConfig.trendWindowSize / 2 << "s" << RESET
       << string(width / 2 - 3, ' ') << CYAN << anomalyConfig.trendWindowSize
       << "s" << RESET << "\n";

    cout.flush();  // 确保立即显示

    return ss.str();
}

// 生成智能防护建议
SecurityAdvice generateSecurityAdvice(const string& srcIp,
                                      const TrafficStats& stats) {
    SecurityAdvice advice;

    if (stats.bytes > anomalyConfig.maxBytesPerSecond * 2) {
        advice.level = "警告";
        advice.emoji = "🚨";
        advice.description = "检测到严重的流量异常";
        advice.tips = {"建议立即检查该IP的访问来源",
                       "考虑临时限制该IP的访问频率",
                       "如果持续异常，可以将该IP加入黑名单"};
    } else if (stats.packets > anomalyConfig.maxPacketsPerSecond) {
        advice.level = "注意";
        advice.emoji = "⚠️";
        advice.description = "发现异常的访问频率";
        advice.tips = {"请密切关注该IP的后续行为", "建议开启流量限制保护"};
    } else {
        advice.level = "温馨提醒";
        advice.emoji = "💝";
        advice.description = "流量状态正常";
        advice.tips = {"继续保持监控", "定期检查安全日志"};
    }

    return advice;
}

// 检查流量异常
void checkTrafficAnomaly(const string& srcIp, uint64_t bytes, int packets) {
    static map<string, pair<uint64_t, int>> trafficStats;
    static time_t lastCheck = time(nullptr);
    time_t now = time(nullptr);

    // 更新流量趋势
    if (anomalyConfig.enableTrendAnalysis) {
        TrendPoint point{now, bytes, packets};
        ipTrends[srcIp].push_back(point);

        // 清理过期数据
        while (!ipTrends[srcIp].empty() &&
               now - ipTrends[srcIp].front().timestamp >
                   anomalyConfig.trendWindowSize) {
            ipTrends[srcIp].pop_front();
        }
    }

    // 每秒重置统计
    if (now != lastCheck) {
        trafficStats.clear();
        lastCheck = now;
    }

    trafficStats[srcIp].first += bytes;
    trafficStats[srcIp].second += packets;

    // 检查异常并生成建议
    if (trafficStats[srcIp].first > anomalyConfig.maxBytesPerSecond) {
        AnomalyEvent event{
            .timestamp = now,
            .type = "高流量",
            .description = "每秒字节数超过阈值",
            .sourceIP = srcIp,
            .value = static_cast<double>(trafficStats[srcIp].first),
            .threshold = static_cast<double>(anomalyConfig.maxBytesPerSecond)};
        anomalyHistory.push_back(event);

        // 生成并显示防护建议
        auto advice = generateSecurityAdvice(srcIp, ipStats[srcIp]);
        cout << "\n"
             << PINK << advice.emoji << " 智能防护建议 " << advice.emoji
             << RESET << "\n";
        cout << PURPLE << "级别: " << advice.level << "\n";
        cout << "描述: " << advice.description << "\n";
        cout << "建议: " << RESET << "\n";
        for (const auto& tip : advice.tips) {
            cout << CYAN << "  🌸 " << tip << RESET << "\n";
        }
    }

    if (trafficStats[srcIp].second > anomalyConfig.maxPacketsPerSecond) {
        AnomalyEvent event{
            .timestamp = now,
            .type = "高包率",
            .description = "每秒包数超过阈值",
            .sourceIP = srcIp,
            .value = static_cast<double>(trafficStats[srcIp].second),
            .threshold =
                static_cast<double>(anomalyConfig.maxPacketsPerSecond)};
        anomalyHistory.push_back(event);
    }

    // 显示流量趋势图
    if (anomalyConfig.enableTrendAnalysis && !ipTrends[srcIp].empty()) {
        cout << PINK << drawTrendGraph(ipTrends[srcIp]) << RESET;
    }
}

// 解析HTTP请求
void parseHTTPRequest(PacketDetails& details, const char* payload, int length) {
    string data(payload, min(length, 1024));
    size_t pos = 0;

    // 解析请求行
    size_t eol = data.find("\r\n");
    if (eol != string::npos) {
        string requestLine = data.substr(0, eol);
        stringstream ss(requestLine);
        ss >> details.httpMethod >> details.httpUri >> details.httpVersion;

        // 解析头部
        pos = eol + 2;
        while (pos < data.length()) {
            eol = data.find("\r\n", pos);
            if (eol == string::npos) break;

            string line = data.substr(pos, eol - pos);
            size_t colon = line.find(":");
            if (colon != string::npos) {
                string key = line.substr(0, colon);
                string value = line.substr(colon + 2);
                details.httpHeaders[key] = value;
            }
            pos = eol + 2;
        }
    }
}

// 更新TCP连接状态
void updateTCPConnection(const string& srcIp, const string& dstIp,
                         uint16_t srcPort, uint16_t dstPort,
                         const struct tcphdr* tcp, int length) {
    string connKey = srcIp + ":" + to_string(srcPort) + "-" + dstIp + ":" +
                     to_string(dstPort);

    auto& conn = tcpConnections[connKey];
    conn.srcIP = srcIp;
    conn.dstIP = dstIp;
    conn.srcPort = srcPort;
    conn.dstPort = dstPort;
    conn.lastSeen = time(nullptr);

    // 更新TCP状态
    if (tcp->th_flags & TH_SYN) {
        if (tcp->th_flags & TH_ACK) {
            conn.state = "SYN_ACK";
        } else {
            conn.state = "SYN_SENT";
        }
    } else if (tcp->th_flags & TH_FIN) {
        conn.state = "FIN_WAIT";
    } else if (tcp->th_flags & TH_RST) {
        conn.state = "CLOSED";
    } else {
        conn.state = "ESTABLISHED";
    }

    // 更新字节计数
    conn.bytesSent += length;
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
    PacketDetails details;
    details.timestamp = header->ts.tv_sec;
    details.srcIp = srcIp;
    details.dstIp = dstIp;
    details.length = header->len;

    switch (ipHeader->ip_p) {
        case IPPROTO_TCP: {
            // TCP协议处理
            const struct tcphdr* tcp =
                (struct tcphdr*)(packet + 14 + ipHeader->ip_hl * 4);
            srcPort = ntohs(tcp->th_sport);
            dstPort = ntohs(tcp->th_dport);
            protocol = "TCP";
            details.srcPort = srcPort;
            details.dstPort = dstPort;

            // 更新TCP连接状态
            updateTCPConnection(srcIp, dstIp, srcPort, dstPort, tcp,
                                header->len);

            // HTTP/HTTPS检测
            const char* payload =
                (const char*)(packet + 14 + ipHeader->ip_hl * 4 +
                              tcp->th_off * 4);
            int payloadLength = ntohs(ipHeader->ip_len) -
                                (ipHeader->ip_hl * 4) - (tcp->th_off * 4);

            if (dstPort == 80 && payloadLength > 0) {
                protocol = "HTTP";
                parseHTTPRequest(details, payload, payloadLength);
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
            details.srcPort = srcPort;
            details.dstPort = dstPort;
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

    // 检查流量异常
    checkTrafficAnomaly(srcIp, header->len, 1);

    // 添加短暂延时，让界面更新更加平滑
    usleep(200000);  // 延时200毫秒

    // 格式化输出界面
    cout << "\033[2J\033[H";  // 清屏并将光标移动到顶部
    cout << PINK << "✧･ﾟ: *✧･ﾟ:* 『流量防护卫士』 *:･ﾟ✧*:･ﾟ✧" << RESET << "\n"
         << CYAN << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << RESET
         << "\n";

    // 格式化IP地址显示
    string formattedSrcIp = isFrequentIP(srcIp)
                                ? BOLD + RED + "⚠️  " + srcIp + RESET
                                : CYAN + "   " + srcIp + RESET;

    string formattedDstIp = isFrequentIP(dstIp)
                                ? BOLD + RED + "⚠️  " + dstIp + RESET
                                : CYAN + "   " + dstIp + RESET;

    // 获取服务信息
    string serviceInfo =
        commonPorts.count(dstPort) ? " (" + commonPorts.at(dstPort) + ")" : "";

    // 获取地理位置信息
    GeoLocation location = getIPLocation(srcIp);
    string locationInfo = "";
    if (!location.country.empty()) {
        locationInfo = location.country;
        if (!location.region.empty()) {
            locationInfo += " · " + location.region;
            if (!location.city.empty()) {
                locationInfo += " · " + location.city;
            }
        }
    }

    // 提取HTTP内容
    string httpContent = "";
    if (protocol == "HTTP" || protocol == "HTTPS") {
        const u_char* payload = packet + 14 + ipHeader->ip_hl * 4;
        if (ipHeader->ip_p == IPPROTO_TCP) {
            const struct tcphdr* tcp = (struct tcphdr*)payload;
            payload += tcp->th_off * 4;
            int payloadLength = ntohs(ipHeader->ip_len) -
                                (ipHeader->ip_hl * 4) - (tcp->th_off * 4);
            if (payloadLength > 0) {
                string payloadStr((char*)payload, min(payloadLength, 100));
                if (payloadStr.find("HTTP") != string::npos) {
                    size_t endOfLine = payloadStr.find("\r\n");
                    if (endOfLine != string::npos) {
                        httpContent = payloadStr.substr(0, endOfLine);
                    }
                }
            }
        }
    }

    // 获取地理位置信息
    if (anomalyConfig.enableGeoTracking && srcIp != "127.0.0.1") {
        GeoLocation srcLocation = getIPLocation(srcIp);
        string location = srcLocation.country;
        if (!srcLocation.region.empty()) {
            location += " · " + srcLocation.region;
            if (!srcLocation.city.empty()) {
                location += " · " + srcLocation.city;
            }
        }
        locationInfo =
            "\n" + PINK + VERTICAL + RESET + "  🌏 地理位置: " + PURPLE +
            location + RESET +
            string(max(2, 80 - static_cast<int>(location.length())), ' ') +
            PINK + VERTICAL + RESET + "\n" + PINK + VERTICAL + RESET +
            "  🏢 网络服务: " + CYAN +
            (srcLocation.isp.empty() ? "未知" : srcLocation.isp) + RESET +
            string(max(2, 80 - static_cast<int>(srcLocation.isp.length())),
                   ' ') +
            PINK + VERTICAL + RESET;
    }

    // 将光标移动到固定位置
    cout << "\033[4;1H";  // 将光标移动到第4行开始位置

    // 构建漂亮的表格输出
    cout << "\n"
         << PINK << "✧･ﾟ: *✧･ﾟ:* 『数据包详情』 *:･ﾟ✧*:･ﾟ✧" << RESET << "\n"
         << PINK << TOP_LEFT << string(100, HORIZONTAL[0]) << TOP_RIGHT << RESET
         << "\n"
         << PINK << VERTICAL << RESET << "  🎀 数据包信息 " << string(84, ' ')
         << PINK << VERTICAL << RESET << "\n"
         << PINK << MIDDLE_LEFT << string(100, HORIZONTAL[0]) << MIDDLE_RIGHT
         << RESET << "\n"
         << PINK << VERTICAL << RESET << "  🔍 源地址: " << formattedSrcIp
         << "     📍 目标地址: " << formattedDstIp << string(15, ' ') << PINK
         << VERTICAL << RESET << "\n"
         << PINK << VERTICAL << RESET << "  🔌 协议: " << PURPLE << setw(8)
         << protocol << RESET << "  🚪 端口: " << CYAN << srcPort << " " << PINK
         << "➜" << RESET << " " << CYAN << dstPort << RESET << " " << YELLOW
         << serviceInfo << RESET << "  📦 大小: " << BLUE << header->len
         << " 字节" << RESET << string(15, ' ') << PINK << VERTICAL << RESET;

    // 添加地理位置信息
    if (!locationInfo.empty()) {
        cout << locationInfo;
    }
    cout << "\n";

    // 如果有HTTP内容，显示额外的行
    if (!httpContent.empty()) {
        cout << PINK << MIDDLE_LEFT << string(98, HORIZONTAL[0]) << MIDDLE_RIGHT
             << RESET << "\n"
             << PINK << VERTICAL << RESET << "  🎀 HTTP 请求内容: " << PURPLE
             << httpContent << RESET
             << string(max(2, 80 - (int)httpContent.length()), ' ') << PINK
             << VERTICAL << RESET << "\n";
    }

    cout << PINK << BOTTOM_LEFT << string(98, HORIZONTAL[0]) << BOTTOM_RIGHT
         << RESET << "\n";

    // 更新统计信息
    ipStats[srcIp].bytes += header->len;
    ipStats[srcIp].packets++;
    ipPacketCount[srcIp]++;
    ipStats[srcIp].protocols[protocol]++;
    if (dstPort > 0) {
        ipStats[srcIp].ports[dstPort]++;
    }

    // 移动光标到趋势图区域并显示更新的趋势图
    cout << "\033[25;1H";  // 将光标移动到第25行
    if (anomalyConfig.enableTrendAnalysis && !ipTrends[srcIp].empty()) {
        cout << drawTrendGraph(ipTrends[srcIp]);
    }
    cout.flush();  // 立即刷新输出缓冲区
}

// 显示统计信息
void displayStatistics() {
    clearScreen();
    // 显示超可爱的标题框
    cout << "\n"
         << PINK << TOP_LEFT << string(68, HORIZONTAL[0]) << TOP_RIGHT << "\n"
         << VERTICAL << "  " << BOLD << "✨ 流量防护卫士 " << RESET << PINK
         << string(50, ' ') << VERTICAL << "\n"
         << VERTICAL << string(68, ' ') << VERTICAL << "\n"
         << VERTICAL << "  " << PURPLE
         << "🎀 欢迎回来! 让我们一起守护网络安全吧~ 💖" << RESET << PINK
         << string(15, ' ') << VERTICAL << "\n"
         << VERTICAL << "  " << CYAN << "🌟 实时监控中..." << RESET << PINK
         << string(48, ' ') << VERTICAL << "\n"
         << BOTTOM_LEFT << string(68, HORIZONTAL[0]) << BOTTOM_RIGHT << RESET
         << "\n\n";

    // 显示异常事件
    if (!anomalyHistory.empty()) {
        cout << "\n" << RED << "⚠️ 检测到的异常事件:" << RESET << "\n";
        cout << PINK << TOP_LEFT << string(88, HORIZONTAL[0]) << TOP_RIGHT
             << RESET << "\n";
        cout << PINK << VERTICAL << RESET << " " << setw(20) << "时间"
             << " " << setw(10) << "类型"
             << " " << setw(25) << "描述"
             << " " << setw(15) << "源IP"
             << " " << setw(10) << "值" << PINK << VERTICAL << RESET << "\n";
        cout << PINK << MIDDLE_LEFT << string(88, HORIZONTAL[0]) << MIDDLE_RIGHT
             << RESET << "\n";

        time_t now = time(nullptr);
        for (const auto& event : anomalyHistory) {
            if (now - event.timestamp <= 60) {  // 只显示最近1分钟的异常
                cout << PINK << VERTICAL << RESET << " " << setw(20)
                     << ctime(&event.timestamp) << " " << setw(10) << event.type
                     << " " << setw(25) << event.description << " " << setw(15)
                     << event.sourceIP << " " << setw(10) << fixed
                     << setprecision(2) << event.value << PINK << VERTICAL
                     << RESET << "\n";
            }
        }
        cout << PINK << BOTTOM_LEFT << string(88, HORIZONTAL[0]) << BOTTOM_RIGHT
             << RESET << "\n";
    }

    // 显示TCP连接状态
    cout << "\n" << PURPLE << "🔌 活跃TCP连接:" << RESET << "\n";
    cout << PINK << TOP_LEFT << string(88, HORIZONTAL[0]) << TOP_RIGHT << RESET
         << "\n";
    cout << PINK << VERTICAL << RESET << " " << setw(25) << "连接标识"
         << " " << setw(15) << "状态"
         << " " << setw(20) << "最后活动时间"
         << " " << setw(15) << "发送字节数" << PINK << VERTICAL << RESET
         << "\n";
    cout << PINK << MIDDLE_LEFT << string(88, HORIZONTAL[0]) << MIDDLE_RIGHT
         << RESET << "\n";

    time_t now = time(nullptr);
    for (const auto& [key, conn] : tcpConnections) {
        if (now - conn.lastSeen <= 30) {  // 只显示30秒内活跃的连接
            string connStr = conn.srcIP + ":" + to_string(conn.srcPort) +
                             " -> " + conn.dstIP + ":" +
                             to_string(conn.dstPort);
            cout << PINK << VERTICAL << RESET << " " << setw(25) << connStr
                 << " " << setw(15) << conn.state << " " << setw(20)
                 << ctime(&conn.lastSeen) << " " << setw(15) << conn.bytesSent
                 << PINK << VERTICAL << RESET << "\n";
        }
    }
    cout << PINK << BOTTOM_LEFT << string(88, HORIZONTAL[0]) << BOTTOM_RIGHT
         << RESET << "\n";

    // 数据包统计表格
    cout << "\n"
         << PURPLE << "🦋 实时流量分析: 每秒数据包统计 ✨" << RESET << "\n";
    cout << PINK << TOP_LEFT << string(68, HORIZONTAL[0]) << TOP_RIGHT << "\n"
         << VERTICAL << " " << BOLD << setw(25) << "🌐 IP 地址" << " "
         << VERTICAL << " " << setw(18) << "📊 数据包/秒" << " " << VERTICAL
         << " " << setw(15) << "📈 状态" << RESET << PINK << " " << VERTICAL
         << "\n"
         << MIDDLE_LEFT << string(27, HORIZONTAL[0]) << CROSS
         << string(20, HORIZONTAL[0]) << CROSS << string(18, HORIZONTAL[0])
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
    cout << "\n" << PURPLE << "✨ 流量分析: 总流量统计 💫" << RESET << "\n";
    cout << PINK << TOP_LEFT << string(68, HORIZONTAL[0]) << TOP_RIGHT << RESET
         << "\n";
    cout << PINK << VERTICAL << RESET << CYAN << "  🌐 " << left << setw(25)
         << "IP 地址" << PINK << VERTICAL << RESET << CYAN << "  📊 "
         << "总字节数" << string(20, ' ') << PINK << VERTICAL << RESET << "\n";
    cout << PINK << MIDDLE_LEFT << string(68, HORIZONTAL[0]) << MIDDLE_RIGHT
         << RESET << "\n";
    for (const auto& [ip, stats] : ipStats) {
        cout << PINK << VERTICAL << RESET << " " << left << setw(19) << ip
             << PINK << VERTICAL << RESET << " " << BLUE << setw(15)
             << stats.bytes << RESET << PINK << VERTICAL << RESET << "\n";
    }
    cout << PINK << BOTTOM_LEFT << string(45, HORIZONTAL[0]) << BOTTOM_RIGHT
         << RESET << "\n";

    // 协议类型统计
    cout << "\n" << PURPLE << "✨ 流量分析: 协议类型分布 🎭" << RESET << "\n";
    cout << PINK << TOP_LEFT << string(68, HORIZONTAL[0]) << TOP_RIGHT << RESET
         << "\n";
    cout << PINK << VERTICAL << RESET << CYAN << "  🌐 " << left << setw(20)
         << "IP 地址" << PINK << VERTICAL << RESET << CYAN << "  🔮 "
         << setw(15) << "协议类型" << PINK << VERTICAL << RESET << CYAN
         << "  🎯 " << setw(15) << "数量" << PINK << VERTICAL << RESET << "\n";
    cout << PINK << MIDDLE_LEFT << string(68, HORIZONTAL[0]) << MIDDLE_RIGHT
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
