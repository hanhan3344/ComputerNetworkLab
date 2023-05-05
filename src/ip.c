#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

extern FILE *arp_fout;
void fprint_buf(FILE* f, buf_t* buf);

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // Step 1: 检查数据包长度是否小于IP头部长度，如果是，则丢弃不处理
    if (buf->len < sizeof(ip_hdr_t)) {
        return;
    }

    // Step 2: 进行报头检测
    ip_hdr_t *iphdr = (ip_hdr_t *)buf->data;
    if (iphdr->version != IP_VERSION_4 || swap16(iphdr->total_len16) > buf->len) {
        return;
    }

    // Step 3: 进行IP头部校验和检测
    uint16_t saved_checksum = iphdr->hdr_checksum16;
    iphdr->hdr_checksum16 = 0;
    if (saved_checksum != checksum16((uint16_t *)iphdr, iphdr->hdr_len * IP_HDR_LEN_PER_BYTE)) {
        return;
    }
    iphdr->hdr_checksum16 = saved_checksum;

    // Step 4: 判断目的IP地址是否为本机IP地址，如果不是，则丢弃不处理
    if (memcmp(iphdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        return;
    }

    // Step 5: 如果接收到的数据包的长度大于IP头部的总长度字段，则去除填充字段
    if (swap16(iphdr->total_len16) < buf->len) {
        buf_remove_padding(buf, buf->len - swap16(iphdr->total_len16));
    }

    // Step 7: 传递数据包给上层协议
    switch (iphdr->protocol) {
        case NET_PROTOCOL_ARP:
        case NET_PROTOCOL_IP:
        case NET_PROTOCOL_ICMP:
        case NET_PROTOCOL_UDP:
            // Step 6: 去掉IP报头
            buf_remove_header(buf, iphdr->hdr_len * IP_HDR_LEN_PER_BYTE);
            net_in(buf, iphdr->protocol, iphdr->src_ip);
            break;
        // case NET_PROTOCOL_TCP:
        //     net_in(buf, iphdr->protocol, iphdr->src_ip);
        //     break;
        default:
            icmp_unreachable(buf, iphdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
            break;
    }
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    buf_add_header(buf, sizeof(ip_hdr_t));

    // 填充IP协议首部
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = 5;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(buf->len);
    ip_hdr->id16 = swap16(id);
    if (mf) ip_hdr->flags_fragment16 = swap16(IP_MORE_FRAGMENT | offset);
    else    ip_hdr->flags_fragment16 = swap16(offset);
    ip_hdr->ttl = IP_DEFALUT_TTL;
    ip_hdr->protocol = protocol;
    ip_hdr->hdr_checksum16 = 0;
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);

    // 计算IP首部校验和
    uint16_t checksum = checksum16((uint16_t *)ip_hdr, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
    ip_hdr->hdr_checksum16 = checksum;
    // fprintf(arp_fout,"###############Personal Log Begin###############\n");
    // fprintf(arp_fout, "len = %hu", ip_hdr->total_len16);
    // fprint_buf(arp_fout,buf);
    // fprintf(arp_fout,"###############Personal Log End###############\n");
    // 发送数据
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    static uint16_t IP_ID = 0;
    // 检查数据包长度是否超过IP协议最大负载包长
    if (buf->len > ETHERNET_MAX_TRANSPORT_UNIT-20) {
        // 计算分片数目
        int num_frags = (buf->len) / (ETHERNET_MAX_TRANSPORT_UNIT-20) + 1;
        // 最后一个分片的长度
        int last_frag_size = buf->len - (num_frags-1) * (ETHERNET_MAX_TRANSPORT_UNIT-20);
        // 分片发送
        for (int i = 0; i < num_frags; i++) {
            // 计算每个分片的偏移量和MF标志
            int offset = i * (ETHERNET_MAX_TRANSPORT_UNIT-20)/IP_HDR_OFFSET_PER_BYTE;
            int mf = (i == num_frags - 1) ? 0 : 1;
            int frag_size = (i == num_frags - 1) ? last_frag_size : (ETHERNET_MAX_TRANSPORT_UNIT-20);
            // 初始化ip_buf
            buf_t ip_buf;
            buf_init(&ip_buf, frag_size);
            // 拷贝数据
            memcpy(ip_buf.data, buf->data, frag_size);
            buf_remove_header(buf, frag_size);
            // 发送分片
            ip_fragment_out(&ip_buf, ip, protocol, IP_ID, offset, mf);
        }
    } else {
        ip_fragment_out(buf, ip, protocol, IP_ID, 0, 0);
    }
    IP_ID++;
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}