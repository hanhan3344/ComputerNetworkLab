#include "udp.h"
#include "ip.h"
#include "icmp.h"

/**
 * @brief udp处理程序表
 * 
 */
map_t udp_table;

/**
 * @brief udp伪校验和计算
 * 
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dst_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    // Step1: 调用buf_add_header()函数增加UDP伪头部
    buf_add_header(buf, sizeof(ip_hdr_t));

    // Step2: 暂存IP头部，以免被覆盖
    ip_hdr_t ip_hdr;
    memcpy(&ip_hdr, buf->data, sizeof(ip_hdr_t));
    buf_remove_header(buf, sizeof(ip_hdr_t) - sizeof(udp_peso_hdr_t));

    // Step3: 填写UDP伪头部的12字节字段
    udp_peso_hdr_t *udp_pseudo_hdr = (udp_peso_hdr_t *) buf->data;
    memcpy(udp_pseudo_hdr->src_ip, src_ip, NET_IP_LEN);
    memcpy(udp_pseudo_hdr->dst_ip, dst_ip, NET_IP_LEN);
    udp_pseudo_hdr->placeholder = 0;
    udp_pseudo_hdr->protocol = NET_PROTOCOL_UDP;
    udp_pseudo_hdr->total_len16 = swap16(buf->len - sizeof(udp_peso_hdr_t));
    memcpy(buf->data, udp_pseudo_hdr, sizeof(udp_peso_hdr_t));

    // Step4: 计算UDP校验和
    int paddled = 0;
    if(buf->len % 2) {
        buf_add_padding(buf, 1);
        paddled = 1;
    }
    uint16_t checksum = checksum16((uint16_t *) buf->data, buf->len);

    // Step5: 将暂存的IP头部拷贝回来
    buf_add_header(buf, sizeof(ip_hdr_t)-sizeof(udp_peso_hdr_t));
    memcpy(buf->data, &ip_hdr, sizeof(ip_hdr_t));

    // Step6: 调用buf_remove_header()函数去掉UDP伪头部
    buf_remove_header(buf, sizeof(ip_hdr_t));

    if(paddled) buf_remove_padding(buf, 1);

    // Step7: 返回计算出来的校验和值
    return checksum;
}

/**
 * @brief 处理一个收到的udp数据包
 * 
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    // Step 1: Check the packet length
    if (buf->len < sizeof(udp_hdr_t)) {
        return;
    }
    udp_hdr_t *hdr = (udp_hdr_t *)buf->data;
    if (buf->len < swap16(hdr->total_len16)) {
        return;
    }
    
    // Step 2: Check the checksum
    uint16_t checksum = hdr->checksum16;
    hdr->checksum16 = 0;
    if (checksum != udp_checksum(buf, src_ip, net_if_ip)) {
        return;
    }
    hdr->checksum16 = checksum;

    // Step 3: Lookup the callback function for the destination port
    uint16_t dst_port16 = swap16(hdr->dst_port16);
    udp_handler_t *cb = (udp_handler_t *)map_get(&udp_table, &dst_port16);
    if (!cb) {
        // Step 4: If the port is not found, send an ICMP unreachable packet
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
        return;
    } else {
        // Step 5: Otherwise, remove the header and call the callback function
        buf_remove_header(buf, sizeof(udp_hdr_t));
        (*cb)(buf->data, buf->len, src_ip, hdr->src_port16);
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    // Step1: 调用buf_add_header()函数添加UDP报头
    buf_add_header(buf, sizeof(udp_hdr_t));

    // Step2: 填充UDP首部字段
    udp_hdr_t *udp_hdr = (udp_hdr_t *) buf->data;
    udp_hdr->src_port16 = swap16(src_port);
    udp_hdr->dst_port16 = swap16(dst_port);
    udp_hdr->total_len16 = swap16(buf->len);  // UDP报文长度包含UDP头部长度
    udp_hdr->checksum16 = 0;  // 先将校验和字段填充0

    memcpy(buf->data, udp_hdr, sizeof(udp_hdr_t));
    // Step3: 调用udp_checksum()函数计算出校验和，将结果填入校验和字段
    udp_hdr->checksum16 = udp_checksum(buf, net_if_ip, dst_ip);
    memcpy(buf->data, udp_hdr, sizeof(udp_hdr_t));

    // Step4: 调用ip_out()函数发送UDP数据报
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 * 
 */
void udp_init()
{
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 * 
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 * 
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 * 
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}